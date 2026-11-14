"""`vds gateway init` — идемпотентное развёртывание gateway с нуля.

SPEC-20261114-fresh-install-v3: одна команда, которая последовательно поднимает
выбранные транспорты через существующие идемпотентные команды (xray install,
hysteria2 install, acme issue, xray add-transport/add-cdn, hysteria2
add-obfs/add-hop-ports, amneziawg install, gateway healthcheck --install-timer).

Правила:
- dry-run по умолчанию; мутации только с apply=True (CLI --apply);
- preflight до мутаций: root, INSTALL_DIR, публичный IP, DNS, занятость портов;
- скипы уже установленного по state.protocols (плюс проверка живости юнита —
  расхождение state/юнит = предупреждение и переустановка шага);
- DNS не резолвится в публичный IP → ACME/XHTTP/CDN пропускаются с warning
  (--require-domain переводит это в ошибку);
- fail-fast: первая ошибка останавливает исполнение, печатается команда
  ручного продолжения; секреты не логируются.

Шаги исполняются через run_list(argv) (не shell) вызовом
`<python> -m src.main <команда>` в корне репозитория — публичные контракты
install/add-* не меняются, вывод и коды возврата шагов тождественны CLI.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.shell import run_list
from src.core.units import unit_active
from src.gateway.paths import (
    ACME_LETSENCRYPT_LIVE,
    AWG_PORT_DEFAULT,
    AWG_UNIT,
    CDN_ORIGIN_PORT_DEFAULT,
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_HOP_UNIT,
    HYSTERIA2_OBFS_PORT_DEFAULT,
    HYSTERIA2_OBFS_UNIT,
    HYSTERIA2_UNIT,
    XHTTP_INTERNAL_PORT,
    XRAY_UNIT,
)
from src.gateway.store import GatewayState, StoreError, load_state

VALID_PROTOCOLS = ("reality", "hysteria2", "obfs", "hop", "xhttp", "cdn", "awg")
DEFAULT_PROTOCOLS = "reality,hysteria2"
DEFAULT_SNI = "www.google.com"
DEFAULT_HOP_RANGE = "20000-20500"

# Протокол → ключ state.protocols (как пишут сами модули-установщики).
STATE_KEY = {
    "reality": "xray",
    "hysteria2": "hysteria2",
    "obfs": "hysteria2-obfs",
    "xhttp": "xhttp",
    "cdn": "xray-cdn",
    "awg": "amneziawg",
}

# systemd-юнит шага (None — шаг не имеет собственного юнита); ключи — имена
# протоколов из --protocols.
STEP_UNIT = {
    "reality": XRAY_UNIT,
    "hysteria2": HYSTERIA2_UNIT,
    "obfs": HYSTERIA2_OBFS_UNIT,
    "hop": HYSTERIA2_HOP_UNIT,
    "awg": AWG_UNIT,
    "xhttp": XRAY_UNIT,
    "cdn": XRAY_UNIT,
    "acme": None,
    "xray-domain": None,
    "healthcheck": None,
}

# Порты шага для preflight (protocol -> [(port, proto)]).
STEP_PORTS: dict[str, list[tuple[int, str]]] = {
    "reality": [(443, "tcp")],
    "hysteria2": [(443, "udp")],
    "obfs": [(HYSTERIA2_OBFS_PORT_DEFAULT, "udp")],
    "awg": [(AWG_PORT_DEFAULT, "udp")],
    "xhttp": [(XHTTP_INTERNAL_PORT, "tcp")],
    "cdn": [(CDN_ORIGIN_PORT_DEFAULT, "tcp")],
    "acme": [(80, "tcp")],
    "hop": [],  # заполняется по диапазону в build_plan
}

# Владелец порта «наш» (уже установленная служба gateway, а не чужой процесс).
_OWN_OWNER_HINTS = ("xray", "hysteria", "awg", "vds-")

# Транспорты, которым для работы нужен домен (ACME выпускается, если запрошен
# хотя бы один из них). XHTTP/CDN требуют reality — это валидирует
# parse_protocols, здесь только гейт по --protocols.
DOMAIN_TRANSPORTS = ("reality", "hysteria2", "xhttp", "cdn")

REPO_ROOT = Path(__file__).resolve().parents[2]


def parse_protocols(value: str) -> list[str]:
    """CSV протоколов -> валидированный список. ValueError при ошибке ввода."""
    items = [p.strip().lower() for p in value.split(",") if p.strip()]
    if not items:
        raise ValueError(
            "Список протоколов пуст. Ожидается csv из: " + ", ".join(VALID_PROTOCOLS)
        )
    unknown = [p for p in items if p not in VALID_PROTOCOLS]
    if unknown:
        raise ValueError(
            f"Неизвестные протоколы: {', '.join(unknown)}. "
            "Допустимо: " + ", ".join(VALID_PROTOCOLS)
        )
    seen: list[str] = []
    for p in items:
        if p not in seen:
            seen.append(p)
    for dep in ("hysteria2",):
        for extra in ("obfs", "hop"):
            if extra in seen and dep not in seen:
                raise ValueError(f"Протокол {extra} требует {dep} в --protocols.")
    if "xhttp" in seen and "reality" not in seen:
        raise ValueError("Протокол xhttp требует reality (инблэнд за SNI-фолбэком, ADR-003).")
    if "cdn" in seen and "reality" not in seen:
        raise ValueError("Протокол cdn требует reality (один инблэнд-семейство xray).")
    return seen


@dataclass
class Step:
    """Один шаг плана: name — ключ протокола, command — argv для run_list."""

    name: str
    title: str
    command: list[str]
    skip_reason: str = ""


@dataclass
class InitPlan:
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _cli(prefix: list[str]) -> list[str]:
    """argv вызова CLI-команды через модуль (python -m src.main …)."""
    return [sys.executable, "-m", "src.main", *prefix]


def _parse_hop_range(raw: str) -> tuple[int, int]:
    """'20000-20500' -> (20000, 20500); ValueError при кривом формате."""
    try:
        start_s, end_s = raw.split("-")
        start, end = int(start_s), int(end_s)
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"Некорректный диапазон {raw!r}: ожидалось 'start-end', напр. 20000-20500."
        ) from exc
    if not (0 < start <= end <= 65535):
        raise ValueError(f"Некорректный диапазон {raw!r}: порты 1..65535, start<=end.")
    if end - start + 1 > 1000:
        raise ValueError(
            f"Диапазон {raw!r} шире 1000 портов — клиентский лимит port hopping."
        )
    return start, end


def _state_installed(state: GatewayState, key: str) -> bool:
    return bool(state.protocols.get(key, {}).get("installed"))


def _state_hop_ports(state: GatewayState) -> str | None:
    meta = state.protocols.get("hysteria2") or {}
    return meta.get("hop_ports") or None


def _health_timer_installed() -> bool:
    """Healthcheck-таймер уже активен или включён — повторная установка не нужна."""
    from src.gateway.health import HEALTH_TIMER_UNIT

    if unit_active(HEALTH_TIMER_UNIT):
        return True
    result = run_list(["systemctl", "is-enabled", HEALTH_TIMER_UNIT], timeout=10)
    return result.ok and result.output.strip() in ("enabled", "enabled-runtime")


def _skip_by_state(state: GatewayState, protocol: str, plan: InitPlan, name: str) -> str:
    """Причина скипа шага по state + живость юнита; '' — шаг нужно выполнить."""
    key = STATE_KEY.get(protocol)
    if protocol == "hop":
        ports = _state_hop_ports(state)
        if not ports:
            return ""
        # Расхождение state/юнит: hop_ports записан, но юнит не жив — переустановка.
        if not unit_active(HYSTERIA2_HOP_UNIT):
            plan.warnings.append(
                f"{name}: state.protocols['hysteria2'].hop_ports={ports} записан, "
                f"но юнит {HYSTERIA2_HOP_UNIT} не активен — шаг будет выполнен заново."
            )
            return ""
        return f"port hopping уже настроен ({ports})"
    if key is None:
        return ""
    if not _state_installed(state, key):
        return ""
    unit = STEP_UNIT.get(protocol)
    if unit is not None and not unit_active(unit):
        plan.warnings.append(
            f"{name}: state.protocols['{key}'] помечен installed, но юнит {unit} "
            "не активен — шаг будет выполнен заново (проверьте `vds gateway status`)."
        )
        return ""
    return "уже установлен (state.protocols)"


def build_plan(
    protocols: list[str],
    domain: str | None,
    email: str | None,
    sni: str = DEFAULT_SNI,
    hop_range: str = DEFAULT_HOP_RANGE,
    cdn_domain: str | None = None,
    state_path: str | None = None,
) -> InitPlan:
    """План шагов + скипы по state. Ошибки ввода — в plan.errors."""
    plan = InitPlan()
    try:
        state = load_state(state_path)
    except StoreError as exc:
        plan.errors.append(f"Не удалось прочитать состояние: {exc}")
        return plan

    domain = (domain or "").strip() or None
    cdn_domain = (cdn_domain or "").strip() or domain
    email = (email or "").strip() or None

    if domain and not email:
        plan.errors.append("Для домена нужен email Let's Encrypt (--email).")
    if "cdn" in protocols and not cdn_domain:
        plan.errors.append("Протокол cdn требует --domain (или --cdn-domain).")
    if "hop" in protocols:
        try:
            _parse_hop_range(hop_range)
        except ValueError as exc:
            plan.errors.append(str(exc))

    # Порядок шагов — SPEC §2 (1–9). Базовые шаги гейтятся по --protocols:
    # запросили только awg — Xray/Hysteria2 не ставим.
    if "reality" in protocols:
        plan.steps.append(
            Step("reality", "Xray VLESS Reality (TCP 443)",
                 _cli(["xray", "install", "--sni", sni]))
        )
    if "hysteria2" in protocols:
        plan.steps.append(
            Step("hysteria2", "Hysteria2 QUIC (UDP 443)", _cli(["hysteria2", "install"]))
        )

    # ACME — только при домене и хотя бы одном доменном транспорте; hy2-cert
    # нужен только Hysteria2, xray-domain — только Reality.
    has_domain_transport = any(p in protocols for p in DOMAIN_TRANSPORTS)
    if domain and has_domain_transport:
        plan.steps.append(
            Step(
                "acme",
                f"LE-сертификат {domain} (HTTP-01)",
                _cli(["acme", "issue", "--domain", domain, "--email", email or ""]),
            )
        )
        if "hysteria2" in protocols:
            plan.steps.append(
                Step(
                    "hy2-cert",
                    "LE-сертификат → Hysteria2",
                    _cli(["hysteria2", "apply-cert", "--apply"]),
                )
            )
        if "reality" in protocols:
            plan.steps.append(
                Step(
                    "xray-domain",
                    f"Адрес ссылок = {domain} (state.domain)",
                    _cli(["xray", "use-domain", "--domain", domain]),
                )
            )
    if "xhttp" in protocols:
        if domain:
            plan.steps.append(
                Step(
                    "xhttp",
                    "XHTTP-транспорт (порт 8443, ADR-003)",
                    _cli(
                        [
                            "xray",
                            "add-transport",
                            "xhttp",
                            "--domain",
                            domain,
                            "--mode",
                            "port",
                            "--apply",
                            "--yes",
                        ]
                    ),
                )
            )
        else:
            plan.warnings.append(
                "xhttp: запрошен, но домен не задан — шаг пропущен "
                "(XHTTP-ссылки строятся от домена)."
            )
    if "cdn" in protocols:
        if cdn_domain:
            plan.steps.append(
                Step(
                    "cdn",
                    f"CDN VLESS+WS+TLS ({cdn_domain}:2053, ADR-006)",
                    _cli(["xray", "add-cdn", "--domain", cdn_domain, "--yes"]),
                )
            )
    if "obfs" in protocols:
        plan.steps.append(
            Step(
                "obfs",
                f"Hysteria2 obfs salamander (UDP {HYSTERIA2_OBFS_PORT_DEFAULT})",
                _cli(["hysteria2", "add-obfs"]),
            )
        )
    if "hop" in protocols:
        plan.steps.append(
            Step(
                "hop",
                f"Hysteria2 port hopping ({hop_range})",
                _cli(["hysteria2", "add-hop-ports", hop_range, "--apply"]),
            )
        )
    if "awg" in protocols:
        plan.steps.append(
            Step(
                "awg",
                f"AmneziaWG (UDP {AWG_PORT_DEFAULT})",
                _cli(["amneziawg", "install"]),
            )
        )
    plan.steps.append(
        Step(
            "healthcheck",
            "Healthcheck-таймер vds-gateway-health.timer",
            _cli(["gateway", "healthcheck", "--install-timer"]),
        )
    )

    # Скипы по state (после сборки шагов, чтобы warnings ложились на шаги).
    for step in plan.steps:
        if step.name == "acme":
            meta = state.protocols.get("acme") or {}
            live = ACME_LETSENCRYPT_LIVE(domain or "")
            if (
                meta.get("installed")
                and str(meta.get("domain") or "") == (domain or "")
                and (live / "fullchain.pem").is_file()
            ):
                step.skip_reason = "сертификат уже выпущен (state.protocols['acme'])"
            continue
        if step.name == "hy2-cert":
            # Сертификат уже применён к Hysteria2 и LE-файлы на месте — apply-cert
            # (с рестартом юнита) не нужен. Нет LE-файлов — ACME не выполнен.
            meta = state.protocols.get("hysteria2") or {}
            live_cert = ACME_LETSENCRYPT_LIVE(domain or "") / "fullchain.pem"
            if (
                HYSTERIA2_CERT_PATH.is_file()
                and str(meta.get("cert_domain") or "") == (domain or "")
            ):
                step.skip_reason = f"LE-сертификат уже применён ({domain})"
            elif not live_cert.is_file():
                step.skip_reason = "LE-файлы домена отсутствуют (ACME не выполнен)"
            continue
        if step.name == "xray-domain":
            if state.domain == (domain or ""):
                step.skip_reason = "домен ссылок уже установлен (state.domain)"
            continue
        if step.name == "healthcheck":
            if _health_timer_installed():
                step.skip_reason = "healthcheck-таймер уже установлен"
            continue
        reason = _skip_by_state(state, step.name, plan, step.title)
        if reason:
            step.skip_reason = reason

    return plan


def preflight(plan: InitPlan, domain: str | None, state_path: str | None = None) -> None:
    """Проверки до мутаций: root, INSTALL_DIR, egress/IP, DNS, порты.

    Ошибки — в plan.errors (init не начнётся), предупреждения — в plan.warnings.
    """
    if os.geteuid() != 0:
        plan.errors.append("Требуется root (запустите через sudo).")
        return

    if not Path(os.environ.get("INSTALL_DIR", "/opt/my-vds")).is_dir():
        plan.warnings.append(
            "INSTALL_DIR не найден — сначала установите пакет (bash install.sh)."
        )

    ip = public_ip()
    if not ip:
        plan.errors.append(
            "Не удалось определить публичный IP (egress/api.ipify.org) — "
            "он нужен для сертификатов и ссылок."
        )
        return

    domain = (domain or "").strip()
    if domain:
        from src.acme.install import dns_resolves_to

        if not dns_resolves_to(domain, ip):
            plan.warnings.append(
                f"Домен {domain} не резолвится в {ip}: ACME/XHTTP/CDN будут "
                "пропущены (исправьте A-запись и повторите init — остальные "
                "шаги отработают)."
            )
            for step in plan.steps:
                if step.name in ("acme", "hy2-cert", "xray-domain", "xhttp", "cdn") and not step.skip_reason:
                    step.skip_reason = f"DNS {domain} не резолвится в публичный IP"

    _preflight_ports(plan, state_path)


def _preflight_ports(plan: InitPlan, state_path: str | None) -> None:
    """Занятость портов шагов, которые не скипнутся по state."""
    for step in plan.steps:
        if step.skip_reason:
            continue
        for port, proto in _ports_for_step(step):
            if port_free(port, proto):
                continue
            owner = port_owner(port, proto)
            owner_info = f" (владелец: {owner})" if owner else ""
            if owner and any(h in (owner or "").lower() for h in _OWN_OWNER_HINTS):
                plan.warnings.append(
                    f"{step.name}: порт {port}/{proto} занят нашей службой "
                    f"{owner_info} — шаг установки сам решит (идемпотентно)."
                )
            else:
                plan.errors.append(
                    f"{step.name}: порт {port}/{proto} занят{owner_info}. "
                    "Освободите порт и повторите — установки не было."
                )


def _ports_for_step(step: Step) -> list[tuple[int, str]]:
    if step.name == "hop":
        import re

        raw = next(
            (arg for arg in step.command if re.fullmatch(r"\d+-\d+", arg)),
            DEFAULT_HOP_RANGE,
        )
        try:
            start, end = _parse_hop_range(raw)
        except ValueError:
            return []
        return [(start, "udp"), (end, "udp")]
    return STEP_PORTS.get(step.name, [])


def _demo_clients(protocols: list[str], state_path: str | None) -> list[str]:
    """Создать демо-клиентов phone/mob/laptop (идемпотентно). Имена созданных."""
    created: list[str] = []
    from src.gateway.store import StoreError

    jobs: list[tuple[str, str, callable]] = []
    if "reality" in protocols:
        from src.xray.clients import add_client as xray_add

        # default-arg фиксирует функцию: без него позднее связывание имени
        # подменило бы обработчик hysteria2 (баг найден на чистой VM).
        jobs.append(("phone", "xray", lambda add=xray_add: add("phone")))
    if "hysteria2" in protocols:
        from src.hysteria2.clients import add_client as hy2_add

        jobs.append(("mob", "hysteria2", lambda add=hy2_add: add("mob")))
    if "awg" in protocols:
        from src.amneziawg.clients import add_client as awg_add

        jobs.append((
            "laptop", "amneziawg",
            lambda add=awg_add: add("laptop", no_psk=False),
        ))

    for name, proto, fn in jobs:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — StoreError/дубль имени/ошибки клиента читаемы
            console.print(
                f"[warning][init] Клиент {name} ({proto}): {exc} — пропуск.[/warning]"
            )
            continue
        created.append(name)
        console.print(f"[success][init] Демо-клиент {name} ({proto}) создан.[/success]")
    del state_path  # клиенты пишут в state через свои модули
    return created


def _summary(protocols: list[str], domain: str | None, cdn_domain: str | None) -> None:
    """Итоговая карта: юниты/порты/сертификаты + ссылки + следующие шаги."""
    from src.gateway.links import render_all_links

    console.print("\n[bold]=== Итог gateway init ===[/bold]")
    state = load_state()
    for key, meta in state.protocols.items():
        if not meta.get("installed"):
            continue
        port = meta.get("port")
        console.print(f"  [success]*[/success] {key} (порт {port or '—'})")
    if domain:
        live = ACME_LETSENCRYPT_LIVE(domain)
        cert_ok = (live / "fullchain.pem").is_file()
        console.print(
            f"  [info]*[/info] сертификат {domain}: "
            f"{'есть' if cert_ok else 'нет (ACME не выполнен)'}"
        )
        if cdn_domain and cdn_domain != domain:
            cdn_ok = (ACME_LETSENCRYPT_LIVE(cdn_domain) / "fullchain.pem").is_file()
            console.print(f"  [info]*[/info] сертификат {cdn_domain}: {'есть' if cdn_ok else 'нет'}")

    try:
        links = render_all_links(include_obfs="obfs" in protocols)
    except (StoreError, ValueError):
        links = []
    if links:
        console.print("\n[bold]Share-links:[/bold]")
        for name, _proto, link in links:
            print(f"{name}: {link}")

    console.print("\n[bold]Следующие шаги:[/bold]")
    console.print("  - откройте порты в UFW/панели провайдера, если нужно (ufw allow)")
    console.print("  - импортируйте ссылки в клиентские приложения")
    console.print("  - статусы: vds gateway status / vds gateway healthcheck")
    console.print("  - откат транспорта: vds <xray|hysteria2|amneziawg> remove --apply")


_ROLLBACK = {
    "reality": "vds xray remove --apply",
    "hysteria2": "vds hysteria2 remove --apply",
    "acme": "certbot delete --cert-name <домен>",
    "hy2-cert": "vds hysteria2 apply-cert --restore",
    "xray-domain": "vds xray use-domain --domain ''  # не поддерживается — правьте state.json",
    "xhttp": "vds xray remove-transport xhttp --apply",
    "cdn": "vds xray remove-cdn --apply",
    "obfs": "vds hysteria2 remove-obfs --apply",
    "hop": "vds hysteria2 remove-hop-ports --apply",
    "awg": "vds amneziawg remove --apply",
    "healthcheck": "systemctl disable --now vds-gateway-health.timer",
}


_POST_STATE = {
    "reality": "xray",
    "hysteria2": "hysteria2",
    "obfs": "hysteria2-obfs",
    "xhttp": "xhttp",
    "cdn": "xray-cdn",
    "awg": "amneziawg",
}


def _verify_step(step: Step, domain: str | None, state_path: str | None) -> bool:
    """Постпроверка шага: state/юнит/сертификат реально на месте.

    Защита от «успешного» no-op (например, install вернул 0, но юнит/state не
    появились — найдено на чистой VM в контейнере 2026-11-14).
    """
    name = step.name
    try:
        state = load_state(state_path)
    except StoreError:
        return False

    if name in _POST_STATE:
        key = _POST_STATE[name]
        if not state.protocols.get(key, {}).get("installed"):
            return False
        unit = STEP_UNIT.get(name)
        return True if unit is None else unit_active(unit)

    if name == "hop":
        return bool((state.protocols.get("hysteria2") or {}).get("hop_ports")) \
            and unit_active(HYSTERIA2_HOP_UNIT)

    if name == "acme":
        return bool(domain) and (ACME_LETSENCRYPT_LIVE(domain) / "fullchain.pem").is_file()

    if name == "hy2-cert":
        return str((state.protocols.get("hysteria2") or {}).get("cert_domain")) == (domain or "")

    if name == "xray-domain":
        return str(state.domain or "") == (domain or "")

    if name == "healthcheck":
        return unit_active("vds-gateway-health.timer")

    return True


def run_init(
    protocols: str = DEFAULT_PROTOCOLS,
    domain: str | None = None,
    email: str | None = None,
    sni: str = DEFAULT_SNI,
    hop_range: str = DEFAULT_HOP_RANGE,
    cdn_domain: str | None = None,
    apply: bool = False,
    demo_clients: bool = False,
    require_domain: bool = False,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds gateway init`. 0 — успех (в т.ч. dry-run / «нечего делать»)."""
    try:
        proto_list = parse_protocols(protocols)
    except ValueError as exc:
        console.print(f"[error][init] {exc}[/error]")
        return 1

    plan = build_plan(
        proto_list, domain, email, sni=sni, hop_range=hop_range,
        cdn_domain=cdn_domain, state_path=state_path,
    )
    for err in plan.errors:
        console.print(f"[error][init] {err}[/error]")
    if plan.errors:
        return 1

    preflight(plan, domain, state_path=state_path)

    if plan.errors:
        console.print("[error][init] Preflight выявил блокеры — ничего не установлено:[/error]")
        for err in plan.errors:
            console.print(f"  [error]- {err}[/error]")
        return 1

    for warn in plan.warnings:
        console.print(f"[warning][init] {warn}[/warning]")

    if require_domain and domain:
        bad = [s for s in plan.steps if s.skip_reason and "DNS" in s.skip_reason]
        if bad:
            console.print(
                f"[error][init] --require-domain: DNS {domain} не подтверждён — "
                "шаги с доменом не будут выполнены. Исправьте A-запись.[/error]"
            )
            return 1

    # Планирование: печать шагов.
    console.print(f"\n[bold][init] План ({'apply' if apply else 'dry-run'}):[/bold]")
    for step in plan.steps:
        if step.skip_reason:
            console.print(f"  [info]- SKIP {step.title}: {step.skip_reason}[/info]")
        else:
            console.print(f"  [change]- {step.title}[/change]")
    if not apply:
        console.print(
            "\n[info][init] Dry-run: мутаций не выполнено. "
            "Для установки добавьте --apply.[/info]"
        )
        return 0

    # Исполнение: fail-fast, без секретов в выводе.
    executed: list[Step] = []
    for step in plan.steps:
        if step.skip_reason:
            continue
        console.print(f"\n[info][init] Шаг: {step.title}[/info]")
        result = run_list(step.command, timeout=600)
        if not result.ok:
            tail = "\n".join((result.output or "").splitlines()[-20:])
            if tail:
                console.print(f"[error][init] Вывод шага (хвост):[/error]\n{tail}")
            console.print(
                f"[error][init] Шаг '{step.title}' упал (код {result.returncode}). "
                f"Докатить вручную: {' '.join(step.command)}[/error]"
            )
            for done in executed:
                console.print(f"  [warning]откат выполненного: {_ROLLBACK.get(done.name, '?')}[/warning]")
            return 1
        executed.append(step)
        if not _verify_step(step, (domain or "").strip() or None, state_path):
            console.print(
                f"[error][init] Шаг '{step.title}' вернул успех, но состояние "
                "не подтверждено (state/юнит/сертификат). Проверьте вручную: "
                f"{' '.join(step.command)}[/error]"
            )
            for done in executed:
                console.print(
                    f"  [warning]откат выполненного: "
                    f"{_ROLLBACK.get(done.name, '?')}[/warning]"
                )
            return 1
        console.print(f"[success][init] Шаг готов: {step.title}[/success]")

    if not executed:
        console.print(
            "[success][init] Все запрошенные компоненты уже установлены — "
            "изменений не требуется.[/success]"
        )

    if demo_clients:
        created = _demo_clients(proto_list, state_path)
        if created:
            console.print(f"[success][init] Демо-клиенты: {', '.join(created)}[/success]")

    _summary(proto_list, (domain or "").strip() or None, (cdn_domain or "").strip() or (domain or "").strip() or None)
    console.print("\n[success][init] Готово.[/success]")
    return 0
