"""`vds relay init` — идемпотентное развёртывание RU-relay (SPEC-20261114-ru-relay
WP-3, ADR-007 «Девиации v1»).

Поток: root-check → preflight (ports 443 tcp/udp, DNS relay-домена, ip_forward,
awg1-конфиг) → dry-run план (без секретов) → с apply=True: FileLock → шаги
ранбука DEPLOY-RU-RELAY.md Фаза 2 1:1:

 1. awg1-конфиг: --exit-conf → sanitize (Table=off, MTU) → /etc/amnezia/awg1.conf;
    без --exit-conf — печатается инструкция «перенести с asv1» (шаг skip,
    остальные шаги продолжаются — идемпотентно дотянуть позже).
 2. Xray Reality TCP 443 RU-SNI: переиспользование src/xray/install.run_install.
 3. AWG-сервер UDP 443: PPA-пакеты, header-чек и генерация ключей — хелперы
    src/amneziawg/install.py (переиспользование, не копирование); конфиг —
    render_relay_server_conf (подсеть 10.10.0.0/24, MTU 1280, порт 443);
    юнит vds-relay-awg из шаблона vds-amneziawg.service.tpl; ufw allow 443/udp.
 4. ip_forward=1 (runtime + persist 99-vds-relay-forward.conf).
 5. awg1-юнит vds-relay-exit (awg-quick up awg1.conf) — при валидном конфиге.
 6. MASQUERADE-юнит vds-relay-nat (awg1 + eth0).
 7. policy-юнит vds-relay-policy (nft-файл + ip rule fwmark + table 100);
    начальный RU-агрегат — через src.relay.cidr.update (сбой сети → пустой
    set + warning, таймер дотянет).
 8. CIDR-юнит + недельный таймер vds-relay-cidr.timer.
 9. метаданные в gateway store (protocols['relay'], без приватных ключей).

Fail-fast: первая ошибка — печать шага и exit 1; секреты не логируются.
"""

import ipaddress
import os
import random
import socket
import shutil
from pathlib import Path
from typing import Optional

from src.amneziawg.config import ServerParams, gen_obfuscation_params
from src.amneziawg.install import (
    _check_kernel_headers,
    _detect_wan_iface,
    _ensure_apt_packages,
    _gen_server_keys,
    _write_text_preserving_mode,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit
from src.gateway.store import load_state, save_state
from src.relay.config import RelayArgs, build_plan, render_relay_server_conf, sanitize_exit_conf
from src.relay.paths import (
    LOCK_FILE,
    RELAY_CONFIG_PATH,
    RELAY_DIR,
    RELAY_EXIT_CONFIG_PATH,
    RELAY_EXIT_IFACE,
    RELAY_EXIT_PORT,
    RELAY_EXIT_UNIT,
    RELAY_IFACE,
    RELAY_NAT_UNIT,
    RELAY_POLICY_UNIT,
    RELAY_PORT,
    RELAY_SUBNET,
    RELAY_SYSCTL_FORWARD_CONF,
    RELAY_UNIT,
)


class RelayInitError(Exception):
    """Сбой шага развёртывания релея (без traceback — печатается в CLI)."""


# ---------------------------------------------------------------------------
# Preflight (read-only)
# ---------------------------------------------------------------------------

def _check_ports() -> list[dict]:
    """Порты 443 TCP/UDP свободны? (preflight ДО любых изменений, паттерн E1)."""
    checks = []
    for proto in ("tcp", "udp"):
        if port_free(RELAY_PORT, proto):
            checks.append({"name": f"порт {RELAY_PORT}/{proto}", "ok": True, "detail": "свободен"})
        else:
            owner = port_owner(RELAY_PORT, proto)
            checks.append(
                {
                    "name": f"порт {RELAY_PORT}/{proto}",
                    "ok": False,
                    "detail": f"занят{f' (владелец: {owner})' if owner else ''} — "
                    "на релее он целевой (AWG udp/443 + Reality tcp/443); "
                    "освободите или пересмотрите закупку VDS",
                }
            )
    return checks


def _check_dns(domain: str) -> dict:
    """DNS relay-домена резолвится в публичный IP этого сервера? (Фаза 0 gate)."""
    ip = public_ip()
    if not domain:
        return {"name": "DNS relay-домена", "ok": False, "detail": "не задан --domain"}
    if not ip:
        return {"name": "DNS relay-домена", "ok": False, "detail": "публичный IP сервера не определён"}
    try:
        answers = {ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except OSError as exc:
        return {"name": "DNS relay-домена", "ok": False, "detail": f"{domain}: не резолвится ({exc})"}
    ok = ip in answers
    detail = (
        f"{domain} → {ip} (ok)"
        if ok
        else f"{domain} → {', '.join(sorted(answers)) or '?'} ≠ публичный IP {ip}. "
        "Проверьте A-запись (DNS-only/серое облако: CF-прокси не пропускает UDP)."
    )
    return {"name": "DNS relay-домена", "ok": ok, "detail": detail}


def _check_exit_conf(path: Optional[str]) -> dict:
    """awg1-конфиг: передан и валиден ([Interface] + PrivateKey)?"""
    if not path:
        return {
            "name": "awg1-конфиг",
            "ok": False,
            "detail": "не передан --exit-conf: сначала на asv1 выполните "
            "`vds amneziawg add-client relay` и заберите .conf",
        }
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return {"name": "awg1-конфиг", "ok": False, "detail": f"{path}: не читается ({exc})"}
    ok = "[Interface]" in text and "PrivateKey = " in text
    return {
        "name": "awg1-конфиг",
        "ok": ok,
        "detail": Path(path).name if ok else "файл без [Interface]/PrivateKey",
    }


def preflight_checks(args: RelayArgs) -> list[dict]:
    """Все read-only проверки; root НЕ проверяется здесь (см. run_init)."""
    checks: list[dict] = []
    checks.append({"name": "exit-IP", "ok": True, "detail": f"{args.exit_ip}:{args.exit_port} (asv1)"})
    checks.extend(_check_ports())
    checks.append(_check_dns(args.domain))
    checks.append(_check_exit_conf(args.exit_conf))
    return checks


# ---------------------------------------------------------------------------
# Шаги apply (под FileLock)
# ---------------------------------------------------------------------------

def _install_awg1_conf(args: RelayArgs) -> bool:
    """Шаг 1: sanitize + запись /etc/amnezia/awg1.conf. False — нет входа (skip)."""
    if not args.exit_conf:
        console.print(
            "[warning][relay] awg1-конфиг не передан (--exit-conf): на asv1 выполните "
            "`vds amneziawg add-client relay`, заберите .conf и перезапустите "
            "`sudo vds relay init --apply --exit-conf <путь>` — остальные шаги уже "
            "выполнены и повтор безопасен.[/warning]"
        )
        return False
    text = Path(args.exit_conf).read_text(encoding="utf-8")
    try:
        sanitized = sanitize_exit_conf(text, mtu=1420)
    except ValueError as exc:
        raise RelayInitError(str(exc)) from exc
    RELAY_EXIT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not write_secret_atomic(str(RELAY_EXIT_CONFIG_PATH), sanitized, mode=0o600):
        raise RelayInitError(f"Не удалось записать {RELAY_EXIT_CONFIG_PATH}.")
    console.print(
        f"[change][relay] awg1-конфиг установлен: {RELAY_EXIT_CONFIG_PATH} (0600, "
        "Table = off — маршруты ведёт vds-relay-policy через fwmark).[/change]"
    )
    return True


def _ensure_ip_forward_relay() -> None:
    """net.ipv4.ip_forward=1: runtime sysctl + persist в 99-vds-relay-forward.conf.

    Паттерн src/amneziawg/install.py, но с relay-именем файла (на релее
    модуль amneziawg-инсталлятора не выполняется, persist-путь несёт метку).
    """
    res = run_list(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=10)
    if not res.ok:
        raise RelayInitError(
            f"sysctl -w net.ipv4.ip_forward=1: {res.stderr.strip() or res.stdout.strip()}"
        )
    if RELAY_SYSCTL_FORWARD_CONF.is_file():
        existing = RELAY_SYSCTL_FORWARD_CONF.read_text(encoding="utf-8")
        if "net.ipv4.ip_forward" in existing:
            return
    RELAY_SYSCTL_FORWARD_CONF.parent.mkdir(parents=True, exist_ok=True)
    _write_text_preserving_mode(RELAY_SYSCTL_FORWARD_CONF, "net.ipv4.ip_forward = 1\n")
    console.print(
        f"[change][relay] ip_forward=1 применён и сохранён в {RELAY_SYSCTL_FORWARD_CONF}.[/change]"
    )


def _installed_awg_server() -> bool:
    """Идемпотентность: серверный конфиг + бинарник awg + юнит активны."""
    return (
        RELAY_CONFIG_PATH.is_file()
        and shutil.which("awg") is not None
        and run_list(["systemctl", "is-active", RELAY_UNIT], timeout=10).output == "active"
    )


def _install_awg_server(args: RelayArgs, state_path: Optional[str]) -> dict:
    """Шаг 3: AWG-сервер UDP 443 (подсеть 10.10.0.0/24, MTU 1280)."""
    if _installed_awg_server():
        state = load_state(state_path)
        meta = state.protocols.get("relay", {})
        console.print(
            "[success][relay] AWG-сервер уже установлен и активен — конфиг не "
            "переписывается (повторный init идемпотентен).[/success]"
        )
        return dict(meta)

    try:
        _check_kernel_headers()
        _ensure_apt_packages()
        private_key, public_key = _gen_server_keys()
        obf = gen_obfuscation_params(random.Random())
        rendered = render_relay_server_conf(
            ServerParams(
                private_key=private_key,
                address=f"{str(ipaddress.ip_network(RELAY_SUBNET).network_address + 1)}/24",
                port=RELAY_PORT,
                obf=obf,
            ),
            mtu=args.mtu,
        )
        RELAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not write_secret_atomic(str(RELAY_CONFIG_PATH), rendered, mode=0o600):
            raise RelayInitError(f"Не удалось записать {RELAY_CONFIG_PATH}.")
    except RelayInitError:
        raise
    except Exception as exc:  # apt/DKMS/ключи: читаемо оборачиваем (паттерн install.py)
        raise RelayInitError(f"AWG-сервер (apt/ключи/конфиг): {exc}") from exc

    if not install_unit(
        "vds-amneziawg.service.tpl",
        RELAY_UNIT,
        ctx={"config_path": str(RELAY_CONFIG_PATH), "iface": RELAY_IFACE},
    ):
        raise RelayInitError(f"Не удалось установить юнит {RELAY_UNIT}")

    if shutil.which("ufw"):
        ufw = run_list(["ufw", "allow", f"{RELAY_PORT}/udp"], timeout=30)
        if not ufw.ok:
            raise RelayInitError(f"ufw allow {RELAY_PORT}/udp: {ufw.stderr.strip()}")

    # stale-интерфейс после неудачного ExecStop (паттерн P14 amneziawg).
    if run_list(["ip", "link", "show", RELAY_IFACE], timeout=10).ok:
        run_list(["ip", "link", "del", RELAY_IFACE], timeout=10)

    enable = run_list(["systemctl", "enable", RELAY_UNIT], timeout=15)
    restart = run_list(["systemctl", "restart", RELAY_UNIT], timeout=60)
    if not (enable.ok and restart.ok):
        raise RelayInitError(
            f"{RELAY_UNIT} не запустился: {restart.stderr.strip() or enable.stderr.strip()}"
        )
    console.print(
        f"[success][relay] AWG-сервер: udp/{RELAY_PORT}, {RELAY_IFACE} ({RELAY_SUBNET}), "
        f"MTU {args.mtu}, юнит {RELAY_UNIT} активен.[/success]"
    )
    return {
        "installed": True,
        "port": RELAY_PORT,
        "iface": RELAY_IFACE,
        "subnet": RELAY_SUBNET,
        "mtu": args.mtu,
        "public_key": public_key,
        "obfuscation": obf,
        "psk_required": True,
    }


def _install_exit_unit() -> bool:
    """Шаг 5: юнит awg1 — только при валидном /etc/amnezia/awg1.conf."""
    if not RELAY_EXIT_CONFIG_PATH.is_file():
        console.print(
            "[warning][relay] /etc/amnezia/awg1.conf отсутствует — юнит "
            f"{RELAY_EXIT_UNIT} не устанавливается (перенесите конфиг с asv1 и "
            "повторите init --apply --exit-conf).[/warning]"
        )
        return False
    if not install_unit(
        "vds-relay-exit.service.tpl",
        RELAY_EXIT_UNIT,
        ctx={"config_path": str(RELAY_EXIT_CONFIG_PATH)},
    ):
        raise RelayInitError(f"Не удалось установить юнит {RELAY_EXIT_UNIT}")
    start = run_list(["systemctl", "restart", RELAY_EXIT_UNIT], timeout=30)
    if not start.ok:
        raise RelayInitError(f"{RELAY_EXIT_UNIT}: {start.stderr.strip() or start.stdout.strip()}")
    console.print(f"[change][relay] {RELAY_EXIT_UNIT}: нога {RELAY_EXIT_IFACE} поднята.[/change]")
    return True


def _install_nat_unit(wan_if: str) -> None:
    """Шаг 6: MASQUERADE awg0-подсети → awg1 и → eth0 (persist-юнит)."""
    if not install_unit(
        "vds-relay-nat.service.tpl",
        RELAY_NAT_UNIT,
        ctx={"client_subnet": RELAY_SUBNET, "exit_iface": RELAY_EXIT_IFACE, "wan_if": wan_if},
    ):
        raise RelayInitError(f"Не удалось установить юнит {RELAY_NAT_UNIT}")
    start = run_list(["systemctl", "start", RELAY_NAT_UNIT], timeout=30)
    if not start.ok:
        raise RelayInitError(
            f"{RELAY_NAT_UNIT}: {start.stderr.strip() or start.stdout.strip()}"
        )
    console.print(
        f"[change][relay] MASQUERADE {RELAY_SUBNET} → {RELAY_EXIT_IFACE} (к asv1) и "
        f"→ {wan_if} (RU-direct) активен и персистентен.[/change]"
    )


def _install_policy_and_cidr() -> None:
    """Шаги 7–8: nft-политика + ip rule + таблица 100 + еженедельный CIDR-таймер."""
    # Начальный агрегат: сбой сети → пустой set + warning (таймер дотянет).
    from src.relay.cidr import update as cidr_update  # лениво: requests в import-chain

    if cidr_update(timeout=30) != 0:
        console.print(
            "[warning][relay] RU-CIDR не загружен (сеть/источник) — ставится "
            "пустой ru_cidr: ВСЁ из awg0 уйдёт через awg1; таймер обновит при "
            "первом успехе.[/warning]"
        )
        RELAY_DIR.mkdir(parents=True, exist_ok=True)
        from src.relay.config import render_nft_policy

        _write_text_preserving_mode(RELAY_DIR / "nft-policy.conf", render_nft_policy([]))

    if not install_unit(
        "vds-relay-policy.service.tpl",
        RELAY_POLICY_UNIT,
        ctx={"nft_file": str(RELAY_DIR / "nft-policy.conf"), "mark": "0x1", "table": "100",
             "exit_iface": RELAY_EXIT_IFACE},
    ):
        raise RelayInitError(f"Не удалось установить юнит {RELAY_POLICY_UNIT}")
    start = run_list(["systemctl", "start", RELAY_POLICY_UNIT], timeout=30)
    if not start.ok:
        raise RelayInitError(f"{RELAY_POLICY_UNIT}: {start.stderr.strip() or start.stdout.strip()}")

    python = shutil.which("python3") or "/usr/bin/python3"
    repo_dir = Path(__file__).resolve().parents[2]
    if not install_unit(
        "vds-relay-cidr.service.tpl",
        "vds-relay-cidr.service",
        ctx={"python": python, "repo_dir": str(repo_dir), "install_dir": str(Path(os.environ.get("INSTALL_DIR", "/opt/my-vds")))},
    ):
        raise RelayInitError("Не удалось установить vds-relay-cidr.service")
    if not install_unit("vds-relay-cidr.timer.tpl", "vds-relay-cidr.timer"):
        raise RelayInitError("Не удалось установить vds-relay-cidr.timer")
    timer = run_list(["systemctl", "enable", "--now", "vds-relay-cidr.timer"], timeout=15)
    if not timer.ok:
        console.print(
            f"[warning][relay] vds-relay-cidr.timer не включён: "
            f"{timer.stderr.strip()} — включите вручную.[/warning]"
        )
    console.print(
        f"[change][relay] policy-routing активен: mark 0x1 → table 100 → "
        f"dev {RELAY_EXIT_IFACE}; RU-CIDR таймер еженедельно.[/change]"
    )


def _save_relay_state(args: RelayArgs, awg_meta: dict, exit_conf_ok: bool,
                      wan_if: str, state_path: Optional[str]) -> None:
    """Шаг 9: метаданные релея в gateway store (без приватных ключей)."""
    state = load_state(state_path)
    state.protocols["relay"] = {
        "installed": True,
        "domain": args.domain,
        "exit_ip": args.exit_ip,
        "exit_port": args.exit_port,
        "sni": args.sni,
        "exit_conf_ok": exit_conf_ok,
        "wan_if": wan_if,
        **awg_meta,
    }
    save_state(state, state_path)


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def run_init(
    exit_ip: str,
    domain: str,
    sni: str,
    exit_conf: Optional[str] = None,
    apply: bool = False,
    state_path: Optional[str] = None,
) -> int:
    """CLI-вход `vds relay init`. 0 — успех (dry-run тоже 0 при валидных входах)."""
    args = RelayArgs(exit_ip=exit_ip, domain=domain, sni=sni, exit_conf=exit_conf)

    if not args.exit_ip:
        console.print("[error][relay] Обязателен --exit <asv1-ip>.[/error]")
        return 1
    try:
        ipaddress.ip_address(args.exit_ip)
    except ValueError:
        console.print(f"[error][relay] --exit должен быть IPv4-адресом, получено {args.exit_ip!r}.[/error]")
        return 1

    checks = preflight_checks(args)
    port_ok = all(c["ok"] for c in checks if c["name"].startswith("порт"))
    plan = build_plan(args, checks, exit_conf_ok=bool(args.exit_conf))

    console.print("[info][relay] План развёртывания RU-relay (ADR-007 v1):[/info]")
    for item in plan:
        mark = "[success]ok[/success]" if item.get("ok", True) else "[warning]warn[/warning]"
        console.print(f"  - {mark} {item['step']}: {item['name']} — {item['detail']}")

    if not apply:
        if not port_ok:
            console.print(
                "[error][relay] Preflight: целевые порты 443 заняты — dry-run "
                "останавливается здесь (мутаций нет).[/error]"
            )
            return 1
        console.print("[info][relay] Dry-run: мутаций нет. Реальное исполнение — --apply.[/info]")
        return 0

    if os.geteuid() != 0:
        console.print("[error][relay] --apply требует root (запустите через sudo).[/error]")
        return 1
    if not port_ok:
        console.print(
            "[error][relay] Применение отменено: порт(ы) 443 заняты — освободите и повторите.[/error]"
        )
        return 1

    with FileLock(LOCK_FILE):
        try:
            exit_conf_ok = _install_awg1_conf(args)

            from src.xray.install import run_install as xray_run_install  # лениво: тяжёлые импорты

            if xray_run_install(sni=args.sni) != 0:
                raise RelayInitError(
                    "Xray Reality не установлен (см. вывод шага xray) — стоп "
                    "(Reality — фолбэк-нога, SPEC R1)."
                )

            awg_meta = _install_awg_server(args, state_path)
            _ensure_ip_forward_relay()
            _install_exit_unit()
            wan_if = _detect_wan_iface()
            _install_nat_unit(wan_if)
            _install_policy_and_cidr()
            _save_relay_state(args, awg_meta, exit_conf_ok, wan_if, state_path)
        except RelayInitError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1
        except (OSError, RuntimeError) as exc:
            console.print(f"[error][relay] Непредвиденная ошибка шага: {exc}[/error]")
            return 1

    console.print(
        f"[success][relay] RU-relay развёрнут. Клиенты: `sudo vds relay add-client NAME`; "
        f"endpoint {args.domain or 'relay-домен'}:{RELAY_PORT}; проверки — "
        "docs/DEPLOY-RU-RELAY.md (curl --interface awg1 ifconfig.me и т.д.).[/success]"
    )
    return 0
