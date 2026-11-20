"""`vds relay exit-leg` — выделенная нога relay→exit на exit-узле (ADR-015, P24).

Отдельный от клиентского `awg0` интерфейс `awg2` (10.11.0.0/30):
exit — 10.11.0.1, релей — 10.11.0.2 (единственный пир). Порт ноги изолирован
от клиентских пиров:

  * UFW открывает ровно `P_base` (51900/udp) и только с `saddr == <relay-ip>`;
  * весь пул 51900–51911 доступен релею через nft REDIRECT (`prerouting`,
    priority dstnat) на `P_base`; с чужого адреса — тихий drop в той же
    nat-цепочке;
  * правила персистентны: oneshot-юнит `vds-awg-relay-pool.service` применяет
    nft-файл и UFW-правило заново после ребута.

Клиентский `awg0` (51825/udp) и пиры 10.9.0.2–10.9.0.4 не трогаются; на
релее команда отказывает (ADR-015 «граница доверия»: релей не получает прав
на exit, WP-M3 работает только с локальным endpoint).

Dry-run по умолчанию; мутации — `--apply` под `core.lock.FileLock`.
Секреты: приватный ключ awg2 живёт только в `/etc/amnezia/awg2.conf` (0600)
и не попадает ни в вывод, ни в state (там только публичный ключ релея).
"""

from __future__ import annotations

import ipaddress
import os
import random
import shutil
from pathlib import Path
from typing import Optional

from src.amneziawg.config import (
    PERSISTENT_KEEPALIVE,
    ServerParams,
    ServerPeer,
    gen_obfuscation_params,
    render_server_conf,
)
from src.amneziawg.install import _gen_server_keys
from src.core.lock import FileLock
from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit, unit_active
from src.gateway.paths import AWG_CONFIG_PATH
from src.gateway.store import GatewayState, load_state, save_state
from src.relay.paths import (
    EXIT_LEG_BASE_PORT,
    EXIT_LEG_CONFIG_PATH,
    EXIT_LEG_IFACE,
    EXIT_LEG_IP,
    EXIT_LEG_LOCK_FILE,
    EXIT_LEG_MTU,
    EXIT_LEG_NFT_FILE,
    EXIT_LEG_NFT_TABLE,
    EXIT_LEG_PEER_IP,
    EXIT_LEG_POOL,
    EXIT_LEG_POOL_SCRIPT,
    EXIT_LEG_POOL_UNIT,
    EXIT_LEG_SUBNET,
    EXIT_LEG_UNIT,
    RELAY_EXIT_CONFIG_PATH,
)


class ExitLegError(Exception):
    """Сбой шага exit-leg (печатается в CLI без traceback)."""


# ---------------------------------------------------------------------------
# Валидация входов и разбор пула
# ---------------------------------------------------------------------------

def parse_pool(pool: str = EXIT_LEG_POOL) -> list[int]:
    """'51900-51911' → [51900, …, 51911]; мусор/пусто/вне 1024-65535 → ValueError."""
    parts = (pool or "").strip().split("-")
    if len(parts) != 2 or not all(p.strip().isdigit() for p in parts):
        raise ValueError(f"Некорректный пул {pool!r}: ожидался формат START-END.")
    start, end = int(parts[0]), int(parts[1])
    if start > end:
        raise ValueError(f"Пул {pool!r}: начало больше конца.")
    if not (1024 <= start <= 65535) or not (1024 <= end <= 65535):
        raise ValueError(f"Пул {pool!r}: порты должны быть в 1024-65535.")
    return list(range(start, end + 1))


def validate_relay_ip(relay_ip: str) -> str:
    """Публичный IPv4 релея — единственный разрешённый saddr. Иначе ExitLegError."""
    try:
        ip = ipaddress.ip_address((relay_ip or "").strip())
    except ValueError as exc:
        raise ExitLegError(
            f"--relay-ip должен быть IPv4-адресом, получено {relay_ip!r}."
        ) from exc
    if ip.version != 4:
        raise ExitLegError(
            f"--relay-ip: нога awg2 — IPv4 (10.11.0.0/30), получено {relay_ip!r}."
        )
    return str(ip)


def validate_public_key(public_key: str) -> str:
    """Публичный ключ релея: один непустой токен (ключ не секрет, маскировать не нужно)."""
    key = (public_key or "").strip()
    if not key or len(key.split()) != 1:
        raise ExitLegError(
            "--public-key: ожидался публичный ключ релея (один токен без пробелов)."
        )
    return key


def exit_node_violation(state: GatewayState) -> Optional[str]:
    """`None` — узел exit; строка — причина отказа (релей / не тот узел)."""
    if (state.protocols.get("relay") or {}).get("installed"):
        return (
            "этот узел — RU-релей (state.protocols['relay'] установлен), а не exit. "
            "`vds relay exit-leg` выполняется только на exit-ноде: релей не получает "
            "прав на exit (ADR-015 «граница доверия»); его сторона — манёвр endpoint (WP-M3)."
        )
    relay_marker = Path(RELAY_EXIT_CONFIG_PATH)
    if relay_marker.is_file():
        # Вторая линия: awg1.conf — клиентская нога релея (relay init), на exit
        # её не бывает. Ловит случаи, когда state релея утерян/пуст.
        return (
            f"обнаружена клиентская нога релея ({relay_marker}) — это RU-релей, "
            "а не exit. `vds relay exit-leg` на релее отказывает (ADR-015 "
            "«граница доверия»)."
        )
    if not Path(AWG_CONFIG_PATH).is_file():
        return (
            f"не найден {AWG_CONFIG_PATH}: узел не похож на exit-ноду "
            "(клиентский AWG-сервер awg0 отсутствует). exit-leg ставится только на exit."
        )
    return None


# ---------------------------------------------------------------------------
# Чистые рендеры (детерминированные; контракт unit-тестов)
# ---------------------------------------------------------------------------

def render_exit_leg_conf(
    *,
    private_key: str,
    public_key: str,
    obf: dict,
    mtu: int = EXIT_LEG_MTU,
) -> str:
    """awg-quick .conf для awg2 (0600): один пир — публичный ключ релея.

    Переиспользует `render_server_conf` (валидация 1.5-обфускации, детерминизм)
    и вставляет MTU после ListenPort — как `render_relay_server_conf` у awg0.
    PersistentKeepalive = 25 на пире (ADR-015 п.5): exit держит метроном к релею.
    """
    base = render_server_conf(
        ServerParams(
            private_key=private_key,
            address=f"{EXIT_LEG_IP}/30",
            port=EXIT_LEG_BASE_PORT,
            obf=obf,
            peers=(
                ServerPeer(
                    public_key=public_key,
                    allowed_ips=f"{EXIT_LEG_PEER_IP}/32",
                    name="relay-exit-leg",
                    keepalive=PERSISTENT_KEEPALIVE,
                ),
            ),
        )
    )
    out: list[str] = []
    for line in base.split("\n"):
        out.append(line)
        if line.startswith("ListenPort = "):
            out.append(f"MTU = {mtu}")
    return "\n".join(out)


def render_nft_leg(
    relay_ip: str,
    *,
    pool: str = EXIT_LEG_POOL,
    base_port: int = EXIT_LEG_BASE_PORT,
    table: str = EXIT_LEG_NFT_TABLE,
) -> str:
    """nft-файл пула: REDIRECT с saddr релея на P_base + тихий drop для прочих.

    Таблица `inet <table>` — только nat-цепочка prerouting (priority dstnat):
    DNAT-стадия выполняется до filter/UFW, поэтому UFW открывает один порт
    (P_base), а не весь пул. Декларация `table` + `flush table` делает
    применение файла идемпотентным (`nft -f` перезаписывает таблицу).
    """
    ip = validate_relay_ip(relay_ip)
    ports = parse_pool(pool)  # валидация формата
    first, last = ports[0], ports[-1]
    return (
        "#!/usr/sbin/nft -f\n"
        "# VDS relay exit-leg port pool (ADR-015, P24). Генерируется\n"
        "# `vds relay exit-leg install` — руками на сервере не править.\n"
        f"table inet {table}\n"
        f"flush table inet {table}\n"
        f"table inet {table} {{\n"
        "    chain prerouting {\n"
        "        type nat hook prerouting priority dstnat; policy accept;\n"
        f"        ip saddr {ip} udp dport {first}-{last} redirect to :{base_port}\n"
        f"        udp dport {first}-{last} drop\n"
        "    }\n"
        "}\n"
    )


def render_pool_script(
    relay_ip: str,
    *,
    nft_file: Path = EXIT_LEG_NFT_FILE,
    base_port: int = EXIT_LEG_BASE_PORT,
) -> str:
    """Идемпотентный apply-скрипт пула (0755, без секретов) для oneshot-юнита.

    Применяет nft-файл целиком и (если ufw есть) открывает ровно P_base с
    saddr релея. Повторный запуск — no-op (nft перезаписывает таблицу, ufw
    пропускает существующее правило).
    """
    ip = validate_relay_ip(relay_ip)
    return (
        "#!/bin/sh\n"
        "# VDS exit-leg port pool (ADR-015). Артефакт `vds relay exit-leg install`\n"
        "# — перегенерируется командой; руками на сервере не править.\n"
        "set -eu\n"
        f"nft -f {nft_file}\n"
        "if command -v ufw >/dev/null 2>&1; then\n"
        f"    ufw allow from {ip} to any port {base_port} proto udp >/dev/null\n"
        "fi\n"
    )


def build_plan(relay_ip: str, public_key: str, *, config_exists: bool) -> list[dict]:
    """Dry-run план exit-leg; порядок = порядок исполнения apply."""
    key_hint = public_key if len(public_key) <= 12 else f"{public_key[:8]}…"
    return [
        {
            "step": "awg2-conf",
            "name": f"awg2-конфиг ({EXIT_LEG_CONFIG_PATH})",
            "detail": (
                "существующий конфиг переиспользуется, ключи не перегенерируются"
                if config_exists
                else f"генерация ключей + обфускации (1.5), {EXIT_LEG_SUBNET}, "
                f"exit {EXIT_LEG_IP}, пир {EXIT_LEG_PEER_IP} ({key_hint}), "
                f"P_base {EXIT_LEG_BASE_PORT}/udp, keepalive {PERSISTENT_KEEPALIVE}"
            ),
        },
        {
            "step": "unit",
            "name": f"юнит {EXIT_LEG_UNIT}",
            "detail": f"awg-quick up {EXIT_LEG_CONFIG_PATH}",
        },
        {
            "step": "nft",
            "name": f"nft table inet {EXIT_LEG_NFT_TABLE} ({EXIT_LEG_NFT_FILE})",
            "detail": (
                f"udp {EXIT_LEG_POOL} saddr {relay_ip} → redirect :{EXIT_LEG_BASE_PORT}; "
                "прочие saddr — drop"
            ),
        },
        {
            "step": "ufw",
            "name": f"UFW: {EXIT_LEG_BASE_PORT}/udp только с {relay_ip}",
            "detail": "один порт (P_base); пул открывается не в фильтре, а REDIRECT'ом",
        },
        {
            "step": "pool-unit",
            "name": f"юнит {EXIT_LEG_POOL_UNIT}",
            "detail": f"oneshot: nft -f {EXIT_LEG_NFT_FILE} + ufw (персистентность ребута)",
        },
        {
            "step": "state",
            "name": "метаданные в gateway store",
            "detail": "protocols['relay_leg'] (без приватного ключа)",
        },
    ]


# ---------------------------------------------------------------------------
# Apply-хелперы
# ---------------------------------------------------------------------------

def _write_if_changed(path: Path, text: str, mode: int) -> bool:
    """Атомарно записать файл, если содержимое изменилось. True — перезаписан."""
    try:
        if path.is_file() and path.read_text(encoding="utf-8") == text:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    return True


def _ufw_allow(relay_ip: str) -> None:
    """Идемпотентно: ufw пропускает существующее правило."""
    if not _ufw_present():
        console.print(
            f"[warning][relay] ufw не найден — правило {EXIT_LEG_BASE_PORT}/udp не "
            "добавлено; проверьте фильтр вручную.[/warning]"
        )
        return
    res = run_list(
        ["ufw", "allow", "from", relay_ip, "to", "any",
         "port", str(EXIT_LEG_BASE_PORT), "proto", "udp"],
        timeout=30,
    )
    if not res.ok:
        raise ExitLegError(
            f"ufw allow from {relay_ip} to any port {EXIT_LEG_BASE_PORT} proto udp: "
            f"{res.stderr.strip() or res.stdout.strip()}"
        )


def _ufw_delete(relay_ip: str) -> None:
    """Снять UFW-правило; отсутствие правила — не ошибка (идемпотентный remove)."""
    if not _ufw_present():
        return
    res = run_list(
        ["ufw", "delete", "allow", "from", relay_ip, "to", "any",
         "port", str(EXIT_LEG_BASE_PORT), "proto", "udp"],
        timeout=30,
    )
    if not res.ok:
        console.print(
            "[warning][relay] UFW-правило exit-leg не найдено (вероятно, уже снято).[/warning]"
        )


def _ufw_present() -> bool:
    return shutil.which("ufw") is not None


def _nft_delete_table() -> bool:
    """Удалить нашу таблицу, если она есть. True — таблица была и удалена."""
    exists = run_list(["nft", "list", "table", "inet", EXIT_LEG_NFT_TABLE], timeout=10).ok
    if not exists:
        return False
    res = run_list(["nft", "delete", "table", "inet", EXIT_LEG_NFT_TABLE], timeout=10)
    if not res.ok:
        raise ExitLegError(
            f"nft delete table inet {EXIT_LEG_NFT_TABLE}: "
            f"{res.stderr.strip() or res.stdout.strip()}"
        )
    return True


def _leg_state(relay_ip: str, public_key: str) -> dict:
    """Метаданные §3.3 SPEC — без приватного ключа."""
    return {
        "iface": EXIT_LEG_IFACE,
        "subnet": EXIT_LEG_SUBNET,
        "exit_ip": EXIT_LEG_IP,
        "peer_ip": EXIT_LEG_PEER_IP,
        "base_port": EXIT_LEG_BASE_PORT,
        "pool": EXIT_LEG_POOL,
        "relay_ip": relay_ip,
        "public_key": public_key,
        "installed": True,
    }


def _install_locked(relay_ip: str, public_key: str, state_path: Optional[str]) -> None:
    """Шаги apply под FileLock: конфиг → юнит awg2 → nft/ufw → state."""
    config = Path(EXIT_LEG_CONFIG_PATH)
    if not config.is_file():
        private_key, _exit_public = _gen_server_keys()
        rendered = render_exit_leg_conf(
            private_key=private_key,
            public_key=public_key,
            obf=gen_obfuscation_params(random.Random()),
        )
        config.parent.mkdir(parents=True, exist_ok=True)
        if not write_secret_atomic(str(config), rendered, mode=0o600):
            raise ExitLegError(f"Не удалось записать {config} (0600).")
        console.print(
            f"[change][relay] awg2-конфиг установлен: {config} (0600, "
            f"{EXIT_LEG_SUBNET}, P_base {EXIT_LEG_BASE_PORT}/udp).[/change]"
        )
    else:
        console.print(
            f"[info][relay] {config} уже есть — переиспользуется "
            "(ключи не перегенерируются; повторный apply идемпотентен).[/info]"
        )

    nft_changed = _write_if_changed(
        Path(EXIT_LEG_NFT_FILE), render_nft_leg(relay_ip), 0o644
    )
    script_changed = _write_if_changed(
        Path(EXIT_LEG_POOL_SCRIPT), render_pool_script(relay_ip), 0o755
    )

    if not install_unit(
        "vds-awg-relay.service.tpl",
        EXIT_LEG_UNIT,
        ctx={"config_path": str(EXIT_LEG_CONFIG_PATH)},
    ):
        raise ExitLegError(f"Не удалось установить юнит {EXIT_LEG_UNIT}.")

    if not unit_active(EXIT_LEG_UNIT):
        # stale-интерфейс после неудачного ExecStop (паттерн P14 amneziawg).
        if run_list(["ip", "link", "show", EXIT_LEG_IFACE], timeout=10).ok:
            run_list(["ip", "link", "del", EXIT_LEG_IFACE], timeout=10)
        started = run_list(["systemctl", "restart", EXIT_LEG_UNIT], timeout=60)
        if not started.ok:
            raise ExitLegError(
                f"{EXIT_LEG_UNIT} не запустился: "
                f"{started.stderr.strip() or started.stdout.strip()}"
            )
        console.print(f"[change][relay] {EXIT_LEG_UNIT}: {EXIT_LEG_IFACE} поднят.[/change]")
    else:
        console.print(f"[info][relay] {EXIT_LEG_IFACE} уже активен — не перезапускается.[/info]")

    if not install_unit(
        "vds-awg-relay-pool.service.tpl",
        EXIT_LEG_POOL_UNIT,
        ctx={"script_path": str(EXIT_LEG_POOL_SCRIPT)},
    ):
        raise ExitLegError(f"Не удалось установить юнит {EXIT_LEG_POOL_UNIT}.")

    if nft_changed or script_changed or not unit_active(EXIT_LEG_POOL_UNIT):
        applied = run_list(["systemctl", "restart", EXIT_LEG_POOL_UNIT], timeout=30)
        if not applied.ok:
            raise ExitLegError(
                f"{EXIT_LEG_POOL_UNIT}: {applied.stderr.strip() or applied.stdout.strip()}"
            )
        console.print(
            f"[change][relay] пул {EXIT_LEG_POOL} → :{EXIT_LEG_BASE_PORT} "
            f"(saddr {relay_ip}) и UFW-правило применены.[/change]"
        )
    else:
        console.print("[info][relay] nft/ufw-правила пула без изменений.[/info]")

    _ufw_allow(relay_ip)

    state = load_state(state_path)
    state.protocols["relay_leg"] = _leg_state(relay_ip, public_key)
    if not save_state(state, state_path):
        raise ExitLegError("Не удалось сохранить state.protocols['relay_leg'].")


# ---------------------------------------------------------------------------
# Точки входа CLI
# ---------------------------------------------------------------------------

def run_install(
    relay_ip: str,
    public_key: str,
    apply: bool = False,
    state_path: Optional[str] = None,
) -> int:
    """`vds relay exit-leg install`. 0 — успех (dry-run тоже 0 при валидных входах)."""
    try:
        ip = validate_relay_ip(relay_ip)
        key = validate_public_key(public_key)
        parse_pool()
    except (ExitLegError, ValueError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    violation = exit_node_violation(load_state(state_path))
    if violation:
        console.print(f"[error][relay] {violation}[/error]")
        return 1

    config_exists = Path(EXIT_LEG_CONFIG_PATH).is_file()
    console.print("[info][relay] План exit-leg (ADR-015, P24):[/info]")
    for item in build_plan(ip, key, config_exists=config_exists):
        console.print(f"  - {item['step']}: {item['name']} — {item['detail']}")

    if not apply:
        console.print("[info][relay] Dry-run: мутаций нет. Реальное исполнение — --apply.[/info]")
        return 0

    if os.geteuid() != 0:
        console.print("[error][relay] --apply требует root (запустите через sudo).[/error]")
        return 1

    with FileLock(EXIT_LEG_LOCK_FILE):
        try:
            _install_locked(ip, key, state_path)
        except ExitLegError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1
        except OSError as exc:
            console.print(f"[error][relay] Файловая операция не удалась: {exc}[/error]")
            return 1

    console.print(
        f"[success][relay] exit-leg установлен: {EXIT_LEG_IFACE} ({EXIT_LEG_SUBNET}), "
        f"пул {EXIT_LEG_POOL}/udp с {ip}, клиентский awg0 не тронут.[/success]"
    )
    return 0


def run_remove(apply: bool = False, state_path: Optional[str] = None) -> int:
    """`vds relay exit-leg remove`: юниты, nft-таблица, UFW-правило, файлы, state."""
    state = load_state(state_path)
    meta = dict(state.protocols.get("relay_leg") or {})
    config_present = Path(EXIT_LEG_CONFIG_PATH).is_file()
    if not meta.get("installed") and not config_present:
        console.print("[info][relay] exit-leg не установлен — удалять нечего.[/info]")
        return 0

    relay_ip = str(meta.get("relay_ip") or "")
    console.print("[info][relay] План удаления exit-leg:[/info]")
    console.print(
        f"  - units: остановить и удалить {EXIT_LEG_POOL_UNIT}, {EXIT_LEG_UNIT}"
    )
    console.print(f"  - nft: удалить table inet {EXIT_LEG_NFT_TABLE}")
    console.print(
        f"  - ufw: снять allow {'from ' + relay_ip + ' ' if relay_ip else ''}"
        f"port {EXIT_LEG_BASE_PORT}/udp"
    )
    console.print(
        f"  - files: {EXIT_LEG_CONFIG_PATH} (0600), {EXIT_LEG_NFT_FILE}, "
        f"{EXIT_LEG_POOL_SCRIPT}"
    )
    console.print("  - state: удалить protocols['relay_leg']")

    if not apply:
        console.print("[info][relay] Dry-run: мутаций нет. Реальное исполнение — --apply.[/info]")
        return 0

    if os.geteuid() != 0:
        console.print("[error][relay] --apply требует root (запустите через sudo).[/error]")
        return 1

    with FileLock(EXIT_LEG_LOCK_FILE):
        try:
            if not remove_unit(EXIT_LEG_POOL_UNIT):
                raise ExitLegError(f"Не удалось удалить {EXIT_LEG_POOL_UNIT}.")
            if not remove_unit(EXIT_LEG_UNIT):
                raise ExitLegError(f"Не удалось удалить {EXIT_LEG_UNIT}.")
            _nft_delete_table()
            if relay_ip:
                _ufw_delete(relay_ip)
            for path in (EXIT_LEG_CONFIG_PATH, EXIT_LEG_NFT_FILE, EXIT_LEG_POOL_SCRIPT):
                Path(path).unlink(missing_ok=True)
            fresh = load_state(state_path)
            fresh.protocols.pop("relay_leg", None)
            if not save_state(fresh, state_path):
                raise ExitLegError("Не удалось обновить state (protocols['relay_leg']).")
        except ExitLegError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1

    console.print(
        f"[success][relay] exit-leg удалён: {EXIT_LEG_IFACE}, пул {EXIT_LEG_POOL} "
        "и UFW-правило сняты; клиентский awg0 не тронут.[/success]"
    )
    return 0
