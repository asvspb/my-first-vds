"""Установка AmneziaWG (SPEC-20261110, ADR-005: PPA ppa:amnezia/ppa → apt).

Поток `vds amneziawg install`: root-check → идемпотентность (пакеты+конфиг
на месте — «уже установлен», exit 0) → port_free(port, udp) ДО любых
изменений (E1: порт занят — отказ до изменений) → FileLock →
apt: software-properties-common (при отсутствии) → add-apt-repository -y
ppa:amnezia/ppa → apt-get update → apt-get install -y amneziawg-tools
amneziawg-dkms → apt-mark hold (пин, E9-устойчивость) → ключи сервера
(`awg genkey`, `awg pubkey`; бинарника `awg` ещё нет до apt — генерация
строго после установки) → obfuscation-параметры (config.py WP-1) → рендер
серверного .conf → write_secret_atomic 0600 → юнит из
systemd/vds-amneziawg.service.tpl → ufw allow <port>/udp (при наличии ufw,
паттерн src/wireguard/install.py) → systemctl enable+restart →
метаданные в gateway store (public_key, obfuscation, psk_required-флаг;
приватный ключ — только в /etc/amnezia/awg0.conf).

Никаких обращений к github/mirror-логике (E2 не применим — ADR-005).
Второй root-check и port-check до apt: «уже установлен» проверяется раньше
порта — активный сервис awg0 сам владеет udp-портом (регрессия P11-паттерн
hysteria2). Реальный apt/PPA не запускается в тестах (WP-6 на asv1).
"""

import os
import platform
import random
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from src.amneziawg.config import (
    ServerParams,
    gen_obfuscation_params,
    render_server_conf,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.secrets import write_secret_atomic
from src.core.shell import ShellResult, run_list
from src.core.units import install_unit
from src.gateway.paths import (
    AWG_ADDRESS_SUBNET,
    AWG_CONFIG_PATH,
    AWG_IFACE,
    AWG_PORT_DEFAULT,
    AWG_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

# ADR-005: пакеты ТОЛЬКО из PPA amnezia (не github, не mirror-конвенция).
AWG_PPA = "ppa:amnezia/ppa"
AWG_APT_PACKAGES = ("amneziawg-tools", "amneziawg-dkms")
LOCK_FILE = "/var/run/vds-amneziawg.lock"

# Серверный адрес в подсети 10.9.0.0/24 (SPEC §3: .1 — сервер, .x — клиенты).
AWG_SERVER_ADDRESS = "10.9.0.1/24"


class InstallError(Exception):
    """Сбой установки AmneziaWG (apt/PPA недоступен, ключи, конфиг, юнит)."""


def _run_checked(args: list[str], timeout: int, what: str) -> ShellResult:
    """run_list с читаемой ошибкой InstallError при неуспехе (без traceback)."""
    result = run_list(args, timeout=timeout)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or f"rc={result.returncode}"
        raise InstallError(f"{what}: {detail}")
    return result


def _installed() -> bool:
    """Установлен ли уже AWG (конфиг сервера + бинарник awg на месте)."""
    return AWG_CONFIG_PATH.is_file() and shutil.which("awg") is not None


def _ensure_apt_packages() -> None:
    """PPA + apt-пакеты amneziawg-tools/amneziawg-dkms + apt-mark hold.

    E1 (PPA/apt недоступен): отказ до каких-либо изменений в системе gateway
    (ключи/конфиг/юнит/state ещё не созданы); apt сам атомарен — повторный
    запуск докатывает (E9).
    """
    sw_props = run_list(
        ["dpkg", "-s", "software-properties-common"], timeout=30
    )
    if not sw_props.ok:
        console.print(
            "[info][amneziawg] Устанавливается software-properties-common…[/info]"
        )
        _run_checked(
            ["apt-get", "install", "-y", "software-properties-common"],
            timeout=300,
            what="apt-get install software-properties-common",
        )

    _run_checked(
        ["add-apt-repository", "-y", AWG_PPA],
        timeout=120,
        what=f"add-apt-repository {AWG_PPA} (E1: PPA недоступен с сервера)",
    )
    _run_checked(["apt-get", "update"], timeout=300, what="apt-get update")
    _run_checked(
        ["apt-get", "install", "-y", *AWG_APT_PACKAGES],
        timeout=600,
        what=f"apt-get install {' '.join(AWG_APT_PACKAGES)}",
    )
    # Пин версии (SPEC §3): apt-mark hold — apt upgrade не сносит DKMS-модуль.
    _run_checked(
        ["apt-mark", "hold", *AWG_APT_PACKAGES],
        timeout=30,
        what="apt-mark hold (пин amneziawg-пакетов)",
    )
    console.print(
        f"[change][amneziawg] Пакеты {'/'.join(AWG_APT_PACKAGES)} установлены "
        f"из {AWG_PPA} и запинены (apt-mark hold).[/change]"
    )


def _check_kernel_headers() -> None:
    """Предупредить об отсутствии linux-headers текущего ядра (DKMS не соберётся).

    Неблокирующая проверка (SPEC §8, риск P2): отказ дать может только сама
    DKMS-сборка при apt install.
    """
    release = platform.release()
    result = run_list(["dpkg", "-s", f"linux-headers-{release}"], timeout=15)
    if not result.ok:
        console.print(
            f"[warning][amneziawg] linux-headers-{release} не найден — "
            "DKMS-модуль amneziawg может не собраться. "
            f"Установите: apt install linux-headers-{release}[/warning]"
        )


def _gen_server_keys() -> tuple[str, str]:
    """Серверная пара ключей: (private_key, public_key) через `awg genkey/pubkey`.

    Приватный ключ проходит через tmp-файл 0600 только для `awg pubkey < file`
    (stdin-редирект); файл удаляется вместе с tmp-каталогом. Вызывается
    строго ПОСЛЕ apt-установки — бинарника `awg` до неё не существует.
    """
    priv_res = _run_checked(["awg", "genkey"], timeout=10, what="awg genkey")
    priv = priv_res.output
    with tempfile.TemporaryDirectory(prefix="vds-awg-") as tmp:
        priv_file = Path(tmp) / "server-priv.tmp"
        try:
            fd = os.open(priv_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(priv + "\n")
        except OSError as exc:
            raise InstallError(f"Не удалось записать tmp-файл ключа: {exc}") from exc
        pub_res = _run_checked(
            ["sh", "-c", f"awg pubkey < {shlex.quote(str(priv_file))}"],
            timeout=10,
            what="awg pubkey",
        )
    return priv, pub_res.output


def _pkg_version() -> str:
    """Версия установленного amneziawg-tools (для state.protocols)."""
    result = run_list(
        ["dpkg-query", "-W", "-f=${Version}", "amneziawg-tools"], timeout=10
    )
    return result.output if result.ok else ""


def _write_config(private_key: str, port: int, obf: dict) -> None:
    """Срендерить и атомарно записать серверный .conf (0600, E10)."""
    rendered = render_server_conf(
        ServerParams(private_key=private_key, address=AWG_SERVER_ADDRESS, port=port, obf=obf)
    )
    AWG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not write_secret_atomic(str(AWG_CONFIG_PATH), rendered, mode=0o600):
        raise InstallError(f"Не удалось записать {AWG_CONFIG_PATH}.")


def _save_state_meta(
    port: int,
    public_key: str,
    obf: dict,
    pkg_version: str,
    state_path: Optional[str],
) -> None:
    """Метаданные amneziawg в gateway store.

    public_key — не секрет; приватный ключ и PSK сюда НЕ попадают
    (приватный — только /etc/amnezia/awg0.conf 0600, PSK — per-client в WP-3).
    """
    state = load_state(state_path)
    state.protocols["amneziawg"] = {
        "installed": True,
        "port": port,
        "iface": AWG_IFACE,
        "subnet": AWG_ADDRESS_SUBNET,
        "pkg_version": pkg_version,
        "public_key": public_key,
        "obfuscation": obf,
        "psk_required": True,
    }
    save_state(state, state_path)


def _install_locked(port: int, state_path: Optional[str]) -> int:
    """Мутирующая часть установки под FileLock; 0 — успех, 1 — отказ."""
    try:
        _check_kernel_headers()
        _ensure_apt_packages()
        private_key, public_key = _gen_server_keys()
        obf = gen_obfuscation_params(random.Random())
        _write_config(private_key, port, obf)
    except (InstallError, OSError) as exc:
        console.print(f"[error][amneziawg] {exc}[/error]")
        return 1

    unit_ok = install_unit(
        "vds-amneziawg.service.tpl",
        AWG_UNIT,
        ctx={"config_path": str(AWG_CONFIG_PATH), "iface": AWG_IFACE},
    )
    if not unit_ok:
        console.print(f"[error][amneziawg] Не удалось установить юнит {AWG_UNIT}[/error]")
        return 1

    # UFW: паттерн src/wireguard/install.py — правило добавляется только при
    # наличии ufw (SPEC §3: единственное новое allow <port>/udp).
    if shutil.which("ufw"):
        ufw_res = run_list(["ufw", "allow", f"{port}/udp"], timeout=30)
        if not ufw_res.ok:
            console.print(
                f"[error][amneziawg] ufw allow {port}/udp не выполнился: "
                f"{ufw_res.stderr.strip()}[/error]"
            )
            return 1

    enable = run_list(["systemctl", "enable", AWG_UNIT], timeout=15)
    restart = run_list(["systemctl", "restart", AWG_UNIT], timeout=60)
    if not (enable.ok and restart.ok):
        console.print(
            f"[error][amneziawg] Сервис {AWG_UNIT} не запустился: "
            f"{restart.stderr.strip() or enable.stderr.strip()}[/error]"
        )
        return 1

    pkg_version = _pkg_version()
    try:
        _save_state_meta(port, public_key, obf, pkg_version, state_path)
    except (StoreError, OSError) as exc:
        console.print(f"[error][amneziawg] Не удалось сохранить состояние: {exc}[/error]")
        return 1

    console.print(
        f"[success][amneziawg] AmneziaWG установлен: udp/{port}, интерфейс "
        f"{AWG_IFACE} ({AWG_ADDRESS_SUBNET}), юнит {AWG_UNIT} активен "
        f"(пакеты {pkg_version or AWG_APT_PACKAGES[0]} из {AWG_PPA}).[/success]"
    )
    console.print(
        "[info][amneziawg] Клиенты: `vds amneziawg add-client NAME` → .conf для "
        "импорта в AmneziaVPN (OQ-2, вариант b).[/info]"
    )
    return 0


def run_install(
    port: int = AWG_PORT_DEFAULT,
    state_path: Optional[str] = None,
) -> int:
    """Точка входа `vds amneziawg install`. 0 — успех (в т.ч. «уже установлено»)."""
    if os.geteuid() != 0:
        console.print("[error][amneziawg] Требуется root (запустите через sudo).[/error]")
        return 1

    # Идемпотентность (E7) ДО проверки порта: активный awg0 сам владеет
    # udp-портом — повторный install не должен быть «порт занят».
    if _installed():
        console.print(
            "[success][amneziawg] AmneziaWG уже установлен (пакеты awg и "
            f"{AWG_CONFIG_PATH} на месте) — повторная установка не требуется.[/success]"
        )
        return 0

    # Проверка порта — ДО любых изменений (E1: apt/PPA-шаги после неё).
    if not port_free(port, "udp"):
        owner = port_owner(port, "udp")
        owner_info = f" (владелец: {owner})" if owner else ""
        console.print(
            f"[error][amneziawg] Порт {port}/udp занят{owner_info}. "
            "Освободите порт или укажите --port и повторите.[/error]"
        )
        return 1

    with FileLock(LOCK_FILE):
        return _install_locked(port, state_path)


def is_service_active() -> bool:
    """Обёртка для status (WP-4): активен ли юнит vds-amneziawg.service."""
    from src.core.units import unit_active  # лениво: без тяжёлого графа импортов

    return unit_active(AWG_UNIT)
