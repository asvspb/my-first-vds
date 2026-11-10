"""Статус AmneziaWG: юнит, DKMS/пакетная версия, UDP-порт, peers, state.

Не установлен — читаемое сообщение и exit != 0. Вывод журнала маскируется:
ключи (PrivateKey/PresharedKey) и известные секреты из state/конфига
заменяются на `***` (SPEC §5). Сертификат для AWG — N/A (ключи WireGuard,
не TLS). config-vs-state рассинхрон: peers в awg0.conf против клиентов в
state.json (паттерн src/xray/status.py).
"""

import re
import shutil
from pathlib import Path
from typing import Iterable

from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.shell import run_list
from src.gateway.paths import (
    AWG_CLIENTS_DIR,
    AWG_CONFIG_PATH,
    AWG_IFACE,
    AWG_PORT_DEFAULT,
    AWG_UNIT,
)
from src.gateway.store import StoreError, load_state
from src.amneziawg.install import is_service_active

UNIT_FILE = Path("/etc/systemd/system") / AWG_UNIT

_PRIVATE_KEY_RE = re.compile(r"(PrivateKey\s*=\s*)(\S+)")
_PRESHARED_KEY_RE = re.compile(r"(PresharedKey\s*=\s*)(\S+)")
_DKMS_LINE_RE = re.compile(r"^amneziawg/([^,\s]+)")


def _mask_secrets(text: str, secrets: Iterable[str]) -> str:
    """Заменить известные секретные значения и ключи в ini-дампах.

    Regex без ^-якоря: journal может светить `PrivateKey = …` в середине
    строки (без отступа/в контексте сообщения).
    """
    masked = text
    for value in secrets:
        if value:
            masked = masked.replace(value, "***")
    masked = _PRIVATE_KEY_RE.sub(r"\1***", masked)
    return _PRESHARED_KEY_RE.sub(r"\1***", masked)


def _known_secrets(state_path: str | None = None) -> list[str]:
    """Секреты для маскирования: ключи/PSK клиентов из state + PrivateKey
    сервера из awg0.conf. Статус не должен падать на битом state/конфиге —
    маскируем то, что удалось прочитать."""
    values: list[str] = []
    try:
        state = load_state(state_path)
    except StoreError:
        state = None
    if state is not None:
        for client in state.clients:
            if client.protocol != "amneziawg":
                continue
            values.append(str(client.extra.get("private_key") or ""))
            values.append(str(client.extra.get("psk") or ""))
    if AWG_CONFIG_PATH.is_file():
        try:
            match = re.search(
                r"^\s*PrivateKey\s*=\s*(\S+)\s*$",
                AWG_CONFIG_PATH.read_text(encoding="utf-8"),
                re.M,
            )
            if match:
                values.append(match.group(1))
        except OSError:
            pass
    return [v for v in values if v]


def _count_peers(conf_text: str) -> int:
    """Число [Peer]-секций в тексте серверного .conf (для рассинхрона)."""
    return sum(1 for line in conf_text.splitlines() if line.strip() == "[Peer]")


def _dkms_version() -> str:
    """Версия DKMS-модуля amneziawg (dkms status) или пустая строка."""
    result = run_list(["dkms", "status"], timeout=10)
    if not result.ok:
        return ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("amneziawg/"):
            match = _DKMS_LINE_RE.match(line)
            if match:
                return match.group(1)
    return ""


def _pkg_versions() -> dict[str, str]:
    """Версии установленных amneziawg-пакетов (dpkg-query)."""
    versions: dict[str, str] = {}
    for pkg in ("amneziawg-tools", "amneziawg-dkms"):
        result = run_list(
            ["dpkg-query", "-W", "-f=${Version}", pkg], timeout=10
        )
        if result.ok:
            versions[pkg] = result.output
    return versions


def collect_status(state_path: str | None = None) -> dict:
    """Собрать состояние AmneziaWG как dict (для adapter и вывода)."""
    installed = shutil.which("awg") is not None
    active = is_service_active() if installed else False
    port = AWG_PORT_DEFAULT
    peers_in_conf: int | None = None
    if AWG_CONFIG_PATH.is_file():
        try:
            conf_text = AWG_CONFIG_PATH.read_text(encoding="utf-8")
            peers_in_conf = _count_peers(conf_text)
            match = re.search(r"^\s*ListenPort\s*=\s*(\d+)\s*$", conf_text, re.M)
            if match:
                port = int(match.group(1))
        except OSError:
            peers_in_conf = None
    port_listening = not port_free(port, "udp")
    owner = port_owner(port, "udp")
    pkg_versions = _pkg_versions() if installed else {}
    dkms_version = _dkms_version() if installed else ""

    client_names: list[str] = []
    state_error: str | None = None
    try:
        state = load_state(state_path)
        client_names = [c.name for c in state.clients if c.protocol == "amneziawg"]
        meta = state.protocols.get("amneziawg") or {}
        meta_port = meta.get("port")
        if meta_port:
            port = int(meta_port)
    except StoreError as exc:
        state_error = str(exc)

    # config-vs-state рассинхрон (паттерн xray/status.py): peers в конфиге
    # против клиентов amneziawg в state.
    desync = peers_in_conf is not None and peers_in_conf != len(client_names)
    clients_dir = AWG_CLIENTS_DIR
    conf_files = sorted(p.name for p in clients_dir.glob("*.conf")) if clients_dir.is_dir() else []
    return {
        "installed": installed,
        "unit_active": active,
        "config_path": str(AWG_CONFIG_PATH),
        "iface": AWG_IFACE,
        "port": port,
        "port_listening": port_listening,
        "port_owner": owner,
        "pkg_versions": pkg_versions,
        "dkms_version": dkms_version,
        "peers_in_conf": peers_in_conf,
        "clients": client_names,
        "client_conf_files": conf_files,
        "desync": desync,
        "state_error": state_error,
    }


def run_status(state_path: str | None = None) -> int:
    """Точка входа `vds amneziawg status`. 0 — установлен; 1 — не установлен."""
    if shutil.which("awg") is None:
        console.print(
            "[warning][amneziawg] AmneziaWG не установлен (бинарник awg не найден).[/warning]"
        )
        console.print("[info][amneziawg] Установите: `vds amneziawg install`[/info]")
        return 1

    info = collect_status(state_path)
    console.print(f"[info][amneziawg] Бинарь:[/info] {shutil.which('awg')}")
    console.print(
        f"[info][amneziawg] Юнит {AWG_UNIT}:[/info] "
        + ("[success]active[/success]" if info["unit_active"] else "[error]inactive[/error]")
    )

    dkms = info["dkms_version"]
    tools = info["pkg_versions"].get("amneziawg-tools", "")
    version_line = f"tools={tools or '?'}"
    version_line += f", dkms-модуль={dkms}" if dkms else ", dkms-модуль не собран"
    dkms_pkg = info["pkg_versions"].get("amneziawg-dkms")
    if dkms_pkg:
        version_line += f" (dkms-пакет {dkms_pkg})"
    console.print(f"[info][amneziawg] Версии:[/info] {version_line}")

    if info["port_listening"]:
        owner = f" (владелец: {info['port_owner']})" if info["port_owner"] else ""
        console.print(f"[info][amneziawg] Порт {info['port']}/udp: слушается{owner}.[/info]")
    else:
        console.print(
            f"[warning][amneziawg] Порт {info['port']}/udp не слушается "
            f"(интерфейс {info['iface']}).[/warning]"
        )

    if info["state_error"]:
        console.print(f"[error][amneziawg] {info['state_error']}[/error]")
    elif info["desync"]:
        console.print(
            f"[warning][amneziawg] Рассинхрон: в {info['config_path']} "
            f"{info['peers_in_conf']} peers, в state {len(info['clients'])} "
            "amneziawg-клиентов — проверьте state.json/конфиг.[/warning]"
        )
    elif info["clients"]:
        names = ", ".join(info["clients"])
        console.print(f"[info][amneziawg] Клиенты ({len(info['clients'])}):[/info] {names}")
    else:
        console.print(
            "[info][amneziawg] Клиентов нет (`vds amneziawg add-client NAME`).[/info]"
        )

    if info["client_conf_files"]:
        console.print(
            f"[info][amneziawg] Конфиги в {AWG_CLIENTS_DIR}:[/info] "
            + ", ".join(info["client_conf_files"])
        )

    console.print(
        "[info][amneziawg] Сертификат: N/A — AWG использует ключи WireGuard, "
        "не TLS.[/info]"
    )

    journal = run_list(
        ["journalctl", "-u", AWG_UNIT, "-n", "20", "--no-pager", "-p", "warning"],
        timeout=10,
    )
    if journal.ok and journal.stdout.strip():
        masked = _mask_secrets(journal.stdout, _known_secrets(state_path))
        console.print("[info][amneziawg] Последние записи journal (секреты маскированы):[/info]")
        for line in masked.splitlines():
            console.print(f"  {line}")
    return 0
