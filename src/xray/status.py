"""Статус Xray: юнит, валидность конфига, порт, ошибки из journal.

Не установлен — читаемое сообщение и exit != 0. Вывод журнала маскируется:
uuid клиентов и приватный ключ Reality заменяются на `***` (SPEC §5).
"""

import json
import re
from pathlib import Path
from typing import Iterable

from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.shell import run_list
from src.gateway.paths import XRAY_BIN_PATH, XRAY_CONFIG_PATH, XRAY_UNIT
from src.gateway.store import StoreError, load_state
from src.xray.install import is_service_active

UNIT_FILE = Path("/etc/systemd/system") / XRAY_UNIT

_PRIVATE_KEY_JSON_RE = re.compile(r'"privateKey"\s*:\s*"[^"]*"')


def _mask_secrets(text: str, secrets: Iterable[str]) -> str:
    """Заменить известные секретные значения и privateKey в JSON-дампах."""
    masked = text
    for value in secrets:
        if value:
            masked = masked.replace(value, "***")
    masked = _PRIVATE_KEY_JSON_RE.sub('"privateKey": "***"', masked)
    return masked


def _known_secrets() -> list[str]:
    """Секреты для маскирования: uuid клиентов + privateKey из config.json.

    Статус не должен падать из-за битого state/конфига — маскируем то, что
    удалось прочитать.
    """
    values: list[str] = []
    try:
        state = load_state()
    except StoreError:
        state = None
    if state is not None:
        values.extend(
            client.uuid for client in state.clients if client.protocol == "xray" and client.uuid
        )
    if XRAY_CONFIG_PATH.is_file():
        try:
            config = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
            inbound = config["inbounds"][0]
            private_key = inbound["streamSettings"]["realitySettings"]["privateKey"]
            values.extend(
                client["id"]
                for client in inbound["settings"].get("clients", [])
                if client.get("id")
            )
        except (json.JSONDecodeError, KeyError, IndexError, OSError, TypeError):
            private_key = ""
        if private_key:
            values.append(private_key)
    return [v for v in values if v]


def collect_status() -> dict:
    """Собрать состояние Xray как dict (для adapter и вывода)."""
    installed = XRAY_BIN_PATH.is_file()
    active = is_service_active() if installed else False
    config_test: bool | None = None
    if installed and XRAY_CONFIG_PATH.is_file():
        result = run_list(
            [str(XRAY_BIN_PATH), "run", "-test", "-config", str(XRAY_CONFIG_PATH)],
            timeout=15,
        )
        config_test = result.ok
    port = 443
    port_listening = not port_free(port, "tcp")
    owner = port_owner(port, "tcp")
    client_names: list[str] = []
    xhttp_client_names: list[str] = []
    state_error: str | None = None
    state = None
    try:
        state = load_state()
        client_names = [c.name for c in state.clients if c.protocol == "xray"]
        xhttp_client_names = [
            c.name
            for c in state.clients
            if c.protocol == "xray" and c.extra.get("transport") == "xhttp"
        ]
    except StoreError as exc:
        state_error = str(exc)

    # XHTTP (SPEC WP-3): transport-мета из state + факт инблэнда в config.json.
    xhttp_meta: dict | None = None
    xhttp_inbound: bool = False
    if state is not None:
        xhttp_meta = state.protocols.get("xhttp")
    if installed and XRAY_CONFIG_PATH.is_file():
        try:
            config = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
            xhttp_inbound = any(
                ib.get("streamSettings", {}).get("network") == "xhttp"
                for ib in config.get("inbounds", [])
            )
        except (json.JSONDecodeError, OSError):
            xhttp_inbound = False

    return {
        "installed": installed,
        "unit_active": active,
        "config_path": str(XRAY_CONFIG_PATH),
        "config_test": config_test,
        "port": port,
        "port_listening": port_listening,
        "port_owner": owner,
        "clients": client_names,
        "state_error": state_error,
        "xhttp": {
            "meta": xhttp_meta,
            "inbound_in_config": xhttp_inbound,
            "clients": xhttp_client_names,
        },
    }


def run_status() -> int:
    """Точка входа `vds xray status`. 0 — установлен; 1 — не установлен."""
    if not XRAY_BIN_PATH.is_file():
        console.print(
            f"[warning][xray] Xray не установлен (нет {XRAY_BIN_PATH}).[/warning]"
        )
        console.print("[info][xray] Установите: `vds xray install`[/info]")
        return 1

    info = collect_status()
    console.print(f"[info][xray] Бинарь:[/info] {XRAY_BIN_PATH}")
    console.print(
        f"[info][xray] Юнит {XRAY_UNIT}:[/info] "
        + ("[success]active[/success]" if info["unit_active"] else "[error]inactive[/error]")
    )
    if info["config_test"] is None:
        console.print(
            f"[warning][xray] Конфиг {XRAY_CONFIG_PATH} не найден.[/warning]"
        )
    elif info["config_test"]:
        console.print("[success][xray] Конфиг валиден (`xray -test` — OK).[/success]")
    else:
        console.print("[error][xray] Конфиг невалиден (`xray -test` — FAIL).[/error]")

    if info["port_listening"]:
        owner = f" (владелец: {info['port_owner']})" if info["port_owner"] else ""
        console.print(f"[info][xray] Порт {info['port']}/tcp: слушается{owner}.[/info]")
    else:
        console.print(
            f"[warning][xray] Порт {info['port']}/tcp не слушается.[/warning]"
        )

    if info["state_error"]:
        console.print(f"[error][xray] {info['state_error']}[/error]")
    elif info["clients"]:
        names = ", ".join(info["clients"])
        console.print(f"[info][xray] Клиенты ({len(info['clients'])}):[/info] {names}")
    else:
        console.print("[info][xray] Клиентов нет (`vds xray add-client NAME`).[/info]")

    # XHTTP (SPEC WP-3): port/mode/сертификат и факт инблэнда в конфиге.
    xhttp = info.get("xhttp", {})
    meta = xhttp.get("meta")
    if meta:
        mode = meta.get("mode", "?")
        domain = meta.get("domain", "?")
        xport = meta.get("port", "?")
        inflag = "[success]инблэнд в конфиге[/success]" if xhttp.get("inbound_in_config") else "[error]инблэнда нет в конфиге[/error]"
        console.print(
            f"[info][xray] XHTTP:[/info] mode={mode}, домен={domain}, "
            f"порт {xport} (127.0.0.1 при fallback), {inflag}"
        )
        if xhttp.get("clients"):
            console.print(
                f"[info][xray] XHTTP-клиенты ({len(xhttp['clients'])}):[/info] "
                + ", ".join(xhttp["clients"])
            )
    elif xhttp.get("inbound_in_config"):
        console.print(
            "[warning][xray] В конфиге есть XHTTP-инблэнд, но в state нет "
            "записи protocols['xhttp'] — рассинхрон, перезапустите "
            "`vds xray add-transport xhttp --domain <домен> --apply` или "
            "проверьте state.json.[/warning]"
        )

    journal = run_list(
        ["journalctl", "-u", XRAY_UNIT, "-n", "20", "--no-pager", "-p", "warning"],
        timeout=10,
    )
    if journal.ok and journal.stdout.strip():
        masked = _mask_secrets(journal.stdout, _known_secrets())
        console.print("[info][xray] Последние записи journal (секреты маскированы):[/info]")
        for line in masked.splitlines():
            console.print(f"  {line}")
    return 0
