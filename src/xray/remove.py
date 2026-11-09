"""Удаление Xray: dry-run по умолчанию, `--apply` + подтверждение.

План: systemd-юнит vds-xray.service, конфиг /usr/local/etc/xray/config.json,
бинарь /usr/local/bin/xray + geodata /usr/local/share/xray, клиенты xray из
gateway store. Идемпотентно: нечего удалять — exit 0 (SPEC §3/§5).
"""

import contextlib
import json
import os
import shutil
from pathlib import Path

from src.core.lock import FileLock
from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import remove_unit, unit_active
from src.gateway.paths import (
    XRAY_BIN_PATH,
    XRAY_CONFIG_PATH,
    XRAY_GEODATA_DIR,
    XRAY_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

UNIT_FILE = Path("/etc/systemd/system") / XRAY_UNIT

# XHTTP (SPEC WP-3, ADR-003): бэкап config.json перед снятием транспорта;
# существующий бэкап не перезаписывается.
XHTTP_REMOVE_BACKUP_SUFFIX = ".bak-remove-xhttp"
XHTTP_PRE_BACKUP_SUFFIX = ".bak-pre-xhttp"
XHTTP_LOCK_FILE = "/var/run/vds-xray.lock"


def _plan(state_path: str | None = None) -> list[str]:
    """Список планируемых к удалению объектов (пустой — нечего удалять)."""
    plan: list[str] = []
    if unit_active(XRAY_UNIT) or UNIT_FILE.exists():
        plan.append(f"systemd-юнит {XRAY_UNIT} (stop, disable, файл)")
    if XRAY_CONFIG_PATH.exists():
        plan.append(f"конфиг {XRAY_CONFIG_PATH}")
    if XRAY_BIN_PATH.exists():
        plan.append(f"бинарь {XRAY_BIN_PATH}")
    if XRAY_GEODATA_DIR.exists():
        plan.append(f"geodata {XRAY_GEODATA_DIR}/")
    state = load_state(state_path)  # StoreError уйдёт в run_remove
    xray_clients = [c for c in state.clients if c.protocol == "xray"]
    if xray_clients:
        names = ", ".join(c.name for c in xray_clients)
        plan.append(f"клиенты xray из store ({len(xray_clients)}): {names}")
    if "xray" in state.protocols:
        plan.append("запись protocols['xray'] из store")
    return plan


def _apply(state_path: str | None = None) -> int:
    if not remove_unit(XRAY_UNIT):
        return 1
    XRAY_CONFIG_PATH.unlink(missing_ok=True)
    # Каталог конфига удаляем, только если он пуст (апстрим-путь /usr/local/etc/xray).
    with contextlib.suppress(OSError):
        XRAY_CONFIG_PATH.parent.rmdir()
    XRAY_BIN_PATH.unlink(missing_ok=True)
    shutil.rmtree(XRAY_GEODATA_DIR, ignore_errors=True)

    state = load_state(state_path)
    state.clients = [c for c in state.clients if c.protocol != "xray"]
    state.protocols.pop("xray", None)
    save_state(state, state_path)

    run_list(["systemctl", "daemon-reload"], timeout=10)
    console.print("[change][xray] Xray полностью удалён.[/change]")
    return 0


def run_remove(
    apply: bool = False,
    yes: bool = False,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds xray remove`. Dry-run без `--apply`; 0 — успех."""
    try:
        plan = _plan(state_path)
    except StoreError as exc:
        console.print(f"[error][xray] {exc}[/error]")
        return 1

    if not plan:
        console.print("[info][xray] Xray не установлен — нечего удалять.[/info]")
        return 0

    console.print("[warning][xray] План удаления (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    if not apply:
        console.print("[info]Это dry-run. Для применения: `vds xray remove --apply`[/info]")
        return 0

    if not yes:
        import questionary

        if not questionary.confirm(
            "Удалить Xray полностью? Клиенты потеряют доступ.", default=False
        ).ask():
            console.print("[info][xray] Удаление отменено.[/info]")
            return 1

    try:
        return _apply(state_path)
    except (StoreError, OSError) as exc:
        console.print(f"[error][xray] Ошибка при удалении: {exc}[/error]")
        return 1


# ---------------------------------------------------------------------------
# XHTTP-транспорт (SPEC WP-3, ADR-003)
# ---------------------------------------------------------------------------


class XHTTPTransportError(Exception):
    """Сбой снятия XHTTP-транспорта (нет установки, битый конфиг, restart)."""


def _strip_xhttp(config: dict) -> tuple[dict, list[str]]:
    """Вычесть фолбэк и XHTTP-инблэнд из конфига (чистая функция).

    Возвращает (новый конфиг, список действий). Если XHTTP не найден —
    действия пустые. realitySettings inbound#0 не трогается.
    """
    actions: list[str] = []
    new_config = json.loads(json.dumps(config))  # deep copy
    inbounds = new_config.get("inbounds", [])
    kept: list[dict] = []
    for inbound in inbounds:
        network = inbound.get("streamSettings", {}).get("network")
        if network == "xhttp":
            actions.append(
                f"инблэнд vless+xhttp ({inbound.get('listen', '*')}:"
                f"{inbound.get('port')})"
            )
            continue
        stream = inbound.get("streamSettings", {})
        if "fallbacks" in stream:
            del stream["fallbacks"]
            actions.append("fallbacks из streamSettings Reality-инблэнда")
        kept.append(inbound)
    new_config["inbounds"] = kept
    return new_config, actions


def _plan_transport(state_path: str | None) -> tuple[list[str], dict, str | None]:
    """План снятия XHTTP; пустой список — нечего удалять."""
    plan: list[str] = []
    if not XRAY_CONFIG_PATH.is_file():
        return [], {}, None
    try:
        config = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise XHTTPTransportError(
            f"Не удалось прочитать {XRAY_CONFIG_PATH}: {exc} (E8)."
        ) from exc
    clean, actions = _strip_xhttp(config)
    plan.extend(actions)
    state = load_state(state_path)  # StoreError уйдёт в run-обёртку
    xhttp_clients = [
        c for c in state.clients
        if c.protocol == "xray" and c.extra.get("transport") == "xhttp"
    ]
    if xhttp_clients:
        names = ", ".join(c.name for c in xhttp_clients)
        plan.append(f"XHTTP-клиенты из store: {names}")
    if "xhttp" in state.protocols:
        plan.append("запись protocols['xhttp'] из store")
    return plan, clean, str(XRAY_CONFIG_PATH) + XHTTP_REMOVE_BACKUP_SUFFIX


def remove_transport_xhttp(
    apply: bool = False,
    yes: bool = False,
    state_path: str | None = None,
) -> int:
    """Снять XHTTP-транспорт (SPEC WP-3, ADR-003 откат).

    Dry-run по умолчанию; apply: бэкап -> чистый конфиг -> `xray -test`
    (fail: откат из бэкапа) -> restart -> store. Идемпотентно: нечего
    снимать — exit 0.
    """
    if os.geteuid() != 0:
        console.print("[error][xray] Требуется root (запустите через sudo).[/error]")
        return 1

    try:
        plan, clean, backup_path = _plan_transport(state_path)
    except (StoreError, XHTTPTransportError) as exc:
        console.print(f"[error][xray] {exc}[/error]")
        return 1

    if not plan:
        console.print("[info][xray] XHTTP не установлен — нечего снимать.[/info]")
        return 0

    console.print("[warning][xray] План снятия XHTTP (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    console.print(f"  - бэкап config.json: {backup_path}")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: "
            "`vds xray remove-transport xhttp --apply`[/info]"
        )
        return 0

    if not yes:
        import questionary

        if not questionary.confirm(
            "Снять XHTTP? Reality (TCP 443) вернётся к конфигурации до XHTTP.",
            default=False,
        ).ask():
            console.print("[info][xray] Операция отменена.[/info]")
            return 1

    payload = json.dumps(clean, indent=2, ensure_ascii=False) + "\n"
    with FileLock(XHTTP_LOCK_FILE):
        current = Path(XRAY_CONFIG_PATH)
        backup = Path(str(backup_path))
        if current.is_file() and not backup.exists():
            shutil.copy2(current, backup)
            os.chmod(backup, 0o600)

        if not write_secret_atomic(str(XRAY_CONFIG_PATH), payload, mode=0o600):
            console.print(
                f"[error][xray] Не удалось записать {XRAY_CONFIG_PATH}.[/error]"
            )
            return 1

        test = run_list(
            [str(XRAY_BIN_PATH), "run", "-test", "-config", str(XRAY_CONFIG_PATH)],
            timeout=15,
        )
        restart_failed = False
        if test.ok:
            restart = run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
            restart_failed = not restart.ok
        if not test.ok or restart_failed:
            shutil.copy2(backup, XRAY_CONFIG_PATH)
            os.chmod(XRAY_CONFIG_PATH, 0o600)
            run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
            detail = "xray -test" if not test.ok else "restart"
            console.print(
                f"[error][xray] {detail} не прошёл — конфиг откатан из бэкапа "
                f"({backup_path}).[/error]"
            )
            return 1

    try:
        state = load_state(state_path)
        state.clients = [
            c for c in state.clients
            if not (c.protocol == "xray" and c.extra.get("transport") == "xhttp")
        ]
        state.protocols.pop("xhttp", None)
        save_state(state, state_path)
    except (StoreError, OSError) as exc:
        console.print(
            f"[error][xray] Конфиг обновлён, но store не изменён: {exc}[/error]"
        )
        return 1

    console.print(
        "[change][xray] XHTTP снят; Reality остаётся на TCP 443 "
        "с прежними realitySettings.[/change]"
    )
    console.print(
        f"[info][xray] Бэкап снятия: {backup_path}.[/info]"
    )
    pre_backup = str(XRAY_CONFIG_PATH) + XHTTP_PRE_BACKUP_SUFFIX
    console.print(
        f"[info][xray] Файл {pre_backup} — снапшот config.json на момент "
        "УСТАНОВКИ XHTTP, а не точка отката этой команды (в него не входят "
        "клиенты, добавленные позже). Last-resort восстановление — только "
        "вручную и с осознанием потери более поздних клиентов.[/info]"
    )
    return 0
