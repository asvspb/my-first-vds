"""Удаление Xray: dry-run по умолчанию, `--apply` + подтверждение.

План: systemd-юнит vds-xray.service, конфиг /usr/local/etc/xray/config.json,
бинарь /usr/local/bin/xray + geodata /usr/local/share/xray, клиенты xray из
gateway store. Идемпотентно: нечего удалять — exit 0 (SPEC §3/§5).
"""

import contextlib
import shutil
from pathlib import Path

from src.core.logger import console
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
