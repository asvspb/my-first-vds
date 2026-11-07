"""Удаление Hysteria2: dry-run по умолчанию, `--apply` + подтверждение.

План: systemd-юнит vds-hysteria2.service, конфиг /etc/hysteria/config.yaml,
сертификаты cert.pem/key.pem, бинарь /usr/local/bin/hysteria, клиенты
hysteria2 из gateway store. sysctl-тюнинг /etc/sysctl.d/99-vds-gateway.conf
НЕ откатывается (ADR-002/OQ-2) — это явно упоминается в плане.
Идемпотентно: нечего удалять — exit 0 (SPEC §3/§5).
"""

import contextlib
from pathlib import Path

from src.core.logger import console
from src.core.shell import run_list
from src.core.units import remove_unit, unit_active
from src.gateway.paths import (
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_CONFIG_PATH,
    HYSTERIA2_KEY_PATH,
    HYSTERIA2_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state
from src.hysteria2.install import HYSTERIA2_BIN_PATH

UNIT_FILE = Path("/etc/systemd/system") / HYSTERIA2_UNIT


def _plan(state_path: str | None = None) -> list[str]:
    """Список планируемых к удалению объектов (пустой — нечего удалять)."""
    removals: list[str] = []
    if unit_active(HYSTERIA2_UNIT) or UNIT_FILE.exists():
        removals.append(f"systemd-юнит {HYSTERIA2_UNIT} (stop, disable, файл)")
    if HYSTERIA2_CONFIG_PATH.exists():
        removals.append(f"конфиг {HYSTERIA2_CONFIG_PATH}")
    if HYSTERIA2_CERT_PATH.exists() or HYSTERIA2_KEY_PATH.exists():
        removals.append(f"сертификаты {HYSTERIA2_CERT_PATH}, {HYSTERIA2_KEY_PATH}")
    if HYSTERIA2_BIN_PATH.exists():
        removals.append(f"бинарь {HYSTERIA2_BIN_PATH}")
    state = load_state(state_path)  # StoreError уйдёт в run_remove
    hy_clients = [c for c in state.clients if c.protocol == "hysteria2"]
    if hy_clients:
        names = ", ".join(c.name for c in hy_clients)
        removals.append(f"клиенты hysteria2 из store ({len(hy_clients)}): {names}")
    if "hysteria2" in state.protocols:
        removals.append("запись protocols['hysteria2'] из store")
    if not removals:
        return []
    # Явное указание в плане: sysctl не откатывается (ADR-002/OQ-2).
    removals.append(
        "НЕ трогаем: sysctl-тюнинг /etc/sysctl.d/99-vds-gateway.conf "
        "(ADR-002: полезен остальным сервисам)"
    )
    return removals


def _apply(state_path: str | None = None) -> int:
    if not remove_unit(HYSTERIA2_UNIT):
        return 1
    HYSTERIA2_CONFIG_PATH.unlink(missing_ok=True)
    HYSTERIA2_CERT_PATH.unlink(missing_ok=True)
    HYSTERIA2_KEY_PATH.unlink(missing_ok=True)
    # Каталог конфига удаляем, только если он пуст (апстрим-путь /etc/hysteria).
    with contextlib.suppress(OSError):
        HYSTERIA2_CONFIG_PATH.parent.rmdir()
    HYSTERIA2_BIN_PATH.unlink(missing_ok=True)

    state = load_state(state_path)
    state.clients = [c for c in state.clients if c.protocol != "hysteria2"]
    state.protocols.pop("hysteria2", None)
    save_state(state, state_path)

    run_list(["systemctl", "daemon-reload"], timeout=10)
    console.print("[change][hysteria2] Hysteria2 полностью удалён.[/change]")
    console.print(
        "[info][hysteria2] sysctl-тюнинг оставлен (ADR-002).[/info]"
    )
    return 0


def run_remove(
    apply: bool = False,
    yes: bool = False,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds hysteria2 remove`. Dry-run без `--apply`; 0 — успех."""
    try:
        plan = _plan(state_path)
    except StoreError as exc:
        console.print(f"[error][hysteria2] {exc}[/error]")
        return 1

    if not plan:
        console.print("[info][hysteria2] Hysteria2 не установлен — нечего удалять.[/info]")
        return 0

    console.print("[warning][hysteria2] План удаления (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: `vds hysteria2 remove --apply`[/info]"
        )
        return 0

    if not yes:
        import questionary

        if not questionary.confirm(
            "Удалить Hysteria2 полностью? Клиенты потеряют доступ.", default=False
        ).ask():
            console.print("[info][hysteria2] Удаление отменено.[/info]")
            return 1

    try:
        return _apply(state_path)
    except (StoreError, OSError) as exc:
        console.print(f"[error][hysteria2] Ошибка при удалении: {exc}[/error]")
        return 1
