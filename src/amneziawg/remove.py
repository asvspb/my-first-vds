"""Удаление AmneziaWG: dry-run по умолчанию, `--apply` + подтверждение.

План: systemd-юнит vds-amneziawg.service, ufw-правило <port>/udp, конфиг
/etc/amnezia/awg0.conf, клиентские .conf в AWG_CLIENTS_DIR, клиенты
amneziawg и запись protocols["amneziawg"] из gateway store. Пакеты PPA
(amneziawg-tools/amneziawg-dkms) НЕ удаляются автоматически — ручной purge
(ADR-005), указывается в плане и финальном сообщении. sysctl — N/A (AWG не
пишет /etc/sysctl.d — SPEC §3). Идемпотентно: нечего удалять — exit 0.

`--apply`: root-check (E8) → confirm → FileLock → бэкап awg0.conf и
каталога клиентов (.bak-pre-remove) → юнит (stop/disable/файл) → ufw delete
→ конфиг-файлы → state-очистка. При сбое — откат из бэкапа (SPEC §5).
"""

import contextlib
import os
import shutil
from pathlib import Path
from typing import Optional

from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import run_list
from src.core.units import remove_unit, unit_active
from src.gateway.paths import (
    AWG_CLIENTS_DIR,
    AWG_CONFIG_PATH,
    AWG_PORT_DEFAULT,
    AWG_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

UNIT_FILE = Path("/etc/systemd/system") / AWG_UNIT
LOCK_FILE = "/var/run/vds-amneziawg-remove.lock"
BACKUP_SUFFIX = ".bak-pre-remove"
AWG_APT_PACKAGES = ("amneziawg-tools", "amneziawg-dkms")
AWG_PPA = "ppa:amnezia/ppa"

_MANUAL_PURGE_HINT = (
    "apt-mark unhold " + " ".join(AWG_APT_PACKAGES)
    + " && apt purge " + " ".join(AWG_APT_PACKAGES)
    + " && add-apt-repository -r " + AWG_PPA
)


def _plan(state_path: Optional[str] = None) -> tuple[list[str], int]:
    """Список планируемых к удалению объектов и порт (пустой — нечего удалять).

    StoreError уходит в run_remove. Пакеты PPA и sysctl — явные пункты
    «НЕ трогаем» (ADR-005; sysctl N/A — AWG его не пишет).
    """
    plan: list[str] = []
    port = AWG_PORT_DEFAULT
    try:
        state = load_state(state_path)
        meta = state.protocols.get("amneziawg") or {}
        if meta.get("port"):
            port = int(meta["port"])
    except StoreError:
        state = None

    if unit_active(AWG_UNIT) or UNIT_FILE.exists():
        plan.append(f"systemd-юнит {AWG_UNIT} (stop, disable, файл)")
    if AWG_CONFIG_PATH.exists():
        plan.append(f"конфиг {AWG_CONFIG_PATH}")
    if AWG_CLIENTS_DIR.is_dir() and any(AWG_CLIENTS_DIR.iterdir()):
        plan.append(f"каталог клиентских .conf {AWG_CLIENTS_DIR}/")
    if state is not None:
        awg_clients = [c for c in state.clients if c.protocol == "amneziawg"]
        if awg_clients:
            names = ", ".join(c.name for c in awg_clients)
            plan.append(f"клиенты amneziawg из store ({len(awg_clients)}): {names}")
        if "amneziawg" in state.protocols:
            plan.append("запись protocols['amneziawg'] из store")
    if not plan:
        return [], port
    if shutil.which("ufw"):
        plan.append(f"ufw-правило allow {port}/udp (delete)")
    plan.append(
        "НЕ трогаем: пакеты PPA " + "/".join(AWG_APT_PACKAGES)
        + " — ручной purge (ADR-005): " + _MANUAL_PURGE_HINT
    )
    plan.append("НЕ трогаем: sysctl — N/A (AWG не пишет /etc/sysctl.d)")
    return plan, port


def _backup_files(conf_path: Path, clients_dir: Path) -> tuple[Path, Path]:
    """Бэкап awg0.conf и каталога клиентов (.bak-pre-remove, 0600).

    Существующий бэкап не перезаписывается. Возвращает (conf_backup, dir_backup).
    """
    conf_backup = conf_path.with_name(conf_path.name + BACKUP_SUFFIX)
    dir_backup = clients_dir.with_name(clients_dir.name + BACKUP_SUFFIX)
    if conf_path.is_file() and not conf_backup.exists():
        shutil.copy2(conf_path, conf_backup)
        os.chmod(conf_backup, 0o600)
    if clients_dir.is_dir() and not dir_backup.exists():
        shutil.copytree(clients_dir, dir_backup)
        for item in dir_backup.rglob("*"):
            if item.is_file():
                os.chmod(item, 0o600)
    return conf_backup, dir_backup


def _restore_backups(
    conf_path: Path,
    clients_dir: Path,
    conf_backup: Path,
    dir_backup: Path,
) -> None:
    """Откат из бэкапа при сбое удаления (SPEC §5)."""
    if conf_backup.is_file():
        shutil.copy2(conf_backup, conf_path)
        os.chmod(conf_path, 0o600)
    if dir_backup.is_dir():
        shutil.rmtree(clients_dir, ignore_errors=True)
        shutil.copytree(dir_backup, clients_dir)
    console.print(
        f"[warning][amneziawg] Откат из бэкапа: {conf_backup}, "
        f"{dir_backup}[/warning]"
    )


def _apply(state_path: Optional[str] = None) -> int:
    """Мутирующая часть удаления под FileLock; 0 — успех, 1 — откат/отказ."""
    conf_backup, dir_backup = _backup_files(AWG_CONFIG_PATH, AWG_CLIENTS_DIR)

    if not remove_unit(AWG_UNIT):
        _restore_backups(AWG_CONFIG_PATH, AWG_CLIENTS_DIR, conf_backup, dir_backup)
        console.print(
            f"[error][amneziawg] Не удалось удалить юнит {AWG_UNIT} — "
            "изменения откатаны из бэкапа.[/error]"
        )
        return 1

    if shutil.which("ufw"):
        state = load_state(state_path)
        meta = state.protocols.get("amneziawg") or {}
        port = int(meta.get("port") or AWG_PORT_DEFAULT)
        ufw_res = run_list(["ufw", "delete", "allow", f"{port}/udp"], timeout=30)
        if not ufw_res.ok:
            console.print(
                f"[warning][amneziawg] ufw delete allow {port}/udp не выполнился: "
                f"{ufw_res.stderr.strip()} — проверьте правила вручную.[/warning]"
            )

    AWG_CONFIG_PATH.unlink(missing_ok=True)
    # Каталог конфига удаляем, только если он пуст (апстрим-путь /etc/amnezia).
    with contextlib.suppress(OSError):
        AWG_CONFIG_PATH.parent.rmdir()
    shutil.rmtree(AWG_CLIENTS_DIR, ignore_errors=True)

    state = load_state(state_path)
    state.clients = [c for c in state.clients if c.protocol != "amneziawg"]
    state.protocols.pop("amneziawg", None)
    save_state(state, state_path)

    run_list(["systemctl", "daemon-reload"], timeout=10)
    console.print("[change][amneziawg] AmneziaWG полностью удалён.[/change]")
    console.print(
        "[info][amneziawg] Бэкапы сохранены: "
        f"{conf_backup}{' (не создан — конфига не было)' if not conf_backup.is_file() else ''}, "
        f"{dir_backup}{' (не создан — каталога не было)' if not dir_backup.is_dir() else ''}.[/info]"
    )
    console.print(
        "[info][amneziawg] Пакеты PPA " + "/".join(AWG_APT_PACKAGES)
        + " ОСТАЮТСЯ в системе — удалите вручную (ADR-005): "
        + _MANUAL_PURGE_HINT + "[/info]"
    )
    return 0


def run_remove(
    apply: bool = False,
    yes: bool = False,
    state_path: Optional[str] = None,
) -> int:
    """Точка входа `vds amneziawg remove`. Dry-run без `--apply`; 0 — успех."""
    try:
        plan, _port = _plan(state_path)
    except StoreError as exc:
        console.print(f"[error][amneziawg] {exc}[/error]")
        return 1

    if not plan:
        console.print(
            "[info][amneziawg] AmneziaWG не установлен — нечего удалять.[/info]"
        )
        return 0

    console.print("[warning][amneziawg] План удаления (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: `vds amneziawg remove --apply`[/info]"
        )
        return 0

    if os.geteuid() != 0:
        console.print(
            "[error][amneziawg] Требуется root (запустите через sudo).[/error]"
        )
        return 1

    if not yes:
        import questionary

        if not questionary.confirm(
            "Удалить AmneziaWG полностью? Клиенты потеряют доступ.",
            default=False,
        ).ask():
            console.print("[info][amneziawg] Удаление отменено.[/info]")
            return 1

    with FileLock(LOCK_FILE):
        try:
            return _apply(state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error][amneziawg] Ошибка при удалении: {exc}[/error]")
            return 1
