"""CLI DMS: install / remove / test / status / ping (SPEC-20261124-quiet-exit §5).

`install`/`remove` — dry-run по умолчанию; `--apply` требует root.
`test` требует root (читает `dms.env`, делает реальный GET с gate).
`status` работает без root в урезанном виде; URL — только маской.
`ping` — ExecStart юнита, exit-код всегда 0. `root` — тестовый префикс ФС
(конвенция `core.units`), при `root != "/"` `systemctl` не дёргается.
"""
from __future__ import annotations

import os
from pathlib import Path

from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit, resolve_python, unit_active
from src.dms import gate
from src.dms.env import (
    DmsConfig,
    ROLE_EXIT,
    ROLES,
    config_warnings,
    load_config,
    mask_url,
    render_env,
)
from src.dms.paths import DMS_ENV_PATH, DMS_TIMER, DMS_UNIT

REPO_DIR = Path(__file__).resolve().parents[2]

SERVICE_TEMPLATE = "vds-dms-ping.service.tpl"
TIMER_TEMPLATE = "vds-dms-ping.timer.tpl"

# Имена ключей dms.env — печатаются в плане install (значений там нет).
ENV_KEYS = ("DMS_PING_URL", "DMS_ROLE", "DMS_EXIT_HOST")

DEFAULT_INTERVAL_SEC = 300  # 5 мин (Healthchecks period 5m grace 10m)


def _rooted(path: str, root: str) -> Path:
    if root == "/":
        return Path(path)
    return Path(root) / path.lstrip("/")


def _env_path(root: str) -> Path:
    return _rooted(DMS_ENV_PATH, root)


def _install_ctx(interval_sec: int) -> dict[str, str]:
    install_dir = os.environ.get("INSTALL_DIR", "/opt/my-vds")
    return {
        "python": resolve_python(install_dir),
        "repo_dir": str(REPO_DIR),
        "install_dir": install_dir,
        "interval_sec": str(interval_sec),
    }


def _write_env(path: Path, cfg: DmsConfig) -> bool:
    """Создать `dms.env` из шаблона (0600). Секрет пустой — заполняет владелец."""
    return write_secret_atomic(str(path), render_env(cfg, with_secrets=False), mode=0o600)


def _parse_interval(interval: str) -> int:
    """`"5m"|"300s"|"300"` → секунды; мусор → ValueError."""
    raw = (interval or "").strip().lower()
    mult = 1
    if raw.endswith("s"):
        mult, raw = 1, raw[:-1]
    elif raw.endswith("m"):
        mult, raw = 60, raw[:-1]
    elif raw.endswith("h"):
        mult, raw = 3600, raw[:-1]
    seconds = int(raw) * mult
    if seconds <= 0:
        raise ValueError(f"интервал должен быть > 0, получено {interval!r}")
    return seconds


def cmd_install(
    *,
    apply: bool = False,
    role: str = ROLE_EXIT,
    interval: str = "5m",
    force: bool = False,
    root: str = "/",
) -> int:
    """Установить DMS-пинг (юниты + /etc/vds/dms.env). Dry-run по умолчанию."""
    role = (role or "").strip().lower()
    if role not in ROLES:
        console.print(
            f"[error][dms] --role: ожидался {'|'.join(ROLES)}, получено {role!r}[/error]"
        )
        return 1
    try:
        interval_sec = _parse_interval(interval)
    except ValueError as exc:
        console.print(f"[error][dms] {exc}[/error]")
        return 1

    env_path = _env_path(root)
    cfg = DmsConfig(role=role)

    if not apply:
        console.print("[info][dms] DRY-RUN план install:[/info]")
        console.print(f"[info][dms]   1. конфиг {env_path} (0600, только при отсутствии; --force перезапишет)[/info]")
        console.print(f"[info][dms]   2. ключи dms.env: {', '.join(ENV_KEYS)} — заполните DMS_PING_URL (Healthchecks)[/info]")
        console.print(
            f"[info][dms]   3. юниты {DMS_UNIT} + {DMS_TIMER} "
            f"(тик {interval_sec} с, RandomizedDelaySec=20s, [Install] только у таймера)[/info]"
        )
        console.print(
            f"[info][dms]   gate роли {role}: "
            + (
                "awg0 UP + awg2 UP + wstunnel-server active"
                if role == ROLE_EXIT
                else "awg0 UP + table 100 + data-plane носителя (10.11.0.1|10.12.0.1)"
            )
            + "[/info]"
        )
        console.print("[info][dms] Запустите с --apply для исполнения.[/info]")
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][dms] install --apply требует root (sudo).[/error]")
        return 1

    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[error][dms] не удалось создать {env_path.parent}: {exc}[/error]")
        return 1

    if env_path.exists() and not force:
        console.print(f"[info][dms] существующий {env_path} сохранён (--force перезапишет)[/info]")
    elif not _write_env(env_path, cfg):
        console.print(f"[error][dms] не удалось записать {env_path}[/error]")
        return 1
    else:
        console.print(
            f"[change][dms] конфиг {env_path} создан (0600) — заполните DMS_PING_URL[/change]"
        )

    ctx = _install_ctx(interval_sec)
    for template, name in ((SERVICE_TEMPLATE, DMS_UNIT), (TIMER_TEMPLATE, DMS_TIMER)):
        if not install_unit(template, name, ctx, root=root):
            return 1

    start = run_list(["systemctl", "start", DMS_TIMER], timeout=15)
    if not start.ok:
        console.print(f"[error][dms] не удалось запустить {DMS_TIMER}: {start.stderr.strip()}[/error]")
        return 1

    for warning in config_warnings(load_config(str(env_path))):
        console.print(f"[warning][dms] {warning}[/warning]")
    console.print(
        f"[success][dms] DMS установлен: {DMS_UNIT} + {DMS_TIMER}. "
        f"Проверка: sudo vds dms test[/success]"
    )
    return 0


def cmd_remove(*, apply: bool = False, purge: bool = False, root: str = "/") -> int:
    """Снять юниты (dms.env сохраняется); `--purge` удаляет env."""
    env_path = _env_path(root)

    if not apply:
        console.print("[info][dms] DRY-RUN план remove:[/info]")
        console.print(f"[info][dms]   1. stop/disable и удалить {DMS_UNIT}, {DMS_TIMER}[/info]")
        console.print(f"[info][dms]   2. {env_path} {'удалить (--purge)' if purge else 'сохранить'}[/info]")
        console.print("[info][dms] UFW и state.json не затрагиваются.[/info]")
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][dms] remove --apply требует root (sudo).[/error]")
        return 1

    for name in (DMS_UNIT, DMS_TIMER):
        if not remove_unit(name, root=root):
            return 1

    if purge:
        try:
            env_path.unlink(missing_ok=True)
        except OSError as exc:
            console.print(f"[error][dms] не удалось удалить {env_path}: {exc}[/error]")
            return 1
        console.print("[change][dms] dms.env удалён (--purge)[/change]")
    else:
        console.print(f"[info][dms] {env_path} сохранён (удалить: --purge)[/info]")
    console.print("[success][dms] DMS снят.[/success]")
    return 0


def cmd_test(*, root: str = "/") -> int:
    """Один реальный пинг «руками» (gate + GET или GET /fail), без записи state.

    Требует root: читает `/etc/vds/dms.env` (0600). URL не печатается.
    """
    if root == "/" and os.geteuid() != 0:
        console.print("[error][dms] test требует root (читает /etc/vds/dms.env).[/error]")
        return 1

    cfg = load_config(str(_env_path(root)))
    for warning in config_warnings(cfg):
        console.print(f"[warning][dms] {warning}[/warning]")
    if not cfg.ping_url:
        console.print("[error][dms] нет DMS_PING_URL — заполните dms.env[/error]")
        return 1

    gate_result = gate.check_gate(cfg)
    console.print(
        f"[info][dms] gate ({cfg.role}): {'ok' if gate_result.ok else 'FAIL'} — {gate_result.detail}[/info]"
    )
    if gate_result.ok:
        ok, errclass = gate.http_get(cfg.ping_url)
        if ok:
            console.print("DMS-SENT ping", markup=False, highlight=False, soft_wrap=True)
            return 0
        console.print("DMS-FAILED ping", markup=False, highlight=False, soft_wrap=True)
        return 1

    ok, errclass = gate.http_get(gate.fail_url(cfg.ping_url))
    if ok:
        console.print("DMS-SENT fail (нога мертва — алерт отправлен)", markup=False, highlight=False, soft_wrap=True)
    else:
        console.print("DMS-FAILED fail", markup=False, highlight=False, soft_wrap=True)
    return 0


def cmd_status(*, json_out: bool = False, root: str = "/") -> int:
    """Состояние DMS: конфиг (URL маской), юниты. Без root — урезанно."""
    env_path = _env_path(root)
    present = env_path.is_file()
    cfg = DmsConfig()
    unreadable = "конфиг недоступен — запустите под sudo"
    if present:
        try:
            cfg = load_config(str(env_path))
            warnings = config_warnings(cfg)
        except OSError:
            warnings = [unreadable]  # 0600 root: без sudo файл не читается
    else:
        warnings = [unreadable]

    if root == "/":
        units = {"service": unit_active(DMS_UNIT), "timer": unit_active(DMS_TIMER)}
    else:
        units = {"service": False, "timer": False}

    payload = {
        "config": {
            "path": str(env_path),
            "present": present,
            "role": cfg.role,
            "url_masked": mask_url(cfg),
            "url_configured": bool(cfg.ping_url),
            "warnings": warnings,
        },
        "units": units,
    }

    if json_out:
        console.print(_json_dumps(payload), markup=False, highlight=False, soft_wrap=True)
        return 0

    console.print(f"[info][dms] конфиг: {env_path} ({'есть' if present else 'нет'})[/info]")
    console.print(
        f"[info][dms] роль: {cfg.role or '—'}; URL: "
        f"{'настроен (' + mask_url(cfg) + ')' if cfg.ping_url else 'не настроен'}[/info]"
    )
    for warning in warnings:
        console.print(f"[warning][dms] {warning}[/warning]")
    console.print(
        f"[info][dms] юниты: {DMS_UNIT}={units['service']}, {DMS_TIMER}={units['timer']}[/info]"
    )
    return 0


def _json_dumps(payload: dict) -> str:
    import json

    return json.dumps(payload, ensure_ascii=False, indent=2)
