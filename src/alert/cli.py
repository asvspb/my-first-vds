"""CLI сторожа: install / remove / test / status (SPEC-20261117-alert-watch §3.4).

`install`/`remove` — dry-run по умолчанию; `--apply` требует root. `test`
требует root (читает `alert.env`). `status` работает без root в урезанном виде.
`root` — тестовый префикс ФС (конвенция `core.units`), при `root != "/"`
`systemctl` не дёргается тестами напрямую (его мокают), FileLock не берётся.
"""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from src.alert import channels, checks
from src.alert.env import (
    AlertConfig,
    active_channels,
    config_warnings,
    load_config,
    parse_duration,
    render_env,
)
from src.alert.paths import (
    ALERT_ENV_PATH,
    ALERT_STATE_PATH,
    ALERT_TIMER,
    ALERT_UNIT,
    PROBE_WATCH_PATH,
)
from src.alert.state import iso, load_state
from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit, resolve_python, unit_active

REPO_DIR = Path(__file__).resolve().parents[2]

SERVICE_TEMPLATE = "vds-alert-watch.service.tpl"
TIMER_TEMPLATE = "vds-alert-watch.timer.tpl"

# Имена ключей alert.env — печатаются в плане install (значений там нет).
ENV_KEYS = (
    "TG_BOT_TOKEN",
    "TG_CHAT_ID",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "SMTP_FROM",
    "SMTP_TO",
    "SMTP_STARTTLS",
    "ALERT_CHANNELS",
    "ALERT_SITE_NAME",
    "ALERT_HANDSHAKE_THRESHOLD_S",
    "ALERT_HEARTBEAT_H",
    "ALERT_COOLDOWN_MIN",
    "ALERT_RATE_LIMIT_PER_HOUR",
    "ALERT_LOCK_REMINDER_H",
    "ALERT_TELEMETRY_REMINDER_H",
    "ALERT_RELAY_PEER",
    "ALERT_RELAY_PROBE_PORT",
    "ALERT_TCP_TIMEOUT_S",
    "ALERT_CHECKS",
)


def _rooted(path: str, root: str) -> Path:
    if root == "/":
        return Path(path)
    return Path(root) / path.lstrip("/")


def _env_path(root: str) -> Path:
    return _rooted(ALERT_ENV_PATH, root)


def _state_path(root: str) -> Path:
    return _rooted(str(ALERT_STATE_PATH), root)


def _is_relay_node() -> bool:
    """Узел-релей? На релее секретов нет ни в одном файле (SPEC §3.4, §5)."""
    try:
        from src.gateway.paths import STATE_PATH
        from src.gateway.store import load_state as load_gateway_state

        state = load_gateway_state(str(STATE_PATH))
        return "relay" in (state.protocols or {})
    except Exception:  # state.json битый/нет — не отказ, просто «не релей»
        return False


def _install_ctx(interval_sec: int) -> dict[str, str]:
    install_dir = os.environ.get("INSTALL_DIR", "/opt/my-vds")
    return {
        "python": resolve_python(install_dir),
        "repo_dir": str(REPO_DIR),
        "install_dir": install_dir,
        "interval_sec": str(interval_sec),
    }


def _write_env(path: Path, cfg: AlertConfig) -> bool:
    """Создать `alert.env` из шаблона (0600). Значения секретов пустые."""
    return write_secret_atomic(str(path), render_env(cfg, with_secrets=False), mode=0o600)


def cmd_install(
    *,
    apply: bool = False,
    channel: str | None = None,
    interval: str = "2m",
    handshake_threshold: str = "300s",
    heartbeat: str = "24h",
    force: bool = False,
    allow_relay_node: bool = False,
    root: str = "/",
) -> int:
    """Установить сторожа (юниты + alert.env). Dry-run по умолчанию."""
    try:
        interval_sec = parse_duration(interval)
        threshold_s = parse_duration(handshake_threshold)
        heartbeat_h = max(parse_duration(heartbeat) // 3600, 1)
    except ValueError as exc:
        console.print(f"[error][alert] {exc}[/error]")
        return 1

    relay_node = _is_relay_node()
    if relay_node and not allow_relay_node:
        console.print(
            "[error][alert] install на узле-рееле запрещён: секреты на RU-рееле "
            "не храним (SPEC-20261117 §3.4). Уведомления отправляет exit-узел.[/error]"
        )
        return 1
    if relay_node and allow_relay_node:
        console.print(
            "[warning][alert] --allow-relay-node: alert.env с токенами окажется "
            "на RU-рееле — делать не надо[/warning]"
        )

    env_path = _env_path(root)
    channels_req = tuple(c.strip().lower() for c in (channel or "").split(",") if c.strip())
    cfg = AlertConfig(
        channels=channels_req,
        site_name=socket.gethostname() or "vds",
        handshake_threshold_s=threshold_s,
        heartbeat_h=heartbeat_h,
    )

    if not apply:
        console.print("[info][alert] DRY-RUN план install:[/info]")
        console.print(f"[info][alert]   1. конфиг {env_path} (0600, только при отсутствии; --force перезапишет)[/info]")
        console.print(f"[info][alert]   2. ключи alert.env: {', '.join(ENV_KEYS)}[/info]")
        console.print(f"[info][alert]   3. юниты {ALERT_UNIT} + {ALERT_TIMER} (тик {interval_sec} с, OnBootSec=3min)[/info]")
        console.print(
            f"[info][alert]   каналы: {', '.join(channels_req) or 'авто по наличию пар ключей'}; "
            f"порог handshake {threshold_s} с; heartbeat {heartbeat_h} ч[/info]"
        )
        console.print("[info][alert] Запустите с --apply для исполнения.[/info]")
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][alert] install --apply требует root (sudo).[/error]")
        return 1

    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[error][alert] не удалось создать {env_path.parent}: {exc}[/error]")
        return 1

    if env_path.exists() and not force:
        console.print(f"[info][alert] существующий {env_path} сохранён (--force перезапишет)[/info]")
    elif not _write_env(env_path, cfg):
        console.print(f"[error][alert] не удалось записать {env_path}[/error]")
        return 1
    else:
        console.print(f"[change][alert] конфиг {env_path} создан (0600) — заполните каналы[/change]")

    ctx = _install_ctx(interval_sec)
    for template, name in ((SERVICE_TEMPLATE, ALERT_UNIT), (TIMER_TEMPLATE, ALERT_TIMER)):
        if not install_unit(template, name, ctx, root=root):
            return 1

    start = run_list(["systemctl", "start", ALERT_TIMER], timeout=15)
    if not start.ok:
        console.print(f"[error][alert] не удалось запустить {ALERT_TIMER}: {start.stderr.strip()}[/error]")
        return 1

    warnings = config_warnings(load_config(str(env_path)))
    for warning in warnings:
        console.print(f"[warning][alert] {warning}[/warning]")
    console.print(
        f"[success][alert] сторож установлен: {ALERT_UNIT} + {ALERT_TIMER}. "
        f"Проверка: sudo vds alert test[/success]"
    )
    return 0


def cmd_remove(*, apply: bool = False, purge: bool = False, root: str = "/") -> int:
    """Снять юниты (alert.env сохраняется); `--purge` удаляет env и state."""
    env_path = _env_path(root)
    state_path = _state_path(root)

    if not apply:
        console.print("[info][alert] DRY-RUN план remove:[/info]")
        console.print(f"[info][alert]   1. stop/disable и удалить {ALERT_UNIT}, {ALERT_TIMER}[/info]")
        console.print(f"[info][alert]   2. {env_path} {'удалить (--purge)' if purge else 'сохранить'}[/info]")
        if purge:
            console.print(f"[info][alert]   3. {state_path} удалить[/info]")
        console.print(
            "[info][alert] UFW, probe-watch.json и state.json не затрагиваются (откат без следов).[/info]"
        )
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][alert] remove --apply требует root (sudo).[/error]")
        return 1

    for name in (ALERT_UNIT, ALERT_TIMER):
        if not remove_unit(name, root=root):
            return 1

    if purge:
        for path in (env_path, state_path):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                console.print(f"[error][alert] не удалось удалить {path}: {exc}[/error]")
                return 1
        console.print("[change][alert] alert.env и alert-state.json удалены (--purge)[/change]")
    else:
        console.print(f"[info][alert] {env_path} сохранён (удалить: --purge)[/info]")
    console.print("[success][alert] сторож снят.[/success]")
    return 0


def cmd_test(*, root: str = "/", channel: str | None = None) -> int:
    """Реальная отправка «руками», без записи state (SPEC §4 п.4).

    `channel` (`tg`|`smtp`) — аддитивный фильтр: проверить именно почту/бота.
    """
    if root == "/" and os.geteuid() != 0:
        console.print("[error][alert] test требует root (читает /etc/vds/alert.env).[/error]")
        return 1

    cfg = load_config(str(_env_path(root)))
    for warning in config_warnings(cfg):
        console.print(f"[warning][alert] {warning}[/warning]")

    requested = (channel or "").strip().lower()
    if requested and requested not in ("tg", "smtp"):
        console.print(f"[error][alert] --channel: ожидался tg|smtp, получено {requested!r}[/error]")
        return 1

    targets = (requested,) if requested else active_channels(cfg)
    if not targets:
        console.print("[error][alert] нет сконфигурированных каналов — заполните alert.env[/error]")
        return 1
    if requested and requested not in active_channels(cfg):
        console.print(f"[error][alert] канал {requested} не сконфигурирован в alert.env[/error]")
        return 1

    site = cfg.site_name or socket.gethostname() or "vds"
    subject = f"[{site}] vds alert test"
    text = (
        f"{site}: проверка канала vds alert-watch\n"
        f"время (UTC): {iso(datetime.now(timezone.utc))}\n\n"
        "Если вы это читаете — канал настроен верно."
    )

    failures = 0
    for name in targets:
        if name == "tg":
            result = channels.send_telegram(cfg, text)
        else:
            result = channels.send_smtp(cfg, subject, text)
        if result.ok:
            console.print(f"ALERT-SENT {name} test", markup=False, highlight=False, soft_wrap=True)
        else:
            console.print(f"ALERT-FAILED {name} {result.errclass}", markup=False, highlight=False, soft_wrap=True)
            failures += 1
    return 0 if failures == 0 else 1


def _coverage(cfg: AlertConfig, root: str) -> dict:
    """Что сторож реально видит сейчас (без секретов)."""
    now = datetime.now(timezone.utc)
    threat = checks.read_threat(_rooted(str(PROBE_WATCH_PATH), root), now=now)
    result: dict = {
        "threat": {
            "status": threat.status,
            "level": threat.level,
            "age_sec": threat.age_sec,
            "reason": threat.reason,
        },
        "relay_pulse": {"checked": False},
    }
    if root == "/":
        prev, _corrupted = load_state(_state_path(root))
        signal = checks.read_relay_signal(
            cfg=cfg,
            prev_state=prev,
            now=now,
            tcp_probe=lambda host, port, timeout: None,  # status не делает сетевых проб
        )
        result["relay_pulse"] = {
            "checked": True,
            "classification": signal.classification,
            "detail": signal.detail,
            "peer_found": signal.peer_found,
            "handshake_age_sec": signal.handshake_age_sec,
        }
    try:
        result["lockdown"] = {"active": bool(checks.read_lockdown().get("active"))}
    except Exception:
        result["lockdown"] = {"active": False}
    return result


def cmd_status(*, json_out: bool = False, root: str = "/") -> int:
    """Состояние сторожа: каналы, юниты, coverage. Без root — урезанно."""
    env_path = _env_path(root)
    present = env_path.is_file()
    cfg = load_config(str(env_path))
    warnings = config_warnings(cfg) if present else ["конфиг недоступен — запустите под sudo"]

    state_path = _state_path(root)
    alert_state, corrupted = load_state(state_path)

    if root == "/":
        units = {"service": unit_active(ALERT_UNIT), "timer": unit_active(ALERT_TIMER)}
    else:
        units = {"service": False, "timer": False}

    payload = {
        "config": {
            "path": str(env_path),
            "present": present,
            "channels": list(active_channels(cfg)),
            "warnings": warnings,
        },
        "units": units,
        "coverage": _coverage(cfg, root),
        "state": {
            "path": str(state_path),
            "present": state_path.is_file(),
            "corrupted": corrupted,
            "updated": alert_state.get("updated", ""),
        },
    }

    if json_out:
        console.print(json.dumps(payload, ensure_ascii=False, indent=2), markup=False, highlight=False, soft_wrap=True)
        return 0

    console.print(f"[info][alert] конфиг: {env_path} ({'есть' if present else 'нет'})[/info]")
    console.print(
        f"[info][alert] каналы: {', '.join(payload['config']['channels']) or 'нет активных'}[/info]"
    )
    for warning in warnings:
        console.print(f"[warning][alert] {warning}[/warning]")
    console.print(
        f"[info][alert] юниты: {ALERT_UNIT}={payload['units']['service']}, "
        f"{ALERT_TIMER}={payload['units']['timer']}[/info]"
    )
    threat = payload["coverage"]["threat"]
    console.print(
        f"[info][alert] телеметрия: {threat['status']}, level={threat['level']}, "
        f"возраст={threat['age_sec']} с[/info]"
    )
    relay = payload["coverage"]["relay_pulse"]
    if relay.get("checked"):
        if relay.get("peer_found"):
            console.print(
                f"[info][alert] пульс плеча: {relay['classification']}, "
                f"handshake={relay['handshake_age_sec']} с[/info]"
            )
        else:
            console.print(f"[warning][alert] пульс плеча: слеп ({relay.get('detail')})[/warning]")
    else:
        console.print("[info][alert] пульс плеча: не проверялся (нужен root)[/info]")
    console.print(
        f"[info][alert] лок 443: {'активен' if payload['coverage']['lockdown']['active'] else 'не активен'}[/info]"
    )
    return 0
