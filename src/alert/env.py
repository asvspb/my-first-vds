"""Схема `/etc/vds/alert.env` (SPEC-20261117-alert-watch §3.5).

Формат `KEY=VALUE`, `#`-комментарии — разбирается `core.shell.load_env`
(переиспользуем, свой парсер не пишем). Запись — `core.secrets.write_secret_atomic`
(mode 0600) из `cli.py`.

Инвариант: **значения секретов не печатаются нигде**. Единственный путь показа
конфига — `render_env(with_secrets=False)`, где `TG_BOT_TOKEN`/`SMTP_PASS`
заменены на маску.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.alert.paths import ALERT_ENV_PATH
from src.core.shell import load_env

# Маска вместо значения секрета в `render_env(with_secrets=False)`.
SECRET_MASK = "***"

_DURATION_RE = re.compile(r"^(\d+)\s*([smhd]?)$")
_DURATION_MULT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

_TRUTHY = {"1", "true", "yes", "on"}


def parse_duration(text: str) -> int:
    """`"30s"|"2m"|"24h"|"1d"|"45"` → секунды. Мусор/ноль/минус → ValueError."""
    raw = (text or "").strip().lower()
    match = _DURATION_RE.fullmatch(raw)
    if not match:
        raise ValueError(f"ожидался формат <N>[s|m|h|d], получено {text!r}")
    value, unit = int(match.group(1)), match.group(2)
    seconds = value * _DURATION_MULT[unit]
    if seconds <= 0:
        raise ValueError(f"длительность должна быть > 0, получено {text!r}")
    return seconds


@dataclass(frozen=True)
class AlertConfig:
    """Параметры сторожа. Порядок `channels` — порядок отправки."""

    channels: tuple[str, ...] = ()
    tg_token: str = ""
    tg_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_to: tuple[str, ...] = ()
    smtp_starttls: bool = False
    site_name: str = ""
    handshake_threshold_s: int = 300
    heartbeat_h: int = 24
    cooldown_min: int = 30
    rate_limit_per_hour: int = 6
    lock_reminder_h: int = 6
    high_reminder_h: int = 6
    telemetry_reminder_h: int = 24
    relay_peer: str = "relay"
    relay_iface: str = "awg0"
    relay_probe_port: int = 443
    tcp_timeout_s: int = 3
    enabled_checks: tuple[str, ...] = ("threat", "relay_pulse", "lockdown")


def _int(env: dict[str, str], key: str, default: int) -> int:
    raw = (env.get(key) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _int_clamped(env: dict[str, str], key: str, default: int, lo: int, hi: int) -> int:
    """int из env с ограничением диапазона (значения вне — к ближней границе)."""
    return max(lo, min(hi, _int(env, key, default)))


def _bool(env: dict[str, str], key: str, default: bool = False) -> bool:
    raw = (env.get(key) or "").strip().lower()
    if not raw:
        return default
    return raw in _TRUTHY


def _csv(env: dict[str, str], key: str) -> tuple[str, ...]:
    raw = (env.get(key) or "").strip()
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def load_config(path: str = ALERT_ENV_PATH) -> AlertConfig:
    """Прочитать `alert.env`; отсутствие файла — дефолты (SPEC §3.3)."""
    env = load_env(path)
    channels = tuple(c.lower() for c in _csv(env, "ALERT_CHANNELS") if c.lower() in ("tg", "smtp"))
    return AlertConfig(
        channels=channels,
        tg_token=(env.get("TG_BOT_TOKEN") or "").strip(),
        tg_chat_id=(env.get("TG_CHAT_ID") or "").strip(),
        smtp_host=(env.get("SMTP_HOST") or "").strip(),
        smtp_port=_int(env, "SMTP_PORT", 465),
        smtp_user=(env.get("SMTP_USER") or "").strip(),
        smtp_pass=(env.get("SMTP_PASS") or "").strip(),
        smtp_from=(env.get("SMTP_FROM") or "").strip(),
        smtp_to=_csv(env, "SMTP_TO"),
        smtp_starttls=_bool(env, "SMTP_STARTTLS"),
        site_name=(env.get("ALERT_SITE_NAME") or "").strip(),
        handshake_threshold_s=_int(env, "ALERT_HANDSHAKE_THRESHOLD_S", 300),
        heartbeat_h=_int(env, "ALERT_HEARTBEAT_H", 24),
        cooldown_min=_int(env, "ALERT_COOLDOWN_MIN", 30),
        rate_limit_per_hour=_int(env, "ALERT_RATE_LIMIT_PER_HOUR", 6),
        lock_reminder_h=_int(env, "ALERT_LOCK_REMINDER_H", 6),
        # Каденция напоминания о затяжном high: 1..24 ч, дефолт 6 (симметрично
        # lock_reminder_h). Переходы в/из high остаются мгновенными.
        high_reminder_h=_int_clamped(env, "ALERT_HIGH_REMINDER_H", 6, 1, 24),
        telemetry_reminder_h=_int(env, "ALERT_TELEMETRY_REMINDER_H", 24),
        relay_peer=(env.get("ALERT_RELAY_PEER") or "").strip() or "relay",
        relay_iface=(env.get("ALERT_RELAY_IFACE") or "").strip() or "awg0",
        relay_probe_port=_int(env, "ALERT_RELAY_PROBE_PORT", 443),
        tcp_timeout_s=_int(env, "ALERT_TCP_TIMEOUT_S", 3),
        enabled_checks=_csv(env, "ALERT_CHECKS") or ("threat", "relay_pulse", "lockdown"),
    )


def relay_ifaces(cfg: AlertConfig) -> tuple[str, ...]:
    """Интерфейсы ноги релея из `ALERT_RELAY_IFACE` (список через запятую).

    Один носитель — как раньше (`awg0`, `awg2`); два и более — после ADR-016
    (`awg2,wg-ws0`): пульс считается `ok`, если жив ЛЮБОЙ из них.
    """
    raw = (getattr(cfg, "relay_iface", "") or "").strip() or "awg0"
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    return items or ("awg0",)


def tg_configured(cfg: AlertConfig) -> bool:
    return bool(cfg.tg_token and cfg.tg_chat_id)


def smtp_configured(cfg: AlertConfig) -> bool:
    return bool(cfg.smtp_host and cfg.smtp_from and cfg.smtp_to)


def active_channels(cfg: AlertConfig) -> tuple[str, ...]:
    """Каналы, реально готовые к отправке (наличие пары ключей = включён).

    Если `ALERT_CHANNELS` задан, порядок и состав берутся оттуда, но
    недоконфигурированный канал всё равно отбрасывается (иначе отправка
    упала бы в `config` на каждом тике).
    """
    ready = {"tg": tg_configured(cfg), "smtp": smtp_configured(cfg)}
    ordered = cfg.channels or ("tg", "smtp")
    return tuple(ch for ch in ordered if ready.get(ch))


def config_warnings(cfg: AlertConfig) -> list[str]:
    """Человекочитаемые предупреждения о неполной конфигурации каналов."""
    warnings: list[str] = []
    wants = cfg.channels or ("tg", "smtp")
    if "tg" in wants:
        if not cfg.tg_token:
            warnings.append("tg: нет TG_BOT_TOKEN")
        if not cfg.tg_chat_id:
            warnings.append("tg: нет TG_CHAT_ID")
    if "smtp" in wants:
        if not cfg.smtp_host:
            warnings.append("smtp: нет SMTP_HOST")
        if not cfg.smtp_from:
            warnings.append("smtp: нет SMTP_FROM")
        if not cfg.smtp_to:
            warnings.append("smtp: нет SMTP_TO")
        if not cfg.smtp_pass:
            warnings.append("smtp: нет SMTP_PASS (App Password)")
    if not active_channels(cfg):
        warnings.append("нет ни одного канала — уведомления выключены")
    return warnings


def render_env(cfg: AlertConfig, *, with_secrets: bool) -> str:
    """Отрендерить содержимое `alert.env`.

    `with_secrets=False` — единственный допустимый путь для показа конфига:
    `TG_BOT_TOKEN`/`SMTP_PASS` выводятся как маска (или пусто, если не заданы).
    """
    def secret(value: str) -> str:
        if not value:
            return ""
        return value if with_secrets else SECRET_MASK

    to_value = ",".join(cfg.smtp_to)
    checks = ",".join(cfg.enabled_checks)
    lines = [
        "# vds alert — каналы и параметры сторожа (0600). Значения не печатать.",
        "# --- каналы (наличие пары ключей = канал включён) ---",
        f"TG_BOT_TOKEN={secret(cfg.tg_token)}",
        f"TG_CHAT_ID={cfg.tg_chat_id}",
        f"SMTP_HOST={cfg.smtp_host}",
        f"SMTP_PORT={cfg.smtp_port}",
        f"SMTP_USER={cfg.smtp_user}",
        f"SMTP_PASS={secret(cfg.smtp_pass)}",
        f"SMTP_FROM={cfg.smtp_from}",
        f"SMTP_TO={to_value}",
        f"SMTP_STARTTLS={'1' if cfg.smtp_starttls else '0'}",
        f"ALERT_CHANNELS={','.join(cfg.channels)}",
        "# --- параметры (не секреты, но файл всё равно 0600) ---",
        f"ALERT_SITE_NAME={cfg.site_name}",
        f"ALERT_HANDSHAKE_THRESHOLD_S={cfg.handshake_threshold_s}",
        f"ALERT_HEARTBEAT_H={cfg.heartbeat_h}",
        f"ALERT_COOLDOWN_MIN={cfg.cooldown_min}",
        f"ALERT_RATE_LIMIT_PER_HOUR={cfg.rate_limit_per_hour}",
        f"ALERT_LOCK_REMINDER_H={cfg.lock_reminder_h}",
        f"ALERT_HIGH_REMINDER_H={cfg.high_reminder_h}",
        f"ALERT_TELEMETRY_REMINDER_H={cfg.telemetry_reminder_h}",
        f"ALERT_RELAY_PEER={cfg.relay_peer}",
        f"ALERT_RELAY_IFACE={cfg.relay_iface}",
        f"ALERT_RELAY_PROBE_PORT={cfg.relay_probe_port}",
        f"ALERT_TCP_TIMEOUT_S={cfg.tcp_timeout_s}",
        f"ALERT_CHECKS={checks}",
        "",
    ]
    return "\n".join(lines)
