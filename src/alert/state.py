"""Состояние сторожа `/var/lib/vds/alert-state.json` и логика подавления.

Схема (SPEC §3.6, версия 1). Файл — 0600, root, атомарная запись
(`core.secrets.write_secret_atomic`), мутации под `FileLock` (берёт `watch.py`).

`decide()` — **чистая** функция: не читает файлы и не смотрит на часы, всё
приходит параметрами. Это позволяет покрыть таблицу решений тестами без
root/сети/времени.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from src.alert.paths import ALERT_STATE_PATH
from src.core.secrets import write_secret_atomic

STATE_VERSION = 1

# Источники (ключи `state["sources"]`) — они же `event` для `decide()`.
SOURCES = ("threat", "relay_pulse", "lockdown", "heartbeat", "telemetry")


@dataclass(frozen=True)
class Decision:
    send: bool
    reason: str  # "send"|"escalation"|"cooldown"|"duplicate"|"rate_limited"|"disabled"


def iso(dt: datetime) -> str:
    """UTC ISO-8601 с offset (SPEC §3.6: все времена — UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(text: object) -> Optional[datetime]:
    """Разобрать ISO-время; пустое/битое → None (naive трактуется как UTC)."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def empty_state() -> dict:
    return {
        "version": STATE_VERSION,
        "updated": "",
        "sources": {name: {} for name in SOURCES},
        "window": [],
        "suppressed": {},
        "failures": {},
    }


def load_state(path: Path = ALERT_STATE_PATH) -> tuple[dict, bool]:
    """Прочитать состояние. Возвращает `(state, corrupted)`.

    Нет файла — пустое состояние и `corrupted=False` (штатный первый тик).
    Битый JSON / не объект — пустое состояние и `corrupted=True`: тик продолжится,
    в journal уйдёт `ALERT-FAILED state corrupt` (FR-3), файл молча не удаляется.
    """
    state_path = Path(path)
    if not state_path.is_file():
        return empty_state(), False
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return empty_state(), True
    if not isinstance(data, dict):
        return empty_state(), True
    state = empty_state()
    state.update(data)
    # Гарантируем форму, на которую опираются потребители.
    if not isinstance(state.get("sources"), dict):
        state["sources"] = {}
    for name in SOURCES:
        if not isinstance(state["sources"].get(name), dict):
            state["sources"][name] = {}
    for key in ("window", "suppressed", "failures"):
        if not isinstance(state.get(key), type(empty_state()[key])):
            state[key] = empty_state()[key]
    state["version"] = STATE_VERSION
    return state, False


def save_state(state: dict, path: Path = ALERT_STATE_PATH) -> bool:
    """Атомарно сохранить состояние (0600). True — успех."""
    state["version"] = STATE_VERSION
    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return write_secret_atomic(str(path), payload, mode=0o600)


def prune_window(state: dict, now: datetime) -> None:
    """Вычистить метки отправок старше часа (SPEC §3.6)."""
    cutoff = now - timedelta(hours=1)
    kept: list[str] = []
    for raw in state.get("window") or []:
        ts = parse_iso(raw)
        if ts is not None and ts > cutoff:
            kept.append(iso(ts))
    state["window"] = kept


def decide(
    event: str,
    severity: Optional[int],
    prev: dict,
    now: datetime,
    cooldown_min: int,
    rate_limit_per_hour: int,
) -> Decision:
    """Решение «отправлять ли» (SPEC §3.6 / §12 OQ-4).

    Таблица:
      * `severity is None` — проверка выключена → `disabled`;
      * `severity > last_severity` — эскалация, обходит cooldown **и** лимит;
      * `severity == last_severity` и с прошлой отправки меньше cooldown →
        `duplicate`; после cooldown — повтор (напоминание) с учётом лимита;
      * `severity < last_severity` и меньше cooldown → `cooldown` (гасим флап
        high→quiet→high); после cooldown — информирующий `send` (release);
      * больше `rate_limit_per_hour` отправок за час → `rate_limited`.
    """
    if severity is None:
        return Decision(False, "disabled")

    source = (prev.get("sources") or {}).get(event) or {}
    last_ts = parse_iso(source.get("last_sent"))
    last_sev = source.get("severity")
    if not isinstance(last_sev, int):
        last_sev = None

    in_cooldown = (
        last_ts is not None and (now - last_ts) < timedelta(minutes=max(cooldown_min, 0))
    )

    if last_sev is not None and severity > last_sev:
        return Decision(True, "escalation")
    if last_sev is not None and severity == last_sev and in_cooldown:
        return Decision(False, "duplicate")
    if last_sev is not None and severity < last_sev and in_cooldown:
        return Decision(False, "cooldown")

    cutoff = now - timedelta(hours=1)
    sent_last_hour = sum(
        1 for raw in (prev.get("window") or []) if (ts := parse_iso(raw)) and ts > cutoff
    )
    if sent_last_hour >= max(rate_limit_per_hour, 0):
        return Decision(False, "rate_limited")
    return Decision(True, "send")


def record_send(state: dict, event: str, event_type: str, severity: int, now: datetime) -> None:
    """Зафиксировать состоявшуюся доставку (обновляет источник и окно)."""
    sources = state.setdefault("sources", {})
    source = sources.setdefault(event, {})
    source["severity"] = severity
    source["last_sent"] = iso(now)
    source["last_sent_type"] = event_type
    prune_window(state, now)
    state.setdefault("window", []).append(iso(now))
    state["updated"] = iso(now)


def bump_suppressed(state: dict, event_type: str) -> None:
    """Учесть подавлённое сообщение (счётчики сводки, SPEC §3.6)."""
    suppressed = state.setdefault("suppressed", {})
    suppressed[event_type] = int(suppressed.get(event_type) or 0) + 1


def clear_suppressed(state: dict) -> None:
    state["suppressed"] = {}


def set_source(state: dict, event: str, **fields: object) -> None:
    """Обновить служебные поля источника без отметки об отправке."""
    source = state.setdefault("sources", {}).setdefault(event, {})
    source.update(fields)
