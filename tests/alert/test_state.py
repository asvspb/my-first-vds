"""Тесты состояния сторожа и чистой логики подавления (SPEC §3.6, §6)."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

from src.alert.state import (
    bump_suppressed,
    clear_suppressed,
    decide,
    empty_state,
    iso,
    load_state,
    parse_iso,
    prune_window,
    record_send,
    save_state,
    set_source,
)

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# load/save
# ---------------------------------------------------------------------------

def test_load_state_missing_file_is_empty_not_corrupted(tmp_path):
    state, corrupted = load_state(tmp_path / "absent.json")
    assert corrupted is False
    assert state["version"] == 1
    assert state["sources"]["threat"] == {}


def test_load_state_corrupt_json(tmp_path):
    path = tmp_path / "alert-state.json"
    path.write_text("{not json", encoding="utf-8")
    state, corrupted = load_state(path)
    assert corrupted is True
    assert state == empty_state()


def test_load_state_non_object(tmp_path):
    path = tmp_path / "alert-state.json"
    path.write_text("[1,2,3]", encoding="utf-8")
    state, corrupted = load_state(path)
    assert corrupted is True
    assert isinstance(state, dict)


def test_load_state_normalizes_sources(tmp_path):
    path = tmp_path / "alert-state.json"
    path.write_text(json.dumps({"version": 1, "sources": {"threat": "broken"}}), encoding="utf-8")
    state, corrupted = load_state(path)
    assert corrupted is False
    assert state["sources"]["threat"] == {}
    assert state["sources"]["heartbeat"] == {}


def test_save_state_0600_and_atomic(tmp_path):
    path = tmp_path / "alert-state.json"
    state = empty_state()
    record_send(state, "threat", "threat_elevated", 1, NOW)

    assert save_state(state, path) is True
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    # атомарность: никаких .tmp-файлов рядом не осталось
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == []

    reloaded, corrupted = load_state(path)
    assert corrupted is False
    assert reloaded["sources"]["threat"]["severity"] == 1
    assert reloaded["sources"]["threat"]["last_sent"] == iso(NOW)


def test_save_state_unwritable_path_returns_false(tmp_path):
    # путь, где родитель — файл, а не каталог
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    assert save_state(empty_state(), blocker / "state.json") is False


# ---------------------------------------------------------------------------
# decide(): таблица решений
# ---------------------------------------------------------------------------

def _prev(severity: int, sent_ago_min: int, window: int = 0) -> dict:
    state = empty_state()
    set_source(
        state,
        "threat",
        severity=severity,
        last_sent=iso(NOW - timedelta(minutes=sent_ago_min)),
        last_sent_type="threat_elevated",
    )
    state["window"] = [iso(NOW - timedelta(minutes=i)) for i in range(window)]
    return state


def test_decide_disabled_for_none_severity():
    assert decide("threat", None, empty_state(), NOW, 30, 6).reason == "disabled"


def test_decide_first_send():
    decision = decide("threat", 1, empty_state(), NOW, 30, 6)
    assert decision.send is True
    assert decision.reason == "send"


def test_decide_duplicate_within_cooldown():
    decision = decide("threat", 1, _prev(1, sent_ago_min=5), NOW, 30, 6)
    assert decision.send is False
    assert decision.reason == "duplicate"


def test_decide_reminder_after_cooldown():
    decision = decide("threat", 1, _prev(1, sent_ago_min=45), NOW, 30, 6)
    assert decision.send is True
    assert decision.reason == "send"


def test_decide_escalation_bypasses_cooldown_and_rate_limit():
    prev = _prev(1, sent_ago_min=1, window=6)  # и cooldown, и лимит исчерпаны
    decision = decide("threat", 2, prev, NOW, 30, 6)
    assert decision.send is True
    assert decision.reason == "escalation"


def test_decide_downgrade_suppressed_by_cooldown_then_sent():
    prev = _prev(2, sent_ago_min=5)
    assert decide("threat", 0, prev, NOW, 30, 6).reason == "cooldown"
    prev = _prev(2, sent_ago_min=40)
    decision = decide("threat", 0, prev, NOW, 30, 6)
    assert decision.send is True
    assert decision.reason == "send"


def test_decide_rate_limited_at_six_per_hour():
    prev = _prev(1, sent_ago_min=120, window=6)  # лимит исчерпан, cooldown истёк
    decision = decide("threat", 1, prev, NOW, 30, 6)
    assert decision.send is False
    assert decision.reason == "rate_limited"


def test_decide_window_older_than_hour_not_counted():
    state = empty_state()
    state["window"] = [iso(NOW - timedelta(hours=2)) for _ in range(10)]
    assert decide("heartbeat", 0, state, NOW, 0, 6).send is True


def test_decide_per_source_isolation():
    prev = _prev(2, sent_ago_min=1)
    # другой источник не наследует cooldown threat
    assert decide("heartbeat", 0, prev, NOW, 30, 6).send is True


# ---------------------------------------------------------------------------
# bookkeeping
# ---------------------------------------------------------------------------

def test_record_send_updates_source_and_window():
    state = empty_state()
    record_send(state, "relay_pulse", "relay_blocked", 2, NOW)
    src = state["sources"]["relay_pulse"]
    assert src["severity"] == 2
    assert src["last_sent_type"] == "relay_blocked"
    assert src["last_sent"] == iso(NOW)
    assert state["window"] == [iso(NOW)]
    assert state["updated"] == iso(NOW)


def test_prune_window_drops_old_entries():
    state = empty_state()
    state["window"] = [iso(NOW - timedelta(hours=2)), iso(NOW - timedelta(minutes=10))]
    prune_window(state, NOW)
    assert state["window"] == [iso(NOW - timedelta(minutes=10))]


def test_suppressed_counter_increment_and_clear():
    state = empty_state()
    bump_suppressed(state, "threat_high")
    bump_suppressed(state, "threat_high")
    bump_suppressed(state, "relay_pulse")
    assert state["suppressed"] == {"threat_high": 2, "relay_pulse": 1}
    clear_suppressed(state)
    assert state["suppressed"] == {}


def test_parse_iso_tolerance():
    assert parse_iso("") is None
    assert parse_iso("not-a-date") is None
    assert parse_iso(None) is None
    # naive трактуется как UTC
    assert parse_iso("2026-11-17T12:00:00") == NOW
    assert parse_iso("2026-11-17T12:00:00+00:00") == NOW
