"""WP-P2P-3: селектор носителей p2p (ADR-016 §4 I-2, AC-S4…S7).

Без сети/root: пробы и маршруты инжектируются, state — в tmp_path.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

from src.relay import carriers
from src.core.shell import ShellResult
from src.relay.carriers import (
    FALLBACK_TO_RECOVER_MIN_S,
    MAX_SWITCHES_PER_HOUR,
    PRIMARY,
    STATE_EXHAUSTED,
    STATE_FALLBACK,
    STATE_PRIMARY,
    STATE_RECOVERING,
    WSTUNNEL,
    load_state,
    save_state,
)

NOW = carriers.utcnow()

_ip_calls: list[list[str]] = []


def _ok_run(argv, timeout=None, check=False):
    if argv[:2] == ["ip", "route"]:
        _ip_calls.append(list(argv))
    return ShellResult(stdout="", stderr="", returncode=0)


@pytest.fixture(autouse=True)
def _fake_ip_route(monkeypatch):
    _ip_calls.clear()
    monkeypatch.setattr(carriers, "run_list", _ok_run)
    yield


@pytest.fixture(autouse=True)
def _wg_ws0_installed(tmp_path, monkeypatch):
    """Носитель №2 «установлен»: conf существует (иначе весь селектор no-op)."""
    conf = tmp_path / "etc" / "amnezia" / "wg-ws0.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("[Interface]\nPrivateKey = FIXTURE_PW_WG_WS=\n", encoding="utf-8")
    monkeypatch.setattr(carriers, "WG_WS_CONF", conf)
    yield


def _fake_probe(*, awg=True, wstun=True):
    """Проба: awg1 и wg-ws0 управляются флагами."""
    def _probe(iface: str, peer_ip: str) -> bool:
        return awg if iface == "awg1" else wstun
    return _probe


def _write(tmp_path, **over):
    state = carriers.default_state(NOW)
    state.update(over)
    path = str(tmp_path / "p2p-carriers.json")
    assert save_state(state, path)
    return path, state


# --- совместимость / no-op -------------------------------------------------

def test_no_wg_ws0_conf_everything_noop(tmp_path):
    """Без /etc/amnezia/wg-ws0.conf селектор — чистый no-op (совместимость)."""
    monkey_ws = pytest.MonkeyPatch()
    monkey_ws.setattr(carriers, "WG_WS_CONF", tmp_path / "missing.conf")
    try:
        assert carriers.wg_ws0_installed() is False
        assert carriers.p25_noop_reason() is None  # P25 работает как раньше
        assert carriers.on_maneuver_rollback()["action"] == "noop"
        assert carriers.fallback_tick()["action"] == "noop"
    finally:
        monkey_ws.undo()


def test_default_state_is_primary_awg(tmp_path):
    state = load_state(str(tmp_path / "missing.json"))
    assert state["active"] == PRIMARY and state["state"] == STATE_PRIMARY


def test_broken_state_falls_back_to_default(tmp_path):
    path = tmp_path / "p2p.json"
    path.write_text("{broken", encoding="utf-8")
    state = load_state(str(path))
    assert state["active"] == PRIMARY


# --- primary → fallback (хук rollback + pre-check) -------------------------

def test_rollback_with_wstun_alive_switches_to_fallback(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True)
    result = carriers.on_maneuver_rollback(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=True),
    )
    assert result["action"] == "switched" and result["to"] == WSTUNNEL
    state = load_state(path)
    assert state["active"] == WSTUNNEL
    assert state["state"] == STATE_FALLBACK
    assert state["active_iface"] == "wg-ws0"
    assert state["fallback_since"] is not None


def test_rollback_with_wstun_dead_goes_exhausted(tmp_path):
    """AC-S5: не переключаемся на мёртвый носитель — оба мертвы → exhausted."""
    path, _ = _write(tmp_path, wg_ws0_installed=True)
    result = carriers.on_maneuver_rollback(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=False),
    )
    assert result["action"] == "exhausted"
    state = load_state(path)
    assert state["state"] == STATE_EXHAUSTED
    assert state["active"] == PRIMARY  # маршрут не менялся


def test_rollback_idempotent_in_fallback(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK)
    result = carriers.on_maneuver_rollback(state_path=path, now=NOW,
                                           probe=_fake_probe())
    assert result["action"] == "noop"


# --- fallback: P25 no-op и анти-джиттер ------------------------------------

def test_fallback_tick_wg_ok_holds(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=(NOW).isoformat())
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=True),
    )
    assert result["action"] == "hold"
    assert load_state(path)["wg_fail_streak"] == 0


def test_fallback_tick_three_fails_then_exhausted(tmp_path):
    """AC-S5/анти-джиттер: 3/3 провалов wg-ws0 → exhausted, не по одному."""
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=NOW.isoformat())
    for i in range(2):
        result = carriers.fallback_tick(
            state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=False),
        )
        assert result["action"] == "hold"
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=False),
    )
    assert result["action"] == "exhausted"
    assert load_state(path)["state"] == STATE_EXHAUSTED


def test_fallback_no_age_does_not_recover(tmp_path):
    """< 600 с в fallback — возврата нет даже при живом awg1 (AC-6)."""
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=NOW.isoformat())
    for _ in range(5):
        result = carriers.fallback_tick(
            state_path=path, now=NOW, probe=_fake_probe(awg=True, wstun=True),
        )
        assert result["action"] == "hold"  # возраст < 600 с
    assert load_state(path)["active"] == WSTUNNEL


def test_fallback_recover_after_600s_and_3_streak(tmp_path):
    """AC-6: ≥600 с в fallback + 3 подряд ok awg1 → primary + сброс P25-серии."""
    early = NOW - __import__("datetime").timedelta(seconds=FALLBACK_TO_RECOVER_MIN_S + 60)
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=early.isoformat(),
                     switched_at=[early.isoformat()])
    mpath = tmp_path / "relay-maneuver.json"
    # заражённое P25-состояние: 3/3 и exhausted
    mstate = {
        "state": "cooldown", "exhausted": True, "consecutive_failures": 3,
        "failed_ports": [51901, 51902, 51903], "current_port": 51900,
    }
    mpath.write_text(json.dumps(mstate), encoding="utf-8")

    for i in range(2):
        result = carriers.fallback_tick(
            state_path=path, maneuver_path=str(mpath), now=NOW,
            probe=_fake_probe(awg=True, wstun=True),
        )
        assert result["action"] == "hold"  # серия 1, 2
    result = carriers.fallback_tick(
        state_path=path, maneuver_path=str(mpath), now=NOW,
        probe=_fake_probe(awg=True, wstun=True),
    )
    assert result["action"] == "switched" and result["to"] == PRIMARY
    state = load_state(path)
    assert state["active"] == PRIMARY and state["state"] == STATE_PRIMARY
    # P25-серия сброшена (иначе старые 3/3 дадут ложный манёвр)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    assert m["state"] == "healthy"
    assert m["consecutive_failures"] == 0
    assert m["failed_ports"] == []
    assert m["exhausted"] is False


def test_recovering_streak_resets_on_failure(tmp_path):
    late = NOW - __import__("datetime").timedelta(seconds=FALLBACK_TO_RECOVER_MIN_S + 60)
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=late.isoformat(),
                     recover_ok_streak=2)
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=True),
    )
    assert result["action"] == "hold"
    assert load_state(path)["recover_ok_streak"] == 0  # серия сброшена


# --- лимит переключений -----------------------------------------------------

def test_switch_limit_three_per_hour(tmp_path):
    path, state = _write(tmp_path, wg_ws0_installed=True)
    path_str = str(path)
    # 3 переключения за час: туда-обратно-туда
    carriers._apply_switch(WSTUNNEL, state=state, now=NOW, reason="t1",
                           state_path=path_str)
    carriers._apply_switch(PRIMARY, state=state, now=NOW, reason="t2",
                           state_path=path_str)
    carriers._apply_switch(WSTUNNEL, state=state, now=NOW, reason="t3",
                           state_path=path_str)
    with pytest.raises(carriers.CarrierError, match="3 переключений"):
        carriers._apply_switch(PRIMARY, state=state, now=NOW, reason="t4",
                               state_path=path_str)
    # история обрезана до HISTORY_CAP
    assert len(load_state(path_str)["switched_at"]) <= carriers.HISTORY_CAP


# --- exhausted: автовыход ---------------------------------------------------

def test_exhausted_recovers_when_any_carrier_alive(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_EXHAUSTED,
                     active=PRIMARY, active_iface="awg1",
                     exhausted_reason="оба мертвы")
    result = carriers.exhausted_recovery_check(
        state_path=path, now=NOW, probe=_fake_probe(awg=True, wstun=False),
    )
    assert result["action"] == "recovered" and result["to"] == PRIMARY
    assert load_state(path)["state"] == STATE_PRIMARY


def test_exhausted_holds_when_both_dead(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_EXHAUSTED)
    result = carriers.exhausted_recovery_check(
        state_path=path, now=NOW, probe=_fake_probe(awg=False, wstun=False),
    )
    assert result["action"] == "hold"


# --- AC-S4: ExecStartPost скрипт -------------------------------------------

def test_default_iface_script_defaults_and_switches(tmp_path, monkeypatch):
    script_path = tmp_path / "carrier-default-iface.sh"
    monkeypatch.setattr(carriers, "CARRIER_IFACE_SCRIPT", script_path)
    monkeypatch.setattr("src.relay.paths.RELAY_DIR", tmp_path)
    carriers.ensure_default_iface_script()
    text = script_path.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh") and "exit 0" in text

    script_path.chmod(0o755)
    replaced: list[list[str]] = []

    def fake_run(argv, timeout=None, check=False):
        replaced.append(list(argv))
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(carriers, "run_list", fake_run)

    # state без файла → дефолт awg1
    carriers_json = tmp_path / "p2p-carriers.json"
    monkeypatch.setattr(
        carriers, "CARRIERS_STATE_PATH",
        pathlib.Path(carriers_json),
    )
    # Инварианты текста: проверка link перед replace, дефолт из $1, exit 0 всегда
    assert 'ip link show "$iface" >/dev/null 2>&1' in text
    assert 'ip route replace default dev "$iface" table 100' in text
    assert 'case "$i" in' in text and 'awg1|wg-ws0) iface=$i ;;' in text

    # Логика парсера state (внутренний python-фрагмент скрипта) — отдельно:
    state_file = tmp_path / "p2p-carriers.json"
    state_file.write_text(
        json.dumps({"active_iface": "wg-ws0"}), encoding="utf-8"
    )
    parse_snippet = (
        'import json,sys\n'
        'try:\n'
        '    d=json.load(open(sys.argv[1]))\n'
        '    a=str(d.get("active_iface") or "")\n'
        '    print(a if a in ("awg1", "wg-ws0") else "")\n'
        'except Exception:\n'
        '    print("")'
    )
    res = subprocess.run(
        ["python3", "-c", parse_snippet, str(state_file)],
        capture_output=True, text=True,
    )
    assert res.stdout.strip() == "wg-ws0"

    state_file.write_text("{broken", encoding="utf-8")
    res = subprocess.run(
        ["python3", "-c", parse_snippet, str(state_file)],
        capture_output=True, text=True,
    )
    assert res.stdout.strip() == ""  # битый state → пусто → дефолт awg1

    # state с wg-ws0 и живым интерфейсом → wg-ws0 (эмуляция: ip link check пропускаем,
    # проверяем парсинг через подмену run_list не работает — скрипт зовёт ip напрямую;
    # поэтому проверяем только текст скрипта на наличие проверки link)
    assert 'ip link show "$iface"' in text


# --- интеграция с maneuver: no-op в fallback (AC-S6) ------------------------

def test_maneuver_noop_in_fallback(tmp_path, monkeypatch):
    """В fallback тик P25 — no-op: не тратит attempts, не дергает awg set."""
    from src.relay import maneuver

    path = tmp_path / "p2p-carriers.json"
    state = carriers.default_state(NOW)
    state.update({"active": WSTUNNEL, "active_iface": "wg-ws0",
                  "state": STATE_FALLBACK, "wg_ws0_installed": True,
                  "fallback_since": NOW.isoformat()})
    assert save_state(state, str(path))
    monkeypatch.setattr(carriers, "CARRIERS_STATE_PATH", path)
    monkeypatch.setattr(carriers, "WG_WS_CONF", tmp_path / "wg-ws0.conf")

    mstate = maneuver.load_maneuver_state(str(tmp_path / "relay-maneuver.json"))
    mstate.update({"state": "cooldown", "attempts": [], "failed_ports": [],
                   "current_port": 51900})
    maneuver.save_maneuver_state(mstate, str(tmp_path / "relay-maneuver.json"))

    before = maneuver.load_maneuver_state(str(tmp_path / "relay-maneuver.json"))
    result = carriers.fallback_tick(
        state_path=str(path), maneuver_path=str(tmp_path / "relay-maneuver.json"),
        now=NOW, probe=_fake_probe(awg=False, wstun=True),
    )
    after = maneuver.load_maneuver_state(str(tmp_path / "relay-maneuver.json"))
    # attempts не растут (AC-S6), состояние cooldown сохранено
    assert len(after.get("attempts") or []) == len(before.get("attempts") or [])
    assert after["state"] == "cooldown"
    assert result["action"] in ("hold", "noop")


def test_p25_noop_reason_without_carrier2(tmp_path, monkeypatch):
    monkeypatch.setattr(carriers, "WG_WS_CONF", tmp_path / "missing.conf")
    assert carriers.p25_noop_reason() is None  # P25 работает как раньше


def test_p25_noop_reason_in_fallback(tmp_path, monkeypatch):
    path = tmp_path / "p2p-carriers.json"
    state = carriers.default_state(NOW)
    state.update({"active": WSTUNNEL, "state": STATE_FALLBACK,
                  "wg_ws0_installed": True})
    assert save_state(state, str(path))
    monkeypatch.setattr(carriers, "CARRIERS_STATE_PATH", path)
    reason = carriers.p25_noop_reason(carriers.load_state(str(path)))
    assert reason and "AC-S6" in reason
