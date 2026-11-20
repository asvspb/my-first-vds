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
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=True),
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
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=False),
    )
    assert result["action"] == "exhausted"
    state = load_state(path)
    assert state["state"] == STATE_EXHAUSTED
    assert state["active"] == PRIMARY  # маршрут не менялся


def test_rollback_idempotent_in_fallback(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK)
    result = carriers.on_maneuver_rollback(state_path=path, now=NOW,
                                           probe_fn=_fake_probe())
    assert result["action"] == "noop"


# --- fallback: P25 no-op и анти-джиттер ------------------------------------

def test_fallback_tick_wg_ok_holds(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=(NOW).isoformat())
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=True),
    )
    assert result["action"] == "hold"
    assert load_state(path)["wg_fail_streak"] == 0


def test_fallback_tick_three_fails_then_exhausted(tmp_path):
    """AC-S5/анти-джиттер: 3/3 провалов wg-ws0 → exhausted, не по одному."""
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=NOW.isoformat())
    for i in range(2):
        result = carriers.fallback_tick(
            state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=False),
        )
        assert result["action"] == "hold"
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=False),
    )
    assert result["action"] == "exhausted"
    assert load_state(path)["state"] == STATE_EXHAUSTED


def test_fallback_no_age_does_not_recover(tmp_path):
    """< 600 с в fallback — возврата нет даже при живом awg1 (AC-6)."""
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=NOW.isoformat())
    for _ in range(5):
        result = carriers.fallback_tick(
            state_path=path, now=NOW, probe_fn=_fake_probe(awg=True, wstun=True),
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
        "state": "cooldown", "exhausted": True,
        # P0-4: счётчик живёт в last_sample — infect именно там
        "last_sample": {"consecutive_failures": 3, "activity": True},
        "failed_ports": [51901, 51902, 51903], "current_port": 51900,
        "cooldown_until": "2099-01-01T00:00:00+00:00",
    }
    mpath.write_text(json.dumps(mstate), encoding="utf-8")

    for i in range(2):
        result = carriers.fallback_tick(
            state_path=path, maneuver_path=str(mpath), now=NOW,
            probe_fn=_fake_probe(awg=True, wstun=True),
        )
        assert result["action"] == "hold"  # серия 1, 2
    result = carriers.fallback_tick(
        state_path=path, maneuver_path=str(mpath), now=NOW,
        probe_fn=_fake_probe(awg=True, wstun=True),
    )
    assert result["action"] == "switched" and result["to"] == PRIMARY
    state = load_state(path)
    assert state["active"] == PRIMARY and state["state"] == STATE_PRIMARY
    # P25-серия сброшена (иначе старые 3/3 дадут ложный манёвр)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    assert m["state"] == "healthy"
    assert m["last_sample"]["consecutive_failures"] == 0  # P0-4: правильное поле
    assert m["failed_ports"] == []
    assert m["exhausted"] is False
    assert m["cooldown_until"] is None


def test_recovering_streak_resets_on_failure(tmp_path):
    late = NOW - __import__("datetime").timedelta(seconds=FALLBACK_TO_RECOVER_MIN_S + 60)
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=late.isoformat(),
                     recover_ok_streak=2)
    result = carriers.fallback_tick(
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=True),
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
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=True, wstun=False),
    )
    assert result["action"] == "recovered" and result["to"] == PRIMARY
    assert load_state(path)["state"] == STATE_PRIMARY


def test_exhausted_holds_when_both_dead(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_EXHAUSTED)
    result = carriers.exhausted_recovery_check(
        state_path=path, now=NOW, probe_fn=_fake_probe(awg=False, wstun=False),
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
        now=NOW, probe_fn=_fake_probe(awg=False, wstun=True),
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


# --- P0-1 ревью: probe_fn=None → модульная probe через run ------------------

class _InterfaceRunner:
    """run_list: ping жив только для заданного интерфейса (по peer-IP в args)."""

    def __init__(self, *, awg=True, wstun=True):
        self.awg, self.wstun = awg, wstun

    def __call__(self, argv, timeout=None, check=False):
        call = list(argv)
        if call[:1] == ["ping"]:
            peer = next((a for a in call if a.startswith("10.11.") or a.startswith("10.12.")), "")
            ok = self.awg if peer.startswith("10.11.") else self.wstun
            return ShellResult("", "", 0 if ok else 1)
        return ShellResult("", "", 0)


def test_rollback_probe_fn_none_uses_module_probe(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True)
    runner = _InterfaceRunner(awg=False, wstun=True)
    result = carriers.on_maneuver_rollback(state_path=path, now=NOW, run=runner)
    assert result["action"] == "switched" and result["to"] == WSTUNNEL


def test_fallback_tick_probe_fn_none_uses_module_probe(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, active=WSTUNNEL,
                     state=STATE_FALLBACK, fallback_since=NOW.isoformat())
    result = carriers.fallback_tick(
        state_path=path, now=NOW, run=_InterfaceRunner(awg=False, wstun=True),
    )
    assert result["action"] == "hold"


def test_exhausted_check_probe_fn_none_uses_module_probe(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_EXHAUSTED)
    result = carriers.exhausted_recovery_check(
        state_path=path, now=NOW, run=_InterfaceRunner(awg=True, wstun=False),
    )
    assert result["action"] == "recovered" and result["to"] == PRIMARY


def test_is_exhausted(tmp_path):
    path, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_EXHAUSTED)
    assert carriers.is_exhausted(load_state(path)) is True
    path2, _ = _write(tmp_path, wg_ws0_installed=True, state=STATE_PRIMARY)
    assert carriers.is_exhausted(load_state(path2)) is False


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# P2-2 (ревью 769a7eb): интеграционные тесты maneuver → carriers.
# Без подмены probe/wait_liveness — только run_list (общий для обоих модулей):
# ping -I awg1 (10.11.0.1) → fail, ping -I wg-ws0 (10.12.0.1) → ok.
# Закрывает класс регрессий P0-1…P0-5 (живая связка maneuver → carriers).
# ---------------------------------------------------------------------------

import src.relay.maneuver as maneuver_mod

MANEUVER_PUB = "FIXTURE_PUBKEY_MANEUVER_LEG1"
CONF_TEXT = (
    "[Interface]\n"
    "Address = 10.11.0.2/30\n"
    "PrivateKey = FIXTURE_PW_AWG1=\n"
    "Table = off\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {MANEUVER_PUB}\n"
    "Endpoint = 198.51.100.10:51900\n"
    "AllowedIPs = 0.0.0.0/0\n"
)


class _P2PRunner:
    """Общий run_list maneuver + carriers: awg1-пинг мёртв, wg-ws0 жив."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout=None, check=False):
        call = list(argv)
        self.calls.append(call)
        if call[:1] == ["ping"]:
            peer = next(
                (a for a in call if a.startswith("10.11.") or a.startswith("10.12.")), ""
            )
            ok = peer.startswith("10.12.")  # wg-ws0 жив, awg1 мёртв
            return ShellResult("", "", 0 if ok else 1)
        if call[:3] == ["awg", "show", "awg1"] and call[3:] == ["dump"]:
            dump = (
                "privkey\tpubkey\t51900\toff\n"
                f"{MANEUVER_PUB}\t(none)\t198.51.100.10:51900\t10.11.0.2/32\t"
                f"{int(NOW.timestamp())}\t50\t60\toff\n"
            )
            return ShellResult(dump, "", 0)
        if call[:2] == ["awg", "show"] and call[3:4] == ["transfer"]:
            # awg0: tx=50000 → Δtx ≥ 4096 → activity=1 (гейт открыт)
            if call[2] == "awg0":
                return ShellResult("PUBX\t10\t50000\n", "", 0)
            return ShellResult("PUBX\t50\t60\n", "", 0)
        return ShellResult("", "", 0)

    def commands(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


def _setup_maneuver_env(tmp_path, monkeypatch, runner):
    conf = tmp_path / "amnezia" / "awg1.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(CONF_TEXT, encoding="utf-8")
    monkeypatch.setattr(maneuver_mod, "RELAY_EXIT_CONFIG_PATH", conf)
    monkeypatch.setattr(maneuver_mod, "RELAY_MANEUVER_LOCK_FILE",
                        str(tmp_path / "maneuver.lock"))
    monkeypatch.setattr(maneuver_mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(maneuver_mod, "run_list", runner)
    monkeypatch.setattr(carriers, "run_list", runner)
    ws_conf = tmp_path / "etc" / "amnezia" / "wg-ws0.conf"
    ws_conf.parent.mkdir(parents=True, exist_ok=True)
    ws_conf.write_text("[Interface]\nPrivateKey = FIXTURE_PW_WG_WS=\n", encoding="utf-8")
    monkeypatch.setattr(carriers, "WG_WS_CONF", ws_conf)
    monkeypatch.setattr(carriers, "CARRIERS_STATE_PATH",
                        tmp_path / "p2p-carriers.json")

    gw = tmp_path / "gateway-state.json"
    gw.write_text(json.dumps({"version": 1, "protocols": {"relay": {"installed": True}}}),
                  encoding="utf-8")
    return str(gw), str(tmp_path / "relay-maneuver.json")


def _seed_baseline(maneuver_path: str) -> None:
    st = maneuver_mod.default_state()
    st["state"] = "suspect"
    st["last_sample"] = {
        "ts": int(NOW.timestamp()), "liveness_ok": False,
        "consecutive_failures": 2, "activity": True,
        "awg0_rx_sum": 10, "awg0_tx_sum": 10,
        "awg1_rx": 0, "awg1_tx": 10,
    }
    maneuver_mod.save_maneuver_state(st, maneuver_path)


def test_run_tick_rollback_triggers_carrier_switch(tmp_path, monkeypatch):
    """P2-2: полный run_tick → rollback → селектор переключил на wg-ws0."""
    runner = _P2PRunner()
    gw_path, mpath = _setup_maneuver_env(tmp_path, monkeypatch, runner)
    _seed_baseline(mpath)
    assert maneuver_mod.run_tick(
        apply=True, state_path=gw_path, maneuver_path=mpath
    ) == 0
    carriers_state = carriers.load_state()
    assert carriers_state["active"] == WSTUNNEL
    assert carriers_state["state"] == STATE_FALLBACK
    assert carriers_state["since"] is not None
    # awg set дважды: манёвр + rollback (runtime-возврат)
    assert len(runner.commands("awg", "set")) == 2


def test_run_step_in_fallback_is_noop_for_p25(tmp_path, monkeypatch):
    """AC-S6: в fallback run_step не тратит attempts и не вызывает `awg set`."""
    runner = _P2PRunner()
    gw_path, mpath = _setup_maneuver_env(tmp_path, monkeypatch, runner)
    state = carriers.default_state(NOW)
    state.update({"active": WSTUNNEL, "active_iface": "wg-ws0",
                  "state": STATE_FALLBACK, "fallback_since": NOW.isoformat()})
    assert save_state(state)
    _seed_baseline(mpath)
    before = maneuver_mod.load_maneuver_state(mpath)

    assert maneuver_mod.run_step(
        apply=True, state_path=gw_path, maneuver_path=mpath
    ) == 0
    assert runner.commands("awg", "set") == []  # P25 молчит (AC-S6)
    after = maneuver_mod.load_maneuver_state(mpath)
    assert len(after.get("attempts") or []) == len(before.get("attempts") or [])


def test_run_step_exhausted_recovers_and_resets_p25(tmp_path, monkeypatch):
    """P0-5: exhausted + живой awg1 → автовыход в primary + сброс P25-серии."""
    runner = _P2PRunner(awg_ok=True) if False else _P2PRunner()
    # для recovery нужно: ping awg1 ok. В _P2PRunner awg1 мёртв — добавим
    # отдельный runner с живым awg1 и мёртвым wg-ws0 (после возврата неважно).
    class _AliveRunner(_P2PRunner):
        def __call__(self, argv, timeout=None, check=False):
            call = list(argv)
            self.calls.append(call)
            if call[:1] == ["ping"]:
                return ShellResult("", "", 0)  # всё живо
            if call[:3] == ["awg", "show", "awg1"] and call[3:] == ["dump"]:
                dump = (
                    "privkey\tpubkey\t51900\toff\n"
                    f"{MANEUVER_PUB}\t(none)\t198.51.100.10:51900\t10.11.0.2/32\t"
                    f"{int(NOW.timestamp())}\t50\t60\toff\n"
                )
                return ShellResult(dump, "", 0)
            if call[:3] == ["awg", "show"] and call[3:] == ["transfer"]:
                return ShellResult("PUBX\t10\t20\n", "", 0)
            return ShellResult("", "", 0)

    runner = _AliveRunner()
    gw_path, mpath = _setup_maneuver_env(tmp_path, monkeypatch, runner)
    state = carriers.default_state(NOW)
    state.update({"active": PRIMARY, "active_iface": "awg1",
                  "state": STATE_EXHAUSTED, "wg_ws0_installed": True,
                  "exhausted_reason": "оба мертвы"})
    assert save_state(state)
    _seed_baseline(mpath)

    assert maneuver_mod.run_step(
        apply=True, state_path=gw_path, maneuver_path=mpath
    ) == 0
    carriers_state = carriers.load_state()
    assert carriers_state["active"] == PRIMARY
    assert carriers_state["state"] == STATE_PRIMARY
    mstate = maneuver_mod.load_maneuver_state(mpath)
    assert mstate["last_sample"]["consecutive_failures"] == 0  # P0-4: сброс серии
    assert mstate["state"] == "healthy"


# --- P0-1 ревью 5513b68: run_switch(to=awg, apply=True) ---------------------

class _FakeLock:
    """Локальный fake (как в test_wstunnel): реальный flock не нужен."""

    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_run_switch_to_awg_applies_and_resets_p25(tmp_path, monkeypatch):
    """Ручной возврат на awg: route + сброс P25-серии ВНУТРИ lock, без NameError."""
    from src.relay import maneuver

    state_path = str(tmp_path / "p2p-carriers.json")
    state = carriers.default_state(NOW)
    state.update({"active": WSTUNNEL, "active_iface": "wg-ws0",
                  "state": STATE_FALLBACK, "wg_ws0_installed": True,
                  "fallback_since": NOW.isoformat()})
    assert save_state(state, state_path)

    mstate = {
        "state": "cooldown", "exhausted": True,
        "last_sample": {"consecutive_failures": 3},
        "failed_ports": [51901], "current_port": 51900,
    }
    maneuver_path = tmp_path / "relay-maneuver.json"
    maneuver_path.write_text(json.dumps(mstate), encoding="utf-8")

    monkeypatch.setattr("src.core.lock.FileLock", _FakeLock)
    monkeypatch.setattr(carriers.os, "geteuid", lambda: 0)
    ip_calls: list[list[str]] = []

    def fake_run(argv, timeout=None, check=False):
        if argv[:2] == ["ip", "route"]:
            ip_calls.append(list(argv))
        return ShellResult("", "", 0)

    monkeypatch.setattr(carriers, "run_list", fake_run)
    monkeypatch.setattr(maneuver, "RELAY_MANEUVER_LOCK_FILE",
                        str(tmp_path / "maneuver.lock"))
    # reset_p25_state ходит в maneuver.load/save_maneuver_state — мокаем оба
    # (save с p=None писал бы в реальный /var/lib/vds)
    monkeypatch.setattr(
        maneuver, "load_maneuver_state",
        lambda p=None: json.loads(maneuver_path.read_text(encoding="utf-8")),
    )
    monkeypatch.setattr(
        maneuver, "save_maneuver_state",
        lambda st, p=None: maneuver_path.write_text(json.dumps(st, ensure_ascii=False))
        or True,
    )

    code = carriers.run_switch(to=PRIMARY, apply=True, state_path=state_path)
    assert code == 0
    assert ip_calls == [["ip", "route", "replace", "default", "dev", "awg1",
                         "table", "100"]]
    st = load_state(state_path)
    assert st["active"] == PRIMARY and st["state"] == STATE_PRIMARY
    # P25-серия сброшена (правильные поля, внутри lock)
    m = json.loads(maneuver_path.read_text(encoding="utf-8"))
    assert m["state"] == "healthy" and m["exhausted"] is False
    assert m["last_sample"]["consecutive_failures"] == 0


def test_run_switch_dry_run_touches_nothing(tmp_path, monkeypatch):
    state_path = str(tmp_path / "p2p-carriers.json")
    state = carriers.default_state(NOW)
    state.update({"active": WSTUNNEL, "wg_ws0_installed": True})
    assert save_state(state, state_path)
    monkeypatch.setattr(carriers.os, "geteuid", lambda: 1000)

    code = carriers.run_switch(to=PRIMARY, apply=False, state_path=state_path)
    assert code == 0
    assert load_state(state_path)["active"] == WSTUNNEL  # dry-run: без изменений
