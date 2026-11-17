"""Тесты телеметрии и классификации (SPEC §3.1–3.2, §6)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.alert import checks
from src.alert.checks import (
    ACTIVITY_WINDOW_S,
    classify_relay,
    parse_awg_dump,
    read_lockdown,
    read_relay_signal,
    read_threat,
)
from src.alert.env import AlertConfig
from src.alert.paths import PROBE_WATCH_PATH
from src.core.shell import ShellResult

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)

PEER_PUB = "FIXTURE_PUBKEY_RELAY111"
PEER_IP = "10.9.0.2"


# ---------------------------------------------------------------------------
# parse_awg_dump
# ---------------------------------------------------------------------------

IFACE_LINE = "privkey\tpubkey\t51820\toff"


def test_parse_awg_dump_empty_output():
    assert parse_awg_dump("") == {}


def test_parse_awg_dump_interface_only():
    assert parse_awg_dump(IFACE_LINE) == {}


def test_parse_awg_dump_none_endpoint():
    text = (
        f"{IFACE_LINE}\n"
        f"{PEER_PUB}\t(none)\t(none)\t{PEER_IP}/32\t0\t0\t0\toff\n"
    )
    peers = parse_awg_dump(text)
    assert set(peers) == {PEER_PUB}
    assert peers[PEER_PUB].endpoint == ""
    assert peers[PEER_PUB].latest_handshake == 0


def test_parse_awg_dump_two_peers_and_spaces():
    text = (
        f"{IFACE_LINE}\n"
        f"PEER_A\tpsk\t198.51.100.7:51820\t10.9.0.2/32\t1700000000\t1000\t2000\toff\n"
        f"PEER_B   psk   (none)   10.9.0.3/32   0   5   7   off\n"
    )
    peers = parse_awg_dump(text)
    assert set(peers) == {"PEER_A", "PEER_B"}
    assert peers["PEER_A"].endpoint == "198.51.100.7:51820"
    assert peers["PEER_A"].latest_handshake == 1700000000
    assert peers["PEER_A"].rx == 1000
    assert peers["PEER_A"].tx == 2000
    assert peers["PEER_B"].endpoint == ""
    assert peers["PEER_B"].rx == 5


def test_parse_awg_dump_broken_numbers_default_to_zero():
    text = f"{IFACE_LINE}\nPEER_A\tpsk\thost:1\t10.9.0.2/32\tnope\tbad\t-\toff\n"
    peer = parse_awg_dump(text)["PEER_A"]
    assert peer.latest_handshake == 0
    assert peer.rx == 0
    assert peer.tx == 0


def test_parse_awg_dump_garbage_never_raises():
    assert parse_awg_dump("\x00\x01not a dump\n\n") == {}
    assert parse_awg_dump("") == {}
    assert parse_awg_dump("  \n\t\n") == {}


# ---------------------------------------------------------------------------
# read_threat: пять состояний
# ---------------------------------------------------------------------------

def _snapshot(tmp_path, *, ts="2026-11-17T11:50:00+00:00", threat=None):
    path = tmp_path / "probe-watch.json"
    payload = {"version": 2, "ts": ts}
    if threat is not None:
        payload["threat"] = threat
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_read_threat_ok(tmp_path):
    path = _snapshot(tmp_path, threat={"level": "elevated", "reason": "RU-PROBE-SUSPECT"})
    signal = read_threat(path, now=NOW)
    assert signal.status == "ok"
    assert signal.level == "elevated"
    assert signal.reason == "RU-PROBE-SUSPECT"
    assert signal.age_sec == 600


def test_read_threat_missing(tmp_path):
    signal = read_threat(tmp_path / "absent.json", now=NOW)
    assert signal.status == "missing"
    assert signal.level is None


def test_read_threat_corrupt(tmp_path):
    path = tmp_path / "probe-watch.json"
    path.write_text("{broken", encoding="utf-8")
    assert read_threat(path, now=NOW).status == "corrupt"

    path.write_text("[]", encoding="utf-8")
    assert read_threat(path, now=NOW).status == "corrupt"


def test_read_threat_bad_ts_is_corrupt(tmp_path):
    path = _snapshot(tmp_path, ts="not-a-date", threat={"level": "quiet"})
    signal = read_threat(path, now=NOW)
    assert signal.status == "corrupt"
    assert signal.reason == "bad_ts"


def test_read_threat_no_level(tmp_path):
    path = _snapshot(tmp_path, threat={})
    signal = read_threat(path, now=NOW)
    assert signal.status == "no_level"

    path = _snapshot(tmp_path, threat={"level": "weird"})
    assert read_threat(path, now=NOW).status == "no_level"


def test_read_threat_stale(tmp_path):
    path = _snapshot(
        tmp_path, ts=(NOW - timedelta(hours=4)).isoformat(), threat={"level": "quiet"}
    )
    signal = read_threat(path, now=NOW)
    assert signal.status == "stale"
    assert signal.level == "quiet"
    assert signal.age_sec >= 4 * 3600


def test_read_threat_stale_threshold_uses_timer_period(tmp_path):
    # 5 часов при часовом тике — stale (порог max(3ч, 3×1ч)); при 3-часовом тике
    # порог 9 ч → ещё ok.
    path = _snapshot(tmp_path, ts=(NOW - timedelta(hours=5)).isoformat(), threat={"level": "quiet"})
    assert read_threat(path, now=NOW, timer_hours=1).status == "stale"
    assert read_threat(path, now=NOW, timer_hours=3).status == "ok"


def test_snapshot_path_matches_probing():
    """Зеркало SNAPSHOT_PATH не должно дрейфовать (SPEC §3.2)."""
    from src.gateway.probing import SNAPSHOT_PATH

    assert PROBE_WATCH_PATH == SNAPSHOT_PATH


# ---------------------------------------------------------------------------
# classify_relay: вся таблица §3.1
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "age,threshold,tcp,active,expected",
    [
        (100, 300, True, True, "ok"),
        (100, 300, False, False, "ok"),          # свежий handshake важнее TCP
        (-1, 300, True, True, "blocked"),        # мёртв + активность + TCP жив
        (400, 300, True, True, "blocked"),
        (-1, 300, False, True, "relay_down"),    # мёртв + активность + TCP мёртв
        (-1, 300, None, True, "inconclusive"),   # проба не удалась
        (-1, 300, True, False, "idle"),          # мёртв без активности — не показательно
        (400, 300, False, False, "idle"),
        (None, 300, True, True, "inconclusive"),  # нет данных о пире
    ],
)
def test_classify_relay_table(age, threshold, tcp, active, expected):
    assert classify_relay(age, threshold, tcp, active) == expected


# ---------------------------------------------------------------------------
# read_relay_signal
# ---------------------------------------------------------------------------

class FakeRunner:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        for key, res in self.mapping.items():
            if list(args)[: len(key)] == list(key):
                return res
        return ShellResult(stdout="", stderr="", returncode=1)


def _res(stdout="", code=0):
    return ShellResult(stdout=stdout, stderr="", returncode=code)


def _write_state(tmp_path, *, name="relay", protocol="amneziawg", pub=PEER_PUB, addr=f"{PEER_IP}/32"):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "clients": [
                    {
                        "name": name,
                        "protocol": protocol,
                        "port": 51825,
                        "extra": {"address": addr, "public_key": pub},
                    }
                ],
                "protocols": {},
                "ufw_lockdown": {},
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _cfg(**over) -> AlertConfig:
    base = dict(relay_peer="relay", handshake_threshold_s=300, relay_probe_port=443, tcp_timeout_s=3)
    base.update(over)
    return AlertConfig(**base)


def _dump(epoch: int, rx: int = 1000) -> str:
    return (
        f"{IFACE_LINE}\n"
        f"{PEER_PUB}\t(none)\t198.51.100.7:51820\t{PEER_IP}/32\t{epoch}\t{rx}\t7\toff\n"
    )


def test_relay_signal_state_unreadable(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{bad", encoding="utf-8")
    signal = read_relay_signal(
        cfg=_cfg(), prev_state={}, now=NOW, run=FakeRunner({}), state_path=str(path)
    )
    assert signal.classification == "inconclusive"
    assert signal.detail == "state_unreadable"


def test_relay_signal_peer_not_found(tmp_path):
    state_path = _write_state(tmp_path, name="someone-else")
    signal = read_relay_signal(
        cfg=_cfg(), prev_state={}, now=NOW, run=FakeRunner({}), state_path=state_path
    )
    assert signal.classification == "inconclusive"
    assert signal.detail == "peer_not_found"
    assert signal.peer_found is False


def test_relay_signal_awg_unavailable(tmp_path):
    state_path = _write_state(tmp_path)
    run = FakeRunner({("awg", "show"): _res("boom", code=1)})
    signal = read_relay_signal(cfg=_cfg(), prev_state={}, now=NOW, run=run, state_path=state_path)
    assert signal.classification == "inconclusive"
    assert signal.detail == "awg_unavailable"


def test_relay_signal_peer_not_in_dump(tmp_path):
    state_path = _write_state(tmp_path)
    dump = _dump(0).replace(PEER_PUB, "OTHER").replace(f"{PEER_IP}/32", "10.9.0.99/32")
    run = FakeRunner({("awg", "show"): _res(dump)})
    signal = read_relay_signal(cfg=_cfg(), prev_state={}, now=NOW, run=run, state_path=state_path)
    assert signal.detail == "peer_not_in_dump"


def test_relay_signal_fresh_handshake_is_ok(tmp_path):
    state_path = _write_state(tmp_path)
    epoch = int(NOW.timestamp()) - 60
    run = FakeRunner({("awg", "show"): _res(_dump(epoch))})
    signal = read_relay_signal(cfg=_cfg(), prev_state={}, now=NOW, run=run, state_path=state_path)
    assert signal.peer_found is True
    assert signal.handshake_age_sec == 60
    assert signal.classification == "ok"
    assert signal.endpoint_host == "198.51.100.7"
    assert signal.endpoint_port == 51820


def test_relay_signal_peer_found_by_allowed_ip(tmp_path):
    state_path = _write_state(tmp_path, pub="PUBKEY_MISMATCH")
    epoch = int(NOW.timestamp()) - 60
    run = FakeRunner({("awg", "show"): _res(_dump(epoch))})
    signal = read_relay_signal(cfg=_cfg(), prev_state={}, now=NOW, run=run, state_path=state_path)
    assert signal.peer_found is True
    assert signal.classification == "ok"


def _prev_active(seconds_ago: int = 60, last_rx: int = 1000) -> dict:
    ts = NOW - timedelta(seconds=seconds_ago)
    return {"sources": {"relay_pulse": {"last_traffic_ts": ts.isoformat(), "last_rx": last_rx}}}


def test_relay_signal_dead_handshake_with_traffic_and_tcp_ok_is_blocked(tmp_path):
    state_path = _write_state(tmp_path)
    run = FakeRunner({("awg", "show"): _res(_dump(0))})
    signal = read_relay_signal(
        cfg=_cfg(), prev_state=_prev_active(), now=NOW, run=run,
        state_path=state_path, tcp_probe=lambda host, port, timeout: True,
    )
    assert signal.traffic_active is True
    assert signal.tcp_ok is True
    assert signal.classification == "blocked"


def test_relay_signal_dead_handshake_tcp_dead_is_relay_down(tmp_path):
    state_path = _write_state(tmp_path)
    ping_fail = _res("", code=1)
    run = FakeRunner({("awg", "show"): _res(_dump(0)), ("ping",): ping_fail})
    signal = read_relay_signal(
        cfg=_cfg(), prev_state=_prev_active(), now=NOW, run=run,
        state_path=state_path, tcp_probe=lambda host, port, timeout: False,
    )
    assert signal.classification == "relay_down"
    assert signal.icmp_ok is False


def test_relay_signal_dead_handshake_without_activity_is_idle(tmp_path):
    state_path = _write_state(tmp_path)
    stale = {"sources": {"relay_pulse": {
        "last_traffic_ts": (NOW - timedelta(seconds=ACTIVITY_WINDOW_S + 60)).isoformat(),
        "last_rx": 1000,
    }}}
    run = FakeRunner({("awg", "show"): _res(_dump(0, rx=1000))})
    signal = read_relay_signal(
        cfg=_cfg(), prev_state=stale, now=NOW, run=run,
        state_path=state_path, tcp_probe=lambda host, port, timeout: True,
    )
    assert signal.traffic_active is False
    assert signal.classification == "idle"


def test_relay_signal_rx_growth_counts_as_activity(tmp_path):
    state_path = _write_state(tmp_path)
    run = FakeRunner({("awg", "show"): _res(_dump(0, rx=2000))})
    signal = read_relay_signal(
        cfg=_cfg(), prev_state=_prev_active(seconds_ago=10_000, last_rx=1500), now=NOW,
        run=run, state_path=state_path, tcp_probe=lambda host, port, timeout: True,
    )
    assert signal.traffic_active is True
    assert signal.classification == "blocked"


def test_relay_signal_none_endpoint_no_tcp_probe(tmp_path):
    state_path = _write_state(tmp_path)
    text = f"{IFACE_LINE}\n{PEER_PUB}\t(none)\t(none)\t{PEER_IP}/32\t0\t100\t7\toff\n"
    run = FakeRunner({("awg", "show"): _res(text)})
    signal = read_relay_signal(
        cfg=_cfg(), prev_state=_prev_active(), now=NOW, run=run,
        state_path=state_path, tcp_probe=lambda *a: pytest.fail("TCP-проба не должна вызываться"),
    )
    assert signal.endpoint_host == ""
    assert signal.tcp_ok is None
    assert signal.classification == "inconclusive"


# ---------------------------------------------------------------------------
# read_lockdown
# ---------------------------------------------------------------------------

def test_read_lockdown_active(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({
            "version": 1,
            "clients": [],
            "protocols": {},
            "ufw_lockdown": {
                "active": True, "since": "2026-11-17T10:00:00+00:00",
                "ttl_until": "2026-11-19T10:00:00+00:00", "ttl_hours": 48,
                "allow_from": ["203.0.113.10"], "reason": "auto:RU-SUSPECT",
            },
        }),
        encoding="utf-8",
    )
    lockdown = read_lockdown(str(path))
    assert lockdown["active"] is True
    assert lockdown["ttl_hours"] == 48
    assert lockdown["reason"] == "auto:RU-SUSPECT"


def test_read_lockdown_broken_state_is_inactive(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{bad", encoding="utf-8")
    assert read_lockdown(str(path))["active"] is False


def test_read_lockdown_missing_state_is_inactive(tmp_path):
    assert read_lockdown(str(tmp_path / "absent.json"))["active"] is False
