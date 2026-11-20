"""Тесты `ALERT_RELAY_IFACE` и выбора интерфейса в `read_relay_signal`.

SPEC-20261120 §3.7 (ADR-015, P24): сторож на exit читает пульс ноги с
настраиваемого интерфейса (default `awg0`; с выделенной ногой — `awg2`),
пир ищется по публичному ключу из gateway state, а не по имени iface.
Логика классификации не меняется — проверяется только источник сигнала.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.alert import checks
from src.alert.checks import read_relay_signal
from src.alert.env import AlertConfig, load_config, render_env
from src.core.shell import ShellResult

NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
FRESH_EPOCH = int(NOW.timestamp()) - 30
STALE_EPOCH = int(NOW.timestamp()) - 6 * 3600

PEER_PUB = "FIXTURE_PUBKEY_RELAY_AWG1_000000000000="
PEER_IP = "10.9.0.5"


class RecordingRunner:
    def __init__(self, dump: str = "", ok: bool = True):
        self.dump = dump
        self.ok = ok
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        if list(args[:2]) == ["awg", "show"]:
            return ShellResult(self.dump, "", 0 if self.ok else 1)
        return ShellResult("", "", 0)


def _state_file(tmp_path, *, pub: str = PEER_PUB, addr: str = f"{PEER_IP}/32") -> str:
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "clients": [
                    {
                        "name": "relay",
                        "protocol": "amneziawg",
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


def _leg_state_file(tmp_path, *, pub: str = PEER_PUB, peer_ip: str = "10.11.0.2") -> str:
    """Exit с выделенной ногой: пира в clients[] НЕТ, есть protocols.relay_leg."""
    path = tmp_path / "state-leg.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "clients": [],
                "protocols": {
                    "relay_leg": {
                        "iface": "awg2",
                        "public_key": pub,
                        "peer_ip": peer_ip,
                        "relay_ip": "203.0.113.7",
                        "installed": True,
                    }
                },
                "ufw_lockdown": {},
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _dump(epoch: int, public_key: str = PEER_PUB, address: str = PEER_IP) -> str:
    return (
        "iface-priv\tiface-pub\t51825\toff\n"
        f"{public_key}\t(none)\t203.0.113.9:51900\t{address}/32\t{epoch}\t100\t7\toff\n"
    )


def _cfg(**over) -> AlertConfig:
    base = dict(relay_peer="relay", handshake_threshold_s=300, relay_probe_port=443,
                tcp_timeout_s=3)
    base.update(over)
    return AlertConfig(**base)


# ---------------------------------------------------------------------------
# env: ALERT_RELAY_IFACE
# ---------------------------------------------------------------------------

def test_relay_iface_default_is_awg0(tmp_path):
    assert load_config(str(tmp_path / "absent.env")).relay_iface == "awg0"


def test_relay_iface_parsed_from_env(tmp_path):
    env = tmp_path / "alert.env"
    env.write_text("ALERT_RELAY_IFACE=awg2\n", encoding="utf-8")
    assert load_config(str(env)).relay_iface == "awg2"


def test_relay_iface_empty_falls_back_to_awg0(tmp_path):
    env = tmp_path / "alert.env"
    env.write_text("ALERT_RELAY_IFACE=\n", encoding="utf-8")
    assert load_config(str(env)).relay_iface == "awg0"


def test_render_env_roundtrip_keeps_relay_iface(tmp_path):
    cfg = _cfg(relay_iface="awg2")
    env = tmp_path / "alert.env"
    env.write_text(render_env(cfg, with_secrets=True), encoding="utf-8")
    assert "ALERT_RELAY_IFACE=awg2" in render_env(cfg, with_secrets=False)
    assert load_config(str(env)).relay_iface == "awg2"


# ---------------------------------------------------------------------------
# read_relay_signal: выбор интерфейса, поиск пира по ключу
# ---------------------------------------------------------------------------

def test_default_reads_awg0(tmp_path):
    run = RecordingRunner(_dump(FRESH_EPOCH))
    signal = read_relay_signal(
        cfg=_cfg(), prev_state={}, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert run.calls[0] == ["awg", "show", "awg0", "dump"]
    assert signal.classification == "ok"


def test_configured_iface_is_used(tmp_path):
    run = RecordingRunner(_dump(FRESH_EPOCH))
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert run.calls[0] == ["awg", "show", "awg2", "dump"]
    assert signal.peer_found and signal.classification == "ok"


def test_peer_found_by_public_key_not_iface(tmp_path):
    # Адрес в state — клиентский (awg0), в dump — адрес ноги (awg2):
    # пир находится по ключу, а не по адресу/имени интерфейса.
    run = RecordingRunner(_dump(FRESH_EPOCH, address="10.11.0.2"))
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert signal.peer_found
    assert signal.classification == "ok"


def test_peer_found_from_relay_leg_without_clients(tmp_path):
    """P0-5: state.clients пуст, личность пира — из protocols.relay_leg."""
    run = RecordingRunner(
        _dump(FRESH_EPOCH, public_key=PEER_PUB, address="10.11.0.2")
    )
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=_leg_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert run.calls[0] == ["awg", "show", "awg2", "dump"]
    assert signal.peer_found is True
    assert signal.classification == "ok"


def test_relay_leg_fallback_to_clients_when_key_missing(tmp_path):
    # relay_leg есть, но без public_key → фолбэк на clients[].
    path = tmp_path / "state-leg-empty.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "clients": [
                    {
                        "name": "relay",
                        "protocol": "amneziawg",
                        "port": 51825,
                        "extra": {"address": "10.9.0.5/32", "public_key": PEER_PUB},
                    }
                ],
                "protocols": {"relay_leg": {"iface": "awg2", "installed": True}},
                "ufw_lockdown": {},
            }
        ),
        encoding="utf-8",
    )
    run = RecordingRunner(_dump(FRESH_EPOCH, address="10.9.0.5"))
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=str(path), tcp_probe=lambda *a: None,
    )
    assert signal.peer_found is True


def test_missing_peer_is_inconclusive(tmp_path):
    run = RecordingRunner(_dump(FRESH_EPOCH, public_key="OTHER_PEER_KEY", address="10.9.0.9"))
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert signal.classification == "inconclusive"
    assert signal.detail == "peer_not_in_dump"


def test_awg_unavailable_on_missing_iface(tmp_path):
    run = RecordingRunner("", ok=False)
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state={}, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: None,
    )
    assert signal.classification == "inconclusive"
    assert signal.detail == "awg_unavailable"


def test_classification_logic_unchanged_on_new_iface(tmp_path):
    # Stale handshake + активный трафик + TCP до exit жив → blocked (как на awg0).
    prev = {"sources": {"relay_pulse": {"last_rx": 10, "last_traffic_ts": NOW.isoformat()}}}
    run = RecordingRunner(_dump(STALE_EPOCH))
    signal = read_relay_signal(
        cfg=_cfg(relay_iface="awg2"), prev_state=prev, now=NOW, run=run,
        state_path=_state_file(tmp_path), tcp_probe=lambda *a: True,
    )
    assert signal.classification == "blocked"
    assert signal.traffic_active


def test_parse_awg_dump_still_interface_agnostic():
    # Один и тот же dump — одинаковый разбор вне зависимости от iface-имени.
    peers = checks.parse_awg_dump(_dump(FRESH_EPOCH))
    assert set(peers) == {PEER_PUB}
