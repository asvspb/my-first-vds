"""AC-F12 (SPEC-20261118-vpn-failover §10.1): allow-list релея при авто-локе.

Без root/сети/ufw: только план (`build_lockdown_plan`) и предупреждение
`vds gateway probe-watch config --auto-lockdown on`.  Фикстуры — RFC 5737.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import src.gateway.probing as probing
import src.system.ufw as ufw
from src.gateway.store import ClientProfile, GatewayState, save_state

RELAY_IP = "203.0.113.10"      # RFC 5737 TEST-NET-3
OWN_IP = "203.0.113.50"


def _relay_state() -> GatewayState:
    st = GatewayState()
    st.clients = [ClientProfile(
        name="relay", protocol="amneziawg", port=51825,
        extra={"address": "10.9.0.2/32", "endpoint": f"{RELAY_IP}:51825",
               "public_key": "FIXTURE_PUBKEY_RELAY"},
    )]
    return st


def _snapshot() -> ufw.UfwSnapshot:
    return ufw.parse_ufw_status(
        "Status: active\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "443/tcp                    ALLOW       Anywhere\n"
        "443/udp                    ALLOW       Anywhere\n")


def test_ac_f12_allow_rule_precedes_blocking_443() -> None:
    plan = ufw.build_lockdown_plan(_relay_state(), _snapshot(), [RELAY_IP],
                                   with_udp=False)
    allow_index = next(
        index for index, item in enumerate(plan)
        if item.kind == "rule" and str(item.meta.get("spec", "")).startswith(
            f"from {RELAY_IP}"))
    delete_index = next(
        index for index, item in enumerate(plan)
        if item.kind == "rule" and item.meta.get("delete")
        and item.meta.get("spec") == "443/tcp")
    # fail-safe: доступ для релея ставится ДО изъятия широкого allow
    assert allow_index < delete_index
    assert plan[allow_index].action == "add"


def test_ac_f12_relay_gap_detected() -> None:
    state = _relay_state()
    assert probing.relay_ips_from_state(state) == [RELAY_IP]
    # allow покрывает только «свой» адрес → релей в дыре
    assert probing.relay_allow_gaps([OWN_IP], {OWN_IP}, state) == [RELAY_IP]
    # релей покрыт собственным allow
    assert probing.relay_allow_gaps([RELAY_IP], set(), state) == []


def test_ac_f12_config_warns_when_relay_not_covered(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(probing, "SNAPSHOT_PATH", tmp_path / "snap.json")
    monkeypatch.setattr(probing, "LOCK_FILE", str(tmp_path / "probe.lock"))
    monkeypatch.setattr(probing, "OWN_IPS_FILE", tmp_path / "allow-ips.txt")
    state_path = str(tmp_path / "state.json")
    save_state(_relay_state(), state_path)

    rc = probing.cmd_config(
        auto_lockdown="on", lockdown_allow=OWN_IP,
        snapshot_path=tmp_path / "snap.json", state_path=state_path,
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert f"релей {RELAY_IP} не покрыт" in out

    # покрытый релей предупреждения не даёт
    capsys.readouterr()
    rc = probing.cmd_config(
        auto_lockdown="on", lockdown_allow=f"{OWN_IP},{RELAY_IP}",
        snapshot_path=tmp_path / "snap.json", state_path=state_path,
    )
    assert rc == 0
    assert "не покрыт" not in capsys.readouterr().out
