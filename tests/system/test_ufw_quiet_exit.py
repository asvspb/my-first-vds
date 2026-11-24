"""Unit-тесты quiet-exit профиля UFW (SPEC-20261124-quiet-exit §2, §10 P0-1/P1-3/P1-6/P1-7).

Без root/сети/реального ufw: FakeUfw из test_ufw.py + tmp-пути + monkeypatch.
IP-фикстуры — только RFC 5737 TEST-NET (203.0.113.0/24).
"""
from __future__ import annotations

from pathlib import Path

import pytest

import src.system.ufw as ufw
from src.gateway.store import GatewayState
from tests.system.test_ufw import FakeUfw, _wire

RELAY_IP = "203.0.113.10"  # RFC 5737 TEST-NET


def _quiet_state(relay_ips: list[str] | None = None, **extra) -> GatewayState:
    st = GatewayState()
    meta = {
        "installed": True,
        "relay_ips": relay_ips if relay_ips is not None else [RELAY_IP],
        "oob_ssh_only": False,
        "pending": [],
    }
    meta.update(extra)
    st.protocols = {"quiet_exit": meta}
    return st


def _snap(rules: list[str] | None = None, active: bool = True):
    fake = FakeUfw(rules=rules, active=active)
    return ufw.parse_ufw_status(fake._status_text())


# ── profile_service_specs ────────────────────────────────────────────────────


def test_specs_ignore_protocol_rules_except_amneziawg() -> None:
    """P0-1/P39: quiet-exit игнорирует _PROTOCOL_RULES (80/443/8443/2053 не открываются)."""
    st = _quiet_state()
    st.protocols.update({
        "xray": {"installed": True, "port": 443},
        "hysteria2": {"installed": True, "port": 443},
        "xhttp": {"installed": True, "port": 8443},
        "xray-cdn": {"installed": True, "port": 2053},
        "acme": {"installed": True, "port": 80},  # TECHDEBT P39
    })
    specs, cascade = ufw.profile_service_specs(st, "quiet-exit")
    assert "80/tcp" not in specs
    assert "443/tcp" not in specs and "443/udp" not in specs
    assert "8443/tcp" not in specs and "2053/tcp" not in specs
    assert cascade == []
    assert "51825/udp" in specs


def test_specs_relay_ip_allowlist() -> None:
    st = _quiet_state()
    specs, _ = ufw.profile_service_specs(st, "quiet-exit")
    assert f"from {RELAY_IP} to any port 51900 proto udp" in specs
    assert f"from {RELAY_IP} to any port 9443 proto tcp" in specs


def test_specs_no_relay_ips_no_allowlist() -> None:
    st = _quiet_state(relay_ips=[])
    specs, _ = ufw.profile_service_specs(st, "quiet-exit")
    assert specs == ["51825/udp"]


# ── build_plan ───────────────────────────────────────────────────────────────


def test_build_plan_quiet_exit_no_public_tcp() -> None:
    """AC WP-QX-1: build_plan('quiet-exit') не открывает 80/443/8443/2053."""
    st = _quiet_state()
    st.protocols["acme"] = {"installed": True, "port": 80}
    plan = ufw.build_plan("quiet-exit", st, _snap(), ufw.HardeningOpts())
    for item in plan:
        spec = str(item.meta.get("spec") or "")
        assert not any(p in spec for p in ("80/tcp", "443/", "8443/tcp", "2053/tcp"))
        assert item.action != "add" or "delete" not in item.meta


def test_build_plan_rules_present() -> None:
    st = _quiet_state()
    plan = ufw.build_plan("quiet-exit", st, _snap(), ufw.HardeningOpts())
    specs = [str(p.meta.get("spec")) for p in plan if p.kind == "rule" and not p.meta.get("delete")]
    assert "in on awg0 proto tcp from any to 10.9.0.1 port 22" in specs  # OOB-1 (живой синтаксис ufw, ES-1 2026-11-25)
    assert f"from {RELAY_IP} to any port 51900 proto udp" in specs
    assert f"from {RELAY_IP} to any port 9443 proto tcp" in specs
    assert "51825/udp" in specs


def test_build_plan_ssh_limit_phase1_with_warning() -> None:
    """Фаза 1 (IQ-3): публичный SSH limit остаётся + warning."""
    st = _quiet_state()
    plan = ufw.build_plan("quiet-exit", st, _snap(), ufw.HardeningOpts())
    assert any(
        p.kind == "rule" and p.meta.get("ssh") and p.meta.get("spec") == "22/tcp"
        for p in plan
    )
    assert any("Фаза 1" in p.detail for p in plan if p.action == "warn")


def test_no_direct_awg_requires_vnc_flag() -> None:
    """P1-7: --no-direct-awg без --yes-i-have-vnc → abort (UfwError)."""
    st = _quiet_state()
    with pytest.raises(ufw.UfwError, match="yes-i-have-vnc"):
        ufw.build_plan(
            "quiet-exit", st, _snap(),
            ufw.HardeningOpts(no_direct_awg=True, yes_i_have_vnc=False),
        )
    plan = ufw.build_plan(
        "quiet-exit", st, _snap(),
        ufw.HardeningOpts(no_direct_awg=True, yes_i_have_vnc=True),
    )
    assert not any(
        p.kind == "rule" and p.meta.get("spec") == "51825/udp" and not p.meta.get("delete")
        for p in plan
    )


def test_no_direct_awg_from_state_honored() -> None:
    st = _quiet_state(no_direct_awg=True)
    specs, _ = ufw.profile_service_specs(st, "quiet-exit")
    assert "51825/udp" not in specs


def test_unknown_profile_rejected() -> None:
    with pytest.raises(ufw.UfwError, match="quiet-exit"):
        ufw.build_plan("no-such", _quiet_state(), _snap(), ufw.HardeningOpts())


def test_forbidden_listener_is_violation() -> None:
    st = _quiet_state()
    ss_lines = [
        'LISTEN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=3))',
        "LISTEN 0 0 0.0.0.0:51900 0.0.0.0:* users:((\"awg-quick\",pid=2,fd=3))",
        "LISTEN 0 0 127.0.0.1:2053 0.0.0.0:*",  # loopback — не нарушение
    ]
    plan = ufw.build_plan("quiet-exit", st, _snap(), ufw.HardeningOpts(), ss_lines)
    viols = [p for p in plan if "нарушение quiet-exit" in p.detail]
    assert len(viols) == 1 and "443" in viols[0].detail


def test_quiet_exit_listeners_covered_no_spurious_warn() -> None:
    st = _quiet_state()
    ss_lines = [
        'UNCONN 0 0 0.0.0.0:51825 0.0.0.0:* users:(("awg-quick",pid=1,fd=3))',
        'UNCONN 0 0 0.0.0.0:51900 0.0.0.0:* users:(("awg-quick",pid=1,fd=4))',
        'LISTEN 0 0 0.0.0.0:9443 0.0.0.0:* users:(("wstunnel",pid=2,fd=3))',
        "LISTEN 0 0 0.0.0.0:22 0.0.0.0:*",
    ]
    plan = ufw.build_plan("quiet-exit", st, _snap(), ufw.HardeningOpts(), ss_lines)
    warns = [p for p in plan if p.action == "warn" and "слушается" in p.detail]
    assert not warns


# ── run_harden: нарушения блокируют apply ────────────────────────────────────


def test_run_harden_forbidden_listener_exit_1(monkeypatch, tmp_path) -> None:
    fake = FakeUfw(active=True)
    _wire(fake, monkeypatch)
    monkeypatch.setattr(ufw.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "src.gateway.store.STATE_PATH", tmp_path / "state.json", raising=False
    )
    from src.gateway import store as gw_store

    monkeypatch.setattr(ufw, "STATE_PATH", str(tmp_path / "state.json"))
    st = _quiet_state()
    gw_store.save_state(st, str(tmp_path / "state.json"))
    fake.ss_lines = ['LISTEN 0 0 0.0.0.0:8443 0.0.0.0:* users:(("xray",pid=1,fd=3))']
    code = ufw.run_harden(
        "quiet-exit", apply=False, state_path=str(tmp_path / "state.json"),
        include_ss=True, force=False,
    )
    assert code == 1
    # ничего не применено
    assert not any("8443" in c for call in fake.calls for c in call)


# ── Фаза 2: close-public-ssh ─────────────────────────────────────────────────


def _wire_close(monkeypatch, tmp_path, handshake: str, awg0_up: bool, ssh_ok: bool = True):
    # OOB-1 правило в статусе — Preflight 3 (QX-Q2) требует его для Фазы 2
    fake = FakeUfw(
        rules=["limit 22/tcp",
               "allow in on awg0 proto tcp from any to 10.9.0.1 port 22"], active=True,
        ss_lines=[] if not ssh_ok else ["LISTEN 0 0 0.0.0.0:22 0.0.0.0:*"],
    )
    _wire(fake, monkeypatch)
    monkeypatch.setattr(ufw.os, "geteuid", lambda: 0)
    conf = tmp_path / "awg0.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = FIXTURE_PW_AWG_PRIVKEY_MATERIAL_NOT_REAL\n"
        "ListenPort = 51825\n\n[Peer]\n# oob-laptop\n"
        "PublicKey = FIXTUREPWAWGPEERPUBKEYBASE64PLACEHOLDERVALUE0=\n"
        "AllowedIPs = 10.9.0.2/32\n",
        encoding="utf-8",
    )

    def run(args, timeout=10):
        from src.core.shell import ShellResult

        fake.calls.append(list(args))
        if args[:2] == ["awg", "show"]:
            if not awg0_up:
                return ShellResult(stdout="", stderr="Name or service not known", returncode=1)
            return ShellResult(
                stdout=(
                    "interface: awg0\n  public key: SERVER\n"
                    "peer: FIXTUREPWAWGPEERPUBKEYBASE64PLACEHOLDERVALUE0=\n"
                    f"  latest handshake: {handshake} ago\n"
                ),
                stderr="", returncode=0,
            )
        if args[0] == "ss" and ssh_ok is False:
            return ShellResult(stdout="", stderr="", returncode=0)
        return fake.run(args, timeout)

    monkeypatch.setattr(ufw, "run_list", run)
    monkeypatch.setattr(ufw, "AWG0_CONF_PATH", conf)
    return fake, conf


def test_close_public_ssh_preflight_requires_fresh_handshake(monkeypatch, tmp_path) -> None:
    """P1-3: без свежего handshake (≤3 мин) — exit 1, изменений нет."""
    fake, _ = _wire_close(monkeypatch, tmp_path, "1 minute, 12 seconds", awg0_up=True)
    code = ufw.run_close_public_ssh(
        apply=False, state_path=str(tmp_path / "state.json"),
        lock_path=str(tmp_path / "vds.lock"),
    )
    assert code == 0  # dry-run предпроверки пройдены, план показан, apply=False

    fake2, _ = _wire_close(monkeypatch, tmp_path, "2 hours, 5 minutes", awg0_up=True)
    code = ufw.run_close_public_ssh(
        apply=True, state_path=str(tmp_path / "state.json"),
        lock_path=str(tmp_path / "vds.lock"),
    )
    assert code == 1
    assert not any(c[:3] == ["ufw", "delete", "limit"] for c in fake2.calls)


def test_close_public_ssh_preflight_requires_awg0_up(monkeypatch, tmp_path) -> None:
    fake, _ = _wire_close(monkeypatch, tmp_path, "5 seconds", awg0_up=False)
    code = ufw.run_close_public_ssh(
        apply=True, state_path=str(tmp_path / "state.json"),
        lock_path=str(tmp_path / "vds.lock"),
    )
    assert code == 1
    assert not any(c[:3] == ["ufw", "delete", "limit"] for c in fake.calls)


def test_close_public_ssh_applies_and_records_state(monkeypatch, tmp_path) -> None:
    fake, _ = _wire_close(monkeypatch, tmp_path, "40 seconds", awg0_up=True)
    from src.gateway.store import GatewayState, save_state

    st = GatewayState()
    st.protocols["quiet_exit"] = {"installed": True, "relay_ips": [RELAY_IP]}
    save_state(st, str(tmp_path / "state.json"))
    code = ufw.run_close_public_ssh(
        apply=True, state_path=str(tmp_path / "state.json"),
        lock_path=str(tmp_path / "vds.lock"),
    )
    assert code == 0
    assert any(c[:3] == ["ufw", "delete", "limit"] for c in fake.calls)
    assert "limit 22/tcp" not in fake.rules  # публичный limit удалён
    assert any("in on awg0" in r for r in fake.rules)  # OOB-1 остаётся
    from src.gateway.store import load_state

    qx = load_state(str(tmp_path / "state.json")).protocols["quiet_exit"]
    assert qx["oob_ssh_only"] is True


def test_handshake_seconds_parsing() -> None:
    assert ufw._handshake_seconds("1 minute, 12 seconds", 0) == 72
    assert ufw._handshake_seconds("40 seconds", 0) == 40
    assert ufw._handshake_seconds("2 hours, 5 minutes", 0) == 7500
    assert ufw._handshake_seconds("1 day, 3 hours", 0) == 97200


def test_close_public_ssh_aborts_without_oob_ufw_rule(monkeypatch, tmp_path) -> None:
    """QX-Q2 Preflight 3: свежий awg0 handshake ЕСТЬ, но UFW-правила OOB-1
    нет → exit 1, ни одного ufw delete (реальный lockout)."""
    fake, _ = _wire_close(monkeypatch, tmp_path, "40 seconds", awg0_up=True)
    # убираем OOB-правило из статус-текста (Фаза 1 не применялась)
    fake.rules = [r for r in fake.rules if "in on awg0" not in r]
    code = ufw.run_close_public_ssh(
        apply=True, state_path=str(tmp_path / "state.json"),
        lock_path=str(tmp_path / "vds.lock"),
    )
    assert code == 1
    assert not any(c[:3] == ["ufw", "delete", "limit"] for c in fake.calls)
