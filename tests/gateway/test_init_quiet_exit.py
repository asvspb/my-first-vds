"""Тесты quiet-exit профиля gateway init (SPEC-20261124-quiet-exit §2, §10 P0-2/P1-4).

Все shell/systemd/сеть — за моками; state — в tmp (AGENTS.md §6).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import src.gateway.init as init
from src.gateway.init import (
    QUIET_EXIT_PROFILE,
    build_quiet_exit_plan,
    run_init,
    run_quiet_exit_init,
)
from src.gateway.store import GatewayState, save_state

RELAY_IP = "203.0.113.10"  # RFC 5737 TEST-NET
RELAY_PUBKEY = "FIXTUREPWAWGRELAYPUBKEYBASE64PLACEHOLDERVALUE00000="


@pytest.fixture()
def state_path(tmp_path: Path) -> str:
    return str(tmp_path / "state.json")


@pytest.fixture(autouse=True)
def _no_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(init, "unit_active", lambda name: False)
    monkeypatch.setattr(init, "_health_timer_installed", lambda: False)
    monkeypatch.setattr(init, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr(init, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(init, "port_owner", lambda port, proto="tcp": None)
    monkeypatch.setattr(init.os, "geteuid", lambda: 0)


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    class _R:
        ok = True
        returncode = 0
        output = ""

    def _run(args: list[str], check: bool = False, timeout: int | None = None) -> Any:
        calls.append(list(args))
        return _R()

    monkeypatch.setattr(init, "run_list", _run)
    return calls


# ── run_init: fail-fast ввода ────────────────────────────────────────────────


class TestQuietExitFailFast:
    def test_forbidden_protocols_exit_2(self, state_path: str) -> None:
        """AC WP-QX-1: --profile quiet-exit + reality/hysteria2/... → exit 2.
        awg НЕ forbidden: awg0 (51825 OOB-1) входит в состав профиля
        (исправление живого деплоя ES-1 2026-11-25: awg был ошибочно запрещён)."""
        for proto in ("reality", "hysteria2", "xhttp", "cdn", "obfs", "hop"):
            assert run_init(
                protocols=proto, profile=QUIET_EXIT_PROFILE, relay_ip=RELAY_IP,
                state_path=state_path,
            ) == 2
        # awg допустим (состав профиля)
        assert run_init(
            protocols="awg", profile=QUIET_EXIT_PROFILE, relay_ip=RELAY_IP,
            state_path=state_path,
        ) != 2
        # даже валидный --relay-ip не спасает
        assert run_init(
            protocols="reality,hysteria2", profile=QUIET_EXIT_PROFILE,
            relay_ip=RELAY_IP, state_path=state_path,
        ) == 2

    def test_relay_ip_required(self, state_path: str) -> None:
        """--relay-ip обязателен → exit 2."""
        assert run_init(
            protocols="", profile=QUIET_EXIT_PROFILE, relay_ip=None,
            state_path=state_path,
        ) == 2

    def test_relay_ip_must_be_ipv4(self, state_path: str) -> None:
        assert run_init(
            protocols="", profile=QUIET_EXIT_PROFILE, relay_ip="not-an-ip",
            state_path=state_path,
        ) == 2
        assert run_init(
            protocols="", profile=QUIET_EXIT_PROFILE, relay_ip="2001:db8::1",
            state_path=state_path,
        ) == 2

    def test_valid_profile_passes_validation(self, state_path: str) -> None:
        assert run_init(
            protocols="", profile=QUIET_EXIT_PROFILE, relay_ip=RELAY_IP,
            state_path=state_path,
        ) == 0  # dry-run


# ── build_quiet_exit_plan ────────────────────────────────────────────────────


class TestQuietExitPlan:
    def test_base_steps_no_direct_transports(self, state_path: str) -> None:
        """P0-2: не ставятся xray/hysteria2/zerotier/coturn/healthcheck/probe."""
        plan = build_quiet_exit_plan(RELAY_IP, None, None, None, False, state_path=state_path)
        names = [s.name for s in plan.steps]
        assert names == ["awg-quiet", "awg-oob-client", "ufw-quiet", "alert-quiet"]
        for step in plan.steps:
            joined = " ".join(step.command)
            assert "xray" not in joined and "hysteria2" not in joined
            assert "zerotier" not in joined and "coturn" not in joined
            assert "healthcheck" not in joined and "probe" not in joined

    def test_pending_without_relay_pubkey(self, state_path: str) -> None:
        """P1-4: без --relay-pubkey exit-leg и wstunnel-server — pending."""
        plan = build_quiet_exit_plan(RELAY_IP, None, None, None, False, state_path=state_path)
        assert "exit-leg" in plan.pending
        assert "wstunnel-server" in plan.pending
        assert not any(s.name == "exit-leg" for s in plan.steps)

    def test_pubkey_completes_pending(self, state_path: str) -> None:
        plan = build_quiet_exit_plan(
            RELAY_IP, RELAY_PUBKEY, None, None, False, state_path=state_path
        )
        names = [s.name for s in plan.steps]
        assert "exit-leg" in names
        assert "exit-leg" not in plan.pending
        leg_step = next(s for s in plan.steps if s.name == "exit-leg")
        assert "--relay-ip" in leg_step.command and RELAY_IP in leg_step.command
        assert "--public-key" in leg_step.command

    def test_acme_ws_window_80(self, state_path: str) -> None:
        plan = build_quiet_exit_plan(
            RELAY_IP, None, "ws.example.ru", "admin@example.ru", False,
            state_path=state_path,
        )
        acme = next(s for s in plan.steps if s.name == "acme-ws")
        assert "--window-80" in acme.command

    def test_no_direct_awg_propagates_to_ufw_args(self, state_path: str) -> None:
        plan = build_quiet_exit_plan(RELAY_IP, None, None, None, True, state_path=state_path)
        ufw_step = next(s for s in plan.steps if s.name == "ufw-quiet")
        assert "--no-direct-awg" in ufw_step.command
        assert "--yes-i-have-vnc" in ufw_step.command

    def test_dms_is_out_of_scope(self, state_path: str) -> None:
        """WP-QX-4: DMS-шага в init нет, предупреждение есть."""
        plan = build_quiet_exit_plan(RELAY_IP, None, None, None, False, state_path=state_path)
        assert not any("dms" in s.name for s in plan.steps)
        assert any("WP-QX-4" in w for w in plan.warnings)

    def test_skip_installed_awg(self, state_path: str) -> None:
        st = GatewayState()
        st.protocols["amneziawg"] = {"installed": True, "port": 51825}
        save_state(st, state_path)
        init.unit_active = lambda name: True  # monkeypatch через атрибут модуля
        plan = build_quiet_exit_plan(RELAY_IP, None, None, None, False, state_path=state_path)
        awg = next(s for s in plan.steps if s.name == "awg-quiet")
        assert awg.skip_reason


# ── run_quiet_exit_init: исполнение + state ──────────────────────────────────


class TestQuietExitRun:
    def test_apply_runs_base_steps_and_records_state(self, state_path, recorded, tmp_path) -> None:
        code = run_quiet_exit_init(
            relay_ip=RELAY_IP, relay_pubkey=None, ws_domain=None, email=None,
            ws_prefix_file=None, no_direct_awg=False, apply=True, state_path=state_path,
            lock_path=str(tmp_path / "vds.lock"),
        )
        assert code == 0
        from src.gateway.store import load_state

        qx = load_state(state_path).protocols["quiet_exit"]
        assert qx["installed"] is True
        assert qx["relay_ips"] == [RELAY_IP]
        assert qx["oob_ssh_only"] is False
        assert "exit-leg" in qx["pending"]
        joined = [" ".join(c) for c in recorded]
        assert any("amneziawg" in c and "install" in c for c in joined)
        assert any("add-client" in c and "oob-laptop" in c for c in joined)
        assert any("ufw" in c and "quiet-exit" in c for c in joined)
        assert any("alert" in c for c in joined)
        # P0-2: healthcheck/probe-таймеры не ставятся
        assert not any("healthcheck" in c or "probe" in c for c in joined)

    def test_relay_ip_change_is_additive(self, state_path, recorded, tmp_path) -> None:
        """P1-8: смена RELAY_IP — аддитивная правка relay_ips."""
        from src.gateway.store import GatewayState, save_state

        st = GatewayState()
        st.protocols["quiet_exit"] = {"installed": True, "relay_ips": ["203.0.113.20"]}
        save_state(st, state_path)
        code = run_quiet_exit_init(
            relay_ip=RELAY_IP, relay_pubkey=None, ws_domain=None, email=None,
            ws_prefix_file=None, no_direct_awg=False, apply=True, state_path=state_path,
            lock_path=str(tmp_path / "vds.lock"),
        )
        assert code == 0
        from src.gateway.store import load_state

        qx = load_state(state_path).protocols["quiet_exit"]
        assert sorted(qx["relay_ips"]) == ["203.0.113.10", "203.0.113.20"]

    def test_pending_resolved_after_pubkey_pass(self, state_path, recorded, tmp_path) -> None:
        """P1-4: повторный init с --relay-pubkey дозавершает pending."""
        run_quiet_exit_init(
            relay_ip=RELAY_IP, relay_pubkey=None, ws_domain=None, email=None,
            ws_prefix_file=None, no_direct_awg=False, apply=True, state_path=state_path,
            lock_path=str(tmp_path / "vds.lock"),
        )
        assert run_quiet_exit_init(
            relay_ip=RELAY_IP, relay_pubkey=RELAY_PUBKEY, ws_domain=None, email=None,
            ws_prefix_file=None, no_direct_awg=False, apply=True, state_path=state_path,
            lock_path=str(tmp_path / "vds.lock"),
        ) == 0
        from src.gateway.store import load_state

        qx = load_state(state_path).protocols["quiet_exit"]
        assert "exit-leg" not in qx["pending"]
        assert any("exit-leg" in " ".join(c) for c in recorded)

    def test_step_failure_is_fail_fast(self, state_path, monkeypatch, tmp_path) -> None:
        class _R:
            ok = False
            returncode = 1
            output = "boom"

        monkeypatch.setattr(init, "run_list", lambda args, timeout=None: _R())
        code = run_quiet_exit_init(
            relay_ip=RELAY_IP, relay_pubkey=None, ws_domain=None, email=None,
            ws_prefix_file=None, no_direct_awg=False, apply=True, state_path=state_path,
            lock_path=str(tmp_path / "vds.lock"),
        )
        assert code == 1
