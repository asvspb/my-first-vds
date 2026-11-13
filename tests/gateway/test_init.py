"""Тесты src/gateway/init.py (SPEC-20261114-fresh-install-v3, WP-1).

Все shell/systemd/сеть — за моками; state — в tmp (AGENTS.md §6).
"""

import json
from pathlib import Path
from typing import Any

import pytest

import src.gateway.init as init
from src.gateway.init import (
    build_plan,
    parse_protocols,
    preflight,
    run_init,
)
from src.gateway.store import GatewayState, save_state


# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def state_path(tmp_path: Path) -> str:
    return str(tmp_path / "state.json")


def _save_state(state: GatewayState, state_path: str) -> None:
    save_state(state, state_path)


def _installed_state(state_path: str, protocols: list[str]) -> GatewayState:
    state = GatewayState()
    if "reality" in protocols:
        state.protocols["xray"] = {"installed": True, "port": 443}
    if "hysteria2" in protocols:
        state.protocols["hysteria2"] = {"installed": True, "port": 443}
    if "obfs" in protocols:
        state.protocols["hysteria2-obfs"] = {"installed": True, "port": 51826}
    if "xhttp" in protocols:
        state.protocols["xhttp"] = {"installed": True, "port": 8443}
    if "cdn" in protocols:
        state.protocols["xray-cdn"] = {"installed": True, "port": 2053}
    if "awg" in protocols:
        state.protocols["amneziawg"] = {"installed": True, "port": 51825}
    _save_state(state, state_path)
    return state


@pytest.fixture()
def _root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(init.os, "geteuid", lambda: 0)


@pytest.fixture()
def _net_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(init, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr(init, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(init, "port_owner", lambda port, proto="tcp": None)


@pytest.fixture()
def _dns_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.acme.install as acme_install

    monkeypatch.setattr(acme_install, "dns_resolves_to", lambda domain, ip: True)


@pytest.fixture()
def _units_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(init, "unit_active", lambda name: True)


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """run_list-лог: каждый вызов возвращает успешный ShellResult-подобный объект."""
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


# ── parse_protocols ───────────────────────────────────────────────────────────


class TestParseProtocols:
    def test_default(self) -> None:
        assert parse_protocols("reality,hysteria2") == ["reality", "hysteria2"]

    def test_trim_and_dedupe(self) -> None:
        assert parse_protocols(" reality, hysteria2,obfs, reality ") == [
            "reality",
            "hysteria2",
            "obfs",
        ]

    def test_unknown_rejected(self) -> None:
        with pytest.raises(ValueError, match="Неизвестные протоколы"):
            parse_protocols("reality,wireguard")

    def test_empty_rejected(self) -> None:
        with pytest.raises(ValueError, match="пуст"):
            parse_protocols(" , ")

    def test_obfs_requires_hysteria2(self) -> None:
        with pytest.raises(ValueError, match="obfs требует"):
            parse_protocols("obfs")

    def test_hop_requires_hysteria2(self) -> None:
        with pytest.raises(ValueError, match="hop требует"):
            parse_protocols("hop")

    def test_xhttp_requires_reality(self) -> None:
        with pytest.raises(ValueError, match="xhttp требует"):
            parse_protocols("xhttp")

    def test_cdn_requires_reality(self) -> None:
        with pytest.raises(ValueError, match="cdn требует"):
            parse_protocols("cdn")


# ── build_plan ────────────────────────────────────────────────────────────────


class TestBuildPlan:
    def test_default_order_and_commands(self, state_path: str) -> None:
        plan = build_plan(["reality", "hysteria2"], None, None, state_path=state_path)
        assert [s.name for s in plan.steps] == ["reality", "hysteria2", "healthcheck"]
        assert plan.steps[0].command[-3:] == ["xray", "install", "--sni"] or (
            "xray" in plan.steps[0].command
        )
        # argv (не shell): первый аргумент — интерпретатор python
        assert plan.steps[0].command[0].endswith("python") or plan.steps[0].command[
            0
        ].endswith("python3")
        assert "-m" in plan.steps[0].command
        assert plan.steps[1].command[-2:] == ["hysteria2", "install"]

    def test_full_set_order(self, state_path: str) -> None:
        plan = build_plan(
            ["reality", "hysteria2", "xhttp", "cdn", "obfs", "hop", "awg"],
            "vpn.example.ru",
            "admin@example.ru",
            state_path=state_path,
        )
        names = [s.name for s in plan.steps]
        assert names.index("reality") < names.index("hysteria2")
        assert names.index("acme") < names.index("hy2-cert")
        assert names.index("hy2-cert") < names.index("xray-domain")
        assert names.index("xray-domain") < names.index("xhttp")
        assert names.index("xhttp") < names.index("cdn")
        assert names.index("cdn") < names.index("obfs")
        assert names.index("obfs") < names.index("hop")
        assert names.index("hop") < names.index("awg")
        assert names[-1] == "healthcheck"

    def test_xhttp_without_domain_is_warning(self, state_path: str) -> None:
        plan = build_plan(["reality", "xhttp"], None, None, state_path=state_path)
        assert not any(s.name == "xhttp" for s in plan.steps)
        assert any("xhttp" in w for w in plan.warnings)

    def test_domain_requires_email(self, state_path: str) -> None:
        plan = build_plan(["reality"], "vpn.example.ru", None, state_path=state_path)
        assert any("email" in e for e in plan.errors)

    def test_cdn_requires_domain(self, state_path: str) -> None:
        plan = build_plan(["reality", "cdn"], None, None, state_path=state_path)
        assert any("cdn" in e for e in plan.errors)

    def test_bad_hop_range_is_error(self, state_path: str) -> None:
        plan = build_plan(
            ["reality", "hysteria2", "hop"], None, None,
            hop_range="20500-20000", state_path=state_path,
        )
        assert any("20000" in e or "Диапазон" in e for e in plan.errors)

    def test_skip_installed_by_state(
        self, _units_up: None, state_path: str
    ) -> None:
        _installed_state(state_path, ["reality", "hysteria2"])
        plan = build_plan(
            ["reality", "hysteria2"], None, None, state_path=state_path
        )
        # healthcheck-таймер не имеет state-ключа — исполняется всегда;
        # транспортные шаги скипаются целиком.
        assert all(s.skip_reason for s in plan.steps if s.name != "healthcheck")
        assert not next(s for s in plan.steps if s.name == "healthcheck").skip_reason

    def test_hop_skip_by_state(self, state_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(init, "unit_active", lambda name: True)
        _installed_state(state_path, ["reality", "hysteria2"])
        state = GatewayState.model_validate(json.loads(Path(state_path).read_text()))
        state.protocols["hysteria2"]["hop_ports"] = "20000-20500"
        _save_state(state, state_path)
        plan = build_plan(
            ["reality", "hysteria2", "hop"], None, None, state_path=state_path
        )
        hop = next(s for s in plan.steps if s.name == "hop")
        assert hop.skip_reason

    def test_state_unit_divergence_reinstalls(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # state говорит installed, юнит мёртв → шаг не скипается, есть warning.
        monkeypatch.setattr(init, "unit_active", lambda name: False)
        _installed_state(state_path, ["reality"])
        plan = build_plan(["reality"], None, None, state_path=state_path)
        assert not plan.steps[0].skip_reason
        assert any("не активен" in w for w in plan.warnings)

    def test_broken_state_is_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "state.json"
        bad.write_text("{not json", encoding="utf-8")
        plan = build_plan(["reality"], None, None, state_path=str(bad))
        assert plan.errors


# ── preflight ─────────────────────────────────────────────────────────────────


class TestPreflight:
    def test_root_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(init.os, "geteuid", lambda: 1000)
        plan = build_plan(["reality"], None, None)
        preflight(plan, None)
        assert any("root" in e for e in plan.errors)

    def test_no_public_ip_is_error(
        self, _root: None, monkeypatch: pytest.MonkeyPatch, state_path: str
    ) -> None:
        monkeypatch.setattr(init, "public_ip", lambda: None)
        _installed_state(state_path, ["reality"])
        plan = build_plan(["reality"], None, None, state_path=state_path)
        preflight(plan, None)
        assert any("публичный IP" in e for e in plan.errors)

    def test_foreign_port_blocks_step(
        self, _root: None, _dns_ok: None, _units_up: None,
        monkeypatch: pytest.MonkeyPatch, state_path: str,
    ) -> None:
        _installed_state(state_path, [])  # ничего не установлено
        monkeypatch.setattr(init, "public_ip", lambda: "203.0.113.10")
        monkeypatch.setattr(
            init, "port_free", lambda port, proto="tcp": not (port == 443)
        )
        monkeypatch.setattr(init, "port_owner", lambda port, proto="tcp": "nginx")
        plan = build_plan(
            ["reality", "hysteria2", "awg"], None, None, state_path=state_path
        )
        preflight(plan, None)
        assert any("443" in e and "nginx" in e for e in plan.errors)

    def test_own_port_is_warning_not_error(
        self, _root: None, _dns_ok: None, _units_up: None,
        monkeypatch: pytest.MonkeyPatch, state_path: str,
    ) -> None:
        monkeypatch.setattr(init, "public_ip", lambda: "203.0.113.10")
        monkeypatch.setattr(init, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(init, "port_owner", lambda port, proto="tcp": "vds-xray")
        plan = build_plan(["reality"], None, None, state_path=state_path)
        preflight(plan, None)
        assert not plan.errors
        assert any("нашей службой" in w for w in plan.warnings)

    def test_dns_mismatch_skips_domain_steps(
        self, _root: None, _net_ok: None, _units_up: None,
        monkeypatch: pytest.MonkeyPatch, state_path: str,
    ) -> None:
        import src.acme.install as acme_install

        monkeypatch.setattr(acme_install, "dns_resolves_to", lambda domain, ip: False)
        plan = build_plan(
            ["reality", "hysteria2", "cdn"],
            "vpn.example.ru", "admin@example.ru", state_path=state_path,
        )
        preflight(plan, "vpn.example.ru")
        assert not plan.errors
        skipped = {s.name for s in plan.steps if s.skip_reason}
        assert {"acme", "hy2-cert", "cdn"} <= skipped
        assert "xray" not in skipped

    def test_require_domain_strict_mode(
        self, _root: None, _net_ok: None, _units_up: None,
        monkeypatch: pytest.MonkeyPatch, state_path: str,
        recorded: list[list[str]],
    ) -> None:
        import src.acme.install as acme_install

        monkeypatch.setattr(acme_install, "dns_resolves_to", lambda domain, ip: False)
        rc = run_init(
            protocols="reality,hysteria2",
            domain="vpn.example.ru",
            email="admin@example.ru",
            apply=True,
            require_domain=True,
            state_path=state_path,
        )
        assert rc == 1
        assert recorded == []  # мутаций нет


# ── run_init: dry-run / fail-fast / идемпотентность ──────────────────────────


class TestRunInit:
    def test_bad_protocols_exit_1(self, recorded: list[list[str]]) -> None:
        assert run_init(protocols="foo") == 1
        assert recorded == []

    def test_dry_run_does_not_mutate(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, recorded: list[list[str]],
    ) -> None:
        assert run_init(
            protocols="reality,hysteria2,obfs,awg",
            apply=False, demo_clients=True, state_path=state_path,
        ) == 0
        assert recorded == []  # dry-run не вызывает мутаций (в т.ч. demo-clients)

    def test_apply_runs_all_steps(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, recorded: list[list[str]],
    ) -> None:
        rc = run_init(
            protocols="reality,hysteria2,awg",
            apply=True, state_path=state_path,
        )
        assert rc == 0
        kinds = [c[-2] if c[-2] in ("install",) else c[3] for c in recorded]
        # xray install, hysteria2 install, awg install, healthcheck --install-timer
        assert any("xray" in " ".join(c) and "install" in " ".join(c) for c in recorded)
        assert any("amneziawg" in " ".join(c) for c in recorded)
        assert any("healthcheck" in " ".join(c) for c in recorded)
        del kinds

    def test_apply_idempotent_skips_all(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, recorded: list[list[str]],
    ) -> None:
        _installed_state(state_path, ["reality", "hysteria2", "awg"])
        rc = run_init(
            protocols="reality,hysteria2,awg",
            apply=True, state_path=state_path,
        )
        assert rc == 0
        # healthcheck-таймер не имеет state-скипа — он единственный исполняемый
        assert len(recorded) == 1
        assert "healthcheck" in " ".join(recorded[0])

    def test_fail_fast_stops_chain(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[list[str]] = []

        class _Fail:
            ok = False
            returncode = 7
            output = "some error line"

        def _run(args: list[str], check: bool = False, timeout: int | None = None) -> Any:
            calls.append(list(args))
            if "xray" in args:
                return _Fail()
            return type("R", (), {"ok": True, "returncode": 0, "output": ""})()

        monkeypatch.setattr(init, "run_list", _run)
        rc = run_init(
            protocols="reality,hysteria2,awg",
            apply=True, state_path=state_path,
        )
        assert rc == 1
        # fail-fast: после упавшего xray hysteria2/awg не запускались
        assert len(calls) == 1
        assert "xray" in calls[0]

    def test_demo_clients_only_after_apply(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, monkeypatch: pytest.MonkeyPatch, recorded: list[list[str]],
    ) -> None:
        demo_calls: list[str] = []
        import src.xray.clients as xray_clients

        monkeypatch.setattr(
            xray_clients, "add_client", lambda name, **kw: demo_calls.append(name) or {}
        )
        # dry-run: клиенты не создаются
        run_init(
            protocols="reality", apply=False, demo_clients=True, state_path=state_path
        )
        assert demo_calls == []
        run_init(
            protocols="reality", apply=True, demo_clients=True, state_path=state_path
        )
        assert demo_calls == ["phone"]

    def test_no_secrets_in_output(
        self, _root: None, _net_ok: None, _dns_ok: None, _units_up: None,
        state_path: str, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        secret = "FIXTURE_PW_SuperSecretValue123"
        state = GatewayState()
        state.protocols["hysteria2"] = {
            "installed": True,
            "port": 443,
            "auth_password": secret,
        }
        _save_state(state, state_path)

        class _R:
            ok = True
            returncode = 0
            output = ""

        monkeypatch.setattr(init, "run_list", lambda args, **kw: _R())
        run_init(protocols="reality,hysteria2", apply=True, state_path=state_path)
        out = capsys.readouterr().out + capsys.readouterr().err
        assert secret not in out
        assert "auth_password" not in out
