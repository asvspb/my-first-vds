"""Тесты src/hysteria2/hop.py (SPEC-20261112 WP-1, ADR-008): валидация
диапазона, идемпотентность iptables-команд, dry-run/apply, план remove —
на моках run_list по паттерну tests/hysteria2/test_install.py::env.
"""

from pathlib import Path

import pytest

import src.hysteria2.hop as hop
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, load_state, save_state

IP = "203.0.113.10"
AUTH_PW = "FIXTURE_PW_HopMain"


class _Recorder:
    """run_list-мок: -C-проверки по настроенному состоянию «файрвола»."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.rule_installed = False
        self.jump_installed = False

    def __call__(self, args: list[str], timeout: int = 10) -> ShellResult:
        self.calls.append(list(args))
        argv = args
        if argv[:5] == ["iptables", "-t", "nat", "-C", hop.HYSTERIA2_HOP_CHAIN]:
            return ShellResult(
                stdout="", stderr="",
                returncode=0 if self.rule_installed else 1,
            )
        if argv == hop._jump_check_args():
            return ShellResult(
                stdout="", stderr="",
                returncode=0 if self.jump_installed else 1,
            )
        if argv[:5] == ["iptables", "-t", "nat", "-A", hop.HYSTERIA2_HOP_CHAIN]:
            self.rule_installed = True
            return ShellResult(stdout="", stderr="", returncode=0)
        if argv == hop._jump_add_args():
            self.jump_installed = True
            return ShellResult(stdout="", stderr="", returncode=0)
        if argv[:5] == ["iptables", "-t", "nat", "-N", hop.HYSTERIA2_HOP_CHAIN]:
            return ShellResult(stdout="", stderr="", returncode=0)
        if argv[:2] == ["iptables", "-t", "nat"] and "-D" in argv:
            if "-D" in argv and "PREROUTING" in argv:
                self.jump_installed = False
            return ShellResult(stdout="", stderr="", returncode=0)
        if argv[:2] == ["iptables", "-t", "nat"] and ("-F" in argv or "-X" in argv):
            self.rule_installed = False
            return ShellResult(stdout="", stderr="", returncode=0)
        if argv[:1] == ["ss"]:
            return ShellResult(stdout="", stderr="", returncode=0)
        return ShellResult(stdout="", stderr="", returncode=0)

    def argvs(self) -> list[str]:
        return [" ".join(c) for c in self.calls]


class _UnitRecorder:
    def __init__(self, owner: dict) -> None:
        self.owner = owner

    def install_unit(self, tpl: str, name: str, ctx: dict = {}, root: str = "/") -> bool:
        self.owner.setdefault("installed", []).append((tpl, name, ctx))
        return True

    def remove_unit(self, name: str, root: str = "/") -> bool:
        self.owner.setdefault("removed", []).append(name)
        return True


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True,
        "port": 443,
        "cert_cn": IP,
        "auth_password": AUTH_PW,
    }
    save_state(state, state_path)

    recorder = _Recorder()
    units = _UnitRecorder({})
    monkeypatch.setattr(hop, "run_list", recorder)
    monkeypatch.setattr(hop, "install_unit", units.install_unit)
    monkeypatch.setattr(hop, "remove_unit", units.remove_unit)
    monkeypatch.setattr(hop, "LOCK_FILE", str(tmp_path / "hop.lock"))
    monkeypatch.setattr(hop, "HYSTERIA2_HOP_SCRIPT", tmp_path / "hop-apply.sh")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return {
        "state_path": state_path,
        "recorder": recorder,
        "units": units,
    }


class TestParsePortRange:
    def test_valid(self) -> None:
        assert hop.parse_port_range("20000-20500") == (20000, 20500)

    def test_inverted(self) -> None:
        with pytest.raises(ValueError):
            hop.parse_port_range("20500-20000")

    def test_too_wide(self) -> None:
        with pytest.raises(ValueError):
            hop.parse_port_range("1000-5000")  # 4001 порт > 1000

    def test_garbage(self) -> None:
        for raw in ("abc", "20000", "20000-abc", "20000-20500-1", "", "1-2-3"):
            with pytest.raises(ValueError):
                hop.parse_port_range(raw)

    def test_below_1024(self) -> None:
        with pytest.raises(ValueError):
            hop.parse_port_range("100-200")

    def test_above_65535(self) -> None:
        with pytest.raises(ValueError):
            hop.parse_port_range("65000-66000")

    def test_single_port_range_rejected(self) -> None:
        # start >= end — инверсия/вырожденный диапазон не допускается
        with pytest.raises(ValueError):
            hop.parse_port_range("20000-20000")


class TestRenderHopScript:
    def test_golden_snapshot(self) -> None:
        script = hop.render_hop_script(20000, 20500, 443, "VDS_HY2_HOP")
        expected = (
            "#!/bin/sh\n"
            "# VDS Hysteria2 port hopping (ADR-008). Артефакт команды\n"
            "# `vds hysteria2 add-hop-ports` — перегенерируется, руками не править.\n"
            "set -eu\n"
            "iptables -t nat -N VDS_HY2_HOP 2>/dev/null || true\n"
            "iptables -t nat -C VDS_HY2_HOP -p udp --dport 20000:20500 "
            "-j REDIRECT --to-ports 443 2>/dev/null || \\\n"
            "  iptables -t nat -A VDS_HY2_HOP -p udp --dport 20000:20500 "
            "-j REDIRECT --to-ports 443\n"
            "iptables -t nat -C PREROUTING -j VDS_HY2_HOP 2>/dev/null || \\\n"
            "  iptables -t nat -A PREROUTING -j VDS_HY2_HOP\n"
        )
        assert script == expected

    def test_deterministic(self) -> None:
        assert (
            hop.render_hop_script(1, 2, 443, "C")
            == hop.render_hop_script(1, 2, 443, "C")
        )

    def test_idempotent_checks_present(self) -> None:
        script = hop.render_hop_script(20000, 20500, 443, "VDS_HY2_HOP")
        # -C перед каждым -A (идемпотентность применения)
        assert script.count("iptables -t nat -C VDS_HY2_HOP ") == 1
        assert "iptables -t nat -C PREROUTING -j VDS_HY2_HOP" in script
        assert "-C PREROUTING" in script

    def test_no_secrets(self) -> None:
        script = hop.render_hop_script(20000, 20500, 443, "VDS_HY2_HOP")
        for secret in (AUTH_PW, "password", "uuid"):
            assert secret.lower() not in script.lower()


class TestAddHopPorts:
    def test_dry_run_no_mutations(self, env: dict) -> None:
        env["recorder"].rule_installed = False
        env["recorder"].jump_installed = False
        state_before = Path(env["state_path"]).read_bytes()
        assert hop.add_hop_ports("20000-20500", apply=False, state_path=env["state_path"]) == 0
        # Только читающие -C-проверки; никаких -A/-N/ufw allow.
        mutating = [
            argv for argv in env["recorder"].argvs()
            if (" -A " in argv or " -N " in argv or argv.startswith("ufw allow"))
        ]
        assert mutating == []
        assert not env["units"].owner.get("installed")
        assert Path(env["state_path"]).read_bytes() == state_before
        assert not Path(hop.HYSTERIA2_HOP_SCRIPT).exists()

    def test_apply_full_sequence_and_state(self, env: dict) -> None:
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 0
        argvs = env["recorder"].argvs()
        assert f"ufw allow 20000:20500/udp" in argvs
        # -A-правило и jump добавлены
        assert " ".join(hop._rule_add_args(20000, 20500)) in argvs
        assert " ".join(hop._jump_add_args()) in argvs
        # скрипт на месте, 0755, идемпотентного содержания
        script = Path(hop.HYSTERIA2_HOP_SCRIPT)
        assert script.is_file()
        assert script.stat().st_mode & 0o777 == 0o755
        assert "-C" in script.read_text(encoding="utf-8")
        # юнит из шаблона с контекстом hop_script
        assert env["units"].owner["installed"] == [
            ("vds-hysteria2-hop.service.tpl", hop.HYSTERIA2_HOP_UNIT,
             {"hop_script": str(hop.HYSTERIA2_HOP_SCRIPT)})
        ]
        state = load_state(env["state_path"])
        assert state.protocols["hysteria2"]["hop_ports"] == "20000-20500"

    def test_apply_twice_idempotent(self, env: dict) -> None:
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 0
        state_after_first = Path(env["state_path"]).read_bytes()
        env["recorder"].calls.clear()
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 0
        # Второй прогон: только -C-хиты, ни одного -A/-N/ufw/юнита.
        argvs = env["recorder"].argvs()
        assert argvs == [
            " ".join(hop._rule_check_args(20000, 20500)),
            " ".join(hop._jump_check_args()),
        ]
        assert Path(env["state_path"]).read_bytes() == state_after_first

    def test_not_root(self, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert hop.add_hop_ports("20000-20500", state_path=env["state_path"]) == 1
        assert env["recorder"].calls == []

    def test_hysteria2_not_installed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state_path = str(tmp_path / "state.json")
        save_state(GatewayState(), state_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        assert hop.add_hop_ports("20000-20500", state_path=state_path) == 1

    def test_bad_range_rejected(self, env: dict) -> None:
        assert hop.add_hop_ports("9000-90000", state_path=env["state_path"]) == 1
        assert env["recorder"].calls == []

    def test_busy_range_port_refused(
        self, env: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = env["recorder"]

        def _run(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:1] == ["ss"]:
                # порт 20001 занят чужим сервисом
                return ShellResult(
                    stdout=(
                        "UNCONN 0 0 0.0.0.0:20001 0.0.0.0:* "
                        'users:(("other",pid=1,fd=3))\n'
                    ),
                    stderr="", returncode=0,
                )
            return recorder(args, timeout)

        monkeypatch.setattr(hop, "run_list", _run)
        recorder.rule_installed = False
        recorder.jump_installed = False
        state_before = Path(env["state_path"]).read_bytes()
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 1
        # отказ ДО мутаций: ни -A, ни ufw
        mutating = [
            a for a in recorder.argvs()
            if " -A " in a or a.startswith("ufw allow")
        ]
        assert mutating == []
        assert Path(env["state_path"]).read_bytes() == state_before


class TestRemoveHopPorts:
    def test_nothing_to_remove(self, env: dict) -> None:
        assert hop.remove_hop_ports(state_path=env["state_path"]) == 0
        # Нечего снимать: plan-путь не выполняется, команд нет.
        assert env["recorder"].argvs() == []

    def test_dry_run_plan(self, env: dict) -> None:
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 0
        env["recorder"].calls.clear()
        state_before = Path(env["state_path"]).read_bytes()
        assert hop.remove_hop_ports(apply=False, state_path=env["state_path"]) == 0
        # dry-run: только читающие -C-проверки
        mutating = [
            a for a in env["recorder"].argvs()
            if (" -D " in a or " -F " in a or " -X " in a or a.startswith("ufw delete"))
        ]
        assert mutating == []
        assert Path(env["state_path"]).read_bytes() == state_before
        assert not env["units"].owner.get("removed")

    def test_apply_cleans_all(self, env: dict) -> None:
        assert hop.add_hop_ports("20000-20500", apply=True, state_path=env["state_path"]) == 0
        env["recorder"].calls.clear()
        assert hop.remove_hop_ports(apply=True, state_path=env["state_path"]) == 0
        argvs = env["recorder"].argvs()
        assert "iptables -t nat -D PREROUTING -j VDS_HY2_HOP" in argvs
        assert f"iptables -t nat -F {hop.HYSTERIA2_HOP_CHAIN}" in argvs
        assert f"iptables -t nat -X {hop.HYSTERIA2_HOP_CHAIN}" in argvs
        assert "ufw delete allow 20000:20500/udp" in argvs
        assert env["units"].owner.get("removed") == [hop.HYSTERIA2_HOP_UNIT]
        assert not Path(hop.HYSTERIA2_HOP_SCRIPT).exists()
        state = load_state(env["state_path"])
        assert "hop_ports" not in state.protocols["hysteria2"]
        # повторный remove — нечего снимать
        assert hop.remove_hop_ports(apply=True, state_path=env["state_path"]) == 0
