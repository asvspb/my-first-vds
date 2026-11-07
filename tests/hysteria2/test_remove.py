"""Тесты src/hysteria2/remove.py: dry-run, --apply, идемпотентность, sysctl не трогаем."""

from pathlib import Path

import pytest

import src.hysteria2.remove as remove_mod
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, load_state, save_state


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Tmp-пути «установленной» hysteria2 + state с клиентами двух протоколов."""
    bin_path = tmp_path / "bin" / "hysteria"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("fake", encoding="utf-8")
    config_path = tmp_path / "etc" / "hysteria" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("listen: :443\n", encoding="utf-8")
    cert_path = tmp_path / "etc" / "hysteria" / "cert.pem"
    key_path = tmp_path / "etc" / "hysteria" / "key.pem"
    cert_path.write_text("CERT", encoding="utf-8")
    key_path.write_text("KEY", encoding="utf-8")
    sysctl_path = tmp_path / "sysctl.d" / "99-vds-gateway.conf"
    sysctl_path.parent.mkdir(parents=True)
    sysctl_path.write_text("net.ipv4.tcp_congestion_control = bbr\n", encoding="utf-8")

    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True, "port": 443, "auth_password": "PW123"
    }
    state.protocols["xray"] = {"installed": True}
    state.clients.append(
        ClientProfile(name="laptop", protocol="hysteria2", port=443, password="PW123")
    )
    state.clients.append(
        ClientProfile(name="phone", protocol="xray", port=443, uuid="u-1")
    )
    save_state(state, state_path)

    monkeypatch.setattr(remove_mod, "HYSTERIA2_BIN_PATH", bin_path)
    monkeypatch.setattr(remove_mod, "HYSTERIA2_CONFIG_PATH", config_path)
    monkeypatch.setattr(remove_mod, "HYSTERIA2_CERT_PATH", cert_path)
    monkeypatch.setattr(remove_mod, "HYSTERIA2_KEY_PATH", key_path)
    monkeypatch.setattr(remove_mod, "UNIT_FILE", tmp_path / "systemd" / "vds-hysteria2.service")
    monkeypatch.setattr(remove_mod, "unit_active", lambda name: False)
    monkeypatch.setattr(
        remove_mod, "run_list",
        lambda args, timeout=10: ShellResult(stdout="", stderr="", returncode=0),
    )

    recorder = _ConsoleRecorder()
    monkeypatch.setattr(remove_mod, "console", recorder)
    removed_units: list[str] = []
    monkeypatch.setattr(
        remove_mod, "remove_unit",
        lambda name, root="/": removed_units.append(name) or True,
    )
    return {
        "root": tmp_path,
        "bin": bin_path,
        "config": config_path,
        "cert": cert_path,
        "key": key_path,
        "sysctl": sysctl_path,
        "state_path": state_path,
        "recorder": recorder,
        "removed_units": removed_units,
    }


class TestRunRemove:
    def test_nothing_to_remove_exit_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(remove_mod, "HYSTERIA2_BIN_PATH", tmp_path / "nope")
        monkeypatch.setattr(remove_mod, "HYSTERIA2_CONFIG_PATH", tmp_path / "nope2")
        monkeypatch.setattr(remove_mod, "HYSTERIA2_CERT_PATH", tmp_path / "nope3")
        monkeypatch.setattr(remove_mod, "HYSTERIA2_KEY_PATH", tmp_path / "nope4")
        monkeypatch.setattr(remove_mod, "UNIT_FILE", tmp_path / "nope5")
        assert remove_mod.run_remove(state_path=str(tmp_path / "s.json")) == 0

    def test_dry_run_removes_nothing_and_mentions_sysctl(self, env) -> None:
        assert remove_mod.run_remove(state_path=env["state_path"]) == 0
        assert env["bin"].exists()
        assert env["config"].exists()
        assert env["cert"].exists()
        assert env["key"].exists()
        assert env["removed_units"] == []
        assert any("dry-run" in line for line in env["recorder"].lines)
        # план явно упоминает, что sysctl НЕ откатывается (ADR-002)
        assert any("sysctl" in line and "НЕ трогаем" in line for line in env["recorder"].lines)
        state = load_state(env["state_path"])
        assert [c.name for c in state.clients] == ["laptop", "phone"]

    def test_apply_removes_hysteria2_only_keeps_sysctl(self, env) -> None:
        assert (
            remove_mod.run_remove(apply=True, yes=True, state_path=env["state_path"]) == 0
        )
        assert not env["bin"].exists()
        assert not env["config"].exists()
        assert not env["cert"].exists()
        assert not env["key"].exists()
        assert env["removed_units"] == ["vds-hysteria2.service"]
        # sysctl-файл оставлен (ADR-002/OQ-2)
        assert env["sysctl"].is_file()

        # hysteria2-клиент и protocols['hysteria2'] удалены; xray не тронут
        state = load_state(env["state_path"])
        assert [c.name for c in state.clients] == ["phone"]
        assert "hysteria2" not in state.protocols
        assert "xray" in state.protocols

        # повторный запуск — идемпотентен (нечего удалять, exit 0)
        assert remove_mod.run_remove(apply=True, yes=True, state_path=env["state_path"]) == 0
