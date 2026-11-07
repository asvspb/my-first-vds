"""Тесты src/xray/remove.py: dry-run по умолчанию, --apply, идемпотентность."""

from pathlib import Path

import pytest

import src.xray.remove as remove_mod
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, load_state, save_state


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Tmp-пути «установленного» xray + state с одним клиентом."""
    bin_path = tmp_path / "bin" / "xray"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("fake", encoding="utf-8")
    config_path = tmp_path / "etc" / "xray" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    geodata_dir = tmp_path / "share" / "xray"
    geodata_dir.mkdir(parents=True)
    (geodata_dir / "geoip.dat").write_text("geoip", encoding="utf-8")

    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["xray"] = {"installed": True, "sni": "www.google.com"}
    state.clients.append(
        ClientProfile(name="phone", protocol="xray", port=443, uuid="u-1")
    )
    state.clients.append(
        ClientProfile(name="hy", protocol="hysteria2", port=443, password="p")
    )
    save_state(state, state_path)

    monkeypatch.setattr(remove_mod, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(remove_mod, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(remove_mod, "XRAY_GEODATA_DIR", geodata_dir)
    monkeypatch.setattr(remove_mod, "UNIT_FILE", tmp_path / "systemd" / "vds-xray.service")
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
        "geodata": geodata_dir,
        "state_path": state_path,
        "recorder": recorder,
        "removed_units": removed_units,
    }


class TestRunRemove:
    def test_nothing_to_remove_exit_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(remove_mod, "XRAY_BIN_PATH", tmp_path / "nope")
        monkeypatch.setattr(remove_mod, "XRAY_CONFIG_PATH", tmp_path / "nope2")
        monkeypatch.setattr(remove_mod, "XRAY_GEODATA_DIR", tmp_path / "nope3")
        monkeypatch.setattr(remove_mod, "UNIT_FILE", tmp_path / "nope4")
        state_path = str(tmp_path / "empty-state.json")
        assert remove_mod.run_remove(state_path=state_path) == 0

    def test_dry_run_removes_nothing(self, env) -> None:
        assert remove_mod.run_remove(state_path=env["state_path"]) == 0
        assert env["bin"].exists()
        assert env["config"].exists()
        assert env["geodata"].exists()
        assert env["removed_units"] == []
        assert any("dry-run" in line for line in env["recorder"].lines)
        # клиент остался в store
        state = load_state(env["state_path"])
        assert [c.name for c in state.clients] == ["phone", "hy"]

    def test_apply_removes_xray_only(self, env) -> None:
        assert (
            remove_mod.run_remove(apply=True, yes=True, state_path=env["state_path"]) == 0
        )
        assert not env["bin"].exists()
        assert not env["config"].exists()
        assert not env["geodata"].exists()
        assert env["removed_units"] == ["vds-xray.service"]

        # xray-клиент и protocols['xray'] удалены; hysteria2-клиент не тронут
        state = load_state(env["state_path"])
        assert [c.name for c in state.clients] == ["hy"]
        assert "xray" not in state.protocols

        # повторный запуск — идемпотентен (нечего удалять, exit 0)
        assert remove_mod.run_remove(apply=True, yes=True, state_path=env["state_path"]) == 0
