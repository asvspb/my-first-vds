"""Тесты src/hysteria2/status.py: не установлен, сертификат, маскировка."""

from pathlib import Path

import pytest

import src.hysteria2.status as status_mod
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    bin_path = tmp_path / "bin" / "hysteria"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("fake", encoding="utf-8")
    cert_path = tmp_path / "etc" / "hysteria" / "cert.pem"
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_text("CERT", encoding="utf-8")
    config_path = tmp_path / "etc" / "hysteria" / "config.yaml"
    config_path.write_text(
        'auth:\n  type: password\n  password: "FIXTURE_PW_Masked"\n', encoding="utf-8"
    )

    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True, "port": 443, "auth_password": "FIXTURE_PW_Masked"
    }
    save_state(state, state_path)

    monkeypatch.setattr(status_mod, "HYSTERIA2_BIN_PATH", bin_path)
    monkeypatch.setattr(status_mod, "HYSTERIA2_CERT_PATH", cert_path)
    monkeypatch.setattr(status_mod, "HYSTERIA2_CONFIG_PATH", config_path)
    monkeypatch.setattr(status_mod, "is_service_active", lambda: True)
    monkeypatch.setattr(status_mod, "port_free", lambda port, proto="udp": False)
    monkeypatch.setattr(status_mod, "port_owner", lambda port, proto="udp": "hysteria")
    monkeypatch.setattr(
        status_mod, "load_state", lambda path=None: _load_state(state_path)
    )

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[:2] == ["openssl", "x509"]:
            return ShellResult(
                stdout="notAfter=Jan  1 00:00:00 2099 GMT\n", stderr="", returncode=0
            )
        if args[:1] == ["journalctl"]:
            return ShellResult(
                stdout="bad line with FIXTURE_PW_Masked and password: FIXTURE_PW_Masked\n",
                stderr="", returncode=0,
            )
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(status_mod, "run_list", _run_list)
    return {"bin": bin_path, "state_path": state_path}


def _load_state(path: str) -> GatewayState:
    from src.gateway.store import load_state as _ls

    return _ls(path)


class TestRunStatus:
    def test_not_installed_exit_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _ConsoleRecorder()
        monkeypatch.setattr(status_mod, "console", recorder)
        monkeypatch.setattr(status_mod, "HYSTERIA2_BIN_PATH", tmp_path / "missing")
        assert status_mod.run_status() == 1
        assert any("не установлен" in line for line in recorder.lines)

    def test_installed_exit_zero_and_cert_days(self, env, monkeypatch) -> None:
        recorder = _ConsoleRecorder()
        monkeypatch.setattr(status_mod, "console", recorder)
        assert status_mod.run_status() == 0
        assert any("2099" not in line and "дн." in line for line in recorder.lines)

    def test_collect_status_fields(self, env) -> None:
        info = status_mod.collect_status()
        assert info["installed"] is True
        assert info["unit_active"] is True
        assert info["port_listening"] is True
        assert info["port_owner"] == "hysteria"
        assert info["cert_days_left"] is not None and info["cert_days_left"] > 20000


class TestMasking:
    def test_journal_password_masked(self, env, monkeypatch) -> None:
        recorder = _ConsoleRecorder()
        monkeypatch.setattr(status_mod, "console", recorder)
        status_mod.run_status()
        # пароль не появился в выводе ни разу
        assert not any("FIXTURE_PW_Masked" in line for line in recorder.lines)
        assert any("***" in line for line in recorder.lines)

    def test_mask_secrets_masks_known_values(self) -> None:
        masked = status_mod._mask_secrets(
            "connect pw=FIXTURE_PW_Masked ok password: FIXTURE_PW_Masked", ["FIXTURE_PW_Masked"]
        )
        assert "FIXTURE_PW_Masked" not in masked
        assert masked.count("***") == 2

    def test_known_secrets_include_obfs_password(self, env, monkeypatch) -> None:
        """obfs-пароль из state и obfs.yaml маскируется наравне с auth (SPEC WP-1)."""
        state = _load_state(env["state_path"])
        state.protocols["hysteria2-obfs"] = {
            "installed": True, "port": 51826, "obfs_password": "FIXTURE_PW_ObfState"
        }
        save_state(state, env["state_path"])
        obfs_cfg = (
            status_mod.HYSTERIA2_CONFIG_PATH.parent / "obfs.yaml"
        )
        obfs_cfg.write_text(
            "auth:\n  type: password\n  password: FIXTURE_PW_ObfYaml\n"
            "obfs:\n  type: salamander\n  password: FIXTURE_PW_ObfState\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(status_mod, "HYSTERIA2_OBFS_CONFIG_PATH", obfs_cfg)

        secrets = status_mod._known_secrets()
        assert "FIXTURE_PW_Masked" in secrets
        assert "FIXTURE_PW_ObfState" in secrets
        assert "FIXTURE_PW_ObfYaml" in secrets
        masked = status_mod._mask_secrets(
            "leak FIXTURE_PW_ObfState and FIXTURE_PW_ObfYaml", secrets
        )
        assert "FIXTURE_PW_ObfState" not in masked
        assert "FIXTURE_PW_ObfYaml" not in masked

    def test_mask_secrets_masks_yaml_password_line(self) -> None:
        masked = status_mod._mask_secrets(
            'auth:\n  password: "FIXTURE_PW_Unknown"\n', ["FIXTURE_PW_Unknown"]
        )
        assert "FIXTURE_PW_Unknown" not in masked
