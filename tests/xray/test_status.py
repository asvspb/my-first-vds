"""Тесты src/xray/status.py: не установлен, маскирование секретов."""

from pathlib import Path

import pytest

import src.xray.status as status_mod
from src.core.shell import ShellResult
from src.gateway.store import GatewayState
from src.xray.config import XrayConfigParams, render_config

UUID = "11111111-2222-3333-4444-555555555555"
PRIVATE_KEY = "PRIVKEYABC"


class TestMaskSecrets:
    def test_masks_uuid_values(self) -> None:
        text = f"failed to auth client {UUID} from 1.2.3.4"
        assert status_mod._mask_secrets(text, [UUID]) == (
            "failed to auth client *** from 1.2.3.4"
        )

    def test_masks_private_key_in_json_dump(self) -> None:
        text = '{"privateKey": "%s", "shortIds": ["abcd1234"]}' % PRIVATE_KEY
        masked = status_mod._mask_secrets(text, [])
        assert PRIVATE_KEY not in masked
        assert '"privateKey": "***"' in masked

    def test_empty_secret_values_ignored(self) -> None:
        assert status_mod._mask_secrets("abc", ["", None]) == "abc"


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def recorder(monkeypatch: pytest.MonkeyPatch) -> _ConsoleRecorder:
    rec = _ConsoleRecorder()
    monkeypatch.setattr(status_mod, "console", rec)
    return rec


class TestRunStatus:
    def test_not_installed_exit_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        monkeypatch.setattr(status_mod, "XRAY_BIN_PATH", tmp_path / "missing")
        assert status_mod.run_status() == 1
        assert any("не установлен" in line for line in recorder.lines)

    def test_installed_masks_journal_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        bin_path = tmp_path / "xray"
        bin_path.write_text("fake", encoding="utf-8")
        config_path = tmp_path / "config.json"
        config_path.write_text(
            render_config(
                XrayConfigParams(client_ids=[UUID], private_key=PRIVATE_KEY, short_ids=["abcd1234"])
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(status_mod, "XRAY_BIN_PATH", bin_path)
        monkeypatch.setattr(status_mod, "XRAY_CONFIG_PATH", config_path)
        monkeypatch.setattr(status_mod, "is_service_active", lambda: True)
        monkeypatch.setattr(status_mod, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(status_mod, "port_owner", lambda port, proto="tcp": "xray")
        monkeypatch.setattr(
            status_mod, "load_state", lambda path=None: GatewayState()
        )

        def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
            if "-test" in args:
                return ShellResult(stdout="Configuration OK.", stderr="", returncode=0)
            if args[0] == "journalctl":
                journal = (
                    f"config: {{\"privateKey\": \"{PRIVATE_KEY}\"}}\n"
                    f"auth failed for {UUID}\n"
                )
                return ShellResult(stdout=journal, stderr="", returncode=0)
            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(status_mod, "run_list", _run_list)

        assert status_mod.run_status() == 0
        output = "\n".join(recorder.lines)
        assert PRIVATE_KEY not in output
        assert UUID not in output
        assert "***" in output
        assert any("active" in line for line in recorder.lines)


def _config_with_cdn() -> str:
    """Конфиг: Reality (inbound#0) + ws-инблэнд на 2053 (CDN)."""
    import json

    base = json.loads(
        render_config(
            XrayConfigParams(
                client_ids=[UUID],
                private_key=PRIVATE_KEY,
                short_ids=["abcd1234"],
            )
        )
    )
    base["inbounds"].append(
        {
            "listen": "0.0.0.0",
            "port": 2053,
            "protocol": "vless",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": "/ws"},
            },
        }
    )
    return json.dumps(base)


class TestStatusCdn:
    """SPEC-20261110 WP-3: CDN-секция статуса (с CDN / без / рассинхрон)."""

    CDN_UUID = "11111111-2222-3333-4444-999999999999"

    def _setup_installed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config_text: str,
        state: GatewayState,
    ) -> None:
        bin_path = tmp_path / "xray"
        bin_path.write_text("fake", encoding="utf-8")
        config_path = tmp_path / "config.json"
        config_path.write_text(config_text, encoding="utf-8")
        monkeypatch.setattr(status_mod, "XRAY_BIN_PATH", bin_path)
        monkeypatch.setattr(status_mod, "XRAY_CONFIG_PATH", config_path)
        monkeypatch.setattr(status_mod, "is_service_active", lambda: True)
        monkeypatch.setattr(status_mod, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(status_mod, "port_owner", lambda port, proto="tcp": "xray")
        monkeypatch.setattr(status_mod, "load_state", lambda path=None: state)

        def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
            if "-test" in args:
                return ShellResult(stdout="Configuration OK.", stderr="", returncode=0)
            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(status_mod, "run_list", _run_list)

    def _cdn_state(self, installed: bool = True) -> GatewayState:
        state = GatewayState()
        state.protocols["xray-cdn"] = {
            "installed": installed,
            "domain": "cdn.example.com",
            "port": 2053,
            "path": "/ws",
            "client_ids": [self.CDN_UUID],
            "clients": {"phone-cdn": self.CDN_UUID},
        }
        return state

    def test_cdn_installed_shows_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        self._setup_installed(
            monkeypatch, tmp_path, _config_with_cdn(), self._cdn_state()
        )
        assert status_mod.run_status() == 0
        output = "\n".join(recorder.lines)
        assert any(
            "CDN:" in line and "cdn.example.com" in line and "2053" in line
            and "инблэнд в конфиге" in line
            for line in recorder.lines
        )
        assert any("CDN-клиенты (1):" in line and "phone-cdn" in line for line in recorder.lines)
        assert self.CDN_UUID not in output  # uuid CDN-клиента не печатается

    def test_cdn_desync_meta_without_inbound(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        """State есть, ws-инблэнда в конфиге нет — рассинхрон."""
        config_text = render_config(
            XrayConfigParams(
                client_ids=[UUID], private_key=PRIVATE_KEY, short_ids=["abcd1234"]
            )
        )
        self._setup_installed(
            monkeypatch, tmp_path, config_text, self._cdn_state()
        )
        assert status_mod.run_status() == 0
        assert any("инблэнда нет в конфиге" in line for line in recorder.lines)

    def test_cdn_desync_inbound_without_meta(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        """ws-инблэнд в конфиге, state-записи нет — рассинхрон."""
        self._setup_installed(
            monkeypatch, tmp_path, _config_with_cdn(), GatewayState()
        )
        assert status_mod.run_status() == 0
        assert any(
            "CDN-инблэнд" in line and "рассинхрон" in line
            for line in recorder.lines
        )

    def test_cdn_masked_in_journal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        bin_path = tmp_path / "xray"
        bin_path.write_text("fake", encoding="utf-8")
        config_path = tmp_path / "config.json"
        config_path.write_text(_config_with_cdn(), encoding="utf-8")
        monkeypatch.setattr(status_mod, "XRAY_BIN_PATH", bin_path)
        monkeypatch.setattr(status_mod, "XRAY_CONFIG_PATH", config_path)
        monkeypatch.setattr(status_mod, "is_service_active", lambda: True)
        monkeypatch.setattr(status_mod, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(status_mod, "port_owner", lambda port, proto="tcp": "xray")
        monkeypatch.setattr(status_mod, "load_state", lambda path=None: self._cdn_state())

        def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
            if "-test" in args:
                return ShellResult(stdout="Configuration OK.", stderr="", returncode=0)
            if args[0] == "journalctl":
                return ShellResult(
                    stdout=f"auth failed for {self.CDN_UUID}\n",
                    stderr="",
                    returncode=0,
                )
            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(status_mod, "run_list", _run_list)

        assert status_mod.run_status() == 0
        output = "\n".join(recorder.lines)
        assert self.CDN_UUID not in output
        assert "***" in output

    def test_no_cdn_no_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        config_text = render_config(
            XrayConfigParams(
                client_ids=[UUID], private_key=PRIVATE_KEY, short_ids=["abcd1234"]
            )
        )
        self._setup_installed(monkeypatch, tmp_path, config_text, GatewayState())
        assert status_mod.run_status() == 0
        assert not any("CDN" in line for line in recorder.lines)

    def test_collect_status_cdn_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._setup_installed(
            monkeypatch, tmp_path, _config_with_cdn(), self._cdn_state()
        )
        info = status_mod.collect_status()
        assert info["cdn"]["inbound_in_config"] is True
        assert info["cdn"]["clients"] == ["phone-cdn"]
        assert info["cdn"]["meta"]["domain"] == "cdn.example.com"
