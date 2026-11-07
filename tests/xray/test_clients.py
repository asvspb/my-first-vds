"""Тесты src/xray/clients.py: share-link, дубликат имени, обновление конфига."""

import json
from pathlib import Path

import pytest

import src.xray.clients as clients
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, StoreError, save_state
from src.xray.config import render_config, XrayConfigParams

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "PUBKEYXYZ"
SID = "abcd1234"
SNI = "www.google.com"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp-конфиг + tmp-state с установленным xray; shell/ip — моки."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        render_config(XrayConfigParams(private_key="PRIVKEY123", short_ids=[SID])),
        encoding="utf-8",
    )
    state_path = tmp_path / "state.json"
    state = GatewayState()
    state.protocols["xray"] = {
        "installed": True,
        "sni": SNI,
        "port": 443,
        "public_key": PBK,
        "short_id": SID,
    }
    save_state(state, str(state_path))

    monkeypatch.setattr(clients, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(clients, "public_ip", lambda: "203.0.113.10")

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(clients, "run_list", _run_list)
    return tmp_path


class TestRenderShareLink:
    def test_exact_format(self) -> None:
        link = clients.render_share_link(
            host="203.0.113.10",
            client_uuid=UUID,
            sni=SNI,
            public_key=PBK,
            short_id=SID,
            name="phone",
        )
        assert link == (
            f"vless://{UUID}@203.0.113.10:443"
            f"?security=reality&sni={SNI}&fp=chrome"
            f"&pbk={PBK}&sid={SID}&flow=xtls-rprx-vision#phone"
        )

    def test_private_key_never_in_link(self) -> None:
        link = clients.render_share_link(
            host="1.2.3.4", client_uuid=UUID, sni=SNI,
            public_key=PBK, short_id=SID, name="n",
        )
        assert "privateKey" not in link
        assert "PRIV" not in link  # приватный ключ Reality отсутствует полностью

    def test_name_with_spaces_is_quoted(self) -> None:
        link = clients.render_share_link(
            host="1.2.3.4", client_uuid=UUID, sni=SNI,
            public_key=PBK, short_id=SID, name="my phone",
        )
        assert link.endswith("#my%20phone")


class TestAddClient:
    def test_duplicate_name_raises_store_error(self, env: Path) -> None:
        state_path = str(env / "state.json")
        from src.gateway.store import load_state

        state = load_state(state_path)
        state.clients.append(
            ClientProfile(name="phone", protocol="xray", port=443, uuid=UUID)
        )
        save_state(state, state_path)

        with pytest.raises(StoreError):
            clients.add_client("phone", state_path=state_path)
        # дубликат ловится ДО записи конфига: список clients не изменился
        config = json.loads((env / "config.json").read_text(encoding="utf-8"))
        assert config["inbounds"][0]["settings"]["clients"] == []

    def test_success_updates_config_and_state(self, env: Path) -> None:
        state_path = str(env / "state.json")
        result = clients.add_client("phone", state_path=state_path)

        assert result["name"] == "phone"
        assert result["protocol"] == "xray"
        assert result["share_link"] == (
            f"vless://{result['uuid']}@203.0.113.10:443"
            f"?security=reality&sni={SNI}&fp=chrome&pbk={PBK}&sid={SID}"
            f"&flow=xtls-rprx-vision#phone"
        )

        config = json.loads((env / "config.json").read_text(encoding="utf-8"))
        stored = config["inbounds"][0]["settings"]["clients"]
        assert [c["id"] for c in stored] == [result["uuid"]]
        assert stored[0]["flow"] == "xtls-rprx-vision"

        from src.gateway.store import load_state

        names = [c.name for c in load_state(state_path).clients]
        assert names == ["phone"]

    def test_not_installed_raises_xray_error(self, env: Path) -> None:
        state_path = str(env / "state.json")
        from src.gateway.store import load_state

        state = load_state(state_path)
        state.protocols.pop("xray")
        save_state(state, state_path)

        with pytest.raises(clients.XrayError):
            clients.add_client("phone", state_path=state_path)

    def test_restart_failure_rolls_back_config(
        self, env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path = str(env / "state.json")
        before = (env / "config.json").read_text(encoding="utf-8")

        def _fail(args: list[str], timeout: int = 10) -> ShellResult:
            return ShellResult(stdout="", stderr="unit failed", returncode=1)

        monkeypatch.setattr(clients, "run_list", _fail)

        with pytest.raises(clients.XrayError):
            clients.add_client("phone", state_path=state_path)
        assert (env / "config.json").read_text(encoding="utf-8") == before


class TestRemoveClient:
    def test_remove_updates_config_and_state(self, env: Path) -> None:
        state_path = str(env / "state.json")
        clients.add_client("phone", state_path=state_path)
        clients.add_client("tablet", state_path=state_path)

        assert clients.remove_client("phone", state_path=state_path) == 0

        config = json.loads((env / "config.json").read_text(encoding="utf-8"))
        stored = config["inbounds"][0]["settings"]["clients"]
        assert len(stored) == 1  # остался только tablet

        from src.gateway.store import load_state

        assert [c.name for c in load_state(state_path).clients] == ["tablet"]

    def test_remove_missing_raises_store_error(self, env: Path) -> None:
        with pytest.raises(StoreError):
            clients.remove_client("ghost", state_path=str(env / "state.json"))
