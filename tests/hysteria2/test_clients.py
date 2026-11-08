"""Тесты src/hysteria2/clients.py: share-link, дубликат имени, маскировка пароля."""

from pathlib import Path

import pytest

import src.hysteria2.clients as clients
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    StoreError,
    load_state,
    save_state,
)

PASSWORD = "FIXTURE_PW_Hysteria123"
IP = "203.0.113.10"


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Tmp-state с установленным hysteria2 (общий пароль); ip — мок."""
    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True,
        "port": 443,
        "cert_cn": IP,
        "auth_password": PASSWORD,
    }
    state.clients.append(
        ClientProfile(name="xuser", protocol="xray", port=443, uuid="u-1")
    )
    save_state(state, state_path)

    monkeypatch.setattr(clients, "public_ip", lambda: IP)
    recorder = _ConsoleRecorder()
    monkeypatch.setattr(clients, "console", recorder)
    return {"state_path": state_path, "recorder": recorder}


class TestRenderShareLink:
    def test_exact_format_with_insecure(self) -> None:
        link = clients.render_share_link(
            host=IP, password=PASSWORD, name="phone", port=443
        )
        assert link == (
            f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#phone"
        )

    def test_insecure_one_and_sni_is_ip(self) -> None:
        link = clients.render_share_link(host=IP, password=PASSWORD, name="n")
        assert "insecure=1" in link
        assert f"sni={IP}" in link
        assert "insecure=0" not in link

    def test_name_with_spaces_is_quoted(self) -> None:
        link = clients.render_share_link(host=IP, password=PASSWORD, name="my phone")
        assert link.endswith("#my%20phone")


class TestAddClient:
    def test_add_client_profile_and_link(self, env) -> None:
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["name"] == "laptop"
        assert result["protocol"] == "hysteria2"
        assert result["password"] == PASSWORD  # общий пароль инбаунда
        assert result["share_link"].startswith(f"hysteria2://{PASSWORD}@{IP}:443/")

        state = load_state(env["state_path"])
        hy = [c for c in state.clients if c.protocol == "hysteria2"]
        assert [c.name for c in hy] == ["laptop"]
        assert hy[0].password == PASSWORD
        assert hy[0].sni == IP
        # xray-клиент не тронут
        assert any(c.protocol == "xray" for c in state.clients)

    def test_duplicate_name_store_error(self, env) -> None:
        clients.add_client("laptop", state_path=env["state_path"])
        with pytest.raises(StoreError):
            clients.add_client("laptop", state_path=env["state_path"])

    def test_not_installed_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        empty_state = str(tmp_path / "empty.json")
        save_state(GatewayState(), empty_state)
        with pytest.raises(clients.Hysteria2Error):
            clients.add_client("n", state_path=empty_state)

    def test_password_only_in_share_link_line(self, env) -> None:
        """Пароль в выводе встречается только внутри share-link (SPEC §5)."""
        clients.add_client("laptop", state_path=env["state_path"])
        occurrences = [
            line for line in env["recorder"].lines if PASSWORD in line
        ]
        assert len(occurrences) == 1
        # единственная строка с паролем — это сам share-link (с rich-тегом [change])
        assert occurrences[0] == (
            f"[change]hysteria2://{PASSWORD}@{IP}:443/"
            f"?sni={IP}&insecure=1#laptop[/change]"
        )


class TestRemoveClient:
    def test_remove_only_hysteria2_client(self, env) -> None:
        clients.add_client("laptop", state_path=env["state_path"])
        assert clients.remove_client("laptop", state_path=env["state_path"]) == 0
        state = load_state(env["state_path"])
        assert [c.protocol for c in state.clients] == ["xray"]

    def test_remove_unknown_raises(self, env) -> None:
        with pytest.raises(StoreError):
            clients.remove_client("ghost", state_path=env["state_path"])


class TestAdapterShareLinks:
    def test_adapter_render_share_links(self) -> None:
        from src.hysteria2.adapter import HysteriaAdapter

        adapter = HysteriaAdapter()
        assert adapter.name == "hysteria2"
        assert adapter.transport == "udp"
        links = adapter.render_share_links(
            {"name": "phone", "password": PASSWORD, "sni": IP, "port": 443}
        )
        assert links == [f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#phone"]
