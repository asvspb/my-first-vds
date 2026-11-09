"""WP-A: render_all_links — share-links всех клиентов gateway state.

Форматы — эталон из существующих тестов: tests/xray/test_clients.py,
tests/xray/test_links_xhttp.py, tests/hysteria2/test_clients.py,
tests/hysteria2/test_links_domain.py. Фикстуры — по AGENTS.md §6:
FIXTURE_PW_*/FIXTURE_UUID_*, 203.0.113.0/24 (RFC 5737).
"""

import pytest

from src.gateway.links import render_all_links
from src.gateway.store import ClientProfile, GatewayState, save_state

UUID = "11111111-2222-3333-4444-555555555555"
UUID_XHTTP = "11111111-2222-3333-4444-666666666666"
PASSWORD = "FIXTURE_PW_Hysteria123"
IP = "203.0.113.10"
DOMAIN = "vpn.example.com"
SNI = "www.google.com"
PBK = "PUBKEYXYZ"
SID = "abcd1234"


@pytest.fixture()
def state_path(tmp_path) -> str:
    return str(tmp_path / "state.json")


def _save(state: GatewayState, state_path: str) -> None:
    save_state(state, state_path)


def _full_state() -> GatewayState:
    """State с тремя клиентами: phone (reality), mob (hysteria2 legacy),
    xhttp-web (xhttp)."""
    state = GatewayState()
    state.domain = ""
    state.protocols["xray"] = {
        "installed": True,
        "sni": SNI,
        "port": 443,
        "public_key": PBK,
        "short_id": SID,
    }
    state.protocols["xhttp"] = {
        "installed": True,
        "port": 8443,
        "mode": "fallback",
        "domain": DOMAIN,
        "extra": {"path": "/xhttp"},
    }
    state.protocols["hysteria2"] = {
        "installed": True,
        "port": 443,
        "cert_cn": IP,
        "auth_password": PASSWORD,
    }
    state.clients = [
        ClientProfile(
            name="phone", protocol="xray", port=443, uuid=UUID, sni=SNI,
            extra={"public_key": PBK, "short_id": SID},
        ),
        ClientProfile(
            name="mob", protocol="hysteria2", port=443, password=PASSWORD,
            sni=IP, extra={},
        ),
        ClientProfile(
            name="xhttp-web", protocol="xray", port=443, uuid=UUID_XHTTP,
            sni=DOMAIN, extra={"transport": "xhttp", "public_key": PBK},
        ),
    ]
    return state


class TestRealityLink:
    def test_ip_host_exact_format(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        state = _full_state()
        del state.protocols["xhttp"]
        state.clients = [state.clients[0]]  # только phone (reality)
        _save(state, state_path)

        result = render_all_links(state_path)
        assert result == [
            (
                "phone",
                "xray",
                f"vless://{UUID}@{IP}:443?security=reality&sni={SNI}&fp=chrome"
                f"&pbk={PBK}&sid={SID}&flow=xtls-rprx-vision#phone",
            )
        ]

    def test_domain_host_when_state_domain_set(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        state = _full_state()
        state.domain = DOMAIN
        del state.protocols["xhttp"]
        state.clients = [state.clients[0]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert result[0][2].startswith(f"vless://{UUID}@{DOMAIN}:443?")

    def test_private_key_not_in_link(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        state = _full_state()
        del state.protocols["xhttp"]
        state.clients = [state.clients[0]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert "PRIV" not in result[0][2].upper()


class TestXhttpLink:
    def test_exact_format(self, state_path: str) -> None:
        """XHTTP-клиент: домен из protocols['xhttp'], port 443 (mode=fallback),
        path из protocols['xhttp']['extra']['path']."""
        state = _full_state()
        state.clients = [state.clients[2]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert result == [
            (
                "xhttp-web",
                "xray",
                f"vless://{UUID_XHTTP}@{DOMAIN}:443"
                f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
                f"&path=/xhttp&type=xhttp#xhttp-web",
            )
        ]

    def test_port_mode_uses_8443(self, state_path: str) -> None:
        state = _full_state()
        state.protocols["xhttp"]["mode"] = "port"
        state.clients = [state.clients[2]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert f"@{DOMAIN}:8443?" in result[0][2]


class TestHysteria2Link:
    def test_legacy_exact_format(self, state_path: str) -> None:
        """Без LE-домена — legacy insecure-ссылка байт-в-байт (инвариант E11)."""
        state = _full_state()
        state.clients = [state.clients[1]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert result == [
            ("mob", "hysteria2", f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#mob")
        ]

    def test_le_link_no_insecure(self, state_path: str) -> None:
        state = _full_state()
        state.protocols["acme"] = {"domain": DOMAIN}
        state.clients = [state.clients[1]]
        _save(state, state_path)

        result = render_all_links(state_path)
        assert result[0][2] == f"hysteria2://{PASSWORD}@{DOMAIN}:443/?sni={DOMAIN}#mob"
        assert "insecure" not in result[0][2]


class TestAllAndFilter:
    def test_all_three_clients(self, state_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        _save(_full_state(), state_path)

        result = render_all_links(state_path)
        assert [(n, p) for n, p, _ in result] == [
            ("phone", "xray"),
            ("mob", "hysteria2"),
            ("xhttp-web", "xray"),
        ]

    def test_filter_protocol_xray(self, state_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        _save(_full_state(), state_path)

        result = render_all_links(state_path, protocol="xray")
        assert [(n, p) for n, p, _ in result] == [
            ("phone", "xray"),
            ("xhttp-web", "xray"),
        ]

    def test_filter_protocol_hysteria2(self, state_path: str) -> None:
        _save(_full_state(), state_path)

        result = render_all_links(state_path, protocol="hysteria2")
        assert [(n, p) for n, p, _ in result] == [("mob", "hysteria2")]

    def test_unknown_protocol_raises(self, state_path: str) -> None:
        _save(_full_state(), state_path)
        with pytest.raises(ValueError):
            render_all_links(state_path, protocol="wireguard")


class TestEmptyState:
    def test_missing_file_returns_empty(self, tmp_path) -> None:
        assert render_all_links(str(tmp_path / "nope.json")) == []

    def test_empty_clients_returns_empty(self, state_path: str) -> None:
        _save(GatewayState(), state_path)
        assert render_all_links(state_path) == []
