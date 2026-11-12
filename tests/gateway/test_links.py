"""WP-A: render_all_links — share-links всех клиентов gateway state.

Форматы — эталон из существующих тестов: tests/xray/test_clients.py,
tests/xray/test_links_xhttp.py, tests/hysteria2/test_clients.py,
tests/hysteria2/test_links_domain.py. Фикстуры — по AGENTS.md §6:
FIXTURE_PW_*/FIXTURE_UUID_*, 203.0.113.0/24 (RFC 5737).
"""

import pytest

from src.gateway.links import render_all_links
from src.gateway.store import ClientProfile, GatewayState, load_state, save_state

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

    def test_state_domain_wins_when_acme_domain_is_cdn_front(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Регресс asv1: acme.domain — CDN-фронт за Cloudflare, сертификат
        hysteria2 выписан на state.domain; sni обязан быть state.domain."""
        import src.hysteria2.clients as hy_clients

        monkeypatch.setattr(hy_clients, "cert_exists", lambda d: d == DOMAIN)
        state = _full_state()
        state.domain = DOMAIN
        state.protocols["acme"] = {"installed": True, "domain": "cdn.example.ru"}
        state.clients = [state.clients[1]]
        _save(state, state_path)

        result = render_all_links(state_path, protocol="hysteria2")
        assert result[0][2] == f"hysteria2://{PASSWORD}@{DOMAIN}:443/?sni={DOMAIN}#mob"
        assert "insecure" not in result[0][2]

    def test_mport_included_when_hop_ports_set(self, state_path: str) -> None:
        state = _full_state()
        state.protocols["acme"] = {"domain": DOMAIN}
        state.protocols["hysteria2"]["hop_ports"] = "20000-20500"
        state.clients = [state.clients[1]]
        _save(state, state_path)

        result = render_all_links(state_path, protocol="hysteria2")
        assert result[0][2].endswith(f"?sni={DOMAIN}&mport=20000-20500#mob")


class TestHysteria2ObfsLinks:
    """`--include-obfs`: второй ряд `<name>@obfs` для obfs-инстанса."""

    def _state(self, state_path: str, *, with_obfs: bool = True) -> None:
        state = _full_state()
        state.protocols["acme"] = {"domain": DOMAIN}
        state.clients = [state.clients[1]]
        if with_obfs:
            state.protocols["hysteria2-obfs"] = {
                "installed": True,
                "port": 51826,
                "obfs_password": "FIXTURE_PW_Obfs",
            }
        _save(state, state_path)

    def test_obfs_link_added(self, state_path: str) -> None:
        self._state(state_path)
        result = render_all_links(
            state_path, protocol="hysteria2", include_obfs=True
        )
        assert [name for name, _, _ in result] == ["mob", "mob@obfs"]
        assert result[1][1] == "hysteria2"
        assert result[1][2] == (
            f"hysteria2://{PASSWORD}@{DOMAIN}:51826/?sni={DOMAIN}"
            f"&obfs=salamander&obfs-password=FIXTURE_PW_Obfs#mob%40obfs"
        )

    def test_obfs_link_includes_mport(self, state_path: str) -> None:
        self._state(state_path)
        state = load_state(state_path)
        state.protocols["hysteria2"]["hop_ports"] = "20000-20500"
        _save(state, state_path)

        result = render_all_links(
            state_path, protocol="hysteria2", include_obfs=True
        )
        for _, _, link in result:
            assert "mport=20000-20500" in link

    def test_obfs_link_absent_without_flag(self, state_path: str) -> None:
        self._state(state_path)
        result = render_all_links(state_path, protocol="hysteria2")
        assert [name for name, _, _ in result] == ["mob"]

    def test_obfs_link_absent_without_instance(self, state_path: str) -> None:
        self._state(state_path, with_obfs=False)
        result = render_all_links(
            state_path, protocol="hysteria2", include_obfs=True
        )
        assert [name for name, _, _ in result] == ["mob"]


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


class TestAmneziawgPlaceholder:
    """SPEC-20261110 WP-3: amneziawg-клиент в links — строка-плейсхолдер
    с путём к .conf (без секретов)."""

    def _awg_state(self) -> GatewayState:
        state = GatewayState()
        state.protocols["amneziawg"] = {
            "installed": True, "port": 51825, "iface": "awg0",
            "public_key": "PUBKEYXYZ", "psk_required": True,
        }
        state.clients = [
            ClientProfile(
                name="mob-awg", protocol="amneziawg", port=51825,
                extra={"conf_path": "/opt/my-vds/gateway/clients/amneziawg/mob-awg.conf",
                       "address": "10.9.0.2/32"},
            ),
        ]
        return state

    def test_placeholder_exact_format(self, state_path: str) -> None:
        _save(self._awg_state(), state_path)
        result = render_all_links(state_path)
        assert result == [
            (
                "mob-awg",
                "amneziawg",
                "amneziawg client 'mob-awg': conf "
                "/opt/my-vds/gateway/clients/amneziawg/mob-awg.conf",
            )
        ]

    def test_filter_protocol_amneziawg(self, state_path: str) -> None:
        _save(self._awg_state(), state_path)
        result = render_all_links(state_path, protocol="amneziawg")
        assert [(n, p) for n, p, _ in result] == [("mob-awg", "amneziawg")]

    def test_golden_xray_hysteria2_output_unchanged_with_awg_present(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Золотой инвариант SPEC WP-3: прежний вывод (phone/mob) не изменился,
        AWG добавляется отдельной строкой-плейсхолдером."""
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        state = _full_state()
        state.clients.append(self._awg_state().clients[0])
        _save(state, state_path)

        result = render_all_links(state_path)
        assert [
            (n, p, l) for n, p, l in result if p != "amneziawg"
        ] == [
            (
                "phone",
                "xray",
                f"vless://{UUID}@{IP}:443?security=reality&sni={SNI}&fp=chrome"
                f"&pbk={PBK}&sid={SID}&flow=xtls-rprx-vision#phone",
            ),
            ("mob", "hysteria2", f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#mob"),
            (
                "xhttp-web",
                "xray",
                f"vless://{UUID_XHTTP}@{DOMAIN}:443"
                f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
                f"&path=/xhttp&type=xhttp#xhttp-web",
            ),
        ]
        assert result[3][2].startswith("amneziawg client 'mob-awg': conf ")

    def test_missing_conf_path_skipped(self, state_path: str) -> None:
        state = self._awg_state()
        state.clients[0].extra.pop("conf_path")
        _save(state, state_path)
        assert render_all_links(state_path) == []

    def test_no_secrets_in_placeholder(self, state_path: str) -> None:
        state = self._awg_state()
        state.clients[0].extra["private_key"] = "FIXTURE_PW_SECRET="
        _save(state, state_path)
        result = render_all_links(state_path)
        assert "FIXTURE_PW_SECRET" not in result[0][2]


class TestCdnLink:
    """SPEC-20261110 WP-3: CDN-клиенты из protocols['xray-cdn']['clients']
    в links — реюз render_cdn_share_link (формат WP-1)."""

    CDN_UUID = "11111111-2222-3333-4444-777777777777"
    CDN_DOMAIN = "cdn.example.com"

    def _cdn_state(self) -> GatewayState:
        state = GatewayState()
        state.protocols["xray-cdn"] = {
            "installed": True,
            "domain": self.CDN_DOMAIN,
            "port": 2053,
            "path": "/ws",
            "client_ids": [self.CDN_UUID],
            "clients": {"phone-cdn": self.CDN_UUID},
        }
        return state

    def test_exact_format(self, state_path: str) -> None:
        _save(self._cdn_state(), state_path)
        result = render_all_links(state_path)
        assert result == [
            (
                "phone-cdn",
                "xray-cdn",
                f"vless://{self.CDN_UUID}@{self.CDN_DOMAIN}:2053"
                f"?encryption=none&security=tls&sni={self.CDN_DOMAIN}"
                f"&type=ws&host={self.CDN_DOMAIN}&path=%2Fws#phone-cdn",
            )
        ]

    def test_filter_protocol_xray_cdn(self, state_path: str) -> None:
        state = self._cdn_state()
        state.protocols["xray-cdn"]["clients"] = {
            "a": self.CDN_UUID,
            "b": "11111111-2222-3333-4444-888888888888",
        }
        _save(state, state_path)
        result = render_all_links(state_path, protocol="xray-cdn")
        assert [(n, p) for n, p, _ in result] == [("a", "xray-cdn"), ("b", "xray-cdn")]

    def test_not_installed_no_lines(self, state_path: str) -> None:
        state = self._cdn_state()
        state.protocols["xray-cdn"]["installed"] = False
        _save(state, state_path)
        assert render_all_links(state_path) == []

    def test_no_clients_no_lines(self, state_path: str) -> None:
        state = self._cdn_state()
        state.protocols["xray-cdn"]["clients"] = {}
        _save(state, state_path)
        assert render_all_links(state_path) == []

    def test_golden_existing_output_unchanged_with_cdn_present(
        self, state_path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Золотой инвариант: прежний вывод (phone/mob/xhttp-web/awg) не
        изменился, CDN-строка добавляется отдельной записью."""
        monkeypatch.setattr("src.core.netcheck.public_ip", lambda: IP)
        state = _full_state()
        state.protocols["xray-cdn"] = self._cdn_state().protocols["xray-cdn"]
        state.clients.append(
            ClientProfile(
                name="mob-awg", protocol="amneziawg", port=51825,
                extra={"conf_path": "/opt/my-vds/gateway/clients/amneziawg/mob-awg.conf"},
            )
        )
        _save(state, state_path)

        result = render_all_links(state_path)
        assert [
            (n, p, l) for n, p, l in result if p != "amneziawg" and p != "xray-cdn"
        ] == [
            (
                "phone",
                "xray",
                f"vless://{UUID}@{IP}:443?security=reality&sni={SNI}&fp=chrome"
                f"&pbk={PBK}&sid={SID}&flow=xtls-rprx-vision#phone",
            ),
            ("mob", "hysteria2", f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#mob"),
            (
                "xhttp-web",
                "xray",
                f"vless://{UUID_XHTTP}@{DOMAIN}:443"
                f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
                f"&path=/xhttp&type=xhttp#xhttp-web",
            ),
        ]
        assert result[3][2].startswith("amneziawg client 'mob-awg': conf ")
        assert result[4][2] == (
            f"vless://{self.CDN_UUID}@{self.CDN_DOMAIN}:2053"
            f"?encryption=none&security=tls&sni={self.CDN_DOMAIN}"
            f"&type=ws&host={self.CDN_DOMAIN}&path=%2Fws#phone-cdn"
        )


class TestEmptyState:
    def test_missing_file_returns_empty(self, tmp_path) -> None:
        assert render_all_links(str(tmp_path / "nope.json")) == []

    def test_empty_clients_returns_empty(self, state_path: str) -> None:
        _save(GatewayState(), state_path)
        assert render_all_links(state_path) == []


class TestCliOutputNoWrap:
    """Blocker D1: `vds gateway links` печатает машиночитаемые строки через
    rich, который переносит их по ширине терминала; клиент парсит построчно.
    Регрессия: каждая запись `name: link` — ровно одна физическая строка."""

    def test_long_link_is_one_physical_line(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        long_link = (
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443"
            "?security=reality&sni=www.google.com&fp=chrome"
            "&pbk=" + "P" * 200 + "&sid=abcd1234&flow=xtls-rprx-vision#phone"
        )
        assert len(long_link) > 200

        def fake_render(state_path: "str | None" = None,
                        protocol: "str | None" = None,
                        include_obfs: bool = False):
            return [("phone", "xray", long_link)]

        monkeypatch.setattr("src.gateway.links.render_all_links", fake_render)

        from src.main import gateway_links  # локальный импорт: CLI-модуль

        gateway_links()
        out = capsys.readouterr().out
        lines = out.splitlines()
        matching = [line for line in lines if line.startswith("phone: ")]
        assert len(matching) == 1
        assert matching[0] == f"phone: {long_link}"  # нет переноса внутри ссылки
