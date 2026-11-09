"""Рендер config.json с XHTTP (SPEC WP-3, ADR-003).

Золотой снапшот старого рендера байт-в-байт (без xhttp-полей конфиг не
меняется ни на символ) + fallbacks + XHTTP-inbound: детерминизм,
realitySettings не изменился, loopback 127.0.0.1:8443, mode=port.
"""

import json

from src.xray.config import XrayConfigParams, render_config

UUID = "11111111-2222-3333-4444-555555555555"
XUUID = "99999999-8888-7777-6666-555555555555"
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
DOMAIN = "example-103-45-247-172.example.invalid"
CERT = "/etc/letsencrypt/live/" + DOMAIN + "/fullchain.pem"
KEY = "/etc/letsencrypt/live/" + DOMAIN + "/privkey.pem"


def _params(**overrides) -> XrayConfigParams:
    base = dict(
        client_ids=[UUID],
        private_key=PRIVATE_KEY,
        short_ids=[SHORT_ID],
        sni="www.google.com",
        port=443,
    )
    base.update(overrides)
    return XrayConfigParams(**base)


def _xhttp_params(**overrides) -> XrayConfigParams:
    xhttp = dict(
        xhttp_enabled=True,
        domain=DOMAIN,
        cert_path=CERT,
        key_path=KEY,
        xhttp_client_ids=[XUUID],
        xhttp_mode="fallback",
    )
    xhttp.update(overrides)
    return _params(**xhttp)


class TestGoldenSnapshotOldRender:
    """Без xhttp-полей рендер обязан совпадать со старым байт-в-байт (SPEC §4)."""

    def test_snapshot_exact_no_xhttp(self) -> None:
        expected = json.dumps(
            {
                "inbounds": [
                    {
                        "port": 443,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {"id": UUID, "flow": "xtls-rprx-vision"}
                            ],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "dest": "www.google.com:443",
                                "serverNames": ["www.google.com"],
                                "privateKey": PRIVATE_KEY,
                                "shortIds": [SHORT_ID],
                            },
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"
        assert render_config(_params()) == expected

    def test_default_params_still_old_render(self) -> None:
        expected = json.dumps(
            {
                "inbounds": [
                    {
                        "port": 443,
                        "protocol": "vless",
                        "settings": {
                            "clients": [],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "dest": "www.google.com:443",
                                "serverNames": ["www.google.com"],
                                "privateKey": "",
                                "shortIds": [],
                            },
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"
        assert render_config(XrayConfigParams()) == expected


class TestFallbacksRender:
    def test_fallbacks_present_and_exact(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        stream = parsed["inbounds"][0]["streamSettings"]
        assert stream["fallbacks"] == [
            {"alpn": ["http/1.1", "h2"], "dest": "127.0.0.1:8443"}
        ]

    def test_reality_settings_unchanged_with_xhttp(self) -> None:
        without = json.loads(render_config(_params()))
        with_xhttp = json.loads(render_config(_xhttp_params()))
        assert (
            with_xhttp["inbounds"][0]["streamSettings"]["realitySettings"]
            == without["inbounds"][0]["streamSettings"]["realitySettings"]
        )

    def test_reality_clients_unchanged_with_xhttp(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        clients = parsed["inbounds"][0]["settings"]["clients"]
        assert clients == [{"id": UUID, "flow": "xtls-rprx-vision"}]

    def test_two_inbounds_and_outbounds_kept(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        assert len(parsed["inbounds"]) == 2
        assert parsed["outbounds"] == [{"protocol": "freedom"}]


class TestXHTTPInbound:
    def test_internal_loopback_port(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        inbound = parsed["inbounds"][1]
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["port"] == 8443

    def test_network_security_tls_cert_paths(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        stream = parsed["inbounds"][1]["streamSettings"]
        assert stream["network"] == "xhttp"
        assert stream["security"] == "tls"
        cert = stream["tlsSettings"]["certificates"][0]
        assert cert["certificateFile"] == CERT
        assert cert["keyFile"] == KEY

    def test_xhttp_settings_path_fixed_and_deterministic(self) -> None:
        # Дельта WP-3: фиксированный path=/xhttp в xhttpSettings, без
        # параметризации; два рендера — байт-в-байт одинаковы.
        first = render_config(_xhttp_params())
        second = render_config(_xhttp_params())
        assert first == second
        stream = json.loads(first)["inbounds"][1]["streamSettings"]
        assert stream["xhttpSettings"] == {"path": "/xhttp"}

    def test_no_xhttp_settings_without_xhttp(self) -> None:
        parsed = json.loads(render_config(_params()))
        assert "xhttpSettings" not in parsed["inbounds"][0]["streamSettings"]

    def test_xhttp_clients_no_flow_field(self) -> None:
        parsed = json.loads(render_config(_xhttp_params()))
        clients = parsed["inbounds"][1]["settings"]["clients"]
        assert clients == [{"id": XUUID}]
        assert parsed["inbounds"][1]["settings"]["decryption"] == "none"

    def test_multiple_xhttp_clients_order_preserved(self) -> None:
        parsed = json.loads(
            render_config(_xhttp_params(xhttp_client_ids=[XUUID, UUID]))
        )
        ids = [c["id"] for c in parsed["inbounds"][1]["settings"]["clients"]]
        assert ids == [XUUID, UUID]


class TestPortMode:
    """Fallback-план ADR-003: публичный 8443 без SNI-разделения."""

    def test_no_fallbacks_in_port_mode(self) -> None:
        parsed = json.loads(render_config(_xhttp_params(xhttp_mode="port")))
        stream = parsed["inbounds"][0]["streamSettings"]
        assert "fallbacks" not in stream

    def test_no_listen_in_port_mode(self) -> None:
        parsed = json.loads(render_config(_xhttp_params(xhttp_mode="port")))
        inbound = parsed["inbounds"][1]
        assert "listen" not in inbound
        assert inbound["port"] == 8443


class TestDeterminism:
    def test_same_input_same_output(self) -> None:
        assert render_config(_xhttp_params()) == render_config(_xhttp_params())

    def test_valid_json(self) -> None:
        json.loads(render_config(_xhttp_params(xhttp_mode="port")))
