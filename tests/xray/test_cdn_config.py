"""Рендер config.json с CDN-инблэндом (SPEC-20261110 WP-1, ADR-006).

Золотой снапшот старого рендера байт-в-байт (без cdn-полей конфиг не
меняется ни на символ) + CDN-инблэнд vless+ws+tls на 2053: детерминизм,
Reality и XHTTP не изменились, LE-cert пути, share-link формат.
"""

import json
from urllib.parse import unquote

from src.gateway.paths import (
    ACME_LETSENCRYPT_LIVE,
    CDN_DOMAIN_HINT,
    CDN_ORIGIN_PORT_DEFAULT,
    CDN_WS_PATH,
)
from src.xray.config import (
    XrayConfigParams,
    render_cdn_share_link,
    render_config,
)

UUID = "11111111-2222-3333-4444-555555555555"
XUUID = "99999999-8888-7777-6666-555555555555"
CDN_UUID = "11111111-2222-3333-4444-666666666666"
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
DOMAIN = "example-103-45-247-172.example.invalid"
CDN_DOMAIN = "cdn.eu-cloud-xip.com"
CDN_CERT = str(ACME_LETSENCRYPT_LIVE(CDN_DOMAIN) / "fullchain.pem")
CDN_KEY = str(ACME_LETSENCRYPT_LIVE(CDN_DOMAIN) / "privkey.pem")


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


def _cdn_params(**overrides) -> XrayConfigParams:
    cdn = dict(
        cdn_enabled=True,
        cdn_domain=CDN_DOMAIN,
        cdn_client_ids=[CDN_UUID],
        cdn_cert_path=CDN_CERT,
        cdn_key_path=CDN_KEY,
    )
    cdn.update(overrides)
    return _params(**cdn)


class TestGoldenSnapshotNoCdn:
    """Без cdn-полей рендер обязан совпадать с прежним байт-в-байт (SPEC §4)."""

    def test_snapshot_exact_no_cdn(self) -> None:
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


class TestCdnInbound:
    def test_third_inbound_appended(self) -> None:
        parsed = json.loads(render_config(_cdn_params()))
        assert len(parsed["inbounds"]) == 2
        with_xhttp = json.loads(
            render_config(
                _cdn_params(
                    xhttp_enabled=True,
                    domain=DOMAIN,
                    cert_path="/etc/letsencrypt/live/x/fullchain.pem",
                    key_path="/etc/letsencrypt/live/x/privkey.pem",
                    xhttp_client_ids=[XUUID],
                    xhttp_mode="port",
                )
            )
        )
        assert len(with_xhttp["inbounds"]) == 3

    def test_port_listen_all_interfaces(self) -> None:
        parsed = json.loads(render_config(_cdn_params()))
        inbound = parsed["inbounds"][1]
        assert inbound["port"] == CDN_ORIGIN_PORT_DEFAULT == 2053
        assert "listen" not in inbound

    def test_ws_settings(self) -> None:
        stream = json.loads(render_config(_cdn_params()))["inbounds"][1][
            "streamSettings"
        ]
        assert stream["network"] == "ws"
        assert stream["wsSettings"]["path"] == CDN_WS_PATH == "/cdnws"
        assert stream["wsSettings"]["headers"] == {"Host": CDN_DOMAIN}

    def test_tls_le_cert_paths(self) -> None:
        stream = json.loads(render_config(_cdn_params()))["inbounds"][1][
            "streamSettings"
        ]
        assert stream["security"] == "tls"
        cert = stream["tlsSettings"]["certificates"][0]
        assert cert["certificateFile"] == CDN_CERT
        assert cert["keyFile"] == CDN_KEY
        assert "/etc/letsencrypt/live/" + CDN_DOMAIN in cert["certificateFile"]

    def test_cdn_clients_no_flow(self) -> None:
        inbound = json.loads(render_config(_cdn_params()))["inbounds"][1]
        assert inbound["settings"]["clients"] == [{"id": CDN_UUID}]
        assert inbound["settings"]["decryption"] == "none"

    def test_multiple_cdn_clients_order_preserved(self) -> None:
        parsed = json.loads(
            render_config(_cdn_params(cdn_client_ids=[CDN_UUID, XUUID]))
        )
        ids = [c["id"] for c in parsed["inbounds"][1]["settings"]["clients"]]
        assert ids == [CDN_UUID, XUUID]

    def test_custom_port_and_path(self) -> None:
        parsed = json.loads(
            render_config(_cdn_params(cdn_port=8443, cdn_ws_path="/altws"))
        )
        inbound = parsed["inbounds"][1]
        assert inbound["port"] == 8443
        assert inbound["streamSettings"]["wsSettings"]["path"] == "/altws"


class TestCdnIsolation:
    """Reality и существующие каналы CDN-кодом не трогаются (SPEC §4.1)."""

    def test_reality_settings_unchanged_with_cdn(self) -> None:
        without = json.loads(render_config(_params()))
        with_cdn = json.loads(render_config(_cdn_params()))
        base = with_cdn["inbounds"][0]
        assert base == without["inbounds"][0]

    def test_no_cdn_keys_without_cdn(self) -> None:
        parsed = json.loads(render_config(_params()))
        stream = parsed["inbounds"][0]["streamSettings"]
        assert "wsSettings" not in stream
        assert stream["security"] == "reality"

    def test_reality_private_key_not_in_cdn_inbound(self) -> None:
        parsed = json.loads(render_config(_cdn_params()))
        cdn_inbound = parsed["inbounds"][1]
        cdn_json = json.dumps(cdn_inbound)
        assert PRIVATE_KEY not in cdn_json

    def test_outbounds_unchanged(self) -> None:
        parsed = json.loads(render_config(_cdn_params()))
        assert parsed["outbounds"] == [{"protocol": "freedom"}]


class TestDeterminism:
    def test_same_input_same_output(self) -> None:
        assert render_config(_cdn_params()) == render_config(_cdn_params())

    def test_valid_json(self) -> None:
        json.loads(render_config(_cdn_params()))


FRONT_1_CERT = "/etc/letsencrypt/live/cdn1.example.invalid/fullchain.pem"
FRONT_1_KEY = "/etc/letsencrypt/live/cdn1.example.invalid/privkey.pem"
FRONT_2_CERT = "/etc/letsencrypt/live/cdn2.example.invalid/fullchain.pem"
FRONT_2_KEY = "/etc/letsencrypt/live/cdn2.example.invalid/privkey.pem"


class TestCdnExtraCerts:
    """Пул фронтов (SPEC-20261112 WP-2): multi-cert CDN-инблэнд; без extra —
    рендер байт-в-байт прежний (golden-регресс)."""

    def test_two_fronts_three_certificates_deterministic_order(self) -> None:
        parsed = json.loads(
            render_config(
                _cdn_params(
                    cdn_extra_certs=[
                        (FRONT_1_CERT, FRONT_1_KEY),
                        (FRONT_2_CERT, FRONT_2_KEY),
                    ]
                )
            )
        )
        certs = parsed["inbounds"][1]["streamSettings"]["tlsSettings"]["certificates"]
        assert certs == [
            {"certificateFile": CDN_CERT, "keyFile": CDN_KEY},
            {"certificateFile": FRONT_1_CERT, "keyFile": FRONT_1_KEY},
            {"certificateFile": FRONT_2_CERT, "keyFile": FRONT_2_KEY},
        ]

    def test_without_extra_byte_identical_to_legacy(self) -> None:
        assert (
            render_config(_cdn_params())
            == render_config(_cdn_params(cdn_extra_certs=[]))
        )
        parsed = json.loads(render_config(_cdn_params()))
        certs = parsed["inbounds"][1]["streamSettings"]["tlsSettings"]["certificates"]
        assert certs == [{"certificateFile": CDN_CERT, "keyFile": CDN_KEY}]

    def test_default_params_no_extra(self) -> None:
        assert XrayConfigParams().cdn_extra_certs == []

    def test_extra_certs_do_not_touch_reality(self) -> None:
        without = json.loads(render_config(_params()))
        with_extra = json.loads(
            render_config(
                _cdn_params(cdn_extra_certs=[(FRONT_1_CERT, FRONT_1_KEY)])
            )
        )
        assert with_extra["inbounds"][0] == without["inbounds"][0]


class TestCdnPathsConstants:
    def test_defaults(self) -> None:
        assert CDN_ORIGIN_PORT_DEFAULT == 2053
        assert CDN_WS_PATH == "/cdnws"
        assert CDN_DOMAIN_HINT == "cdn."

    def test_cdn_params_defaults(self) -> None:
        params = XrayConfigParams()
        assert params.cdn_enabled is False
        assert params.cdn_port == 2053
        assert params.cdn_ws_path == "/cdnws"


class TestCdnShareLink:
    def test_format_exact(self) -> None:
        link = render_cdn_share_link(CDN_UUID, CDN_DOMAIN, 2053, "/cdnws", "phone")
        assert link == (
            f"vless://{CDN_UUID}@{CDN_DOMAIN}:2053"
            f"?encryption=none&security=tls&sni={CDN_DOMAIN}"
            f"&type=ws&host={CDN_DOMAIN}&path=%2Fcdnws#phone"
        )

    def test_path_percent_encoded_and_decodable(self) -> None:
        link = render_cdn_share_link(CDN_UUID, CDN_DOMAIN, 2053, "/cdnws", "mob")
        raw_path = link.split("path=")[1].split("#")[0]
        assert unquote(raw_path) == "/cdnws"

    def test_custom_port(self) -> None:
        link = render_cdn_share_link(CDN_UUID, CDN_DOMAIN, 8443, "/cdnws", "x")
        assert f"@{CDN_DOMAIN}:8443?" in link
