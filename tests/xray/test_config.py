"""Снапшот-тесты рендера config.json (SPEC §3, VPN-PROTOCOLS §2.1)."""

import json

from src.xray.config import FLOW, XrayConfigParams, render_config

UUID = "11111111-2222-3333-4444-555555555555"
PRIVATE_KEY = "PRIVATEKEY123"
SHORT_ID = "abcd1234"


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


class TestRenderConfigSnapshot:
    def test_snapshot_exact(self) -> None:
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

    def test_valid_json_roundtrip(self) -> None:
        parsed = json.loads(render_config(_params()))
        inbound = parsed["inbounds"][0]
        assert inbound["streamSettings"]["security"] == "reality"
        assert inbound["settings"]["clients"][0]["flow"] == FLOW
        assert FLOW == "xtls-rprx-vision"

    def test_empty_clients_on_fresh_install(self) -> None:
        parsed = json.loads(render_config(_params(client_ids=[])))
        assert parsed["inbounds"][0]["settings"]["clients"] == []

    def test_custom_sni_reaches_dest_and_server_names(self) -> None:
        parsed = json.loads(render_config(_params(sni="example.org")))
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["dest"] == "example.org:443"
        assert reality["serverNames"] == ["example.org"]


class TestDeterminism:
    def test_same_input_same_output(self) -> None:
        assert render_config(_params()) == render_config(_params())

    def test_multiple_clients_order_preserved(self) -> None:
        two = render_config(_params(client_ids=[UUID, "99999999-8888-7777-6666-555555555555"]))
        parsed = json.loads(two)
        ids = [c["id"] for c in parsed["inbounds"][0]["settings"]["clients"]]
        assert ids == [UUID, "99999999-8888-7777-6666-555555555555"]

    def test_defaults(self) -> None:
        params = XrayConfigParams()
        assert params.sni == "www.google.com"
        assert params.port == 443
