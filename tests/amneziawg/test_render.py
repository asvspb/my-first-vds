"""Снапшот-тесты рендера awg-quick .conf (SPEC §3, AGENTS.md §6 — фикс-фикстуры)."""

import random

import pytest

from src.amneziawg.config import (
    ClientParams,
    ServerParams,
    ServerPeer,
    gen_obfuscation_params,
    render_client_conf,
    render_server_conf,
    validate_obfuscation,
)

# Фикстуры по конвенции AGENTS.md §6 (RFC 5737, FIXTURE_*-префиксы).
SERVER_PRIV = "FIXTURE_PW_AWG_SERVER_PRIVATE_KEY_0123456789abcdef="
CLIENT_PRIV = "FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY_0123456789abcdef="
SERVER_PUB = "FIXTURE_PW_AWG_SERVER_PUBLIC_KEY_0123456789abcdef="
CLIENT_PUB = "FIXTURE_PW_AWG_CLIENT_PUBLIC_KEY_0123456789abcdef="
PSK = "FIXTURE_PW_AWG_PRESHARED_KEY_0123456789abcdef0123456789abcdef012="

OBF = {
    "Jc": 6, "Jmin": 64, "Jmax": 256, "S1": 88, "S2": 128,
    "H1": 2149340781, "H2": 1934967624, "H3": 1242853139, "H4": 881236702,
}
CLIENT_JUNK = {"Jc": 4, "Jmin": 32, "Jmax": 120}

EXPECTED_SERVER = """\
[Interface]
Address = 10.9.0.1/24
ListenPort = 51825
PrivateKey = FIXTURE_PW_AWG_SERVER_PRIVATE_KEY_0123456789abcdef=
SaveConfig = false
Jc = 6
Jmin = 64
Jmax = 256
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702

[Peer]
# mob-awg
PublicKey = FIXTURE_PW_AWG_CLIENT_PUBLIC_KEY_0123456789abcdef=
PresharedKey = FIXTURE_PW_AWG_PRESHARED_KEY_0123456789abcdef0123456789abcdef012=
AllowedIPs = 10.9.0.2/32
"""

EXPECTED_SERVER_NO_PSK = """\
[Interface]
Address = 10.9.0.1/24
ListenPort = 51825
PrivateKey = FIXTURE_PW_AWG_SERVER_PRIVATE_KEY_0123456789abcdef=
SaveConfig = false
Jc = 6
Jmin = 64
Jmax = 256
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702

[Peer]
# mob-awg
PublicKey = FIXTURE_PW_AWG_CLIENT_PUBLIC_KEY_0123456789abcdef=
AllowedIPs = 10.9.0.2/32
"""

EXPECTED_CLIENT = """\
[Interface]
PrivateKey = FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY_0123456789abcdef=
Address = 10.9.0.2/32
Jc = 4
Jmin = 32
Jmax = 120
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702

[Peer]
PublicKey = FIXTURE_PW_AWG_SERVER_PUBLIC_KEY_0123456789abcdef=
PresharedKey = FIXTURE_PW_AWG_PRESHARED_KEY_0123456789abcdef0123456789abcdef012=
Endpoint = 203.0.113.10:51825
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
"""

EXPECTED_CLIENT_NO_PSK = """\
[Interface]
PrivateKey = FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY_0123456789abcdef=
Address = 10.9.0.2/32
Jc = 4
Jmin = 32
Jmax = 120
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702

[Peer]
PublicKey = FIXTURE_PW_AWG_SERVER_PUBLIC_KEY_0123456789abcdef=
Endpoint = 203.0.113.10:51825
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
"""


def _server(peers: tuple = ()) -> ServerParams:
    return ServerParams(
        private_key=SERVER_PRIV, obf=OBF, peers=peers,
    )


def _client(**overrides) -> ClientParams:
    base = dict(
        private_key=CLIENT_PRIV,
        address="10.9.0.2/32",
        server_pubkey=SERVER_PUB,
        endpoint="203.0.113.10:51825",
        junk=CLIENT_JUNK,
        obf=OBF,
        psk=PSK,
    )
    base.update(overrides)
    return ClientParams(**base)


class TestServerRenderSnapshot:
    def test_snapshot_with_peer_and_psk(self) -> None:
        peer = ServerPeer(
            public_key=CLIENT_PUB, allowed_ips="10.9.0.2/32", psk=PSK, name="mob-awg",
        )
        assert render_server_conf(_server((peer,))) == EXPECTED_SERVER

    def test_snapshot_no_psk_semantics(self) -> None:
        peer = ServerPeer(
            public_key=CLIENT_PUB, allowed_ips="10.9.0.2/32", psk=None, name="mob-awg",
        )
        assert render_server_conf(_server((peer,))) == EXPECTED_SERVER_NO_PSK

    def test_determinism(self) -> None:
        peer = ServerPeer(public_key=CLIENT_PUB, allowed_ips="10.9.0.2/32", psk=PSK)
        conf = render_server_conf(_server((peer,)))
        assert conf == render_server_conf(_server((peer,)))


class TestClientRenderSnapshot:
    def test_snapshot_with_psk(self) -> None:
        assert render_client_conf(_client()) == EXPECTED_CLIENT

    def test_snapshot_no_psk(self) -> None:
        assert render_client_conf(_client(psk=None)) == EXPECTED_CLIENT_NO_PSK

    def test_determinism(self) -> None:
        assert render_client_conf(_client()) == render_client_conf(_client())

    def test_client_uses_server_s_h_and_own_junk(self) -> None:
        conf = render_client_conf(_client())
        assert "S1 = 88" in conf and "S2 = 128" in conf  # серверные S
        assert "H1 = 2149340781" in conf  # серверные H
        assert "Jc = 4" in conf and "Jmax = 120" in conf  # клиентские J

    def test_generated_params_render_deterministically(self) -> None:
        obf = gen_obfuscation_params(random.Random(42))
        junk = {"Jc": obf["Jc"], "Jmin": obf["Jmin"], "Jmax": obf["Jmax"]}
        validate_obfuscation(obf)
        conf = render_client_conf(_client(obf=obf, junk=junk))
        assert conf == render_client_conf(_client(obf=obf, junk=junk))


class TestRenderValidation:
    def test_server_render_rejects_awg_20(self) -> None:
        obf = dict(OBF)
        obf["S3"] = 12
        with pytest.raises(ValueError, match="ADR-005: линия 1.5"):
            render_server_conf(ServerParams(private_key=SERVER_PRIV, obf=obf))

    def test_server_render_rejects_duplicate_h(self) -> None:
        obf = dict(OBF)
        obf["H4"] = obf["H1"]
        with pytest.raises(ValueError, match="H4"):
            render_server_conf(ServerParams(private_key=SERVER_PRIV, obf=obf))

    def test_client_render_rejects_bad_junk(self) -> None:
        junk = {"Jc": 4, "Jmin": 200, "Jmax": 120}  # Jmin >= Jmax
        with pytest.raises(ValueError, match="Jmin.*меньше Jmax"):
            render_client_conf(_client(junk=junk))
