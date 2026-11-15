"""Тесты чистых рендеров/парсеров RU-relay (SPEC-20261114-ru-relay WP-4).

Фикстуры — по конвенции AGENTS.md §6: FIXTURE_*-префиксы, RFC 5737
(203.0.113.0/24), без правдоподобных секретов.
"""

import pytest

from src.amneziawg.config import ServerParams, validate_obfuscation
from src.relay.config import (
    RelayArgs,
    build_plan,
    handshake_age,
    parse_awg_show,
    render_dnsmasq_proposal,
    render_nft_policy,
    render_policy_rule_args,
    render_relay_server_conf,
    sanitize_exit_conf,
)

SERVER_PRIV = "FIXTURE_PW_RELAY_SERVER_PRIVATE_KEY_0123456789abcdef="
CLIENT_PRIV = "FIXTURE_PW_RELAY_CLIENT_PRIVATE_KEY_0123456789abcdef="
SERVER_PUB = "FIXTURE_PW_RELAY_SERVER_PUBLIC_KEY_0123456789abcdef="

OBF = {
    "Jc": 6, "Jmin": 64, "Jmax": 256, "S1": 88, "S2": 128,
    "H1": 2149340781, "H2": 1934967624, "H3": 1242853139, "H4": 881236702,
}


def _server_params() -> ServerParams:
    return ServerParams(private_key=SERVER_PRIV, address="10.10.0.1/24", port=443, obf=OBF)


class TestRenderServerConf:
    def test_mtu_inserted_after_listenport(self):
        conf = render_relay_server_conf(_server_params(), mtu=1280)
        lines = conf.split("\n")
        assert lines.index("ListenPort = 443") + 1 == lines.index("MTU = 1280")

    def test_subnet_and_port(self):
        conf = render_relay_server_conf(_server_params(), mtu=1280)
        assert "Address = 10.10.0.1/24" in conf
        assert "ListenPort = 443" in conf
        assert "10.9.0.0/24" not in conf

    def test_obf_validation_reused(self):
        with pytest.raises(ValueError):
            render_relay_server_conf(
                ServerParams(private_key=SERVER_PRIV, address="10.10.0.1/24",
                             port=443, obf={**OBF, "H2": OBF["H1"]}),  # дубликат H
                mtu=1280,
            )

    def test_deterministic(self):
        assert render_relay_server_conf(_server_params()) == render_relay_server_conf(_server_params())


class TestSanitizeExitConf:
    BASE = f"""[Interface]
PrivateKey = {CLIENT_PRIV}
Address = 10.9.0.7/32
Jc = 5
Jmin = 40
Jmax = 120
S1 = 20
S2 = 30
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = {SERVER_PUB}
Endpoint = 103.45.247.172:51825
AllowedIPs = 0.0.0.0/0, ::/0

"""

    def test_table_off_and_mtu_added(self):
        out = sanitize_exit_conf(self.BASE, mtu=1420)
        assert "Table = off" in out
        assert "MTU = 1420" in out
        # Table идёт в [Interface] (до [Peer])
        assert out.index("Table = off") < out.index("[Peer]")

    def test_no_duplicate_on_second_pass(self):
        once = sanitize_exit_conf(self.BASE)
        twice = sanitize_exit_conf(once)
        assert twice.count("Table = off") == 1
        assert twice.count("MTU = ") == 1

    def test_existing_table_preserved(self):
        text = self.BASE.replace("Address = 10.9.0.7/32",
                                 "Address = 10.9.0.7/32\nTable = 51820")
        out = sanitize_exit_conf(text)
        assert out.count("Table = ") == 1
        assert "Table = 51820" in out

    def test_broken_conf_rejected(self):
        with pytest.raises(ValueError, match="PrivateKey"):
            sanitize_exit_conf("[Interface]\nAddress = 10.9.0.7/32\n")


class TestNftPolicy:
    def test_structure_and_elements(self):
        text = render_nft_policy(["203.0.113.0/24", "198.51.100.0/24"])
        assert "table inet vds_relay" in text
        assert "set ru_cidr" in text
        assert "203.0.113.0/24" in text and "198.51.100.0/24" in text
        assert 'iifname "awg0" meta mark set 0x1' in text
        assert 'oifname "awg1" ip saddr 10.10.0.0/24 masquerade' in text
        assert 'oifname "eth0" ip saddr 10.10.0.0/24 masquerade' in text

    def test_idempotent_header(self):
        text = render_nft_policy(["203.0.113.0/24"])
        # `table inet vds_relay` до flush: применение файла не падает на
        # отсутствующей таблице (первый запуск).
        assert text.index("table inet vds_relay") < text.index("flush table")

    def test_empty_cidrs(self):
        text = render_nft_policy([])
        assert "elements = {  }" in text

    def test_non_ipv4_skipped(self):
        text = render_nft_policy(["203.0.113.0/24", "2001:db8::/64"])
        assert "203.0.113.0/24" in text
        assert "2001:db8" not in text

    def test_localhost_never_in_set_used_as_direct(self):
        # awg0→10.10.0.0/24 всегда return (до mark) — трафик сервера к клиентам.
        text = render_nft_policy([])
        assert 'iifname "awg0" ip daddr 10.10.0.0/24 return' in text


class TestPolicyRuleArgs:
    def test_args(self):
        args = render_policy_rule_args()
        assert args[0] == ["ip", "rule", "add", "fwmark", "0x1", "table", "100"]
        assert args[1][-2:] == ["table", "100"] and "awg1" in args[1]


class TestDnsmasqProposal:
    def test_scheme(self):
        text = render_dnsmasq_proposal(ru_dns="77.88.8.8", foreign_dns="1.1.1.1", exit_iface="awg1")
        assert "server=/ru/77.88.8.8" in text
        assert "server=/1.1.1.1@awg1" in text
        assert "no-resolv" in text


class TestBuildPlan:
    def _args(self, exit_conf=None) -> RelayArgs:
        return RelayArgs(exit_ip="203.0.113.10", domain="relay.example.ru", sni="www.example.ru", exit_conf=exit_conf)

    def test_step_order_matches_runbook(self):
        plan = build_plan(self._args(), [{"name": "x", "ok": True, "detail": "d"}], exit_conf_ok=False)
        steps = [item["step"] for item in plan]
        assert steps == ["preflight", "awg1-conf", "xray-reality", "awg-server",
                         "ip-forward", "exit-unit", "nat", "policy", "cidr", "state", "verify"]

    def test_plan_without_secrets(self):
        plan = build_plan(self._args(), [{"name": "x", "ok": True, "detail": "d"}], exit_conf_ok=False)
        for item in plan:
            for value in item.values():
                assert "FIXTURE_" not in str(value)

    def test_missing_exit_conf_warns_in_verify(self):
        plan = build_plan(self._args(), [], exit_conf_ok=False)
        verify = next(i for i in plan if i["step"] == "verify")
        assert "awg1-конфиг ещё не перенесён" in verify["detail"]

    def test_exit_conf_path_reflected(self):
        plan = build_plan(self._args(exit_conf="/tmp/awg1.conf"), [], exit_conf_ok=True)
        step = next(i for i in plan if i["step"] == "awg1-conf")
        assert "/tmp/awg1.conf" in step["detail"] and "Table = off" in step["detail"]


class TestParseAwgShow:
    def test_parse(self):
        text = (
            "FIXTURE_UUID_PEER1= 1763100000\n"
            "FIXTURE_UUID_PEER2= 0\n"
            "garbage line\n"
        )
        peers = parse_awg_show(text)
        assert peers["FIXTURE_UUID_PEER1="]["latest_handshake"] == 1763100000
        assert peers["FIXTURE_UUID_PEER2="]["latest_handshake"] == 0
        assert len(peers) == 2

    def test_empty(self):
        assert parse_awg_show("") == {}
        assert parse_awg_show("no numbers here") == {}


class TestHandshakeAge:
    def test_fresh(self):
        assert handshake_age(1000, 1030) == 30

    def test_never(self):
        assert handshake_age(0, 1000) == -1

    def test_no_negative(self):
        assert handshake_age(2000, 1000) == 0


def test_obf_fixture_is_valid_line15():
    validate_obfuscation(OBF)  # фикс-фикстура валидна для линии 1.5 (ADR-005)
