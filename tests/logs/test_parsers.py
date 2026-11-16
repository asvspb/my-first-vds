"""Тесты парсеров источников logs-collect (без root/сети, фикстуры RFC 5737)."""
from __future__ import annotations

from tests.logs import fixtures as fx
from src.logs.collect import parse_awg_handshakes, parse_nft_json, parse_nstat, parse_ss


class TestParseNftJson:
    def test_counters_and_probers(self):
        state = parse_nft_json(fx.NFT_JSON)
        assert state is not None
        assert state.syn_bare == 812
        assert state.syn_valid == 37
        assert state.udp_443 == 10422
        assert state.probers == {"203.0.113.7": 19, "198.51.100.9": 2}

    def test_per_element_flag(self):
        state = parse_nft_json(fx.NFT_JSON)
        assert state.per_element_counters is True
        fallback = parse_nft_json(fx.NFT_JSON_NO_ELEM_COUNTER)
        assert fallback.per_element_counters is False
        assert fallback.probers == {"203.0.113.7": 0}

    def test_broken_json_returns_none(self):
        assert parse_nft_json(None) is None
        assert parse_nft_json({}) is None
        assert parse_nft_json({"nftables": "garbage"}) is None


class TestParseSs:
    def test_estab_and_zombie_count(self):
        # 4 ESTAB: (1) retrans:0/2>0 zombie, (2) timer:(on,..) zombie,
        # (3) чистый, (4) Send-Q>0 zombie
        out = parse_ss(fx.SS_TEXT)
        assert out["estab_443"] == 4
        assert out["zombie_443"] == 3

    def test_clean_sockets_zero_zombies(self):
        out = parse_ss(fx.SS_CLEAN_TEXT)
        assert out["estab_443"] == 2
        assert out["zombie_443"] == 0


class TestParseNstat:
    def test_known_keys(self):
        out = parse_nstat(fx.NSTAT_TEXT)
        assert out["TcpExtTCPTimeouts"] == 1
        assert out["TcpRetransSegs"] == 12
        assert out["UdpInErrors"] == 0
        assert "TcpExtTCPLostRetransmit" not in out  # вне NSTAT_KEYS

    def test_missing_keys_absent(self):
        out = parse_nstat("TcpExtTCPTimeouts\t5\t0.0\n")
        assert out == {"TcpExtTCPTimeouts": 5}
        assert "TcpRetransSegs" not in out


class TestParseAwgHandshakes:
    def test_fresh_peer_count(self):
        # FIXTURE_PUBKEY_AAA11111: epoch = now - 60 (fresh); BBB: 0 (нет HS)
        import time

        now = int(time.time())
        text = f"FIXTURE_PUBKEY_AAA11111\t{now - 60}\nFIXTURE_PUBKEY_BBB22222\t0\n"
        out = parse_awg_handshakes(text, now_epoch=now)
        assert out == {"peers_total": 2, "peers_fresh_lt180s": 1}

    def test_stale_peer_not_fresh(self):
        import time

        now = int(time.time())
        text = f"FIXTURE_PUBKEY_AAA11111\t{now - 600}\n"
        out = parse_awg_handshakes(text, now_epoch=now)
        assert out["peers_fresh_lt180s"] == 0
        assert out["peers_total"] == 1

    def test_garbage_lines_skipped(self):
        out = parse_awg_handshakes("garbage\n\ninterface: awg0\n", now_epoch=1)
        assert out["peers_total"] == 0
