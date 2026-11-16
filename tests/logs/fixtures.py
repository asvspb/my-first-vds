"""Фикстуры tests/logs (RFC 5737 IP, FIXTURE-префиксы — AGENTS §6).

Только синтетические данные: никаких «правдоподобных» секретов, IP —
203.0.113.0/24 (TEST-NET-3), 198.51.100.0/24, 192.0.2.0/24.
"""
from __future__ import annotations

import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def load_json(name: str) -> object:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


# --- nft -j list table inet vds_probe (per-element counter) ----------------
NFT_JSON = {
    "nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"counter": {"family": "inet", "name": "syn_bare", "packets": 812, "bytes": 32480}},
        {"counter": {"family": "inet", "name": "syn_valid", "packets": 37, "bytes": 5180}},
        {"counter": {"family": "inet", "name": "udp_443", "packets": 10422, "bytes": 9876543}},
        {"set_elem": {"family": "inet", "set": "probers4",
                      "elem": {"val": "203.0.113.7", "timeout": 3600,
                               "counter": {"packets": 19, "bytes": 760}}}},
        {"set_elem": {"family": "inet", "set": "probers4",
                      "elem": {"val": "198.51.100.9", "timeout": 3600,
                               "counter": {"packets": 2, "bytes": 80}}}},
    ]
}

# --- nft без per-element счётчиков (fallback-ядро) --------------------------
NFT_JSON_NO_ELEM_COUNTER = {
    "nftables": [
        {"counter": {"family": "inet", "name": "syn_bare", "packets": 812, "bytes": 32480}},
        {"counter": {"family": "inet", "name": "syn_valid", "packets": 37, "bytes": 5180}},
        {"counter": {"family": "inet", "name": "udp_443", "packets": 10422, "bytes": 9876543}},
        {"set_elem": {"family": "inet", "set": "probers4", "elem": {"val": "203.0.113.7"}}},
    ]
}

# --- ss -Htoi state established '( sport = :443 )' ---------------------------
SS_TEXT = (
    "ESTAB 0      0        203.0.113.5:443        192.0.2.10:51234\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 ato:40 mss:1448 "
    "send 23168000 unacked:1 rcv_space:29200 retrans:0/2\n"
    "ESTAB 0      0        203.0.113.5:443        192.0.2.11:51235\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 ato:40 mss:1448 "
    "send 23168000 timer:(on,3ms,0) retrans:0/0\n"
    "ESTAB 0      0        203.0.113.5:443        192.0.2.12:51236\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 ato:40 mss:1448 "
    "send 23168000 retrans:0/0\n"
    "ESTAB 0      4096     203.0.113.5:443        192.0.2.13:51237\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 mss:1448 send 23168000 retrans:0/0\n"
)

SS_CLEAN_TEXT = (
    "ESTAB 0      0        203.0.113.5:443        192.0.2.10:51234\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 mss:1448 send 23168000 retrans:0/0\n"
    "ESTAB 0      0        203.0.113.5:443        192.0.2.11:51235\n"
    "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 mss:1448 send 23168000 retrans:0/0\n"
)

# --- nstat -asz -------------------------------------------------------------
NSTAT_TEXT = (
    "#kernel\n"
    "IpInDiscards\t0\t0.0\n"
    "TcpRetransSegs\t12\t0.0\n"
    "TcpOutSegs\t98000\t0.0\n"
    "TcpExtTCPTimeouts\t1\t0.0\n"
    "TcpExtListenOverflows\t0\t0.0\n"
    "TcpExtListenDrops\t0\t0.0\n"
    "UdpInErrors\t0\t0.0\n"
    "TcpExtTCPLostRetransmit\t4\t0.0\n"
)

# --- awg show awg0 latest-handshakes ----------------------------------------
AWG_TEXT = (
    "FIXTURE_PUBKEY_AAA11111\t1773888000\n"
    "FIXTURE_PUBKEY_BBB22222\t0\n"
)

# --- journal (для redaction) -------------------------------------------------
XRAY_JOURNAL = (
    "2026-11-16T11:59:58.000000+00:00 asv2 xray[1234]: REALITY: processed invalid connection from 203.0.113.7\n"
    "2026-11-16T11:59:59.000000+00:00 asv2 xray[1234]: privateKey=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 loaded\n"
)
