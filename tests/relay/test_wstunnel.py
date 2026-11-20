"""WP-P2P-1: вендоринг wstunnel и рендер контракта (ADR-016, SPEC §2.2).

Без сети и root: проверяются пиннинг, sha256, безопасная распаковка,
argv обеих сторон (секрет не в argv), env-файлы и шаблоны юнитов.
"""
from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from src.core.shell import ShellResult
from src.relay import wstunnel as ws

TEMPLATES = Path(__file__).resolve().parents[2] / "systemd"


def _archive(tmp_path: Path, payload: bytes = b"#!/bin/sh\necho ok\n", name: str = "wstunnel") -> Path:
    path = tmp_path / "wstunnel.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(payload))
    return path


# --- пиннинг -------------------------------------------------------------

def test_version_and_sha_pinned():
    assert ws.WSTUNNEL_VERSION == "11.1.0"
    assert len(ws.WSTUNNEL_SHA256) == 64
    assert all(c in "0123456789abcdef" for c in ws.WSTUNNEL_SHA256)


def test_asset_name_and_url():
    assert ws.asset_name("11.1.0", "amd64") == "wstunnel_11.1.0_linux_amd64.tar.gz"
    assert ws.download_url("11.1.0", "arm64").endswith(
        "/v11.1.0/wstunnel_11.1.0_linux_arm64.tar.gz"
    )


def test_detect_arch_mapping_and_reject():
    assert ws.detect_arch("x86_64") == "amd64"
    assert ws.detect_arch("aarch64") == "arm64"
    with pytest.raises(ws.WstunnelError):
        ws.detect_arch("mips")


# --- sha256 и распаковка -------------------------------------------------

def test_verify_archive_accepts_matching_sha(tmp_path):
    archive = _archive(tmp_path)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    ws.verify_archive(archive, digest)  # не бросает


def test_verify_archive_rejects_mismatch(tmp_path):
    archive = _archive(tmp_path)
    with pytest.raises(ws.WstunnelError, match="sha256"):
        ws.verify_archive(archive, "0" * 64)


def test_extract_binary_installs_executable(tmp_path):
    archive = _archive(tmp_path)
    dest = tmp_path / "bin" / "wstunnel"
    out = ws.extract_binary(archive, dest)
    assert out == dest and dest.is_file()
    assert dest.stat().st_mode & 0o777 == 0o755


def test_extract_binary_rejects_traversal(tmp_path):
    path = tmp_path / "bad.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("../wstunnel")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"bad"))
    with pytest.raises(ws.WstunnelError, match="путь"):
        ws.extract_binary(path, tmp_path / "bin")


def test_extract_binary_requires_member(tmp_path):
    archive = _archive(tmp_path, name="README.md")
    with pytest.raises(ws.WstunnelError, match="нет файла wstunnel"):
        ws.extract_binary(archive, tmp_path / "bin")


# --- argv: секрет не в argv, LE обязателен -------------------------------

def test_server_argv_restricts_forward_to_loopback():
    argv = ws.server_argv(ws_port=9443, wg_port=51821,
                          cert_path="/etc/letsencrypt/live/ws/fullchain.pem",
                          key_path="/etc/letsencrypt/live/ws/privkey.pem")
    assert argv[1] == "server"
    assert "wss://0.0.0.0:9443" in argv
    idx = argv.index("--restrict-to")
    assert argv[idx + 1] == "127.0.0.1:51821"
    assert "--tls-certificate" in argv and "--tls-private-key" in argv


def test_server_argv_requires_tls():
    with pytest.raises(ws.WstunnelError, match="tls-certificate"):
        ws.server_argv(cert_path="", key_path="")


def test_client_argv_uses_hostname_and_udp_forward():
    argv = ws.client_argv(domain="ws.example.net", ws_port=9443,
                          local_udp=51822, wg_port=51821)
    assert argv[1] == "client"
    assert "-L" in argv
    assert "udp://127.0.0.1:51822:127.0.0.1:51821?timeout_sec=0" in argv
    assert "--tls-verify-certificate" in argv
    assert "wss://ws.example.net:9443" in argv
    # target форварда обязан совпадать со --restrict-to сервера строкой
    restrict = ws.server_argv(cert_path="c", key_path="k")
    target = restrict[restrict.index("--restrict-to") + 1]
    assert f"127.0.0.1:51821" == target


def test_client_argv_rejects_ip():
    with pytest.raises(ws.WstunnelError, match="hostname"):
        ws.client_argv(domain="203.0.113.10")


def test_secret_not_in_argv():
    """Path-prefix не должен появляться в argv ни одной стороны."""
    prefix = ws.gen_path_prefix()
    server = " ".join(ws.server_argv(cert_path="c", key_path="k"))
    client = " ".join(ws.client_argv(domain="ws.example.net"))
    assert prefix not in server and prefix not in client
    assert prefix not in ws.render_server_env(prefix).split("=")[0]


# --- env-файлы -----------------------------------------------------------

def test_env_files_use_v11_variable_names():
    prefix = "FIXTURE_PREFIX_ABC"
    assert "WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX=" + prefix in ws.render_server_env(prefix)
    assert "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=" + prefix in ws.render_client_env(prefix)


def test_gen_path_prefix_is_random_and_alpha():
    a, b = ws.gen_path_prefix(), ws.gen_path_prefix()
    assert a != b and len(a) >= 16
    assert a.isalnum()


def test_write_env_is_0600(tmp_path):
    path = tmp_path / "wstunnel.env"
    ws.write_env(path, ws.render_client_env("FIXTURE_PREFIX"))
    assert path.stat().st_mode & 0o777 == 0o600


# --- юниты ---------------------------------------------------------------

def test_server_unit_template_sandbox_and_flags():
    text = (TEMPLATES / "vds-wstunnel-server.service.tpl").read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/vds/wstunnel-server.env" in text
    assert "Restart=always" in text and "RestartSec=5" in text
    assert "StartLimitIntervalSec=0" in text
    assert "ProtectSystem=strict" in text
    # секрет не передаётся флагом: в шаблоне нет -r/--restrict-http-upgrade-path-prefix
    assert "--restrict-http-upgrade-path-prefix" not in text


def test_client_unit_template_uses_wss_and_udp_timeout():
    text = (TEMPLATES / "vds-wstunnel-client.service.tpl").read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/vds/wstunnel-client.env" in text
    assert "timeout_sec=0" in text and "--tls-verify-certificate" in text
    assert "wss://{domain}:{ws_port}" in text
    assert "Restart=always" in text and "StartLimitIntervalSec=0" in text


# --- install/status ------------------------------------------------------

def test_run_install_dry_run_does_not_touch(tmp_path):
    archive = _archive(tmp_path)
    code = ws.run_install(archive=archive, dry_run=True, apply=False)
    assert code == 0
    assert not ws.WSTUNNEL_BIN.exists()


def test_run_install_rejects_bad_sha(tmp_path, monkeypatch):
    archive = _archive(tmp_path)
    monkeypatch.setattr(ws, "WSTUNNEL_SHA256", "0" * 64)
    with pytest.raises(ws.WstunnelError, match="sha256"):
        ws.run_install(archive=archive, dry_run=False, apply=True)


def test_installed_version_parses(monkeypatch, tmp_path):
    fake_bin = tmp_path / "wstunnel"
    fake_bin.write_text("x", encoding="utf-8")
    monkeypatch.setattr(ws, "WSTUNNEL_BIN", fake_bin)

    def run(argv, timeout=None, check=False):
        return ShellResult(stdout="wstunnel 11.1.0\n", stderr="", returncode=0)

    assert ws.installed_version(run) == "11.1.0"


def test_run_status_reports_pin(monkeypatch, tmp_path):
    monkeypatch.setattr(ws, "WSTUNNEL_BIN", tmp_path / "missing")
    monkeypatch.setattr(ws, "WS_SERVER_ENV", tmp_path / "s.env")
    monkeypatch.setattr(ws, "WS_CLIENT_ENV", tmp_path / "c.env")
    status = ws.run_status()
    assert status["pinned_version"] == "11.1.0"
    assert status["installed_version"] is None
    assert status["env_server"] is False and status["env_client"] is False


# --- конфиги wg-ws0 и nft exit-стороны (WP-P2P-2) ------------------------

def test_exit_conf_plain_address_and_keepalive():
    conf = ws.render_exit_conf(
        private_key="FIXTURE_PW_WG_WS_EXIT_PRIV=",
        peer_public_key="FIXTURE_PW_WG_WS_RELAY_PUB=",
    )
    assert "Address = 10.12.0.1/30" in conf
    assert "ListenPort = 51821" in conf
    assert "AllowedIPs = 10.12.0.2/32" in conf
    assert "PersistentKeepalive = 25" in conf
    assert "Jc" not in conf and "H1" not in conf  # plain внутри WSS


def test_relay_conf_table_off_loopback_endpoint_and_mtu():
    conf = ws.render_relay_conf(
        private_key="FIXTURE_PW_WG_WS_RELAY_PRIV=",
        server_public_key="FIXTURE_PW_WG_WS_EXIT_PUB=",
    )
    assert "Address = 10.12.0.2/30" in conf
    assert "Table = off" in conf           # иначе wg-quick снесёт default в main
    assert "MTU = 1240" in conf
    assert "Endpoint = 127.0.0.1:51822" in conf  # порт wstunnel client -L
    assert "PersistentKeepalive = 25" in conf
    assert "Jc" not in conf


def test_relay_conf_requires_keys():
    with pytest.raises(ws.WstunnelError):
        ws.render_relay_conf(private_key="", server_public_key="PUB")


def test_exit_nft_isolation_and_nat():
    text = ws.render_exit_nft(relay_ip="203.0.113.10", wan_iface="enp0s3")
    assert "ip saddr 10.12.0.0/30 oifname \"enp0s3\" masquerade" in text
    assert "ip saddr != 203.0.113.10 tcp dport 9443 drop" in text
    assert 'iifname != "lo" udp dport 51821 drop' in text
    assert "meta nfproto ipv6 tcp dport 9443 drop" in text
    # forward-цепочки нет: на exit DEFAULT_FORWARD_POLICY=ACCEPT (проверено)
    assert "chain forward" not in text
    assert "flush table inet vds_relay_wstun" in text


def test_exit_nft_rejects_bad_ip():
    with pytest.raises(Exception):
        ws.render_exit_nft(relay_ip="not-an-ip", wan_iface="enp0s3")


def test_relay_nat_template_masquerades_client_subnet_to_p2p_iface():
    """P1 ревью: src должен быть {client_subnet}, а не 10.12.0.0/30.

    В wg-ws0 уходят пакеты клиентов (10.10.0.0/24), как и в awg1 рядом;
    подстановочного {p2p_subnet} нет намеренно — перепутать невозможно.
    """
    text = (TEMPLATES / "vds-relay-nat.service.tpl").read_text(encoding="utf-8")
    assert "if [ -n \"{p2p_iface}\" ]" in text
    assert "-s {client_subnet} -o {p2p_iface} -j MASQUERADE" in text
    assert "{p2p_subnet}" not in text


# --- P2 ревью 2026-11-20: архитектуры и строгая проверка hostname ----------

def test_expected_sha256_rejects_unknown_arch():
    with pytest.raises(ws.WstunnelError, match="не поддерживается"):
        ws.expected_sha256("arm64")


def test_expected_sha256_amd64_matches_pin():
    assert ws.expected_sha256("amd64") == ws.WSTUNNEL_SHA256_BY_ARCH["amd64"]


@pytest.mark.parametrize("bad", ["203.0.113.10", "[::1]", "ws.example.net/path", "ws example.net", ""])
def test_client_argv_rejects_non_hostname(bad):
    with pytest.raises(ws.WstunnelError):
        ws.client_argv(domain=bad)


def test_client_argv_accepts_fqdn():
    assert ws.client_argv(domain="ws.example.net")[-1] == "wss://ws.example.net:9443"


# --- WP-P2P-2 ч. 2: init/server/client (dry-run и чистые части) -----------

def test_parse_prefix_env_both_names():
    assert ws.parse_prefix_env("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=abc\n") == "abc"
    assert ws.parse_prefix_env("# c\nWSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX=xyz\n") == "xyz"
    with pytest.raises(ws.WstunnelError):
        ws.parse_prefix_env("TG_BOT_TOKEN=secret\n")


def test_render_nft_script_applies_and_restricts():
    text = ws.render_nft_script("203.0.113.10")
    assert "nft -c -f" in text and "nft -f" in text
    assert "ufw allow from 203.0.113.10 to any port 9443 proto tcp" in text
    assert "set -e" in text


def test_render_nft_script_remove_branch():
    text = ws.render_nft_script("203.0.113.10", remove=True)
    assert "nft delete table inet vds_relay_wstun" in text
    assert "ufw delete allow from 203.0.113.10" in text


def test_gen_keypair_reads_awg(monkeypatch):
    calls = []

    def fake_run(argv, timeout=None, check=False):
        calls.append(list(argv))
        return ShellResult(stdout="FIXTURE_PW_WG_PRIV=\n", stderr="", returncode=0)

    monkeypatch.setattr(ws, "run_list", fake_run)
    monkeypatch.setattr(
        "src.relay.exit_leg._pubkey_from_private", lambda k: "FIXTURE_PUB_FROM_PRIV"
    )
    priv, pub = ws.gen_keypair()
    assert priv == "FIXTURE_PW_WG_PRIV=" and pub == "FIXTURE_PUB_FROM_PRIV"
    assert calls and calls[0][:2] == ["awg", "genkey"]


def test_read_private_key_from_conf_and_raw(tmp_path):
    conf = tmp_path / "conf"
    conf.write_text("[Interface]\nPrivateKey = FIXTURE_PW_K=\n", encoding="utf-8")
    assert ws.read_private_key(conf) == "FIXTURE_PW_K="
    raw = tmp_path / "raw"
    raw.write_text("FIXTURE_PW_RAW=\n", encoding="utf-8")
    assert ws.read_private_key(raw) == "FIXTURE_PW_RAW="
    with pytest.raises(ws.WstunnelError):
        ws.read_private_key(tmp_path / "missing")


def test_run_init_dry_run_prints_public_only(monkeypatch, tmp_path):
    """Dry-run не создаёт файлов и не печатает приватный ключ."""
    monkeypatch.setattr(ws, "WG_WS_RAW_PRIV", tmp_path / "priv")
    monkeypatch.setattr(ws, "WS_CLIENT_ENV", tmp_path / "client.env")
    assert ws.run_init(dry_run=True, apply=False) == 0
    assert not (tmp_path / "priv").exists()


def test_exit_install_rejects_without_prefix_file(capsys):
    code = ws.run_exit_install(
        relay_ip="203.0.113.10", relay_public_key="FIXTURE_PUB_RELAY",
        domain="ws.example.net", prefix_file=None, apply=False,
    )
    assert code == 1
    assert "prefix-file" in capsys.readouterr().out


def test_exit_install_rejects_ip_domain():
    code = ws.run_exit_install(
        relay_ip="203.0.113.10", relay_public_key="FIXTURE_PUB_RELAY",
        domain="203.0.113.10", prefix_file=__import__("pathlib").Path("/dev/null"),
        apply=False,
    )
    assert code == 1
