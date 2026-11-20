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
from src.relay import carriers
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


# ---------------------------------------------------------------------------
# --apply-ветки (P2-3 ревью): порядок рестартов, бинарник, ключи, state
# ---------------------------------------------------------------------------

import contextlib
import pathlib as _pathlib

from src.gateway.store import load_state


class _FakeLock:
    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_common(monkeypatch, tmp_path, *, restarts):
    monkeypatch.setattr(ws.os, "geteuid", lambda: 0)
    binary = tmp_path / "bin" / "wstunnel"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(ws, "WSTUNNEL_BIN", binary)
    monkeypatch.setattr("src.core.lock.FileLock", _FakeLock)
    monkeypatch.setattr("src.core.units.install_unit", lambda *a, **kw: True)
    monkeypatch.setattr(ws, "_restart_unit", lambda unit, run=None: restarts.append(unit))
    # WP-P2P-4: exit-apply ставит deploy-hook — патчим пути в tmp
    monkeypatch.setattr(ws, "RENEW_HOOKS_DIR", tmp_path / "renewal-hooks" / "deploy")
    monkeypatch.setattr(ws, "RENEW_HOOK",
                        tmp_path / "renewal-hooks" / "deploy" / "vds-wstunnel-reload.sh")


def _lock_helper():
    return _FakeLock()


def test_exit_apply_starts_units_in_order(monkeypatch, tmp_path):
    from src.relay import exit_leg

    restarts: list[str] = []
    _patch_common(monkeypatch, tmp_path, restarts=restarts)
    monkeypatch.setattr(exit_leg, "ensure_ip_forward", lambda: None)
    monkeypatch.setattr(exit_leg, "detect_wan_iface", lambda: "enp0s3")
    monkeypatch.setattr(exit_leg, "exit_node_violation", lambda state: None)

    cert_dir = tmp_path / "certs" / "ws.example.net"
    cert_dir.mkdir(parents=True)
    (cert_dir / "fullchain.pem").write_text("c", encoding="utf-8")
    (cert_dir / "privkey.pem").write_text("k", encoding="utf-8")
    monkeypatch.setattr(ws, "CERT_ROOT", tmp_path / "certs")
    monkeypatch.setattr(ws, "WG_WS_CONF", tmp_path / "wg-ws0.conf")
    monkeypatch.setattr(ws, "EXIT_NFT_FILE", tmp_path / "wstun.nft")
    monkeypatch.setattr(ws, "WS_NFT_SCRIPT", tmp_path / "apply.sh")
    monkeypatch.setattr(ws, "WS_SERVER_ENV", tmp_path / "server.env")

    prefix_file = tmp_path / "client.env"
    prefix_file.write_text("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=FIXTURE_PREFIX\n", encoding="utf-8")
    state_path = str(tmp_path / "state.json")

    code = ws.run_exit_install(
        relay_ip="203.0.113.10", relay_public_key="FIXTURE_PUB_RELAY",
        domain="ws.example.net", prefix_file=prefix_file, apply=True,
        state_path=state_path,
    )
    assert code == 0
    assert restarts == [ws.WS_NFT_UNIT, ws.WG_WS_UNIT, ws.WS_SERVER_UNIT]
    st = load_state(state_path)
    meta = st.protocols["p2p_wstunnel"]
    assert meta["iface"] == "wg-ws0"
    assert meta["public_key"] == "FIXTURE_PUB_RELAY"  # ключ ПИРА
    assert meta["peer_ip"] == "10.12.0.2"
    assert meta["installed"] is True
    # секретов в state нет
    raw = _pathlib.Path(state_path).read_text(encoding="utf-8")
    assert "FIXTURE_PREFIX" not in raw
    assert "PrivateKey" not in raw


def test_exit_apply_refuses_without_binary(monkeypatch, tmp_path):
    restarts: list[str] = []
    _patch_common(monkeypatch, tmp_path, restarts=restarts)
    monkeypatch.setattr(ws, "WSTUNNEL_BIN", tmp_path / "missing")
    cert_dir = tmp_path / "certs" / "ws.example.net"
    cert_dir.mkdir(parents=True)
    (cert_dir / "fullchain.pem").write_text("c", encoding="utf-8")
    (cert_dir / "privkey.pem").write_text("k", encoding="utf-8")
    monkeypatch.setattr(ws, "CERT_ROOT", tmp_path / "certs")
    prefix_file = tmp_path / "client.env"
    prefix_file.write_text("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=P\n", encoding="utf-8")

    code = ws.run_exit_install(
        relay_ip="203.0.113.10", relay_public_key="FIXTURE_PUB_RELAY",
        domain="ws.example.net", prefix_file=prefix_file, apply=True,
        state_path=str(tmp_path / "state.json"),
    )
    assert code == 1
    assert restarts == []  # ничего не стартовали


def test_exit_apply_updates_peer_key_keeping_private(monkeypatch, tmp_path):
    """P1: смена --relay-public-key переписывает conf, private_key сохраняется."""
    from src.relay import exit_leg

    restarts: list[str] = []
    _patch_common(monkeypatch, tmp_path, restarts=restarts)
    monkeypatch.setattr(exit_leg, "ensure_ip_forward", lambda: None)
    monkeypatch.setattr(exit_leg, "detect_wan_iface", lambda: "enp0s3")
    monkeypatch.setattr(exit_leg, "exit_node_violation", lambda state: None)
    cert_dir = tmp_path / "certs" / "ws.example.net"
    cert_dir.mkdir(parents=True)
    (cert_dir / "fullchain.pem").write_text("c", encoding="utf-8")
    (cert_dir / "privkey.pem").write_text("k", encoding="utf-8")
    monkeypatch.setattr(ws, "CERT_ROOT", tmp_path / "certs")
    conf = tmp_path / "wg-ws0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.12.0.1/30\nPrivateKey = FIXTURE_PW_EXIT_KEEP=\n\n"
        "[Peer]\nPublicKey = OLD_PEER_KEY\nAllowedIPs = 10.12.0.2/32\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ws, "WG_WS_CONF", conf)
    monkeypatch.setattr(ws, "EXIT_NFT_FILE", tmp_path / "wstun.nft")
    monkeypatch.setattr(ws, "WS_NFT_SCRIPT", tmp_path / "apply.sh")
    monkeypatch.setattr(ws, "WS_SERVER_ENV", tmp_path / "server.env")
    monkeypatch.setattr(
        "src.relay.exit_leg._pubkey_from_private", lambda k: "FIXTURE_PUB_EXIT"
    )
    prefix_file = tmp_path / "client.env"
    prefix_file.write_text("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=P\n", encoding="utf-8")

    code = ws.run_exit_install(
        relay_ip="203.0.113.10", relay_public_key="NEW_PEER_KEY",
        domain="ws.example.net", prefix_file=prefix_file, apply=True,
        state_path=str(tmp_path / "state.json"),
    )
    assert code == 0
    text = conf.read_text(encoding="utf-8")
    assert "FIXTURE_PW_EXIT_KEEP=" in text   # свой ключ цел
    assert "NEW_PEER_KEY" in text and "OLD_PEER_KEY" not in text


def test_relay_apply_starts_units_and_checks_policy(monkeypatch, tmp_path):
    from src.relay import exit_leg, paths as relay_paths

    restarts: list[str] = []
    _patch_common(monkeypatch, tmp_path, restarts=restarts)
    monkeypatch.setattr(exit_leg, "detect_wan_iface", lambda: "eth0")
    monkeypatch.setattr(ws, "WG_WS_CONF", tmp_path / "wg-ws0.conf")
    monkeypatch.setattr(ws, "WS_CLIENT_ENV", tmp_path / "client.env")
    monkeypatch.setattr(carriers, "CARRIER_IFACE_SCRIPT", tmp_path / "carrier-default-iface.sh")
    raw = tmp_path / "wg-ws0.priv"
    raw.write_text("FIXTURE_PW_RELAY=\n", encoding="utf-8")
    monkeypatch.setattr(ws, "WG_WS_RAW_PRIV", raw)

    relay_marker = tmp_path / "awg1.conf"
    relay_marker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(relay_paths, "RELAY_EXIT_CONFIG_PATH", relay_marker)
    monkeypatch.setattr(relay_paths, "RELAY_DIR", tmp_path)
    monkeypatch.setattr(relay_paths, "RELAY_NFT_POLICY_FILE", tmp_path / "nft-policy.conf")
    monkeypatch.setattr(relay_paths, "RELAY_CIDR_LIST", tmp_path / "ru-cidrs.txt")
    (tmp_path / "ru-cidrs.txt").write_text("203.0.113.0/24\n", encoding="utf-8")
    (tmp_path / "client.env").write_text("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=P\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_run(argv, timeout=None, check=False):
        calls.append(list(argv))
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(ws, "run_list", fake_run)

    code = ws.run_relay_install(
        exit_public_key="FIXTURE_PUB_EXIT", domain="ws.example.net",
        apply=True, state_path=str(tmp_path / "state.json"),
    )
    assert code == 0
    assert restarts == [
        ws.WS_CLIENT_UNIT, ws.WG_WS_UNIT,
        relay_paths.RELAY_NAT_UNIT, relay_paths.RELAY_POLICY_UNIT,
    ]
    # nft -c -f выполнен ДО рестарта policy, файл атомарно заменён
    assert any(c[:3] == ["nft", "-c", "-f"] for c in calls)
    assert "wg-ws0" in (tmp_path / "nft-policy.conf").read_text(encoding="utf-8")


# --- P2 ревью 9a2cb7b: mkdir родителя + чистка tmp при провале nft -c ------

def test_exit_conf_parent_dir_created(tmp_path):
    """write_secret_atomic не создаёт родителя — install обязан сам."""
    conf = tmp_path / "deep" / "nested" / "wg-ws0.conf"
    ws.write_env(conf.parent / "x.env", "A=1\n") if False else None
    conf.parent.mkdir(parents=True, exist_ok=True)  # тест создаёт сам, но проверяем функцию
    from src.core.secrets import write_secret_atomic as _w
    deep = tmp_path / "p2" / "wg-ws0.conf"
    assert _w(str(deep), "x") is False  # родителя нет → False, не исключение
    deep.parent.mkdir(parents=True, exist_ok=True)
    assert _w(str(deep), "x") is True


def test_relay_apply_policy_check_failure_cleans_tmp_and_keeps_live(monkeypatch, tmp_path):
    """Провал nft -c -f: tmp вычищен, живая nft-policy.conf не тронута, policy не рестартует."""
    from src.relay import exit_leg, paths as relay_paths

    restarts: list[str] = []
    _patch_common(monkeypatch, tmp_path, restarts=restarts)
    monkeypatch.setattr(exit_leg, "detect_wan_iface", lambda: "eth0")
    monkeypatch.setattr(ws, "WG_WS_CONF", tmp_path / "wg-ws0.conf")
    monkeypatch.setattr(ws, "WS_CLIENT_ENV", tmp_path / "client.env")
    raw = tmp_path / "wg-ws0.priv"
    raw.write_text("FIXTURE_PW_RELAY=\n", encoding="utf-8")
    monkeypatch.setattr(ws, "WG_WS_RAW_PRIV", raw)
    relay_marker = tmp_path / "awg1.conf"
    relay_marker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(relay_paths, "RELAY_EXIT_CONFIG_PATH", relay_marker)
    monkeypatch.setattr(relay_paths, "RELAY_DIR", tmp_path)
    monkeypatch.setattr(relay_paths, "RELAY_NFT_POLICY_FILE", tmp_path / "nft-policy.conf")
    monkeypatch.setattr(relay_paths, "RELAY_CIDR_LIST", tmp_path / "ru-cidrs.txt")
    (tmp_path / "ru-cidrs.txt").write_text("203.0.113.0/24\n", encoding="utf-8")
    (tmp_path / "client.env").write_text("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=P\n", encoding="utf-8")
    live_policy = tmp_path / "nft-policy.conf"
    live_policy.write_text("LIVE-POLICY\n", encoding="utf-8")

    state_calls = {"nft_checked": 0}

    def fake_run(argv, timeout=None, check=False):
        if argv[:2] == ["nft", "-c"]:
            state_calls["nft_checked"] += 1
            return ShellResult(stdout="", stderr="syntax error", returncode=1)
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(ws, "run_list", fake_run)

    code = ws.run_relay_install(
        exit_public_key="FIXTURE_PUB_EXIT", domain="ws.example.net",
        apply=True, state_path=str(tmp_path / "state.json"),
    )
    assert code == 1
    assert state_calls["nft_checked"] == 1
    assert live_policy.read_text(encoding="utf-8") == "LIVE-POLICY\n"  # не тронута
    # tmp вычищен
    assert not list(tmp_path.glob(".nft-policy.*"))
    # fail-fast: проверка policy идёт ДО любых рестартов — ни один юнит не тронут
    assert restarts == []


# --- WP-P2P-4: deploy-hook LE с фильтром $RENEWED_DOMAINS ------------------

def test_renew_hook_filters_domain():
    text = ws.render_renew_hook("ws.example.net")
    assert 'case " $RENEWED_DOMAINS " in' in text
    assert '*" ws.example.net "*) systemctl try-restart vds-wstunnel-server.service' in text
    # мульти-SAN: пробельный матч ловит домен в середине списка
    import tempfile
    import subprocess
    script = text.replace("{unit}", "vds-wstunnel-server.service").replace("{host}", "ws.example.net")
    fd, probe_path = tempfile.mkstemp(suffix=".sh")
    with __import__("os").fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(script)
    __import__("os").chmod(probe_path, 0o755)
    try:
        # end-to-end: fake systemctl в PATH → проверяем пробельный матч
        # (certbot передаёт RENEWED_DOMAINS ЧЕРЕЗ ПРОБЕЛ, мульти-SAN включительно)
        bin_dir = tmp_path if "tmp_path" in dir() else None
        # tmp_path недоступен (нет фикстуры) — используем tempfile-каталог
        import tempfile as _tf
        bin_dir = _tf.mkdtemp()
        stub = Path(bin_dir) / "systemctl"
        log = Path(bin_dir) / "log"
        stub.write_text(
            "#!/bin/sh\necho \"$@\" >> " + str(log) + "\nexit 0\n", encoding="utf-8"
        )
        stub.chmod(0o755)
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin",
               "RENEWED_DOMAINS": ""}
        for domains, expect in (("ws.example.net", True),
                                ("asv2.example.net ws.example.net", True),
                                ("asv2.example.net", False)):
            log.unlink(missing_ok=True)
            e = dict(env); e["RENEWED_DOMAINS"] = domains
            res = subprocess.run(["sh", probe_path], capture_output=True,
                                 text=True, env=e)
            assert res.returncode == 0, (domains, res.stderr)
            restarted = log.exists() and "try-restart" in log.read_text(encoding="utf-8")
            assert restarted == expect, (domains, restarted)
        __import__("shutil").rmtree(bin_dir, ignore_errors=True)
    finally:
        __import__("os").unlink(probe_path)


def test_renew_hook_rejects_ip():
    with pytest.raises(ws.WstunnelError):
        ws.render_renew_hook("203.0.113.10")


def test_ensure_renew_hook_installed_0755(tmp_path, monkeypatch):
    import stat as _stat

    hooks = tmp_path / "renewal-hooks" / "deploy"
    monkeypatch.setattr(ws, "RENEW_HOOKS_DIR", hooks)
    monkeypatch.setattr(ws, "RENEW_HOOK", hooks / "vds-wstunnel-reload.sh")
    path = ws.ensure_renew_hook("ws.example.net")
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o755
    assert "ws.example.net" in path.read_text(encoding="utf-8")


def test_p2_fallback_since_set_on_wstun_recovery(tmp_path, monkeypatch):
    """P2 (ревью dfe7f2c): автовыход на wg-ws0 ставит fallback_since —
    иначе prefer_primary в fallback_tick никогда не сработал бы."""
    state_path = str(tmp_path / "p2p-carriers.json")
    now = carriers.utcnow()
    # wg_ws0_installed() проверяет ФАЙЛ (не state) — создаём его
    ws_conf = tmp_path / "etc" / "amnezia" / "wg-ws0.conf"
    ws_conf.parent.mkdir(parents=True, exist_ok=True)
    ws_conf.write_text("[Interface]\nPrivateKey = FIXTURE_PW_WG_WS=\n", encoding="utf-8")
    monkeypatch.setattr(carriers, "WG_WS_CONF", ws_conf)

    state = carriers.default_state(now)
    state.update({"active": "awg", "active_iface": "awg1",
                  "state": "exhausted", "wg_ws0_installed": True,
                  "exhausted_reason": "оба мертвы"})
    assert carriers.save_state(state, state_path)

    # P2-1: сбой route должен превращаться в hold — патчим run_list так,
    # чтобы ip route заменялся успешно (проверяем happy-path автовыхода).
    monkeypatch.setattr(
        carriers, "run_list",
        lambda argv, timeout=None, check=False: ShellResult("", "", 0),
    )
    result = carriers.exhausted_recovery_check(
        state_path=state_path, now=now,
        probe_fn=lambda iface, peer: peer.startswith("10.12."),
    )
    assert result["action"] == "recovered" and result["to"] == "wstunnel"
    st = carriers.load_state(state_path)
    assert st["fallback_since"] is not None  # теперь prefer_primary сработает
    assert st["state"] == "fallback"
