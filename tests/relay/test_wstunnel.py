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
    assert "udp://127.0.0.1:51822:localhost:51821?timeout_sec=0" in argv
    assert "--tls-verify-certificate" in argv
    assert "wss://ws.example.net:9443" in argv


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
