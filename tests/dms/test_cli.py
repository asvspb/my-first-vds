"""Тесты CLI DMS: install/remove/test/status, рендер таймера, маска в --json."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.core.shell import ShellResult
from src.dms import cli as dms_cli
from src.main import app

runner = CliRunner()

FIXTURE_URL = "https://hc-ping.com/FIXTURE_PW_DMS_URL"


class FakeConsole:
    def __init__(self):
        self.lines: list[str] = []

    def print(self, text="", **kwargs):
        self.lines.append(str(text))


@pytest.fixture
def fake_console(monkeypatch):
    fake = FakeConsole()
    monkeypatch.setattr(dms_cli, "console", fake)
    return fake


@pytest.fixture
def no_systemd(monkeypatch):
    """systemctl — no-op (в тестах нет systemd); файлы юнитов пишутся реально."""
    calls: list[list[str]] = []

    def _run(args, **kwargs):
        calls.append(list(args))
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr("src.core.units.run_list", _run)
    monkeypatch.setattr(dms_cli, "run_list", _run)
    return calls


def _unit_file(root: str, name: str) -> Path:
    return Path(root) / "etc" / "systemd" / "system" / name


# --- install ---------------------------------------------------------------

def test_install_dry_run_prints_plan_no_url(fake_console):
    result = runner.invoke(app, ["dms", "install", "--role", "exit"])
    assert result.exit_code == 0
    text = "\n".join(fake_console.lines)
    assert "DRY-RUN" in text
    assert "DMS_PING_URL" in text
    assert FIXTURE_URL not in text


def test_install_dry_run_rejects_bad_role(fake_console):
    result = runner.invoke(app, ["dms", "install", "--role", "banana"])
    assert result.exit_code == 1
    assert any("--role" in line for line in fake_console.lines)


def test_install_apply_writes_env_0600_and_units(fake_console, no_systemd, tmp_path):
    root = str(tmp_path)
    # `root` — тестовый префикс ФС, в CLI наружу не выставляется: зовём cmd напрямую.
    assert dms_cli.cmd_install(apply=True, role="relay", root=root) == 0
    env_path = Path(root) / "etc" / "vds" / "dms.env"
    assert env_path.is_file()
    assert stat.S_IMODE(os.stat(env_path).st_mode) == 0o600
    assert _unit_file(root, dms_cli.DMS_UNIT).is_file()
    assert _unit_file(root, dms_cli.DMS_TIMER).is_file()


def test_timer_rendered_from_template(fake_console, no_systemd, tmp_path):
    root = str(tmp_path)
    assert dms_cli.cmd_install(apply=True, role="exit", root=root) == 0
    timer = _unit_file(root, dms_cli.DMS_TIMER).read_text(encoding="utf-8")
    service = _unit_file(root, dms_cli.DMS_UNIT).read_text(encoding="utf-8")
    # SPEC §5: OnUnitActiveSec=5min, RandomizedDelaySec=20s; [Install] только у таймера.
    assert "OnUnitActiveSec=300s" in timer
    assert "RandomizedDelaySec=20s" in timer
    assert "[Install]" in timer
    assert "[Install]" not in service
    # Sandbox: исходящий HTTPS — AF_INET обязателен (SPEC §10 P2).
    assert "RestrictAddressFamilies=AF_INET" in service
    assert "AF_NETLINK" in service
    # Секрет в юнит не попадает — только путь к env.
    assert "/etc/vds/dms.env" in service
    assert "DMS_PING_URL=" not in service


# --- remove ----------------------------------------------------------------

def test_remove_apply_keeps_env_by_default(fake_console, no_systemd, tmp_path):
    root = str(tmp_path)
    dms_cli.cmd_install(apply=True, role="exit", root=root)
    env_path = Path(root) / "etc" / "vds" / "dms.env"
    assert dms_cli.cmd_remove(apply=True, root=root) == 0
    assert not _unit_file(root, dms_cli.DMS_TIMER).exists()
    assert env_path.is_file()


def test_remove_purge_deletes_env(fake_console, no_systemd, tmp_path):
    root = str(tmp_path)
    dms_cli.cmd_install(apply=True, role="exit", root=root)
    env_path = Path(root) / "etc" / "vds" / "dms.env"
    assert dms_cli.cmd_remove(apply=True, purge=True, root=root) == 0
    assert not env_path.exists()


# --- status ----------------------------------------------------------------

def test_status_json_masks_url(fake_console, no_systemd, tmp_path, monkeypatch):
    root = str(tmp_path)
    dms_cli.cmd_install(apply=True, role="exit", root=root)
    env_path = Path(root) / "etc" / "vds" / "dms.env"
    env_path.write_text(f"DMS_PING_URL={FIXTURE_URL}\nDMS_ROLE=exit\n", encoding="utf-8")

    # root != "/" → systemctl не дёргается; заодно проверяем, что fake_console
    # ловит вывод (он идёт через monkeypatch-нутый console).
    assert dms_cli.cmd_status(json_out=True, root=root) == 0
    payload = json.loads(fake_console.lines[-1])
    assert payload["config"]["url_configured"] is True
    assert payload["config"]["url_masked"] == "***"
    assert payload["config"]["role"] == "exit"
    assert FIXTURE_URL not in json.dumps(payload)
