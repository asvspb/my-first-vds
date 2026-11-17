"""Тесты CLI сторожа, юнитов и идемпотентности (SPEC §3.4, §6).

`root` = tmp-префикс ФС: файлы пишутся в `<root>/etc/...`, `systemctl`
замокан (ни root, ни реального systemd не нужно).
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.alert import cli as alert_cli
from src.core.shell import ShellResult

runner = CliRunner()

TG_TOKEN = "FIXTURE_TG_BOT_TOKEN"
SMTP_PASS = "FIXTURE_PW_SMTP"


class FakeConsole:
    def __init__(self):
        self.lines: list[str] = []

    def print(self, text="", **kwargs):
        self.lines.append(str(text))


@pytest.fixture
def fake_console(monkeypatch):
    fake = FakeConsole()
    monkeypatch.setattr(alert_cli, "console", fake)
    return fake


@pytest.fixture
def no_systemd(monkeypatch):
    """systemctl — no-op (в тестах нет systemd); файлы юнитов пишутся реально."""
    calls: list[list[str]] = []

    def _run(args, **kwargs):
        calls.append(list(args))
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr("src.core.units.run_list", _run)
    monkeypatch.setattr(alert_cli, "run_list", _run)
    return calls


@pytest.fixture
def gateway_state(tmp_path, monkeypatch):
    """state.json по умолчанию — пустой exit-узел (не релей)."""
    path = tmp_path / "gateway-state.json"
    path.write_text(
        json.dumps({"version": 1, "clients": [], "protocols": {}, "ufw_lockdown": {}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", path)
    return path


def _env_file(root: Path) -> Path:
    return root / "etc" / "vds" / "alert.env"


def test_install_dry_run_plan_has_key_names_and_no_values(tmp_path, gateway_state, fake_console):
    code = alert_cli.cmd_install(root=str(tmp_path))
    text = "\n".join(fake_console.lines)

    assert code == 0
    assert "DRY-RUN" in text
    assert "vds-alert-watch.service" in text and "vds-alert-watch.timer" in text
    assert "SMTP_HOST" in text and "TG_BOT_TOKEN" in text
    assert TG_TOKEN not in text and SMTP_PASS not in text
    assert not _env_file(tmp_path).exists()
    assert not (tmp_path / "etc" / "systemd" / "system").exists()


def test_install_apply_creates_units_and_env_0600(tmp_path, gateway_state, no_systemd):
    code = alert_cli.cmd_install(apply=True, root=str(tmp_path))
    assert code == 0

    unit_dir = tmp_path / "etc" / "systemd" / "system"
    assert (unit_dir / "vds-alert-watch.service").is_file()
    assert (unit_dir / "vds-alert-watch.timer").is_file()
    service = (unit_dir / "vds-alert-watch.service").read_text(encoding="utf-8")
    assert "alert watch --config /etc/vds/alert.env" in service
    assert "EnvironmentFile" not in service  # секреты не в Environment

    env_path = _env_file(tmp_path)
    assert env_path.is_file()
    assert stat.S_IMODE(os.stat(env_path).st_mode) == 0o600
    assert ["systemctl", "start", "vds-alert-watch.timer"] in no_systemd


def test_install_apply_is_idempotent_for_env(tmp_path, gateway_state, no_systemd):
    assert alert_cli.cmd_install(apply=True, root=str(tmp_path)) == 0
    env_path = _env_file(tmp_path)
    env_path.write_text("SMTP_HOST=smtp.example.com\n", encoding="utf-8")
    before = env_path.read_text(encoding="utf-8")

    assert alert_cli.cmd_install(apply=True, root=str(tmp_path)) == 0
    assert env_path.read_text(encoding="utf-8") == before


def test_install_force_rewrites_env(tmp_path, gateway_state, no_systemd):
    assert alert_cli.cmd_install(apply=True, root=str(tmp_path)) == 0
    env_path = _env_file(tmp_path)
    env_path.write_text("SMTP_HOST=custom\n", encoding="utf-8")

    assert alert_cli.cmd_install(apply=True, force=True, root=str(tmp_path)) == 0
    assert "SMTP_HOST=custom" not in env_path.read_text(encoding="utf-8")


def test_install_refused_on_relay_node(tmp_path, no_systemd, fake_console, monkeypatch):
    path = tmp_path / "gateway-state.json"
    path.write_text(
        json.dumps({"version": 1, "clients": [], "protocols": {"relay": {"exit": "203.0.113.1"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", path)

    code = alert_cli.cmd_install(apply=True, root=str(tmp_path))
    assert code == 1
    assert not _env_file(tmp_path).exists()
    assert any("запрещён" in line for line in fake_console.lines)


def test_install_allow_relay_node_warns_but_proceeds(tmp_path, gateway_state, no_systemd, fake_console, monkeypatch):
    path = tmp_path / "gateway-state.json"
    path.write_text(
        json.dumps({"version": 1, "clients": [], "protocols": {"relay": {}}}), encoding="utf-8"
    )
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", path)

    assert alert_cli.cmd_install(apply=True, allow_relay_node=True, root=str(tmp_path)) == 0
    assert any("--allow-relay-node" in line for line in fake_console.lines)


def test_install_rejects_bad_duration(tmp_path, gateway_state, fake_console):
    assert alert_cli.cmd_install(interval="2x", root=str(tmp_path)) == 1
    assert any("формат" in line for line in fake_console.lines)


def test_remove_keeps_env_and_purge_deletes(tmp_path, gateway_state, no_systemd, fake_console):
    assert alert_cli.cmd_install(apply=True, root=str(tmp_path)) == 0
    env_path = _env_file(tmp_path)
    state_path = tmp_path / "var" / "lib" / "vds" / "alert-state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("{}", encoding="utf-8")

    assert alert_cli.cmd_remove(apply=True, root=str(tmp_path)) == 0
    assert env_path.is_file()
    assert not (tmp_path / "etc" / "systemd" / "system" / "vds-alert-watch.service").exists()

    assert alert_cli.cmd_remove(apply=True, purge=True, root=str(tmp_path)) == 0
    assert not env_path.exists()
    assert not state_path.exists()


def test_remove_dry_run_writes_nothing(tmp_path, gateway_state, fake_console):
    assert alert_cli.cmd_remove(root=str(tmp_path)) == 0
    assert not (tmp_path / "etc").exists()


def test_status_json_schema_without_secrets(tmp_path, gateway_state, fake_console):
    env_path = _env_file(tmp_path)
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "\n".join(
            [
                f"TG_BOT_TOKEN={TG_TOKEN}",
                "TG_CHAT_ID=111111111",
                "SMTP_HOST=smtp.example.com",
                "SMTP_FROM=alert-test@example.com",
                "SMTP_TO=owner@example.com",
                f"SMTP_PASS={SMTP_PASS}",
                "ALERT_CHECKS=threat",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert alert_cli.cmd_status(json_out=True, root=str(tmp_path)) == 0
    payload = json.loads(fake_console.lines[-1])
    assert payload["config"]["channels"] == ["tg", "smtp"]
    assert payload["config"]["present"] is True
    assert payload["coverage"]["threat"]["status"] in {"missing", "corrupt", "no_level", "stale", "ok"}
    assert "state" in payload and "units" in payload

    rendered = json.dumps(payload, ensure_ascii=False)
    assert TG_TOKEN not in rendered and SMTP_PASS not in rendered


def test_status_without_config_is_graceful(tmp_path, gateway_state, fake_console):
    assert alert_cli.cmd_status(root=str(tmp_path)) == 0
    text = "\n".join(fake_console.lines)
    assert "конфиг" in text
    assert "не настроены" in text or "нет активных" in text


def test_status_unreadable_env_is_truncated(tmp_path, gateway_state, fake_console, monkeypatch):
    """0600 root без sudo: status не падает, а печатает урезанный вид."""
    env_path = _env_file(tmp_path)
    env_path.parent.mkdir(parents=True)
    env_path.write_text("SMTP_HOST=smtp.example.com\n", encoding="utf-8")

    def boom(path):
        raise PermissionError("denied")

    monkeypatch.setattr(alert_cli, "load_config", boom)
    assert alert_cli.cmd_status(root=str(tmp_path)) == 0
    assert any("конфиг недоступен" in line for line in fake_console.lines)


def test_test_channel_invalid(tmp_path, fake_console):
    assert alert_cli.cmd_test(root=str(tmp_path), channel="carrier-pigeon") == 1
    assert any("--channel" in line for line in fake_console.lines)


def test_test_channel_not_configured(tmp_path, gateway_state, fake_console):
    env_path = _env_file(tmp_path)
    env_path.parent.mkdir(parents=True)
    env_path.write_text("ALERT_CHECKS=smtp\n", encoding="utf-8")
    assert alert_cli.cmd_test(root=str(tmp_path), channel="smtp") == 1


def test_test_smtp_sends_without_state(tmp_path, gateway_state, fake_console, monkeypatch):
    env_path = _env_file(tmp_path)
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "\n".join(
            [
                "SMTP_HOST=smtp.example.com",
                "SMTP_FROM=alert-test@example.com",
                "SMTP_TO=owner@example.com",
                f"SMTP_PASS={SMTP_PASS}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sent = []

    from src.alert import channels as channels_mod

    def fake_send(cfg, subject, text, **kwargs):
        sent.append((subject, text))
        return channels_mod.ChannelResult("smtp", True, "")

    monkeypatch.setattr(channels_mod, "send_smtp", fake_send)

    assert alert_cli.cmd_test(root=str(tmp_path), channel="smtp") == 0
    assert len(sent) == 1
    assert "ALERT-SENT smtp test" in fake_console.lines
    # state не пишется
    assert not (tmp_path / "var" / "lib" / "vds" / "alert-state.json").exists()


def test_test_smtp_failure_exit_1(tmp_path, gateway_state, fake_console, monkeypatch):
    env_path = _env_file(tmp_path)
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "\n".join(
            [
                "SMTP_HOST=smtp.example.com",
                "SMTP_FROM=alert-test@example.com",
                "SMTP_TO=owner@example.com",
                "SMTP_PASS=FIXTURE_PW_SMTP",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    from src.alert import channels as channels_mod

    monkeypatch.setattr(
        channels_mod, "send_smtp",
        lambda cfg, subject, text, **kw: channels_mod.ChannelResult("smtp", False, "auth"),
    )
    assert alert_cli.cmd_test(root=str(tmp_path), channel="smtp") == 1
    assert "ALERT-FAILED smtp auth" in fake_console.lines


# ---------------------------------------------------------------------------
# CLI-поверхность и шаблоны
# ---------------------------------------------------------------------------

def test_cli_help_lists_alert_subcommands():
    result = runner.invoke(alert_cli_main_app(), ["alert", "--help"])
    assert result.exit_code == 0
    for name in ("install", "remove", "test", "status", "watch"):
        assert name in result.output


def test_cli_test_has_channel_flag():
    result = runner.invoke(alert_cli_main_app(), ["alert", "test", "--help"])
    assert result.exit_code == 0
    assert "--channel" in result.output


def test_service_template_renders_with_ctx():
    from src.alert.cli import SERVICE_TEMPLATE, TIMER_TEMPLATE
    from src.core.units import SYSTEMD_DIR

    ctx = {
        "python": "/usr/bin/python3",
        "repo_dir": "/opt/my-vds",
        "install_dir": "/opt/my-vds",
        "interval_sec": "120",
    }
    for name in (SERVICE_TEMPLATE, TIMER_TEMPLATE):
        text = (SYSTEMD_DIR / name).read_text(encoding="utf-8").format(**ctx)
        assert "{python}" not in text and "{interval_sec}" not in text


def alert_cli_main_app():
    from src.main import app

    return app
