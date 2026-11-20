"""Тесты opt-in таймера манёвра (SPEC-20261120 WP-M4 / ADR-015, TECHDEBT P25).

Всё на моках: без root, сети и реального systemd/awg. Проверяются:
рендер обоих шаблонов (инварианты песочницы), install auto=off/--enable-auto,
идемпотентный remove и «тик всегда exit 0» с одним структурированным тегом.
"""

from __future__ import annotations

import json

import pytest

import src.relay.maneuver as maneuver
from src.core.lock import LockError
from src.core.shell import ShellResult
from src.core.units import SYSTEMD_DIR
from src.gateway.store import GatewayState, StoreError


class SystemctlRecorder:
    """run_list-мок: пишет вызовы, `systemctl is-*` отвечает как выключенный."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        call = list(args)
        self.calls.append(call)
        if call[:2] == ["systemctl", "is-enabled"]:
            return ShellResult("disabled", "", 1)
        if call[:2] == ["systemctl", "is-active"]:
            return ShellResult("inactive", "", 3)
        return ShellResult("", "", 0)

    def commands(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


@pytest.fixture
def timer_env(tmp_path, monkeypatch):
    runner = SystemctlRecorder()
    monkeypatch.setattr(maneuver, "run_list", runner)
    monkeypatch.setattr(maneuver, "RELAY_MANEUVER_LOCK_FILE", str(tmp_path / "maneuver.lock"))
    conf = tmp_path / "awg1.conf"
    conf.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(maneuver, "RELAY_EXIT_CONFIG_PATH", conf)
    monkeypatch.setattr(
        maneuver, "load_state",
        lambda path=None: GatewayState(version=1, protocols={"relay": {"installed": True}}),
    )
    monkeypatch.setattr(maneuver, "read_leg", lambda iface=maneuver.RELAY_EXIT_IFACE: {
        "iface": "awg1",
        "listen_port": 59036,
        "peer_public_key": "FIXTURE_PUBKEY_EXIT_AWG2_0000000000=",
        "endpoint_host": "203.0.113.9",
        "endpoint_port": 51900,
    })
    monkeypatch.setattr(maneuver, "probe_liveness", lambda target=maneuver.EXIT_LEG_IP: (True, 47))
    monkeypatch.setattr(maneuver.os, "geteuid", lambda: 0)

    installs: list[tuple[str, str, dict, bool]] = []
    removals: list[tuple[str, str]] = []

    def fake_install(template, name, ctx=None, root="/", enable=True):
        installs.append((template, name, dict(ctx or {}), enable))
        return True

    def fake_remove(name, root="/"):
        removals.append((name, root))
        return True

    monkeypatch.setattr(maneuver, "install_unit", fake_install)
    monkeypatch.setattr(maneuver, "remove_unit", fake_remove)
    return {
        "tmp": tmp_path,
        "runner": runner,
        "installs": installs,
        "removals": removals,
    }


# ---------------------------------------------------------------------------
# Рендер шаблонов: инварианты песочницы (SPEC §2, P0)
# ---------------------------------------------------------------------------

class TestTemplates:
    def _render(self, name: str, interval_sec: int = 60) -> str:
        text = (SYSTEMD_DIR / name).read_text(encoding="utf-8")
        return text.format(
            python="/opt/my-vds/venv/bin/python3",
            repo_dir="/opt/my-vds",
            install_dir="/opt/my-vds",
            interval_sec=str(interval_sec),
        )

    def test_service_template_sandbox(self):
        text = self._render(maneuver.MANEUVER_SERVICE_TEMPLATE)
        # persist_endpoint/бэкап в /etc/amnezia → иначе EROFS под strict
        assert "ReadWritePaths=/var/lib/vds /var/run /etc/amnezia" in text
        # awg show/set (netlink) + ping -I (raw)
        assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in text
        assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK" in text
        assert "TimeoutStartSec=60" in text
        assert "SyslogIdentifier=vds-relay-maneuver" in text
        assert "StandardOutput=journal" in text and "StandardError=journal" in text
        assert "ExecStart=/opt/my-vds/venv/bin/python3 -m src.main relay maneuver tick --apply" in text
        # .service включается только таймером: секции [Install] быть не должно
        assert "[Install]" not in text

    def test_timer_template(self):
        text = self._render(maneuver.MANEUVER_TIMER_TEMPLATE, interval_sec=90)
        assert "OnUnitActiveSec=90s" in text
        assert "Unit=vds-relay-maneuver.service" in text
        assert "[Install]" in text and "WantedBy=timers.target" in text


# ---------------------------------------------------------------------------
# install: auto=off по умолчанию, --enable-auto — opt-in
# ---------------------------------------------------------------------------

class TestInstall:
    def test_dry_run_mutates_nothing(self, timer_env, capsys):
        assert maneuver.run_install(apply=False, root=str(timer_env["tmp"])) == 0
        assert timer_env["installs"] == []
        assert timer_env["runner"].commands("systemctl") == []
        out = capsys.readouterr().out
        assert "DRY-RUN" in out and "opt-in" in out

    def test_install_without_enable_auto_does_not_enable_or_start(self, timer_env):
        assert maneuver.run_install(apply=True, root=str(timer_env["tmp"])) == 0

        by_name = {name: enable for _tpl, name, _ctx, enable in timer_env["installs"]}
        assert by_name == {
            maneuver.MANEUVER_UNIT: False,   # включается только таймером
            maneuver.MANEUVER_TIMER: False,  # opt-in: не включён
        }
        # Ни enable, ни start для таймера.
        assert timer_env["runner"].commands("systemctl", "enable") == []
        assert timer_env["runner"].commands("systemctl", "start") == []

    def test_install_enable_auto_enables_and_starts(self, timer_env):
        assert maneuver.run_install(
            apply=True, enable_auto=True, root=str(timer_env["tmp"])
        ) == 0

        by_name = {name: enable for _tpl, name, _ctx, enable in timer_env["installs"]}
        assert by_name[maneuver.MANEUVER_UNIT] is False
        assert by_name[maneuver.MANEUVER_TIMER] is True
        assert timer_env["runner"].commands("systemctl", "start", maneuver.MANEUVER_TIMER)

    def test_install_interval_rendered(self, timer_env):
        assert maneuver.run_install(
            apply=True, interval="90s", root=str(timer_env["tmp"])
        ) == 0
        timer_ctx = [
            ctx for _tpl, name, ctx, _en in timer_env["installs"]
            if name == maneuver.MANEUVER_TIMER
        ][0]
        assert timer_ctx["interval_sec"] == "90"

    @pytest.mark.parametrize("interval", ["10s", "14", "0s", "abc", ""])
    def test_interval_below_minimum_rejected(self, timer_env, capsys, interval):
        assert maneuver.run_install(apply=True, interval=interval, root=str(timer_env["tmp"])) == 1
        assert timer_env["installs"] == []
        assert "--interval" in capsys.readouterr().out

    def test_interval_parser_minimum(self):
        assert maneuver.parse_interval("15s") == 15
        assert maneuver.parse_interval("60s") == 60
        assert maneuver.parse_interval("2m") == 120
        with pytest.raises(maneuver.ManeuverError):
            maneuver.parse_interval("10s")

    def test_install_refuses_exit_node(self, timer_env, monkeypatch, capsys):
        monkeypatch.setattr(
            maneuver, "load_state",
            lambda path=None: GatewayState(
                version=1, protocols={"relay_leg": {"installed": True}}
            ),
        )
        assert maneuver.run_install(apply=True, root=str(timer_env["tmp"])) == 1
        assert timer_env["installs"] == []
        assert "exit" in capsys.readouterr().out

    def test_install_refuses_port_outside_pool(self, timer_env, monkeypatch):
        monkeypatch.setattr(maneuver, "read_leg", lambda iface="awg1": {
            "iface": "awg1", "listen_port": 59036,
            "peer_public_key": "FIXTURE_PUBKEY_EXIT_AWG2_0000000000=",
            "endpoint_host": "203.0.113.9", "endpoint_port": 51825,
        })
        assert maneuver.run_install(apply=True, root=str(timer_env["tmp"])) == 1
        assert timer_env["installs"] == []


# ---------------------------------------------------------------------------
# remove: идемпотентно, state сохраняется
# ---------------------------------------------------------------------------

class TestRemove:
    def test_dry_run_does_not_touch_units(self, timer_env, capsys):
        assert maneuver.run_remove(apply=False, root=str(timer_env["tmp"])) == 0
        assert timer_env["removals"] == []
        assert "DRY-RUN" in capsys.readouterr().out

    def test_remove_is_idempotent_and_keeps_state(self, timer_env):
        state = timer_env["tmp"] / "relay-maneuver.json"
        state.write_text(json.dumps({"version": 1, "current_port": 51900}), encoding="utf-8")

        assert maneuver.run_remove(apply=True, root=str(timer_env["tmp"])) == 0
        first = list(timer_env["removals"])
        assert [name for name, _root in first] == [
            maneuver.MANEUVER_TIMER, maneuver.MANEUVER_UNIT
        ]

        # Повторный remove — no-op по эффекту: те же юниты, exit 0.
        assert maneuver.run_remove(apply=True, root=str(timer_env["tmp"])) == 0
        assert [name for name, _root in timer_env["removals"]] == [
            maneuver.MANEUVER_TIMER, maneuver.MANEUVER_UNIT
        ] * 2
        assert state.is_file()  # история манёвра не удаляется


# ---------------------------------------------------------------------------
# tick: ВСЕГДА exit 0 + один структурированный тег без секретов
# ---------------------------------------------------------------------------

def _assert_tag(out: str) -> None:
    assert "[relay-maneuver]" in out
    assert "state=" in out and "port=" in out and "liveness=" in out
    assert "ms=" in out and "activity=" in out and "fails=" in out
    assert "acted=" in out and "result=" in out
    for secret in ("PrivateKey", "PresharedKey", "FIXTURE_PSK", "FIXTURE_PRIVKEY"):
        assert secret not in out


class TestTick:
    def test_tick_guard_refusal_exits_zero(self, timer_env, monkeypatch, capsys):
        monkeypatch.setattr(
            maneuver, "load_state",
            lambda path=None: GatewayState(
                version=1, protocols={"relay_leg": {"installed": True}}
            ),
        )
        assert maneuver.run_tick(apply=True) == 0
        _assert_tag(capsys.readouterr().out)

    def test_tick_maneuver_error_exits_zero(self, timer_env, monkeypatch, capsys):
        def boom(iface=maneuver.RELAY_EXIT_IFACE):
            raise maneuver.ManeuverError("awg show awg1 dump: сбой")

        monkeypatch.setattr(maneuver, "read_leg", boom)
        assert maneuver.run_tick(apply=True) == 0
        out = capsys.readouterr().out
        _assert_tag(out)
        assert "reason=" in out

    def test_tick_store_error_exits_zero(self, timer_env, monkeypatch, capsys):
        def boom(path=None):
            raise StoreError("битый state.json")

        monkeypatch.setattr(maneuver, "load_state", boom)
        assert maneuver.run_tick(apply=True) == 0
        _assert_tag(capsys.readouterr().out)

    def test_tick_busy_lock_exits_zero(self, timer_env, monkeypatch, capsys):
        class BusyLock:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                raise LockError("Не удалось получить блокировку")

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(maneuver, "FileLock", BusyLock)
        assert maneuver.run_tick(apply=True) == 0
        _assert_tag(capsys.readouterr().out)

    def test_tick_non_root_apply_exits_zero(self, timer_env, monkeypatch, capsys):
        monkeypatch.setattr(maneuver.os, "geteuid", lambda: 1000)
        assert maneuver.run_tick(apply=True) == 0
        _assert_tag(capsys.readouterr().out)
