"""Тесты gate-логики DMS и тика пинга: exit/relay, /fail, маска URL (SPEC §5).

Без сети и root: shell — фейковый `run`, HTTP — мок `urllib.request.urlopen`.
"""
from __future__ import annotations

import urllib.error
from io import BytesIO

import pytest

from src.core.shell import ShellResult
from src.dms import gate
from src.dms.env import DmsConfig

FIXTURE_URL = "https://hc-ping.com/FIXTURE_PW_DMS_URL"


class FakeRun:
    """Фейковый `run_list`: результат по префиксу команды."""

    def __init__(self, *, awg0=True, awg2=True, wstunnel=True, table=True,
                 ping_awg=True, ping_ws=True):
        self.awg0 = awg0
        self.awg2 = awg2
        self.wstunnel = wstunnel
        self.table = table
        self.ping_awg = ping_awg
        self.ping_ws = ping_ws
        self.calls: list[list[str]] = []

    def _ok(self, value: bool) -> ShellResult:
        return ShellResult(stdout="", stderr="" if value else "err", returncode=0 if value else 1)

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        head = args[0]
        if head == "ip":
            if args[1] == "link":
                name = args[-1]
                if name == "awg0":
                    return self._ok(self.awg0)
                if name in ("awg1", "awg2"):
                    return self._ok(self.awg2)
            if args[1] == "rule":
                rule = "0:      from all lookup local\n32765:	from all fwmark 0x1 lookup 100" if self.table else "0:      from all lookup local"
                return ShellResult(stdout=rule, stderr="", returncode=0)
        if head == "systemctl":
            if args[1] == "is-active" and args[2] == gate.WSTUNNEL_SERVER_UNIT:
                out = "active" if self.wstunnel else "inactive"
                code = 0 if self.wstunnel else 3
                return ShellResult(stdout=out, stderr="", returncode=code)
        if head == "ping":
            target = args[-1]
            if target == gate.RELAY_CARRIER_AWG_GW:
                return self._ok(self.ping_awg)
            if target == gate.RELAY_CARRIER_WS_GW:
                return self._ok(self.ping_ws)
        return ShellResult(stdout="", stderr="", returncode=0)


class FakeResponse(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def status(self):  # urllib.HTTPResponse носит .status
        return 200


def _install_urlopen(monkeypatch, status=200, http_error=None, url_error=None):
    calls: list[str] = []

    def fake_urlopen(url, timeout=0):
        calls.append(str(url))
        if http_error is not None:
            raise urllib.error.HTTPError(url, http_error, "boom", hdrs=None, fp=None)
        if url_error is not None:
            raise urllib.error.URLError(url_error)
        return FakeResponse(b"OK")

    monkeypatch.setattr(gate.urllib.request, "urlopen", fake_urlopen)
    return calls


# --- exit gate -------------------------------------------------------------

def test_check_exit_all_up():
    result = gate.check_exit(FakeRun())
    assert result.ok and result.role == "exit"
    assert result.detail == "all up"


def test_check_exit_wstunnel_down():
    result = gate.check_exit(FakeRun(wstunnel=False))
    assert not result.ok
    assert "wstunnel_server" in result.detail


def test_check_exit_awg2_down():
    result = gate.check_exit(FakeRun(awg2=False))
    assert not result.ok
    assert "awg2" in result.detail


# --- relay gate ------------------------------------------------------------

def test_check_relay_awg_carrier_alive():
    result = gate.check_relay(FakeRun())
    assert result.ok
    assert result.detail == "awg carrier"


def test_check_relay_only_wstunnel_carrier_alive():
    result = gate.check_relay(FakeRun(ping_awg=False))
    assert result.ok
    assert result.detail == "wstunnel carrier"


def test_check_relay_both_carriers_dead():
    result = gate.check_relay(FakeRun(ping_awg=False, ping_ws=False))
    assert not result.ok
    assert "both carriers dead" in result.detail


def test_check_relay_table100_missing():
    result = gate.check_relay(FakeRun(table=False))
    assert not result.ok
    assert "table100 missing" in result.detail


def test_check_gate_unknown_role_fails():
    result = gate.check_gate(DmsConfig(role=""))
    assert not result.ok


# --- fail URL и HTTP --------------------------------------------------------

def test_fail_url():
    assert gate.fail_url(FIXTURE_URL) == FIXTURE_URL + "/fail"
    assert gate.fail_url(FIXTURE_URL + "/") == FIXTURE_URL + "/fail"


def test_http_get_ok(monkeypatch):
    calls = _install_urlopen(monkeypatch)
    ok, err = gate.http_get(FIXTURE_URL)
    assert ok and err == ""
    assert calls == [FIXTURE_URL]


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"http_error": 404}, "http_404"),
        ({"url_error": "conn refused"}, "URLError"),
    ],
)
def test_http_get_failures(monkeypatch, kwargs, expected):
    _install_urlopen(monkeypatch, **kwargs)
    ok, err = gate.http_get(FIXTURE_URL)
    assert not ok and err == expected


# --- тик пинга --------------------------------------------------------------

import tempfile
import os

from src.dms.env import render_env


def _env_file(role: str, url: str = FIXTURE_URL) -> str:
    fd, path = tempfile.mkstemp(suffix=".env")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_env(DmsConfig(ping_url=url, role=role), with_secrets=True))
    return path


def test_run_ping_gate_ok_pings_base_url(monkeypatch):
    calls = _install_urlopen(monkeypatch)
    lines: list[str] = []
    code = gate.run_ping(
        config_path=_env_file("exit"),
        run=FakeRun(),
        now_journal=lines.append,
    )
    assert code == 0
    assert calls == [FIXTURE_URL]
    assert any(line.startswith("DMS-PING ok") for line in lines)
    assert all(FIXTURE_URL not in line for line in lines)  # URL не утекает в journal


def test_run_ping_gate_fail_sends_fail(monkeypatch):
    calls = _install_urlopen(monkeypatch)
    lines: list[str] = []
    code = gate.run_ping(
        config_path=_env_file("relay"),
        run=FakeRun(ping_awg=False, ping_ws=False),
        now_journal=lines.append,
    )
    assert code == 0
    assert calls == [FIXTURE_URL + "/fail"]
    assert any(line.startswith("DMS-PING gatefail") for line in lines)
    assert any(line == "DMS-FAIL sent" for line in lines)
    assert all(FIXTURE_URL not in line for line in lines)


def test_run_ping_no_url_skips(monkeypatch):
    calls = _install_urlopen(monkeypatch)
    lines: list[str] = []
    code = gate.run_ping(config_path=_env_file("exit", url=""), run=FakeRun(), now_journal=lines.append)
    assert code == 0
    assert calls == []
    assert lines == ["DMS-PING skip no_url"]


def test_run_ping_gate_details_masked_never_contains_url(monkeypatch):
    """Даже при HTTP-сбое journal не содержит URL."""
    _install_urlopen(monkeypatch, url_error="timeout")
    lines: list[str] = []
    gate.run_ping(config_path=_env_file("exit"), run=FakeRun(), now_journal=lines.append)
    assert all(FIXTURE_URL not in line for line in lines)
