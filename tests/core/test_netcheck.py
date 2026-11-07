"""Unit tests for src/core/netcheck.py (FR-0.4). run_list and requests mocked."""

import pytest

import src.core.netcheck as netcheck
from src.core.shell import ShellResult


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(stdout=stdout, stderr="", returncode=0)


def _fail(stderr: str = "boom") -> ShellResult:
    return ShellResult(stdout="", stderr=stderr, returncode=1)


class TestPortFree:
    def test_busy_tcp_port_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ss_output = (
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
            "LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=2,fd=6))\n"
        )
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _ok(ss_output))
        assert netcheck.port_free(443, "tcp") is False

    def test_free_udp_port_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            netcheck, "run_list", lambda args, timeout=5: _ok("")
        )
        assert netcheck.port_free(443, "udp") is True

    def test_ss_failure_returns_false_no_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _fail())
        assert netcheck.port_free(443, "tcp") is False

    def test_invalid_port_or_proto_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called: list = []
        monkeypatch.setattr(
            netcheck, "run_list", lambda args, timeout=5: called.append(args) or _ok("")
        )
        assert netcheck.port_free(0, "tcp") is False
        assert netcheck.port_free(70000, "tcp") is False
        assert netcheck.port_free(443, "sctp") is False
        assert called == []  # ss не вызывался на невалидных аргументах

    def test_ipv6_and_wildcard_addresses_parsed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ss_output = "LISTEN 0 128 [::]:8443 [::]:* users:((\"xray\",pid=3,fd=7))\n"
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _ok(ss_output))
        assert netcheck.port_free(8443, "tcp") is False
        assert netcheck.port_free(443, "tcp") is True


class TestPortOwner:
    def test_returns_process_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ss_output = (
            "LISTEN 0 511 0.0.0.0:443 0.0.0.0:* "
            "users:((\"nginx\",pid=2,fd=6),(\"nginx\",pid=2,fd=7))\n"
        )
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _ok(ss_output))
        assert netcheck.port_owner(443, "tcp") == "nginx"

    def test_free_port_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _ok(""))
        assert netcheck.port_owner(443, "udp") is None

    def test_ss_failure_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _fail())
        assert netcheck.port_owner(443, "tcp") is None

    def test_socket_without_users_info_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # без root колонка users:(...) пуста
        ss_output = "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
        monkeypatch.setattr(netcheck, "run_list", lambda args, timeout=5: _ok(ss_output))
        assert netcheck.port_owner(443, "tcp") is None


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text


class TestPublicIp:
    def test_returns_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            netcheck.requests,
            "get",
            lambda url, timeout: _FakeResponse("203.0.113.7\n"),
        )
        assert netcheck.public_ip() == "203.0.113.7"

    def test_network_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(url: str, timeout: int) -> None:
            raise netcheck.requests.RequestException("no network")

        monkeypatch.setattr(netcheck.requests, "get", _raise)
        assert netcheck.public_ip() is None

    def test_empty_response_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            netcheck.requests, "get", lambda url, timeout: _FakeResponse("  ")
        )
        assert netcheck.public_ip() is None
