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


class TestClassifyBlock:
    """Таблица истинности classify_block (SPEC-20261112 WP-3, ≥10 кейсов)."""

    def test_target_none_unknown(self) -> None:
        assert netcheck.classify_block(True, None, True) == "unknown"
        assert netcheck.classify_block(None, None, None) == "unknown"
        assert netcheck.classify_block(False, None, False) == "unknown"

    def test_local_fail_target_ok_local_problem(self) -> None:
        assert netcheck.classify_block(False, True, True) == "local_problem"
        assert netcheck.classify_block(None, True, True) == "local_problem"

    def test_local_fail_target_fail_control_ok_ip_block(self) -> None:
        assert netcheck.classify_block(False, False, True) == "ip_block_likely"
        assert netcheck.classify_block(None, False, True) == "ip_block_likely"

    def test_all_ok_ok(self) -> None:
        assert netcheck.classify_block(True, True, True) == "ok"

    def test_ru_only_fail_ru_segment(self) -> None:
        assert netcheck.classify_block(
            True, True, True, ru_nodes_ok=0, ru_nodes_total=3
        ) == "ru_segment_block_likely"

    def test_ru_partially_ok_not_segment_block(self) -> None:
        assert netcheck.classify_block(
            True, True, True, ru_nodes_ok=1, ru_nodes_total=3
        ) == "ok"

    def test_ru_stats_without_total_not_segment_block(self) -> None:
        # ru_total=0: RU-узлов не было в ответе — не делаем вывод о сегменте
        assert netcheck.classify_block(
            True, True, True, ru_nodes_ok=0, ru_nodes_total=0
        ) == "ok"

    def test_local_ok_control_ok_target_fail_ip_block(self) -> None:
        assert netcheck.classify_block(True, False, True) == "ip_block_likely"

    def test_control_fail_target_fail_global_degradation(self) -> None:
        assert netcheck.classify_block(True, False, False) == "global_degradation"
        assert netcheck.classify_block(True, False, None) == "global_degradation"

    def test_control_fail_target_ok_ok(self) -> None:
        # check-host деградировал частично, наш IP жив извне
        assert netcheck.classify_block(True, True, False) == "ok"
        assert netcheck.classify_block(True, True, None) == "ok"


class _JsonResponse:
    def __init__(self, payload) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class TestCheckHostTcp:
    """check-host-клиент на моках requests: submit -> poll -> агрегат."""

    def _mock_requests(self, monkeypatch: pytest.MonkeyPatch, responses: list) -> list[str]:
        calls: list[str] = []
        # Фейковые часы: sleep продвигает monotonic-часы (иначе цикл poll
        # крутится до реального таймаута — медленный тест).
        clock = {"t": 0.0}
        monkeypatch.setattr(netcheck.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(
            netcheck.time, "sleep",
            lambda seconds: clock.__setitem__("t", clock["t"] + seconds),
        )

        def _get(url: str, **kwargs):
            calls.append(url)
            if not responses:
                raise netcheck.requests.RequestException("no more responses")
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        monkeypatch.setattr(netcheck.requests, "get", _get)
        return calls

    def test_submit_poll_aggregate_ru_world(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [
            _JsonResponse({"ok": 1, "request_id": "req-1"}),
            # первый poll: узлы ещё считают (null)
            _JsonResponse({"ru.node1": None, "de.node1": None}),
            _JsonResponse({
                "ru.node1": {"time": 0.05},
                "de.node1": {"time": 0.07},
            }),
        ]
        calls = self._mock_requests(monkeypatch, responses)
        result = netcheck.check_host_tcp("203.0.113.10", 443, timeout=30.0)
        assert result is not None
        assert result["nodes"] == {"ru.node1": True, "de.node1": True}
        assert result["ru_ok"] == 1 and result["ru_total"] == 1
        assert result["world_ok"] == 1 and result["world_total"] == 1
        assert any("check-tcp" in url for url in calls)
        assert any("check-result/req-1" in url for url in calls)

    def test_error_node_counts_not_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [
            _JsonResponse({"ok": 1, "request_id": "req-2"}),
            _JsonResponse({
                "ru.node1": {"error": 1},
                "de.node1": {"time": 0.05},
            }),
        ]
        self._mock_requests(monkeypatch, responses)
        result = netcheck.check_host_tcp("203.0.113.10", 443)
        assert result is not None
        assert result["nodes"] == {"ru.node1": False, "de.node1": True}
        assert result["ru_ok"] == 0 and result["ru_total"] == 1
        assert result["world_ok"] == 1

    def test_timeout_pending_node_counts_not_ok(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Узел без результата к таймауту — не-ok (не None-сбой)."""
        responses = [
            _JsonResponse({"ok": 1, "request_id": "req-3"}),
            _JsonResponse({"ru.node1": {"time": 0.05}, "us.node1": None}),
        ]
        self._mock_requests(monkeypatch, responses)
        result = netcheck.check_host_tcp("203.0.113.10", 443, timeout=1.0)
        assert result is not None
        assert result["nodes"] == {"ru.node1": True, "us.node1": False}

    def test_request_exception_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [netcheck.requests.RequestException("offline")]
        self._mock_requests(monkeypatch, responses)
        assert netcheck.check_host_tcp("203.0.113.10", 443) is None

    def test_poll_exception_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [
            _JsonResponse({"ok": 1, "request_id": "req-4"}),
            netcheck.requests.RequestException("offline"),
        ]
        self._mock_requests(monkeypatch, responses)
        assert netcheck.check_host_tcp("203.0.113.10", 443) is None

    def test_no_request_id_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [_JsonResponse({"ok": 0})]
        self._mock_requests(monkeypatch, responses)
        assert netcheck.check_host_tcp("203.0.113.10", 443) is None


class TestRunBlockcheck:
    def _mock(self, monkeypatch: pytest.MonkeyPatch, target, control) -> None:
        responses: list = []
        for payload in (target, control):
            if payload is None:
                responses.append(netcheck.requests.RequestException("offline"))
            else:
                responses.extend([
                    _JsonResponse({"ok": 1, "request_id": "r"}),
                    _JsonResponse(payload),
                ])
        monkeypatch.setattr(
            netcheck.requests, "get",
            lambda url, **kw: (
                responses.pop(0) if not isinstance(responses[0], Exception)
                else (_ for _ in ()).throw(responses.pop(0))
            ),
        )
        monkeypatch.setattr(netcheck.time, "sleep", lambda seconds: None)
        monkeypatch.setattr(netcheck, "public_ip", lambda: "203.0.113.10")
        monkeypatch.setattr(
            netcheck, "_local_tcp_probe", lambda ip, port=443, timeout=5.0: True
        )
        monkeypatch.setattr(
            "src.core.units.unit_active", lambda name: True
        )

    def test_collects_evidence_no_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._mock(
            monkeypatch,
            target={"ru.node1": {"time": 0.05}, "de.node1": {"time": 0.06}},
            control={"us.node1": {"time": 0.05}},
        )
        verdict, evidence = netcheck.run_blockcheck(timeout=5.0)
        assert verdict == "ok"
        assert evidence["public_ip"] == "203.0.113.10"
        assert evidence["local_tcp_ok"] is True
        assert evidence["unit_active"] is True
        assert evidence["target"]["ru_ok"] == 1
        assert evidence["control"]["world_ok"] == 1

    def test_offline_unknown_no_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._mock(monkeypatch, target=None, control=None)
        verdict, evidence = netcheck.run_blockcheck(timeout=5.0)
        assert verdict == "unknown"
        assert evidence["target"] is None
        assert evidence["control"] is None
