"""Тесты src/gateway/health.py (W1 GR-18/GR-12): все shell/systemctl — за моками."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

import src.gateway.health as health
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state


@pytest.fixture(autouse=True)
def _tmp_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Файловая блокировка healthcheck — в tmp (тесты не трогают /var/run)."""
    monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "health.lock"))


def _state(
    tmp_path: Path,
    *,
    xray: bool = True,
    hysteria2: bool = True,
    obfs: bool = False,
    xhttp: bool = False,
    cdn: bool = False,
    acme_days_cert: bool = False,
) -> GatewayState:
    """Собрать state.json с установленными протоколами (порты дефолтные)."""
    state = GatewayState()
    if xray:
        state.protocols["xray"] = {"installed": True, "port": 443}
    if hysteria2:
        state.protocols["hysteria2"] = {"installed": True, "port": 443}
    if obfs:
        state.protocols["hysteria2-obfs"] = {"installed": True, "port": 51826}
    if xhttp:
        state.protocols["xhttp"] = {"installed": True, "port": 8443}
    if cdn:
        state.protocols["xray-cdn"] = {"installed": True, "port": 2053}
    if acme_days_cert:
        state.protocols["acme"] = {
            "installed": True,
            "domain": "vpn.example.com",
            "cert_path": str(tmp_path / "fullchain.pem"),
        }
    save_state(state, str(tmp_path / "state.json"))
    return state


class TestCollectTargets:
    def test_empty_state_no_targets(self) -> None:
        assert health.collect_targets(GatewayState()) == []

    def test_base_protocols(self, tmp_path: Path) -> None:
        state = _state(tmp_path)
        targets = health.collect_targets(state)
        assert [(t.unit, t.ports) for t in targets] == [
            ("vds-xray.service", [(443, "tcp")]),
            ("vds-hysteria2.service", [(443, "udp")]),
        ]

    def test_obfs_optional_by_state(self, tmp_path: Path) -> None:
        state = _state(tmp_path, obfs=True)
        units = [t.unit for t in health.collect_targets(state)]
        assert "vds-hysteria2-obfs.service" in units

    def test_xhttp_and_cdn_ports_attach_to_xray(self, tmp_path: Path) -> None:
        state = _state(tmp_path, xhttp=True, cdn=True, hysteria2=False)
        targets = health.collect_targets(state)
        assert len(targets) == 1
        assert targets[0].unit == "vds-xray.service"
        assert (8443, "tcp") in targets[0].ports
        assert (2053, "tcp") in targets[0].ports

    def test_cdn_port_from_state_not_default(self, tmp_path: Path) -> None:
        state = _state(tmp_path, hysteria2=False)
        state.protocols["xray-cdn"] = {"installed": True, "port": 2087}
        targets = health.collect_targets(state)
        assert (2087, "tcp") in targets[0].ports


class TestCertClassification:
    def test_thresholds(self) -> None:
        assert health.classify_cert_days(90)[0] == "ok"
        assert health.classify_cert_days(14)[0] == "ok"
        assert health.classify_cert_days(13)[0] == "warning"
        assert health.classify_cert_days(7)[0] == "warning"
        assert health.classify_cert_days(6)[0] == "error"
        assert health.classify_cert_days(0)[0] == "error"
        assert health.classify_cert_days(-1)[0] == "error"

    def test_unreadable_cert_is_warning(self) -> None:
        assert health.classify_cert_days(None)[0] == "warning"


class TestRateLimiter:
    def test_allows_up_to_limit(self, tmp_path: Path) -> None:
        now = datetime(2026, 11, 13, 12, 0, 0)
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"), now=lambda: now
        )
        for _ in range(health.MAX_RESTARTS_PER_HOUR):
            assert limiter.allow("vds-xray.service") is True
            limiter.record("vds-xray.service")
        assert limiter.allow("vds-xray.service") is False
        assert limiter.recent_count("vds-xray.service") == 3

    def test_per_unit_counters(self, tmp_path: Path) -> None:
        now = datetime(2026, 11, 13, 12, 0, 0)
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"), now=lambda: now
        )
        limiter.record("vds-xray.service")
        assert limiter.recent_count("vds-hysteria2.service") == 0
        assert limiter.allow("vds-hysteria2.service") is True

    def test_window_expiry_frees_limit(self, tmp_path: Path) -> None:
        clock = {"now": datetime(2026, 11, 13, 12, 0, 0)}
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"),
            now=lambda: clock["now"],
        )
        for _ in range(3):
            limiter.record("vds-xray.service")
        assert limiter.allow("vds-xray.service") is False
        clock["now"] += timedelta(hours=1, seconds=1)
        assert limiter.allow("vds-xray.service") is True
        assert limiter.recent_count("vds-xray.service") == 0

    def test_corrupt_lines_ignored(self, tmp_path: Path) -> None:
        state_file = tmp_path / "restarts"
        state_file.write_text("garbage line\nnot-a-date unit\n", encoding="utf-8")
        limiter = health.RestartRateLimiter(
            state_file=str(state_file), now=lambda: datetime(2026, 11, 13, 12, 0, 0)
        )
        assert limiter.recent_count("vds-xray.service") == 0


class TestPortListening:
    def test_none_on_ss_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            health, "run_list", lambda args, timeout=5: ShellResult("", "boom", 1)
        )
        assert health.port_listening(443, "tcp") is None

    def test_listening_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stdout = "LISTEN 0 4096 0.0.0.0:443 users:((\"xray\",pid=1,fd=6))"
        monkeypatch.setattr(
            health, "run_list", lambda args, timeout=5: ShellResult(stdout, "", 0)
        )
        assert health.port_listening(443, "tcp") is True
        assert health.port_listening(8443, "tcp") is False


class TestRunHealthcheck:
    """run_healthcheck целиком: моки unit_active/run_list/port_listening/cert."""

    def test_all_healthy_manual_rc0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path, obfs=True, acme_days_cert=True)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(
            health, "unit_active", lambda unit: True, raising=True
        )
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(
            health, "check_cert", lambda s: [health.Finding("ok", "cert 90 дн.")]
        )
        with health.console.capture() as captured:
            rc = health.run_healthcheck(state_path=str(tmp_path / "state.json"))
        assert rc == 0, captured.get()
        assert "активен" in captured.get()

    def test_down_unit_restarted_rc0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        restarts: list[str] = []
        active: set[str] = set()

        def _unit_active(unit: str) -> bool:
            return unit in active

        def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:2] == ["systemctl", "restart"]:
                restarts.append(args[2])
                active.add(args[2])
                return ShellResult("", "", 0)
            return ShellResult("", "", 1)

        monkeypatch.setattr(health, "unit_active", _unit_active)
        monkeypatch.setattr(health, "run_list", _run_list)
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "h.lock"))
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"),
            now=lambda: datetime.now(),
        )
        with health.console.capture() as captured:
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"), limiter=limiter
            )
        assert rc == 0, captured.get()
        assert restarts == ["vds-xray.service", "vds-hysteria2.service"]
        assert "перезапущен" in captured.get()

    def test_rate_limit_blocks_restart_error_manual_rc1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(health, "unit_active", lambda unit: False)
        monkeypatch.setattr(
            health,
            "run_list",
            lambda args, timeout=10: ShellResult("", "", 0),
        )
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "check_cert", lambda s: [])
        monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "h.lock"))
        now = datetime(2026, 11, 13, 12, 0, 0)
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"), now=lambda: now
        )
        for _ in range(3):
            limiter.record("vds-xray.service")
        with health.console.capture() as captured:
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"), limiter=limiter
            )
        assert rc == 1
        assert "rate-limit" in captured.get()

    def test_unit_mode_rc0_despite_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(health, "unit_active", lambda unit: False)
        monkeypatch.setattr(
            health, "run_list", lambda args, timeout=10: ShellResult("", "", 0)
        )
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "check_cert", lambda s: [])
        monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "h.lock"))
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"),
            now=lambda: datetime(2026, 11, 13, 12, 0, 0),
        )
        for unit in ("vds-xray.service", "vds-hysteria2.service"):
            for _ in range(3):
                limiter.record(unit)
        with health.console.capture():
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"),
                unit_mode=True,
                limiter=limiter,
            )
        assert rc == 0

    def test_no_restart_flag_read_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        restarts: list[str] = []
        monkeypatch.setattr(
            health,
            "run_list",
            lambda args, timeout=10: restarts.append(args) or ShellResult("", "", 0),
        )
        monkeypatch.setattr(health, "unit_active", lambda unit: False)
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "check_cert", lambda s: [])
        with health.console.capture():
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"), restart=False
            )
        assert rc == 1
        assert restarts == []

    def test_port_not_listened_is_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(health, "unit_active", lambda unit: True)
        monkeypatch.setattr(health, "port_listening", lambda p, proto: False)
        monkeypatch.setattr(health, "check_cert", lambda s: [])
        with health.console.capture() as captured:
            rc = health.run_healthcheck(state_path=str(tmp_path / "state.json"))
        assert rc == 1
        assert "не слушается" in captured.get()

    def test_broken_state_is_catastrophe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = tmp_path / "state.json"
        bad.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr("os.geteuid", lambda: 0)
        with health.console.capture():
            rc_manual = health.run_healthcheck(state_path=str(bad))
            rc_unit = health.run_healthcheck(state_path=str(bad), unit_mode=True)
        assert rc_manual == 1 and rc_unit == 1


class TestCertCheck:
    def test_cert_days_from_acme_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state(tmp_path, xray=False, hysteria2=False, acme_days_cert=True)

        import src.acme.install as acme

        # healthcheck импортирует cert_days_left лениво из acme.install —
        # мок на атрибуте модуля-источника перехватывается при вызове.
        monkeypatch.setattr(acme, "cert_days_left", lambda path: 5)
        findings = health.check_cert(state)
        assert len(findings) == 1 and findings[0].level == "error"

    def test_cert_missing_path_is_warning(self, tmp_path: Path) -> None:
        state = _state(tmp_path, xray=False, hysteria2=False)
        state.protocols["acme"] = {"installed": True}
        findings = health.check_cert(state)
        assert len(findings) == 1 and findings[0].level == "warning"

    def test_no_acme_no_findings(self, tmp_path: Path) -> None:
        state = _state(tmp_path)
        assert health.check_cert(state) == []

    def test_parallel_run_lockerror_falls_back_to_readonly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LockError (таймер+ручной): рестарты отданы параллельному прогону."""
        from src.core.lock import LockError

        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(health, "unit_active", lambda unit: True)
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "check_cert", lambda s: [])

        class _BusyLock:
            def __init__(self, path: str) -> None:
                pass

            def __enter__(self) -> None:
                raise LockError("занято")

            def __exit__(self, *args: object) -> None:
                return None

        monkeypatch.setattr(health, "FileLock", _BusyLock)
        monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "h.lock"))
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"),
            now=lambda: datetime.now(),
        )
        with health.console.capture() as captured:
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"), limiter=limiter
            )
        assert rc == 0, captured.get()
        assert "Параллельный прогон" in captured.get()

    def test_grace_sleep_after_restart(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """После успешного рестарта port-чек ждёт PORT_GRACE_SECONDS."""
        state = _state(tmp_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        active: set[str] = set()

        def _unit_active(unit: str) -> bool:
            return unit in active

        def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:2] == ["systemctl", "restart"]:
                active.add(args[2])
                return ShellResult("", "", 0)
            return ShellResult("", "", 1)

        monkeypatch.setattr(health, "unit_active", _unit_active)
        monkeypatch.setattr(health, "run_list", _run_list)
        monkeypatch.setattr(health, "port_listening", lambda p, proto: True)
        monkeypatch.setattr(health, "check_cert", lambda s: [])
        monkeypatch.setattr(health, "LOCK_FILE", str(tmp_path / "h.lock"))
        sleeps: list[float] = []
        monkeypatch.setattr(health.time, "sleep", sleeps.append)
        limiter = health.RestartRateLimiter(
            state_file=str(tmp_path / "restarts"),
            now=lambda: datetime.now(),
        )
        with health.console.capture():
            rc = health.run_healthcheck(
                state_path=str(tmp_path / "state.json"), limiter=limiter
            )
        assert rc == 0
        assert sleeps == [health.PORT_GRACE_SECONDS]


class TestCertSniMatch:
    """GR-10: CN развёрнутого сертификата обязан совпадать с sni ссылок."""

    def _state(self, tmp_path: Path, cert_domain: str) -> "object":
        state = health.GatewayState()
        state.protocols["hysteria2"] = {
            "installed": True, "port": 443, "cert_domain": cert_domain,
        }
        return state

    def test_match_is_ok(self, tmp_path: Path, monkeypatch) -> None:
        state = self._state(tmp_path, "vpn.example.com")
        monkeypatch.setattr(health, "cert_subject_cn", lambda path=None: "vpn.example.com")
        findings = health.check_cert_sni_match(state)
        assert [f.level for f in findings] == ["ok"]

    def test_mismatch_is_error(self, tmp_path: Path, monkeypatch) -> None:
        state = self._state(tmp_path, "vpn.example.com")
        monkeypatch.setattr(health, "cert_subject_cn", lambda path=None: "front.example.ru")
        findings = health.check_cert_sni_match(state)
        assert [f.level for f in findings] == ["error"]
        assert "set-cert-domain" in findings[0].text

    def test_self_signed_skipped(self, tmp_path: Path) -> None:
        state = self._state(tmp_path, "")
        state.protocols["hysteria2"]["cert_cn"] = "203.0.113.10"
        assert health.check_cert_sni_match(state) == []

    def test_awg_nat_rule_present_ok(self, tmp_path, monkeypatch):
        """MASQUERADE в iptables-save → ok (инцидент 2026-11-13)."""
        monkeypatch.setattr(health, "_awg_installed", lambda: True)
        dump = "-A POSTROUTING -s 10.9.0.0/24 -o enp6s18 -j MASQUERADE\n"
        monkeypatch.setattr(
            health, "run_list",
            lambda args, timeout=10: ShellResult(dump, "", 0),
        )
        findings = health.check_awg_nat()
        assert len(findings) == 1 and findings[0].level == "ok"

    def test_awg_nat_rule_missing_error(self, monkeypatch):
        """Правила нет → error с подсказкой восстановления."""
        monkeypatch.setattr(health, "_awg_installed", lambda: True)
        monkeypatch.setattr(
            health, "run_list", lambda args, timeout=10: ShellResult("-A OTHER\n", "", 0)
        )
        findings = health.check_awg_nat()
        assert len(findings) == 1 and findings[0].level == "error"
        assert "vds-amneziawg-nat" in findings[0].text

    def test_awg_not_installed_no_findings(self, monkeypatch):
        monkeypatch.setattr(health, "_awg_installed", lambda: False)
        assert health.check_awg_nat() == []
