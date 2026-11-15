"""Тесты src/gateway/probing_rucidr.py (SPEC-20261116-probe-response §3).

Без root/сети: fetch мокается на уровне src.relay.cidr, юниты и systemctl —
на моках; агрегация идёт настоящей (collapse_addresses). Путь агрегата —
/tmp- target (параметр), совместимость с relay-путем проверяется константой.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

import src.gateway.probing_rucidr as rucidr
import src.relay.cidr as relay_cidr
from src.core.shell import ShellResult
from src.relay.paths import RELAY_CIDR_LIST, RELAY_CIDR_TIMER

RU_ZONE = [
    "203.0.113.0/24",
    "203.0.113.1/24",     # сосед — склеится при агрегации
    "198.51.100.0/25",
    "2a00:5c00::/29",     # v6 — отсекается aggregate()
]


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(stdout=stdout, stderr="", returncode=0)


class TestUpdateAggregate:
    def test_writes_collapsed_v4_to_target(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay_cidr, "fetch", lambda timeout=60: list(RU_ZONE))
        target = tmp_path / "ru-cidrs.txt"
        assert rucidr.update_aggregate(target=target) == 0
        text = target.read_text(encoding="utf-8")
        assert "203.0.113.0/24" in text          # соседние /24 склеились в одну
        assert text.count("203.0.113.") == 1
        assert "198.51.100.0/25" in text
        assert "2a00:" not in text               # только v4
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o644

    def test_failure_keeps_previous_aggregate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "ru-cidrs.txt"
        target.write_text("203.0.113.0/24\n", encoding="utf-8")

        def _boom(timeout: int = 60) -> list[str]:
            raise RuntimeError("network down")

        monkeypatch.setattr(relay_cidr, "fetch", _boom)
        assert rucidr.update_aggregate(target=target) == 1
        assert target.read_text(encoding="utf-8") == "203.0.113.0/24\n"  # не тронут

    def test_bad_cidr_fails_without_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay_cidr, "fetch", lambda timeout=60: ["not-a-cidr"])
        target = tmp_path / "ru-cidrs.txt"
        assert rucidr.update_aggregate(target=target) == 1
        assert not target.exists()

    def test_default_target_is_relay_compatible_path(self) -> None:
        # SPEC §3: тот же путь, что ждёт relay (relay init не перезатирает чужое)
        assert rucidr.RU_CIDR_FILE == RELAY_CIDR_LIST


class TestInstallUpdateCommands:
    def test_install_dry_run_no_shell(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        def _fail(args: list[str], **kw: Any) -> ShellResult:
            raise AssertionError(f"dry-run не должен вызывать shell: {args}")

        monkeypatch.setattr("src.core.shell.run_list", _fail)
        monkeypatch.setattr("src.core.units.install_unit", _fail)
        assert rucidr.cmd_ru_cidr_install(apply=False) == 0
        assert "DRY-RUN" in capsys.readouterr().out

    def test_update_dry_run(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        def _fail(args: list[str], **kw: Any) -> ShellResult:
            raise AssertionError(f"dry-run не должен вызывать shell: {args}")

        monkeypatch.setattr("src.core.shell.run_list", _fail)
        assert rucidr.cmd_ru_cidr_update(apply=False) == 0
        assert "DRY-RUN" in capsys.readouterr().out

    def test_install_apply_units_and_timer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        installed: list[tuple[str, str]] = []
        monkeypatch.setattr(relay_cidr, "fetch", lambda timeout=60: list(RU_ZONE))
        target = tmp_path / "ru-cidrs.txt"
        monkeypatch.setattr(rucidr, "RU_CIDR_FILE", target)

        def _install_unit(template: str, name: str, ctx: dict = {}, root: str = "/") -> bool:
            installed.append((template, name))
            return True

        shell_calls: list[list[str]] = []

        def _run(args: list[str], timeout: int = 10) -> ShellResult:
            shell_calls.append(list(args))
            return _ok()

        monkeypatch.setattr("src.core.units.install_unit", _install_unit)
        monkeypatch.setattr("src.core.shell.run_list", _run)
        monkeypatch.setattr(rucidr, "LOCK_FILE", str(tmp_path / "probe.lock"))

        assert rucidr.cmd_ru_cidr_install(apply=True) == 0
        # агрегат записан, v4-агрегат склеен
        assert "203.0.113.0/24" in target.read_text(encoding="utf-8")
        # оба юнита из шаблонов с правильными именами
        assert installed == [
            ("vds-probe-rucidr.service.tpl", rucidr.PROBE_RUCIDR_UNIT),
            ("vds-probe-rucidr.timer.tpl", rucidr.PROBE_RUCIDR_TIMER),
        ]
        # таймер включён немедленно
        assert ["systemctl", "enable", "--now", rucidr.PROBE_RUCIDR_TIMER] in shell_calls
        out = capsys.readouterr().out
        assert "установлен" in out

    def test_install_apply_survives_fetch_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Сбой первой загрузки не валит install: юниты ставятся, таймер дотянет."""
        def _boom(timeout: int = 60) -> list[str]:
            raise RuntimeError("network down")

        monkeypatch.setattr(relay_cidr, "fetch", _boom)
        monkeypatch.setattr(
            "src.core.units.install_unit", lambda template, name, ctx={}, root="/": True
        )
        monkeypatch.setattr("src.core.shell.run_list", lambda args, timeout=10: _ok())
        monkeypatch.setattr(rucidr, "LOCK_FILE", str(tmp_path / "probe.lock"))
        assert rucidr.cmd_ru_cidr_install(apply=True) == 0  # паттерн relay init

    def test_update_apply_writes_under_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay_cidr, "fetch", lambda timeout=60: ["203.0.113.0/24"])
        target = tmp_path / "ru-cidrs.txt"
        monkeypatch.setattr(rucidr, "RU_CIDR_FILE", target)
        monkeypatch.setattr(rucidr, "LOCK_FILE", str(tmp_path / "probe.lock"))
        assert rucidr.cmd_ru_cidr_update(apply=True) == 0
        assert target.read_text(encoding="utf-8") == "203.0.113.0/24\n"


class TestUnitNames:
    def test_names_distinct_from_relay(self) -> None:
        # не конфликтуют с relay-юнитами (relay init ставит свои)
        assert rucidr.PROBE_RUCIDR_UNIT != "vds-relay-cidr.service"
        assert rucidr.PROBE_RUCIDR_TIMER != RELAY_CIDR_TIMER
