"""Unit tests for src/core/units.py (FR-0.6). run_list mocked, tmp_path as root prefix."""

from pathlib import Path

import pytest

import src.core.units as units
from src.core.shell import ShellResult


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(stdout=stdout, stderr="", returncode=0)


def _fail(stderr: str = "boom") -> ShellResult:
    return ShellResult(stdout="", stderr=stderr, returncode=1)


@pytest.fixture()
def fake_systemd_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Каталог шаблонов во tmp вместо репозиторного systemd/."""
    tpl_dir = tmp_path / "systemd"
    tpl_dir.mkdir()
    (tpl_dir / "demo.service.tpl").write_text(
        "[Unit]\nDescription=vds {name} unit\n[Service]\nExecStart={exec_start}\n"
    )
    monkeypatch.setattr(units, "SYSTEMD_DIR", tpl_dir)
    return tpl_dir


@pytest.fixture()
def calls(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    recorded: list[list[str]] = []

    def _rec(args: list[str], timeout: int = 10) -> ShellResult:
        recorded.append(list(args))
        return _ok()

    monkeypatch.setattr(units, "run_list", _rec)
    return recorded


class TestInstallUnit:
    def test_renders_and_installs(
        self,
        fake_systemd_dir: Path,
        calls: list[list[str]],
        tmp_path: Path,
    ) -> None:
        assert (
            units.install_unit(
                "demo.service.tpl",
                "vds-demo.service",
                ctx={"name": "demo", "exec_start": "/usr/bin/demo"},
                root=str(tmp_path),
            )
            is True
        )
        unit_file = tmp_path / "etc" / "systemd" / "system" / "vds-demo.service"
        assert unit_file.read_text() == (
            "[Unit]\nDescription=vds demo unit\n[Service]\nExecStart=/usr/bin/demo\n"
        )
        assert ["systemctl", "daemon-reload"] in calls
        assert ["systemctl", "enable", "vds-demo.service"] in calls

    def test_idempotent_second_call(
        self,
        fake_systemd_dir: Path,
        calls: list[list[str]],
        tmp_path: Path,
    ) -> None:
        for _ in range(2):
            assert (
                units.install_unit(
                    "demo.service.tpl",
                    "vds-demo.service",
                    ctx={"name": "demo", "exec_start": "/x"},
                    root=str(tmp_path),
                )
                is True
            )
        unit_dir = tmp_path / "etc" / "systemd" / "system"
        files = [p.name for p in unit_dir.iterdir() if p.is_file()]
        assert files == ["vds-demo.service"]  # дублей и tmp-остатков нет

    def test_missing_template_returns_false(
        self, fake_systemd_dir: Path, calls: list[list[str]], tmp_path: Path
    ) -> None:
        assert (
            units.install_unit("nope.service.tpl", "x.service", root=str(tmp_path))
            is False
        )
        assert calls == []  # systemctl не вызывался

    def test_systemctl_failure_returns_false(
        self,
        fake_systemd_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(units, "run_list", lambda args, timeout=10: _fail())
        assert (
            units.install_unit(
                "demo.service.tpl",
                "vds-demo.service",
                ctx={"name": "d", "exec_start": "/x"},
                root=str(tmp_path),
            )
            is False
        )


class TestUnitActive:
    def test_active(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            units, "run_list", lambda args, timeout=10: _ok("active\n")
        )
        assert units.unit_active("vds-demo.service") is True

    def test_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            units, "run_list", lambda args, timeout=10: _ok("inactive\n")
        )
        assert units.unit_active("vds-demo.service") is False

    def test_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(units, "run_list", lambda args, timeout=10: _fail())
        assert units.unit_active("vds-demo.service") is False


class TestRemoveUnit:
    def test_removes_installed_unit(
        self,
        fake_systemd_dir: Path,
        calls: list[list[str]],
        tmp_path: Path,
    ) -> None:
        units.install_unit(
            "demo.service.tpl",
            "vds-demo.service",
            ctx={"name": "demo", "exec_start": "/x"},
            root=str(tmp_path),
        )
        assert units.remove_unit("vds-demo.service", root=str(tmp_path)) is True
        unit_file = tmp_path / "etc" / "systemd" / "system" / "vds-demo.service"
        assert not unit_file.exists()
        assert ["systemctl", "stop", "vds-demo.service"] in calls
        assert ["systemctl", "disable", "vds-demo.service"] in calls
        assert calls.count(["systemctl", "daemon-reload"]) == 2

    def test_idempotent_missing_unit(
        self, calls: list[list[str]], tmp_path: Path
    ) -> None:
        assert units.remove_unit("absent.service", root=str(tmp_path)) is True

    def test_daemon_reload_failure_returns_false(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(units, "run_list", lambda args, timeout=30: _fail())
        assert units.remove_unit("absent.service", root=str(tmp_path)) is False
