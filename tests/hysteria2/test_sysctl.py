"""Тесты src/hysteria2/sysctl.py: детерминированный рендер + применение."""

from pathlib import Path

import pytest

import src.hysteria2.sysctl as sysctl_mod
from src.core.shell import ShellResult


class TestRender:
    def test_render_deterministic(self) -> None:
        assert sysctl_mod.render_sysctl() == sysctl_mod.render_sysctl()

    def test_contains_bbr_and_buffers(self) -> None:
        rendered = sysctl_mod.render_sysctl()
        assert "net.ipv4.tcp_congestion_control = bbr" in rendered
        assert "net.core.default_qdisc = fq" in rendered
        assert "net.core.rmem_max = 16777216" in rendered
        assert "net.core.wmem_max = 16777216" in rendered


class TestApply:
    def test_apply_writes_and_runs_sysctl_p(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        conf = tmp_path / "sysctl.d" / "99-vds-gateway.conf"
        calls: list[list[str]] = []
        monkeypatch.setattr(
            sysctl_mod, "run_list",
            lambda args, timeout=10: calls.append(args)
            or ShellResult(stdout="", stderr="", returncode=0),
        )
        assert sysctl_mod.apply_sysctl(conf_path=conf) is True
        assert conf.is_file()
        assert conf.read_text(encoding="utf-8") == sysctl_mod.render_sysctl()
        assert conf.stat().st_mode & 0o777 == 0o644
        assert calls == [["sysctl", "-p", str(conf)]]

    def test_apply_idempotent_same_content(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        conf = tmp_path / "99-vds-gateway.conf"
        monkeypatch.setattr(
            sysctl_mod, "run_list",
            lambda args, timeout=10: ShellResult(stdout="", stderr="", returncode=0),
        )
        assert sysctl_mod.apply_sysctl(conf_path=conf) is True
        first = conf.read_text(encoding="utf-8")
        assert sysctl_mod.apply_sysctl(conf_path=conf) is True
        assert conf.read_text(encoding="utf-8") == first

    def test_apply_failure_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sysctl_mod, "run_list",
            lambda args, timeout=10: ShellResult(stdout="", stderr="boom", returncode=1),
        )
        assert sysctl_mod.apply_sysctl(conf_path=tmp_path / "c.conf") is False
