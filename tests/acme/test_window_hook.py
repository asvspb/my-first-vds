"""Тесты ACME окна 80/tcp (SPEC-20261124-quiet-exit §2, §10 P1-5).

Без root/ufw: tmp-пути + fake run_list (AGENTS.md §6).
"""
from __future__ import annotations

from pathlib import Path

import pytest

import src.acme.window_hook as wh
import src.system.ufw as ufw


class _R:
    def __init__(self, ok: bool = True, stdout: str = "", stderr: str = "") -> None:
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0 if ok else 1


# ── render hooks ─────────────────────────────────────────────────────────────


def test_render_open_hook_idempotent_content(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    text = wh.render_open_hook(marker)
    assert text.startswith("#!/bin/sh")
    assert "ufw allow 80/tcp" in text
    assert f"touch {marker}" in text


def test_render_close_hook_tolerant_and_marker_guarded(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    text = wh.render_close_hook(marker)
    assert "if [ -f " + str(marker) in text
    assert "ufw delete allow 80/tcp || true" in text
    assert "rm -f" in text
    assert text.rstrip("\n").endswith("exit 0")


# ── install ──────────────────────────────────────────────────────────────────


def test_install_window_hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wh, "ACME_WINDOW_OPEN_HOOK", tmp_path / "pre" / "open.sh")
    monkeypatch.setattr(wh, "ACME_WINDOW_CLOSE_HOOK", tmp_path / "post" / "close.sh")
    assert wh.install_window_hooks() is True
    open_hook = tmp_path / "pre" / "open.sh"
    close_hook = tmp_path / "post" / "close.sh"
    assert open_hook.is_file() and close_hook.is_file()
    assert (open_hook.stat().st_mode & 0o777) == 0o755
    assert (close_hook.stat().st_mode & 0o777) == 0o755


# ── open/close окна ──────────────────────────────────────────────────────────


def test_open_window_sets_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "run" / "vds-acme-80-opened"
    calls: list[list[str]] = []

    def run(args, timeout=None):
        calls.append(list(args))
        return _R(ok=True, stdout="Rule added")

    monkeypatch.setattr(wh, "run_list", run)
    assert wh.open_80_window(marker) is True
    assert marker.is_file()
    assert calls[0][:3] == ["ufw", "allow", "80/tcp"]


def test_open_window_ufw_failure_no_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "marker"
    monkeypatch.setattr(wh, "run_list", lambda args, timeout=None: _R(ok=False, stderr="boom"))
    assert wh.open_80_window(marker) is False
    assert not marker.is_file()


def test_close_window_idempotent_without_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "marker"
    calls: list[list[str]] = []

    def run(args, timeout=None):
        calls.append(list(args))
        return _R(ok=True)

    monkeypatch.setattr(wh, "run_list", run)
    assert wh.close_80_window(marker) is True
    assert calls == []  # маркера нет — ufw не трогаем


def test_close_window_failure_keeps_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1-5: сбой delete не снимает маркер — периодический чек поймает."""
    marker = tmp_path / "marker"
    marker.write_text("", encoding="utf-8")
    monkeypatch.setattr(wh, "run_list", lambda args, timeout=None: _R(ok=False, stderr="boom"))
    assert wh.close_80_window(marker) is False
    assert marker.is_file()


# ── fail-safe периодический чек ──────────────────────────────────────────────


def _wire_ufw(monkeypatch: pytest.MonkeyPatch, open80: bool) -> list[list[str]]:
    calls: list[list[str]] = []
    rules = ["allow 80/tcp"] if open80 else []

    def run(args, timeout=None):
        calls.append(list(args))
        if args[:2] == ["ufw", "status"]:
            if not rules:
                return _R(ok=True, stdout="Status: inactive\n")
            lines = [
                "Status: active",
                "Default: deny (incoming), allow (outgoing)",
                "To                         Action      From",
                "--                         ------      ----",
            ]
            for r in rules:
                lines.append(f"{r.split(' ', 1)[1]:<26} ALLOW IN    Anywhere")
            return _R(ok=True, stdout="\n".join(lines) + "\n")
        if args[:3] == ["ufw", "show", "added"]:
            return _R(ok=True, stdout="Added user rules:\n" + "\n".join(f"ufw {r}" for r in rules))
        return _R(ok=True)

    monkeypatch.setattr(ufw, "run_list", run)
    monkeypatch.setattr(ufw, "command_exists", lambda name: name == "ufw")
    return calls


def test_check_warns_80_open_without_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """P1-5: post-hook упал до закрытия → 80 открыт вне окна → WARN (severity 2)."""
    _wire_ufw(monkeypatch, open80=True)
    severity, msg = wh.check_window_state(tmp_path / "absent-marker")
    assert severity == 2 and "вне окна" in msg


def test_check_cleans_stale_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_ufw(monkeypatch, open80=False)
    marker = tmp_path / "stale"
    marker.write_text("", encoding="utf-8")
    severity, msg = wh.check_window_state(marker)
    assert severity == 1
    assert not marker.is_file()


def test_check_ok_when_consistent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_ufw(monkeypatch, open80=False)
    severity, _ = wh.check_window_state(tmp_path / "absent")
    assert severity == 0


def test_run_check_window_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_ufw(monkeypatch, open80=False)
    assert wh.run_check_window() == 0
    _wire_ufw(monkeypatch, open80=True)
    assert wh.run_check_window() == 1
