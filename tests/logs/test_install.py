"""Тесты thresholds-override, capture BPF и install (dry-run/fs-часть)."""
from __future__ import annotations

import json

import pytest

from src.logs.capture import bpf_filter
from src.logs.detect import DEFAULT_THRESHOLDS, load_thresholds


class TestThresholdsOverride:
    def test_fallback_defaults(self, tmp_path):
        th, rules_hash = load_thresholds(tmp_path / "no-rules.json")
        assert th == DEFAULT_THRESHOLDS
        assert len(rules_hash) == 12

    def test_override_applied(self, tmp_path):
        rules = tmp_path / "rules.json"
        rules.write_text(json.dumps({"t05_auth_fail_per_10m": 50}), encoding="utf-8")
        th, _ = load_thresholds(rules)
        assert th["t05_auth_fail_per_10m"] == 50
        assert th["t01_zombie_pct"] == DEFAULT_THRESHOLDS["t01_zombie_pct"]

    def test_unknown_keys_ignored(self, tmp_path):
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps({"hacker_key": 1, "t01_zombie_pct": "not-a-number"}),
            encoding="utf-8",
        )
        th, _ = load_thresholds(rules)
        assert "hacker_key" not in th
        assert th["t01_zombie_pct"] == DEFAULT_THRESHOLDS["t01_zombie_pct"]


class TestBpfFilter:
    def test_starts_with_ip_and(self):
        """§8.1 ревью G2: classic BPF tcp[n] не работает для IPv6 — BPF обязан
        начинаться с `ip and` (иначе на asv2 с /48 tcpdump упадёт)."""
        filt = bpf_filter(["203.0.113.5"])
        assert filt.startswith(
            "ip and tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-push) != 0)"
        )

    def test_multiple_hosts_grouped_not_chained(self):
        """§8.1: несколько собственных IP → `and not (host A or host B …)`."""
        filt = bpf_filter(["203.0.113.5", "203.0.113.6"])
        assert "not (host 203.0.113.5 or host 203.0.113.6)" in filt
        assert "not host 203.0.113.5 and not host" not in filt

    def test_private_ranges_excluded(self):
        filt = bpf_filter([])
        assert "not net 10.0.0.0/8" in filt
        assert "not net 172.16.0.0/12" in filt
        assert "not net 192.168.0.0/16" in filt


class TestInstallFilesystem:
    """fs-часть install (без systemctl): dry-run ничего не пишет; apply
    создаёт 0700/0600; повтор идемпотентен. Пути подменяются monkeypatch."""

    @pytest.fixture()
    def tmp_paths(self, monkeypatch, tmp_path):
        from src.logs import paths as logs_paths

        monkeypatch.setattr(logs_paths, "TELEMETRY_DIR", tmp_path / "telemetry")
        monkeypatch.setattr(logs_paths, "CAPTURES_DIR", tmp_path / "captures")
        monkeypatch.setattr(logs_paths, "BUNDLES_DIR", tmp_path / "bundles")
        monkeypatch.setattr(logs_paths, "REPORTS_DIR", tmp_path / "reports")
        monkeypatch.setattr(logs_paths, "HMAC_KEY_FILE", tmp_path / "hmac.key")
        monkeypatch.setattr(logs_paths, "RULES_FILE", tmp_path / "rules.json")
        monkeypatch.setattr(logs_paths, "INSTALL_STATE_FILE", tmp_path / "install-state.json")
        return tmp_path, logs_paths

    def test_dry_run_writes_nothing(self, tmp_paths):
        from src.logs.install import cmd_install

        tmp_path, logs_paths = tmp_paths
        assert cmd_install(apply=False) == 0
        assert list(tmp_path.iterdir()) == []

    def test_apply_fs_part_idempotent(self, tmp_paths):
        from src.logs.install import _ensure_hmac_key, _ensure_rules_default, _make_dirs

        _tmp, logs_paths = tmp_paths
        assert len(_make_dirs(dry_run=False)) == 4
        assert logs_paths.TELEMETRY_DIR.is_dir()
        key_created, key_path = _ensure_hmac_key(dry_run=False)
        assert key_created and key_path
        assert oct(logs_paths.HMAC_KEY_FILE.stat().st_mode & 0o777) == "0o600"
        rules_created, _ = _ensure_rules_default(dry_run=False)
        assert rules_created
        # идемпотентность: повтор — ничего нового
        assert _make_dirs(dry_run=False) == []
        assert _ensure_hmac_key(dry_run=False) == (False, key_path)
        assert _ensure_rules_default(dry_run=False) == (False, str(logs_paths.RULES_FILE))

    def test_journal_roundtrip(self, tmp_path):
        from src.logs.install import _read_journal, _write_journal

        path = tmp_path / "install-state.json"
        state = {"version": 1, "units": ["vds-logs-sample.service"]}
        assert _write_journal(state, path) is True
        assert _read_journal(path) == state
        assert _read_journal(tmp_path / "missing.json") == {}

    def test_sample_unit_allows_runtime_lock(self):
        """`logs sample` берёт `/var/run/vds-logs.lock`; при
        ProtectSystem=strict каталог обязан быть в ReadWritePaths, иначе
        FileLock падает EROFS (живой дефект asv2 2026-11-16)."""
        from pathlib import Path

        tpl = Path(__file__).resolve().parents[2] / "systemd" / "vds-logs-sample.service.tpl"
        line = next(
            line for line in tpl.read_text(encoding="utf-8").splitlines()
            if line.startswith("ReadWritePaths=")
        )
        assert "/var/run" in line.split()
