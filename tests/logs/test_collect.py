"""Интеграция collect: Event + compute_delta БЕЗ мутации (M1, spy) + disk-cap.

Спи-тест подтверждает границу M1 SPEC §5.2: collect_event вызывает ТОЛЬКО
чистые load_snapshot/compute_delta из probing — save_snapshot и
update_threat не вызываются (мутация снапшота съела бы дельту окна
часового таймера probe-watch).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from src.gateway import probing
from src.logs.collect import collect_event, write_sample

from tests.logs import fixtures as fx

NOW = datetime(2026, 11, 16, 12, 5, 0, tzinfo=timezone.utc)


class FakeRunner:
    """run_list-мок: источник → ShellResult."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        from src.core.shell import ShellResult

        for key, res in self.mapping.items():
            if args[: len(key)] == list(key):
                return res
        return ShellResult(stdout="", stderr="", returncode=1)


def _res(stdout: str, code: int = 0):
    from src.core.shell import ShellResult

    return ShellResult(stdout=stdout, stderr="", returncode=code)


def _fake_run() -> FakeRunner:
    fresh_epoch = int(NOW.timestamp()) - 60  # handshake 60 c до NOW → fresh
    awg_text = f"FIXTURE_PUBKEY_AAA11111\t{fresh_epoch}\nFIXTURE_PUBKEY_BBB22222\t0\n"
    return FakeRunner({
        ("nft", "-j", "list"): _res(json.dumps(fx.NFT_JSON)),
        ("ss",): _res(fx.SS_TEXT),
        ("nstat",): _res(fx.NSTAT_TEXT),
        ("awg", "show"): _res(awg_text),
        ("systemctl", "show", "vds-xray.service"): _res("active\n"),
        ("systemctl", "show", "vds-xray.service", "-p", "NRestarts"): _res("0\n"),
        ("systemctl", "show", "vds-hysteria2.service"): _res("active\n"),
        ("hostname",): _res(""),
        ("journalctl",): _res(""),
    })


class TestCollectEventReadOnlyDelta:
    def test_delta_computed_no_mutation(self, monkeypatch, tmp_path):
        """M1: compute_delta in-process, save_snapshot/update_threat НЕ вызываются."""
        snapshot = {
            "version": 2,
            "ts": "2026-11-16T11:00:00",
            "syn_bare": 800,
            "syn_valid": 30,
            "udp_443": 10000,
            "probers": {"203.0.113.7": 15},
            "threat": {"level": "high", "reason": "RU-PROBE-SUSPECT 2 окна подряд"},
        }
        snap_file = tmp_path / "probe-watch.json"
        snap_file.write_text(json.dumps(snapshot), encoding="utf-8")

        called = {"save": 0, "threat": 0}

        def spy_save(*args, **kwargs):
            called["save"] += 1
            return True

        def spy_threat(*args, **kwargs):
            called["threat"] += 1
            raise AssertionError("update_threat запрещён в collect (M1)")

        monkeypatch.setattr(probing, "save_snapshot", spy_save)
        monkeypatch.setattr(probing, "update_threat", spy_threat)

        event, coverage = collect_event(run=_fake_run(), now=NOW, snapshot_path=snap_file)

        assert called["save"] == 0, "save_snapshot НЕ должен вызываться (M1)"
        assert called["threat"] == 0
        assert event["computed_by"] == "logs-collect (read-only)"

        probe = event["probe"]
        assert probe["delta"]["syn_bare"] == 12      # 812 - 800
        assert probe["delta"]["syn_valid"] == 7      # 37 - 30
        assert probe["delta"]["udp_443"] == 422      # 10422 - 10000
        # 203.0.113.7: 19-15=4>0; 198.51.100.9: нет в снапшоте → delta=2 —
        # оба активны в окне (compute_delta, ревью: протухший/новый элемент)
        assert probe["delta"]["unique_probers"] == 2
        assert probe["threat_level"] == "high"
        assert probe["verdict"] == "RU-PROBE-SUSPECT"  # из снапшота, не пересчёт

    def test_sources_in_event(self, monkeypatch, tmp_path):
        snap_file = tmp_path / "probe-watch.json"
        snap_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(
            "src.logs.collect.read_interface_counters",
            lambda base=None: {"eth0": {"rx_b": 1, "tx_b": 2}},
        )
        event, coverage = collect_event(run=_fake_run(), now=NOW, snapshot_path=snap_file)
        assert event["ss"]["estab_443"] == 4
        assert event["ss"]["zombie_443"] == 3
        assert event["awg"]["peers_fresh_lt180s"] == 1
        assert event["nstat"]["TcpExtTCPTimeouts"] == 1
        assert event["v"] == 1
        assert event["host"]
        for name in ("nft", "ss", "nstat", "awg", "probe", "net"):
            assert coverage[name]["status"] in ("ok", "missing", "partial")


class TestDiskCap:
    def test_disk_cap_90_refuses_write(self, monkeypatch, tmp_path):
        """§11: disk_pct > 90 — сэмплер отказывается писать (T-10)."""
        event = {
            "v": 1, "ts": "2026-11-16T12:05:00Z", "host": "test",
            "res": {"disk_pct": 95},
        }
        telemetry = tmp_path / "telemetry"
        telemetry.mkdir()
        path = write_sample(event, telemetry_dir=telemetry, lock_file=str(tmp_path / "l.lock"))
        assert path is None
        assert not list(telemetry.glob("*.ndjson"))

    def test_disk_ok_writes_0600(self, tmp_path):
        event = {
            "v": 1, "ts": "2026-11-16T12:05:00Z", "host": "test",
            "res": {"disk_pct": 41},
        }
        telemetry = tmp_path / "telemetry"
        telemetry.mkdir()
        path = write_sample(event, telemetry_dir=telemetry, lock_file=str(tmp_path / "l.lock"))
        assert path is not None
        assert path.stat().st_mode & 0o777 == 0o600
        lines = path.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["res"]["disk_pct"] == 41
