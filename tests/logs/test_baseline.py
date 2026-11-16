"""Тесты baseline (§7.8): 24 бакета hour_of_day, non-scorable floor, MAD."""
from __future__ import annotations

from src.logs.baseline import (
    METRIC_FLOORS,
    build_baseline,
    is_scorable_value,
    load_baseline,
    sample_hour,
    z_score,
)


def _sample(ts: str, syn_valid: int, udp_443: int = 20000, estab: int = 2) -> dict:
    return {
        "v": 1,
        "ts": ts,
        "nft": {"syn_bare": 100, "syn_valid": syn_valid, "udp_443": udp_443},
        "ss": {"estab_443": estab, "zombie_443": 0},
        "awg": {"peers_total": 1, "peers_fresh_lt180s": 1},
    }


class TestHourOfDay:
    def test_24_buckets_built(self):
        samples = [_sample(f"2026-11-16T{h:02d}:05:00Z", 40) for h in range(24)]
        baseline = build_baseline(samples, window_days=1)
        metrics = baseline["metrics"]
        assert len(metrics["syn_valid"]["hours"]) == 24
        # каждый бакет получил свой час
        for h, bucket in enumerate(metrics["syn_valid"]["hours"]):
            assert bucket["count"] == 1, f"час {h}"
            assert bucket["median"] == 40.0

    def test_bad_ts_ignored(self):
        samples = [{"v": 1, "ts": "garbage", "nft": {"syn_valid": 5}}]
        baseline = build_baseline(samples)
        assert baseline["samples_used"] == 0
        assert baseline["quality"] == "none"

    def test_sample_hour(self):
        assert sample_hour("2026-11-16T23:05:00Z") == 23
        assert sample_hour("garbage") == -1


class TestNonScorable:
    def test_mad_zero_not_scorable(self):
        # все значения одинаковые → MAD=0 → non-scorable
        samples = [_sample("2026-11-16T05:05:00Z", 40) for _ in range(30)]
        baseline = build_baseline(samples, window_days=1)
        bucket = baseline["metrics"]["syn_valid"]["hours"][5]
        assert bucket["mad"] == 0.0
        assert bucket["scorable"] is False
        assert z_score(400.0, bucket) is None  # static-режим: z не считается

    def test_median_below_floor_not_scorable(self):
        # медиана syn_valid=5 ниже absolute-floor 20 → static-skip (T-02/§7.8)
        samples = [_sample("2026-11-16T05:05:00Z", 5 + (i % 3)) for i in range(30)]
        baseline = build_baseline(samples, window_days=1)
        bucket = baseline["metrics"]["syn_valid"]["hours"][5]
        assert bucket["median"] < METRIC_FLOORS["syn_valid"]
        assert bucket["scorable"] is False

    def test_median_above_floor_scorable(self):
        samples = [_sample("2026-11-16T05:05:00Z", 40 + (i % 7)) for i in range(30)]
        baseline = build_baseline(samples, window_days=1)
        bucket = baseline["metrics"]["syn_valid"]["hours"][5]
        assert bucket["scorable"] is True
        assert z_score(1000.0, bucket) is not None

    def test_is_scorable_helper(self):
        assert is_scorable_value("syn_valid", median=0.0, mad=5.0) is False
        assert is_scorable_value("syn_valid", median=25.0, mad=5.0) is True
        assert is_scorable_value("syn_valid", median=25.0, mad=0.0) is False


class TestQuality:
    def test_cold_start_none(self):
        baseline = build_baseline([])
        assert baseline["quality"] == "none"

    def test_sparse_history_low(self):
        samples = [_sample("2026-11-16T05:05:00Z", 40)]
        baseline = build_baseline(samples, window_days=14)
        assert baseline["quality"] == "low"
        assert baseline["metrics"]["syn_valid"]["global"]["count"] == 1


class TestSaveLoad:
    def test_roundtrip(self, tmp_path):
        baseline = build_baseline([_sample("2026-11-16T05:05:00Z", 40)])
        path = tmp_path / "baseline.json"
        from src.logs.baseline import save_baseline

        assert save_baseline(baseline, path) is True
        assert path.stat().st_mode & 0o777 == 0o600
        loaded = load_baseline(path)
        assert loaded["version"] == baseline["version"]
        assert loaded["metrics"]["syn_valid"]["floor"] == METRIC_FLOORS["syn_valid"]

    def test_missing_returns_none(self, tmp_path):
        assert load_baseline(tmp_path / "nope.json") is None
