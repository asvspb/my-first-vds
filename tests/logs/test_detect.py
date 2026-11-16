"""Тесты правил detect T-01/T-02/T-03/T-04/T-08 + корреляция §7.6 (R-9)."""
from __future__ import annotations

import pytest

from src.logs.detect import (
    DEFAULT_THRESHOLDS,
    analyze_samples,
    correlate,
    evaluate_t01,
    evaluate_t02,
    evaluate_t03_t04,
    evaluate_t07_t08,
    max_severity,
    sample_deltas,
)

TH = dict(DEFAULT_THRESHOLDS)


def _window(ts: str, *, syn_valid_delta=5, udp_delta=20000, estab=4, zombie=3,
            timeouts=2, retrans=10, hy2="active", verdict="quiet",
            threat=("quiet", "")) -> dict:
    return {
        "ts": ts,
        "nft": {"syn_bare": 100, "syn_valid": syn_valid_delta, "udp_443": udp_delta},
        "nstat": {"TcpExtTCPTimeouts": timeouts, "TcpRetransSegs": retrans},
        "ss": {"estab_443": estab, "zombie_443": zombie, "synrecv_443": 0},
        "awg": {"peers_total": 1, "peers_fresh_lt180s": 1},
        "units": {"vds-hysteria2.service": {"state": hy2, "restarts": 0}},
        "journal": {},
        "probe": {"verdict": verdict, "threat_level": threat[0],
                  "threat_reason": threat[1], "delta": {}},
        "lockdown": {"active": False},
        "reset": False,
    }


class TestT01:
    def test_zombie_sockets_trigger(self):
        """T-01 ревью G2-2: data-phase blackhole = ESTABLISHED-зомби
        (retrans/Send-Q>0), НЕ исчезающие сокеты; 3 сэмпла подряд."""
        windows = [
            _window(f"2026-11-16T12:{m:02d}:00Z") for m in (0, 5, 10)
        ]
        findings = evaluate_t01(windows, TH)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        evidence_sources = {ev["source"] for ev in f["evidence"]}
        assert evidence_sources == {"nft", "ss", "kernel"}
        assert f["evidence"][1]["metric"] == "estab443_zombie_pct"
        assert f["evidence"][1]["value"] == pytest.approx(0.75)  # 3/4

    def test_no_client_activity_no_finding(self):
        """Guard §7.5: пустой сервер без клиентов — не blackhole (estab=0,
        AWG-handshake не свежий → guard не подтверждает активность)."""
        windows = []
        for m in (0, 5, 10):
            w = _window(f"2026-11-16T12:{m:02d}:00Z", estab=0, zombie=0)
            w["awg"] = {"peers_total": 0, "peers_fresh_lt180s": 0}
            windows.append(w)
        findings = evaluate_t01(windows, TH)
        assert findings == []

    def test_zombie_below_threshold_no_finding(self):
        windows = [_window(f"2026-11-16T12:{m:02d}:00Z", zombie=1) for m in (0, 5, 10)]
        assert evaluate_t01(windows, TH) == []  # 1/4 < 60%

    def test_two_consecutive_not_enough(self):
        windows = [_window("2026-11-16T12:00:00Z"), _window("2026-11-16T12:05:00Z")]
        assert evaluate_t01(windows, TH) == []


class TestT02:
    def _baseline_udp_median(self, median: float) -> dict:
        return {
            "quality": "high",
            "metrics": {
                "udp_443": {
                    "floor": 1000,
                    "hours": [
                        {"median": median, "mad": 100.0, "count": 40, "scorable": True}
                        for _ in range(24)
                    ],
                }
            },
        }

    def test_collapse_triggers(self):
        windows = [
            _window(f"2026-11-16T12:{m:02d}:00Z", udp_delta=100)  # <20% of 20000
            for m in (0, 5, 10, 15)
        ]
        findings = evaluate_t02(windows, self._baseline_udp_median(20000.0), TH)
        assert len(findings) == 1
        assert findings[0]["rule"] == "T-02"
        assert findings[0]["severity"] == "medium"

    def test_absolute_floor_skip(self):
        """T-02 ревью G2: median≈0 (ниже absolute-floor) — правило
        неприменимо (static-skip): нулевой UDP на простое — не аномалия."""
        windows = [
            _window(f"2026-11-16T12:{m:02d}:00Z", udp_delta=0)
            for m in (0, 5, 10, 15)
        ]
        findings = evaluate_t02(windows, self._baseline_udp_median(0.0), TH)
        assert findings == []

    def test_hy2_inactive_no_finding(self):
        windows = [
            _window(f"2026-11-16T12:{m:02d}:00Z", udp_delta=100, hy2="inactive")
            for m in (0, 5, 10, 15)
        ]
        findings = evaluate_t02(windows, self._baseline_udp_median(20000.0), TH)
        assert findings == []


class TestT03T04:
    def test_verdicts_consumed_not_recomputed(self):
        """R-8: анализатор потребляет вердикт probe-watch, не пересчитывает."""
        windows = [
            _window("2026-11-16T12:00:00Z", verdict="RU-PROBE-SUSPECT",
                    threat=("high", "RU-PROBE-SUSPECT 2 окна подряд")),
            _window("2026-11-16T12:05:00Z", verdict="PROBE-BURST",
                    threat=("elevated", "PROBE-BURST")),
        ]
        findings = evaluate_t03_t04(windows)
        rules = [f["rule"] for f in findings]
        assert rules == ["T-03", "T-04"]
        assert findings[0]["severity"] == "high"
        assert findings[1]["severity"] == "info"

    def test_quiet_no_findings(self):
        assert evaluate_t03_t04([_window("2026-11-16T12:00:00Z")]) == []


class TestT07T08:
    def test_ch_len_517_does_not_trigger(self):
        """T-08 ревью G2 (И41): нормальный ClientHello 517–1300 Б —
        НЕ мусор (<209/>214 давали 100% FP на PQ-Kyber)."""
        pcap = {
            "start": "2026-11-16T12:00:00Z",
            "end": "2026-11-16T12:10:00Z",
            "client_hellos": [
                {"ch_len": 517, "first_byte": 0x16, "src_ip": "203.0.113.7"}
                for _ in range(10)
            ],
        }
        findings = evaluate_t07_t08(pcap, TH)
        assert [f["rule"] for f in findings] == ["T-07"]  # серия есть, мусора нет

    def test_garbage_and_short_ch_trigger(self):
        pcap = {
            "start": "2026-11-16T12:00:00Z",
            "end": "2026-11-16T12:10:00Z",
            "client_hellos": [
                {"ch_len": 60, "first_byte": 0x47},   # не-TLS мусор
                {"ch_len": 100, "first_byte": 0x16},  # короткий «сканер»
                {"ch_len": 512, "first_byte": 0x47},
            ],
        }
        findings = evaluate_t07_t08(pcap, TH)
        rules = sorted(f["rule"] for f in findings)
        assert rules == ["T-08"]

    def test_missing_pcap_silent(self):
        assert evaluate_t07_t08(None, TH) == []  # coverage missing, не «чисто»


class TestCorrelate:
    def test_single_finding_never_probing_plus_effect(self):
        assert correlate([{"rule": "T-03"}])[0] == "probing_only"
        assert correlate([{"rule": "T-01"}])[0] == "effect_only"

    def test_probing_plus_effect(self):
        assert correlate([{"rule": "T-03"}, {"rule": "T-01"}])[0] == "probing_plus_effect"

    def test_local_fault(self):
        assert correlate([{"rule": "T-09"}, {"rule": "T-10"}])[0] == "local_fault"


class TestAnalyzeSamples:
    def test_reset_delta_handled(self):
        """§6.1: отрицательная дельта = reset (переустановка nft/ребут)."""
        samples = [
            {"v": 1, "ts": "2026-11-16T12:00:00Z", "nft": {"syn_valid": 500, "udp_443": 5000}},
            {"v": 1, "ts": "2026-11-16T12:05:00Z", "nft": {"syn_valid": 3, "udp_443": 20}},
        ]
        windows = sample_deltas(samples)
        assert windows[0]["reset"] is True
        assert windows[0]["nft"]["syn_valid"] == 3  # вся текущая часть за окно

    def test_critical_missing_inconclusive(self):
        """§7.2: нет nft+probe+kernel → verdict inconclusive, high запрещён."""
        samples = [
            {"v": 1, "ts": "2026-11-16T12:00:00Z"},
            {"v": 1, "ts": "2026-11-16T12:05:00Z"},
        ]
        coverage = {"nft": {"status": "missing"}, "probe": {"status": "missing"},
                    "kernel": {"status": "missing"}}
        report = analyze_samples(samples, None, coverage=coverage)
        assert report["summary"]["verdict"] == "inconclusive"
        for f in report["findings"]:
            assert f["confidence"] != "high"

    def test_no_reactions_in_output(self):
        """R-9: выход только отчёт — рекомендация, не исполнение; в JSON нет
        полей-команд (никаких ufw/lock/restart-инструкций как действий)."""
        report = analyze_samples(
            [{"v": 1, "ts": "2026-11-16T12:00:00Z"}], None,
            coverage={"nft": {"status": "ok"}},
        )
        assert set(report["summary"].keys()) == {"verdict", "action", "headline"}
        dumped = json_dump(report).lower()
        for forbidden in ("ufw lock", "systemctl restart", "iptables ", "nft add", "nft delete"):
            assert forbidden not in dumped, f"R-9: отчёт содержит команду {forbidden!r}"

    def test_max_severity_exit_mapping(self):
        report = {"findings": [{"severity": "medium"}]}
        assert max_severity(report) == "medium"
        assert max_severity({"findings": []}) == "info"


def json_dump(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False)
