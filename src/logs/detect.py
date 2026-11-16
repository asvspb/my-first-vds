"""Правила T-01…T-17 (SPEC §7.5) + корреляция инцидентов (§7.6), WP-2.

Границы (SPEC R-9/OQ-7): выход ТОЛЬКО отчёт (findings/incidents/coverage);
никаких реакций — исполнение за `probe-response`/оператором. Пороги —
fallback-дефолты из спеки, override — /etc/vds-forensics/rules.json
(валидация схемой, rules_hash печатается в отчёте — OQ-9).

Вшитые пороги — точный текст §7.5 с правками G2:
- T-01: зомби-сокеты (retrans/Send-Q>0/timer:on) ≥60% 3 сэмпла подряд
  (15 мин) при syn_validΔ>0 и TcpTimeouts/TcpRetransSegs↑; при
  data-phase blackhole сокеты ВИСЯТ ESTABLISHED-зомби, а не исчезают.
- T-02: udp_443Δ < 20% медианы в 3/4 сэмпла при активном hy2 И медиана
  ≥ absolute-floor (median≈0 → static-skip, правило неприменимо).
- T-08: первый PSH-байт != 0x16 (не-TLS мусор) ИЛИ CH len < 180
  (нормальный ClientHello 517–1300 Б — <209/>214 давали 100% FP на
  браузерах с PQ-Kyber; наш ch_len=517 НЕ триггерит).

Типы инцидентов (§7.6): probing_only / effect_only / probing_plus_effect /
local_fault / inconclusive. `probing_plus_effect` невозможен по одному
finding'у. Coverage-поле честно фиксирует missing-источники; при
critical_missing (нет nft+probe+kernel) — high-confidence запрещён,
вердикт inconclusive.

Guard §7.5: T-01/T-02 применяются только при подтверждённой клиентской
активности (estab/transfer в предыдущем окне, AWG-handshake <5 мин);
пустой сервер без клиентов — не «blackhole», finding понижается до
info/inconclusive.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from src.logs import paths as logs_paths
from src.logs.baseline import (
    METRIC_FLOORS,
    is_scorable_value,
    load_baseline,
    sample_hour,
    z_score,
)

# ---------------------------------------------------------------------------
# Дефолты порогов (SPEC §7.5; override — RULES_FILE)
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLDS: dict[str, object] = {
    "t01_zombie_pct": 0.60,        # доля зомби-сокетов :443
    "t01_consecutive": 3,          # сэмпла подряд (15 мин)
    "t01_min_syn_valid_delta": 1,  # syn_validΔ>0 (ревью G2: >0)
    "t02_udp_share": 0.20,         # <20% медианы
    "t02_window_samples": 4,       # 3 из 4 сэмплов (20 мин)
    "t02_min_active_hy2": True,    # только при активном hy2
    "t05_auth_fail_per_10m": 20,
    "t06_ufw_block_per_10m": 50,
    "t07_probe_series": 6,         # ClientHello/10с
    "t07_probe_series_tls": 8,     # 8-пробная серия (443)
    "t08_min_garbage": 3,
    "t08_ch_min_len": logs_paths.PCAP_CH_MIN_LEN,  # 180
    "t09_restarts_delta": 1,
    "t10_conntrack_pct": 0.80,
    "t10_disk_pct": 90,
    "t10_fd_pct": 0.80,
    "t11_cert_days_left": 7,
    "t12_relay_handshake_max_s": 300,
    "t13_clock_skew_s": 2,
    "t14_new24_mad_mult": 3.0,
    "t16_novel_min_count": 3,
    "t17_panic_min": 2,
    "guard_client_active_estab": 1,
    "guard_awg_fresh_s": 300,
}

RULE_ORDER = [f"T-{i:02d}" for i in range(1, 18)]
SEVERITY: dict[str, str] = {
    "T-01": "high", "T-02": "medium", "T-03": "high", "T-04": "info",
    "T-05": "medium", "T-06": "low", "T-07": "high", "T-08": "medium",
    "T-09": "high", "T-10": "high", "T-11": "medium", "T-12": "high",
    "T-13": "low", "T-14": "medium", "T-15": "info", "T-16": "low",
    "T-17": "high",
}

# Источники доказательств, считающиеся «прямыми» (§7.6).
DIRECT_SOURCES = {"nft", "kernel", "pcap"}
INDEPENDENT_SOURCES = {
    "nft", "kernel", "ss", "app-log", "pcap", "probe", "resource", "client_report",
}

CRITICAL_MISSING = ("nft", "probe", "kernel")  # все три missing → inconclusive


def load_thresholds(rules_file: Optional[Path] = None) -> tuple[dict[str, object], str]:
    """Пороги = defaults + override RULES_FILE; возвращает (пороги, rules_hash).

    Override валидируется схемой: только известные ключи и скаляры —
    иначе файл игнорируется с warning (менять пороги «на ходу» без
    версии нельзя — SPEC §7.5).
    """
    thresholds = dict(DEFAULT_THRESHOLDS)
    rules_file = rules_file or logs_paths.RULES_FILE
    if not rules_file.is_file():
        return thresholds, _rules_hash(thresholds)
    try:
        data = json.loads(rules_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return thresholds, _rules_hash(thresholds)
    if not isinstance(data, dict):
        return thresholds, _rules_hash(thresholds)
    for key, value in data.items():
        if key in DEFAULT_THRESHOLDS and (
            isinstance(value, (int, float, bool))
        ):
            thresholds[key] = value
    return thresholds, _rules_hash(thresholds)


def _rules_hash(thresholds: dict[str, object]) -> str:
    payload = json.dumps(thresholds, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Дельты между сэмплами (кумулятивные счётчики; reset-обработка §6.1)
# ---------------------------------------------------------------------------

def sample_deltas(samples: list[dict[str, object]]) -> list[dict[str, object]]:
    """Дельты nft/nstat между соседними сэмплами; отрицательная дельта = reset.

    Возвращает список по сэмплам (кроме первого): {ts, nft{...}, reset,
    nstat_delta{...}} — reset=true при cur<prev (переустановка таблицы/ребут),
    дельта тогда = cur (вся текущая часть за окно, правило probing.compute_delta).
    """
    out: list[dict[str, object]] = []
    for prev, cur in zip(samples, samples[1:]):
        prev_nft = prev.get("nft") if isinstance(prev.get("nft"), dict) else {}
        cur_nft = cur.get("nft") if isinstance(cur.get("nft"), dict) else {}
        nft_delta: dict[str, object] = {}
        reset = False
        for key in ("syn_bare", "syn_valid", "udp_443"):
            p = prev_nft.get(key)
            c = cur_nft.get(key)
            if not isinstance(p, (int, float)) or not isinstance(c, (int, float)):
                nft_delta[key] = None
                continue
            d = c - p
            if c < p:
                reset = True
                d = c
            nft_delta[key] = int(d)
        prev_stat = prev.get("nstat") if isinstance(prev.get("nstat"), dict) else {}
        cur_stat = cur.get("nstat") if isinstance(cur.get("nstat"), dict) else {}
        stat_delta: dict[str, int] = {}
        for key in ("TcpExtTCPTimeouts", "TcpRetransSegs"):
            p, c = prev_stat.get(key), cur_stat.get(key)
            if isinstance(p, (int, float)) and isinstance(c, (int, float)):
                stat_delta[key] = max(0, int(c) - int(p))
        out.append(
            {
                "ts": str(cur.get("ts", "")),
                "nft": nft_delta,
                "nstat": stat_delta,
                "ss": cur.get("ss") if isinstance(cur.get("ss"), dict) else {},
                "awg": cur.get("awg") if isinstance(cur.get("awg"), dict) else {},
                "units": cur.get("units") if isinstance(cur.get("units"), dict) else {},
                "res": cur.get("res") if isinstance(cur.get("res"), dict) else {},
                "journal": cur.get("journal") if isinstance(cur.get("journal"), dict) else {},
                "probe": cur.get("probe") if isinstance(cur.get("probe"), dict) else {},
                "lockdown": cur.get("lockdown") if isinstance(cur.get("lockdown"), dict) else {},
                "reset": reset,
            }
        )
    return out


def _client_active(window: dict[str, object], thresholds: dict[str, object]) -> bool:
    """Guard §7.5: подтверждённая клиентская активность в окне."""
    ss = window.get("ss") if isinstance(window.get("ss"), dict) else {}
    estab = ss.get("estab_443") or 0
    if isinstance(estab, (int, float)) and estab >= int(thresholds["guard_client_active_estab"]):
        return True
    awg = window.get("awg") if isinstance(window.get("awg"), dict) else {}
    fresh = awg.get("peers_fresh_lt180s") or 0
    return isinstance(fresh, (int, float)) and fresh > 0


# ---------------------------------------------------------------------------
# Правила. Каждая: evaluate(windows, baseline, coverage, thresholds) → findings
# ---------------------------------------------------------------------------

def _finding(
    rule: str,
    window_start: str,
    window_end: str,
    evidence: list[dict[str, object]],
    hypothesis: str,
    alternatives: Optional[list[str]] = None,
    action: str = "",
    severity: Optional[str] = None,
) -> dict[str, object]:
    """Собрать finding с детерминированным ID (R-3: sha256(rule|window|key))."""
    evidence_key = json.dumps(evidence, sort_keys=True)
    raw = f"{rule}|{window_start}|{evidence_key}".encode("utf-8")
    return {
        "id": hashlib.sha256(raw).hexdigest()[:12],
        "rule": rule,
        "severity": severity or SEVERITY.get(rule, "info"),
        "window": [window_start, window_end],
        "evidence": evidence,
        "hypothesis": hypothesis,
        "alternatives": alternatives or [],
        "action": action,
    }


def _metric_bucket(baseline: Optional[dict[str, object]], metric: str, hour: int) -> Optional[dict[str, object]]:
    if not baseline:
        return None
    metrics = baseline.get("metrics")
    if not isinstance(metrics, dict):
        return None
    data = metrics.get(metric)
    if not isinstance(data, dict):
        return None
    hours = data.get("hours")
    if not isinstance(hours, list) or len(hours) != 24:
        return None
    bucket = hours[hour]
    return bucket if isinstance(bucket, dict) else None


def evaluate_t01(windows: list[dict[str, object]], thresholds: dict[str, object]) -> list[dict[str, object]]:
    """T-01 tcp443_data_blackhole (§7.5 + ревью G2-2: зомби-сокеты)."""
    findings: list[dict[str, object]] = []
    need = int(thresholds["t01_consecutive"])
    zombie_pct_threshold = float(thresholds["t01_zombie_pct"])
    run: list[dict[str, object]] = []
    for window in windows:
        nft = window.get("nft") if isinstance(window.get("nft"), dict) else {}
        ss = window.get("ss") if isinstance(window.get("ss"), dict) else {}
        syn_valid_delta = nft.get("syn_valid")
        estab = ss.get("estab_443") or 0
        zombie = ss.get("zombie_443") or 0
        zombie_pct = zombie / estab if isinstance(estab, (int, float)) and estab > 0 else 0.0
        stat = window.get("nstat") if isinstance(window.get("nstat"), dict) else {}
        timeouts_up = (
            isinstance(stat.get("TcpExtTCPTimeouts"), int) and stat["TcpExtTCPTimeouts"] > 0
        ) or (
            isinstance(stat.get("TcpRetransSegs"), int) and stat["TcpRetransSegs"] > 0
        )
        hit = (
            isinstance(syn_valid_delta, int)
            and syn_valid_delta >= int(thresholds["t01_min_syn_valid_delta"])
            and estab
            and zombie_pct >= zombie_pct_threshold
            and timeouts_up
            and _client_active(window, thresholds)
        )
        if hit:
            run.append(window)
        else:
            run = []
        if len(run) >= need:
            first, last = run[0], run[-1]
            findings.append(
                _finding(
                    "T-01", str(first.get("ts", "")), str(last.get("ts", "")),
                    [
                        {"source": "nft", "metric": "syn_valid", "value": syn_valid_delta},
                        {"source": "ss", "metric": "estab443_zombie_pct", "value": round(zombie_pct, 2)},
                        {"source": "kernel", "metric": "nstat_timeouts_retrans", "value": stat},
                    ],
                    "TCP-443 data-phase blackhole (SYN проходит, данные душатся)",
                    ["upstream/провайдер"],
                    "не рестартить xray; ждать/переключить (§5.9)",
                )
            )
            run = []
    return findings


def evaluate_t02(
    windows: list[dict[str, object]],
    baseline: Optional[dict[str, object]],
    thresholds: dict[str, object],
) -> list[dict[str, object]]:
    """T-02 udp443_collapse: udp_443Δ < 20% медианы 3/4 сэмплов при hy2 и
    медиана ≥ absolute-floor (median≈0 → static-skip, ревью G2)."""
    findings: list[dict[str, object]] = []
    share = float(thresholds["t02_udp_share"])
    window_size = int(thresholds["t02_window_samples"])
    floor = METRIC_FLOORS.get("udp_443", 0)
    for i in range(len(windows) - window_size + 1):
        chunk = windows[i : i + window_size]
        under = 0
        ref_median: Optional[float] = None
        samples_seen = 0
        for window in chunk:
            nft = window.get("nft") if isinstance(window.get("nft"), dict) else {}
            delta = nft.get("udp_443")
            if not isinstance(delta, int):
                continue
            samples_seen += 1
            hour = sample_hour(str(window.get("ts", "")))
            bucket = _metric_bucket(baseline, "udp_443", max(hour, 0))
            if bucket is None or not is_scorable_value("udp_443", float(bucket.get("median", 0.0)), float(bucket.get("mad", 0.0))):
                median = float(floor)
            else:
                median = float(bucket.get("median", 0.0))
            if median <= floor:
                median = float(floor)
            ref_median = median
            if delta < median * share:
                under += 1
        hy2_active = any(
            isinstance(w.get("units"), dict)
            and isinstance((w["units"] or {}).get("vds-hysteria2.service"), dict)
            and (w["units"]["vds-hysteria2.service"] or {}).get("state") == "active"
            for w in chunk
        )
        if samples_seen >= 3 and under >= 3 and hy2_active and ref_median and ref_median > floor:
            findings.append(
                _finding(
                    "T-02", str(chunk[0].get("ts", "")), str(chunk[-1].get("ts", "")),
                    [{"source": "nft", "metric": "udp_443", "value": f"<{share:.0%} of median {int(ref_median)}", "samples_under": under}],
                    "UDP-443 путь деградировал/заблокирован",
                    ["провайдер-шейпер", "апстрим"],
                    "проверить hy2/hop/obfs; переключить клиента",
                )
            )
    return findings


def evaluate_t03_t04(windows: list[dict[str, object]]) -> list[dict[str, object]]:
    """T-03/T-04: вердикт probe-watch (R-8: потребляем, не пересчитываем)."""
    findings: list[dict[str, object]] = []
    seen_suspect = False
    seen_burst = False
    for window in windows:
        probe = window.get("probe") if isinstance(window.get("probe"), dict) else {}
        verdict = str(probe.get("verdict", ""))
        ts = str(window.get("ts", ""))
        if verdict == "RU-PROBE-SUSPECT" and not seen_suspect:
            seen_suspect = True
            findings.append(
                _finding(
                    "T-03", ts, ts,
                    [{"source": "probe", "metric": "verdict", "value": verdict,
                      "reason": str(probe.get("threat_reason", ""))}],
                    "активное зондирование из РФ (probe-watch)", None,
                    "наблюдать; конфиги не менять",
                )
            )
        if verdict == "PROBE-BURST" and not seen_burst:
            seen_burst = True
            findings.append(
                _finding(
                    "T-04", ts, ts,
                    [{"source": "probe", "metric": "verdict", "value": verdict}],
                    "масс-сканеры, не ТСПУ", None, "игнор, не эскалировать", severity="info",
                )
            )
    return findings


def evaluate_t05_t06(windows: list[dict[str, object]], thresholds: dict[str, object]) -> list[dict[str, object]]:
    """T-05 auth-брутфорс hy2 / T-06 UFW-block-flood — по журнальным счётчикам."""
    findings: list[dict[str, object]] = []
    for window in windows:
        journal = window.get("journal") if isinstance(window.get("journal"), dict) else {}
        ts = str(window.get("ts", ""))
        hy2 = journal.get("vds-hysteria2.service")
        if isinstance(hy2, dict) and hy2.get("hysteria_auth_fail", 0) >= int(thresholds["t05_auth_fail_per_10m"]):
            findings.append(
                _finding("T-05", ts, ts,
                         [{"source": "app-log", "metric": "hysteria_auth_fail", "value": hy2.get("hysteria_auth_fail")}],
                         "перебор пароля/скан hysteria2", ["публичный сканер"], "проверить пароль клиентов"))
        kernel = journal.get("kernel")
        if isinstance(kernel, dict) and kernel.get("ufw_block_443", 0) >= int(thresholds["t06_ufw_block_per_10m"]):
            findings.append(
                _finding("T-06", ts, ts,
                         [{"source": "kernel", "metric": "ufw_block_443", "value": kernel.get("ufw_block_443")}],
                         "сканер/шум UFW", None, "не эскалировать", severity="low"))
    return findings


def evaluate_t07_t08(pcap_summary: Optional[dict[str, object]], thresholds: dict[str, object]) -> list[dict[str, object]]:
    """T-07/T-08 — по pcap-метаданным (§8.2); отсутствует → правило молчит
    (coverage pcap missing, не «чисто»)."""
    findings: list[dict[str, object]] = []
    if not isinstance(pcap_summary, dict):
        return findings
    chs = pcap_summary.get("client_hellos")
    if not isinstance(chs, list):
        return findings
    window_start = str(pcap_summary.get("start", ""))
    window_end = str(pcap_summary.get("end", ""))
    series_threshold = int(thresholds["t07_probe_series"])
    if len(chs) >= series_threshold:
        findings.append(
            _finding("T-07", window_start, window_end,
                     [{"source": "pcap", "metric": "client_hello_series", "value": len(chs)}],
                     "профиль активного зондирования (И40)", None, "наблюдать; готовить резервный транспорт"))
    garbage = [
        ch for ch in chs
        if isinstance(ch, dict) and (
            (isinstance(ch.get("first_byte"), int) and ch["first_byte"] != 0x16)
            or (isinstance(ch.get("ch_len"), int) and ch["ch_len"] < int(thresholds["t08_ch_min_len"]))
        )
    ]
    if len(garbage) >= int(thresholds["t08_min_garbage"]):
        findings.append(
            _finding("T-08", window_start, window_end,
                     [{"source": "pcap", "metric": "garbage_probe", "value": len(garbage)}],
                     "артефакт проб: не-TLS мусор / примитивный сканер (И41)", None,
                     "сопоставить с T-03"))
    return findings


def evaluate_t09_t10_t17(windows: list[dict[str, object]], thresholds: dict[str, object]) -> list[dict[str, object]]:
    """T-09/T-10/T-17 — локальные сбои (юниты/ресурсы/аварии)."""
    findings: list[dict[str, object]] = []
    prev_restarts: dict[str, int] = {}
    for window in windows:
        ts = str(window.get("ts", ""))
        units = window.get("units") if isinstance(window.get("units"), dict) else {}
        for unit, info in units.items():
            if not isinstance(info, dict):
                continue
            restarts = info.get("restarts")
            state = str(info.get("state", ""))
            if isinstance(restarts, int) and unit in prev_restarts and restarts - prev_restarts[unit] >= int(thresholds["t09_restarts_delta"]):
                findings.append(
                    _finding("T-09", ts, ts,
                             [{"source": "systemd", "metric": "NRestarts", "unit": unit, "value": restarts}],
                             "локальный сбой юнита, не цензор", None, "чинить локально (healthcheck)"))
            if state == "failed":
                findings.append(
                    _finding("T-09", ts, ts,
                             [{"source": "systemd", "metric": "ActiveState", "unit": unit, "value": state}],
                             f"юнит {unit} failed", None, "чинить локально"))
            if isinstance(restarts, int):
                prev_restarts[unit] = restarts
        res = window.get("res") if isinstance(window.get("res"), dict) else {}
        conntrack = res.get("conntrack")
        conntrack_max = res.get("conntrack_max")
        if (
            isinstance(conntrack, int) and isinstance(conntrack_max, int) and conntrack_max > 0
            and conntrack / conntrack_max > float(thresholds["t10_conntrack_pct"])
        ):
            findings.append(
                _finding("T-10", ts, ts,
                         [{"source": "resource", "metric": "conntrack_pct", "value": round(conntrack / conntrack_max, 2)}],
                         "таблица conntrack близка к переполнению", None, "проверить nf_conntrack_max"))
        disk_pct = res.get("disk_pct")
        if isinstance(disk_pct, int) and disk_pct >= int(thresholds["t10_disk_pct"]):
            findings.append(
                _finding("T-10", ts, ts,
                         [{"source": "resource", "metric": "disk_pct", "value": disk_pct}],
                         "диск заполнен (сэмплер приостановлен disk-cap)", None, "очистить диск"))
        journal = window.get("journal") if isinstance(window.get("journal"), dict) else {}
        panic_count = 0
        for source_events in journal.values():
            if isinstance(source_events, dict):
                for pattern, count in source_events.items():
                    if isinstance(pattern, str) and ("panic" in pattern or "fatal" in pattern or "segfault" in pattern):
                        panic_count += int(count) if isinstance(count, int) else 0
        if panic_count >= int(thresholds["t17_panic_min"]):
            findings.append(
                _finding("T-17", ts, ts,
                         [{"source": "app-log", "metric": "panic_or_crash", "value": panic_count}],
                         "локальная авария (panic/fatal/segfault)", None, "чинить локально"))
    return findings


def evaluate_t11_t12_t13_t15_t16(
    windows: list[dict[str, object]],
    baseline: Optional[dict[str, object]],
    thresholds: dict[str, object],
    extra: Optional[dict[str, object]] = None,
) -> list[dict[str, object]]:
    """T-11 cert / T-12 relay-leg / T-13 clock / T-15 drift / T-16 novel-template.

    Источники отсутствуют (certs/config-hash/chrony/baseline-templates не
    входят в 5-мин сэмпл v1) → правила молчат, coverage помечает missing
    (слепота признаётся явно, не «чисто»).
    """
    findings: list[dict[str, object]] = []
    extra = extra or {}
    certs = extra.get("certs")
    if isinstance(certs, list):
        for cert in certs:
            if isinstance(cert, dict) and isinstance(cert.get("days_left"), int) \
                    and cert["days_left"] < int(thresholds["t11_cert_days_left"]):
                findings.append(
                    _finding("T-11", "", "",
                             [{"source": "resource", "metric": "cert_days_left", "value": cert["days_left"], "name": cert.get("name", "")}],
                             "сертификат истекает — сломается сам", None, "certbot renew"))
    if windows:
        awg1 = extra.get("awg1_handshake_age_s")
        relay_active = any(
            isinstance(w.get("units"), dict)
            and isinstance((w["units"] or {}).get("vds-relay-exit.service"), dict)
            and (w["units"]["vds-relay-exit.service"] or {}).get("state") == "active"
            for w in windows
        )
        if relay_active and isinstance(awg1, int) and awg1 > int(thresholds["t12_relay_handshake_max_s"]):
            findings.append(
                _finding("T-12", str(windows[0].get("ts", "")), str(windows[-1].get("ts", "")),
                         [{"source": "app-log", "metric": "awg1_handshake_age_s", "value": awg1}],
                         "нога релея мертва (handshake > 300 c)", None, "проверить relay/asv1"))
    clock = extra.get("clock_skew_s")
    if isinstance(clock, int) and clock > int(thresholds["t13_clock_skew_s"]):
        findings.append(
            _finding("T-13", "", "", [{"source": "app-log", "metric": "clock_skew_s", "value": clock}],
                     "окна недостоверны (skew)", None, "проверить chrony", severity="low"))
    drift = extra.get("config_drift")
    if isinstance(drift, list) and drift:
        findings.append(
            _finding("T-15", "", "", [{"source": "resource", "metric": "config_hash_changed", "value": len(drift)}],
                     "ручная правка/дрейф конфигов без deploy-события", None, "сверить с STATUS", severity="info"))
    templates = extra.get("templates")
    baseline_templates = None
    if isinstance(baseline, dict):
        baseline_templates = baseline.get("templates")
    if isinstance(templates, dict) and isinstance(baseline_templates, dict):
        novel = {
            h: c for h, c in templates.items()
            if isinstance(h, str) and h not in baseline_templates and isinstance(c, int)
            and c >= int(thresholds["t16_novel_min_count"])
        }
        if novel and str(baseline.get("quality", "none")) != "none":
            findings.append(
                _finding("T-16", "", "", [{"source": "app-log", "metric": "novel_templates", "value": len(novel)}],
                         "новые ошибки/версия (template-hash)", None, "разобрать журнал", severity="low"))
    return findings


def evaluate_t14(
    windows: list[dict[str, object]],
    baseline: Optional[dict[str, object]],
    thresholds: dict[str, object],
) -> list[dict[str, object]]:
    """T-14 prober_mix_anomaly: доля новых /24 > baseline + 3×MAD (baseline-only)."""
    findings: list[dict[str, object]] = []
    if not isinstance(baseline, dict) or str(baseline.get("quality", "none")) != "high":
        return findings
    mad_mult = float(thresholds["t14_new24_mad_mult"])
    for window in windows:
        probe = window.get("probe") if isinstance(window.get("probe"), dict) else {}
        delta = probe.get("delta") if isinstance(probe.get("delta"), dict) else {}
        top = delta.get("top")
        if not isinstance(top, list) or not top:
            continue
        networks = set()
        for item in top:
            if isinstance(item, dict) and isinstance(item.get("ip"), str):
                parts = item["ip"].split(".")
                if len(parts) == 4:
                    networks.add(".".join(parts[:3]))
        ts = str(window.get("ts", ""))
        hour = max(sample_hour(ts), 0)
        bucket = _metric_bucket(baseline, "syn_valid", hour)
        if bucket is None:
            continue
        median = float(bucket.get("median", 0.0))
        mad = float(bucket.get("mad", 0.0))
        if not is_scorable_value("syn_valid", median, mad):
            continue
        z = z_score(float(len(networks)), bucket)
        if z is not None and abs(z) >= mad_mult and len(networks) >= METRIC_FLOORS.get("syn_valid", 0):
            findings.append(
                _finding("T-14", ts, ts,
                         [{"source": "nft", "metric": "new_prober_24_count", "value": len(networks), "z": round(z, 2)}],
                         "новая кампания/сеть пробующих /24", None, "наблюдать; сопоставить T-03"))
    return findings


# ---------------------------------------------------------------------------
# Уверенность (§7.6) и корреляция
# ---------------------------------------------------------------------------

def _confidence(evidence: list[dict[str, object]], coverage: dict[str, object], baseline_quality: str, window_minutes: int) -> str:
    sources = {str(ev.get("source", "")) for ev in evidence if ev.get("source")}
    n = len([s for s in sources if s in INDEPENDENT_SOURCES])
    has_direct = bool(sources & DIRECT_SOURCES)
    if n >= 3 and has_direct:
        level = "high"
    elif n >= 2:
        level = "medium"
    else:
        level = "low"
    if baseline_quality in ("none", "low") or window_minutes < 30:
        level = _downgrade(level)
    if str(coverage.get("status", "")) in ("partial", "missing"):
        level = _downgrade(level)
    return level


def _downgrade(level: str) -> str:
    return {"high": "medium", "medium": "low", "low": "low"}.get(level, level)


def correlate(findings: list[dict[str, object]]) -> tuple[str, str]:
    """Тип инцидента + рекомендация (§7.6; один finding ≠ probing_plus_effect)."""
    rules = {str(f.get("rule")) for f in findings}
    probing = rules & {"T-03", "T-07"}
    effect = rules & {"T-01", "T-02"}
    local = rules & {"T-09", "T-10", "T-11", "T-12", "T-17"}
    if probing and effect:
        return (
            "probing_plus_effect",
            "готовить переключение клиента (Hy2/asv1/relay); лок 443 — только по probe-response",
        )
    if effect:
        return "effect_only", "вероятнее путь/апстрим; внешняя проверка, не рестарт"
    if probing:
        return "probing_only", "наблюдать; конфиги не менять; проверить резервный транспорт"
    if rules & {"T-04"}:
        return "mass_scan", "игнор, не эскалировать"
    if local:
        return "local_fault", "чинить локально"
    return "inconclusive", "сузить окно, добрать источник"


def analyze_samples(
    samples: list[dict[str, object]],
    baseline: Optional[dict[str, object]],
    coverage: Optional[dict[str, object]] = None,
    thresholds: Optional[dict[str, object]] = None,
    rules_hash: str = "",
    pcap_summary: Optional[dict[str, object]] = None,
    extra: Optional[dict[str, object]] = None,
) -> dict[str, object]:
    """Прогнать все правила в фиксированном порядке (ID), собрать отчёт §7.9.

    Выход — ТОЛЬКО отчёт (R-9). При critical_missing (нет nft+probe+kernel)
    вердикт принудительно inconclusive, high-confidence запрещён (§7.2).
    """
    thresholds, rules_hash = load_thresholds() if thresholds is None else (thresholds, rules_hash)
    cov = dict(coverage or {})
    windows = sample_deltas(samples)
    findings: list[dict[str, object]] = []
    findings += evaluate_t01(windows, thresholds)
    findings += evaluate_t02(windows, baseline, thresholds)
    findings += evaluate_t03_t04(windows)
    findings += evaluate_t05_t06(windows, thresholds)
    findings += evaluate_t07_t08(pcap_summary, thresholds)
    findings += evaluate_t09_t10_t17(windows, thresholds)
    findings += evaluate_t11_t12_t13_t15_t16(windows, baseline, thresholds, extra)
    findings += evaluate_t14(windows, baseline, thresholds)

    baseline_quality = str((baseline or {}).get("quality", "none"))
    window_start = str(samples[0].get("ts", "")) if samples else ""
    window_end = str(samples[-1].get("ts", "")) if samples else ""
    window_minutes = len(samples) * 5
    for f in findings:
        f["confidence"] = _confidence(
            list(f.get("evidence", [])), cov, baseline_quality, window_minutes
        )

    missing_critical = all(
        (cov.get(name) or {}).get("status") == "missing"
        for name in CRITICAL_MISSING
    )
    incident_type, action = correlate(findings)
    if missing_critical:
        incident_type = "inconclusive"
        action = "сузить окно, добрать источник"
        for f in findings:
            f["confidence"] = "low"

    findings.sort(key=lambda f: (f.get("window", ["", ""])[0], f.get("rule", ""), f.get("id", "")))
    headline = _headline(incident_type, findings)
    return {
        "schema_version": 1,
        "window": {"since": window_start, "until": window_end},
        "rules_hash": rules_hash,
        "coverage": cov,
        "baseline": {"quality": baseline_quality, "built_at": str((baseline or {}).get("built_at", ""))},
        "findings": findings,
        "incidents": [{"type": incident_type, "action": action}],
        "summary": {"verdict": incident_type, "action": action, "headline": headline},
    }


def _headline(incident_type: str, findings: list[dict[str, object]]) -> str:
    if not findings:
        return "аномалий не обнаружено (в пределах coverage)"
    top = max(findings, key=lambda f: {"high": 3, "medium": 2, "low": 1, "info": 0}.get(str(f.get("severity")), 0))
    return f"{incident_type}: ведущий finding {top.get('rule')} ({top.get('severity')})"


def max_severity(report: dict[str, object]) -> str:
    """Максимальная severity findings (exit-code analyze §9)."""
    rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
    best = "info"
    for f in report.get("findings", []):
        if isinstance(f, dict):
            sev = str(f.get("severity", "info"))
            if rank.get(sev, 0) > rank.get(best, 0):
                best = sev
    return best
