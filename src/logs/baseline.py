"""Baseline (медиана/MAD) по ndjson-истории телеметрии (SPEC §7.8, WP-2).

Ключ: `metric` × `hour_of_day` (24 бакета; ревью G2: 14 дней × 12 точек/час
→ ~168 точек/бакет, MAD устойчив). hour_of_week — opt-in после накопления
≥4 недель (flag `hour_of_week=True` строит второй ключ, если данных хватает).

Non-scorable (static-режим): MAD = 0 ИЛИ медиана ниже absolute-floor метрики
(§7.8: правило по абсолютному порогу, z не считается — ревью G2 для T-02).
Baseline строится на logs-телеметрии (5-мин сэмплах), НЕ на probe-watch
снапшотах. reset-дельты (переустановка nft/ребут) помечаются вызывающим
(detect) и в baseline не попадают.

Baseline хранит только агрегаты: version, built_at, window_days, metrics
{metric: {hours: [24×{median,mad,count,scorable}]}, quality, floor} —
никаких IP/шаблонов текстом (приватность §7.8: hash-only).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from src.core.logger import console
from src.logs import paths as logs_paths

BASELINE_VERSION = 1
MIN_BUCKET_SAMPLES = 20   # §7.8 минимум на бакет
MIN_DAYS = 7              # иначе глобальная медиана, quality low

# Absolute-floor метрик (§7.8 «всегда с абсолютным минимумом»: шум на
# нулевой медиане не даёт тревог; T-02 ревью G2 — median≈0 static-skip).
METRIC_FLOORS: dict[str, int] = {
    "syn_valid": 20,
    "udp_443": 1000,
    "estab_443": 1,
    "peers_fresh_lt180s": 1,
}

BASELINE_METRICS = ("syn_valid", "udp_443", "estab_443", "peers_fresh_lt180s")


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def _mad(values: list[float], median: float) -> float:
    return _median([abs(v - median) for v in values])


def sample_hour(ts: str) -> int:
    """Час суток UTC из ts сэмпла ('2026-11-16T12:05:00Z'); битый ts → -1."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return -1
    return dt.hour


def extract_metric(sample: dict[str, object], metric: str) -> Optional[float]:
    """Значение метрики из сэмпла; отсутствует → None (не участвует)."""
    if metric == "estab_443":
        ss = sample.get("ss")
        if isinstance(ss, dict) and "estab_443" in ss:
            value = ss["estab_443"]
            return float(value)  # value: object, всегда int из парсера
        return None
    if metric == "peers_fresh_lt180s":
        awg = sample.get("awg")
        if isinstance(awg, dict) and "peers_fresh_lt180s" in awg:
            value = awg["peers_fresh_lt180s"]
            return float(value)
        return None
    nft = sample.get("nft")
    if isinstance(nft, dict) and metric in nft:
        value = nft[metric]
        return float(value)
    return None


def build_baseline(
    samples: list[dict[str, object]],
    window_days: int = 14,
    hour_of_week: bool = False,
    now: Optional[datetime] = None,
) -> dict[str, object]:
    """Построить baseline по ndjson-истории (чистая функция от samples).

    Non-scorable: MAD=0 или медиана ниже absolute-floor → бакет static-режим
    (`scorable=false`, правило по абсолютному порогу). Бакетов < MIN_DAYS
    или точек в бакете < MIN_BUCKET_SAMPLES → quality=low (глобальная
    медиана в поле `global`). Пустая история → quality=none (cold start).
    """
    now = now or datetime.now(timezone.utc)
    per_metric: dict[str, dict[int, list[float]]] = {
        m: {h: [] for h in range(24)} for m in BASELINE_METRICS
    }
    used_samples = 0
    for sample in samples:
        if sample.get("v") != 1:
            continue
        hour = sample_hour(str(sample.get("ts", "")))
        if hour < 0:
            continue
        used_samples += 1
        for metric in BASELINE_METRICS:
            value = extract_metric(sample, metric)
            if value is not None:
                per_metric[metric][hour].append(value)

    metrics_out: dict[str, object] = {}
    scorable_count = 0
    total_buckets = 0
    for metric, hours in per_metric.items():
        floor = METRIC_FLOORS.get(metric, 0)
        buckets: list[dict[str, object]] = []
        for h in range(24):
            values = hours[h]
            total_buckets += 1
            if values:
                median = _median(values)
                mad = _mad(values, median)
                scorable = bool(values) and mad > 0 and median >= floor
                buckets.append(
                    {
                        "median": round(median, 3),
                        "mad": round(mad, 3),
                        "count": len(values),
                        "scorable": scorable,
                    }
                )
            else:
                buckets.append({"median": 0.0, "mad": 0.0, "count": 0, "scorable": False})
            if buckets[-1]["scorable"]:
                scorable_count += 1
        all_values = [v for vals in hours.values() for v in vals]
        global_bucket: dict[str, object] = {}
        if all_values:
            g_median = _median(all_values)
            g_mad = _mad(all_values, g_median)
            global_bucket = {
                "median": round(g_median, 3),
                "mad": round(g_mad, 3),
                "count": len(all_values),
                "scorable": bool(g_mad > 0 and g_median >= floor),
            }
        metrics_out[metric] = {"hours": buckets, "floor": floor, "global": global_bucket}

    days_covered = _distinct_days(samples)
    if used_samples == 0:
        quality = "none"
    elif days_covered >= MIN_DAYS and _buckets_dense(metrics_out):
        quality = "high"
    else:
        # меньше недели данных или разреженные бакеты — глобальная медиана, low
        quality = "low"

    baseline: dict[str, object] = {
        "version": BASELINE_VERSION,
        "built_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": window_days,
        "samples_used": used_samples,
        "quality": quality,
        "metrics": metrics_out,
    }
    if hour_of_week:
        baseline["hour_of_week"] = _build_hour_of_week(samples)
    return baseline


def _build_hour_of_week(samples: list[dict[str, object]]) -> dict[str, object]:
    """Opt-in key hour_of_week (168 слотов); строится при ≥4 неделях данных."""
    per_metric: dict[str, list[float]] = {m: [] for m in BASELINE_METRICS}
    for sample in samples:
        ts = str(sample.get("ts", ""))
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        for metric in BASELINE_METRICS:
            value = extract_metric(sample, metric)
            if value is not None:
                per_metric[metric].append(value)
    weeks = len(per_metric["syn_valid"]) / 288.0 if per_metric["syn_valid"] else 0.0
    if weeks < 4:
        return {"available": False, "weeks": round(weeks, 2), "note": "нужно ≥4 недель"}
    out: dict[str, object] = {"available": True, "weeks": round(weeks, 2), "metrics": {}}
    for metric, values in per_metric.items():
        if not values:
            continue
        median = _median(values)
        out["metrics"][metric] = {
            "median": round(median, 3),
            "mad": round(_mad(values, median), 3),
            "count": len(values),
        }
    return out


def _distinct_days(samples: list[dict[str, object]]) -> int:
    """Число различных дат в истории (для порога качества §7.8)."""
    days: set[str] = set()
    for sample in samples:
        ts = str(sample.get("ts", ""))[:10]
        if ts:
            days.add(ts)
    return len(days)


def _buckets_dense(metrics_out: dict[str, object]) -> bool:
    """Каждый непустой бакет каждой метрики имеет ≥ MIN_BUCKET_SAMPLES точек."""
    for metric_data in metrics_out.values():
        if not isinstance(metric_data, dict):
            continue
        for bucket in metric_data.get("hours", []):
            if isinstance(bucket, dict) and bucket.get("count", 0) and bucket["count"] < MIN_BUCKET_SAMPLES:
                return False
    return True


def load_baseline(path: Optional[object] = None) -> Optional[dict[str, object]]:
    """Загрузить baseline.json; отсутствует/бит → None (cold start честно)."""
    from pathlib import Path

    p = Path(path) if path is not None else logs_paths.FORENSICS_DIR / "baseline.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def save_baseline(baseline: dict[str, object], path: Optional[object] = None) -> bool:
    """Атомарная запись baseline (0600). True — успех."""
    from pathlib import Path

    p = Path(path) if path is not None else logs_paths.FORENSICS_DIR / "baseline.json"
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(p.parent, 0o700)
        tmp = p.with_name(f".{p.name}.tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
        return True
    except OSError as exc:
        console.print(f"[error][logs] Не удалось записать baseline {p}: {exc}[/error]")
        return False


def z_score(value: float, bucket: dict[str, object]) -> Optional[float]:
    """z = 0.6745·(x − median)/MAD (§7.8); non-scorable бакет → None."""
    median = float(bucket.get("median", 0.0))
    mad = float(bucket.get("mad", 0.0))
    if not bucket.get("scorable") or mad <= 0:
        return None
    return 0.6745 * (value - median) / mad


def is_scorable_value(metric: str, median: float, mad: float) -> bool:
    """Non-scorable: MAD=0 или медиана ниже absolute-floor (T-02 ревью G2)."""
    return mad > 0 and median >= METRIC_FLOORS.get(metric, 0)
