"""Daily-отчёт log-forensics (SPEC §7.9, WP-2): JSON + human-вывод.

`vds logs report --apply` (вызывается и таймером vds-logs-daily 04:15):
читает ndjson-историю, строит/загружает baseline, прогоняет detect,
пишет отчёт в /var/lib/vds/forensics/reports/report-YYYYMMDD.json (0600)
и печатает человекочитаемую сводку. Анализатор read-only — реакций нет
(R-9), фиксирует только рекомендации.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.core.logger import console
from src.logs import paths as logs_paths
from src.logs.baseline import build_baseline, load_baseline
from src.logs.collect import read_samples
from src.logs.detect import analyze_samples, load_thresholds, max_severity


def build_daily_report(
    telemetry_dir: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
    now: Optional[datetime] = None,
) -> dict[str, object]:
    """Собрать отчёт за сегодня (read-only, чистая от fs кроме baseline-чтения)."""
    now = now or datetime.now(timezone.utc)
    telemetry_dir = telemetry_dir or logs_paths.TELEMETRY_DIR
    baseline = load_baseline(baseline_path)
    samples = read_samples(window_days=1, telemetry_dir=telemetry_dir)
    thresholds, rules_hash = load_thresholds()
    report = analyze_samples(
        samples,
        baseline,
        coverage=_coverage_from_samples(samples),
        thresholds=thresholds,
        rules_hash=rules_hash,
    )
    report["generated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    report["samples_count"] = len(samples)
    return report


def _coverage_from_samples(samples: list[dict[str, object]]) -> dict[str, object]:
    """Coverage из фактического наличия источников в сэмплах (честно)."""
    if not samples:
        return {
            "status": "missing",
            "note": "нет сэмплов телеметрии за окно",
        }
    last = samples[-1]
    cov: dict[str, object] = {}
    nft = last.get("nft") if isinstance(last.get("nft"), dict) else {}
    cov["nft"] = {"status": "ok" if nft else "missing", "note": ""}
    probe = last.get("probe") if isinstance(last.get("probe"), dict) else {}
    cov["probe"] = {"status": "ok" if probe else "missing", "note": ""}
    kernel = last.get("journal") if isinstance(last.get("journal"), dict) else {}
    cov["kernel"] = {"status": "ok" if kernel else "missing", "note": ""}
    cov["pcap"] = {"status": "missing", "note": "pcap-захват не выполнялся (v1 — только вручную)"}
    return cov


def write_report(report: dict[str, object], reports_dir: Optional[Path] = None, now: Optional[datetime] = None) -> Optional[Path]:
    """Атомарная запись отчёта (0600) в reports/; возвращает путь."""
    now = now or datetime.now(timezone.utc)
    reports_dir = reports_dir or logs_paths.REPORTS_DIR
    path = reports_dir / f"report-{now.strftime('%Y%m%d')}.json"
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        Path(reports_dir).chmod(0o700)
        tmp = path.with_name(f".{path.name}.tmp.{now.strftime('%H%M%S')}")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=1, sort_keys=True)
        tmp.chmod(0o600)
        tmp.replace(path)
        return path
    except OSError as exc:
        console.print(f"[error][logs] Не удалось записать отчёт {path}: {exc}[/error]")
        return None


def print_report(report: dict[str, object]) -> None:
    """Human-вывод: наблюдали / гипотеза / чего не видим / что делать."""
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    verdict = str(summary.get("verdict", "inconclusive"))
    tag = {"probing_plus_effect": "error", "effect_only": "error", "probing_only": "warning",
           "local_fault": "warning", "inconclusive": "info"}.get(verdict, "info")
    window = report.get("window") if isinstance(report.get("window"), dict) else {}
    console.print(
        f"[info][logs] Окно {window.get('since', '—')} … {window.get('until', '—')} "
        f"(сэмплов: {report.get('samples_count', 0)})[/info]"
    )
    console.print(
        f"[{tag}][logs] Вердикт: {verdict} — {summary.get('headline', '')}[/{tag}]"
    )
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    if findings:
        for f in findings:
            if not isinstance(f, dict):
                continue
            console.print(
                f"[warning][logs]   {f.get('rule')} {f.get('severity')}/{f.get('confidence')} "
                f"{f.get('window', ['', ''])[0]}..{f.get('window', ['', ''])[-1]} — "
                f"{f.get('hypothesis', '')}[/warning]"
            )
    else:
        console.print("[info][logs]   findings: нет[/info]")
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    cov_notes = [
        f"{name}: {info.get('status')}"
        for name, info in sorted(coverage.items())
        if isinstance(info, dict) and info.get("status") != "ok"
    ]
    if cov_notes:
        console.print(f"[warning][logs] coverage: {', '.join(cov_notes)}[/warning]")
    console.print(f"[info][logs] action: {summary.get('action', '')}[/info]")
    console.print("[info][logs] Анализатор read-only: реакций нет (R-9) — исполнение "
                  "за оператором/probe-response.[/info]")


def cmd_report(apply: bool = False, last: bool = False) -> int:
    """`vds logs report`: dry-run печатает сводку; --apply пишет отчёт;
    --last печатает последний сохранённый."""
    if last:
        reports_dir = logs_paths.REPORTS_DIR
        try:
            files = sorted(reports_dir.glob("report-*.json"))
        except OSError:
            files = []
        if not files:
            console.print("[info][logs] Отчётов ещё нет (daily-таймер или report --apply).[/info]")
            return 0
        try:
            report = json.loads(files[-1].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[error][logs] Битый отчёт {files[-1]}: {exc}[/error]")
            return 1
        print_report(report)
        return 0

    report = build_daily_report()
    print_report(report)
    if not apply:
        console.print("[info][logs] Dry-run: отчёт не записан. Для записи — --apply.[/info]")
        return 0
    path = write_report(report)
    if path is None:
        return 1
    console.print(f"[success][logs] Отчёт записан: {path}[/success]")
    return 0


def cmd_analyze(live: bool = False, since_hours: int = 24, json_out: bool = False) -> int:
    """`vds logs analyze --live --since Nh` — read-only, без записи файлов.

    Exit codes §9: 0 — ok, 1 — findings ≥ medium, 2 — ошибка.
    """
    samples = read_samples(window_days=max(1, since_hours // 24) + 1)
    if not samples:
        console.print(
            "[error][logs] Телеметрии нет — выполните `vds logs sample --apply` "
            "(таймер vds-logs-sample) или соберите bundle.[/error]"
        )
        return 2
    baseline = load_baseline()
    window = samples[-since_hours * 12 :]
    report = analyze_samples(window, baseline, coverage=_coverage_from_samples(window))
    if json_out:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        print_report(report)
    return 1 if max_severity(report) in ("medium", "high") else 0
