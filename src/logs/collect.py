"""Сборщик телеметрии log-forensics (SPEC-20261116-log-forensics §5/§6, WP-1).

Один вызов `collect_event` собирает снимок всех источников в канонический
Event-словарь (схема §6.1/§7.1 SPEC) и опционально аппендит его в
`/var/lib/vds/telemetry/samples-YYYYMMDD.ndjson` (атомарно, 0600, FileLock).

Ключевая граница (ревью M1 SPEC §5.2): мутирующий `probe-watch watch`
ЗАПРЕЩЁН — он перезаписывает снапшот и съедает дельту окна часового таймера
(может сорвать RU-SUSPECT-гистерезис). Collect читает снапшот
/var/lib/vds/probe-watch.json и nft-таблицу и считает дельту IN-PROCESS
чистой функцией `probing.compute_delta` (импорт; save_snapshot/update_threat
не вызываются). Поле `computed_by: "logs-collect (read-only)"` фиксирует это.

Все shell-команды — через `run_list([...])` (AGENTS §5.2), без shell=True;
сбой источника → поле отсутствует/coverage `missing`, сбор продолжается.

Активность AWG (ревью G2): UDP-сокет 51825 в ss — состояние UNCONN,
"estab_51825" НЕ СУЩЕСТВУЕТ; активность = свежесть latest-handshakes
(`awg show awg0 latest-handshakes`, peers_fresh_lt180s).

Disk-cap (§11): при disk_pct > 90 сэмплер отказывается писать + предупреждение
T-10; сбор отдаётся анализатору как есть.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from src.core.logger import console
from src.core.shell import ShellResult, run_list
from src.logs import paths as logs_paths
from src.logs.redact import redact_raw_text

RunFn = Callable[..., ShellResult]

COMPUTED_BY = "logs-collect (read-only)"

# Счётчики nstat, попадающие в сэмпл (§6.1). nstat ОБЯЗАН вызываться с -sz
# (alias -s = --no-update): без него nstat сбрасывает базовую линию
# /tmp/.nstat.u0 и sample/collect обнуляют дельты друг друга.
NSTAT_KEYS = (
    "TcpRetransSegs",
    "TcpOutSegs",
    "TcpExtTCPTimeouts",
    "TcpExtListenOverflows",
    "TcpExtListenDrops",
    "UdpInErrors",
    "IpInDiscards",
)

# Юниты, состояние которых пишем в сэмпл (T-09/T-17).
WATCH_UNITS = (
    "vds-xray.service",
    "vds-hysteria2.service",
    "vds-hysteria2-obfs.service",
    "vds-hysteria2-hop.service",
    "vds-amneziawg.service",
    "vds-relay-exit.service",
)

AWG_HANDSHAKE_FRESH_S = 180  # peers_fresh_lt180s (§6.1)


# ---------------------------------------------------------------------------
# Парсеры источников (чистые функции, тестируются на фикстурах)
# ---------------------------------------------------------------------------

def parse_nft_json(data: object) -> "Any":
    """Разобрать вывод `nft -j list table inet vds_probe` → probing.NftState.

    Формат: {"nftables": [{"metainfo":…}, {"counter": {name, packets, bytes}},
    {"set_elem": {set: "probers4", elem: {val, counter?}}} | {"set": …}]}.
    per_element_counters — по фактическому наличию счётчика на элементах
    (fallback-ядро отдаёт элементы без counter). Битый/пустой вывод → None.
    """
    from src.gateway.probing import NftState

    if not isinstance(data, dict):
        return None
    items = data.get("nftables")
    if not isinstance(items, list):
        return None
    state = NftState()
    has_counter_elem = False
    for obj in items:
        if not isinstance(obj, dict):
            continue
        counter = obj.get("counter")
        if isinstance(counter, dict):
            name = str(counter.get("name", ""))
            if name in ("syn_bare", "syn_valid", "udp_443"):
                setattr(state, name, int(counter.get("packets", 0) or 0))
            continue
        elem = obj.get("set_elem")
        if not isinstance(elem, dict):
            continue
        if str(elem.get("set", "")) != "probers4":
            continue
        inner = elem.get("elem")
        val = inner.get("val") if isinstance(inner, dict) else inner
        if not isinstance(val, str):
            continue
        ip_counter = inner.get("counter") if isinstance(inner, dict) else None
        packets = 0
        if isinstance(ip_counter, dict):
            packets = int(ip_counter.get("packets", 0) or 0)
            has_counter_elem = True
        state.probers[val] = packets
    state.per_element_counters = has_counter_elem
    return state


def parse_ss(text: str) -> dict[str, int]:
    """Разобрать `ss -Htoi state established '( sport = :443 )'`.

    Вывод: строка сокета (State Recv-Q Send-Q Local Peer) + строка деталей
    (tab, `… retrans:X/Y … timer:(on,3ms,0) …`). Zombie-признаки (T-01,
    ревью G2-2: при data-phase blackhole сокеты ВИСЯТ ESTABLISHED-зомби):
    total-retrans > 0 ИЛИ Send-Q > 0 ИЛИ timer:(on,…). Возвращает
    {"estab_443": N, "zombie_443": N, "synrecv_443": N}.
    """
    import re as _re

    estab = 0
    zombie = 0
    lines = text.splitlines()
    i = 0
    retrans_re = _re.compile(r"\bretrans:\d+/(\d+)\b")
    timer_re = _re.compile(r"\btimer:\(on[,)]")
    while i < len(lines):
        line = lines[i]
        cols = line.split()
        if not cols:
            i += 1
            continue
        detail = lines[i + 1] if i + 1 < len(lines) and lines[i + 1].startswith("\t") else ""
        i += 2 if detail else 1
        if cols[0] == "ESTAB":
            estab += 1
            try:
                sendq = int(cols[2])
            except (IndexError, ValueError):
                sendq = 0
            retrans_total = 0
            m = retrans_re.search(detail)
            if m:
                retrans_total = int(m.group(1))
            if sendq > 0 or retrans_total > 0 or timer_re.search(detail):
                zombie += 1
        elif cols[0] == "SYN-RECV":
            pass  # synrecv учитывается отдельным прогоном ss -Htn
    return {"estab_443": estab, "zombie_443": zombie, "synrecv_443": 0}


def parse_nstat(text: str) -> dict[str, int]:
    """Разобрать `nstat -asz` (строки 'TcpExtTCPTimeouts\\t123\\t0.0').

    Берём колонку значения (2-я); ключи вне NSTAT_KEYS игнорируем. Битые
    строки пропускаем построчно.
    """
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] not in NSTAT_KEYS:
            continue
        try:
            out[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return out


def parse_awg_handshakes(text: str, now_epoch: int, fresh_s: int = AWG_HANDSHAKE_FRESH_S) -> dict[str, int]:
    """Разобрать `awg show awg0 latest-handshakes` → активность AWG.

    Строки '<pubkey>\\t<epoch>' (без ключа, только счётчики — приватных
    данных в выводе нет по определению). peers_fresh_lt180s — пиров с
    handshake моложе 180 с (это и есть «активность AWG»: у UDP-сокета
    51825 состояния ESTAB НЕ существует).
    """
    fresh = 0
    total = 0
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0] == "interface":
            continue
        try:
            epoch = int(parts[-1])
        except ValueError:
            continue
        total += 1
        if epoch > 0 and 0 <= now_epoch - epoch < fresh_s:
            fresh += 1
    return {"peers_total": total, "peers_fresh_lt180s": fresh}


def read_interface_counters(base: Path = Path("/sys/class/net")) -> dict[str, dict[str, int]]:
    """rx/tx bytes/drops/errors прямо из /sys/class/net/*/statistics (без shell)."""
    out: dict[str, dict[str, int]] = {}
    try:
        ifaces = sorted(p.name for p in base.iterdir() if p.is_dir())
    except OSError:
        return out
    for iface in ifaces:
        counters: dict[str, int] = {}
        for key, fname in (
            ("rx_b", "rx_bytes"), ("tx_b", "tx_bytes"),
            ("rx_d", "rx_dropped"), ("tx_d", "tx_dropped"),
            ("rx_e", "rx_errors"), ("tx_e", "tx_errors"),
        ):
            try:
                counters[key] = int((base / iface / "statistics" / fname).read_text().strip())
            except (OSError, ValueError):
                continue
        if counters:
            out[iface] = counters
    return out


# ---------------------------------------------------------------------------
# Источники через run_list
# ---------------------------------------------------------------------------

def _collect_nft(run: RunFn) -> tuple[Optional[Any], dict[str, str]]:
    """`nft -j list table inet vds_probe` → (NftState|None, coverage-примечание)."""
    res = run(["nft", "-j", "list", "table", "inet", logs_paths.NFT_TABLE], timeout=15)
    if not res.ok:
        return None, {"status": "missing", "note": res.stderr.strip() or "nft недоступен"}
    import json as _json

    try:
        data = _json.loads(res.stdout)
    except _json.JSONDecodeError:
        return None, {"status": "missing", "note": "nft -j вернул не-JSON"}
    state = parse_nft_json(data)
    if state is None:
        return None, {"status": "missing", "note": "таблица inet vds_probe не распознана"}
    return state, {"status": "ok", "note": ""}


def _collect_ss(run: RunFn) -> tuple[dict[str, int], dict[str, str]]:
    res = run(
        ["ss", "-Htoi", "state", "established", "( sport = :443 )"], timeout=10
    )
    if not res.ok:
        return {}, {"status": "missing", "note": res.stderr.strip() or "ss недоступен"}
    return parse_ss(res.stdout), {"status": "ok", "note": ""}


def _collect_nstat(run: RunFn) -> tuple[dict[str, int], dict[str, str]]:
    # -sz = --no-update: БЕЗ него nstat сбрасывает базовую линию (SPEC §5.2).
    res = run(["nstat", "-asz"], timeout=10)
    if not res.ok:
        return {}, {"status": "missing", "note": res.stderr.strip() or "nstat недоступен"}
    return parse_nstat(res.stdout), {"status": "ok", "note": ""}


def _collect_awg(run: RunFn, now_epoch: int) -> tuple[dict[str, int], dict[str, str]]:
    res = run(["awg", "show", "awg0", "latest-handshakes"], timeout=10)
    if not res.ok:
        # AWG может быть не установлен — честный missing, не «0 клиентов».
        return {}, {"status": "missing", "note": "awg недоступен / не установлен"}
    return parse_awg_handshakes(res.stdout, now_epoch), {"status": "ok", "note": ""}


def _collect_units(run: RunFn) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {}
    for unit in WATCH_UNITS:
        state_res = run(["systemctl", "show", unit, "-p", "ActiveState", "--value"], timeout=10)
        restarts_res = run(["systemctl", "show", unit, "-p", "NRestarts", "--value"], timeout=10)
        state = state_res.stdout.strip() if state_res.ok else "unknown"
        try:
            restarts = int(restarts_res.stdout.strip()) if restarts_res.ok else 0
        except ValueError:
            restarts = 0
        out[unit] = {"state": state or "unknown", "restarts": restarts}
    return out


def _collect_journal(run: RunFn) -> dict[str, dict[str, int]]:
    """Журнальные сигнатуры за окно сэмпла (xray/hy2/kernel-UFW) — read-only.

    Переиспользуем scan_journal из probing (НЕ дублируем паттерны). Отдельные
    сырые строки в ndjson не пишем (приватность + объём §6.4).
    """
    from src.gateway.probing import scan_journal

    hits = scan_journal(f"-{logs_paths.SAMPLE_WINDOW_MINUTES} min", run=run)
    out: dict[str, dict[str, int]] = {}
    for hit in hits:
        bucket = out.setdefault(hit.source, {})
        bucket[hit.pattern_name] = bucket.get(hit.pattern_name, 0) + hit.count
    return out


def _collect_redacted_journal_excerpt(run: RunFn, unit: str, lines: int = 5) -> list[str]:
    """Последние строки журнала юнита с redaction (для бандла, не для сэмпла).

    Жадные блобы применяются (raw-режим SPEC §5.3): это сырой текст журнала.
    """
    res = run(
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-q", "-o", "short-iso"],
        timeout=15,
    )
    if not res.ok:
        return []
    out: list[str] = []
    for line in res.stdout.splitlines():
        redacted, _ = redact_raw_text(line)
        out.append(redacted)
    return out


def disk_usage_pct(path: Path = Path("/var/lib/vds")) -> Optional[int]:
    """Заполненность ФС с артефактами в процентах; недоступно → None."""
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if total <= 0:
        return None
    used = total - free
    return int(used * 100 // total)


def _probe_verdict_readonly(
    current: Optional[Any],
    snapshot_path: Path,
) -> tuple[dict[str, object], dict[str, str]]:
    """Вердикт probe-watch БЕЗ мутации (M1): снапшот + in-process compute_delta.

    Импортируем ТОЛЬКО чистые функции (load_snapshot/compute_delta);
    save_snapshot/update_threat из probing не вызываются — это граница M1
    (тест-спай подтверждает).
    """
    from src.gateway.probing import compute_delta, load_snapshot

    snapshot = load_snapshot(snapshot_path)
    cov = {"status": "ok", "note": ""}
    if current is None:
        cov = {"status": "missing", "note": "nft-таблица недоступна — дельта не посчитана"}
        delta_dict: dict[str, object] = {}
        verdict = "unknown"
        threat = dict(snapshot.get("threat") or {})
    else:
        delta = compute_delta(current, snapshot)
        delta_dict = {
            "syn_bare": delta.syn_bare,
            "syn_valid": delta.syn_valid,
            "udp_443": delta.udp_443,
            "bare_no_payload": delta.bare_no_payload,
            "unique_probers": delta.unique_probers,
            "top": [{"ip": ip, "delta": d} for ip, d in delta.top],
        }
        threat = dict(snapshot.get("threat") or {})
        threat_level = str(threat.get("level", "quiet"))
        # Вердикт последнего тика — из снапшота (R-8: анализатор не
        # пересчитывает пороги probe-watch, только потребляет): high
        # достигается только через RU-PROBE-SUSPECT, elevated — тоже
        # через BURST (машина threat-level SPEC-20261116-probe-response §2).
        verdict = {
            "high": "RU-PROBE-SUSPECT",
            "elevated": "PROBE-BURST",
            "quiet": "quiet",
        }.get(threat_level, "quiet")
    probe: dict[str, object] = {
        "verdict": verdict,
        "threat_level": str(threat.get("level", "quiet")),
        "threat_reason": str(threat.get("reason", "")),
        "delta": delta_dict,
        "snapshot_ts": str(snapshot.get("ts", "")),
        "computed_by": COMPUTED_BY,
    }
    return probe, cov


def _fast_contour_hook(run: RunFn) -> None:
    """Быстрый контур детекта серий ТСПУ (SPEC-20261116-probe-coverage §2).

    Ленивый импорт (logs не тянет gateway на старте); nft-таблицы нет —
    fast_contour_check возвращает тихий скип (probe-watch не установлен —
    это норма, не ошибка coverage). Пишет только сайдкар-кэш сэмплера
    /var/lib/vds/probe-fast-cache.json; снапшот probe-watch.json не
    мутируется никогда (граница M1/ADR-014 сохранена).
    """
    from src.gateway.probing import fast_contour_check

    fast_contour_check(run=run)


def _lockdown_active() -> bool:
    """Активен ли lock-443 (§5.4: лок ослепляет syn_valid). Read-only."""
    try:
        from src.gateway.store import StoreError, load_state
        from src.system.ufw import get_lockdown

        state = load_state()
        return bool(get_lockdown(state).get("active"))
    except (StoreError, OSError):
        return False


def collect_event(
    run: RunFn = run_list,
    now: Optional[datetime] = None,
    snapshot_path: Optional[Path] = None,
    journal_excerpt: bool = False,
) -> tuple[dict[str, object], dict[str, dict[str, str]]]:
    """Собрать один Event-снимок (схема §6.1) + coverage источников.

    journal_excerpt=True — добавить redacted-хвосты журналов юнитов (для
    bundle-режима; в 5-мин сэмпл не пишем). Возвращает (event, coverage).
    """
    now = now or datetime.now(timezone.utc)
    snapshot_path = snapshot_path or logs_paths.SNAPSHOT_FILE
    coverage: dict[str, dict[str, str]] = {}

    nft_state, cov = _collect_nft(run)
    coverage["nft"] = cov
    ss, cov = _collect_ss(run)
    coverage["ss"] = cov
    nstat, cov = _collect_nstat(run)
    coverage["nstat"] = cov
    now_epoch = int(now.timestamp())
    awg, cov = _collect_awg(run, now_epoch)
    coverage["awg"] = cov

    if nstat:
        coverage["nstat"].setdefault("note", "")
        missing_keys = [k for k in NSTAT_KEYS if k not in nstat]
        if missing_keys:
            coverage["nstat"] = {
                "status": "partial",
                "note": f"нет счётчиков: {', '.join(missing_keys)}",
            }

    probe, cov = _probe_verdict_readonly(nft_state, snapshot_path)
    coverage["probe"] = cov

    # W1-1: быстрый контур (5-мин дельта probers4 + verified-IP в сайдкар) —
    # после read-only вердикта, отдельным хуком (пишет только свой кэш).
    _fast_contour_hook(run)

    lockdown = {"active": _lockdown_active()}

    net = read_interface_counters()
    coverage["net"] = {"status": "ok" if net else "missing", "note": "" if net else "/sys/class/net недоступен"}

    conntrack, conntrack_max = _conntrack_counts()
    disk_pct = disk_usage_pct()
    mem_avail_b = _mem_available()
    load1 = _load1()

    units = _collect_units(run)
    journal = _collect_journal(run)

    event: dict[str, object] = {
        "v": 1,
        "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": os.uname().nodename,
        "window_s": logs_paths.SAMPLE_WINDOW_MINUTES * 60,
        "computed_by": COMPUTED_BY,
        "nft": _nft_snapshot_values(nft_state),
        "probe": probe,
        "ss": ss,
        "awg": awg,
        "net": net,
        "nstat": {k: nstat[k] for k in NSTAT_KEYS if k in nstat},
        "units": units,
        "journal": journal,
        "res": {
            "conntrack": conntrack,
            "conntrack_max": conntrack_max,
            "disk_pct": disk_pct,
            "load1": load1,
            "mem_avail_b": mem_avail_b,
        },
        "lockdown": lockdown,
    }
    if journal_excerpt:
        excerpts = {
            unit: _collect_redacted_journal_excerpt(run, unit)
            for unit in ("vds-xray.service", "vds-hysteria2.service")
        }
        kernel = _collect_redacted_journal_excerpt(run, "kernel", lines=10)
        excerpts["kernel"] = kernel
        event["journal_excerpt"] = excerpts
    return event, coverage


def _nft_snapshot_values(state: Optional[Any]) -> dict[str, object]:
    """Кумулятивные значения счётчиков nft (§6.1; дельты — на анализаторе)."""
    if state is None:
        return {}
    return {
        "syn_bare": state.syn_bare,
        "syn_valid": state.syn_valid,
        "udp_443": state.udp_443,
        "probers": len(state.probers),
        "per_element": bool(state.per_element_counters),
    }


def _conntrack_counts() -> tuple[Optional[int], Optional[int]]:
    try:
        cur = int(Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text().strip())
        mx = int(Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip())
        return cur, mx
    except (OSError, ValueError):
        return None, None


def _mem_available() -> Optional[int]:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _load1() -> Optional[float]:
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Запись сэмпла (ndjson-append, 0600, FileLock, disk-cap)
# ---------------------------------------------------------------------------

def write_sample(
    event: dict[str, object],
    telemetry_dir: Optional[Path] = None,
    lock_file: Optional[str] = None,
) -> Optional[Path]:
    """Атомарно дописать сэмпл в samples-YYYYMMDD.ndjson (0600, FileLock).

    Disk-cap §11: disk_pct > 90 → запись ОТКАННА (не забивать диск) +
    предупреждение T-10 в консоль. Возвращает путь или None (отказ/ошибка).
    """
    from src.core.lock import FileLock

    telemetry_dir = telemetry_dir or logs_paths.TELEMETRY_DIR
    lock_file = lock_file or logs_paths.LOCK_FILE

    disk_pct = event.get("res", {}).get("disk_pct") if isinstance(event.get("res"), dict) else None
    if isinstance(disk_pct, int) and disk_pct > logs_paths.DISK_CAP_PCT:
        console.print(
            f"[error][logs] disk_pct={disk_pct}% > {logs_paths.DISK_CAP_PCT}% — "
            "сэмпл не записан (disk-cap, T-10 resource_pressure). Очистите диск "
            "или снимите cap в /etc/vds-forensics/rules.json.[/error]"
        )
        return None

    path = telemetry_dir / Path(logs_paths.samples_path_for().name)
    line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        telemetry_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(telemetry_dir, 0o700)
        with FileLock(lock_file):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(path, 0o600)
    except OSError as exc:
        console.print(f"[error][logs] Не удалось записать сэмпл {path}: {exc}[/error]")
        return None
    return path


def read_samples(window_days: int = 14, telemetry_dir: Optional[Path] = None) -> list[dict[str, object]]:
    """Прочитать ndjson-историю (для baseline/detect); битые строки пропускаем."""
    telemetry_dir = telemetry_dir or logs_paths.TELEMETRY_DIR
    out: list[dict[str, object]] = []
    try:
        files = sorted(telemetry_dir.glob("samples-*.ndjson"))[-window_days:]
    except OSError:
        return out
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def cmd_sample(apply: bool = False, run: RunFn = run_list) -> int:
    """`vds logs sample`: dry-run печатает план; --apply пишет сэмпл."""
    if not apply:
        console.print("[info][logs] DRY-RUN план sample:[/info]")
        console.print(
            f"[info][logs]   собрать Event (nft/ss/nstat/awg/units/journal/probe-watch read-only) "
            f"→ {logs_paths.samples_path_for()} (0600, append)[/info]"
        )
        console.print("[info][logs] Запустите с --apply для записи.[/info]")
        return 0
    event, coverage = collect_event(run=run)
    path = write_sample(event)
    if path is None:
        return 1
    _print_coverage(coverage)
    probe = event.get("probe", {})
    console.print(
        f"[success][logs] Сэмпл записан: {path} "
        f"(threat={probe.get('threat_level', 'quiet')}, "
        f"computed_by={COMPUTED_BY}).[/success]"
    )
    return 0


def _print_coverage(coverage: dict[str, dict[str, str]]) -> None:
    bad = {k: v for k, v in coverage.items() if v.get("status") != "ok"}
    if not bad:
        console.print("[info][logs] coverage: все источники ok[/info]")
        return
    for name, cov in bad.items():
        tag = "warning" if cov.get("status") == "partial" else "error"
        console.print(
            f"[{tag}][logs] coverage {name}: {cov.get('status')} — "
            f"{cov.get('note', '')}[/{tag}]"
        )
