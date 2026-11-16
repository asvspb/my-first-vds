"""Bounded pcap-захват log-forensics (SPEC §8.1, WP-2): start/status/stop.

Политика (§8.1):
- только по явной команде (v1, OQ-4: авто-захват не выполняется);
- bounded: `--duration` (default 1h, max 4h), `--max-mb` (default 50),
  кольцо `-C=<max_mb//5>` / `-G 3600` / `-W 5`, `-s 1600` (полный MTU:
  PQ-TLS ClientHello Chrome 130+ ~1100–1300Б, `-s 1024` резал его);
- BPF IPv4-only v1 (classic BPF `tcp[n]` не работает для IPv6 — обязан
  начинаться с `ip and`), несколько собственных IP → `and not (host A or
  host B …)`, плюс исключение private-диапазонов;
- путь /var/lib/vds/forensics/captures/ (0700/0600, НЕ /var/tmp);
- TTL-чистка 7 дней;
- stop убивает ТОЛЬКО PID из pidfile после проверки `comm == tcpdump`
  (не «по порту/имени» — AGENTS §6/TECHDEBT P4);
- без tcpdump — [error] + инструкция; метаданные (§8.2) — отдельный
  parse-pcap (WP-4), здесь фиксируются только сводка файлов в status.
"""
from __future__ import annotations

import json
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.core.logger import console
from src.core.shell import run_list
from src.logs import paths as logs_paths

PIDFILE = "capture.pid"
MAX_DURATION_H = 4
MAX_MB = 50
RING_FILES = 5
SNAPLEN = 1600


def bpf_filter(own_hosts: list[str]) -> str:
    """BPF §8.1: `ip and tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-push)
    != 0) and not (host A or host B …)` + private-диапазоны."""
    base = (
        "ip and tcp port 443 and "
        "(tcp[tcpflags] & (tcp-syn|tcp-push) != 0)"
    )
    hosts = [h for h in own_hosts if h]
    if hosts:
        base += " and not (" + " or ".join(f"host {h}" for h in hosts) + ")"
    base += (
        " and not net 10.0.0.0/8 and not net 172.16.0.0/12 "
        "and not net 192.168.0.0/16"
    )
    return base


def collect_own_hosts(run=None) -> list[str]:
    """Собственный IP + whitelist allow-ips.txt + AWG-endpoints (§8.1)."""
    from src.gateway.probing import load_own_ips, read_awg_endpoints

    hosts: list[str] = []
    res = run_list(["hostname", "-I"], timeout=5)
    if res.ok:
        for ip in res.stdout.split():
            hosts.append(ip)
    hosts += sorted(load_own_ips())
    hosts += read_awg_endpoints()  # сбой awg → [] (read_awg_endpoints возвращает [])
    seen: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.append(h)
    return seen


def _pidfile_path(captures_dir: Optional[Path] = None) -> Path:
    return (captures_dir or logs_paths.CAPTURES_DIR) / PIDFILE


def _comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return ""


def _read_pidfile(path: Path) -> Optional[int]:
    try:
        raw = path.read_text().strip()
    except OSError:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            pid = int(data.get("pid", 0) or 0)
            return pid or None
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    try:
        return int(raw)
    except ValueError:
        return None


def cleanup_ttl(captures_dir: Optional[Path] = None, ttl_days: int = logs_paths.CAPTURE_TTL_DAYS) -> int:
    """Удалить pcap старше TTL (7 дней §11); возвращает число удалённых."""
    d = captures_dir or logs_paths.CAPTURES_DIR
    removed = 0
    try:
        files = list(d.glob("*.pcap"))
    except OSError:
        return 0
    cutoff = time.time() - ttl_days * 86400
    for f in files:
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def cmd_capture_start(
    duration_h: int = 1,
    max_mb: int = MAX_MB,
    apply: bool = False,
    captures_dir: Optional[Path] = None,
) -> int:
    """capture start: dry-run печатает BPF/лимиты; --apply запускает tcpdump."""
    captures_dir = captures_dir or logs_paths.CAPTURES_DIR
    cleanup_ttl(captures_dir)
    duration_h = min(max(duration_h, 1), MAX_DURATION_H)
    max_mb = min(max(max_mb, 5), 4096)
    # §8.1 ревью G2: кламп к 50 при кольце -C 10 -W 5; >50 → пересчёт C.
    per_file_mb = max(max_mb // RING_FILES, 1)

    if not run_list(["which", "tcpdump"], timeout=5).ok:
        console.print(
            "[error][logs] tcpdump не установлен — выполните `apt install tcpdump`. "
            "Без него bounded-захват недоступен (stdlib-парсер разбирает только "
            "готовый pcap-файл).[/error]"
        )
        return 2

    own = collect_own_hosts()
    filt = bpf_filter(own)
    pidfile = _pidfile_path(captures_dir)
    if pidfile.is_file():
        pid = _read_pidfile(pidfile)
        if pid and _comm(pid) == "tcpdump":
            console.print(
                f"[warning][logs] Захват уже идёт (pid {pid}); "
                "`vds logs capture status` / `capture stop --apply`.[/warning]"
            )
            return 1
        try:
            pidfile.unlink()
        except OSError:
            pass

    if not apply:
        console.print("[info][logs] DRY-RUN план capture start:[/info]")
        console.print(f"[info][logs]   tcpdump -i any -s {SNAPLEN} -G 3600 -W {RING_FILES} -C {per_file_mb} "
                      f"-w {captures_dir}/ (duration {duration_h}h, ring {max_mb} MB)[/info]")
        console.print(f"[info][logs]   BPF: {filt}[/info]")
        console.print("[info][logs] Запустите с --apply для старта.[/info]")
        return 0

    from src.core.lock import FileLock

    try:
        captures_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(captures_dir, 0o700)
    except OSError as exc:
        console.print(f"[error][logs] Не удалось создать {captures_dir}: {exc}[/error]")
        return 1

    args = [
        "tcpdump", "-i", "any", "-s", str(SNAPLEN),
        "-G", "3600", "-W", str(RING_FILES), "-C", str(per_file_mb),
        "-w", str(captures_dir / "cap-%Y%m%d-%H%M%S.pcap"),
        "-U", "-n", filt,
    ]
    with FileLock(logs_paths.CAPTURE_LOCK_FILE):
        proc_pid = os.fork()
        if proc_pid == 0:  # child: отвязать от сессии и exec tcpdump
            os.setsid()
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execvp("tcpdump", args)
            os._exit(127)  # exec не вернулся
        # parent: подождать и проверить, что tcpdump жив
        time.sleep(1.0)
        if _comm(proc_pid) != "tcpdump":
            console.print("[error][logs] tcpdump не запустился (смотрите journal/dmesg).[/error]")
            return 1
        payload = {
            "pid": proc_pid,
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_h": duration_h,
            "max_mb": max_mb,
            "per_file_mb": per_file_mb,
            "filter": filt,
            "own_hosts_count": len(own),
        }
        try:
            fd = os.open(pidfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.chmod(pidfile, 0o600)
        except OSError as exc:
            console.print(f"[error][logs] Не удалось записать pidfile: {exc}[/error]")
            return 1
    console.print(
        f"[success][logs] Захват запущен (pid {proc_pid}, до {duration_h}ч, "
        f"кольцо {max_mb} MB, metadata-only IPv4-фильтр). Останов: "
        "`vds logs capture stop --apply`; состояние: `capture status`.[/success]"
    )
    return 0


def cmd_capture_status(captures_dir: Optional[Path] = None) -> int:
    """capture status: pidfile+comm, файлы, размеры (bounded-кольцо)."""
    captures_dir = captures_dir or logs_paths.CAPTURES_DIR
    pidfile = _pidfile_path(captures_dir)
    if not pidfile.is_file():
        console.print("[info][logs] Захват не запущен (pidfile отсутствует).[/info]")
        return 0
    pid = _read_pidfile(pidfile)
    alive = bool(pid and _comm(pid) == "tcpdump")
    if not alive:
        console.print("[warning][logs] Захват НЕ активен (pidfile протух — tcpdump завершился).[/warning]")
    else:
        console.print(f"[success][logs] Захват активен: pid {pid} (comm=tcpdump).[/success]")
    try:
        files = sorted(captures_dir.glob("*.pcap"))
    except OSError:
        files = []
    total = 0
    for f in files:
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        total += size
        console.print(f"[info][logs]   {f.name}: {size // 1024} KB[/info]")
    console.print(f"[info][logs] Итого: {len(files)} файлов, {total // (1024 * 1024)} MB "
                  f"(TTL {logs_paths.CAPTURE_TTL_DAYS} дней).[/info]")
    return 0


def cmd_capture_stop(apply: bool = False, captures_dir: Optional[Path] = None) -> int:
    """capture stop: kill ТОЛЬКО PID из pidfile после comm==tcpdump (AGENTS §6)."""
    captures_dir = captures_dir or logs_paths.CAPTURES_DIR
    pidfile = _pidfile_path(captures_dir)
    if not pidfile.is_file():
        console.print("[info][logs] Захват не запущен.[/info]")
        return 0
    pid = _read_pidfile(pidfile)
    if not pid or _comm(pid) != "tcpdump":
        console.print("[warning][logs] PID из pidfile не является tcpdump — pidfile удалён, процесс не тронут.[/warning]")
        try:
            pidfile.unlink()
        except OSError:
            pass
        return 0
    if not apply:
        console.print(f"[info][logs] DRY-RUN: SIGTERM pid {pid} (comm=tcpdump). Для исполнения — --apply.[/info]")
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1.0)
        if _comm(pid) == "tcpdump":
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as exc:
        console.print(f"[warning][logs] Не удалось завершить pid {pid}: {exc}[/warning]")
    try:
        pidfile.unlink()
    except OSError:
        pass
    console.print("[success][logs] Захват остановлен; pcap в captures/ (parse-pcap → delete-after-parse).[/success]")
    return 0
