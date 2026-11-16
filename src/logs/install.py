"""Install/remove log-forensics (SPEC OQ-2, WP-2): каталоги, hmac-ключ,
правила-дефолт, sample/daily таймеры. Opt-in: dry-run по умолчанию,
--apply исполняет. Remove — по undo-журналу install-state.json (паттерн
ufw-модуля: снимаем ровно то, что поставили).

Undo-журнал хранит: созданные каталоги, установленные юниты/таймеры,
флаг генерации ключа/правил. Секреты (hmac.key) remove НЕ читает и НЕ
логирует — только удаляет, если journal помечает сгенерированные нами.
"""
from __future__ import annotations

import json
import os
import secrets as pysecrets
from typing import Optional

from src.core.logger import console
from src.core.shell import run_list
from src.logs import paths as logs_paths


def _unit_ctx() -> dict[str, str]:
    """Контекст рендера systemd-шаблонов (паттерн probing._unit_ctx)."""
    import shutil

    return {
        "python": shutil.which("python3") or "/usr/bin/python3",
        "repo_dir": str(logs_paths.REPO_DIR),
        "install_dir": os.environ.get("INSTALL_DIR", "/opt/my-vds"),
    }


def _read_journal(path: Optional[Path] = None) -> dict[str, object]:
    p = path or logs_paths.INSTALL_STATE_FILE
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _write_journal(state: dict[str, object], path: Optional[Path] = None) -> bool:
    p = path or logs_paths.INSTALL_STATE_FILE
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
        return True
    except OSError as exc:
        console.print(f"[error][logs] Не удалось записать undo-журнал {p}: {exc}[/error]")
        return False


def _make_dirs(dry_run: bool) -> list[str]:
    created: list[str] = []
    for d in (logs_paths.TELEMETRY_DIR, logs_paths.CAPTURES_DIR, logs_paths.BUNDLES_DIR, logs_paths.REPORTS_DIR):
        if not d.is_dir():
            created.append(str(d))
            if not dry_run:
                try:
                    d.mkdir(parents=True, exist_ok=True)
                    os.chmod(d, 0o700)
                except OSError as exc:
                    console.print(f"[error][logs] mkdir {d}: {exc}[/error]")
                    return created
    return created


def _ensure_hmac_key(dry_run: bool) -> tuple[bool, str]:
    """hmac.key (0600): создаётся ТОЛЬКО при отсутствии (не ротируем —
    детерминизм HMAC-IP между сборами)."""
    key_file = logs_paths.HMAC_KEY_FILE
    if key_file.is_file():
        return False, str(key_file)
    if not dry_run:
        from src.core.secrets import write_secret_atomic

        if not write_secret_atomic(str(key_file), pysecrets.token_hex(32), 0o600):
            return False, ""
    return True, str(key_file)


def _ensure_rules_default(dry_run: bool) -> tuple[bool, str]:
    """rules.json с дефолтами — только при отсутствии (override оператора
    не перезаписываем)."""
    rules_file = logs_paths.RULES_FILE
    if rules_file.is_file():
        return False, str(rules_file)
    if not dry_run:
        from src.logs.detect import DEFAULT_THRESHOLDS

        from src.core.secrets import write_secret_atomic

        payload = json.dumps(DEFAULT_THRESHOLDS, ensure_ascii=False, indent=1, sort_keys=True)
        if not write_secret_atomic(str(rules_file), payload, 0o600):
            return False, ""
    return True, str(rules_file)


def cmd_install(apply: bool = False, root: str = "/") -> int:
    """install: dry-run печатает план; --apply создаёт каталоги/ключ/правила
    и ставит таймеры vds-logs-sample (5 мин) и vds-logs-daily (04:15)."""
    if not apply:
        console.print("[info][logs] DRY-RUN план install:[/info]")
        console.print(f"[info][logs]   1. каталоги {logs_paths.TELEMETRY_DIR}, "
                      f"{logs_paths.CAPTURES_DIR}, {logs_paths.BUNDLES_DIR}, {logs_paths.REPORTS_DIR} (0700)[/info]")
        console.print(f"[info][logs]   2. hmac-ключ {logs_paths.HMAC_KEY_FILE} (0600, только при отсутствии)[/info]")
        console.print(f"[info][logs]   3. правила {logs_paths.RULES_FILE} (0600, дефолты §7.5, только при отсутствии)[/info]")
        console.print(f"[info][logs]   4. юниты {logs_paths.SAMPLE_UNIT}+{logs_paths.SAMPLE_TIMER} (5 мин, "
                      f"RandomizedDelaySec=30, Nice=10, idle, MemoryMax=64M)[/info]")
        console.print(f"[info][logs]   5. юниты {logs_paths.DAILY_UNIT}+{logs_paths.DAILY_TIMER} (04:15, MemoryMax=192M)[/info]")
        console.print("[info][logs] Запустите с --apply для исполнения (opt-in OQ-2).[/info]")
        return 0

    from src.core.lock import FileLock
    from src.core.units import install_unit

    ctx = _unit_ctx()
    with FileLock(logs_paths.LOCK_FILE):
        journal = _read_journal()
        created = _make_dirs(dry_run=False)
        key_created, key_path = _ensure_hmac_key(dry_run=False)
        rules_created, rules_path = _ensure_rules_default(dry_run=False)
        console.print(
            f"[info][logs] каталоги: {created or 'на месте'}; hmac.key: "
            f"{'сгенерирован' if key_created else 'уже есть'}; rules.json: "
            f"{'дефолты записаны' if rules_created else 'уже есть'}[/info]"
        )
        if key_created and not key_path:
            return 1

        installed: list[str] = []
        for template, name in (
            (logs_paths.SAMPLE_SERVICE_TEMPLATE, logs_paths.SAMPLE_UNIT),
            (logs_paths.SAMPLE_TIMER_TEMPLATE, logs_paths.SAMPLE_TIMER),
            (logs_paths.DAILY_SERVICE_TEMPLATE, logs_paths.DAILY_UNIT),
            (logs_paths.DAILY_TIMER_TEMPLATE, logs_paths.DAILY_TIMER),
        ):
            if not install_unit(template, name, ctx, root=root):
                return 1
            installed.append(name)

        start_res = run_list(["systemctl", "start", logs_paths.SAMPLE_TIMER], timeout=15)
        start_res2 = run_list(["systemctl", "start", logs_paths.DAILY_TIMER], timeout=15)
        if not (start_res.ok and start_res2.ok):
            console.print(
                f"[error][logs] Не удалось запустить таймеры: "
                f"{start_res.stderr.strip()} {start_res2.stderr.strip()}[/error]"
            )
            return 1

        journal.update(
            {
                "version": 1,
                "units": sorted(set(list(journal.get("units") or []) + installed)),
                "dirs_created": sorted(set(list(journal.get("dirs_created") or []) + created)),
                "key_generated": bool(key_created or journal.get("key_generated")),
                "rules_generated": bool(rules_created or journal.get("rules_generated")),
                "installed_at": ctx.get("install_dir", ""),
            }
        )
        if not _write_journal(journal):
            return 1
    console.print(
        f"[success][logs] log-forensics установлен: sample 5 мин + daily 04:15 "
        f"запущены. Откат: `vds logs remove --apply` (по undo-журналу).[/success]"
    )
    return 0


def cmd_remove(apply: bool = False, root: str = "/") -> int:
    """remove: dry-run печатает план; --apply демонтирует юниты/таймеры по
    undo-журналу. Каталоги артефактов не удаляем (данные владельца —
    руками, ADR-012 «откат»)."""
    journal = _read_journal()
    units = [str(u) for u in (journal.get("units") or [])] or [
        logs_paths.SAMPLE_UNIT, logs_paths.SAMPLE_TIMER,
        logs_paths.DAILY_UNIT, logs_paths.DAILY_TIMER,
    ]
    if not apply:
        console.print("[info][logs] DRY-RUN план remove:[/info]")
        console.print(f"[info][logs]   systemctl disable --now {', '.join(units)}[/info]")
        console.print(f"[info][logs]   удалить юниты + undo-журнал {logs_paths.INSTALL_STATE_FILE}[/info]")
        console.print(f"[info][logs]   каталоги {logs_paths.TELEMETRY_DIR}/{logs_paths.FORENSICS_DIR} НЕ удаляются (данные владельца)[/info]")
        console.print("[info][logs] Запустите с --apply для исполнения.[/info]")
        return 0

    from src.core.lock import FileLock
    from src.core.units import remove_unit

    with FileLock(logs_paths.LOCK_FILE):
        for name in units:
            run_list(["systemctl", "disable", "--now", name], timeout=15)
            if not remove_unit(name, root=root):
                console.print(f"[warning][logs] юнит {name} не удалён (возможно, отсутствует)[/warning]")
        try:
            logs_paths.INSTALL_STATE_FILE.unlink(missing_ok=True)
        except OSError as exc:
            console.print(f"[error][logs] Не удалось удалить undo-журнал: {exc}[/error]")
            return 1
    console.print("[success][logs] log-forensics демонтирован (артефакты сохранены).[/success]")
    return 0


def cmd_status() -> int:
    """`vds logs status`: каталоги, таймеры, последний сэмпл, disk_pct, захват."""
    from src.logs.collect import disk_usage_pct, read_samples

    for name, d in (
        ("telemetry", logs_paths.TELEMETRY_DIR),
        ("forensics", logs_paths.FORENSICS_DIR),
    ):
        exists = d.is_dir()
        console.print(f"[{'success' if exists else 'error'}][logs] {name}: {d} "
                      f"({'есть' if exists else 'нет — logs install --apply'})[/{'success' if exists else 'error'}]")
    for timer in (logs_paths.SAMPLE_TIMER, logs_paths.DAILY_TIMER):
        res = run_list(["systemctl", "is-active", timer], timeout=10)
        state = res.stdout.strip() or "unknown"
        tag = "success" if state == "active" else "warning"
        console.print(f"[{tag}][logs] {timer}: {state}[/{tag}]")
    samples = read_samples(window_days=1)
    if samples:
        last = samples[-1]
        probe = last.get("probe") if isinstance(last.get("probe"), dict) else {}
        console.print(
            f"[info][logs] последний сэмпл: {last.get('ts')} "
            f"(threat={probe.get('threat_level', 'quiet')}, "
            f"computed_by={last.get('computed_by', '')})[/info]"
        )
    else:
        console.print("[warning][logs] сэмплов за сутки нет[/warning]")
    disk = disk_usage_pct()
    if disk is not None:
        tag = "error" if disk > logs_paths.DISK_CAP_PCT else "info"
        note = " — disk-cap активен, сэмплы не пишутся" if disk > logs_paths.DISK_CAP_PCT else ""
        console.print(f"[{tag}][logs] disk_pct: {disk}%{note}[/{tag}]")
    from src.logs.capture import _pidfile_path, _comm, _read_pidfile

    pidfile = _pidfile_path()
    if pidfile.is_file():
        pid = _read_pidfile(pidfile)
        alive = bool(pid and _comm(pid) == "tcpdump")
        console.print(f"[info][logs] capture: pid={pid} ({'активен' if alive else 'неактивен'})[/info]")
    else:
        console.print("[info][logs] capture: не запущен[/info]")
    return 0
