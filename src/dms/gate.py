"""Gate-логика DMS (SPEC-20261124-quiet-exit §5, §10 P2).

Пинг на Healthchecks уходит **только при живых ногах** — иначе DMS ложно
успокаивает мониторинг при падении канала:

* exit: `awg0` UP + `awg2` UP + `vds-wstunnel-server.service` active;
* relay: `awg0` UP + policy `table 100` на месте + data-plane активного
  носителя (`ping -c1 -W3 10.11.0.1` awg-нога или `10.12.0.1` wg-ws0).

Отказ gate → `GET <DMS_PING_URL>/fail` — мгновенный алерт (Healthchecks
показывает fail сразу, не дожидаясь просрочки period).

HTTP — stdlib `urllib.request`, таймаут, без shell. URL в journal/stdout
не печатается — только машиночитаемые теги `DMS-PING`/`DMS-FAIL`.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import ShellResult, run_list
from src.core.units import unit_active
from src.dms.env import DmsConfig, ROLE_EXIT, ROLE_RELAY
from src.dms.paths import DMS_LOCK_FILE
from src.relay.paths import RELAY_MARK, RELAY_TABLE

# --- exit-узел
EXIT_AWG_ADMIN_IFACE = "awg0"        # OOB/admin AWG (10.9.0.1/24)
EXIT_RELAY_IFACE = "awg2"            # нога до релея (10.11.0.0/30)
WSTUNNEL_SERVER_UNIT = "vds-wstunnel-server.service"

# --- релей
RELAY_AWG_IFACE = "awg0"
RELAY_CARRIER_AWG_GW = "10.11.0.1"   # exit-конец awg1/awg2-ноги
RELAY_CARRIER_WS_GW = "10.12.0.1"    # exit-конец wg-ws0-ноги

HTTP_TIMEOUT_S = 10

JournalFn = Callable[[str], None]


@dataclass
class GateResult:
    """Итог gate-проверки. `detail` секретов не содержит."""

    ok: bool
    role: str
    detail: str
    checks: dict[str, bool] = field(default_factory=dict)


def _tag(text: str) -> None:
    """Машиночитаемая строка в journal: без переносов и разметки."""
    console.print(text, markup=False, highlight=False, soft_wrap=True)


def _iface_up(name: str, run: Callable[..., ShellResult] = run_list) -> bool:
    return run(["ip", "link", "show", name], timeout=10).ok


def _unit_active(name: str, run: Callable[..., ShellResult] = run_list) -> bool:
    result = run(["systemctl", "is-active", name], timeout=10)
    return result.ok and result.output.strip() == "active"


def _table_ok(run: Callable[..., ShellResult] = run_list) -> bool:
    """Policy-routing table 100 (fwmark) на месте (`ip rule show`)."""
    rules = run(["ip", "rule", "show"], timeout=10)
    return rules.ok and f"fwmark {RELAY_MARK} lookup {RELAY_TABLE}" in rules.stdout


def _ping_alive(ip: str, run: Callable[..., ShellResult] = run_list) -> bool:
    """Data-plane проба носителя: `ping -c1 -W3 <exit-конец ноги>`."""
    return run(["ping", "-c", "1", "-W", "3", ip], timeout=10).ok


def check_exit(run: Callable[..., ShellResult] = run_list) -> GateResult:
    """exit: awg0 UP + awg2 UP + wstunnel-server active (SPEC §5)."""
    awg0 = _iface_up(EXIT_AWG_ADMIN_IFACE, run)
    awg2 = _iface_up(EXIT_RELAY_IFACE, run)
    wst = _unit_active(WSTUNNEL_SERVER_UNIT, run)
    checks = {"awg0": awg0, "awg2": awg2, "wstunnel_server": wst}
    down = [name for name, up in checks.items() if not up]
    detail = "all up" if not down else "down: " + ",".join(down)
    return GateResult(ok=not down, role=ROLE_EXIT, detail=detail, checks=checks)


def check_relay(run: Callable[..., ShellResult] = run_list) -> GateResult:
    """relay: awg0 UP + table 100 + data-plane активного носителя (SPEC §5).

    Носителей два (ADR-016): awg-нога (10.11.0.1) и wg-ws0 (10.12.0.1).
    Gate жив, если data-plane отвечает ХОТЯ БЫ ОДНОГО; отказ обоих — /fail.
    """
    awg0 = _iface_up(RELAY_AWG_IFACE, run)
    table = _table_ok(run)
    awg_carrier = _ping_alive(RELAY_CARRIER_AWG_GW, run)
    ws_carrier = _ping_alive(RELAY_CARRIER_WS_GW, run)
    checks = {
        "awg0": awg0,
        "table100": table,
        "carrier_awg": awg_carrier,
        "carrier_wstunnel": ws_carrier,
    }
    problems: list[str] = []
    if not awg0:
        problems.append("awg0 down")
    if not table:
        problems.append("table100 missing")
    if not (awg_carrier or ws_carrier):
        problems.append("both carriers dead")
    detail = "awg carrier" if awg_carrier else ("wstunnel carrier" if ws_carrier else "no carrier")
    if problems:
        detail = "; ".join(problems)
    return GateResult(ok=not problems, role=ROLE_RELAY, detail=detail, checks=checks)


def check_gate(cfg: DmsConfig, run: Callable[..., ShellResult] = run_list) -> GateResult:
    """Gate по роли из конфига; роль не задана — gate провален."""
    if cfg.role == ROLE_EXIT:
        return check_exit(run)
    if cfg.role == ROLE_RELAY:
        return check_relay(run)
    return GateResult(ok=False, role=cfg.role, detail="role not configured")


def fail_url(url: str) -> str:
    """`<URL>/fail` для мгновенного алерта (конвенция Healthchecks)."""
    return url.rstrip("/") + "/fail"


def http_get(url: str, timeout: int = HTTP_TIMEOUT_S) -> tuple[bool, str]:
    """Исходящий HTTPS GET (stdlib urllib). (ok, errclass); URL не печатается."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            ok = 200 <= response.status < 300
            return ok, "" if ok else f"http_{response.status}"
    except urllib.error.HTTPError as exc:
        return False, f"http_{exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, type(exc).__name__


def run_ping(
    *,
    config_path: str,
    run: Callable[..., ShellResult] = run_list,
    get: Callable[..., tuple[bool, str]] = http_get,
    now_journal: Optional[JournalFn] = None,
) -> int:
    """Один тик DMS (`vds dms ping`, ExecStart юнита). Exit-код всегда 0.

    Порядок: прочитать конфиг → gate по роли → GET URL или GET `<URL>/fail`.
    URL нигде не печатается. Сбой сети/HTTP — не сбой юнита (next tick).
    """
    from src.dms.env import load_config  # лениво: CLI-старт не тянет модуль

    journal = now_journal or _tag
    cfg = load_config(config_path)

    if not cfg.ping_url:
        journal("DMS-PING skip no_url")
        return 0
    gate = check_gate(cfg, run)
    if gate.ok:
        ok, errclass = get(cfg.ping_url)
        if ok:
            journal(f"DMS-PING ok role={cfg.role} gate={gate.detail}")
        else:
            journal(f"DMS-PING failed role={cfg.role} err={errclass}")
        return 0

    journal(f"DMS-PING gatefail role={cfg.role} detail={gate.detail}")
    ok, errclass = get(fail_url(cfg.ping_url))
    if ok:
        journal("DMS-FAIL sent")
    else:
        journal(f"DMS-FAIL send_failed err={errclass}")
    return 0


def run_ping_locked(**kwargs) -> int:
    """`run_ping` под FileLock (nonblock): пересечение тиков — пропуск."""
    lock = FileLock(DMS_LOCK_FILE)
    if not lock.acquire(nonblock=True):
        _tag("DMS-PING skip locked")
        return 0
    try:
        return run_ping(**kwargs)
    finally:
        lock.release()
