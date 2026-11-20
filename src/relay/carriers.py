"""Селектор носителей p2p relay↔exit (ADR-016 §4 I-2, WP-P2P-3).

Два носителя: `awg` (приоритет 1, UDP, манёвр P25 внутри) и `wstunnel`
(приоритет 2, WG поверх WSS). Селектор живёт на **реле** и управляет
`table 100`; exit не трогается (граница доверия I-5).

**Блокировка (анти-deadlock, AC-7):** и манёвр P25 (`maneuver.py`), и CLI
селектора делят один lock-файл `RELAY_MANEUVER_LOCK_FILE`. Публичные точки
(`run_switch`) берут lock сами; внутренние (`on_maneuver_rollback`,
`fallback_tick`) вызываются **уже под локом** и его не берут.

**Обратная совместимость:** на релее без `/etc/amnezia/wg-ws0.conf` всё —
чистый no-op: P25 работает по-старому, state не пишется.

**State** `/var/lib/vds/p2p-carriers.json` (0600, атомарно, aware-UTC,
история `switched_at` ограничена HISTORY_CAP записей).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from src.core.logger import console
from src.core.shell import ShellResult, run_list

CARRIERS_STATE_PATH = Path("/var/lib/vds/p2p-carriers.json")
CARRIER_IFACE_SCRIPT = Path("/etc/vds-relay/carrier-default-iface.sh")

PRIMARY = "awg"
WSTUNNEL = "wstunnel"
IFACES = {PRIMARY: "awg1", WSTUNNEL: "wg-ws0"}
PEER_IPS = {PRIMARY: "10.11.0.1", WSTUNNEL: "10.12.0.1"}
WG_WS_CONF = Path("/etc/amnezia/wg-ws0.conf")

STATE_PRIMARY = "primary"
STATE_FALLBACK = "fallback"
STATE_RECOVERING = "recovering"
STATE_EXHAUSTED = "exhausted"

FALLBACK_TO_RECOVER_MIN_S = 600   # минимум в fallback до возврата (AC-6)
RECOVER_OK_STREAK = 3             # подряд успешных проб awg1 для возврата
WG_WS_FAIL_LIMIT = 3              # 3/3 провалов wg-ws0 → exhausted (анти-джиттер)
MAX_SWITCHES_PER_HOUR = 3         # лимит переключений → exhausted
HISTORY_CAP = 100                 # записей switched_at в state

PROBE_TIMEOUT_S = 3


class CarrierError(RuntimeError):
    """Ошибка селектора носителей (сообщение — для оператора)."""


# --- время (aware UTC — урок P0 из WP-PW-HYSTERESIS) -----------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def parse_ts(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# --- состояние -------------------------------------------------------------

def default_state(now: Optional[datetime] = None) -> dict:
    moment = iso(now or utcnow())
    return {
        "version": 1,
        "active": PRIMARY,
        "active_iface": IFACES[PRIMARY],
        "state": STATE_PRIMARY,
        "since": moment,
        "wg_ws0_installed": False,
        "wg_fail_streak": 0,
        "recover_ok_streak": 0,
        "fallback_since": None,
        "exhausted_reason": "",
        "switched_at": [],
    }


def load_state(path: Optional[str] = None) -> dict:
    target = Path(path) if path is not None else CARRIERS_STATE_PATH
    if not target.is_file():
        return default_state()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return default_state()  # битый state → безопасный дефолт (AC-S4)
    if not isinstance(data, dict) or data.get("active") not in (PRIMARY, WSTUNNEL):
        return default_state()
    base = default_state()
    base.update({k: v for k, v in data.items() if isinstance(v, (str, int, bool, list))})
    return base


def save_state(state: dict, path: Optional[str] = None) -> bool:
    target = Path(path) if path is not None else CARRIERS_STATE_PATH
    tmp: Optional[str] = None  # иначе UnboundLocalError в except при mkstemp-сбое
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = __import__("tempfile").mkstemp(
            dir=str(target.parent), prefix=".p2p-carriers."
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        return True
    except OSError:
        if tmp:  # mkstemp мог упасть до присвоения
            Path(tmp).unlink(missing_ok=True)
        return False


def wg_ws0_installed() -> bool:
    """Носитель №2 установлен? (нет conf — селектор весь no-op)."""
    return WG_WS_CONF.is_file()


def active_carrier(state: Optional[dict] = None) -> str:
    st = state if state is not None else load_state()
    return str(st.get("active") or PRIMARY)


def is_fallback(state: Optional[dict] = None) -> bool:
    """P25 в fallback не крутит порты (AC-S6)."""
    return wg_ws0_installed() and active_carrier(state) == WSTUNNEL


def is_exhausted(state: Optional[dict] = None) -> bool:
    """P0-5: селектор в exhausted — тик сначала пробует автовыход."""
    st = state if state is not None else load_state()
    return wg_ws0_installed() and str(st.get("state") or "") == STATE_EXHAUSTED


# --- пробы ------------------------------------------------------------------

def probe(iface: str, peer_ip: str,
          run: Optional[Callable[..., ShellResult]] = None) -> bool:
    """Data-plane проба носителя: ping через интерфейс (SPEC §5)."""
    runner = run or run_list
    res = runner(
        ["ping", "-I", iface, "-c1", "-W2", "-n", peer_ip], timeout=PROBE_TIMEOUT_S
    )
    return bool(res.ok)


# --- переключение (внутреннее, БЕЗ захвата лока) ----------------------------

def _switch_route(iface: str, run: Optional[Callable[..., ShellResult]] = None) -> None:
    res = (run or run_list)(
        ["ip", "route", "replace", "default", "dev", iface, "table", "100"],
        timeout=10,
    )
    if not res.ok:
        raise CarrierError(
            f"ip route replace default dev {iface} table 100: "
            f"{res.stderr.strip() or res.stdout.strip()}"
        )


def _prune_history(state: dict) -> None:
    entries = state.get("switched_at") or []
    if len(entries) > HISTORY_CAP:
        state["switched_at"] = entries[-HISTORY_CAP:]


def _switches_last_hour(state: dict, now: datetime) -> int:
    cutoff = now - timedelta(hours=1)
    return sum(
        1 for raw in (state.get("switched_at") or [])
        if (ts := parse_ts(raw)) and ts > cutoff
    )


def _apply_switch(
    to: str,
    *,
    state: dict,
    now: datetime,
    reason: str,
    state_path: Optional[str] = None,
    run: Optional[Callable[..., ShellResult]] = None,
) -> None:
    """Сменить table 100 и state. **Лок берёт вызывающий** (AC-7)."""
    if _switches_last_hour(state, now) >= MAX_SWITCHES_PER_HOUR:
        state["state"] = STATE_EXHAUSTED
        state["exhausted_reason"] = "лимит 3 переключений в час исчерпан"
        # P1-1: сохраняем ДО raise — иначе переход в exhausted не доживёт до диска.
        save_state(state, state_path)
        raise CarrierError(state["exhausted_reason"])
    try:
        _switch_route(IFACES[to], run=run)
    except CarrierError as exc:
        # P1-1: сбой ip route — фиксируем exhausted на диске и пробрасываем.
        state["state"] = STATE_EXHAUSTED
        state["exhausted_reason"] = str(exc)
        save_state(state, state_path)
        raise
    state["active"] = to
    state["active_iface"] = IFACES[to]
    state["state"] = STATE_FALLBACK if to == WSTUNNEL else STATE_PRIMARY
    state["since"] = iso(now)
    state["fallback_since"] = iso(now) if to == WSTUNNEL else None
    state.setdefault("switched_at", []).append(iso(now))
    _prune_history(state)
    state["reason"] = reason
    if not save_state(state, state_path):
        raise CarrierError("не удалось сохранить p2p-carriers.json (0600)")


# --- P25 no-op / хук rollback ------------------------------------------------

def p25_noop_reason(state: Optional[dict] = None) -> Optional[str]:
    """Почему тик P25 должен быть no-op; None — работаем как обычно."""
    if not wg_ws0_installed():
        return None  # носитель №2 не установлен — P25 как раньше
    if is_fallback(state):
        return "traffic on wstunnel (fallback) — P25 не крутит порты (AC-S6)"
    return None


def on_maneuver_rollback(
    state_path: Optional[str] = None,
    *,
    now: Optional[datetime] = None,
    probe_fn: Optional[Callable[[str, str], bool]] = None,
    run: Optional[Callable[..., ShellResult]] = None,
) -> dict:
    """Хук из maneuver.py ПОСЛЕ rollback (уже под локом P25).

    Pre-check `ping -I wg-ws0 10.12.0.1`:
    * ok → `primary → fallback` (table 100 на wg-ws0);
    * провален → `primary → exhausted` (оба мертвы, AC-S5).
    Носитель №2 не установлен → no-op.
    """
    moment = utcnow() if now is None else now
    if not wg_ws0_installed():
        return {"action": "noop", "reason": "wg-ws0 не установлен"}
    state = load_state(state_path)
    if state.get("state") == STATE_EXHAUSTED:
        return {"action": "noop", "reason": "селектор в exhausted"}
    if active_carrier(state) != PRIMARY:
        return {"action": "noop", "reason": f"active={active_carrier(state)}"}

    # P0-1 (ревью 769a7eb): вызов через фолбэк — модульная probe, не затенение.
    # P1-2 (ревью 5513b68): фолбэк единообразен с fallback_tick — с run=run.
    run_probe = probe_fn or (lambda i, p: probe(i, p, run=run))
    wstun_ok = run_probe(IFACES[WSTUNNEL], PEER_IPS[WSTUNNEL])
    if wstun_ok:
        try:
            _apply_switch(
                WSTUNNEL, state=state, now=moment,
                reason="rollback P25 — UDP-пул заблокирован, уходим на WSS",
                state_path=state_path, run=run,
            )
            return {"action": "switched", "to": WSTUNNEL, "state": state["state"]}
        except CarrierError as exc:
            return {"action": "exhausted", "reason": str(exc)}
    state["state"] = STATE_EXHAUSTED
    state["exhausted_reason"] = "rollback P25, pre-check wg-ws0 провален — оба носителя мертвы"
    if not save_state(state, state_path):
        return {"action": "exhausted", "reason": state["exhausted_reason"] + " (state не сохранён)"}
    return {"action": "exhausted", "reason": state["exhausted_reason"]}


# --- тик в fallback (prefer_primary + анти-джиттер) --------------------------

def reset_p25_state(maneuver_path: Optional[str] = None) -> None:
    """Возврат на primary: сброс P25-серии (иначе старые 3/3 дадут ложный манёвр).

    P0-4 (ревью 769a7eb): счётчик серии живёт в ``last_sample``;
    верхнеуровневый ``st["consecutive_failures"]`` maneuver.py не читает.
    """
    from src.relay.maneuver import load_maneuver_state, save_maneuver_state  # лениво

    st = load_maneuver_state(maneuver_path)
    if isinstance(st.get("last_sample"), dict):
        st["last_sample"]["consecutive_failures"] = 0
    st["cooldown_until"] = None
    st["failed_ports"] = []
    st["exhausted"] = False
    st["state"] = "healthy"
    save_maneuver_state(st, maneuver_path)


def fallback_tick(
    state_path: Optional[str] = None,
    maneuver_path: Optional[str] = None,
    *,
    now: Optional[datetime] = None,
    probe_fn: Optional[Callable[[str, str], bool]] = None,
    run: Optional[Callable[..., ShellResult]] = None,
) -> dict:
    """Тик селектора при `active == "wstunnel"` (вызывается под локом P25).

    * liveness `wg-ws0`: 3/3 провалов → `exhausted` (анти-джиттер);
    * liveness `awg1`: 3 подряд ok **и** ≥ 600 с в fallback → возврат на
      primary + сброс P25-серии;
    * любая неудача сбрасывает серию.
    """
    moment = utcnow() if now is None else now
    if not wg_ws0_installed():
        return {"action": "noop", "reason": "wg-ws0 не установлен"}
    state = load_state(state_path)
    if active_carrier(state) != WSTUNNEL:
        return {"action": "noop", "reason": f"active={active_carrier(state)}"}

    # P0-1: параметр probe_fn — фолбэк на модульную probe (не затенённую).
    run_probe = probe_fn or (lambda i, p: probe(i, p, run=run))

    # 1) жив ли резерв?
    if run_probe(IFACES[WSTUNNEL], PEER_IPS[WSTUNNEL]):
        state["wg_fail_streak"] = 0
    else:
        state["wg_fail_streak"] = int(state.get("wg_fail_streak") or 0) + 1
        if state["wg_fail_streak"] >= WG_WS_FAIL_LIMIT:
            state["state"] = STATE_EXHAUSTED
            state["exhausted_reason"] = (
                f"wg-ws0 не отвечает {WG_WS_FAIL_LIMIT} раза подряд"
            )
            save_state(state, state_path)
            return {"action": "exhausted", "reason": state["exhausted_reason"]}

    # 2) оживил ли awg1? (проба через интерфейс — connected-маршрут в main)
    fallback_since = parse_ts(state.get("fallback_since"))
    min_age_ok = (
        fallback_since is not None
        and (moment - fallback_since) >= timedelta(seconds=FALLBACK_TO_RECOVER_MIN_S)
    )
    awg_ok = run_probe(IFACES[PRIMARY], PEER_IPS[PRIMARY])
    if awg_ok and min_age_ok:
        state["recover_ok_streak"] = int(state.get("recover_ok_streak") or 0) + 1
        # P1-3: серия 1..2 — recovering (SPEC §5); сброс — обратно fallback.
        if state["recover_ok_streak"] >= 1:
            state["state"] = STATE_RECOVERING
    else:
        state["recover_ok_streak"] = 0
        if state["state"] == STATE_RECOVERING:
            state["state"] = STATE_FALLBACK

    if state["recover_ok_streak"] >= RECOVER_OK_STREAK:
        try:
            _apply_switch(
                PRIMARY, state=state, now=moment,
                reason="awg1 восстановился — возврат на primary (prefer_primary)",
                state_path=state_path, run=run,
            )
        except CarrierError as exc:
            # P1-1: лимит/сбой маршрута — не поднимать (maneuver ловит только
            # ManeuverError/OSError): состояние уже сохранено в state.
            return {"action": "exhausted", "reason": str(exc)}
        reset_p25_state(maneuver_path)
        return {"action": "switched", "to": PRIMARY, "state": STATE_PRIMARY}

    if not save_state(state, state_path):
        return {"action": "noop", "reason": "state не сохранён"}
    return {
        "action": "hold",
        "state": state["state"],
        "wg_fail_streak": state["wg_fail_streak"],
        "recover_ok_streak": state["recover_ok_streak"],
        "min_age_ok": min_age_ok,
    }


def exhausted_recovery_check(
    state_path: Optional[str] = None,
    *,
    now: Optional[datetime] = None,
    probe_fn: Optional[Callable[[str, str], bool]] = None,
    run: Optional[Callable[..., ShellResult]] = None,
) -> dict:
    """Автовыход из `exhausted`, когда любой носитель стабильно отвечает."""
    moment = utcnow() if now is None else now
    if not wg_ws0_installed():
        return {"action": "noop"}
    state = load_state(state_path)
    if state.get("state") != STATE_EXHAUSTED:
        return {"action": "noop"}
    # P0-1: параметр probe_fn — фолбэк на модульную probe (не затенённую).
    run_probe = probe_fn or (lambda i, p: probe(i, p, run=run))
    # P2-1 (ревью 5513b68): сбой ip route при автовыходе не пробрасывается —
    # maneuver.py ловит только ManeuverError/OSError.
    for carrier, state_name in (
        (PRIMARY, STATE_PRIMARY),
        (WSTUNNEL, STATE_FALLBACK),
    ):
        if not run_probe(IFACES[carrier], PEER_IPS[carrier]):
            continue
        state["state"] = state_name
        state["active"] = carrier
        state["active_iface"] = IFACES[carrier]
        state["exhausted_reason"] = ""
        state["wg_fail_streak"] = 0
        state["since"] = iso(moment)
        # P2 (ревью dfe7f2c): без fallback_since на wstunnel условие
        # min_age_ok в fallback_tick останется False — prefer_primary
        # (возврат на awg1) никогда не сработал бы.
        state["fallback_since"] = iso(moment) if carrier == WSTUNNEL else None
        try:
            _switch_route(IFACES[carrier], run=run)
        except CarrierError as exc:
            return {"action": "hold", "reason": str(exc)}
        save_state(state, state_path)
        return {"action": "recovered", "to": carrier}
    return {"action": "hold", "reason": "оба носителя всё ещё мертвы"}


# --- CLI --------------------------------------------------------------------

def run_status(json_output: bool = False) -> int:
    import json as _json

    state = load_state()
    payload = {
        **state,
        "wg_ws0_installed": wg_ws0_installed(),
        "switches_last_hour": _switches_last_hour(state, utcnow()),
    }
    if json_output:
        print(_json.dumps(payload, ensure_ascii=False))
        return 0
    console.print(f"[info][carrier] active={payload['active']} "
                  f"({payload['active_iface']}), state={payload['state']}[/info]")
    console.print(f"[info][carrier] wg-ws0 установлен: {payload['wg_ws0_installed']}[/info]")
    console.print(f"[info][carrier] переключений за час: "
                  f"{payload['switches_last_hour']}/{MAX_SWITCHES_PER_HOUR}[/info]")
    if payload.get("exhausted_reason"):
        console.print(f"[warning][carrier] exhausted: {payload['exhausted_reason']}[/warning]")
    return 0


def run_switch(to: str, apply: bool = False,
               state_path: Optional[str] = None) -> int:
    """Ручное переключение (публичная точка: берёт lock сама — AC-7)."""
    from src.relay.maneuver import RELAY_MANEUVER_LOCK_FILE
    from src.core.lock import FileLock, LockError

    if to not in (PRIMARY, WSTUNNEL):
        console.print(f"[error][carrier] --to: ожидалось {PRIMARY}|{WSTUNNEL}[/error]")
        return 1
    if to == WSTUNNEL and not wg_ws0_installed():
        console.print(
            "[error][carrier] wg-ws0 не установлен — сначала "
            "`vds relay wstunnel client … --apply`[/error]"
        )
        return 1
    if not apply:
        console.print(f"[info][carrier] dry-run: переключил бы table 100 → "
                      f"{IFACES[to]} ({to}). Реальное исполнение — --apply.[/info]")
        return 0
    if os.geteuid() != 0:
        console.print("[error][carrier] --apply требует root (sudo).[/error]")
        return 1
    now = utcnow()
    try:
        with FileLock(RELAY_MANEUVER_LOCK_FILE):
            state = load_state(state_path)
            if active_carrier(state) == to:
                console.print(f"[info][carrier] уже active={to} — ничего не делаем[/info]")
                return 0
            _apply_switch(to, state=state, now=now,
                          reason="ручное переключение (carrier switch)",
                          state_path=state_path)
            # P0-1 (ревью 5513b68): сброс P25-серии ВНУТРИ lock (гонка с таймером)
            # и правильное имя (старое _reset_p25_state давало NameError).
            if to == PRIMARY:
                reset_p25_state(None)
    except (CarrierError, LockError, OSError) as exc:
        console.print(f"[error][carrier] {exc}[/error]")
        return 1
    console.print(f"[success][carrier] table 100 → {IFACES[to]} ({to})[/success]")
    return 0


# --- AC-S4: script для policy-юнита ( ExecStartPost) ------------------------

def render_default_iface_script() -> str:
    """ExecStartPost policy-юнита: table 100 → активный носитель из state.

    Дефолт — `awg1` (отсутствие/битость state совместимы со старым поведением).
    `ip link show` проверяется: интерфейс не поднялся → маршрут не трогаем
    (fallback на awg1 вместо падения юнита — ADR-016 I-2a).
    """
    return (
        "#!/bin/sh\n"
        "# ADR-016 AC-S4: table 100 -> активный носитель из p2p-carriers.json.\n"
        "# Генерируется `vds relay wstunnel client` / `vds relay carrier install`.\n"
        "# Дефолт awg1; отсутствие/битость state — старое поведение.\n"
        "f=/var/lib/vds/p2p-carriers.json\n"
        "iface=$1\n"
        "if [ -s \"$f\" ]; then\n"
        "  i=$(python3 -c 'import json,sys\n"
        "try:\n"
        "    d=json.load(open(sys.argv[1]))\n"
        "    a=str(d.get(\"active_iface\") or \"\")\n"
        "    print(a if a in (\"awg1\", \"wg-ws0\") else \"\")\n"
        "except Exception:\n"
        "    print(\"\")' \"$f\" 2>/dev/null)\n"
        "  case \"$i\" in\n"
        "    awg1|wg-ws0) iface=$i ;;\n"
        "  esac\n"
        "fi\n"
        "if ip link show \"$iface\" >/dev/null 2>&1; then\n"
        "  ip route replace default dev \"$iface\" table 100\n"
        "fi\n"
        "exit 0\n"
    )


def ensure_default_iface_script(run: Optional[Callable[..., ShellResult]] = None) -> None:
    """Записать/обновить `carrier-default-iface.sh` (0755, без секретов)."""
    from src.relay.paths import RELAY_DIR

    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    path = CARRIER_IFACE_SCRIPT
    path.write_text(render_default_iface_script(), encoding="utf-8")
    os.chmod(path, 0o755)
    console.print(f"[change][carrier] script {path} обновлён (0755).[/change]")


__all__ = [
    "CARRIERS_STATE_PATH", "PRIMARY", "WSTUNNEL", "IFACES", "PEER_IPS",
    "WG_WS_CONF", "CARRIER_IFACE_SCRIPT",
    "STATE_PRIMARY", "STATE_FALLBACK", "STATE_RECOVERING", "STATE_EXHAUSTED",
    "FALLBACK_TO_RECOVER_MIN_S", "RECOVER_OK_STREAK", "WG_WS_FAIL_LIMIT",
    "MAX_SWITCHES_PER_HOUR", "HISTORY_CAP", "CarrierError",
    "default_state", "load_state", "save_state", "wg_ws0_installed",
    "active_carrier", "is_fallback", "is_exhausted", "p25_noop_reason",
    "probe", "reset_p25_state",
    "on_maneuver_rollback", "fallback_tick", "exhausted_recovery_check",
    "render_default_iface_script",
    "ensure_default_iface_script", "run_status", "run_switch",
    "utcnow", "iso", "parse_ts",
]
