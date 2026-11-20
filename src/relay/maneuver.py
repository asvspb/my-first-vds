"""`vds relay maneuver` — локальный манёвр ноги awg1 relay→exit (ADR-015, P25).

Релей меняет ТОЛЬКО свой локальный endpoint: exit-сторона (awg2 + пул
51900–51911) статична (WP-M2), прав на exit у релея нет (ADR-015 «граница
доверия»). Смена 4-кортежа — исключительно runtime:

    awg set awg1 listen-port 0 peer <exit-pub> endpoint <exit-ip>:<next_port>

`listen-port 0` — ядро берёт эфемерный порт, поэтому меняется весь 4-кортеж
(иначе пришлось бы гадать, какой из полей ТСПУ отслеживает). `awg-quick
down/up`, рестарты `vds-relay-exit`/`vds-relay-policy` в горячем пути
запрещены (SPEC §2.3): `table 100` и policy-routing не рвутся.

Персист `Endpoint` в `/etc/amnezia/awg1.conf` — только после подтверждённого
liveness (правка одной строки, бэкап `.bak-pre-maneuver` 0600, атомарная
запись 0600). При откате по таймауту конфиг НЕ трогается — только runtime
возврат endpoint на прежний порт.

Триггер — data-plane liveness (`ping -I awg1` внутри туннеля), а не возраст
handshake (WP-M0: stale-handshake при живом канале). Activity gate отсекает
манёвр в простое: прирост клиентского трафика `awg0` (rx+tx) ≥ noise либо
растущий `awg1.tx` при нулевом `awg1.rx` (keepalive/junk сам по себе — не
активность). Счётчики сбрасываются при рестарте интерфейса: отрицательных
delta нет.

Источник правды о текущем порту — `awg show awg1 dump` (endpoint/listen_port/
peer public key), а не `state.protocols["relay"].exit_port` (там старый 51825).
Секреты: приватный ключ (первое поле dump и `PrivateKey` конфига) и
preshared key не читаются в вывод/state/логи — только публичные идентификаторы.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from src.core.lock import FileLock, LockError
from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit, resolve_python
from src.gateway.store import GatewayState, StoreError, load_state
from src.relay.paths import (
    EXIT_LEG_BASE_PORT,
    EXIT_LEG_IP,
    EXIT_LEG_POOL,
    RELAY_EXIT_CONFIG_PATH,
    RELAY_EXIT_IFACE,
    RELAY_MANEUVER_BACKUP_SUFFIX,
    RELAY_MANEUVER_LOCK_FILE,
    RELAY_MANEUVER_STATE_PATH,
)

# --- Параметры манёвра (SPEC §3.5, контракт WP-M3) ---
STATE_VERSION = 1
POOL_START = EXIT_LEG_BASE_PORT
PROBE_TIMEOUT_S = 20  # суммарное окно ожидания liveness после смены порта
PROBE_INTERVAL_S = 2  # период повторной пробы (handshake после смены — 1–5 с)
COOLDOWN_S = 600  # ≤1 попытка в 10 мин (anti-ping-pong)
MAX_ATTEMPTS_PER_HOUR = 3
ATTEMPTS_WINDOW = 100  # кольцевое окно истории
LIVENESS_FAIL_THRESHOLD = 3  # N подряд упавших проб → suspect
ACTIVITY_NOISE_BYTES = 4096  # порог прироста, ниже — шум keepalive/junk
DEFAULT_HISTORY_LIMIT = 10

STATES = ("idle", "healthy", "suspect", "maneuvering", "cooldown", "exhausted")

# --- Opt-in таймер (SPEC §4 WP-M4) ---
MANEUVER_UNIT = "vds-relay-maneuver.service"
MANEUVER_TIMER = "vds-relay-maneuver.timer"
MANEUVER_SERVICE_TEMPLATE = "vds-relay-maneuver.service.tpl"
MANEUVER_TIMER_TEMPLATE = "vds-relay-maneuver.timer.tpl"
DEFAULT_INTERVAL_S = 60  # тик раз в минуту → детекция 3/3 ≈ 180 с
MIN_INTERVAL_S = 15  # защита от самоподрыва (стенд — 15s)
REPO_DIR = Path(__file__).resolve().parents[2]

_ENDPOINT_LINE_RE = re.compile(r"^(\s*Endpoint\s*=\s*).*$", re.IGNORECASE)
_PING_MS_RE = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms")


class ManeuverError(Exception):
    """Сбой шага манёвра (печатается в CLI без traceback)."""


# ---------------------------------------------------------------------------
# Чистые парсеры (контракт unit-тестов; без сети)
# ---------------------------------------------------------------------------

def parse_awg_dump(text: str) -> dict:
    """Разбор `awg show <iface> dump` → {'listen_port', 'peers': [...]}.

    Первая строка — интерфейс: `<privkey>\\t<pubkey>\\t<listen-port>\\t<fwmark>`.
    **Первое поле (приватный ключ) не читается** — только listen-port.
    Строки пиров: `pubkey\\tpsk\\tendpoint\\tallowed\\ths\\trx\\ttx\\tkeepalive`;
    берём публичный ключ, endpoint и счётчики, preshared key игнорируется.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    result: dict = {"listen_port": 0, "peers": []}
    if not lines:
        return result
    iface = lines[0].split("\t")
    if len(iface) >= 3 and iface[2].strip().isdigit():
        result["listen_port"] = int(iface[2])
    for raw in lines[1:]:
        parts = raw.split("\t")
        if len(parts) < 7:
            continue
        host, port = split_endpoint(parts[2])
        try:
            rx, tx = int(parts[5]), int(parts[6])
        except ValueError:
            rx, tx = 0, 0
        result["peers"].append(
            {
                "public_key": parts[0],
                "endpoint_host": host,
                "endpoint_port": port,
                "rx": rx,
                "tx": tx,
            }
        )
    return result


def split_endpoint(endpoint: str) -> tuple[str, Optional[int]]:
    """`host:port` / `[v6]:port` / `(none)` → (host, port|None)."""
    raw = (endpoint or "").strip()
    if not raw or raw == "(none)" or ":" not in raw:
        return "", None
    host, _, tail = raw.rpartition(":")
    if not tail.isdigit():
        return "", None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(tail)


def parse_transfer(text: str) -> dict[str, tuple[int, int]]:
    """`awg show <iface> transfer` → {pubkey: (rx, tx)}."""
    out: dict[str, tuple[int, int]] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            out[parts[0]] = (int(parts[1]), int(parts[2]))
    return out


def sum_transfer(entries: dict[str, tuple[int, int]]) -> tuple[int, int]:
    """Суммы (rx, tx) по всем пирам интерфейса."""
    return (sum(rx for rx, _ in entries.values()), sum(tx for _, tx in entries.values()))


def parse_ping_ms(text: str) -> Optional[int]:
    """`time=47.2 ms` → 47; нет поля — None (потеря/нестандартный вывод)."""
    match = _PING_MS_RE.search(text or "")
    if not match:
        return None
    return int(round(float(match.group(1))))


def pool_ports(pool: str = EXIT_LEG_POOL) -> list[int]:
    """Пул exit-ноги → [51900, …, 51911] (валидация формата — в exit_leg)."""
    from src.relay.exit_leg import parse_pool

    return parse_pool(pool)


def next_port(current: int, ports: list[int], failed: list[int]) -> Optional[int]:
    """Следующий порт пула по кругу, не равный текущему и не в failed.

    Детерминированный обход: после отката 51901 следующий манёвр пробует
    51902 (а не 51901). Все прочие порты отказали → None (pool exhausted).
    """
    if not ports:
        return None
    if current in ports:
        start = ports.index(current)
    else:
        start = 0
    for step in range(1, len(ports)):
        candidate = ports[(start + step) % len(ports)]
        if candidate in failed or candidate == current:
            continue
        return candidate
    return None


def _delta(current: int, previous: int) -> int:
    """Прирост счётчика; рестарт интерфейса (new < prev) — 0, не отрицательное."""
    return current - previous if current >= previous else 0


def compute_activity(
    prev: Optional[dict],
    cur: dict,
    *,
    noise: int = ACTIVITY_NOISE_BYTES,
) -> bool:
    """Activity gate (SPEC §3.5): есть ли у клиентов реальный трафик.

    Активность = прирост `awg0` (rx+tx) ≥ noise ЛИБО `awg1.tx` вырос ≥ noise
    при нулевом приросте `awg1.rx` (junk/keepalive уходят, ответа нет).
    Один `delta(awg1.tx) > 0` активностью не считается (PersistentKeepalive).
    Первый сэмпл (prev is None) — базовая линия, активности не подтверждает.
    """
    if not prev:
        return False
    awg0_delta = _delta(cur["awg0_rx_sum"], prev["awg0_rx_sum"]) + _delta(
        cur["awg0_tx_sum"], prev["awg0_tx_sum"]
    )
    if awg0_delta >= noise:
        return True
    tx_delta = _delta(cur["awg1_tx"], prev["awg1_tx"])
    rx_delta = _delta(cur["awg1_rx"], prev["awg1_rx"])
    return tx_delta >= noise and rx_delta == 0


# ---------------------------------------------------------------------------
# Состояние манёвра (state.json 0600)
# ---------------------------------------------------------------------------

def default_state() -> dict:
    """Начальное состояние: idle, счётчики не сняты."""
    return {
        "version": STATE_VERSION,
        "state": "idle",
        "current_port": EXIT_LEG_BASE_PORT,
        "previous_port": EXIT_LEG_BASE_PORT,
        "attempts": [],
        "cooldown_until": None,
        "exhausted": False,
        "failed_ports": [],
        "liveness_ms": None,
        "last_sample": None,
    }


def load_maneuver_state(path: Optional[str] = None) -> dict:
    """Прочитать state манёвра; отсутствие/битый JSON — default_state (не ошибка)."""
    target = Path(path) if path is not None else RELAY_MANEUVER_STATE_PATH
    try:
        raw = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default_state()
    except OSError:
        return default_state()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default_state()
    if not isinstance(data, dict):
        return default_state()
    state = default_state()
    for key in state:
        if key in data:
            state[key] = data[key]
    if state["state"] not in STATES:
        state["state"] = "idle"
    if not isinstance(state["attempts"], list):
        state["attempts"] = []
    if not isinstance(state["failed_ports"], list):
        state["failed_ports"] = []
    return state


def save_maneuver_state(state: dict, path: Optional[str] = None) -> bool:
    """Атомарно записать state (0600). False — ошибка записи."""
    target = Path(path) if path is not None else RELAY_MANEUVER_STATE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(state, ensure_ascii=False, indent=2) + "\n"
    return write_secret_atomic(str(target), payload, mode=0o600)


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value: object) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def cooldown_epoch(state: dict) -> float:
    """Момент окончания cooldown (epoch); нет/битая метка — 0."""
    return _parse_iso(state.get("cooldown_until")) or 0.0


def hourly_attempts(state: dict, now: float) -> int:
    """Сколько попыток манёвра было за последний час (окно 3600 с)."""
    count = 0
    for attempt in state.get("attempts") or []:
        if not isinstance(attempt, dict):
            continue
        ts = _parse_iso(attempt.get("ts"))
        if ts is not None and 0 <= now - ts < 3600:
            count += 1
    return count


def _append_attempt(
    state: dict,
    now: float,
    from_port: int,
    to_port: int,
    result: str,
    liveness_ms: Optional[int],
) -> None:
    attempts = list(state.get("attempts") or [])
    attempts.append(
        {
            "ts": _now_iso(now),
            "from": from_port,
            "to": to_port,
            "result": result,
            "liveness_ms": liveness_ms,
        }
    )
    state["attempts"] = attempts[-ATTEMPTS_WINDOW:]


# ---------------------------------------------------------------------------
# Guard роли узла и пула (P0: до любых действий)
# ---------------------------------------------------------------------------

def relay_node_violation(state: GatewayState) -> Optional[str]:
    """`None` — узел релей; строка — причина отказа (зеркально exit_node_violation).

    Отказ: (а) установлен exit-leg (`relay_leg`) — это exit; (б) нет
    `/etc/amnezia/awg1.conf` — клиентской ноги релея нет, манёвр невозможен.
    """
    if (state.protocols.get("relay_leg") or {}).get("installed"):
        return (
            "этот узел — exit (state.protocols['relay_leg'] установлен), а не RU-релей. "
            "`vds relay maneuver` выполняется только на релее (ADR-015): exit-сторона — "
            "`vds relay exit-leg`, а не манёвр локального endpoint."
        )
    if not Path(RELAY_EXIT_CONFIG_PATH).is_file():
        return (
            f"не найден {RELAY_EXIT_CONFIG_PATH}: узел не похож на RU-релей "
            "(клиентская нога awg1 отсутствует). Манёвр — только на релее; на exit "
            "прав у релея нет (ADR-015 «граница доверия»)."
        )
    return None


def guard_leg_port(port: Optional[int], ports: list[int]) -> None:
    """Текущий порт ноги обязан быть из пула; иначе ManeuverError.

    До cutover релей держит endpoint на старом awg0/51825 — манёвр не должен
    перекидывать старый конфиг (SPEC §2 инварианты).
    """
    if port is None:
        raise ManeuverError(
            "не удалось прочитать endpoint awg1 (`awg show awg1 dump`): "
            "пир с endpoint не найден — манёвр невозможен."
        )
    if port not in ports:
        raise ManeuverError(
            f"текущий порт ноги {port} вне пула {ports[0]}-{ports[-1]}: "
            "конфиг до cutover (старый awg0/51825) или чужой пул. Манёвр не "
            "перекидывает старый конфиг — сначала перенесите ногу на awg2 (ADR-015)."
        )


# ---------------------------------------------------------------------------
# Runtime: чтение ноги и актуатор `awg set`
# ---------------------------------------------------------------------------

def read_leg(iface: str = RELAY_EXIT_IFACE) -> dict:
    """Текущее runtime-состояние ноги из `awg show <iface> dump`.

    Возвращает listen_port, публичный ключ пира (exit) и его endpoint.
    Приватный ключ интерфейса не покидает парсер.
    """
    res = run_list(["awg", "show", iface, "dump"], timeout=10)
    if not res.ok:
        raise ManeuverError(
            f"awg show {iface} dump: {res.stderr.strip() or res.stdout.strip() or 'сбой'}"
        )
    dump = parse_awg_dump(res.stdout)
    peers = [p for p in dump["peers"] if p["endpoint_port"]]
    if not peers:
        raise ManeuverError(
            f"у {iface} нет пира с endpoint — нога не настроена "
            "(проверьте `vds relay status`)."
        )
    peer = peers[0]
    return {
        "iface": iface,
        "listen_port": dump["listen_port"],
        "peer_public_key": peer["public_key"],
        "endpoint_host": peer["endpoint_host"],
        "endpoint_port": peer["endpoint_port"],
    }


def _actuate_set(peer_public_key: str, host: str, port: int) -> object:
    """`awg set ... listen-port 0 peer <pub> endpoint <host>:<port>`.

    `listen-port 0` обязателен: ядро берёт эфемерный порт и меняется весь
    4-кортеж. Никаких awg-quick/systemctl в горячем пути.
    """
    return run_list(
        [
            "awg", "set", RELAY_EXIT_IFACE,
            "listen-port", "0",
            "peer", peer_public_key,
            "endpoint", f"{host}:{port}",
        ],
        timeout=15,
    )


def probe_liveness(target: str = EXIT_LEG_IP) -> tuple[bool, Optional[int]]:
    """Одна проба внутри туннеля: `ping -I awg1 -c 1 -W 2 10.11.0.1`."""
    res = run_list(
        ["ping", "-I", RELAY_EXIT_IFACE, "-c", "1", "-W", "2", target], timeout=5
    )
    if not res.ok:
        return False, None
    return True, parse_ping_ms(res.stdout)


def wait_liveness(
    *,
    timeout_s: float = PROBE_TIMEOUT_S,
    interval_s: float = PROBE_INTERVAL_S,
    probe: Callable[[], tuple[bool, Optional[int]]] = probe_liveness,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[bool, Optional[int]]:
    """Ждать liveness до timeout_s, пробуя каждые interval_s.

    Handshake после смены порта берёт 1–5 с — один мгновенный ping на t=0
    не годится (SPEC §2.6). True — канал ожил, вместе с задержкой последней
    успешной пробы.
    """
    start = clock()
    last_ms: Optional[int] = None
    while True:
        ok, ms = probe()
        if ok:
            return True, ms
        if ms is not None:
            last_ms = ms
        if clock() - start >= timeout_s:
            return False, last_ms
        sleep(interval_s)


def update_conf_endpoint(text: str, host: str, port: int) -> str:
    """Заменить ТОЛЬКО строку `Endpoint = ...`, сохранив остальной конфиг.

    PrivateKey/Address/Table/MTU/Jc..H4/PersistentKeepalive/комментарии
    остаются байт-в-байт. Нет строки Endpoint — ManeuverError (битый конфиг).
    """
    out: list[str] = []
    replaced = False
    for line in text.splitlines():
        match = _ENDPOINT_LINE_RE.match(line)
        if match and not replaced:
            out.append(f"{match.group(1)}{host}:{port}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise ManeuverError(
            "в awg1.conf нет строки `Endpoint = ...` — конфиг повреждён; "
            "персист endpoint невозможен (проверьте `vds relay status`)."
        )
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + trailing


def persist_endpoint(conf_path: Path, host: str, port: int) -> bool:
    """Персист Endpoint: бэкап 0600 + атомарная запись 0600. True — изменён.

    Бэкап через write_secret_atomic (не shutil.copy: umask дал бы 0644 на
    файле с PrivateKey). Идемпотентно: то же содержимое — без записи.
    """
    try:
        original = conf_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManeuverError(f"не удалось прочитать {conf_path}: {exc}") from exc
    updated = update_conf_endpoint(original, host, port)
    if updated == original:
        return False
    backup = conf_path.with_name(conf_path.name + RELAY_MANEUVER_BACKUP_SUFFIX)
    if not write_secret_atomic(str(backup), original, mode=0o600):
        raise ManeuverError(f"не удалось записать бэкап {backup} (0600).")
    if not write_secret_atomic(str(conf_path), updated, mode=0o600):
        raise ManeuverError(f"не удалось записать {conf_path} (0600).")
    return True


# ---------------------------------------------------------------------------
# State-machine (чистые решения)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """Результат одного тика: целевое состояние, нужен ли манёвр, причина."""

    state: str
    maneuver: bool
    reason: str


def decide(
    name: str,
    sample: dict,
    *,
    now: float,
    cooldown_until: float,
    hourly_attempts_count: int,
    candidate: Optional[int],
) -> Decision:
    """Чистая функция перехода (SPEC §3.4/§3.5).

    Таблица (см. tests/relay/test_maneuver.py):
      * liveness ok → healthy (в т.ч. автовыход exhausted→healthy);
      * exhausted при упавшей liveness остаётся exhausted;
      * cooldown действует до cooldown_until, затем снимается;
      * < LIVENESS_FAIL_THRESHOLD подряд — suspect (idle остаётся idle);
      * нет активности — манёвра нет (activity gate);
      * активность + ≥ N отказов + свободный cooldown → maneuvering;
      * ≥ MAX_ATTEMPTS_PER_HOUR или нет кандидата → exhausted.
    """
    liveness_ok = bool(sample.get("liveness_ok"))
    fails = int(sample.get("consecutive_failures") or 0)
    activity = bool(sample.get("activity"))

    if liveness_ok:
        return Decision("healthy", False, "liveness жив — манёвр не нужен")
    if name == "exhausted":
        return Decision("exhausted", False, "exhausted: ждём самостоятельного восстановления liveness")
    if name == "cooldown":
        if now < cooldown_until:
            return Decision("cooldown", False, f"cooldown активен ещё {int(cooldown_until - now)} с")
        name = "suspect"  # cooldown истёк — дальше обычная логика

    if fails < LIVENESS_FAIL_THRESHOLD:
        nxt = "suspect" if name in ("healthy", "suspect", "maneuvering") else name
        return Decision(nxt, False, f"liveness падает ({fails}/{LIVENESS_FAIL_THRESHOLD}) подряд")

    if not activity:
        nxt = "suspect" if name in ("healthy", "suspect", "maneuvering") else name
        return Decision(
            nxt,
            False,
            "нет клиентского трафика (activity gate): простой/keepalive манёвр не триггерит",
        )

    if now < cooldown_until:
        return Decision("cooldown", False, f"cooldown активен ещё {int(cooldown_until - now)} с")

    if hourly_attempts_count >= MAX_ATTEMPTS_PER_HOUR:
        return Decision(
            "exhausted",
            False,
            f"{hourly_attempts_count} попыток за час (лимит {MAX_ATTEMPTS_PER_HOUR}) — exhausted",
        )

    if candidate is None:
        return Decision("exhausted", False, "пул исчерпан: все прочие порты уже отказали")

    return Decision("maneuvering", True, "liveness мёртв при живом трафике — манёвр")


# ---------------------------------------------------------------------------
# Тик: сэмплирование и (опционально) исполнение
# ---------------------------------------------------------------------------

def _transfer_sums(iface: str) -> tuple[int, int]:
    """(rx, tx) суммы по пирам; сбой `awg show` — (0, 0)."""
    res = run_list(["awg", "show", iface, "transfer"], timeout=10)
    if not res.ok:
        return 0, 0
    return sum_transfer(parse_transfer(res.stdout))


def collect_sample(
    prev: Optional[dict],
    *,
    now: float,
    probe: Callable[[], tuple[bool, Optional[int]]] = probe_liveness,
) -> dict:
    """Снять сэмпл: счётчики awg0/awg1, liveness, activity gate, серия отказов."""
    awg0_rx, awg0_tx = _transfer_sums("awg0")
    awg1_rx, awg1_tx = _transfer_sums("awg1")
    liveness_ok, liveness_ms = probe()
    prev_fails = int((prev or {}).get("consecutive_failures") or 0)
    fails = 0 if liveness_ok else prev_fails + 1
    sample = {
        "ts": now,
        "awg0_rx_sum": awg0_rx,
        "awg0_tx_sum": awg0_tx,
        "awg1_rx": awg1_rx,
        "awg1_tx": awg1_tx,
        "liveness_ok": liveness_ok,
        "liveness_ms": liveness_ms,
        "consecutive_failures": fails,
    }
    sample["activity"] = compute_activity(prev, sample)
    return sample


def _sample_for_state(sample: dict) -> dict:
    """Подмножество last_sample, которое хранится в state (SPEC §3.4)."""
    return {
        "ts": sample.get("ts"),
        "awg0_rx_sum": sample.get("awg0_rx_sum", 0),
        "awg0_tx_sum": sample.get("awg0_tx_sum", 0),
        "awg1_tx": sample.get("awg1_tx", 0),
        "awg1_rx": sample.get("awg1_rx", 0),
        "consecutive_failures": int(sample.get("consecutive_failures") or 0),
    }


def tick(
    *,
    st: dict,
    leg: dict,
    sample: dict,
    now: float,
    apply: bool,
    force: bool = False,
    state_path: Optional[str] = None,
) -> dict:
    """Один тик автомата: решает и (при apply) исполняет манёвр.

    `force` обходит ТОЛЬКО cooldown (guard роли/пула и лимит «3/час»
    остаются). При apply состояние сохраняется (0600); при dry-run — нет.
    """
    ports = pool_ports()
    current = int(leg["endpoint_port"])
    if current not in ports:
        # Защита от прямого вызова в обход run_step.
        raise ManeuverError(
            f"текущий порт ноги {current} вне пула {ports[0]}-{ports[-1]} — манёвр запрещён."
        )
    failed = [int(p) for p in (st.get("failed_ports") or []) if isinstance(p, int)]
    candidate = next_port(current, ports, failed)
    cooldown_until = 0.0 if force else cooldown_epoch(st)
    decision = decide(
        str(st.get("state") or "idle"),
        sample,
        now=now,
        cooldown_until=cooldown_until,
        hourly_attempts_count=hourly_attempts(st, now),
        candidate=candidate,
    )
    result = {
        "state": decision.state,
        "maneuver": decision.maneuver,
        "reason": decision.reason,
        "acted": False,
        "result": None,
        "target_port": candidate if decision.maneuver else None,
        "exhausted": bool(st.get("exhausted")),
    }
    if not apply:
        return result

    st["last_sample"] = _sample_for_state(sample)
    if not decision.maneuver:
        st["state"] = decision.state
        if decision.state == "exhausted":
            st["exhausted"] = True
        if decision.state == "healthy":
            # Здоровый канал: свежая задержка всегда; отказавшие порты забываем,
            # только если инцидент закрыт (exhausted) или cooldown истёк.
            # В активном cooldown список сохраняется (защита от флаппинга 600 с).
            st["liveness_ms"] = sample.get("liveness_ms")
            if st.get("exhausted") or now >= cooldown_epoch(st):
                st["failed_ports"] = []
            # Автовыход exhausted→healthy: инцидент закрыт, пул снова доступен.
            st["exhausted"] = False
        if not save_maneuver_state(st, state_path):
            raise ManeuverError("не удалось сохранить state манёвра (0600).")
        return result

    # --- Манёвр: runtime-смена, затем liveness, затем (только при успехе) персист ---
    st["state"] = "maneuvering"
    if not save_maneuver_state(st, state_path):
        raise ManeuverError("не удалось сохранить state манёвра (0600).")

    host = leg["endpoint_host"]
    pub = leg["peer_public_key"]
    switched = _actuate_set(pub, host, candidate)
    if not getattr(switched, "ok", False):
        # Даже runtime-смена не прошла: фиксируем откат и закрываем попытку.
        st["state"] = "cooldown"
        st["cooldown_until"] = _now_iso(now + COOLDOWN_S)
        st["failed_ports"] = sorted(set(failed + [candidate]))
        _append_attempt(st, now, current, candidate, "rollback", None)
        if next_port(current, ports, st["failed_ports"]) is None:
            st["state"] = "exhausted"
            st["exhausted"] = True
        save_maneuver_state(st, state_path)
        result.update(acted=True, result="rollback", exhausted=bool(st.get("exhausted")))
        # ADR-016 (WP-P2P-3): rollback первого носителя — сигнал селектору.
        # Вызов под нашим FileLock (анти-deadlock AC-7); state селектора — СВОЙ
        # файл (p2p-carriers.json), НО НЕ maneuver_path (P0-3 ревью: перезапись).
        from src.relay import carriers as _carriers
        result["carrier"] = _carriers.on_maneuver_rollback()
        return result

    alive, liveness_ms = wait_liveness()
    if alive:
        persist_endpoint(Path(RELAY_EXIT_CONFIG_PATH), host, candidate)
        st["previous_port"] = current
        st["current_port"] = candidate
        st["liveness_ms"] = liveness_ms
        st["state"] = "cooldown"
        st["cooldown_until"] = _now_iso(now + COOLDOWN_S)
        st["failed_ports"] = []
        # Канал ожил: серия отказов закрыта — иначе один потерянный ping после
        # cooldown сразу дал бы 4/3 и спровоцировал новый манёвр.
        st["last_sample"]["consecutive_failures"] = 0
        _append_attempt(st, now, current, candidate, "ok", liveness_ms)
        result.update(acted=True, result="ok")
    else:
        # Откат по таймауту: конфиг НЕ трогаем, только runtime endpoint.
        _actuate_set(pub, host, current)
        st["previous_port"] = current
        st["current_port"] = current
        st["state"] = "cooldown"
        st["cooldown_until"] = _now_iso(now + COOLDOWN_S)
        st["failed_ports"] = sorted(set(failed + [candidate]))
        _append_attempt(st, now, current, candidate, "rollback", None)
        if (
            next_port(current, ports, st["failed_ports"]) is None
            or hourly_attempts(st, now) >= MAX_ATTEMPTS_PER_HOUR
        ):
            st["state"] = "exhausted"
            st["exhausted"] = True
        result.update(acted=True, result="rollback")
        # ADR-016: хук селектора (уже под нашим FileLock — AC-7); без maneuver-path.
        from src.relay import carriers as _carriers
        result["carrier"] = _carriers.on_maneuver_rollback()
    result["exhausted"] = bool(st.get("exhausted"))
    if not save_maneuver_state(st, state_path):
        raise ManeuverError("не удалось сохранить state манёвра (0600).")
    return result


# ---------------------------------------------------------------------------
# CLI-точки входа
# ---------------------------------------------------------------------------

def run_step(
    apply: bool = False,
    force: bool = False,
    *,
    state_path: Optional[str] = None,
    maneuver_path: Optional[str] = None,
) -> int:
    """`vds relay maneuver step`: один тик автомата. Dry-run по умолчанию."""
    try:
        gstate = load_state(state_path)
        violation = relay_node_violation(gstate)
    except StoreError as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1
    if violation:
        console.print(f"[error][relay] {violation}[/error]")
        return 1

    if not apply:
        # Dry-run: только чтение. Лок не нужен — мутаций нет.
        try:
            leg = read_leg()
            ports = pool_ports()
            guard_leg_port(leg["endpoint_port"], ports)
        except ManeuverError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1
        st = load_maneuver_state(maneuver_path)
        # Runtime — источник правды (в state.protocols["relay"] порт может быть старый).
        if int(st.get("current_port") or 0) != leg["endpoint_port"]:
            st["current_port"] = leg["endpoint_port"]
        now = time.time()
        sample = collect_sample(st.get("last_sample"), now=now, probe=probe_liveness)
        try:
            result = tick(
                st=st, leg=leg, sample=sample, now=now, apply=False,
                force=force, state_path=maneuver_path,
            )
        except ManeuverError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1
        console.print(
            f"[info][relay] step (dry-run): state={result['state']} — {result['reason']}[/info]"
        )
        if result["maneuver"]:
            console.print(
                f"  - предложено: endpoint {leg['endpoint_host']}:{leg['endpoint_port']} → "
                f"{leg['endpoint_host']}:{result['target_port']} "
                f"(awg set awg1 listen-port 0 peer <pub> endpoint …)"
            )
            console.print("  - liveness-окно 20 с, персист Endpoint только при успехе")
        console.print("[info][relay] Dry-run: мутаций нет. Реальное исполнение — --apply.[/info]")
        return 0

    if os.geteuid() != 0:
        console.print("[error][relay] --apply требует root (запустите через sudo).[/error]")
        return 1

    # TOCTOU: state/нога/сэмпл читаются ВНУТРИ лока — иначе между чтением и
    # `awg set` состояние могло бы смениться другим процессом, а сэмпл был бы
    # снят по устаревшим счётчикам.
    try:
        with FileLock(RELAY_MANEUVER_LOCK_FILE):
            # ADR-016 (WP-P2P-3): сначала автовыход из exhausted (P0-5 ревью),
            # затем fallback-режим (AC-S6). Порядок: exhausted → fallback.
            from src.relay import carriers as _carriers
            if _carriers.is_exhausted():
                recovery = _carriers.exhausted_recovery_check()
                if recovery.get("action") == "recovered" and recovery.get("to") == _carriers.PRIMARY:
                    _carriers.reset_p25_state(maneuver_path)
                console.print(
                    f"[info][relay] step (exhausted): селектор — "
                    f"{recovery.get('action')} ({recovery.get('to') or recovery.get('reason')})[/info]"
                )
                return 0
            if _carriers.is_fallback():
                carrier_result = _carriers.fallback_tick(maneuver_path=maneuver_path)
                console.print(
                    f"[info][relay] step (fallback): носитель №2 активен — P25 no-op; "
                    f"селектор: {carrier_result.get('action')} "
                    f"({carrier_result.get('reason') or carrier_result.get('state')})[/info]"
                )
                return 0
            st = load_maneuver_state(maneuver_path)
            leg = read_leg()
            ports = pool_ports()
            guard_leg_port(leg["endpoint_port"], ports)
            # Runtime — источник правды (в state.protocols["relay"] порт старый).
            if int(st.get("current_port") or 0) != leg["endpoint_port"]:
                st["current_port"] = leg["endpoint_port"]
            now = time.time()
            sample = collect_sample(
                st.get("last_sample"), now=now, probe=probe_liveness
            )
            result = tick(
                st=st, leg=leg, sample=sample, now=now, apply=True,
                force=force, state_path=maneuver_path,
            )
    except (ManeuverError, OSError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    if result["result"] == "ok":
        console.print(
            f"[success][relay] манёвр выполнен: {leg['endpoint_port']} → "
            f"{result['target_port']}, liveness {st.get('liveness_ms')} мс, "
            f"{RELAY_EXIT_CONFIG_PATH} обновлён (Endpoint).[/success]"
        )
    elif result["result"] == "rollback":
        console.print(
            f"[warning][relay] откат: {leg['endpoint_port']} → "
            f"{result['target_port']} не ожил за {PROBE_TIMEOUT_S} с; endpoint "
            "возвращён на прежний порт, конфиг не изменён.[/warning]"
        )
    else:
        console.print(
            f"[info][relay] step: state={result['state']} — {result['reason']} "
            "(манёвр не требуется).[/info]"
        )
    if result.get("exhausted"):
        console.print(
            "[warning][relay] exhausted: пул/лимит попыток исчерпан — манёвр "
            "приостановлен до восстановления liveness.[/warning]"
        )
    return 0


def _timer_state() -> dict:
    """Состояние opt-in таймера: enabled (is-enabled) и active (is-active).

    Read-only, без секретов. Вне systemd/без прав — False (не ошибка).
    """
    enabled_res = run_list(["systemctl", "is-enabled", MANEUVER_TIMER], timeout=10)
    active_res = run_list(["systemctl", "is-active", MANEUVER_TIMER], timeout=10)
    return {
        "timer_enabled": enabled_res.ok and enabled_res.output.strip() == "enabled",
        "auto_timer_active": active_res.ok and active_res.output.strip() == "active",
    }


def collect_status(*, maneuver_path: Optional[str] = None) -> dict:
    """Машиночитаемый статус манёвра; без секретов (только публичные поля)."""
    st = load_maneuver_state(maneuver_path)
    now = time.time()
    runtime: Optional[dict] = None
    try:
        leg = read_leg()
        runtime = {
            "endpoint_host": leg["endpoint_host"],
            "endpoint_port": leg["endpoint_port"],
            "listen_port": leg["listen_port"],
        }
    except ManeuverError:
        runtime = None
    return {
        "state": st["state"],
        "current_port": st["current_port"],
        "previous_port": st["previous_port"],
        "cooldown_remaining_s": max(0, int(cooldown_epoch(st) - now)),
        "exhausted": bool(st["exhausted"]),
        "failed_ports": list(st["failed_ports"]),
        "liveness_ms": st["liveness_ms"],
        "attempts_total": len(st["attempts"]),
        "pool": EXIT_LEG_POOL,
        "probe_target": EXIT_LEG_IP,
        "runtime": runtime,
        "last_sample": st["last_sample"],
        **_timer_state(),
    }


def run_status(json_output: bool = False, *, maneuver_path: Optional[str] = None) -> int:
    """`vds relay maneuver status`. Read-only; exit 0 всегда."""
    snapshot = collect_status(maneuver_path=maneuver_path)
    if json_output:
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return 0
    console.print("[info][relay] ══ Манёвр ноги relay→exit (ADR-015, P25) ══[/info]")
    console.print(
        f"[info] Состояние:[/info] {snapshot['state']}   "
        f"[info]Порт:[/info] {snapshot['current_port']} (пред. {snapshot['previous_port']})"
    )
    runtime = snapshot["runtime"]
    if runtime:
        console.print(
            f"[info] Runtime:[/info] endpoint {runtime['endpoint_host']}:"
            f"{runtime['endpoint_port']}, listen {runtime['listen_port']}"
        )
    else:
        console.print("[warning] Runtime: awg1 dump недоступен (нога не поднята?)[/warning]")
    cooldown = snapshot["cooldown_remaining_s"]
    console.print(
        f"[info] Cooldown:[/info] {'—' if not cooldown else f'{cooldown} с'}   "
        f"[info]Exhausted:[/info] {'ДА' if snapshot['exhausted'] else 'нет'}   "
        f"[info]Failed:[/info] {snapshot['failed_ports'] or '—'}"
    )
    console.print(
        f"[info] Пул:[/info] {snapshot['pool']}   "
        f"[info]Проба:[/info] {snapshot['probe_target']} внутри туннеля   "
        f"[info]Попыток:[/info] {snapshot['attempts_total']}"
    )
    console.print(
        f"[info] Таймер:[/info] enabled={'да' if snapshot['timer_enabled'] else 'нет'}   "
        f"[info]active:[/info] {'да' if snapshot['auto_timer_active'] else 'нет'}   "
        "(opt-in, `vds relay maneuver install --enable-auto`)"
    )
    return 0


def collect_history(limit: int = DEFAULT_HISTORY_LIMIT, *, maneuver_path: Optional[str] = None) -> list[dict]:
    """Последние N попыток манёвра (старые → новые)."""
    st = load_maneuver_state(maneuver_path)
    attempts = [a for a in st["attempts"] if isinstance(a, dict)]
    if limit > 0:
        return attempts[-limit:]
    return attempts


def run_history(limit: int = DEFAULT_HISTORY_LIMIT, *, maneuver_path: Optional[str] = None) -> int:
    """`vds relay maneuver history [--limit N]`."""
    rows = collect_history(limit, maneuver_path=maneuver_path)
    if not rows:
        console.print("[info][relay] история манёвров пуста.[/info]")
        return 0
    console.print(f"[info][relay] История манёвров (последние {len(rows)}):[/info]")
    for attempt in reversed(rows):
        live = attempt.get("liveness_ms")
        console.print(
            f"  {attempt.get('ts', '—')}  {attempt.get('from')}→{attempt.get('to')}  "
            f"{attempt.get('result', '—')}"
            + (f"  liveness {live} мс" if live is not None else "")
        )
    return 0


def run_rollback(
    apply: bool = False,
    *,
    state_path: Optional[str] = None,
    maneuver_path: Optional[str] = None,
) -> int:
    """`vds relay maneuver rollback`: вернуть endpoint на previous_port.

    Идемпотентно: previous == current → exit 0. Персист конфига — только если
    после возврата liveness ожил (иначе runtime остаётся на лучшем порту).
    """
    try:
        gstate = load_state(state_path)
        violation = relay_node_violation(gstate)
    except StoreError as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1
    if violation:
        console.print(f"[error][relay] {violation}[/error]")
        return 1

    if not apply:
        # Dry-run: только чтение, без лока и мутаций.
        try:
            leg = read_leg()
            ports = pool_ports()
            guard_leg_port(leg["endpoint_port"], ports)
        except ManeuverError as exc:
            console.print(f"[error][relay] {exc}[/error]")
            return 1
        st = load_maneuver_state(maneuver_path)
        current = int(leg["endpoint_port"])
        previous = int(st.get("previous_port") or current)
        if previous == current or previous not in ports:
            console.print(
                "[info][relay] предыдущий порт совпадает с текущим (или вне пула) — "
                "откатывать нечего.[/info]"
            )
            return 0
        console.print(
            f"[info][relay] План отката: endpoint {leg['endpoint_host']}:{current} → "
            f"{leg['endpoint_host']}:{previous} (runtime awg set; конфиг — только при liveness).[/info]"
        )
        console.print("[info][relay] Dry-run: мутаций нет. Реальное исполнение — --apply.[/info]")
        return 0

    if os.geteuid() != 0:
        console.print("[error][relay] --apply требует root (запустите через sudo).[/error]")
        return 1

    try:
        # TOCTOU: state и нога читаются под локом — решение об откате и
        # `awg set` опираются на одно и то же наблюдение.
        with FileLock(RELAY_MANEUVER_LOCK_FILE):
            st = load_maneuver_state(maneuver_path)
            leg = read_leg()
            ports = pool_ports()
            guard_leg_port(leg["endpoint_port"], ports)
            current = int(leg["endpoint_port"])
            previous = int(st.get("previous_port") or current)
            if previous == current or previous not in ports:
                console.print(
                    "[info][relay] предыдущий порт совпадает с текущим (или вне "
                    "пула) — откатывать нечего.[/info]"
                )
                return 0
            console.print(
                f"[info][relay] План отката: endpoint {leg['endpoint_host']}:{current} → "
                f"{leg['endpoint_host']}:{previous} (runtime awg set; конфиг — только "
                "при liveness).[/info]"
            )
            now = time.time()
            switched = _actuate_set(leg["peer_public_key"], leg["endpoint_host"], previous)
            if not getattr(switched, "ok", False):
                console.print(
                    "[error][relay] не удалось вернуть endpoint на прежний порт "
                    "(`awg set`): см. `vds relay status`.[/error]"
                )
                return 1
            alive, liveness_ms = wait_liveness()
            if alive:
                persist_endpoint(Path(RELAY_EXIT_CONFIG_PATH), leg["endpoint_host"], previous)
                # Канал ожил: серия отказов закрыта, exhausted снят.
                if isinstance(st.get("last_sample"), dict):
                    st["last_sample"]["consecutive_failures"] = 0
                st["exhausted"] = False
            st["state"] = "cooldown" if alive else "suspect"
            st["cooldown_until"] = _now_iso(now + COOLDOWN_S) if alive else None
            st["previous_port"] = current
            st["current_port"] = previous
            st["liveness_ms"] = liveness_ms
            st["failed_ports"] = [p for p in st.get("failed_ports", []) if p != previous]
            _append_attempt(st, now, current, previous, "rollback", liveness_ms)
            # ADR-016 (P0-3 ревью): ручной rollback НЕ сигнал селектору — он
            # выполняется при ОЖИВШЕМ awg1 (alive), селектор здесь только навредил бы;
            # плюс state_path — это gateway state.json (чужой файл для carriers).
            if not save_maneuver_state(st, maneuver_path):
                raise ManeuverError("не удалось сохранить state манёвра (0600).")
    except (ManeuverError, OSError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    if alive:
        console.print(
            f"[success][relay] откат выполнен: {current} → {previous}, "
            f"liveness {liveness_ms} мс, Endpoint персистнут.[/success]"
        )
    else:
        console.print(
            f"[warning][relay] endpoint возвращён на {previous}, но liveness не "
            "подтвердился — конфиг не изменён, требуется диагностика.[/warning]"
        )
    return 0


# ---------------------------------------------------------------------------
# Opt-in таймер (SPEC §4 WP-M4): install / remove / tick
# ---------------------------------------------------------------------------

def parse_interval(text: str) -> int:
    """`--interval` манёвра → секунды. Парсер тот же, что у alert install.

    Минимум MIN_INTERVAL_S: при 60 с и N=3 детекция в авторежиме ≈180 с
    (3 тика) + 5–20 с манёвр; 15 с — только для стенда.
    """
    from src.alert.env import parse_duration

    try:
        seconds = parse_duration(text)
    except ValueError as exc:
        raise ManeuverError(f"--interval: {exc}") from exc
    if seconds < MIN_INTERVAL_S:
        raise ManeuverError(
            f"--interval: минимум {MIN_INTERVAL_S} с (получено {seconds}); "
            "меньше — самоподрыв таймера при liveness-окне 20 с"
        )
    return seconds


def _install_ctx(interval_sec: int) -> dict[str, str]:
    install_dir = os.environ.get("INSTALL_DIR", "/opt/my-vds")
    return {
        "python": resolve_python(install_dir),
        "repo_dir": str(REPO_DIR),
        "install_dir": install_dir,
        "interval_sec": str(interval_sec),
    }


def _guard_node_and_port(state_path: Optional[str]) -> None:
    """Guard роли узла и пула (P0) — до любых изменений install."""
    try:
        gstate = load_state(state_path)
    except StoreError as exc:
        raise ManeuverError(str(exc)) from exc
    violation = relay_node_violation(gstate)
    if violation:
        raise ManeuverError(violation)
    leg = read_leg()
    guard_leg_port(leg["endpoint_port"], pool_ports())


def run_install(
    apply: bool = False,
    enable_auto: bool = False,
    interval: str = f"{DEFAULT_INTERVAL_S}s",
    *,
    state_path: Optional[str] = None,
    root: str = "/",
) -> int:
    """`vds relay maneuver install`: юниты таймера. Dry-run по умолчанию.

    auto=off (opt-in): без `--enable-auto` файлы ставятся и daemon-reload
    выполняется, но таймер НЕ включён и НЕ запущен (`.service` — enable=False,
    `.timer` — enable=False). `--enable-auto` → enable=True + start timer.
    """
    try:
        interval_sec = parse_interval(interval)
        _guard_node_and_port(state_path)
    except (ManeuverError, OSError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    if not apply:
        console.print("[info][relay] DRY-RUN план maneuver install:[/info]")
        console.print(
            f"[info][relay]   1. {MANEUVER_UNIT} из {MANEUVER_SERVICE_TEMPLATE} "
            "(enable=off: включается только таймером)[/info]"
        )
        console.print(
            f"[info][relay]   2. {MANEUVER_TIMER} из {MANEUVER_TIMER_TEMPLATE} "
            f"(OnUnitActiveSec={interval_sec}s, Unit={MANEUVER_UNIT})[/info]"
        )
        console.print(
            f"[info][relay]   авто-режим: {'ВКЛ (--enable-auto)' if enable_auto else 'выкл (opt-in: файлы поставлены, таймер не включён/не запущен)'}[/info]"
        )
        console.print(
            f"[info][relay]   тайминг: 60 с × 3 тика ≈ 180 с до suspect + "
            f"5–20 с манёвр; текущий интервал {interval_sec} с[/info]"
        )
        console.print("[info][relay] Запустите с --apply для исполнения.[/info]")
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][relay] install --apply требует root (sudo).[/error]")
        return 1

    ctx = _install_ctx(interval_sec)
    try:
        with FileLock(RELAY_MANEUVER_LOCK_FILE):
            if not install_unit(
                MANEUVER_SERVICE_TEMPLATE, MANEUVER_UNIT, ctx, root=root, enable=False
            ):
                return 1
            if not install_unit(
                MANEUVER_TIMER_TEMPLATE, MANEUVER_TIMER, ctx, root=root,
                enable=enable_auto,
            ):
                return 1
            if enable_auto:
                started = run_list(["systemctl", "start", MANEUVER_TIMER], timeout=15)
                if not started.ok:
                    console.print(
                        f"[error][relay] не удалось запустить {MANEUVER_TIMER}: "
                        f"{started.stderr.strip()}[/error]"
                    )
                    return 1
    except (LockError, OSError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    if enable_auto:
        console.print(
            f"[success][relay] таймер установлен и включён: {MANEUVER_TIMER} "
            f"(интервал {interval_sec} с). Проверка: vds relay maneuver status[/success]"
        )
    else:
        console.print(
            f"[success][relay] таймер установлен, авторежим ВЫКЛ (opt-in): "
            f"{MANEUVER_TIMER}. Включить: sudo systemctl enable --now "
            f"{MANEUVER_TIMER}[/success]"
        )
    return 0


def run_remove(apply: bool = False, *, root: str = "/") -> int:
    """`vds relay maneuver remove`: снять .timer и .service. State сохраняется.

    Идемпотентно: `remove_unit` — stop+disable+rm (нет файла — успех), поэтому
    повторный запуск не ломает ничего. `/var/lib/vds/relay-maneuver.json`
    (история) НЕ удаляется.
    """
    if not apply:
        console.print("[info][relay] DRY-RUN план maneuver remove:[/info]")
        console.print(
            f"[info][relay]   1. stop/disable и удалить {MANEUVER_TIMER}, {MANEUVER_UNIT}[/info]"
        )
        console.print(
            f"[info][relay]   2. {RELAY_MANEUVER_STATE_PATH} сохранить (история)[/info]"
        )
        return 0

    if root == "/" and os.geteuid() != 0:
        console.print("[error][relay] remove --apply требует root (sudo).[/error]")
        return 1

    try:
        with FileLock(RELAY_MANEUVER_LOCK_FILE):
            for name in (MANEUVER_TIMER, MANEUVER_UNIT):
                if not remove_unit(name, root=root):
                    return 1
    except (LockError, OSError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        return 1

    console.print(
        f"[success][relay] таймер снят ({MANEUVER_TIMER}, {MANEUVER_UNIT}); "
        f"state {RELAY_MANEUVER_STATE_PATH} сохранён (история).[/success]"
    )
    return 0


def _journal_tag(
    *,
    state: str,
    port: object,
    liveness_ok: bool,
    liveness_ms: Optional[int],
    activity: bool,
    fails: int,
    acted: bool,
    result: Optional[str],
) -> str:
    """Одна структурированная строка тика (journal). Секретов нет по построению."""
    return (
        f"[relay-maneuver] state={state} port={port if port is not None else '-'} "
        f"liveness={'ok' if liveness_ok else 'fail'} "
        f"ms={liveness_ms if liveness_ms is not None else '-'} "
        f"activity={1 if activity else 0} fails={fails}/{LIVENESS_FAIL_THRESHOLD} "
        f"acted={1 if acted else 0} result={result or 'none'}"
    )


def run_tick(
    apply: bool = False,
    force: bool = False,
    *,
    state_path: Optional[str] = None,
    maneuver_path: Optional[str] = None,
) -> int:
    """`vds relay maneuver tick` — ExecStart таймера. **Всегда exit 0.**

    ManeuverError/StoreError/OSError/отказ guard/занятый FileLock
    перехватываются: печатается ровно одна структурированная journal-строка,
    oneshot-юнит не уходит в failed. `--apply` — реальный тик; без него —
    read-only сэмпл (тот же тег, state не пишется).
    """
    state_name = "unknown"
    port: object = None
    liveness_ok = False
    liveness_ms: Optional[int] = None
    activity = False
    fails = 0
    acted = False
    result_name: Optional[str] = None
    sample: Optional[dict] = None
    try:
        gstate = load_state(state_path)
        violation = relay_node_violation(gstate)
        if violation:
            raise ManeuverError(violation)

        if apply:
            if os.geteuid() != 0:
                raise ManeuverError("--apply требует root (systemd-юнит запускает от root)")
            with FileLock(RELAY_MANEUVER_LOCK_FILE):
                # ADR-016 (WP-P2P-3): exhausted-автовыход, затем fallback (AC-S6).
                from src.relay import carriers as _carriers
                if _carriers.is_exhausted():
                    recovery = _carriers.exhausted_recovery_check()
                    if recovery.get("action") == "recovered" and recovery.get("to") == _carriers.PRIMARY:
                        _carriers.reset_p25_state(maneuver_path)
                    console.print(
                        _journal_tag(
                            state=f"exhausted({recovery.get('action')})",
                            port=port, liveness_ok=False, liveness_ms=None,
                            activity=False, fails=0, acted=False, result=None,
                        ),
                        markup=False, highlight=False, soft_wrap=True,
                    )
                    return 0
                if _carriers.is_fallback():
                    carrier_result = _carriers.fallback_tick(maneuver_path=maneuver_path)
                    console.print(
                        _journal_tag(
                            state=f"fallback({carrier_result.get('action')})",
                            port=port, liveness_ok=False, liveness_ms=None,
                            activity=True, fails=0, acted=False, result=None,
                        ),
                        markup=False, highlight=False, soft_wrap=True,
                    )
                    return 0
                st = load_maneuver_state(maneuver_path)
                leg = read_leg()
                port = leg["endpoint_port"]
                guard_leg_port(leg["endpoint_port"], pool_ports())
                if int(st.get("current_port") or 0) != leg["endpoint_port"]:
                    st["current_port"] = leg["endpoint_port"]
                now = time.time()
                sample = collect_sample(st.get("last_sample"), now=now, probe=probe_liveness)
                result = tick(
                    st=st, leg=leg, sample=sample, now=now, apply=True,
                    force=force, state_path=maneuver_path,
                )
        else:
            st = load_maneuver_state(maneuver_path)
            leg = read_leg()
            port = leg["endpoint_port"]
            guard_leg_port(leg["endpoint_port"], pool_ports())
            now = time.time()
            sample = collect_sample(st.get("last_sample"), now=now, probe=probe_liveness)
            result = tick(
                st=st, leg=leg, sample=sample, now=now, apply=False,
                force=force, state_path=maneuver_path,
            )

        state_name = str(result["state"])
        acted = bool(result["acted"])
        result_name = result["result"]
    except (ManeuverError, StoreError, OSError, LockError) as exc:
        if sample is not None:
            liveness_ok = bool(sample.get("liveness_ok"))
            liveness_ms = sample.get("liveness_ms")
            activity = bool(sample.get("activity"))
            fails = int(sample.get("consecutive_failures") or 0)
        console.print(
            _journal_tag(
                state="error", port=port, liveness_ok=liveness_ok,
                liveness_ms=liveness_ms, activity=activity, fails=fails,
                acted=False, result=None,
            )
            + f" reason={str(exc).replace(chr(10), ' ')}",
            markup=False,
            highlight=False,
            soft_wrap=True,
        )
        return 0

    if sample is not None:
        liveness_ok = bool(sample.get("liveness_ok"))
        liveness_ms = sample.get("liveness_ms")
        activity = bool(sample.get("activity"))
        fails = int(sample.get("consecutive_failures") or 0)
    tag = _journal_tag(
        state=state_name, port=port, liveness_ok=liveness_ok,
        liveness_ms=liveness_ms, activity=activity, fails=fails,
        acted=acted, result=result_name,
    )
    target = result.get("target_port") if isinstance(result, dict) else None
    if acted and target is not None:
        tag += f" to={target}"
    console.print(
        tag,
        markup=False,
        highlight=False,
        soft_wrap=True,
    )
    return 0
