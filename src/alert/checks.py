"""Чтение источников сигнала и их классификация (SPEC-20261117-alert-watch §3.1–3.2).

Слой **только читает**:
  * `probe-watch.json` — своим минимальным json-читателем (не импортируем
    2300-строчный `probing`, который намеренно маскирует «нет данных» в пустой
    снапшот — для сторожа это недопустимо, SPEC §3.2);
  * `awg show awg0 dump` — через `run_list`;
  * gateway `state.json` — через `gateway.store.load_state` (только чтение);
  * состояние лока — `system.ufw.get_lockdown` (ленивый импорт).

Отсутствие данных **никогда** не превращается в тревогу: это `inconclusive` /
`telemetry_unavailable`, а не «канал мёртв».
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal, Optional

from src.alert.env import AlertConfig
from src.alert.paths import PROBE_WATCH_PATH
from src.alert.state import parse_iso
from src.core.shell import ShellResult, run_list

ProbeStatus = Literal["ok", "missing", "corrupt", "no_level", "stale"]
RelayClass = Literal["ok", "blocked", "relay_down", "idle", "inconclusive"]

# «Нога активна»: трафик по пиру шёл в пределах окна. SPEC §3.1 — max(3×тик, 10 мин),
# тик по умолчанию 2 мин → 10 минут.
ACTIVITY_WINDOW_S = 600

# Порог «телеметрия замерла»: 3 пропущенных часовых тика probe-watch (§3.2).
STALE_FLOOR_S = 3 * 3600


@dataclass(frozen=True)
class AwgPeer:
    public_key: str
    endpoint: str  # "" если "(none)"
    allowed_ips: str
    latest_handshake: int
    rx: int
    tx: int


@dataclass(frozen=True)
class ThreatSignal:
    status: ProbeStatus
    level: Optional[str]
    reason: str
    snapshot_ts: str
    age_sec: Optional[int]


@dataclass(frozen=True)
class RelaySignal:
    classification: RelayClass
    detail: str
    peer_found: bool
    handshake_age_sec: Optional[int]
    endpoint_host: str
    endpoint_port: int
    tcp_ok: Optional[bool]
    icmp_ok: Optional[bool]
    traffic_active: bool
    # rx пира: нужен гейту активности между тиками (last_rx в alert-state).
    peer_rx: int = 0


# ---------------------------------------------------------------------------
# awg show dump — терпимый парсер (формат проверяется на живом узле, AC-13)
# ---------------------------------------------------------------------------

def _to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_awg_dump(text: str) -> dict[str, AwgPeer]:
    """`wg`/`awg show … dump` → `{public_key: AwgPeer}`.

    Терпимость обязательна (SPEC §3.1): табы и пробелы равнозначны, любое число
    полей ≥ 8 принимается, непарсящиеся числа → 0, пустой/битый вывод → `{}`.
    Интерфейсная строка (4 поля) отбрасывается сама собой.
    """
    peers: dict[str, AwgPeer] = {}
    if not isinstance(text, str):
        return peers
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 8:
            continue  # интерфейсная строка или мусор
        public_key = fields[0]
        if not public_key:
            continue
        endpoint = fields[2]
        if endpoint in ("(none)", "-", ""):
            endpoint = ""
        peers[public_key] = AwgPeer(
            public_key=public_key,
            endpoint=endpoint,
            allowed_ips=fields[3],
            latest_handshake=_to_int(fields[4]),
            rx=_to_int(fields[5]),
            tx=_to_int(fields[6]),
        )
    return peers


# ---------------------------------------------------------------------------
# threat: пять состояний вместо «тихих» дефолтов
# ---------------------------------------------------------------------------

def _parse_snapshot_ts(raw: object) -> Optional[datetime]:
    ts = parse_iso(raw)
    return ts


def read_threat(
    path: Path = PROBE_WATCH_PATH,
    now: Optional[datetime] = None,
    timer_hours: int = 1,
) -> ThreatSignal:
    """Прочитать снапшот probe-watch и различить пять состояний (SPEC §3.2)."""
    moment = now or datetime.now(timezone.utc)
    snapshot = Path(path)
    if not snapshot.is_file():
        return ThreatSignal("missing", None, "missing", "", None)
    try:
        data = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ThreatSignal("corrupt", None, "bad_json", "", None)
    if not isinstance(data, dict):
        return ThreatSignal("corrupt", None, "bad_json", "", None)

    ts_raw = data.get("ts")
    ts = _parse_snapshot_ts(ts_raw)
    if ts is None:
        return ThreatSignal("corrupt", None, "bad_ts", str(ts_raw or ""), None)
    age = int((moment - ts).total_seconds())

    threat = data.get("threat")
    level = threat.get("level") if isinstance(threat, dict) else None
    if level not in ("quiet", "elevated", "high"):
        reason = "no_level"
        if isinstance(threat, dict) and threat.get("level"):
            reason = "unexpected_level"
        return ThreatSignal("no_level", None, reason, str(ts_raw), age)

    threshold = max(STALE_FLOOR_S, 3 * max(int(timer_hours), 0) * 3600)
    if age > threshold:
        return ThreatSignal("stale", level, "stale", str(ts_raw), age)

    reason = str(threat.get("reason") or "") if isinstance(threat, dict) else ""
    return ThreatSignal("ok", level, reason, str(ts_raw), age)


# ---------------------------------------------------------------------------
# пульс плеча: классификация
# ---------------------------------------------------------------------------

def classify_relay(
    handshake_age_sec: Optional[int],
    threshold_s: int,
    tcp_ok: Optional[bool],
    traffic_active: bool,
) -> RelayClass:
    """Таблица истинности SPEC §3.1 (шесть строк).

    Возраст handshake сам по себе не признак блокировки: на `awg1` по умолчанию
    нет `PersistentKeepalive` (И44), поэтому в простое он законно стареет.
    Без недавней активности ноги → `idle`, а не алерт.
    """
    if handshake_age_sec is None:
        return "inconclusive"
    if handshake_age_sec >= 0 and handshake_age_sec < max(int(threshold_s), 0):
        return "ok"
    # handshake мёртв: -1 (никогда) или старше порога
    if not traffic_active:
        return "idle"
    if tcp_ok is True:
        return "blocked"
    if tcp_ok is False:
        return "relay_down"
    return "inconclusive"


def _gateway_state_path(state_path: Optional[str]) -> str:
    """Путь gateway `state.json`; по умолчанию — `gateway.paths.STATE_PATH`.

    Резолвим здесь (а не полагаемся на дефолт `store.load_state`), чтобы
    `state_path` был явным и тесты могли подменить путь без импорта store.
    """
    if state_path is not None:
        return str(state_path)
    from src.gateway.paths import STATE_PATH

    return str(STATE_PATH)


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    """`1.2.3.4:51820` / `[2001:db8::1]:51820` → (host, port); мусор → ("", 0)."""
    if not endpoint:
        return "", 0
    if endpoint.startswith("["):
        host, _, rest = endpoint[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else 0
    host, sep, port = endpoint.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return endpoint, 0


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _signal(
    classification: RelayClass,
    detail: str,
    *,
    peer_found: bool = False,
    handshake_age_sec: Optional[int] = None,
    endpoint_host: str = "",
    endpoint_port: int = 0,
    tcp_ok: Optional[bool] = None,
    icmp_ok: Optional[bool] = None,
    traffic_active: bool = False,
    peer_rx: int = 0,
) -> RelaySignal:
    return RelaySignal(
        classification=classification,
        detail=detail,
        peer_found=peer_found,
        handshake_age_sec=handshake_age_sec,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        tcp_ok=tcp_ok,
        icmp_ok=icmp_ok,
        traffic_active=traffic_active,
        peer_rx=peer_rx,
    )


def read_relay_signal(
    *,
    cfg: AlertConfig,
    prev_state: dict,
    now: datetime,
    run: Callable[..., ShellResult] = run_list,
    state_path: Optional[str] = None,
    tcp_probe: Optional[Callable[[str, int, float], bool]] = None,
) -> RelaySignal:
    """Пульс плеча relay→exit: `awg show awg0 dump` + пир из gateway state.

    Пир-релей на exit-узле — это **AWG-клиент** (`clients[]`, `protocol ==
    "amneziawg"`, `name == cfg.relay_peer`), а не `state.protocols["relay"]`
    (SPEC §3.1). `tcp_probe` — инжектируемая проба (тесты без сети).
    """
    try:
        from src.gateway.store import load_state

        gateway_state = load_state(_gateway_state_path(state_path))
    except Exception:  # StoreError и любые ошибки чтения — «слеп», не алерт
        return _signal("inconclusive", "state_unreadable")

    peer = next(
        (
            c
            for c in gateway_state.clients
            if c.name == cfg.relay_peer and c.protocol == "amneziawg"
        ),
        None,
    )
    if peer is None:
        return _signal("inconclusive", "peer_not_found")

    public_key = str(peer.extra.get("public_key") or "")
    address = str(peer.extra.get("address") or "")
    address_ip = address.split("/")[0].strip()

    result = run(["awg", "show", "awg0", "dump"], timeout=5)
    if not result.ok:
        return _signal("inconclusive", "awg_unavailable", peer_found=False)

    peers = parse_awg_dump(result.stdout)
    awg_peer: Optional[AwgPeer] = peers.get(public_key) if public_key else None
    if awg_peer is None and address_ip:
        for candidate in peers.values():
            tokens = [tok.split("/")[0] for tok in candidate.allowed_ips.split(",")]
            if address_ip in tokens:
                awg_peer = candidate
                break
    if awg_peer is None:
        return _signal("inconclusive", "peer_not_in_dump", peer_found=False)

    endpoint_host, endpoint_port = _split_endpoint(awg_peer.endpoint)

    from src.relay.config import handshake_age

    age = handshake_age(awg_peer.latest_handshake, int(now.timestamp()))

    pulse = (prev_state.get("sources") or {}).get("relay_pulse") or {}
    last_traffic = parse_iso(pulse.get("last_traffic_ts"))
    last_rx = pulse.get("last_rx")
    traffic_active = False
    if last_traffic is not None and (now - last_traffic) <= timedelta(seconds=ACTIVITY_WINDOW_S):
        traffic_active = True
    if isinstance(last_rx, int) and awg_peer.rx > last_rx:
        traffic_active = True

    dead = age is None or age < 0 or age >= max(cfg.handshake_threshold_s, 0)
    tcp_ok: Optional[bool] = None
    icmp_ok: Optional[bool] = None
    if dead and endpoint_host:
        if tcp_probe is not None:
            try:
                tcp_ok = bool(tcp_probe(endpoint_host, cfg.relay_probe_port, float(cfg.tcp_timeout_s)))
            except OSError:
                tcp_ok = False
        else:
            tcp_ok = _tcp_probe(endpoint_host, cfg.relay_probe_port, float(cfg.tcp_timeout_s))
        if tcp_ok is False:
            # ICMP — только уточнение текста, не триггер (SPEC §3.1).
            ping = run(["ping", "-c1", "-W2", "-n", endpoint_host], timeout=4)
            icmp_ok = ping.ok

    classification = classify_relay(age, cfg.handshake_threshold_s, tcp_ok, traffic_active)
    detail = "ok" if classification == "ok" else classification
    return _signal(
        classification,
        detail,
        peer_found=True,
        handshake_age_sec=age,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        tcp_ok=tcp_ok,
        icmp_ok=icmp_ok,
        traffic_active=traffic_active,
        peer_rx=awg_peer.rx,
    )


# ---------------------------------------------------------------------------
# лок 443
# ---------------------------------------------------------------------------

def read_lockdown(state_path: Optional[str] = None) -> dict:
    """Нормализованное состояние лока 443; ошибка чтения → `active: False`."""
    try:
        from src.gateway.store import load_state
        from src.system.ufw import get_lockdown

        return get_lockdown(load_state(_gateway_state_path(state_path)))
    except Exception:  # битый state.json → лок считается неактивным (§5 failure modes)
        return {"active": False, "error": "state_unreadable"}
