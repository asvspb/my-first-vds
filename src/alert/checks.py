"""Чтение источников сигнала и их классификация (SPEC-20261117-alert-watch §3.1–3.2).

Слой **только читает**:
  * `probe-watch.json` — своим минимальным json-читателем (не импортируем
    2300-строчный `probing`, который намеренно маскирует «нет данных» в пустой
    снапшот — для сторожа это недопустимо, SPEC §3.2);
  * `awg show <ALERT_RELAY_IFACE> dump` (default `awg0`) — через `run_list`;
  * gateway `state.json` — через `gateway.store.load_state` (только чтение);
  * состояние лока — `system.ufw.get_lockdown` (ленивый импорт).

Отсутствие данных **никогда** не превращается в тревогу: это `inconclusive` /
`telemetry_unavailable`, а не «канал мёртв».
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal, Optional

from src.alert.env import AlertConfig, relay_ifaces
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


#: Интерфейс носителя №2 (ADR-016): у него СВОЯ пара ключей и свой IP 10.12.0.2.
P2P_WSTUN_IFACE = "wg-ws0"


def _relay_peer_identity(
    gateway_state, cfg: AlertConfig, iface: str
) -> tuple[str, str]:
    """(public_key, address_ip) пира релея **для конкретного интерфейса**.

    Три источника, и выбор строго по интерфейсу (P0 ревью 2026-11-20 — раньше
    для любого не-`awg0` брался `relay_leg`, и `wg-ws0` искал ключ от awg2 →
    вечный `peer_not_found` и ложный `relay_blocked` при работе на резерве):

    * `wg-ws0` → `state.protocols["p2p_wstunnel"]` (ADR-016);
    * прочие не-`awg0` (например `awg2`) → `state.protocols["relay_leg"]`;
    * `awg0` → `clients[]` (`protocol=amneziawg`, `name=relay_peer`).

    Легаси-совместимость: `relay_leg` без поля `iface` по-прежнему обслуживает
    любой не-`awg0` интерфейс (кроме `wg-ws0`).
    """
    protocols = getattr(gateway_state, "protocols", None) or {}
    leg = protocols.get("relay_leg") or {}
    wstun = protocols.get("p2p_wstunnel") or {}

    def _identity(src: dict) -> tuple[str, str]:
        return (
            str(src.get("public_key") or ""),
            str(src.get("peer_ip") or "").split("/")[0].strip(),
        )

    wstun_iface = str(wstun.get("iface") or P2P_WSTUN_IFACE)
    if iface in (P2P_WSTUN_IFACE, wstun_iface) and wstun:
        public_key, peer_ip = _identity(wstun)
        if public_key:
            return public_key, peer_ip

    leg_iface = str(leg.get("iface") or "")
    use_leg = bool(leg) and (
        iface == leg_iface or (iface != "awg0" and iface != P2P_WSTUN_IFACE)
    )
    if use_leg:
        public_key, peer_ip = _identity(leg)
        if public_key:
            return public_key, peer_ip

    peer = next(
        (
            c
            for c in gateway_state.clients
            if c.name == cfg.relay_peer and c.protocol == "amneziawg"
        ),
        None,
    )
    if peer is None:
        return "", ""
    public_key = str(peer.extra.get("public_key") or "")
    address_ip = str(peer.extra.get("address") or "").split("/")[0].strip()
    return public_key, address_ip


def _probe_one_iface(
    *,
    cfg: AlertConfig,
    prev_state: dict,
    now: datetime,
    run: Callable[..., ShellResult] = run_list,
    state_path: Optional[str] = None,
    tcp_probe: Optional[Callable[[str, int, float], bool]] = None,
    iface: Optional[str] = None,
) -> RelaySignal:
    """Пульс плеча relay→exit: `awg show <ALERT_RELAY_IFACE> dump` + пир из gateway state.

    Пир-релей на exit-узле — либо **AWG-клиент** (`clients[]`, `protocol ==
    "amneziawg"`, `name == cfg.relay_peer`), либо пир выделенной ноги
    `state.protocols["relay_leg"]` (ADR-015), а не `state.protocols["relay"]`
    (SPEC §3.1). Интерфейс читается из `ALERT_RELAY_IFACE` (default `awg0`;
    на exit с выделенной ногой — `awg2`, ADR-015); пир ищется по публичному
    ключу из state, а не по имени iface — имя интерфейса лишь выбирает источник
    (SPEC-20261120 §3.7). `tcp_probe` — инжектируемая проба (тесты без сети).
    """
    try:
        from src.gateway.store import load_state

        gateway_state = load_state(_gateway_state_path(state_path))
    except Exception:  # StoreError и любые ошибки чтения — «слеп», не алерт
        return _signal("inconclusive", "state_unreadable")

    if iface is None:
        values = relay_ifaces(cfg)
        iface = values[0]
    public_key, address_ip = _relay_peer_identity(gateway_state, cfg, iface)
    if not public_key and not address_ip:
        return _signal("inconclusive", "peer_not_found")

    result = run(["awg", "show", iface, "dump"], timeout=5)
    if not result.ok:
        return _signal("inconclusive", "awg_unavailable", peer_found=False)

    peers = parse_awg_dump(result.stdout)
    awg_peer: Optional[AwgPeer] = peers.get(public_key) if public_key else None
    if awg_peer is None and address_ip:
        # Совместимость: старые state без public_key — ищем по адресу пира.
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
                probed = tcp_probe(
                    endpoint_host, cfg.relay_probe_port, float(cfg.tcp_timeout_s)
                )
                # None = проба не выполнялась (например, `vds alert status`)
                tcp_ok = None if probed is None else bool(probed)
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


def read_relay_signal(
    *,
    cfg: AlertConfig,
    prev_state: dict,
    now: datetime,
    run: Callable[..., ShellResult] = run_list,
    state_path: Optional[str] = None,
    tcp_probe: Optional[Callable[[str, int, float], bool]] = None,
) -> RelaySignal:
    """Пульс ноги релея с учётом **списка** интерфейсов (ADR-016).

    `ALERT_RELAY_IFACE` может перечислять носители через запятую
    (`awg2,wg-ws0`): пульс `ok`, если жив **любой**; `blocked` — только если
    мертвы все. Для одного интерфейса поведение прежнее (прямой вызов
    `_probe_one_iface`), поэтому существующие тесты и логи не меняются.
    `peer_rx` в мульти-режиме — сумма по найденным носителям (гейт активности).
    """
    ifaces = relay_ifaces(cfg)
    if len(ifaces) == 1:
        return _probe_one_iface(
            cfg=cfg, prev_state=prev_state, now=now, run=run,
            state_path=state_path, tcp_probe=tcp_probe, iface=ifaces[0],
        )

    signals = [
        _probe_one_iface(
            cfg=cfg, prev_state=prev_state, now=now, run=run,
            state_path=state_path, tcp_probe=tcp_probe, iface=iface,
        )
        for iface in ifaces
    ]
    rx_total = sum(sig.peer_rx for sig in signals)
    active = any(sig.traffic_active for sig in signals)

    ok = next((sig for sig in signals if sig.classification == "ok"), None)
    if ok is not None:
        return replace(ok, peer_rx=rx_total, traffic_active=active)

    non_inc = [sig for sig in signals if sig.classification != "inconclusive"]
    if non_inc:
        # Худший живой вердикт (blocked важнее degraded): первый по списку.
        return replace(non_inc[0], peer_rx=rx_total, traffic_active=active)

    details = {sig.detail for sig in signals}
    detail = next(iter(details)) if len(details) == 1 else "no_live_leg"
    return _signal(
        "inconclusive",
        detail,
        peer_found=any(sig.peer_found for sig in signals),
        peer_rx=rx_total,
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
