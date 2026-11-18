"""Один тик сторожа (SPEC-20261117-alert-watch §2, §3.6–3.9).

Порядок: собрать сигналы (только чтение) → `state.decide()` → доставка →
journal-теги → сохранить состояние. Exit-код **всегда 0**: сбой доставки не
должен валить таймер (SPEC §5).

Инварианты:
  * `probe-watch.json` и gateway `state.json` не мутируются;
  * `watch --no-send` не отправляет и не пишет state;
  * «нет данных» → `ALERT-SKIP … no_telemetry`, не алерт.
"""
from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from src.alert import channels, checks
from src.alert.channels import ChannelResult, backoff_delay_sec
from src.alert.env import (
    AlertConfig,
    active_channels,
    config_warnings,
    load_config,
)
from src.alert.paths import (
    ALERT_ENV_PATH,
    ALERT_LOCK_FILE,
    ALERT_STATE_PATH,
    PROBE_WATCH_PATH,
)
from src.alert.state import (
    bump_suppressed,
    clear_suppressed,
    decide,
    iso,
    load_state,
    parse_iso,
    record_send,
    save_state,
    set_source,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import ShellResult, run_list

ROUTING_KINDS = {
    "threat_elevated",
    "threat_high",
    "threat_high_still",
    "lockdown_on",
    "lockdown_still",
}

TITLES = {
    "threat_elevated": "Угроза: ELEVATED (волна проб)",
    "threat_high": "Угроза: HIGH",
    "threat_high_still": "Угроза всё ещё HIGH",
    "threat_release": "Угроза спала: quiet",
    "relay_blocked": "Плечо relay→exit: похоже на блокировку",
    "relay_down": "Плечо relay→exit: релей недоступен",
    "relay_recovered": "Плечо relay→exit: восстановлено",
    "lockdown_on": "Лок 443 включён",
    "lockdown_still": "Лок 443 всё ещё активен",
    "telemetry_unavailable": "Телеметрия недоступна",
    "heartbeat": "Сторож жив (heartbeat)",
    "summary": "Отфильтрованные повторы за час",
}

# Метка статуса в шапке сообщения (вариант A: карточка).
STATUS_MARKS = {"quiet": "🟢", "elevated": "🟠", "high": "🔴"}

THREAT_KINDS = {"threat_elevated", "threat_high", "threat_high_still", "threat_release"}

KIND_MARKS = {
    "relay_blocked": "🟠",
    "relay_down": "🔴",
    "relay_recovered": "🟢",
    "lockdown_on": "🔴",
    "lockdown_still": "🔴",
    "telemetry_unavailable": "🟠",
    "heartbeat": "⚪",
    "summary": "ℹ️",
}

# Ширина линии-разделителя больше не используется: подчёркивание под шапкой
# убрано по требованию владельца (2026-11-19).


def _mark(kind: str, level: str) -> str:
    """Эмодзи статуса: для угрозы — по level, иначе — по типу события."""
    if kind in THREAT_KINDS:
        if level in STATUS_MARKS:
            return STATUS_MARKS[level]
        return "🟢" if kind == "threat_release" else "🟠"
    return KIND_MARKS.get(kind, "⚪")


TAG_SENT = "ALERT-SENT"
TAG_FAILED = "ALERT-FAILED"
TAG_SKIP = "ALERT-SKIP"


def _tag(text: str) -> None:
    """Машиночитаемая строка в journal: без переносов и разметки."""
    console.print(text, markup=False, highlight=False, soft_wrap=True)


def _site(cfg: AlertConfig) -> str:
    return cfg.site_name or socket.gethostname() or "vds"


def routing_advice(lockdown_until: str = "") -> str:
    """Секция «Чем подключаться сейчас» (требование владельца к содержанию).

    Печатается в сообщениях о threat/lock-443: владельцу нужен не только факт
    тревоги, но и рабочая альтернатива, пока 443/tcp закрыт.
    """
    if lockdown_until:
        first = f"• 443/tcp закрыт до {lockdown_until} — используйте Relay (AmneziaWG / Hysteria2)"
    else:
        first = "• 443/tcp под угрозой (при HIGH лок включится автоматически) — держите Relay (AmneziaWG / Hysteria2) под рукой"
    return "\n".join(
        [
            "🔌 Чем подключаться сейчас",
            first,
            "• direct + AmneziaWG (не 443/tcp) — отдельный UDP-порт, лок его не трогает",
            "• на клиенте: vpn scout — покажет, что живо прямо сейчас",
        ]
    )


def format_message(kind: str, cfg: AlertConfig, payload: dict) -> tuple[str, str]:
    """(subject, body) для journal/Telegram/SMTP. Секретов не содержит."""
    title = TITLES.get(kind, kind)
    site = _site(cfg)
    subject = f"[{site}] {title}"

    lines: list[str] = []
    now = payload.get("now")
    if now:
        lines.append(f"Время (UTC): {now}")
    lines.append(f"Сервер: {site}")

    level = payload.get("level")
    if level:
        lines.append(f"Уровень: {level}")
    if payload.get("level_since"):
        lines.append(f"Уровень с: {payload['level_since']} (телеметрия часового тика — лаг до 1 ч)")
    if payload.get("reason"):
        lines.append(f"Причина: {payload['reason']}")
    if payload.get("age_sec") is not None:
        lines.append(f"Снапшот: {int(payload['age_sec'])} с назад")
    if payload.get("status"):
        lines.append(f"Телеметрия: {payload['status']}")

    if payload.get("classification"):
        detail = str(payload.get("detail") or "")
        suffix = f" ({detail})" if detail and detail != payload["classification"] else ""
        lines.append(f"Плечо: {payload['classification']}{suffix}")
    if payload.get("handshake_age_sec") is not None:
        age = payload["handshake_age_sec"]
        lines.append("Handshake: никогда" if age == -1 else f"Handshake: {age} с")
    if payload.get("endpoint"):
        lines.append(f"Релей: {payload['endpoint']}")
    if payload.get("tcp_ok") is not None:
        lines.append(f"TCP до релея: {'жив' if payload['tcp_ok'] else 'не отвечает'}")
    if payload.get("icmp_ok") is not None:
        lines.append(f"ICMP: {'отвечает' if payload['icmp_ok'] else 'нет'}")
    if payload.get("traffic_active") is not None:
        lines.append(f"Трафик по ноге: {'есть' if payload['traffic_active'] else 'нет'}")

    if payload.get("ttl_until"):
        lines.append(f"Лок 443 до: {payload['ttl_until']}")
    if payload.get("lockdown_since"):
        lines.append(f"Лок 443 с: {payload['lockdown_since']}")
    if payload.get("lockdown_reason"):
        lines.append(f"Причина лока: {payload['lockdown_reason']}")
    if payload.get("allow_from_count") is not None:
        lines.append(f"Allow-list лока: {payload['allow_from_count']} адрес(ов)")

    if payload.get("missed_hours"):
        lines.append(f"Пропущено часов без heartbeat: {payload['missed_hours']}")

    for extra in payload.get("extra_lines") or []:
        lines.append(str(extra))

    if kind == "summary":
        suppressed = payload.get("suppressed") or {}
        for name, count in sorted(suppressed.items()):
            lines.append(f"  подавлено {name}: {count}")

    if payload.get("channel_warnings"):
        lines.append("Каналы:")
        for warning in payload["channel_warnings"]:
            lines.append(f"  ! {warning}")

    mark = _mark(kind, str(level or ""))
    header = f"{mark} {title.upper()}"
    # Подчёркивания нет (владелец, 2026-11-19): шапка, пустая строка, поля.
    body_parts = [header, ""]
    body_parts.extend(lines)
    if kind in ROUTING_KINDS:
        body_parts.extend(["", routing_advice(str(payload.get("ttl_until") or ""))])
    return subject, "\n".join(body_parts)


def _send_one(
    channel: str,
    cfg: AlertConfig,
    subject: str,
    body: str,
    senders: Optional[dict[str, Callable[..., ChannelResult]]],
) -> ChannelResult:
    if senders and channel in senders:
        try:
            return senders[channel](cfg, body)
        except Exception:  # канал не должен валить тик
            return ChannelResult(channel, False, "conn")
    if channel == "tg":
        return channels.send_telegram(cfg, body)
    if channel == "smtp":
        return channels.send_smtp(cfg, subject, body)
    return ChannelResult(channel, False, "config")


def _ready_channels(cfg: AlertConfig, state: dict, now: datetime) -> list[str]:
    """Активные каналы минус те, что в backoff после прошлых сбоев."""
    failures = state.get("failures") or {}
    ready: list[str] = []
    for channel in active_channels(cfg):
        info = failures.get(channel) if isinstance(failures.get(channel), dict) else {}
        next_at = parse_iso(info.get("next_attempt")) if info else None
        if next_at is not None and next_at > now:
            continue
        ready.append(channel)
    return ready


def _register_failure(state: dict, channel: str, now: datetime) -> None:
    failures = state.setdefault("failures", {})
    info = failures.get(channel)
    if not isinstance(info, dict):
        info = {"count": 0, "next_attempt": ""}
    count = int(info.get("count") or 0) + 1
    info["count"] = count
    info["next_attempt"] = iso(now + timedelta(seconds=backoff_delay_sec(count)))
    failures[channel] = info


def _register_success(state: dict, channel: str) -> None:
    failures = state.setdefault("failures", {})
    failures[channel] = {"count": 0, "next_attempt": ""}


def _deliver(
    *,
    cfg: AlertConfig,
    state: dict,
    channels_ready: list[str],
    subject: str,
    body: str,
    senders: Optional[dict[str, Callable[..., ChannelResult]]],
    now: datetime,
    event_type: str,
) -> bool:
    """Отправить по готовым каналам; True — хотя бы один принял сообщение."""
    delivered = False
    for channel in channels_ready:
        result = _send_one(channel, cfg, subject, body, senders)
        if result.ok:
            _tag(f"{TAG_SENT} {channel} {event_type}")
            _register_success(state, channel)
            delivered = True
        else:
            _tag(f"{TAG_FAILED} {channel} {result.errclass}")
            _register_failure(state, channel, now)
    return delivered


def _handle(
    *,
    event: str,
    event_type: str,
    severity: int,
    subject: str,
    body: str,
    cooldown_min: int,
    cfg: AlertConfig,
    state: dict,
    now: datetime,
    no_send: bool,
    senders: Optional[dict[str, Callable[..., ChannelResult]]],
) -> bool:
    """Провести одно событие через decide → (опционально) доставку.

    Возвращает True, если сообщение реально доставлено хоть по одному каналу.
    При `no_send` печатает план и ничего не пишет в state.
    """
    decision = decide(event, severity, state, now, cooldown_min, cfg.rate_limit_per_hour)
    if not decision.send:
        if decision.reason in ("duplicate", "cooldown", "rate_limited"):
            bump_suppressed(state, event_type)
        _tag(f"{TAG_SKIP} {event_type} {decision.reason}")
        return False

    if no_send:
        console.print(
            f"[info][alert] DRY-RUN: отправил бы {event_type} "
            f"(каналы: {', '.join(active_channels(cfg)) or 'не настроены'})[/info]"
        )
        return False

    if not active_channels(cfg):
        _tag(f"{TAG_SKIP} {event_type} channel_not_configured")
        return False

    ready = _ready_channels(cfg, state, now)
    if not ready:
        _tag(f"{TAG_SKIP} {event_type} rate_limited")
        bump_suppressed(state, event_type)
        return False

    if _deliver(
        cfg=cfg,
        state=state,
        channels_ready=ready,
        subject=subject,
        body=body,
        senders=senders,
        now=now,
        event_type=event_type,
    ):
        record_send(state, event, event_type, severity, now)
        return True
    return False


def _payload_base(now: datetime) -> dict:
    return {"now": iso(now)}


def run_tick(
    *,
    config_path: str = ALERT_ENV_PATH,
    no_send: bool = False,
    now: Optional[datetime] = None,
    run: Callable[..., ShellResult] = run_list,
    senders: Optional[dict[str, Callable[..., ChannelResult]]] = None,
    probe_path: Path = PROBE_WATCH_PATH,
    state_path: Path = ALERT_STATE_PATH,
) -> int:
    """Один тик сторожа. Exit-код всегда 0 (сбой доставки — не сбой юнита)."""
    moment = now or datetime.now(timezone.utc)
    cfg = load_config(config_path)

    use_lock = Path(state_path) == Path(ALERT_STATE_PATH)
    lock = FileLock(ALERT_LOCK_FILE) if use_lock else None
    if lock is not None and not lock.acquire(nonblock=True):
        console.print("[warning][alert] предыдущий тик ещё выполняется — пропуск[/warning]")
        return 0
    try:
        state, corrupted = load_state(state_path)
        if corrupted:
            _tag(f"{TAG_FAILED} state corrupt")
        _tick(
            cfg=cfg,
            state=state,
            moment=moment,
            no_send=no_send,
            run=run,
            senders=senders,
            probe_path=Path(probe_path),
            save_path=Path(state_path),
        )
    finally:
        if lock is not None:
            lock.release()
    return 0


def _tick(
    *,
    cfg: AlertConfig,
    state: dict,
    moment: datetime,
    no_send: bool,
    run: Callable[..., ShellResult],
    senders: Optional[dict[str, Callable[..., ChannelResult]]],
    probe_path: Path,
    save_path: Path,
) -> None:
    common = dict(cfg=cfg, state=state, now=moment, no_send=no_send, senders=senders)

    # --- сводка подавлённого (одна отправка, счётчики обнуляются)
    if state.get("suppressed"):
        sent_last_hour = sum(
            1
            for raw in (state.get("window") or [])
            if (ts := parse_iso(raw)) and ts > moment - timedelta(hours=1)
        )
        if sent_last_hour < cfg.rate_limit_per_hour:
            subject, body = format_message(
                "summary",
                cfg,
                {**_payload_base(moment), "suppressed": dict(state["suppressed"])},
            )
            if _handle(
                event="summary",
                event_type="summary",
                severity=0,
                subject=subject,
                body=body,
                cooldown_min=60,
                **common,
            ):
                clear_suppressed(state)

    lockdown = checks.read_lockdown() if "lockdown" in cfg.enabled_checks else {"active": False}
    lockdown_until = str(lockdown.get("ttl_until") or "") if lockdown.get("active") else ""

    # --- threat + telemetry
    threat: Optional[checks.ThreatSignal] = None
    if "threat" in cfg.enabled_checks:
        threat = checks.read_threat(probe_path, now=moment)
        if threat.status != "ok":
            set_source(
                state,
                "telemetry",
                probe_watch={"status": threat.status, "reason": threat.reason},
            )
            subject, body = format_message(
                "telemetry_unavailable",
                cfg,
                {
                    **_payload_base(moment),
                    "status": threat.status,
                    "reason": threat.reason,
                    "age_sec": threat.age_sec,
                    "level_since": threat.snapshot_ts or None,
                },
            )
            _handle(
                event="telemetry",
                event_type="telemetry_unavailable",
                severity=0,
                subject=subject,
                body=body,
                cooldown_min=cfg.telemetry_reminder_h * 60,
                **common,
            )
        else:
            set_source(state, "telemetry", probe_watch={"status": "ok", "reason": ""})
            level = threat.level or "quiet"
            severity = {"quiet": 0, "elevated": 1, "high": 2}[level]
            last_sev = state["sources"].get("threat", {}).get("severity")
            payload = {
                **_payload_base(moment),
                "level": level,
                "level_since": threat.snapshot_ts or None,
                "reason": threat.reason or None,
                "age_sec": threat.age_sec,
            }
            if level == "quiet":
                if isinstance(last_sev, int) and last_sev > 0:
                    subject, body = format_message("threat_release", cfg, payload)
                    _handle(
                        event="threat",
                        event_type="threat_release",
                        severity=0,
                        subject=subject,
                        body=body,
                        cooldown_min=cfg.cooldown_min,
                        **common,
                    )
            else:
                event_type = "threat_elevated" if level == "elevated" else (
                    "threat_high_still" if last_sev == 2 else "threat_high"
                )
                subject, body = format_message(event_type, cfg, payload)
                _handle(
                    event="threat",
                    event_type=event_type,
                    severity=severity,
                    subject=subject,
                    body=body,
                    cooldown_min=cfg.cooldown_min,
                    **common,
                )

    # --- пульс плеча
    if "relay_pulse" in cfg.enabled_checks:
        relay = checks.read_relay_signal(cfg=cfg, prev_state=state, now=moment, run=run)
        pulse = state["sources"].setdefault("relay_pulse", {})
        if relay.peer_found:
            prev_rx = pulse.get("last_rx")
            if isinstance(prev_rx, int) and relay.peer_rx > prev_rx:
                pulse["last_traffic_ts"] = iso(moment)
            pulse["last_rx"] = relay.peer_rx
            pulse["class"] = relay.classification

        payload = {
            **_payload_base(moment),
            "classification": relay.classification,
            "detail": relay.detail,
            "handshake_age_sec": relay.handshake_age_sec,
            "endpoint": (
                f"{relay.endpoint_host}:{relay.endpoint_port}" if relay.endpoint_host else ""
            ),
            "tcp_ok": relay.tcp_ok,
            "icmp_ok": relay.icmp_ok,
            "traffic_active": relay.traffic_active,
        }
        last_sev = pulse.get("severity")
        if relay.classification == "blocked":
            subject, body = format_message("relay_blocked", cfg, payload)
            _handle(
                event="relay_pulse", event_type="relay_blocked", severity=2,
                subject=subject, body=body, cooldown_min=cfg.cooldown_min, **common,
            )
        elif relay.classification == "relay_down":
            subject, body = format_message("relay_down", cfg, payload)
            _handle(
                event="relay_pulse", event_type="relay_down", severity=3,
                subject=subject, body=body, cooldown_min=cfg.cooldown_min, **common,
            )
        elif relay.classification == "ok" and isinstance(last_sev, int) and last_sev > 0:
            subject, body = format_message("relay_recovered", cfg, payload)
            _handle(
                event="relay_pulse", event_type="relay_recovered", severity=0,
                subject=subject, body=body, cooldown_min=cfg.cooldown_min, **common,
            )
        elif relay.classification == "inconclusive":
            _tag(f"{TAG_SKIP} relay_pulse no_telemetry")

    # --- лок 443
    if "lockdown" in cfg.enabled_checks:
        prev_active = bool((state["sources"].get("lockdown") or {}).get("active"))
        active = bool(lockdown.get("active"))
        set_source(state, "lockdown", active=active)
        if active:
            event_type = "lockdown_still" if prev_active else "lockdown_on"
            payload = {
                **_payload_base(moment),
                "ttl_until": lockdown.get("ttl_until") or "",
                "lockdown_since": lockdown.get("since") or "",
                "lockdown_reason": lockdown.get("reason") or "",
                "allow_from_count": len(lockdown.get("allow_from") or []),
            }
            subject, body = format_message(event_type, cfg, payload)
            _handle(
                event="lockdown",
                event_type=event_type,
                severity=2,
                subject=subject,
                body=body,
                cooldown_min=0 if not prev_active else cfg.lock_reminder_h * 60,
                **common,
            )

    # --- heartbeat (dead-man switch)
    hb = state["sources"].setdefault("heartbeat", {})
    last_hb = parse_iso(hb.get("last_sent"))
    due = last_hb is None or (moment - last_hb) >= timedelta(hours=max(cfg.heartbeat_h, 1))
    if due:
        missed = 0
        if last_hb is not None:
            missed = int((moment - last_hb).total_seconds() // 3600)
        payload = {
            **_payload_base(moment),
            "level": threat.level if threat is not None else None,
            "level_since": threat.snapshot_ts if threat is not None else None,
            "status": threat.status if threat is not None else "disabled",
            "channel_warnings": config_warnings(cfg),
            "missed_hours": missed if missed > cfg.heartbeat_h else 0,
        }
        subject, body = format_message("heartbeat", cfg, payload)
        _handle(
            event="heartbeat",
            event_type="heartbeat",
            severity=0,
            subject=subject,
            body=body,
            cooldown_min=cfg.heartbeat_h * 60,
            **common,
        )

    if not no_send:
        state["updated"] = iso(moment)
        if not save_state(state, save_path):
            _tag(f"{TAG_FAILED} state write")
