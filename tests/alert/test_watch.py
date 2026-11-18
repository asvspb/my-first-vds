"""Тесты тика сторожа (SPEC §6): решения, сообщения, теги, heartbeat, read-only."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.alert import checks as checks_mod
from src.alert import watch
from src.alert.channels import ChannelResult
from src.alert.env import AlertConfig, render_env
from src.alert.state import iso
from src.alert.watch import format_message, run_tick
from src.core.shell import ShellResult

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)
PEER_PUB = "FIXTURE_PUBKEY_RELAY111"
PEER_IP = "10.9.0.2"


# ---------------------------------------------------------------------------
# окружение: env-файл, probe-watch.json, alert-state, gateway state
# ---------------------------------------------------------------------------

class FakeConsole:
    def __init__(self):
        self.lines: list[str] = []

    def print(self, text="", **kwargs):
        self.lines.append(str(text))


class Sender:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls: list[str] = []

    def __call__(self, cfg, text):
        self.calls.append(text)
        return ChannelResult("smtp", self.ok, "" if self.ok else "conn")


class FakeRunner:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        for key, res in self.mapping.items():
            if list(args)[: len(key)] == list(key):
                return res
        return ShellResult(stdout="", stderr="", returncode=1)


def _res(stdout="", code=0):
    return ShellResult(stdout=stdout, stderr="", returncode=code)


def _env_file(tmp_path, *, checks="threat", heartbeat_h=24) -> str:
    cfg = AlertConfig(
        channels=("smtp",),
        smtp_host="smtp.example.com",
        smtp_port=465,
        smtp_user="alert-test@example.com",
        smtp_pass="FIXTURE_PW_SMTP",
        smtp_from="alert-test@example.com",
        smtp_to=("owner@example.com",),
        site_name="asv2",
        enabled_checks=tuple(checks.split(",")),
        heartbeat_h=heartbeat_h,
    )
    path = tmp_path / "alert.env"
    path.write_text(render_env(cfg, with_secrets=True), encoding="utf-8")
    return str(path)


def _probe(tmp_path, *, level="elevated", reason="RU-PROBE-SUSPECT", ts=None):
    path = tmp_path / "probe-watch.json"
    payload = {
        "version": 2,
        "ts": ts or (NOW - timedelta(minutes=5)).isoformat(),
        "threat": {"level": level, "reason": reason},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _gateway_state(tmp_path, *, with_relay=True, lockdown=None) -> str:
    clients = []
    if with_relay:
        clients.append(
            {
                "name": "relay",
                "protocol": "amneziawg",
                "port": 51825,
                "extra": {"address": f"{PEER_IP}/32", "public_key": PEER_PUB},
            }
        )
    payload = {
        "version": 1,
        "clients": clients,
        "protocols": {},
        "ufw_lockdown": lockdown or {},
    }
    path = tmp_path / "gateway-state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _seed_alert_state(tmp_path, *, heartbeat_ago_h=1, relay_traffic_ago_s=120, last_rx=100):
    path = tmp_path / "alert-state.json"
    sources = {
        "heartbeat": {"last_sent": iso(NOW - timedelta(hours=heartbeat_ago_h))},
        "relay_pulse": {
            "last_traffic_ts": iso(NOW - timedelta(seconds=relay_traffic_ago_s)),
            "last_rx": last_rx,
        },
    }
    payload = {"version": 1, "sources": sources, "window": [], "suppressed": {}, "failures": {}}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture
def gw(tmp_path, monkeypatch):
    """Gateway state.json изолирован от /opt (только чтение)."""
    path = _gateway_state(tmp_path)
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", path)
    monkeypatch.setattr(checks_mod, "_tcp_probe", lambda host, port, timeout: True)
    return path


def _tick(
    tmp_path,
    *,
    checks="threat",
    moment=NOW,
    sender=None,
    no_send=False,
    run=None,
    gateway_state=None,
    state_path=None,
    probe_kwargs=None,
):
    fake_console = FakeConsole()
    original = watch.console
    watch.console = fake_console
    try:
        code = run_tick(
            config_path=_env_file(tmp_path, checks=checks),
            no_send=no_send,
            now=moment,
            run=run or FakeRunner(),
            senders={"smtp": sender} if sender is not None else {},
            probe_path=_probe(tmp_path, **(probe_kwargs or {})),
            state_path=state_path or (tmp_path / "alert-state.json"),
        )
    finally:
        watch.console = original
    return code, fake_console.lines


def _dump(epoch: int, rx: int = 100, endpoint: str = "198.51.100.7:51820") -> str:
    return (
        "privkey\tpubkey\t51820\toff\n"
        f"{PEER_PUB}\t(none)\t{endpoint}\t{PEER_IP}/32\t{epoch}\t{rx}\t7\toff\n"
    )


# ---------------------------------------------------------------------------
# threat: переходы, дедуп, эскалация, релиз
# ---------------------------------------------------------------------------

def test_quiet_to_elevated_sends_once(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    code, lines = _tick(tmp_path, sender=sender, state_path=state)

    assert code == 0
    assert len(sender.calls) == 1
    assert "ALERT-SENT smtp threat_elevated" in lines


def test_repeat_within_window_is_duplicate(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _tick(tmp_path, sender=sender, state_path=state)
    sender2 = Sender()
    _, lines = _tick(tmp_path, sender=sender2, state_path=state, moment=NOW + timedelta(minutes=5))

    assert sender2.calls == []
    assert "ALERT-SKIP threat_elevated duplicate" in lines


def test_escalation_elevated_to_high_sends_again(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _tick(tmp_path, sender=sender, state_path=state)

    sender2 = Sender()
    _, lines = _tick(
        tmp_path, sender=sender2, state_path=state,
        moment=NOW + timedelta(minutes=5), probe_kwargs={"level": "high"},
    )

    assert len(sender2.calls) == 1
    assert "ALERT-SENT smtp threat_high" in lines
    assert "HIGH" in sender2.calls[0]


def test_high_to_quiet_sends_release(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _tick(tmp_path, sender=sender, state_path=state)

    _tick(
        tmp_path, sender=sender, state_path=state,
        moment=NOW + timedelta(minutes=5), probe_kwargs={"level": "high"},
    )

    sender3 = Sender()
    _, lines = _tick(
        tmp_path, sender=sender3, state_path=state,
        moment=NOW + timedelta(minutes=40), probe_kwargs={"level": "quiet"},
    )

    assert len(sender3.calls) == 1
    assert "ALERT-SENT smtp threat_release" in lines


def test_threat_skips_when_check_disabled(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _, lines = _tick(tmp_path, checks="relay_pulse", sender=sender, state_path=state)
    assert sender.calls == []
    assert not any("threat" in line for line in lines)


# ---------------------------------------------------------------------------
# телеметрия недоступна ≠ тихо
# ---------------------------------------------------------------------------

def _tick_missing_probe(tmp_path, *, moment, sender, state):
    fake = FakeConsole()
    original = watch.console
    watch.console = fake
    try:
        run_tick(
            config_path=_env_file(tmp_path, checks="threat"),
            now=moment, run=FakeRunner(), senders={"smtp": sender},
            probe_path=tmp_path / "absent-probe.json", state_path=state,
        )
    finally:
        watch.console = original
    return fake.lines


def test_missing_probe_sends_telemetry_unavailable_once(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _tick_missing_probe(tmp_path, moment=NOW, sender=sender, state=state)
    assert len(sender.calls) == 1
    assert "Телеметрия" in sender.calls[0]

    # повтор в пределах 24 ч — подавлен
    sender2 = Sender()
    lines = _tick_missing_probe(
        tmp_path, moment=NOW + timedelta(minutes=5), sender=sender2, state=state
    )
    assert sender2.calls == []
    assert "ALERT-SKIP telemetry_unavailable duplicate" in lines


def test_stale_probe_reported(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _tick(
        tmp_path, sender=sender, state_path=state,
        probe_kwargs={"ts": (NOW - timedelta(hours=5)).isoformat()},
    )
    assert len(sender.calls) == 1
    assert "stale" in sender.calls[0]


# ---------------------------------------------------------------------------
# пульс плеча
# ---------------------------------------------------------------------------

def _relay_tick(
    tmp_path, monkeypatch, *, epoch, tcp_ok, rx=100, traffic_ago_s=120, last_rx=100
):
    state = _seed_alert_state(
        tmp_path, relay_traffic_ago_s=traffic_ago_s, last_rx=last_rx
    )
    run = FakeRunner({("awg", "show"): _res(_dump(epoch, rx=rx))})
    sender = Sender()
    monkeypatch.setattr(checks_mod, "_tcp_probe", lambda host, port, timeout: tcp_ok)
    _, lines = _tick(tmp_path, checks="relay_pulse", sender=sender, state_path=state, run=run)
    return sender, lines


def test_relay_blocked_one_message(tmp_path, gw, monkeypatch):
    sender, lines = _relay_tick(tmp_path, monkeypatch, epoch=0, tcp_ok=True)
    assert len(sender.calls) == 1
    assert "ALERT-SENT smtp relay_blocked" in lines
    assert "relay_down" not in " ".join(lines)


def test_relay_down_one_message(tmp_path, gw, monkeypatch):
    sender, lines = _relay_tick(tmp_path, monkeypatch, epoch=0, tcp_ok=False)
    assert len(sender.calls) == 1
    assert "ALERT-SENT smtp relay_down" in lines
    assert "relay_blocked" not in " ".join(lines)


def test_relay_idle_without_activity_is_silent(tmp_path, gw, monkeypatch):
    sender, lines = _relay_tick(
        tmp_path, monkeypatch, epoch=0, tcp_ok=True,
        traffic_ago_s=2000, last_rx=100, rx=100,
    )
    assert sender.calls == []
    assert lines == []


def test_relay_fresh_handshake_is_silent(tmp_path, gw, monkeypatch):
    epoch = int(NOW.timestamp()) - 60
    sender, lines = _relay_tick(tmp_path, monkeypatch, epoch=epoch, tcp_ok=True)
    assert sender.calls == []
    assert lines == []


def test_relay_inconclusive_is_skip_not_alert(tmp_path, gw, monkeypatch):
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", tmp_path / "absent.json")
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _, lines = _tick(tmp_path, checks="relay_pulse", sender=sender, state_path=state)

    assert sender.calls == []
    assert "ALERT-SKIP relay_pulse no_telemetry" in lines


# ---------------------------------------------------------------------------
# лок 443 и совет «чем подключаться»
# ---------------------------------------------------------------------------

def test_lockdown_message_contains_routing_advice():
    """Требование владельца: в сообщении о локе есть секция с альтернативами."""
    cfg = AlertConfig(site_name="asv2")
    subject, body = format_message(
        "lockdown_on",
        cfg,
        {"now": iso(NOW), "ttl_until": "2026-11-19T10:00:00+00:00", "lockdown_reason": "auto:RU-SUSPECT"},
    )
    assert "Лок 443" in subject
    assert "Чем подключаться сейчас" in body
    assert "443/tcp закрыт до 2026-11-19T10:00:00+00:00" in body
    assert "Relay" in body and "AmneziaWG" in body and "Hysteria2" in body
    assert "vpn scout" in body


def test_message_card_format():
    """Вариант A: шапка с меткой статуса, без подчёркивания, подписи с заглавной."""
    cfg = AlertConfig(site_name="asv2")
    _, high = format_message("threat_high", cfg, {"level": "high", "reason": "PROBE-BURST"})
    header, rest = high.split("\n", 1)
    assert header == "🔴 УГРОЗА: HIGH"  # заголовок заглавными, без имени узла
    assert "━" not in high  # подчёркивание под шапкой убрано (владелец, 2026-11-19)
    assert rest.startswith("\n")  # шапка отделена пустой строкой, а не линией
    assert "Причина: PROBE-BURST" in high
    assert high.index("Сервер: asv2") < high.index("Уровень:")  # сервер — перед уровнем

    _, long_msg = format_message("threat_elevated", cfg, {"level": "elevated"})
    long_header, _ = long_msg.split("\n", 1)
    assert long_header == "🟠 УГРОЗА: ELEVATED (ВОЛНА ПРОБ)"
    assert "━" not in long_msg

    _, elevated = format_message("threat_elevated", cfg, {"level": "elevated"})
    assert elevated.startswith("🟠")

    _, release = format_message("threat_release", cfg, {"level": "quiet"})
    assert release.startswith("🟢")

    _, heartbeat = format_message("heartbeat", cfg, {})
    assert heartbeat.startswith("⚪")

    # подпись «только уведомление» удалена по требованию владельца
    assert "только уведомление" not in high


def test_lockdown_on_sends_once_then_reminder(tmp_path, gw, monkeypatch):
    lockdown = {
        "active": True,
        "since": "2026-11-17T10:00:00+00:00",
        "ttl_until": "2026-11-19T10:00:00+00:00",
        "ttl_hours": 48,
        "allow_from": ["203.0.113.10"],
        "reason": "auto:RU-SUSPECT",
    }
    path = _gateway_state(tmp_path, lockdown=lockdown)
    monkeypatch.setattr("src.gateway.paths.STATE_PATH", path)
    state = _seed_alert_state(tmp_path)

    sender = Sender()
    _, lines = _tick(tmp_path, checks="lockdown", sender=sender, state_path=state)
    assert "ALERT-SENT smtp lockdown_on" in lines
    assert "Чем подключаться сейчас" in sender.calls[0]

    # второй тик через 30 мин — cooldown на "still" (напоминание раз в 6 ч)
    sender2 = Sender()
    _, lines2 = _tick(
        tmp_path, checks="lockdown", sender=sender2, state_path=state,
        moment=NOW + timedelta(minutes=30),
    )
    assert sender2.calls == []
    assert any("lockdown_still" in line and "ALERT-SKIP" in line for line in lines2)


def test_lockdown_inactive_is_silent(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender()
    _, lines = _tick(tmp_path, checks="lockdown", sender=sender, state_path=state)
    assert sender.calls == []
    assert lines == []


# ---------------------------------------------------------------------------
# heartbeat и битый state
# ---------------------------------------------------------------------------

def test_heartbeat_first_tick_sent_then_not_repeated(tmp_path, gw):
    # state без heartbeat.last_sent → первый тик отправляет heartbeat
    state = tmp_path / "alert-state.json"
    state.write_text(json.dumps({"version": 1, "sources": {}}), encoding="utf-8")

    sender = Sender()
    _, lines = _tick(tmp_path, checks="none", sender=sender, state_path=state)
    assert "ALERT-SENT smtp heartbeat" in lines

    sender2 = Sender()
    _, lines2 = _tick(
        tmp_path, checks="none", sender=sender2, state_path=state,
        moment=NOW + timedelta(hours=1),
    )
    assert sender2.calls == []
    assert lines2 == []


def test_heartbeat_repeats_after_interval(tmp_path, gw):
    state = _seed_alert_state(tmp_path, heartbeat_ago_h=30)
    sender = Sender()
    _, lines = _tick(tmp_path, checks="none", sender=sender, state_path=state)
    assert "ALERT-SENT smtp heartbeat" in lines
    assert "Пропущено часов без heartbeat: 30" in sender.calls[0]


def test_corrupt_state_recovers_and_reports(tmp_path, gw):
    state = tmp_path / "alert-state.json"
    state.write_text("{broken", encoding="utf-8")
    sender = Sender()
    code, lines = _tick(tmp_path, sender=sender, state_path=state)

    assert code == 0
    assert "ALERT-FAILED state corrupt" in lines
    assert len(sender.calls) >= 1  # тик продолжился (threat + heartbeat)
    json.loads(state.read_text(encoding="utf-8"))  # файл пересоздан валидным


# ---------------------------------------------------------------------------
# no_send и read-only
# ---------------------------------------------------------------------------

def test_no_send_writes_nothing(tmp_path, gw):
    state = tmp_path / "alert-state.json"
    sender = Sender()
    code, lines = _tick(tmp_path, sender=sender, no_send=True, state_path=state)

    assert code == 0
    assert sender.calls == []
    assert not state.exists()
    assert any("DRY-RUN" in line for line in lines)


def test_no_send_does_not_mutate_existing_state(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    before = state.read_text(encoding="utf-8")
    _tick(tmp_path, sender=Sender(), no_send=True, state_path=state)
    assert state.read_text(encoding="utf-8") == before


def test_probe_watch_and_gateway_state_are_read_only(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    probe = _probe(tmp_path)
    probe_before = probe.read_bytes()
    gw_before = (tmp_path / "gateway-state.json").read_bytes()

    _tick(tmp_path, checks="threat,relay_pulse,lockdown", sender=Sender(), state_path=state)

    assert probe.read_bytes() == probe_before
    assert (tmp_path / "gateway-state.json").read_bytes() == gw_before


# ---------------------------------------------------------------------------
# сбой канала: тег + state не падает
# ---------------------------------------------------------------------------

def test_channel_failure_does_not_raise_and_backoff_applied(tmp_path, gw):
    state = _seed_alert_state(tmp_path)
    sender = Sender(ok=False)
    code, lines = _tick(tmp_path, sender=sender, state_path=state)

    assert code == 0
    assert "ALERT-FAILED smtp conn" in lines
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["failures"]["smtp"]["count"] == 1
    assert saved["failures"]["smtp"]["next_attempt"]

    # следующий тик в пределах backoff — канал не дёргается
    sender2 = Sender()
    _, lines2 = _tick(
        tmp_path, sender=sender2, state_path=state, moment=NOW + timedelta(seconds=30)
    )
    assert sender2.calls == []
    assert "ALERT-SKIP threat_elevated rate_limited" in lines2


def test_channel_not_configured_skips(tmp_path, gw):
    # env без SMTP-пары → каналов нет, ALERT-SKIP … channel_not_configured
    state = _seed_alert_state(tmp_path)
    env_path = tmp_path / "alert.env"
    env_path.write_text("ALERT_CHECKS=threat\n", encoding="utf-8")
    fake = FakeConsole()
    original = watch.console
    watch.console = fake
    try:
        code = run_tick(
            config_path=str(env_path), now=NOW, run=FakeRunner(),
            probe_path=_probe(tmp_path), state_path=state,
        )
    finally:
        watch.console = original
    assert code == 0
    assert "ALERT-SKIP threat_elevated channel_not_configured" in fake.lines
