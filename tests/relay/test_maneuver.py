"""Тесты `vds relay maneuver` (ADR-015, SPEC-20261120 WP-M3 / TECHDEBT P25).

Всё на моках: ни root, ни сети, ни systemd, ни реального `awg`. Проверяются
чистые парсеры/переходы, activity gate (регресс WP-M0), актуатор `awg set`,
откат по 20 с, anti-ping-pong, guard роли/пула и отсутствие секретов.
"""

from __future__ import annotations

import json
import stat

import pytest

import src.relay.maneuver as maneuver
from src.core.shell import ShellResult
from src.gateway.store import GatewayState

NOW = 1_700_000_000.0
EXIT_HOST = "203.0.113.9"  # RFC 5737 — фикстура, не реальный адрес
PEER_PUB = "FIXTURE_PUBKEY_EXIT_AWG2_0000000000="
PEER_PSK = "FIXTURE_PSK_NEVER_LEAK_000000000000="
PRIV = "FIXTURE_PRIVKEY_RELAY_AWG1_00000000000000="
PRIV0 = "FIXTURE_PRIVKEY_AWG0_000000000000000000="
POOL = list(range(51900, 51912))

DUMP_TMPL = (
    f"{PRIV[:40]}\t{PEER_PUB}\t59036\toff\n"
    f"{PEER_PUB}\t{PEER_PSK}\t{{host}}:{{port}}\t0.0.0.0/0\t1700000000\t100\t200\t25\n"
)

CONF_TEXT = (
    "[Interface]\n"
    f"PrivateKey = {PRIV}\n"
    "Address = 10.11.0.2/32\n"
    "Table = off\n"
    "MTU = 1420\n"
    "Jc = 3\n"
    "Jmin = 10\n"
    "Jmax = 50\n"
    "S1 = 20\n"
    "S2 = 30\n"
    "H1 = 1\n"
    "H2 = 2\n"
    "H3 = 3\n"
    "H4 = 4\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {PEER_PUB}\n"
    "AllowedIPs = 0.0.0.0/0\n"
    f"Endpoint = {EXIT_HOST}:51900\n"
    "PersistentKeepalive = 25\n"
)


def make_sample(
    *,
    ok: bool = False,
    fails: int = 3,
    activity: bool = True,
    now: float = NOW,
    awg0_rx: int = 50_000,
    awg0_tx: int = 50_000,
    awg1_rx: int = 100,
    awg1_tx: int = 200,
) -> dict:
    return {
        "ts": now,
        "awg0_rx_sum": awg0_rx,
        "awg0_tx_sum": awg0_tx,
        "awg1_rx": awg1_rx,
        "awg1_tx": awg1_tx,
        "liveness_ok": ok,
        "liveness_ms": 47 if ok else None,
        "consecutive_failures": 0 if ok else fails,
        "activity": activity,
    }


def leg(port: int = 51900) -> dict:
    return {
        "iface": "awg1",
        "listen_port": 59036,
        "peer_public_key": PEER_PUB,
        "endpoint_host": EXIT_HOST,
        "endpoint_port": port,
    }


class FakeRunner:
    """prefix-match мок `run_list`; пишет все вызовы."""

    def __init__(self, *, port: int = 51900, set_ok: bool = True):
        self.port = port
        self.set_ok = set_ok
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        call = list(args)
        self.calls.append(call)
        if call[:3] == ["awg", "show", "awg1"] and call[3:] == ["dump"]:
            return ShellResult(DUMP_TMPL.format(host=EXIT_HOST, port=self.port), "", 0)
        if call[:3] == ["awg", "show", "awg0"] and call[3:] == ["transfer"]:
            return ShellResult("PUB0\t100\t200\n", "", 0)
        if call[:3] == ["awg", "show", "awg1"] and call[3:] == ["transfer"]:
            return ShellResult(f"{PEER_PUB}\t50\t60\n", "", 0)
        if call[:2] == ["awg", "set"]:
            return ShellResult("", "", 0 if self.set_ok else 1)
        if call[:1] == ["ping"]:
            return ShellResult("", "unreachable", 1)
        return ShellResult("", "", 0)

    def commands(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    conf = tmp_path / "amnezia" / "awg1.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(CONF_TEXT, encoding="utf-8")
    conf.chmod(0o600)
    monkeypatch.setattr(maneuver, "RELAY_EXIT_CONFIG_PATH", conf)
    monkeypatch.setattr(maneuver, "RELAY_MANEUVER_LOCK_FILE", str(tmp_path / "maneuver.lock"))
    monkeypatch.setattr(maneuver.os, "geteuid", lambda: 0)

    gw = tmp_path / "gateway-state.json"
    gw.write_text(
        json.dumps({"version": 1, "protocols": {"relay": {"installed": True}}}),
        encoding="utf-8",
    )
    runner = FakeRunner()
    monkeypatch.setattr(maneuver, "run_list", runner)
    return {
        "tmp": tmp_path,
        "conf": conf,
        "runner": runner,
        "state_path": str(gw),
        "maneuver_path": str(tmp_path / "relay-maneuver.json"),
    }


# ---------------------------------------------------------------------------
# Чистые парсеры
# ---------------------------------------------------------------------------

class TestParsers:
    def test_dump_parses_listen_and_peer_without_private_key(self):
        dump = maneuver.parse_awg_dump(DUMP_TMPL.format(host=EXIT_HOST, port=51900))
        assert dump["listen_port"] == 59036
        assert len(dump["peers"]) == 1
        peer = dump["peers"][0]
        assert peer["endpoint_host"] == EXIT_HOST
        assert peer["endpoint_port"] == 51900
        assert peer["public_key"] == PEER_PUB
        # Приватный ключ интерфейса и PSK не выходят из парсера.
        assert PRIV not in json.dumps(dump)
        assert PEER_PSK not in json.dumps(dump)

    @pytest.mark.parametrize(
        "endpoint,expected",
        [
            ("203.0.113.9:51900", ("203.0.113.9", 51900)),
            ("[2001:db8::1]:51900", ("2001:db8::1", 51900)),
            ("(none)", ("", None)),
            ("", ("", None)),
            ("garbage", ("", None)),
        ],
    )
    def test_split_endpoint(self, endpoint, expected):
        assert maneuver.split_endpoint(endpoint) == expected

    def test_transfer_sums(self):
        text = "A\t10\t20\nB\t5\t7\n"
        entries = maneuver.parse_transfer(text)
        assert maneuver.sum_transfer(entries) == (15, 27)

    def test_ping_ms(self):
        assert maneuver.parse_ping_ms("64 bytes from 10.11.0.1: time=47.2 ms") == 47
        assert maneuver.parse_ping_ms("time<1 ms") == 1
        assert maneuver.parse_ping_ms("no stats") is None

    def test_pool_matches_exit_leg(self):
        assert maneuver.pool_ports() == POOL

    def test_next_port_walks_pool_and_skips_failed(self):
        assert maneuver.next_port(51900, POOL, []) == 51901
        assert maneuver.next_port(51900, POOL, [51901]) == 51902
        assert maneuver.next_port(51911, POOL, []) == 51900
        # Все прочие отказали — пул исчерпан.
        assert maneuver.next_port(51900, POOL, POOL[1:]) is None


class TestActivityGate:
    def test_first_sample_is_baseline(self):
        cur = make_sample(ok=True)
        assert maneuver.compute_activity(None, cur) is False

    def test_client_traffic_triggers(self):
        prev = make_sample(awg0_rx=1000, awg0_tx=1000)
        cur = make_sample(awg0_rx=1000 + maneuver.ACTIVITY_NOISE_BYTES, awg0_tx=1000)
        assert maneuver.compute_activity(prev, cur) is True

    def test_keepalive_only_is_not_activity(self):
        # PersistentKeepalive 25: крошечный прирост tx, rx стоит.
        prev = make_sample(awg1_tx=10_000, awg1_rx=5_000)
        cur = make_sample(awg1_tx=10_064, awg1_rx=5_000)
        assert maneuver.compute_activity(prev, cur) is False

    def test_one_tx_delta_alone_is_not_activity(self):
        prev = make_sample(awg1_tx=10_000, awg1_rx=5_000)
        cur = make_sample(awg1_tx=10_001, awg1_rx=5_000)
        assert maneuver.compute_activity(prev, cur) is False

    def test_junk_tx_without_response_is_activity(self):
        prev = make_sample(awg1_tx=10_000, awg1_rx=5_000)
        cur = make_sample(awg1_tx=10_000 + maneuver.ACTIVITY_NOISE_BYTES, awg1_rx=5_000)
        assert maneuver.compute_activity(prev, cur) is True

    def test_tx_growth_with_rx_growth_is_not_junk(self):
        prev = make_sample(awg1_tx=10_000, awg1_rx=5_000)
        cur = make_sample(
            awg1_tx=10_000 + maneuver.ACTIVITY_NOISE_BYTES, awg1_rx=5_000 + 100
        )
        assert maneuver.compute_activity(prev, cur) is False

    def test_counter_reset_is_safe(self):
        prev = make_sample(awg0_rx=10_000_000, awg0_tx=10_000_000, awg1_tx=10_000)
        cur = make_sample(awg0_rx=10, awg0_tx=10, awg1_tx=1)
        assert maneuver.compute_activity(prev, cur) is False


# ---------------------------------------------------------------------------
# State-machine: таблица переходов всех 6 состояний
# ---------------------------------------------------------------------------

COOLDOWN_ACTIVE = NOW + 600
COOLDOWN_EXPIRED = NOW - 1


def _decide(name, *, ok=False, fails=3, activity=True, cooldown=COOLDOWN_EXPIRED, hourly=0, candidate=51901):
    return maneuver.decide(
        name,
        make_sample(ok=ok, fails=fails, activity=activity),
        now=NOW,
        cooldown_until=cooldown,
        hourly_attempts_count=hourly,
        candidate=candidate,
    )


class TestTransitions:
    def test_idle_liveness_ok_goes_healthy(self):
        assert _decide("idle", ok=True).state == "healthy"

    def test_idle_failures_below_threshold_stay_idle(self):
        d = _decide("idle", fails=1, activity=False)
        assert d.state == "idle" and d.maneuver is False

    def test_idle_no_activity_never_maneuvers(self):
        d = _decide("idle", fails=5, activity=False)
        assert d.state == "idle" and d.maneuver is False

    def test_idle_fail_and_activity_maneuvers(self):
        d = _decide("idle")
        assert d.state == "maneuvering" and d.maneuver is True

    def test_healthy_ok(self):
        assert _decide("healthy", ok=True).state == "healthy"

    def test_healthy_failures_accumulate_to_suspect(self):
        d = _decide("healthy", fails=2, activity=False)
        assert d.state == "suspect" and d.maneuver is False

    def test_healthy_no_activity_no_maneuver(self):
        d = _decide("healthy", fails=4, activity=False)
        assert d.state == "suspect" and d.maneuver is False

    def test_healthy_cooldown_blocks(self):
        d = _decide("healthy", cooldown=COOLDOWN_ACTIVE)
        assert d.state == "cooldown" and d.maneuver is False

    def test_healthy_fail_activity_maneuvers(self):
        d = _decide("healthy")
        assert d.state == "maneuvering" and d.maneuver is True

    def test_suspect_ok_recovers(self):
        assert _decide("suspect", ok=True).state == "healthy"

    def test_suspect_fail_activity_maneuvers(self):
        d = _decide("suspect")
        assert d.state == "maneuvering" and d.maneuver is True

    def test_suspect_no_activity_stays_suspect(self):
        assert _decide("suspect", activity=False).state == "suspect"

    def test_maneuvering_fail_activity_retries(self):
        d = _decide("maneuvering")
        assert d.state == "maneuvering" and d.maneuver is True

    def test_maneuvering_fail_below_threshold_goes_suspect(self):
        assert _decide("maneuvering", fails=2).state == "suspect"

    def test_cooldown_ok_exits_early(self):
        assert _decide("cooldown", ok=True, cooldown=COOLDOWN_ACTIVE).state == "healthy"

    def test_cooldown_active_stays(self):
        d = _decide("cooldown", cooldown=COOLDOWN_ACTIVE)
        assert d.state == "cooldown" and d.maneuver is False

    def test_cooldown_expired_no_activity_goes_suspect(self):
        d = _decide("cooldown", activity=False, cooldown=COOLDOWN_EXPIRED)
        assert d.state == "suspect" and d.maneuver is False

    def test_cooldown_expired_activity_maneuvers(self):
        d = _decide("cooldown", cooldown=COOLDOWN_EXPIRED)
        assert d.state == "maneuvering" and d.maneuver is True

    def test_exhausted_fail_stays(self):
        d = _decide("exhausted")
        assert d.state == "exhausted" and d.maneuver is False

    def test_exhausted_auto_exit_to_healthy(self):
        assert _decide("exhausted", ok=True).state == "healthy"

    def test_rate_limit_exhausts(self):
        d = _decide("healthy", hourly=maneuver.MAX_ATTEMPTS_PER_HOUR)
        assert d.state == "exhausted" and d.maneuver is False

    def test_pool_exhaustion_exhausts(self):
        d = _decide("healthy", candidate=None)
        assert d.state == "exhausted" and d.maneuver is False


class TestWpM0Regression:
    """WP-M0: stale handshake + простой (только keepalive) не триггерит манёвр."""

    def test_idle_stale_handshake_zero_traffic_no_maneuver(self):
        # handshake_age в триггере не участвует вовсе; клиентского трафика нет,
        # awg1.tx растёт только от keepalive.
        prev = make_sample(ok=False, fails=1, activity=False, awg1_tx=1_000, awg1_rx=900)
        cur = make_sample(ok=False, fails=2, activity=False, awg1_tx=1_064, awg1_rx=900)
        assert maneuver.compute_activity(prev, cur) is False
        d = maneuver.decide(
            "idle", cur, now=NOW, cooldown_until=0.0,
            hourly_attempts_count=0, candidate=51901,
        )
        assert d.maneuver is False and d.state == "idle"


class TestExhaustedAutoRecovery:
    def test_next_tick_with_liveness_clears_exhausted(self, env):
        st = maneuver.default_state()
        st["state"] = "exhausted"
        st["exhausted"] = True
        st["failed_ports"] = [51901, 51902]
        res = _run_tick(env, st=st, sample=make_sample(ok=True), apply=True)
        assert res["state"] == "healthy" and res["maneuver"] is False

        saved = json.loads(
            env["tmp"].joinpath("relay-maneuver.json").read_text(encoding="utf-8")
        )
        assert saved["state"] == "healthy"
        assert saved["exhausted"] is False
        assert saved["failed_ports"] == []
        assert saved["last_sample"]["consecutive_failures"] == 0


# ---------------------------------------------------------------------------
# Актуатор: успех, откат, anti-ping-pong
# ---------------------------------------------------------------------------

def _run_tick(env, *, st, sample, now=NOW, apply=True, force=False, wait=(True, 47), leg_port=51900):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(maneuver, "wait_liveness", lambda: wait)
    try:
        return maneuver.tick(
            st=st, leg=leg(leg_port), sample=sample, now=now,
            apply=apply, force=force, state_path=env["maneuver_path"],
        )
    finally:
        monkeypatch.undo()


class TestManeuverSuccess:
    def test_switches_whole_tuple_and_persists_endpoint(self, env):
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        res = _run_tick(env, st=st, sample=make_sample(ok=False, fails=3, activity=True))

        assert res["result"] == "ok" and res["acted"] is True
        set_calls = env["runner"].commands("awg", "set")
        assert len(set_calls) == 1
        call = set_calls[0]
        assert call[:3] == ["awg", "set", "awg1"]
        assert call[3:5] == ["listen-port", "0"]  # меняется весь 4-кортеж
        assert f"{EXIT_HOST}:51901" in call
        assert PEER_PUB in call

        # Горячий путь не рестартует юниты и не дёргает awg-quick.
        assert env["runner"].commands("systemctl") == []
        assert env["runner"].commands("awg-quick") == []
        joined = " ".join(" ".join(c) for c in env["runner"].calls)
        assert "vds-relay-exit" not in joined
        assert "vds-relay-policy" not in joined
        assert "down" not in joined and "up" not in joined

        # Конфиг: изменена ТОЛЬКО строка Endpoint.
        before = CONF_TEXT.splitlines()
        after = env["conf"].read_text(encoding="utf-8").splitlines()
        assert len(before) == len(after)
        diff = [(a, b) for a, b in zip(before, after) if a != b]
        assert len(diff) == 1
        assert diff[0][1] == f"Endpoint = {EXIT_HOST}:51901"
        assert f"PrivateKey = {PRIV}" in after
        assert "PersistentKeepalive = 25" in after
        assert stat.S_IMODE(env["conf"].stat().st_mode) == 0o600

        # Бэкап 0600 содержит исходный конфиг целиком.
        backup = env["conf"].with_name(env["conf"].name + ".bak-pre-maneuver")
        assert backup.is_file()
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert backup.read_text(encoding="utf-8") == CONF_TEXT

        saved = json.loads(env["tmp"].joinpath("relay-maneuver.json").read_text(encoding="utf-8"))
        assert saved["state"] == "cooldown"
        assert saved["current_port"] == 51901
        assert saved["previous_port"] == 51900
        assert saved["liveness_ms"] == 47
        assert saved["attempts"][-1]["result"] == "ok"
        assert stat.S_IMODE(
            env["tmp"].joinpath("relay-maneuver.json").stat().st_mode
        ) == 0o600

    def test_no_secret_in_state(self, env):
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        _run_tick(env, st=st, sample=make_sample())
        text = env["tmp"].joinpath("relay-maneuver.json").read_text(encoding="utf-8")
        assert "PrivateKey" not in text
        assert "PresharedKey" not in text
        assert PRIV not in text
        assert PEER_PSK not in text


class TestRollback:
    def test_timeout_rolls_back_and_leaves_conf_untouched(self, env):
        conf_before = env["conf"].read_text(encoding="utf-8")
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        res = _run_tick(
            env, st=st, sample=make_sample(ok=False, fails=3, activity=True),
            wait=(False, None),
        )

        assert res["result"] == "rollback"
        set_calls = env["runner"].commands("awg", "set")
        assert len(set_calls) == 2
        assert f"{EXIT_HOST}:51901" in set_calls[0]
        # Возврат строго на прежний порт, без правки конфига.
        assert f"{EXIT_HOST}:51900" in set_calls[1]
        assert env["conf"].read_text(encoding="utf-8") == conf_before
        assert not env["conf"].with_name(
            env["conf"].name + ".bak-pre-maneuver"
        ).exists()

        saved = json.loads(env["tmp"].joinpath("relay-maneuver.json").read_text(encoding="utf-8"))
        assert saved["state"] == "cooldown"
        assert saved["current_port"] == 51900
        assert saved["failed_ports"] == [51901]
        assert saved["attempts"][-1]["result"] == "rollback"

        # Следующий манёвр пропускает только что отказавший порт.
        st2 = saved
        res2 = _run_tick(
            env, st=st2, sample=make_sample(ok=False, fails=3, activity=True,
                                            now=NOW + 700),
            now=NOW + 700, apply=False,
        )
        assert res2["maneuver"] is True
        assert res2["target_port"] == 51902

    def test_full_pool_exhausts(self, env):
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        st["failed_ports"] = POOL[1:]  # все прочие порты уже отказали
        res = _run_tick(env, st=st, sample=make_sample(ok=False, fails=3, activity=True))
        # decide не даёт манёвр: кандидатов нет → exhausted.
        assert res["maneuver"] is False
        assert res["state"] == "exhausted"


class TestAntiPingPong:
    def test_second_attempt_within_cooldown_rejected(self, env):
        st = maneuver.default_state()
        st["state"] = "cooldown"
        st["cooldown_until"] = maneuver._now_iso(NOW + 600)
        st["current_port"] = 51900
        res = _run_tick(env, st=st, sample=make_sample(ok=False, fails=3, activity=True), apply=False)
        assert res["maneuver"] is False and res["state"] == "cooldown"

    def test_force_bypasses_cooldown_only(self, env):
        st = maneuver.default_state()
        st["state"] = "cooldown"
        st["cooldown_until"] = maneuver._now_iso(NOW + 600)
        res = _run_tick(
            env, st=st, sample=make_sample(ok=False, fails=3, activity=True),
            apply=False, force=True,
        )
        assert res["maneuver"] is True

    def test_four_attempts_per_hour_exhausts(self, env):
        st = maneuver.default_state()
        st["state"] = "healthy"
        st["attempts"] = [
            {"ts": maneuver._now_iso(NOW - 60 * i), "from": 51900, "to": 51900 + i,
             "result": "rollback", "liveness_ms": None}
            for i in range(1, 4)
        ]
        res = _run_tick(env, st=st, sample=make_sample(ok=False, fails=3, activity=True), apply=False)
        assert res["maneuver"] is False and res["state"] == "exhausted"


# ---------------------------------------------------------------------------
# Guard роли узла и пула
# ---------------------------------------------------------------------------

class TestGuards:
    def test_exit_node_refused(self, env):
        gw = env["tmp"] / "exit-state.json"
        gw.write_text(
            json.dumps({"version": 1, "protocols": {"relay_leg": {"installed": True}}}),
            encoding="utf-8",
        )
        assert maneuver.relay_node_violation(maneuver.load_state(str(gw))) is not None
        before = list(env["runner"].calls)
        assert maneuver.run_step(
            apply=False, state_path=str(gw), maneuver_path=env["maneuver_path"]
        ) == 1
        assert env["runner"].calls == before  # ни одного awg-вызова

    def test_missing_awg1_conf_refused(self, env, monkeypatch):
        monkeypatch.setattr(maneuver, "RELAY_EXIT_CONFIG_PATH", env["tmp"] / "nope.conf")
        state = GatewayState(version=1, protocols={"relay": {"installed": True}})
        assert maneuver.relay_node_violation(state) is not None

    def test_relay_node_allowed(self, env):
        state = GatewayState(version=1, protocols={"relay": {"installed": True}})
        assert maneuver.relay_node_violation(state) is None

    def test_port_outside_pool_refused(self):
        with pytest.raises(maneuver.ManeuverError):
            maneuver.guard_leg_port(51825, POOL)
        with pytest.raises(maneuver.ManeuverError):
            maneuver.guard_leg_port(None, POOL)
        maneuver.guard_leg_port(51900, POOL)  # ок

    def test_step_refuses_old_port(self, env, monkeypatch):
        monkeypatch.setattr(maneuver, "run_list", FakeRunner(port=51825))
        assert maneuver.run_step(
            apply=False, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 1


# ---------------------------------------------------------------------------
# CLI: dry-run, root, отсутствие секретов в выводе
# ---------------------------------------------------------------------------

class TestCli:
    def test_dry_run_mutates_nothing(self, env, monkeypatch):
        monkeypatch.setattr(maneuver, "probe_liveness", lambda: (False, None))
        assert maneuver.run_step(
            apply=False, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        assert env["runner"].commands("awg", "set") == []
        assert not env["tmp"].joinpath("relay-maneuver.json").exists()
        assert env["conf"].read_text(encoding="utf-8") == CONF_TEXT

    def test_apply_requires_root(self, env, monkeypatch):
        monkeypatch.setattr(maneuver.os, "geteuid", lambda: 1000)
        assert maneuver.run_step(
            apply=True, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 1
        assert env["runner"].commands("awg", "set") == []

    def test_status_json_has_no_secrets(self, env, capsys):
        maneuver.save_maneuver_state(
            {
                **maneuver.default_state(),
                "state": "cooldown",
                "attempts": [{"ts": "2026-11-20T10:00:00+00:00", "from": 51900,
                              "to": 51901, "result": "ok", "liveness_ms": 47}],
            },
            env["maneuver_path"],
        )
        assert maneuver.run_status(json_output=True, maneuver_path=env["maneuver_path"]) == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["state"] == "cooldown"
        for secret in ("PrivateKey", "PresharedKey", PRIV, PEER_PSK):
            assert secret not in out

    def test_history_has_no_secrets(self, env, capsys):
        maneuver.save_maneuver_state(
            {
                **maneuver.default_state(),
                "attempts": [{"ts": "2026-11-20T10:00:00+00:00", "from": 51900,
                              "to": 51901, "result": "rollback", "liveness_ms": None}],
            },
            env["maneuver_path"],
        )
        assert maneuver.run_history(limit=5, maneuver_path=env["maneuver_path"]) == 0
        out = capsys.readouterr().out
        assert "51900→51901" in out
        for secret in ("PrivateKey", "PresharedKey", PRIV, PEER_PSK):
            assert secret not in out

    def test_tick_journal_tag_has_to_on_success(self, env, monkeypatch, capsys):
        """P2 (M5): при acted=1 тег дополняется to=<target_port>."""
        monkeypatch.setattr(maneuver, "probe_liveness", lambda: (False, None))
        monkeypatch.setattr(maneuver, "wait_liveness", lambda: (True, 47))
        # transfer-счётчики «выросли» относительно засеянного baseline (activity=1)
        monkeypatch.setattr(maneuver, "_transfer_sums", lambda iface: (60_000, 80_000))
        st = maneuver.default_state()
        # свежий state: первый тик — baseline (fails=1). Чтобы за один тик дойти
        # до манёвра, seed'им baseline с fails=2 и низкими счётчиками.
        st["last_sample"] = {
            **make_sample(ok=False, fails=2, activity=True,
                          awg0_rx=10, awg0_tx=10, awg1_rx=0, awg1_tx=10),
        }
        st["state"] = "suspect"
        maneuver.save_maneuver_state(st, env["maneuver_path"])
        assert maneuver.run_tick(
            apply=True, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        out = capsys.readouterr().out
        assert "acted=1 result=ok to=51901" in out

    def test_tick_journal_tag_no_to_without_maneuver(self, env, monkeypatch, capsys):
        monkeypatch.setattr(maneuver, "probe_liveness", lambda: (True, 31))
        st = maneuver.default_state()
        maneuver.save_maneuver_state(st, env["maneuver_path"])
        assert maneuver.run_tick(
            apply=True, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        out = capsys.readouterr().out
        assert "acted=0 result=none" in out and "to=" not in out


    def test_rollback_is_idempotent_when_previous_equals_current(self, env, capsys):
        st = maneuver.default_state()  # previous == current == 51900
        maneuver.save_maneuver_state(st, env["maneuver_path"])
        assert maneuver.run_rollback(
            apply=False, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        assert "откатывать нечего" in capsys.readouterr().out
        assert env["runner"].commands("awg", "set") == []


# ---------------------------------------------------------------------------
# Конфиг: точечная правка Endpoint
# ---------------------------------------------------------------------------

class TestConfEndpoint:
    def test_only_endpoint_line_changes(self):
        updated = maneuver.update_conf_endpoint(CONF_TEXT, EXIT_HOST, 51907)
        before = CONF_TEXT.splitlines()
        after = updated.splitlines()
        assert len(before) == len(after)
        changed = [(a, b) for a, b in zip(before, after) if a != b]
        assert changed == [(f"Endpoint = {EXIT_HOST}:51900", f"Endpoint = {EXIT_HOST}:51907")]

    def test_missing_endpoint_raises(self):
        with pytest.raises(maneuver.ManeuverError):
            maneuver.update_conf_endpoint("[Interface]\nPrivateKey = x\n", EXIT_HOST, 51901)

    def test_idempotent_persist_when_unchanged(self, env):
        assert maneuver.persist_endpoint(env["conf"], EXIT_HOST, 51900) is False
        assert not env["conf"].with_name(env["conf"].name + ".bak-pre-maneuver").exists()


# ---------------------------------------------------------------------------
# P1: счётчик consecutive_failures после успеха
# ---------------------------------------------------------------------------

def _saved(env) -> dict:
    return json.loads(
        env["tmp"].joinpath("relay-maneuver.json").read_text(encoding="utf-8")
    )


class TestFailureCounterAfterSuccess:
    def test_successful_maneuver_resets_counter(self, env):
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        st["last_sample"] = {"consecutive_failures": 3}
        res = _run_tick(env, st=st, sample=make_sample(ok=False, fails=3, activity=True))
        assert res["result"] == "ok"
        saved = _saved(env)
        assert saved["last_sample"]["consecutive_failures"] == 0

        # Один потерянный ping после cooldown — только suspect (1/3), манёвра нет.
        nxt = maneuver.collect_sample(
            saved["last_sample"], now=NOW + 700, probe=lambda: (False, None)
        )
        assert nxt["consecutive_failures"] == 1
        res2 = _run_tick(env, st=saved, sample=nxt, now=NOW + 700)
        assert res2["state"] == "suspect" and res2["maneuver"] is False
        assert res2["acted"] is False

    def test_successful_rollback_resets_counter_and_exhausted(self, env):
        monkeypatch = pytest.MonkeyPatch()
        try:
            monkeypatch.setattr(maneuver, "run_list", FakeRunner(port=51902))
            monkeypatch.setattr(maneuver, "wait_liveness", lambda: (True, 47))
            maneuver.save_maneuver_state(
                {
                    **maneuver.default_state(),
                    "state": "exhausted",
                    "exhausted": True,
                    "previous_port": 51900,
                    "current_port": 51902,
                    "last_sample": {"consecutive_failures": 5},
                },
                env["maneuver_path"],
            )
            assert maneuver.run_rollback(
                apply=True, state_path=env["state_path"],
                maneuver_path=env["maneuver_path"],
            ) == 0
        finally:
            monkeypatch.undo()
        saved = _saved(env)
        assert saved["last_sample"]["consecutive_failures"] == 0
        assert saved["exhausted"] is False
        assert saved["state"] == "cooldown"


# ---------------------------------------------------------------------------
# P1: лимит «3/час» согласован с decide() (>=, не >)
# ---------------------------------------------------------------------------

class TestHourlyLimitConsistency:
    def test_third_rollback_within_hour_sets_exhausted(self, env):
        st = maneuver.default_state()
        st["state"] = "maneuvering"
        st["attempts"] = [
            {"ts": maneuver._now_iso(NOW - 60 * i), "from": 51900, "to": 51900 + i,
             "result": "rollback", "liveness_ms": None}
            for i in (1, 2)
        ]
        assert maneuver.hourly_attempts(st, NOW) == 2
        res = _run_tick(
            env, st=st, sample=make_sample(ok=False, fails=3, activity=True),
            wait=(False, None),
        )
        assert res["result"] == "rollback"
        assert res["exhausted"] is True
        saved = _saved(env)
        assert saved["state"] == "exhausted"
        assert saved["exhausted"] is True
        assert maneuver.hourly_attempts(saved, NOW) == 3


# ---------------------------------------------------------------------------
# P1: failed_ports/liveness_ms на здоровом канале
# ---------------------------------------------------------------------------

class TestHealthyRefreshesPortState:
    def test_expired_cooldown_clears_failed_ports(self, env):
        st = maneuver.default_state()
        st["state"] = "cooldown"
        st["cooldown_until"] = maneuver._now_iso(NOW - 1)
        st["failed_ports"] = [51901, 51902]
        st["liveness_ms"] = None
        res = _run_tick(env, st=st, sample=make_sample(ok=True))
        assert res["state"] == "healthy" and res["maneuver"] is False
        saved = _saved(env)
        assert saved["failed_ports"] == []
        assert saved["liveness_ms"] == 47

    def test_active_cooldown_keeps_failed_ports(self, env):
        st = maneuver.default_state()
        st["state"] = "cooldown"
        st["cooldown_until"] = maneuver._now_iso(NOW + 600)
        st["failed_ports"] = [51901]
        st["liveness_ms"] = None
        res = _run_tick(env, st=st, sample=make_sample(ok=True), now=NOW + 60)
        assert res["state"] == "healthy"
        saved = _saved(env)
        assert saved["failed_ports"] == [51901]
        assert saved["liveness_ms"] == 47


# ---------------------------------------------------------------------------
# P1: FileLock берётся ДО чтения state/ноги (TOCTOU)
# ---------------------------------------------------------------------------

class TestLockOrdering:
    @staticmethod
    def _journal(monkeypatch) -> list[str]:
        journal: list[str] = []
        real_load = maneuver.load_maneuver_state
        real_read = maneuver.read_leg

        class JournalLock:
            def __init__(self, path: str):
                self.path = path

            def __enter__(self):
                journal.append("lock_enter")
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                journal.append("lock_exit")
                return False

        def load_spy(path=None):
            journal.append("load")
            return real_load(path)

        def read_spy(iface=maneuver.RELAY_EXIT_IFACE):
            journal.append("read_leg")
            return real_read(iface)

        monkeypatch.setattr(maneuver, "FileLock", JournalLock)
        monkeypatch.setattr(maneuver, "load_maneuver_state", load_spy)
        monkeypatch.setattr(maneuver, "read_leg", read_spy)
        monkeypatch.setattr(maneuver, "wait_liveness", lambda: (True, 47))
        return journal

    def test_run_step_locks_before_reads(self, env, monkeypatch):
        journal = self._journal(monkeypatch)
        assert maneuver.run_step(
            apply=True, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        assert journal[0] == "lock_enter"
        assert journal.count("load") == 1 and journal.count("read_leg") == 1
        assert journal.index("load") > journal.index("lock_enter")
        assert journal.index("read_leg") > journal.index("lock_enter")

    def test_run_rollback_locks_before_reads(self, env, monkeypatch):
        monkeypatch.setattr(maneuver, "run_list", FakeRunner(port=51902))
        maneuver.save_maneuver_state(
            {**maneuver.default_state(), "previous_port": 51900, "current_port": 51902},
            env["maneuver_path"],
        )
        journal = self._journal(monkeypatch)
        assert maneuver.run_rollback(
            apply=True, state_path=env["state_path"], maneuver_path=env["maneuver_path"]
        ) == 0
        assert journal[0] == "lock_enter"
        assert journal.count("load") == 1 and journal.count("read_leg") == 1
        assert journal.index("load") > journal.index("lock_enter")
        assert journal.index("read_leg") > journal.index("lock_enter")
