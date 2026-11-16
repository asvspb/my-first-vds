"""HF-1 (SPEC-20261116-surface-hardening §1): verified_session_ips + кэш.

T1–T6, T12 без root/сети: ss/nf_conntrack за моками и фикстурными строками
(RFC 5737 203.0.113.x/198.51.100.x), fail-closed парсеры, аффинность кэша
24 ч, ужесточение fail-fast cmd_config, стык с vpn guard (record=False не
мутирует снапшот).
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import src.gateway.probing as probing
from src.core.shell import ShellResult

# Фикстуры: только RFC 5737 (AGENTS §6).
SRV_IP = "198.51.100.1"
RU_NET = "203.0.113.0/24\n"


def _shell_result(stdout: str = "", stderr: str = "", code: int = 0) -> ShellResult:
    return ShellResult(stdout=stdout, stderr=stderr, returncode=code)


class FakeRun:
    """run_list-заменитель: ответы по префиксу + журнал вызовов."""

    def __init__(self, answers: dict[str, ShellResult] | None = None):
        self.answers = answers or {}
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> ShellResult:
        self.calls.append(args)
        key = " ".join(args)
        for prefix, res in self.answers.items():
            if key.startswith(prefix):
                return res
        return _shell_result()


def _nft_state(probers: dict[str, int]) -> probing.NftState:
    return probing.NftState(
        syn_bare=20, syn_valid=10, udp_443=0,
        per_element_counters=True, probers=probers,
    )


def _patch_common(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    nft: probing.NftState | None,
) -> None:
    monkeypatch.setattr(probing, "LOCK_FILE", str(tmp_path / "probe.lock"))
    monkeypatch.setattr(probing, "RU_CIDR_FILE", tmp_path / "ru-cidrs.txt")
    monkeypatch.setattr(probing, "OWN_IPS_FILE", tmp_path / "allow-ips.txt")
    monkeypatch.setattr(probing, "NF_CONNTRACK_PROC", tmp_path / "nf_conntrack")
    monkeypatch.setattr(
        probing, "_load_lockdown",
        lambda state_path=None: {"active": False, "since": "", "ttl_until": "",
                                 "allow_from": []},
    )
    monkeypatch.setattr(probing, "_server_public_ip", lambda: SRV_IP)
    monkeypatch.setattr(probing, "read_awg_endpoints", lambda run=None, iface="awg0": [])
    if nft is not None:
        monkeypatch.setattr(probing, "list_nft_table", lambda run=None: nft)


# ---------------------------------------------------------------------------
# T1: пороги ss — двусторонний трафик верифицирует, односторонний нет
# ---------------------------------------------------------------------------

SS_VERIFIED = (
    "ESTAB 0 0 198.51.100.1:443 203.0.113.5:54321\n"
    "\t cubic wscale:7,7 rto:364 rtt:10/2 ato:11 mss:1448 cwnd:10 "
    "bytes_acked:20000 bytes_received:8000 segs_out:15 segs_in:12\n"
)
SS_ONE_WAY = (
    "ESTAB 0 0 198.51.100.1:443 203.0.113.6:54322\n"
    "\t cubic wscale:7,7 rto:364 bytes_acked:20000 bytes_received:100\n"
)
SS_NO_TRAFFIC = (
    "ESTAB 0 0 198.51.100.1:443 203.0.113.7:54323\n"
    "\t cubic wscale:7,7 rto:364 bytes_acked:120 bytes_received:80\n"
)


class TestSsThresholds:
    def test_t1_both_thresholds_verified(self) -> None:
        out = probing.parse_ss_verified(SS_VERIFIED + SS_ONE_WAY + SS_NO_TRAFFIC)
        assert out == {"203.0.113.5"}

    def test_t1_exact_boundaries_included(self) -> None:
        text = (
            "ESTAB 0 0 198.51.100.1:8443 203.0.113.8:1\n"
            "\t cubic bytes_acked:16384 bytes_received:4096\n"
        )
        assert probing.parse_ss_verified(text) == {"203.0.113.8"}

    def test_t1_all_server_ports_and_client_side_excluded(self) -> None:
        text = (
            # серверные sport 8443 и 2053 — считаются
            "ESTAB 0 0 198.51.100.1:8443 203.0.113.9:2\n"
            "\t cubic bytes_acked:99999 bytes_received:99999\n"
            "ESTAB 0 0 198.51.100.1:2053 203.0.113.10:3\n"
            "\t cubic bytes_acked:99999 bytes_received:99999\n"
            # исходящая сессия сервера (sport=54321, dport=443 чужого) — нет
            "ESTAB 0 0 198.51.100.1:54321 192.0.2.1:443\n"
            "\t cubic bytes_acked:99999 bytes_received:99999\n"
        )
        assert probing.parse_ss_verified(text) == {"203.0.113.9", "203.0.113.10"}

    def test_ss_failure_degrades_to_empty(self) -> None:
        run = FakeRun({"ss": _shell_result("", "ss: error", 1)})
        assert probing.read_verified_session_ips(run=run) == set()


# ---------------------------------------------------------------------------
# T2: кривой ss (без bytes-полей) — fail-closed, без исключения
# ---------------------------------------------------------------------------

class TestSsFailClosed:
    def test_t2_no_metrics_line_at_all(self) -> None:
        text = (
            "ESTAB 0 0 198.51.100.1:443 203.0.113.11:9\n"
            "ESTAB 0 0 198.51.100.1:443 203.0.113.12:10\n"
        )
        assert probing.parse_ss_verified(text) == set()

    def test_t2_metrics_without_bytes_fields(self) -> None:
        text = (
            "ESTAB 0 0 198.51.100.1:443 203.0.113.13:11\n"
            "\t cubic wscale:7,7 rto:364 rtt:1/1 mss:1448\n"
        )
        assert probing.parse_ss_verified(text) == set()

    def test_t2_only_one_bytes_field(self) -> None:
        text = (
            "ESTAB 0 0 198.51.100.1:443 203.0.113.14:12\n"
            "\t cubic bytes_acked:50000\n"
        )
        assert probing.parse_ss_verified(text) == set()

    def test_t2_garbage_lines_do_not_raise(self) -> None:
        assert probing.parse_ss_verified("total 0\n\nrandom junk\n\t orphan metrics\n") == set()


# ---------------------------------------------------------------------------
# T12: dual-stack ::ffff: + conntrack-пороги
# ---------------------------------------------------------------------------

class TestDualStackAndConntrack:
    def test_t12_ipv4_mapped_prefix_stripped(self) -> None:
        text = (
            "ESTAB 0 0 [198.51.100.1]:443 [::ffff:203.0.113.5]:54321\n"
            "\t cubic bytes_acked:20000 bytes_received:8000\n"
        )
        assert probing.parse_ss_verified(text) == {"203.0.113.5"}  # IPv4-ключ probers4

    def test_t12_bare_ipv6_peer_ignored(self) -> None:
        text = (
            "ESTAB 0 0 [198.51.100.1]:443 [2001:db8::1]:54321\n"
            "\t cubic bytes_acked:20000 bytes_received:8000\n"
        )
        assert probing.parse_ss_verified(text) == set()  # v6 — non-goal v1

    def test_t12_conntrack_bytes_over_threshold(self) -> None:
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.7 dst=198.51.100.1 sport=52000 "
            "dport=443 src=198.51.100.1 dst=203.0.113.7 sport=443 dport=52000 "
            "[ASSURED] mark=0 use=2 bytes_orig=20000 bytes_reply=40000"
        )
        assert probing.parse_conntrack_udp(line) == {"203.0.113.7"}

    def test_t12_conntrack_bytes_below_threshold(self) -> None:
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.8 dst=198.51.100.1 sport=52001 "
            "dport=443 src=198.51.100.1 dst=203.0.113.8 sport=443 dport=52001 "
            "[ASSURED] mark=0 use=2 bytes_orig=10000 bytes_reply=10000"
        )
        assert probing.parse_conntrack_udp(line) == set()  # 20000 <= 32768

    def test_t12_conntrack_no_bytes_fallback_assured(self) -> None:
        # nf_conntrack_acct=0: полей bytes= нет — фолбэк на [ASSURED]
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.9 dst=198.51.100.1 sport=52002 "
            "dport=443 src=198.51.100.1 dst=203.0.113.9 sport=443 dport=52002 "
            "[ASSURED] mark=0 use=2"
        )
        assert probing.parse_conntrack_udp(line) == {"203.0.113.9"}

    def test_t12_conntrack_bytes_without_assured_rejected(self) -> None:
        line = (
            "ipv4 2 udp 17 30 src=203.0.113.10 dst=198.51.100.1 sport=52003 "
            "dport=51826 src=198.51.100.1 dst=203.0.113.10 sport=51826 "
            "dport=52003 mark=0 use=2 bytes_orig=99999 bytes_reply=99999"
        )
        assert probing.parse_conntrack_udp(line) == set()

    def test_t12_conntrack_wrong_dport_ignored(self) -> None:
        line = (
            "ipv4 2 udp 17 30 src=203.0.113.11 dst=198.51.100.1 sport=52004 "
            "dport=53 src=198.51.100.1 dst=203.0.113.11 sport=53 dport=52004 "
            "[ASSURED] mark=0 use=2"
        )
        assert probing.parse_conntrack_udp(line) == set()

    def test_t12_conntrack_real_kernel_two_bytes_fields(self) -> None:
        # Реальный формат /proc/net/nf_conntrack (ядро Linux): ДВА кортежа
        # (original + reply) с одинаковым полем bytes= без суффиксов —
        # регресс-фикс ревью HF-1 (старые регулярки ждали bytes_orig=/bytes_reply=
        # и молча проваливались в [ASSURED]-фолбэк, теряя порог 32768).
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.20 dst=198.51.100.1 sport=52010 "
            "dport=443 src=198.51.100.1 dst=203.0.113.20 sport=443 dport=52010 "
            "[ASSURED] mark=0 use=2 bytes=20000 bytes=40000"
        )
        assert probing.parse_conntrack_udp(line) == {"203.0.113.20"}

    def test_t12_conntrack_real_kernel_bytes_below_threshold(self) -> None:
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.21 dst=198.51.100.1 sport=52011 "
            "dport=443 src=198.51.100.1 dst=203.0.113.21 sport=443 dport=52011 "
            "[ASSURED] mark=0 use=2 bytes=10000 bytes=10000"
        )
        assert probing.parse_conntrack_udp(line) == set()  # 20000 <= 32768

    def test_t12_conntrack_real_kernel_single_bytes_field_fail_closed(self) -> None:
        # Один bytes= (кривая строка) — fail-closed, не фолбэк на [ASSURED].
        line = (
            "ipv4 2 udp 17 180 src=203.0.113.22 dst=198.51.100.1 sport=52012 "
            "dport=443 src=198.51.100.1 dst=203.0.113.22 sport=443 dport=52012 "
            "[ASSURED] mark=0 use=2 bytes=99999"
        )
        assert probing.parse_conntrack_udp(line) == set()

    def test_conntrack_file_absent_quiet_degradation(self, tmp_path: Path) -> None:
        ips, available = probing.read_conntrack_verified(tmp_path / "absent")
        assert ips == set() and available is False

    def test_conntrack_file_present(self, tmp_path: Path) -> None:
        ct = tmp_path / "nf_conntrack"
        ct.write_text(
            "ipv4 2 udp 17 180 src=203.0.113.9 dst=198.51.100.1 sport=1 "
            "dport=443 src=198.51.100.1 dst=203.0.113.9 sport=443 dport=1 "
            "[ASSURED] mark=0 use=2\n",
            encoding="utf-8",
        )
        ips, available = probing.read_conntrack_verified(ct)
        assert ips == {"203.0.113.9"} and available is True


# ---------------------------------------------------------------------------
# T3: аффинность кэша — TTL 24 ч, last_seen обновляется
# ---------------------------------------------------------------------------

T0 = probing.datetime(2026, 11, 16, 12, 0, 0)


class TestOwnIpsCacheAffinity:
    def _entries(self, ip: str, hours_ago: float) -> list[list[str]]:
        ts = T0 - probing.timedelta(hours=hours_ago)
        return [[ip, ts.isoformat(timespec="seconds")]]

    def test_t3_recent_entry_stays_active(self) -> None:
        entries = self._entries("203.0.113.5", hours_ago=1)
        assert probing.active_cache_ips(entries, T0) == {"203.0.113.5"}
        # сокета нет (verified пуст), но < 24 ч — в кэше остаётся
        assert probing.merge_own_ips_cache(entries, set(), T0) == entries

    def test_t3_entry_expired_after_24h(self) -> None:
        entries = self._entries("203.0.113.5", hours_ago=25)
        assert probing.active_cache_ips(entries, T0) == set()
        assert probing.merge_own_ips_cache(entries, set(), T0) == []

    def test_t3_last_seen_refreshed_for_verified(self) -> None:
        entries = self._entries("203.0.113.5", hours_ago=3)
        merged = probing.merge_own_ips_cache(entries, {"203.0.113.5"}, T0)
        assert merged == [["203.0.113.5", T0.isoformat(timespec="seconds")]]

    def test_broken_timestamp_dropped(self) -> None:
        assert probing.active_cache_ips([["203.0.113.5", "not-a-ts"]], T0) == set()
        assert probing.merge_own_ips_cache([["203.0.113.5", "not-a-ts"]], set(), T0) == []

    def test_malformed_cache_entries_filtered_on_load(self) -> None:
        raw = [["203.0.113.5", "2026-11-16T10:00:00"], ["bad"], ["a", "b", "c"], "junk"]
        assert probing.own_ips_cache_entries({"own_ips_cache": raw}) == [
            ["203.0.113.5", "2026-11-16T10:00:00"]
        ]

    def test_t3_watch_record_cache_lifecycle(self, tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        """Интеграция: окно N верифицирует IP → кэш; N+1 без сокета < 24 ч —
        остаётся; N+2 (> 24 ч) — удалён."""
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        snap_path = tmp_path / "snap.json"
        ss_ok = FakeRun({"ss": _shell_result(SS_VERIFIED)})
        ss_empty = FakeRun()

        # окно N: сессия живая, ss верифицирует 203.0.113.5
        assert probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=ss_ok, now=T0,
        ) == 0
        cache = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert cache == [["203.0.113.5", T0.isoformat(timespec="seconds")]]

        # окно N+1 (через час): сокета нет — IP всё ещё в кэше/own_ips
        t1 = T0 + probing.timedelta(hours=1)
        assert probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=ss_empty, now=t1,
        ) == 0
        cache = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert cache == [["203.0.113.5", T0.isoformat(timespec="seconds")]]

        # окно N+2 (через 25 ч): TTL истёк, чистка при record-тике
        t2 = T0 + probing.timedelta(hours=25)
        assert probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=ss_empty, now=t2,
        ) == 0
        assert probing.load_snapshot(snap_path)["own_ips_cache"] == []


# ---------------------------------------------------------------------------
# T4: fail-fast ужесточён — 51825 в state больше не основание
# ---------------------------------------------------------------------------

class TestConfigFailfastHardened:
    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
               allow_file: str | None) -> Path:
        from src.gateway.store import GatewayState

        _patch_common(tmp_path, monkeypatch, None)
        snap_path = tmp_path / "snap.json"
        if allow_file is not None:
            monkeypatch.setattr(
                probing, "OWN_IPS_FILE", tmp_path / "allow-ips.txt"
            )
            (tmp_path / "allow-ips.txt").write_text(allow_file, encoding="utf-8")
        state_path = str(tmp_path / "state.json")
        st = GatewayState()
        st.protocols = {"amneziawg": {"installed": True, "port": 51825}}
        from src.gateway.store import save_state

        save_state(st, state_path)
        return snap_path

    def test_t4_rejected_even_with_51825_in_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        snap_path = self._setup(tmp_path, monkeypatch, allow_file=None)
        rc = probing.cmd_config(
            auto_lockdown="on", apply=True, snapshot_path=snap_path,
            state_path=str(tmp_path / "state.json"),
        )
        assert rc == 1
        out = capsys.readouterr().out
        assert "отклонён" in out and "allow-ips.txt" in out
        assert probing.load_snapshot(snap_path).get("config") == {}

    def test_filled_allow_ips_file_is_enough_without_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap_path = self._setup(tmp_path, monkeypatch, allow_file="# свои\n203.0.113.5\n")
        rc = probing.cmd_config(
            auto_lockdown="on", apply=True, snapshot_path=snap_path,
            state_path=str(tmp_path / "state.json"),
        )
        assert rc == 0
        cfg = probing.load_snapshot(snap_path)["config"]
        assert cfg["auto_lockdown"] is True and cfg["lockdown_allow"] == []

    def test_explicit_lockdown_allow_still_works(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap_path = self._setup(tmp_path, monkeypatch, allow_file=None)
        rc = probing.cmd_config(
            auto_lockdown="on", lockdown_allow="203.0.113.5", apply=True,
            snapshot_path=snap_path, state_path=str(tmp_path / "state.json"),
        )
        assert rc == 0


# ---------------------------------------------------------------------------
# T5: верифицированный RU-IP не даёт RU-PROBE-SUSPECT
# ---------------------------------------------------------------------------

class TestVerifiedNotSuspect:
    def test_t5_two_new_ru_one_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _patch_common(tmp_path, monkeypatch, _nft_state(
            {"203.0.113.200": 5, "203.0.113.201": 3}
        ))
        (tmp_path / "ru-cidrs.txt").write_text(RU_NET, encoding="utf-8")
        # ss верифицирует 203.0.113.200 (ноут владельца без AWG-туннеля)
        ss_ok = (
            "ESTAB 0 0 198.51.100.1:443 203.0.113.200:54321\n"
            "\t cubic bytes_acked:20000 bytes_received:8000\n"
        )
        run = FakeRun({"ss": _shell_result(ss_ok)})
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=tmp_path / "snap.json", run=run, now=T0,
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert data["verdict"] == "quiet"  # один незнакомый RU-IP < порога 2
        assert data["new_ru_ips"] == ["203.0.113.201"]
        assert any("tcp/ss: 1 IP" in s for s in data["own_ips_sources"])

    def test_t5_without_verified_still_suspects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _patch_common(tmp_path, monkeypatch, _nft_state(
            {"203.0.113.200": 5, "203.0.113.201": 3}
        ))
        (tmp_path / "ru-cidrs.txt").write_text(RU_NET, encoding="utf-8")
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=tmp_path / "snap.json",
            run=FakeRun(), now=T0,
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert data["verdict"] == "RU-PROBE-SUSPECT"


# ---------------------------------------------------------------------------
# T6: watch без --record не мутирует снапшот (стык с vpn guard, AC-16)
# ---------------------------------------------------------------------------

class TestWatchNoRecordDoesNotMutate:
    def _seed_snapshot(self, tmp_path: Path) -> Path:
        snap_path = tmp_path / "snap.json"
        assert probing.save_snapshot(
            probing.NftState(syn_bare=0, syn_valid=0, per_element_counters=True),
            snap_path,
            extra={
                "threat": {"level": "quiet"},
                "config": {"auto_lockdown": False},
                "own_ips": {"ips": [], "ts": "2026-11-16T00:00:00"},
                "own_ips_cache": [["203.0.113.50", "2026-11-16T00:00:00"]],
            },
        )
        return snap_path

    def test_t6_no_record_file_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        snap_path = self._seed_snapshot(tmp_path)
        # AC-16: проверяем оба файла, которые sync/guard не вправе мутировать.
        from src.gateway.store import GatewayState, save_state

        state_path = tmp_path / "state.json"
        state = GatewayState()
        state.protocols = {"xray": {"installed": True, "port": 443}}
        save_state(state, str(state_path))

        def fingerprint(path: Path) -> tuple[int, str]:
            stat = path.stat()
            return stat.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()

        snapshot_before = fingerprint(snap_path)
        state_before = fingerprint(state_path)
        before = snap_path.read_bytes()
        run = FakeRun({"ss": _shell_result(SS_VERIFIED)})  # свежий verified есть
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=snap_path, state_path=str(state_path),
            run=run, now=T0,
        )
        assert rc == 0
        assert fingerprint(snap_path) == snapshot_before
        assert fingerprint(state_path) == state_before
        assert snap_path.read_bytes() == before  # файл не тронут (AC-16/M1)
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        # ...но в памяти отчёта verified учтён (источник виден в тегах)
        assert any("tcp/ss: 1 IP" in s for s in data["own_ips_sources"])

    def test_t6_record_mutates_own_ips_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        snap_path = self._seed_snapshot(tmp_path)
        before = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert before == [["203.0.113.50", "2026-11-16T00:00:00"]]
        run = FakeRun({"ss": _shell_result(SS_VERIFIED)})
        rc = probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=run, now=T0,
        )
        assert rc == 0
        after = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert ["203.0.113.5", T0.isoformat(timespec="seconds")] in after
        # .50 (сокета нет, < 24 ч) остался со своей старой меткой: last_seen
        # обновляется только пока сессия верифицируется
        assert ["203.0.113.50", "2026-11-16T00:00:00"] in after
