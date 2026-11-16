"""W1-1 (SPEC-20261116-probe-coverage): probers4 на {443, 8443, 2053} +
extra-счётчики + быстрый контур детекта.

W1 — рендер nft (port-set в probers4-правиле, extra-счётчики, строки 443
байт-в-байт прежние); W2 — JSON-контракт watch --json (старый набор ключей ⊂
новый, новые — аддитивно); W3 — probers 8443/2053 → new_ru_ips →
RU-PROBE-SUSPECT, verified-клиент 8443 не попадает (HF-1); W4 —
fast_contour_check (порог, тишина, скип без таблицы, снапшот не мутируется);
W5 — PROBE-BURST не зависит от extra; cmd_watch record=True вливает
fast-кэш в snapshot own_ips_cache, record=False — нет.

Без root/сети: shell за моками, IP — только RFC 5737 (203.0.113/198.51.100).
"""

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

import src.gateway.probing as probing
from src.core.shell import ShellResult

SRV_IP = "198.51.100.1"
RU_NET = "203.0.113.0/24\n"
T0 = probing.datetime(2026, 11, 16, 12, 0, 0)

OLD_JSON_KEYS = (
    "now", "window", "verdict", "reasons", "threshold",
    "syn_bare", "syn_valid", "udp_443", "bare_no_payload",
    "ratio_no_payload", "unique_probers", "per_element_counters",
    "geo_source", "top", "new_ru_ips", "ru_top", "journal",
    "threat_level", "threat_reason", "ru_syn_new", "own_ips_sources",
    "lockdown",
)


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
    monkeypatch.setattr(probing, "FAST_CACHE_PATH", tmp_path / "probe-fast-cache.json")
    monkeypatch.setattr(probing, "FAST_LOCK_FILE", str(tmp_path / "probe-fast.lock"))
    monkeypatch.setattr(
        probing, "_load_lockdown",
        lambda state_path=None: {"active": False, "since": "", "ttl_until": "",
                                 "allow_from": []},
    )
    monkeypatch.setattr(probing, "_server_public_ip", lambda: SRV_IP)
    monkeypatch.setattr(probing, "read_awg_endpoints", lambda run=None, iface="awg0": [])
    if nft is not None:
        monkeypatch.setattr(probing, "list_nft_table", lambda run=None: nft)


def _nft_list_text(probers: dict[str, int], per_element: bool = True) -> str:
    """Вывод `nft list table inet vds_probe` с optional extra-счётчиками."""
    if per_element:
        elems = ", ".join(
            f"{ip} counter packets {pk} bytes {pk * 60}" for ip, pk in probers.items()
        )
    else:
        elems = ", ".join(probers)
    counter_decl = "\t\tcounter\n" if per_element else ""
    return (
        "table inet vds_probe {\n"
        "\tcounter syn_bare {\n\t\tpackets 20 bytes 1200\n\t}\n"
        "\tcounter syn_valid {\n\t\tpackets 10 bytes 600\n\t}\n"
        "\tcounter udp_443 {\n\t\tpackets 0 bytes 0\n\t}\n"
        "\tcounter syn_valid_extra {\n\t\tpackets 33 bytes 1980\n\t}\n"
        "\tcounter syn_bare_extra {\n\t\tpackets 44 bytes 2640\n\t}\n"
        "\tset probers4 {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags dynamic, timeout\n"
        "\t\ttimeout 1h\n"
        f"{counter_decl}"
        "\t\tsize 65535\n"
        f"\t\telements = {{ {elems} }}\n"
        "\t}\n"
        "\tchain input_hook {\n"
        "\t\ttype filter hook input priority -140; policy accept;\n"
        "\t}\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# W1: рендер nft
# ---------------------------------------------------------------------------


class TestW1Render:
    def test_prober_rule_port_set(self) -> None:
        """Один named set на все три боевых TCP-порта + фильтр ip length."""
        for text in (probing.render_nft(True), probing.render_nft(False)):
            assert (
                "tcp dport { 443, 8443, 2053 } tcp flags & (fin|syn|rst|ack) == syn "
                "ip length > 40 update @probers4 { ip saddr }"
            ) in text

    def test_prober_rule_no_udp(self) -> None:
        """UDP в probers4 НЕ входит (QUIC-клиенты → ложные срабатывания)."""
        line = next(
            l for l in probing.render_nft(True).splitlines() if "update @probers4" in l
        )
        assert "udp" not in line

    def test_extra_counters_declared(self) -> None:
        text = probing.render_nft(True)
        assert "counter syn_valid_extra { }" in text
        assert "counter syn_bare_extra { }" in text

    def test_extra_counter_rules(self) -> None:
        """syn_valid_extra — ip length > 40; syn_bare_extra — БЕЗ ip-length-фильтра
        (симметрично 443: bare = bare+valid, ревью W1-1)."""
        text = probing.render_nft(True)
        assert (
            "tcp dport { 8443, 2053 } tcp flags & (fin|syn|rst|ack) == syn "
            'ip length > 40 counter name "syn_valid_extra"'
        ) in text
        bare_extra = next(
            l for l in text.splitlines() if 'counter name "syn_bare_extra"' in l
        )
        assert "tcp dport { 8443, 2053 }" in bare_extra
        assert "ip length" not in bare_extra

    def test_443_lines_byte_identical_snapshot(self) -> None:
        """Строки 443 — байт-в-байт прежние (калибровка PROBE-BURST, история
        порогов и старые тесты не ломаются)."""
        old_443_lines = [
            '        tcp dport 443 tcp flags & (fin|syn|rst|ack) == syn '
            'ip length > 40 counter name "syn_valid"\n',
            '        tcp dport 443 tcp flags & (fin|syn|rst|ack) == syn '
            'counter name "syn_bare"\n',
            '        udp dport 443 counter name "udp_443"\n',
        ]
        for per_element in (True, False):
            text = probing.render_nft(per_element)
            for line in old_443_lines:
                assert line in text, f"изменилась строка 443: {line!r}"

    def test_parse_extras(self) -> None:
        state = probing.parse_nft_table(_nft_list_text({}))
        assert state.syn_valid_extra == 33
        assert state.syn_bare_extra == 44


# ---------------------------------------------------------------------------
# W2: JSON-контракт watch --json (аддитивно, старая семантика не меняется)
# ---------------------------------------------------------------------------


class TestW2JsonContract:
    def _watch_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture, nft: probing.NftState | None = None,
    ) -> dict[str, Any]:
        _patch_common(tmp_path, monkeypatch, nft or _nft_state({}))
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=tmp_path / "snap.json",
            run=FakeRun(), now=T0,
        )
        assert rc == 0
        return json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    def test_old_keys_subset_of_new(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        data = self._watch_json(tmp_path, monkeypatch, capsys)
        for key in OLD_JSON_KEYS:
            assert key in data, f"старый ключ пропал: {key}"

    def test_new_keys_additive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        data = self._watch_json(
            tmp_path, monkeypatch, capsys,
            nft=probing.NftState(
                syn_bare=20, syn_valid=10, udp_443=1,
                syn_valid_extra=33, syn_bare_extra=44,
                per_element_counters=True, probers={},
            ),
        )
        assert data["syn_valid_extra"] == 33
        assert data["syn_bare_extra"] == 44
        assert data["extra_ports"] == [8443, 2053]
        # семантика старых полей не поехала: дельта от пустого снапшота = текущее
        assert data["syn_bare"] == 20
        assert data["syn_valid"] == 10
        assert data["udp_443"] == 1

    def test_lockdown_block_shape_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        data = self._watch_json(tmp_path, monkeypatch, capsys)
        assert set(data["lockdown"]) == {"active", "since", "ttl_until", "allow_from"}


# ---------------------------------------------------------------------------
# W3: probers 8443/2053 → new_ru_ips → SUSPECT; verified 8443 не попадает
# ---------------------------------------------------------------------------


class TestW3ExtraPortProbers:
    def test_extra_port_probers_trigger_suspect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Сканер, видимый только в 8443/2053 (в nft set портов нет), попадает
        в probers4 → new_ru_ips → RU-PROBE-SUSPECT (SPEC §1.4)."""
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
        assert sorted(data["new_ru_ips"]) == ["203.0.113.200", "203.0.113.201"]

    def test_extra_only_ports_suspect_when_443_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Тихий час на 443 (syn_valid=0) + прицельные пробы 8443
        (syn_valid_extra=5) + 2 новых RU-IP → RU-PROBE-SUSPECT.

        Регресс ревью W1-1: до фикса `syn_valid_total=delta.syn_valid`
        обнулял вердикт, хотя зондирование было видно на extra-портах.
        """
        _patch_common(tmp_path, monkeypatch, probing.NftState(
            syn_bare=20, syn_valid=0, udp_443=0,
            syn_valid_extra=5, syn_bare_extra=7,
            per_element_counters=True,
            probers={"203.0.113.200": 5, "203.0.113.201": 3},
        ))
        (tmp_path / "ru-cidrs.txt").write_text(RU_NET, encoding="utf-8")
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=tmp_path / "snap.json",
            run=FakeRun(), now=T0,
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert data["verdict"] == "RU-PROBE-SUSPECT"
        assert sorted(data["new_ru_ips"]) == ["203.0.113.200", "203.0.113.201"]

    def test_verified_client_8443_not_suspect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Verified-клиент XHTTP (двусторонний трафик на 8443, HF-1) из
        new_ru_ips исключается — один незнакомый RU-IP < порога 2 → quiet."""
        _patch_common(tmp_path, monkeypatch, _nft_state(
            {"203.0.113.200": 5, "203.0.113.201": 3}
        ))
        (tmp_path / "ru-cidrs.txt").write_text(RU_NET, encoding="utf-8")
        ss_verified_8443 = (
            "ESTAB 0 0 198.51.100.1:8443 203.0.113.200:54321\n"
            "\t cubic bytes_acked:20000 bytes_received:8000\n"
        )
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=tmp_path / "snap.json",
            run=FakeRun({"ss": _shell_result(ss_verified_8443)}), now=T0,
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert data["verdict"] == "quiet"
        assert data["new_ru_ips"] == ["203.0.113.201"]
        assert any("tcp/ss: 1 IP" in s for s in data["own_ips_sources"])


# ---------------------------------------------------------------------------
# W4: fast_contour_check
# ---------------------------------------------------------------------------


def _fast_run(probers: dict[str, int], per_element: bool = True) -> FakeRun:
    return FakeRun({
        "nft list table inet vds_probe": _shell_result(_nft_list_text(probers, per_element)),
    })


class TestW4FastContour:
    def _check(
        self, tmp_path: Path, run: FakeRun,
    ) -> probing.FastContourResult:
        return probing.fast_contour_check(
            run=run,
            cache_path=tmp_path / "fast.json",
            lock_file=str(tmp_path / "fast.lock"),
            now=T0,
        )

    def test_burst_at_threshold_tags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        _patch_common(tmp_path, monkeypatch, None)
        probers = {f"203.0.113.{i}": 2 for i in range(10)}
        result = self._check(tmp_path, _fast_run(probers))
        assert result.skipped is False
        assert result.probers_window == 10
        assert result.alert is True
        assert "FAST-CONTOUR: 10 probers/5min" in capsys.readouterr().out

    def test_below_threshold_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        _patch_common(tmp_path, monkeypatch, None)
        probers = {f"203.0.113.{i}": 2 for i in range(9)}
        result = self._check(tmp_path, _fast_run(probers))
        assert result.alert is False
        assert "FAST-CONTOUR" not in capsys.readouterr().out

    def test_no_table_quiet_skip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        _patch_common(tmp_path, monkeypatch, None)
        run = FakeRun({
            "nft list table inet vds_probe": _shell_result("", "No such file", 1),
        })
        result = self._check(tmp_path, run)
        assert result.skipped is True and result.alert is False
        assert not (tmp_path / "fast.json").exists()
        assert "FAST-CONTOUR" not in capsys.readouterr().out

    def test_probe_watch_snapshot_not_mutated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Инвариант ADR-014: быстрый контур никогда не пишет снапшот
        probe-watch.json (только свой сайдкар-кэш)."""
        _patch_common(tmp_path, monkeypatch, None)
        snap = tmp_path / "snap.json"
        assert probing.save_snapshot(
            probing.NftState(per_element_counters=True), snap,
            extra={"threat": {"level": "quiet"}},
        )
        before = snap.read_bytes()
        probers = {f"203.0.113.{i}": 3 for i in range(15)}
        result = self._check(tmp_path, _fast_run(probers))
        assert result.alert is True
        assert snap.read_bytes() == before

    def test_cache_written_0600_with_baseline_and_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch_common(tmp_path, monkeypatch, None)
        ss_verified = (
            "ESTAB 0 0 198.51.100.1:8443 203.0.113.77:54321\n"
            "\t cubic bytes_acked:20000 bytes_received:8000\n"
        )
        run = FakeRun({
            "nft list table inet vds_probe": _shell_result(_nft_list_text({"203.0.113.5": 2})),
            "ss": _shell_result(ss_verified),
        })
        result = self._check(tmp_path, run)
        assert result.cache_written is True
        cache_path = tmp_path / "fast.json"
        assert stat.S_IMODE(os.stat(cache_path).st_mode) == 0o600
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        # база probers для следующей 5-мин дельты
        assert cache["probers"] == {"203.0.113.5": 2}
        # verified-IP (HF-1, тот же инвариант) — в сайдкар-кэше
        assert cache["own_ips_cache"] == [
            ["203.0.113.77", T0.isoformat(timespec="seconds")]
        ]

    def test_second_tick_zero_delta_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Между тиками активности нет → счётчики не росли → тишина (кэш-база)."""
        _patch_common(tmp_path, monkeypatch, None)
        probers = {f"203.0.113.{i}": 2 for i in range(12)}
        run = _fast_run(probers)
        assert self._check(tmp_path, run).alert is True
        capsys.readouterr()
        second = self._check(tmp_path, _fast_run(probers))
        assert second.probers_window == 0 and second.alert is False
        assert "FAST-CONTOUR" not in capsys.readouterr().out

    def test_fallback_new_set_members_counted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ядро без per-element счётчиков: новые элементы set ≈ активность
        окна (timeout 1h) — консервативная оценка."""
        _patch_common(tmp_path, monkeypatch, None)
        probers = {f"203.0.113.{i}": 0 for i in range(11)}
        result = self._check(tmp_path, _fast_run(probers, per_element=False))
        assert result.probers_window == 11 and result.alert is True

    def test_no_auto_actions(self) -> None:
        """Контракт §2: быстрый контур — только телеметрия; в коде нет
        вызовов ufw/lockdown-реакций (lock-443 — прерогатива часового тика)."""
        import inspect

        src = inspect.getsource(probing.fast_contour_check)
        assert "ufw" not in src
        assert "run_auto_reactions" not in src
        assert "apply_auto_lockdown" not in src


# ---------------------------------------------------------------------------
# W5: PROBE-BURST не зависит от extra; fast-кэш ↔ own_ips_cache в cmd_watch
# ---------------------------------------------------------------------------


class TestW5BurstCalibration:
    def test_extra_counters_do_not_affect_verdict(self) -> None:
        """Калибровка PROBE-BURST — только 443: гигантские extra-дельты не
        поднимают вердикт (unique/ratio по 443 тихие → quiet)."""
        delta = probing.Delta(
            syn_bare=100, syn_valid=99, udp_443=0,
            bare_no_payload=1,
            ratio_no_payload=1 / 100,
            unique_probers=3,
            syn_valid_extra=10**6,
            syn_bare_extra=10**6,
        )
        assert probing.compute_verdict(delta, 50).name == "quiet"

    def test_burst_still_fires_on_443_only(self) -> None:
        delta = probing.Delta(
            syn_bare=200, syn_valid=5, udp_443=0,
            bare_no_payload=195, ratio_no_payload=195 / 200,
            unique_probers=60,
            syn_valid_extra=0, syn_bare_extra=0,
        )
        assert probing.compute_verdict(delta, 50).name == "PROBE-BURST"


class TestW5WatchFastCacheMerge:
    def _seed_fast_cache(self, tmp_path: Path, entries: list[list[str]]) -> None:
        (tmp_path / "probe-fast-cache.json").write_text(
            json.dumps({"version": 1, "ts": "2026-11-16T11:00:00",
                        "probers": {}, "own_ips_cache": entries}),
            encoding="utf-8",
        )

    def test_record_merges_fast_cache_into_snapshot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Короткая сессия между часовыми тиками: verified из 5-мин кэша
        сэмплера вливается в snapshot own_ips_cache при record-тике."""
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        recent = (T0 - probing.timedelta(minutes=10)).isoformat(timespec="seconds")
        stale = (T0 - probing.timedelta(hours=25)).isoformat(timespec="seconds")
        self._seed_fast_cache(
            tmp_path,
            [["203.0.113.77", recent], ["203.0.113.78", stale]],
        )
        snap_path = tmp_path / "snap.json"
        rc = probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=FakeRun(), now=T0,
        )
        assert rc == 0
        cache = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert ["203.0.113.77", recent] in cache  # влит из fast-кэша
        assert not any(ip == "203.0.113.78" for ip, _ in cache)  # TTL 24 ч чистка

    def test_record_merges_with_max_last_seen(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Один IP в обоих кэшах — остаётся max(last_seen)."""
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        older = (T0 - probing.timedelta(hours=3)).isoformat(timespec="seconds")
        newer = (T0 - probing.timedelta(hours=1)).isoformat(timespec="seconds")
        snap_path = tmp_path / "snap.json"
        probing.write_snapshot_payload(
            {"own_ips_cache": [["203.0.113.90", older]]}, snap_path
        )
        self._seed_fast_cache(tmp_path, [["203.0.113.90", newer]])
        rc = probing.cmd_watch(
            record=True, snapshot_path=snap_path, run=FakeRun(), now=T0,
        )
        assert rc == 0
        cache = probing.load_snapshot(snap_path)["own_ips_cache"]
        assert cache == [["203.0.113.90", newer]]

    def test_no_record_mutates_neither_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """record=False: снапшот И fast-кэш не мутируются (ADR-014/M1);
        fast-запись видна только в отчёте (own_ips исключает IP)."""
        _patch_common(tmp_path, monkeypatch, _nft_state({}))
        recent = (T0 - probing.timedelta(minutes=5)).isoformat(timespec="seconds")
        self._seed_fast_cache(tmp_path, [["203.0.113.77", recent]])
        snap_path = tmp_path / "snap.json"
        assert probing.write_snapshot_payload(
            {"own_ips_cache": []}, snap_path
        )
        snap_before = snap_path.read_bytes()
        fast_before = (tmp_path / "probe-fast-cache.json").read_bytes()
        # RU-сеть + сканер: без fast-verified оба IP были бы в new_ru_ips
        monkeypatch.setattr(
            probing, "list_nft_table",
            lambda run=None: _nft_state({"203.0.113.77": 4, "203.0.113.88": 2}),
        )
        (tmp_path / "ru-cidrs.txt").write_text(RU_NET, encoding="utf-8")
        rc = probing.cmd_watch(
            json_out=True, snapshot_path=snap_path, run=FakeRun(), now=T0,
        )
        assert rc == 0
        assert snap_path.read_bytes() == snap_before
        assert (tmp_path / "probe-fast-cache.json").read_bytes() == fast_before
        # в памяти отчёта fast-verified учтён: .77 исключён из new_ru_ips
        data = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert data["new_ru_ips"] == ["203.0.113.88"]
        assert data["verdict"] == "quiet"  # 1 новый RU-IP < порога 2


class TestW5CollectHook:
    def test_collect_event_calls_fast_contour(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Сэмплер вызывает fast_contour_check; нет nft-таблицы (не-JSON
        list не замокан) — тихий скип без исключения."""
        from src.logs.collect import collect_event

        called = {"n": 0}

        def spy(**kwargs: Any) -> probing.FastContourResult:
            called["n"] += 1
            return probing.FastContourResult(skipped=True)

        monkeypatch.setattr(probing, "fast_contour_check", spy)
        run = FakeRun({  # nft -j есть, обычного list нет → таблицы «нет»
            "nft -j list table": _shell_result("{}"),
            "systemctl": _shell_result(""),
            "journalctl": _shell_result(""),
        })
        event, _coverage = collect_event(
            run=run, snapshot_path=tmp_path / "probe-watch.json",
        )
        assert called["n"] == 1
        assert event["computed_by"] == "logs-collect (read-only)"
