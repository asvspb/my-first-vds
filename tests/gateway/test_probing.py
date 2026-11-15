"""Тесты src/gateway/probing.py (И33 v1): без root/сети — все shell за моками.

Покрытие WP: рендер nft-файла (+идемпотентность), дельта-логика снапшота,
парсеры journal-паттернов (RFC-5737 203.0.113.x), вердикт-пороги,
explain на моках, CLI (dry-run не мутит, --help полный).
"""

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import src.gateway.probing as probing
from src.core.shell import ShellResult
from src.main import app

runner = CliRunner()


def _shell_result(stdout: str = "", stderr: str = "", code: int = 0) -> ShellResult:
    return ShellResult(stdout=stdout, stderr=stderr, returncode=code)


class FakeRun:
    """Заменитель run_list: очередь ответов по префиксам + журнал вызовов."""

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


NFT_LIST_WITH_COUNTERS = """table inet vds_probe {
\tcounter syn_bare {
\t\tpackets 150 bytes 9000
\t}
\tcounter syn_valid {
\t\tpackets 120 bytes 7200
\t}
\tcounter udp_443 {
\t\tpackets 60 bytes 18000
\t}
\tset probers4 {
\t\ttype ipv4_addr
\t\tflags dynamic, timeout
\t\ttimeout 1h
\t\tcounter
\t\telements = { 203.0.113.5 counter packets 3 bytes 180, 203.0.113.9 counter packets 7 bytes 420 }
\t}
\tchain input_hook {
\t\ttype filter hook input priority -140; policy accept;
\t\ttcp dport 443 tcp flags & (fin|syn|rst|ack) == syn update @probers4 { ip saddr }
\t}
}
"""

NFT_LIST_NO_COUNTERS = NFT_LIST_WITH_COUNTERS.replace(
    "203.0.113.5 counter packets 3 bytes 180", "203.0.113.5"
).replace("203.0.113.9 counter packets 7 bytes 420", "203.0.113.9").replace(
    "\t\tcounter\n", ""  # fallback-вариант: декларации counter в set нет
)

NFT_LIST_EMPTY_SET = NFT_LIST_WITH_COUNTERS.replace(
    "\t\telements = { 203.0.113.5 counter packets 3 bytes 180, 203.0.113.9 counter packets 7 bytes 420 }\n",
    "",
)

TABLES_PRESENT = "table inet vds_probe\ntable inet relay_cidr\n"
TABLES_ABSENT = ""


@pytest.fixture(autouse=True)
def _no_net(monkeypatch: pytest.MonkeyPatch) -> None:
    """Сетевого вызова netcheck.public_ip в тестах нет (server_ip подменяется)."""
    monkeypatch.setattr(probing, "_server_public_ip", lambda: "")


# ---------------------------------------------------------------------------
# Рендер nft-файла
# ---------------------------------------------------------------------------

class TestRenderNft:
    def test_named_counters_in_rules(self) -> None:
        """Ревью 2026-11-15: анонимный counter в правиле НЕ трогает
        именованные объекты — правила обязаны ссылаться через counter name."""
        text = probing.render_nft(True)
        assert 'ip length > 40 counter name "syn_valid"' in text
        assert 'tcp flags & (fin|syn|rst|ack) == syn counter name "syn_bare"' in text
        assert 'udp dport 443 counter name "udp_443"' in text

    def test_no_anonymous_counter_in_rules(self) -> None:
        text = probing.render_nft(True)
        chain = text.split("chain input_hook {", 1)[1]
        # нет голого " counter" в конце правила (он не пишется в named)
        for line in chain.splitlines():
            if "counter" in line and "name" not in line:
                # допустима только строка с set-декларацией, а в цепочке её нет
                raise AssertionError(f"анонимный counter в правиле цепочки: {line!r}")

    def test_no_counter_counter_duplication(self) -> None:
        """'counter counter' — реальный провал True-варианта на asv2."""
        for text in (probing.render_nft(True), probing.render_nft(False)):
            assert "counter counter" not in text

    def test_set_update_not_add(self) -> None:
        """update @set { ip saddr } — инкремент + refresh timeout; без слова
        counter внутри (иначе 'counter counter')."""
        text = probing.render_nft(True)
        assert "update @probers4 { ip saddr }" in text
        assert "add @probers4" not in text
        element = text.split("update @probers4 {", 1)[1].split("}", 1)[0]
        assert "counter" not in element

    def test_set_declaration_dynamic_timeout_size(self) -> None:
        text = probing.render_nft(True)
        assert "flags dynamic, timeout" in text
        assert "size 65535" in text
        assert "timeout 1h" in text
        set_block = text.split("set probers4 {", 1)[1].split("}", 1)[0]
        assert set_block.count("counter") == 1  # декларация — ровно один раз

    def test_contains_core_objects(self) -> None:
        text = probing.render_nft(per_element_counter=True)
        assert "table inet vds_probe {" in text
        assert "counter syn_bare { }" in text
        assert "counter syn_valid { }" in text
        assert "counter udp_443 { }" in text
        assert "type ipv4_addr" in text
        # приоритет input -140: до ufw-цепочек, не мешает UFW/relay
        assert "type filter hook input priority -140" in text
        assert "policy accept;" in text

    def test_idempotent_render(self) -> None:
        assert probing.render_nft(True) == probing.render_nft(True)
        assert probing.render_nft(False) == probing.render_nft(False)

    def test_fallback_without_element_counters(self) -> None:
        full = probing.render_nft(True)
        plain = probing.render_nft(False)
        assert "        counter\n" in full  # декларация в set
        assert "        counter\n" not in plain  # fallback: декларации нет
        # именованные счётчики в правилах есть в обеих ветках
        assert 'counter name "syn_bare"' in plain
        assert 'counter name "udp_443"' in plain


# ---------------------------------------------------------------------------
# Парсер nft list table
# ---------------------------------------------------------------------------

class TestParseNftTable:
    def test_counters_and_per_element(self) -> None:
        state = probing.parse_nft_table(NFT_LIST_WITH_COUNTERS)
        assert state.syn_bare == 150
        assert state.syn_valid == 120
        assert state.udp_443 == 60
        assert state.probers == {"203.0.113.5": 3, "203.0.113.9": 7}
        assert state.per_element_counters is True

    def test_without_element_counters(self) -> None:
        state = probing.parse_nft_table(NFT_LIST_NO_COUNTERS)
        assert state.syn_bare == 150
        assert sorted(state.probers) == ["203.0.113.5", "203.0.113.9"]
        assert state.per_element_counters is False

    def test_empty_set_with_counter_decl_is_supported(self) -> None:
        """Ревью 2026-11-16 (edge-case 2): пустой set + counter в декларации
        = счётчики на IP поддерживаются (explain не врёт «ядро не умеет»)."""
        state = probing.parse_nft_table(NFT_LIST_EMPTY_SET)
        assert state.probers == {}
        assert state.per_element_counters is True

    def test_set_without_counter_decl_is_fallback(self) -> None:
        state = probing.parse_nft_table(NFT_LIST_NO_COUNTERS)
        assert state.per_element_counters is False

    def test_empty_output(self) -> None:
        state = probing.parse_nft_table("")
        assert state.syn_bare == 0 and state.syn_valid == 0
        assert state.probers == {}


# ---------------------------------------------------------------------------
# Снапшот: загрузка/сохранение/дельта
# ---------------------------------------------------------------------------

class TestSnapshot:
    def test_missing_file_is_zero_baseline(self, tmp_path: Path) -> None:
        snap = probing.load_snapshot(tmp_path / "absent.json")
        assert snap["syn_bare"] == 0 and snap["syn_valid"] == 0
        assert snap["probers"] == {}

    def test_corrupt_file_is_zero_baseline(self, tmp_path: Path) -> None:
        p = tmp_path / "broken.json"
        p.write_text("{not json", encoding="utf-8")
        snap = probing.load_snapshot(p)
        assert snap["syn_bare"] == 0 and snap["probers"] == {}

    def test_roundtrip_0600(self, tmp_path: Path) -> None:
        p = tmp_path / "snap.json"
        state = probing.NftState(syn_bare=10, syn_valid=8, probers={"203.0.113.5": 2})
        assert probing.save_snapshot(state, p) is True
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
        snap = probing.load_snapshot(p)
        assert snap["syn_bare"] == 10
        assert snap["probers"] == {"203.0.113.5": 2}
        assert snap["ts"]  # метка времени записана

    def test_zero_values_roundtrip(self, tmp_path: Path) -> None:
        p = tmp_path / "snap.json"
        assert probing.save_snapshot(probing.NftState(), p) is True
        snap = probing.load_snapshot(p)
        assert snap["syn_bare"] == 0 and snap["probers"] == {}
        assert snap["udp_443"] == 0


class TestDelta:
    def test_first_run_all_delta_from_zero(self, tmp_path: Path) -> None:
        current = probing.NftState(
            syn_bare=150, syn_valid=120,
            probers={"203.0.113.5": 3, "203.0.113.9": 7},
            per_element_counters=True,
        )
        delta = probing.compute_delta(current, probing.load_snapshot(tmp_path / "no.json"))
        assert delta.syn_bare == 150 and delta.syn_valid == 120
        assert delta.unique_probers == 2
        assert delta.top == [("203.0.113.9", 7), ("203.0.113.5", 3)]

    def test_delta_against_previous_snapshot(self, tmp_path: Path) -> None:
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(syn_bare=100, syn_valid=90,
                                probers={"203.0.113.5": 3}, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = probing.NftState(syn_bare=130, syn_valid=120,
                                   probers={"203.0.113.5": 5, "203.0.113.9": 2},
                                   per_element_counters=True)
        delta = probing.compute_delta(current, probing.load_snapshot(snap_path))
        assert delta.syn_bare == 30 and delta.syn_valid == 30
        assert delta.unique_probers == 2  # 113.5: +2, 113.9: +2

    def test_counter_regression_counts_as_window(self, tmp_path: Path) -> None:
        """Ревью 2026-11-16 (3a): current < snap — сброс счётчиков (ребут/
        переустановка); дельта = current, а не кламп до 0 (счёт за окно
        не теряется, см. test_global_counter_reset_after_reinstall)."""
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(syn_bare=200, syn_valid=100, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = probing.NftState(syn_bare=50, syn_valid=10, per_element_counters=True)
        delta = probing.compute_delta(current, probing.load_snapshot(snap_path))
        assert delta.syn_bare == 50 and delta.syn_valid == 10

    def test_fallback_set_size_without_element_counters(self) -> None:
        current = probing.NftState(syn_bare=10, syn_valid=5,
                                   probers={"203.0.113.5": 0, "203.0.113.9": 0},
                                   per_element_counters=False)
        delta = probing.compute_delta(current, {"syn_bare": 0, "syn_valid": 0, "probers": {}})
        assert delta.unique_probers == 2
        assert all(cnt == 0 for _, cnt in delta.top)

    def test_udp_443_delta(self, tmp_path: Path) -> None:
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(udp_443=10, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = probing.NftState(udp_443=25, per_element_counters=True)
        delta = probing.compute_delta(current, probing.load_snapshot(snap_path))
        assert delta.udp_443 == 15

    def test_global_counter_reset_after_reinstall(self) -> None:
        """Ревью 2026-11-16 (edge-case 3a): current < snap — ребут/переустановка
        таблицы; дельта = current (те же правила, что для протухшего элемента)."""
        snap = {"syn_bare": 5000, "syn_valid": 4000, "udp_443": 500, "probers": {}}
        current = probing.NftState(syn_bare=3, syn_valid=2, udp_443=1,
                                   per_element_counters=True)
        delta = probing.compute_delta(current, snap)
        assert delta.syn_bare == 3
        assert delta.syn_valid == 2
        assert delta.udp_443 == 1

    def test_stale_element_restart_not_lost(self) -> None:
        """Ревью: элемент протух (timeout 1h) и пересоздан — packets < prev;
        дельта = packets (весь счётчик элемента за окно), IP не теряется."""
        current = probing.NftState(
            syn_bare=10, syn_valid=5,
            probers={"203.0.113.5": 2, "203.0.113.20": 4},
            per_element_counters=True,
        )
        snap = {"syn_bare": 10, "syn_valid": 5, "udp_443": 0,
                "probers": {"203.0.113.5": 9, "203.0.113.20": 0}}
        delta = probing.compute_delta(current, snap)
        assert delta.top[0] == ("203.0.113.20", 4)  # пересоздан: d = packets
        assert ("203.0.113.5", 2) in delta.top      # тоже протух: d = 2
        assert delta.unique_probers == 2


# ---------------------------------------------------------------------------
# Вердикт-пороги
# ---------------------------------------------------------------------------

def _delta(
    unique: int = 0, bare: int = 0, valid: int = 0, udp: int = 0
) -> probing.Delta:
    return probing.Delta(
        syn_bare=bare, syn_valid=valid, udp_443=udp,
        bare_no_payload=max(0, bare - valid),
        ratio_no_payload=(max(0, bare - valid) / bare) if bare > 0 else None,
        unique_probers=unique,
    )


class TestVerdict:
    def test_burst_by_unique_probers_threshold(self) -> None:
        assert probing.compute_verdict(_delta(unique=50, bare=200, valid=200), 50).name == "PROBE-BURST"
        assert probing.compute_verdict(_delta(unique=49, bare=200, valid=200), 50).name == "quiet"

    def test_burst_by_bare_ratio(self) -> None:
        # голые SYN без payload, объём 101 > 100, ratio ~1.0 >= 0.90
        assert probing.compute_verdict(_delta(bare=101, valid=1), 50).name == "PROBE-BURST"

    def test_volume_100_is_below_burst(self) -> None:
        # объём ровно 100 — не > 100 → quiet (строгий порог)
        assert probing.compute_verdict(_delta(bare=100, valid=1), 50).name == "quiet"

    def test_normal_traffic_is_quiet(self) -> None:
        # клиенты шлют SYN с опциями: valid ≈ bare → ratio низкий
        assert probing.compute_verdict(_delta(unique=3, bare=5000, valid=4990), 50).name == "quiet"

    def test_no_traffic_quiet(self) -> None:
        assert probing.compute_verdict(_delta(), 50).name == "quiet"


class TestRuProbeSuspectVerdict:
    """RU-PROBE-SUSPECT: новые RU-IP >= 2/окно при живом syn_valid и
    доступном RU-CIDR (границы)."""

    def test_two_new_ru_ips_triggers(self) -> None:
        d = _delta(unique=0, bare=5, valid=5)
        v = probing.compute_verdict(
            d, 50, new_ru_ips=["203.0.113.101", "203.0.113.102"],
            ru_available=True, syn_valid_total=10,
        )
        assert v.name == "RU-PROBE-SUSPECT"
        assert "новых IP из RU-зоны" in v.reasons[0]

    def test_one_new_ru_ip_below_threshold(self) -> None:
        d = _delta(unique=0, bare=5, valid=5)
        v = probing.compute_verdict(
            d, 50, new_ru_ips=["203.0.113.101"],
            ru_available=True, syn_valid_total=10,
        )
        assert v.name == "quiet"

    def test_ru_unavailable_disables_verdict(self) -> None:
        d = _delta(unique=0, bare=5, valid=5)
        v = probing.compute_verdict(
            d, 50, new_ru_ips=["203.0.113.101", "203.0.113.102"],
            ru_available=False, syn_valid_total=10,
        )
        assert v.name == "quiet"

    def test_no_valid_baseline_disables_verdict(self) -> None:
        # syn_valid_total == 0: базовой легитимной активности нет —
        # «новые RU-IP» не интерпретируются (таблица ещё не работала)
        d = _delta(unique=0, bare=5, valid=0)
        v = probing.compute_verdict(
            d, 50, new_ru_ips=["203.0.113.101", "203.0.113.102"],
            ru_available=True, syn_valid_total=0,
        )
        assert v.name == "quiet"

    def test_ru_verdict_wins_over_burst(self) -> None:
        d = _delta(unique=60, bare=5000, valid=4990)
        v = probing.compute_verdict(
            d, 50, new_ru_ips=["203.0.113.101", "203.0.113.102"],
            ru_available=True, syn_valid_total=10,
        )
        assert v.name == "RU-PROBE-SUSPECT"
        # причины burst-критерия тоже внутри
        assert any("уникальных пробующих IP" in r for r in v.reasons)

    def test_burst_still_works_alone(self) -> None:
        d = _delta(unique=60, bare=5000, valid=4990)
        v = probing.compute_verdict(d, 50, ru_available=True, syn_valid_total=10)
        assert v.name == "PROBE-BURST"


# ---------------------------------------------------------------------------
# Journal-паттерны (RFC-5737 фиксстуры)
# ---------------------------------------------------------------------------

XRAY_LOG = (
    "2026-11-15T10:00:00+0000 asv2 xray[123]: REALITY: processed invalid connection from 203.0.113.4:12345\n"
    "2026-11-15T10:00:05+0000 asv2 xray[123]: [Info] proxy/vless inbound: accepted [203.0.113.5]:44000\n"
)

HY2_LOG = (
    "2026-11-15T10:01:00+0000 hysteria2[200]: auth failed from 203.0.113.6:51000 (wrong password)\n"
    "2026-11-15T10:01:02+0000 hysteria2[200]: session closed for 203.0.113.5\n"
)

KERNEL_LOG = (
    "Nov 15 10:02:00 asv2 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=213.108.23.119 LEN=40 PROTO=TCP DPT=443\n"
    "Nov 15 10:02:00 asv2 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=213.108.23.119 LEN=40 PROTO=TCP DPT=8443\n"
    "Nov 15 10:02:01 asv2 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=213.108.23.119 LEN=40 PROTO=TCP DPT=443\n"
)


class TestJournalPatterns:
    def test_xray_reality_pattern(self) -> None:
        fake = FakeRun({"journalctl -u vds-xray": _shell_result(XRAY_LOG)})
        hits = probing.scan_journal("-1 hour", fake, sources=["vds-xray.service"])
        assert len(hits) == 1
        assert hits[0].pattern_name == "reality_invalid"
        assert hits[0].count == 1
        assert hits[0].ips == []

    def test_hysteria_auth_fail_pattern(self) -> None:
        fake = FakeRun({"journalctl -u vds-hysteria2": _shell_result(HY2_LOG)})
        hits = probing.scan_journal("-1 hour", fake, sources=["vds-hysteria2.service"])
        assert hits[0].pattern_name == "hysteria_auth_fail"
        assert hits[0].count == 1

    def test_ufw_block_443_with_src_extraction(self) -> None:
        fake = FakeRun({"journalctl -k": _shell_result(KERNEL_LOG)})
        hits = probing.scan_journal("-1 hour", fake, sources=["kernel"])
        assert hits[0].pattern_name == "ufw_block_443"
        assert hits[0].count == 2  # DPT=8443 не считается
        assert hits[0].ips == ["203.0.113.7"]

    def test_journal_read_failure_yields_no_hits(self) -> None:
        fake = FakeRun({"journalctl": _shell_result(stderr="journal error", code=1)})
        assert probing.scan_journal("-1 hour", fake) == []

    def test_patterns_documented_constant(self) -> None:
        # константа сигнатур документирована (note обязателен) — контракт WP
        for source, specs in probing.JOURNAL_PATTERNS.items():
            assert specs, f"пустой список сигнатур для {source}"
            for spec in specs:
                assert spec.get("note"), f"сигнатура {source}/{spec['name']} без note"


# ---------------------------------------------------------------------------
# RU-классификация
# ---------------------------------------------------------------------------

class TestRuClassification:
    def test_missing_file_means_unknown(self, tmp_path: Path) -> None:
        assert probing.load_ru_cidrs(tmp_path / "absent.txt") is None
        assert probing.classify_ip("203.0.113.9", None) == "unknown"

    def test_ip_in_aggregate_marked_ru(self, tmp_path: Path) -> None:
        p = tmp_path / "ru-cidrs.txt"
        p.write_text("203.0.113.0/24\n198.51.100.0/24\n", encoding="utf-8")
        nets = probing.load_ru_cidrs(p)
        assert nets is not None
        assert probing.classify_ip("203.0.113.9", nets) == "[RU]"
        assert probing.classify_ip("203.0.114.9", nets) == "unknown"

    def test_garbage_line_skipped_not_whole_file(self, tmp_path: Path) -> None:
        """Ревью 2026-11-16 (edge-case 1): мусор на 5-й строке из 6 —
        остальные 5 сетей не теряются."""
        p = tmp_path / "ru-cidrs.txt"
        p.write_text(
            "203.0.113.0/24\n198.51.100.0/24\n192.0.2.0/24\n203.0.114.0/24\n"
            "это не CIDR !!!\n198.51.101.0/24\n",
            encoding="utf-8",
        )
        nets = probing.load_ru_cidrs(p)
        assert nets is not None
        assert len(nets) == 5

    def test_ipv6_lines_ignored_file_still_read(self, tmp_path: Path) -> None:
        p = tmp_path / "ru-cidrs.txt"
        p.write_text("203.0.113.0/24\n2a00:5c00::/29\n2001:db8::/32\n", encoding="utf-8")
        nets = probing.load_ru_cidrs(p)
        assert nets is not None
        assert len(nets) == 1  # только v4

    def test_ipv6_only_file_is_empty_list_not_none(self, tmp_path: Path) -> None:
        """Файл сплошь IPv6 → пустой v4-агрегат (НЕ None): classify даст
        unknown, но geo_source скажет «файл есть, v4-агрегат пуст»."""
        p = tmp_path / "ru-cidrs.txt"
        p.write_text("2a00:5c00::/29\n2001:db8::/32\n", encoding="utf-8")
        nets = probing.load_ru_cidrs(p)
        assert nets == []

    def test_empty_v4_aggregate_geo_source_honest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(probing, "RU_CIDR_FILE", tmp_path / "v6only.txt")
        (tmp_path / "v6only.txt").write_text("2a00:5c00::/29\n", encoding="utf-8")
        current = probing.NftState(syn_bare=5, syn_valid=5, per_element_counters=True)
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=tmp_path / "snap.json", server_ip="",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert "есть" in report.geo_source
        assert "пуст" in report.geo_source
        assert "IPv4-агрегат" in report.geo_source
        assert report.verdict.name == "quiet"

    def test_cache_reuses_verdicts_within_run(self, tmp_path: Path) -> None:
        p = tmp_path / "ru-cidrs.txt"
        p.write_text("203.0.113.0/24\n", encoding="utf-8")
        nets = probing.load_ru_cidrs(p)
        cache: dict[str, str] = {}
        assert probing.classify_ip("203.0.113.9", nets, cache=cache) == "[RU]"
        assert probing.classify_ip("203.0.113.9", nets, cache=cache) == "[RU]"
        assert probing.classify_ip("203.0.113.9", None, cache=cache) == "[RU]"  # из кэша
        assert cache == {"203.0.113.9": "[RU]"}

    def test_report_geo_uses_shared_cache(self, tmp_path: Path) -> None:
        nets = [probing.ipaddress.ip_network("203.0.113.0/24")]
        state = probing.NftState(
            syn_bare=1, syn_valid=1,
            probers={"203.0.113.5": 1}, per_element_counters=True,
        )
        report = probing.build_report(
            state, run=lambda args, **kw: _shell_result(),
            snapshot_path=tmp_path / "snap.json", server_ip="",
            now=lambda: probing.datetime(2026, 11, 15, 12, 0, 0),
        )
        report._ru_networks = nets
        assert report.geo("203.0.113.5") == "[RU]"
        assert report._geo_cache == {"203.0.113.5": "[RU]"}
        assert report.to_json()["top"][0]["geo"] == "[RU]"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Watch / report
# ---------------------------------------------------------------------------

class TestWatch:
    def test_missing_table_returns_none(self) -> None:
        # реальный `nft list table` без таблицы: rc=1
        fake = FakeRun({"nft": _shell_result(stderr="Error: No such table", code=1)})
        report, current = probing.run_watch(run=fake, snapshot_path=Path("/nonexistent"))
        assert report is None and current is None

    def test_report_json_shape(self, tmp_path: Path) -> None:
        fake = FakeRun({"nft list table": _shell_result(NFT_LIST_WITH_COUNTERS)})
        report, current = probing.run_watch(
            run=fake, snapshot_path=tmp_path / "snap.json",
            now=lambda: probing.datetime(2026, 11, 15, 12, 0, 0),
        )
        assert report is not None and current is not None
        data = report.to_json()
        for key in ("verdict", "syn_bare", "syn_valid", "udp_443",
                    "unique_probers", "top", "journal", "geo_source",
                    "threshold", "window", "new_ru_ips", "ru_top"):
            assert key in data
        assert data["geo_source"].startswith("unknown")  # без RU-файла — честно
        assert data["top"][0]["ip"] == "203.0.113.9"  # type: ignore[index]
        assert data["udp_443"] == 60  # type: ignore[index]

    def test_ru_marking_with_cidr_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ru_file = tmp_path / "ru-cidrs.txt"
        ru_file.write_text("203.0.113.0/24\n", encoding="utf-8")
        monkeypatch.setattr(probing, "RU_CIDR_FILE", ru_file)
        fake = FakeRun({"nft list table": _shell_result(NFT_LIST_WITH_COUNTERS)})
        report, _ = probing.run_watch(
            run=fake, snapshot_path=tmp_path / "snap.json",
            now=lambda: probing.datetime(2026, 11, 15, 12, 0, 0),
        )
        assert report is not None
        top = report.to_json()["top"]
        geo = {item["ip"]: item["geo"] for item in top}  # type: ignore[index]
        assert geo["203.0.113.5"] == "[RU]"


class TestNewRuIps:
    """RU-логика build_report (ревью 2026-11-16, edge-case 3c): активность
    по дельте, вернувшиеся IP, masscan-гашение, server IP/loopback."""

    RU_FILE = "203.0.113.0/24\n"

    def _state(
        self, probers: dict[str, int], syn_valid: int = 10, syn_bare: int = 100
    ) -> probing.NftState:
        return probing.NftState(
            syn_bare=syn_bare, syn_valid=syn_valid, udp_443=0,
            probers=probers, per_element_counters=True,
        )

    def _ru_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ru_file = tmp_path / "ru-cidrs.txt"
        ru_file.write_text(self.RU_FILE, encoding="utf-8")
        monkeypatch.setattr(probing, "RU_CIDR_FILE", ru_file)

    def test_new_ru_ips_detected_and_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._ru_file(tmp_path, monkeypatch)
        snap_path = tmp_path / "snap.json"
        # 113.5 в снапшоте и активен (delta>0) — «вернувшийся», не триггер;
        # 113.101/113.102 — новые; 113.103 — свой IP сервера — исключён.
        prev = probing.NftState(syn_bare=100, syn_valid=5, udp_443=0,
                                probers={"203.0.113.5": 9}, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = self._state({
            "203.0.113.5": 12,
            "203.0.113.101": 2,
            "203.0.113.102": 1,
            "203.0.113.103": 3,
            "198.51.100.9": 5,  # не RU — не считается
        }, syn_valid=10)
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=snap_path, server_ip="203.0.113.103",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert sorted(report.new_ru_ips) == ["203.0.113.101", "203.0.113.102"]
        assert report.verdict.name == "RU-PROBE-SUSPECT"
        data = report.to_json()
        ru_top = data["ru_top"]
        assert {item["ip"] for item in ru_top} == {  # type: ignore[index]
            "203.0.113.101", "203.0.113.102", "203.0.113.5",
        }
        by_ip = {item["ip"]: item for item in ru_top}  # type: ignore[index]
        assert by_ip["203.0.113.101"]["returned"] is False  # type: ignore[index]
        assert by_ip["203.0.113.5"]["returned"] is True  # type: ignore[index]
        assert by_ip["203.0.113.5"]["delta"] == 3  # type: ignore[index]
        # в reasons — только НОВЫЕ (триггер), не вернувшийся
        assert "113.101" in report.verdict.reasons[0]

    def test_masscan_window_does_not_trigger(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Два 40-байтных masscan-IP из RU при delta.syn_valid=0 → quiet
        (SUSPECT гасится условием delta.syn_valid > 0, ревью 3c-iii)."""
        self._ru_file(tmp_path, monkeypatch)
        snap_path = tmp_path / "snap.json"
        # снапшот: syn_valid совпадает с current → дельта valid = 0
        prev = probing.NftState(syn_bare=100, syn_valid=10, udp_443=0,
                                per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = self._state({
            "203.0.113.101": 5,  # masscan-IP: голые SYN, length=40
            "203.0.113.102": 3,
        }, syn_valid=10, syn_bare=110)
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=snap_path, server_ip="",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert len(report.new_ru_ips) == 2
        assert report.delta.syn_valid == 0
        assert report.verdict.name == "quiet"

    def test_returned_ru_ip_flagged_not_trigger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Бывший в снапшоте RU-IP с положительной дельтой — «вернувшийся»:
        в ru_top с returned=true, но вердикт НЕ триггерит (частый легитимный
        клиент не должен держать SUSPECT постоянно)."""
        self._ru_file(tmp_path, monkeypatch)
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(syn_bare=100, syn_valid=5, udp_443=0,
                                probers={"203.0.113.5": 9}, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = self._state({"203.0.113.5": 15}, syn_valid=10)
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=snap_path, server_ip="",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert report.new_ru_ips == []
        assert len(report.ru_hits) == 1
        assert report.ru_hits[0].returned is True
        assert report.ru_hits[0].delta == 6
        assert report.verdict.name == "quiet"

    def test_without_cidr_file_verdict_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(probing, "RU_CIDR_FILE", tmp_path / "absent.txt")
        current = self._state({"203.0.113.101": 2, "203.0.113.102": 3})
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=tmp_path / "snap.json", server_ip="",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert report.new_ru_ips == []
        assert report.verdict.name == "quiet"

    def test_loopback_and_snapshot_ips_excluded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ru_file = tmp_path / "ru-cidrs.txt"
        ru_file.write_text("127.0.0.0/8\n203.0.113.0/24\n", encoding="utf-8")
        monkeypatch.setattr(probing, "RU_CIDR_FILE", ru_file)
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(syn_bare=1, syn_valid=1, udp_443=0,
                                probers={"203.0.113.9": 1}, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        current = self._state({"127.0.0.1": 5, "203.0.113.9": 2}, syn_valid=5)
        report = probing.build_report(
            current, run=lambda args, **kw: _shell_result(),
            snapshot_path=snap_path, server_ip="",
            now=lambda: probing.datetime(2026, 11, 16, 12, 0, 0),
        )
        assert report.new_ru_ips == []
        # 113.9 в снапшоте и дельта = 2-1 = 1 > 0 → «вернувшийся» в ru_hits
        assert len(report.ru_hits) == 1
        assert report.ru_hits[0].ip == "203.0.113.9"


# ---------------------------------------------------------------------------
# Explain (моки)
# ---------------------------------------------------------------------------

class TestExplain:
    def test_full_coverage_with_table(self) -> None:
        fake = FakeRun({
            "nft list tables": _shell_result(TABLES_PRESENT),
            "nft list table": _shell_result(NFT_LIST_WITH_COUNTERS),
            "systemctl list-unit-files vds-xray.service":
                _shell_result("vds-xray.service enabled enabled\n"),
            "systemctl list-unit-files vds-hysteria2.service":
                _shell_result("vds-hysteria2.service enabled enabled\n"),
            "systemctl list-unit-files vds-probe-watch.timer":
                _shell_result("vds-probe-watch.timer enabled enabled\n"),
        })
        rows = probing.build_explain(fake)
        status = {r.item: r.status for r in rows}
        assert status["nft-таблица inet vds_probe"] == "ok"
        assert status["per-element counter в set probers4"] == "ok"
        assert status["юнит vds-xray.service"] == "ok"
        assert status["таймер vds-probe-watch.timer"] == "ok"
        items = [r.item for r in rows]
        assert any("IPv6" in item for item in items)
        assert any("access-log" in item for item in items)
        assert any("ufw_block_443" in item for item in items)
        assert any("udp_443" in item for item in items)
        udp_row = next(r for r in rows if "udp_443" in r.item)
        assert "QUIC-Initial" in udp_row.note
        assert "нельзя на nft-уровне" in udp_row.note

    def test_missing_table_shows_install_hint(self) -> None:
        fake = FakeRun({"nft list tables": _shell_result(TABLES_ABSENT)})
        rows = probing.build_explain(fake)
        table_row = next(r for r in rows if "vds_probe" in r.item)
        assert table_row.status == "missing"
        assert "install" in table_row.note

    def test_ru_cidr_absence_honest(self, tmp_path: Path) -> None:
        fake = FakeRun({"nft list tables": _shell_result(TABLES_ABSENT)})
        rows = probing.build_explain(fake, ru_cidr_path=tmp_path / "absent.txt")
        ru_row = next(r for r in rows if "RU-CIDR" in r.item)
        assert ru_row.status == "missing"
        assert "unknown" in ru_row.note

    def test_ru_probe_suspect_verdict_availability(self, tmp_path: Path) -> None:
        fake = FakeRun({"nft list tables": _shell_result(TABLES_ABSENT)})
        (tmp_path / "ok.txt").write_text("203.0.113.0/24\n", encoding="utf-8")
        present = probing.build_explain(fake, ru_cidr_path=tmp_path / "ok.txt")
        absent = probing.build_explain(fake, ru_cidr_path=tmp_path / "no.txt")
        ok_row = next(r for r in present if "RU-PROBE-SUSPECT" in r.item)
        no_row = next(r for r in absent if "RU-PROBE-SUSPECT" in r.item)
        assert ok_row.status == "ok"
        assert no_row.status == "missing"
        assert "недоступен" in no_row.note


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@pytest.fixture()
def _no_shell(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Любой реальный shell-вызов в dry-run — ошибка (доказываем, что не мутит)."""
    calls: list[list[str]] = []

    def _fail(args: list[str], **kwargs: Any) -> ShellResult:
        calls.append(args)
        raise AssertionError(f"dry-run не должен вызывать shell: {args}")

    monkeypatch.setattr(probing, "run_list", _fail)
    return calls


class TestInstallSnapshotReset:
    """Ревью 2026-11-16 (edge-case 3d): install --apply сбрасывает снапшот —
    иначе первый watch после переустановки дал бы ложную «отрицательную
    дельту» (0-до-догона) против старых счётчиков."""

    def test_install_resets_snapshot(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        snap_path = tmp_path / "snap.json"
        prev = probing.NftState(syn_bare=5000, syn_valid=4000,
                                probers={"203.0.113.5": 100}, per_element_counters=True)
        assert probing.save_snapshot(prev, snap_path)
        monkeypatch.setattr(probing, "SNAPSHOT_PATH", snap_path)
        monkeypatch.setattr(probing, "LOCK_FILE", str(tmp_path / "probe.lock"))
        monkeypatch.setattr(probing, "_atomic_write", lambda path, text, mode: True)
        monkeypatch.setattr(probing, "_apply_nft", lambda pec: (True, True))
        monkeypatch.setattr(probing, "run_list", lambda args, **kw: _shell_result())
        import src.core.units as units_mod
        monkeypatch.setattr(units_mod, "install_unit", lambda *a, **kw: True)

        assert probing.cmd_install(apply=True) == 0

        snap = probing.load_snapshot(snap_path)
        assert snap["syn_bare"] == 0 and snap["probers"] == {}
        # дельта с нуля, не 0-до-догона:
        current = probing.NftState(syn_bare=3, syn_valid=2, per_element_counters=True)
        delta = probing.compute_delta(current, snap)
        assert delta.syn_bare == 3


class TestCLI:
    def test_help_lists_subcommands(self) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "--help"])
        assert result.exit_code == 0
        for name in ("install", "watch", "explain", "remove"):
            assert name in result.output

    def test_install_dry_run_does_not_mutate(self, _no_shell: list[list[str]]) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "install"])
        assert result.exit_code == 0
        assert "DRY-RUN" in result.output
        assert _no_shell == []

    def test_remove_dry_run_does_not_mutate(self, _no_shell: list[list[str]]) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "remove"])
        assert result.exit_code == 0
        assert "DRY-RUN" in result.output
        assert _no_shell == []

    def test_install_requires_root_for_apply(
        self, monkeypatch: pytest.MonkeyPatch, _no_shell: list[list[str]]
    ) -> None:
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        result = runner.invoke(app, ["gateway", "probe-watch", "install", "--apply"])
        assert result.exit_code == 1
        assert "root" in result.output

    def test_watch_requires_nh_time_format(self, _no_shell: list[list[str]]) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "watch", "--since", "tomorrow"])
        assert result.exit_code == 1
        assert _no_shell == []

    def test_watch_calls_cmd_watch_with_parsed_args(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict[str, Any] = {}

        def _cmd(**kw: Any) -> int:
            recorded.update(kw)
            return 0

        monkeypatch.setattr(probing, "cmd_watch", _cmd)
        result = runner.invoke(
            app,
            ["gateway", "probe-watch", "watch", "--since", "2h",
             "--threshold", "77", "--json"],
        )
        assert result.exit_code == 0
        assert recorded == {
            "since_hours": 2, "threshold": 77, "json_out": True, "record": False,
        }

    def test_explain_flag_via_callback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[bool] = []

        def _cmd(run: Any = None) -> int:
            called.append(True)
            return 0

        monkeypatch.setattr(probing, "cmd_explain", _cmd)
        result = runner.invoke(app, ["gateway", "probe-watch", "--explain"])
        assert result.exit_code == 0
        assert called == [True]

    def test_watch_help_has_examples(self) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "watch", "--help"])
        assert result.exit_code == 0
        for flag in ("--since", "--threshold", "--json"):
            assert flag in result.output
        assert "PROBE-BURST" in result.output

    def test_install_help_full(self) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "install", "--help"])
        assert result.exit_code == 0
        assert "--apply" in result.output

    def test_no_secrets_in_any_help(self) -> None:
        for args in (
            ["gateway", "probe-watch", "--help"],
            ["gateway", "probe-watch", "install", "--help"],
            ["gateway", "probe-watch", "watch", "--help"],
            ["gateway", "probe-watch", "remove", "--help"],
        ):
            result = runner.invoke(app, args)
            out = result.output.lower()
            assert "password" not in out and "uuid" not in out

    def test_watch_cli_end_to_end_mocked(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """cmd_watch: read-only путь с моками nft/journal; без --record
        снапшот НЕ пишется (фейк-fs), с --record — пишется."""
        monkeypatch.setattr(
            probing, "list_nft_table",
            lambda run=None: probing.parse_nft_table(NFT_LIST_WITH_COUNTERS),
        )
        monkeypatch.setattr(probing, "scan_journal", lambda since, run=None, **kw: [])
        monkeypatch.setattr(probing, "load_ru_cidrs", lambda path=None: None)
        monkeypatch.setattr(probing, "SNAPSHOT_PATH", tmp_path / "snap.json")
        monkeypatch.setattr(probing, "LOCK_FILE", str(tmp_path / "probe.lock"))
        snap_path = tmp_path / "snap.json"

        # watch без --record: read-only — файл не появляется
        result = runner.invoke(
            app,
            ["gateway", "probe-watch", "watch", "--since", "1h", "--threshold", "50"],
        )
        assert result.exit_code == 0
        assert not snap_path.exists()
        assert "Вердикт" in result.output

        # watch --record (семантика юнита таймера): снапшот записан
        result = runner.invoke(
            app,
            ["gateway", "probe-watch", "watch", "--since", "1h", "--record"],
        )
        assert result.exit_code == 0
        assert snap_path.is_file()
        data = json.loads(snap_path.read_text(encoding="utf-8"))
        assert data["syn_bare"] == 150
        assert data["udp_443"] == 60

    def test_watch_help_documents_record_flag(self) -> None:
        result = runner.invoke(app, ["gateway", "probe-watch", "watch", "--help"])
        assert result.exit_code == 0
        assert "--record" in result.output
        assert "таймер" in result.output.lower()
