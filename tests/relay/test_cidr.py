"""Тесты CIDR-агрегации и обновления RU-CIDR (SPEC WP-4; сеть — моки)."""

import pytest

import src.relay.cidr as cidr_mod
from src.relay.cidr import aggregate


class TestAggregate:
    def test_adjacent_sl24_merge(self):
        # /23 выравнивается по чётной сети: 112+113 склеиваются,
        # 113+114 — НЕ склеиваются (113 на границе /23).
        assert aggregate(["203.0.112.0/24", "203.0.113.0/24"]) == ["203.0.112.0/23"]
        assert aggregate(["203.0.113.0/24", "203.0.114.0/24"]) == ["203.0.113.0/24", "203.0.114.0/24"]

    def test_redundant_collapses(self):
        assert aggregate(["203.0.113.0/24", "203.0.113.0/22"]) == ["203.0.112.0/22"]

    def test_disjoint_kept_sorted(self):
        out = aggregate(["203.0.113.0/24", "198.51.100.0/24"])
        assert out == ["198.51.100.0/24", "203.0.113.0/24"]

    def test_bad_input_rejected(self):
        with pytest.raises(ValueError):
            aggregate(["not-a-cidr"])

    def test_host_bits_normalized(self):
        assert aggregate(["203.0.113.77/24"]) == ["203.0.113.0/24"]


class TestUpdate:
    def test_update_writes_and_applies(self, tmp_path, monkeypatch):
        import os

        cidr_list = tmp_path / "ru-cidrs.txt"
        nft_file = tmp_path / "nft-policy.conf"
        monkeypatch.setattr(cidr_mod, "RELAY_CIDR_LIST", cidr_list)
        monkeypatch.setattr(cidr_mod, "RELAY_NFT_POLICY_FILE", nft_file)
        monkeypatch.setattr(cidr_mod, "RELAY_DIR", tmp_path)
        monkeypatch.setattr(cidr_mod, "fetch", lambda timeout=60: ["203.0.112.0/24", "203.0.113.0/24"])

        calls: list[list[str]] = []

        def fake_run_list(args, timeout=None, check=False):
            calls.append(list(args))
            from src.core.shell import ShellResult

            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(cidr_mod, "run_list", fake_run_list)
        rc = cidr_mod.update()
        assert rc == 0
        assert cidr_list.read_text(encoding="utf-8").strip() == "203.0.112.0/23"
        nft_text = nft_file.read_text(encoding="utf-8")
        assert "203.0.112.0/23" in nft_text
        assert os.path.exists(nft_file) and (nft_file.stat().st_mode & 0o777) == 0o644
        assert calls == [["nft", "-f", str(nft_file)]]

    def test_fetch_failure_leaves_old_files(self, tmp_path, monkeypatch):
        cidr_list = tmp_path / "ru-cidrs.txt"
        nft_file = tmp_path / "nft-policy.conf"
        cidr_list.write_text("203.0.113.0/24\n", encoding="utf-8")
        nft_file.write_text("old\n", encoding="utf-8")
        monkeypatch.setattr(cidr_mod, "RELAY_CIDR_LIST", cidr_list)
        monkeypatch.setattr(cidr_mod, "RELAY_NFT_POLICY_FILE", nft_file)
        monkeypatch.setattr(cidr_mod, "RELAY_DIR", tmp_path)

        def boom(timeout=60):
            raise RuntimeError("HTTP 503")

        monkeypatch.setattr(cidr_mod, "fetch", boom)
        rc = cidr_mod.update()
        assert rc == 1
        assert cidr_list.read_text(encoding="utf-8").strip() == "203.0.113.0/24"
        assert nft_file.read_text(encoding="utf-8") == "old\n"

    def test_nft_failure_reports_but_files_updated(self, tmp_path, monkeypatch):
        cidr_list = tmp_path / "ru-cidrs.txt"
        nft_file = tmp_path / "nft-policy.conf"
        monkeypatch.setattr(cidr_mod, "RELAY_CIDR_LIST", cidr_list)
        monkeypatch.setattr(cidr_mod, "RELAY_NFT_POLICY_FILE", nft_file)
        monkeypatch.setattr(cidr_mod, "RELAY_DIR", tmp_path)
        monkeypatch.setattr(cidr_mod, "fetch", lambda timeout=60: ["203.0.113.0/24"])

        from src.core.shell import ShellResult

        monkeypatch.setattr(
            cidr_mod, "run_list",
            lambda args, timeout=None: ShellResult(stdout="", stderr="syntax error", returncode=1),
        )
        assert cidr_mod.update() == 1
        assert "203.0.113.0/24" in nft_file.read_text(encoding="utf-8")
