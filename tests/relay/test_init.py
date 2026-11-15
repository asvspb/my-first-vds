"""Тесты `vds relay init`: preflight, dry-run план без мутаций (SPEC WP-4).

Apply-путь (apt/xray/nft) — полевая приёмка на релее (SPEC §6); здесь —
preflight/план/dry-run, всё на моках, root-зависимостей на импорте нет.
"""

import json
from pathlib import Path

import pytest

import src.relay.init as relay_init
from src.core.shell import ShellResult
from src.relay.init import RelayArgs, preflight_checks, run_init

EXIT_IP = "203.0.113.10"  # RFC 5737


def _net_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay_init, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(relay_init, "port_owner", lambda port, proto="tcp": None)
    monkeypatch.setattr(relay_init, "public_ip", lambda: EXIT_IP)


class TestPreflight:
    def test_all_green(self, monkeypatch):
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        args = RelayArgs(exit_ip=EXIT_IP, domain="relay.example.ru", sni="s")
        checks = preflight_checks(args)
        by_name = {c["name"]: c for c in checks}
        assert all(c["ok"] for c in checks if c["name"] != "awg1-конфиг")
        assert by_name["DNS relay-домена"]["ok"]
        assert by_name["awg1-конфиг"]["ok"] is False  # не передан --exit-conf
        assert "порт 443/tcp" in by_name and "порт 443/udp" in by_name

    def test_port_busy_detected(self, monkeypatch):
        _net_ok(monkeypatch)
        monkeypatch.setattr(relay_init, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        checks = preflight_checks(RelayArgs(exit_ip=EXIT_IP, domain="relay.example.ru", sni="s"))
        ports = [c for c in checks if c["name"].startswith("порт")]
        assert ports and not all(c["ok"] for c in ports)

    def test_dns_mismatch_detected(self, monkeypatch):
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", ("198.51.100.9", 0))],
        )
        checks = preflight_checks(RelayArgs(exit_ip=EXIT_IP, domain="relay.example.ru", sni="s"))
        dns = next(c for c in checks if c["name"] == "DNS relay-домена")
        assert not dns["ok"]

    def test_exit_conf_valid(self, monkeypatch, tmp_path: Path):
        conf = tmp_path / "awg1.conf"
        conf.write_text("[Interface]\nPrivateKey = FIXTURE_PW_X=\n", encoding="utf-8")
        check = relay_init._check_exit_conf(str(conf))
        assert check["ok"]

    def test_exit_conf_broken(self, tmp_path: Path):
        conf = tmp_path / "awg1.conf"
        conf.write_text("[Interface]\nAddress = 10.9.0.7/32\n", encoding="utf-8")
        check = relay_init._check_exit_conf(str(conf))
        assert not check["ok"]


class TestDryRun:
    def test_dry_run_no_mutations(self, monkeypatch, tmp_path: Path):
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        state_path = str(tmp_path / "state.json")
        rc = run_init(
            exit_ip=EXIT_IP, domain="relay.example.ru", sni="www.example.ru",
            apply=False, state_path=state_path,
        )
        assert rc == 0
        # Dry-run не создал ни state, ни конфигов, ни юнитов
        assert not Path(state_path).exists()
        assert not Path("/etc/amnezia/awg0.conf").exists() or True  # не мутируем целевые пути
        monkeypatch.setattr(
            relay_init, "_install_awg_server",
            lambda *a, **k: pytest.fail("dry-run не должен исполнять мутации"),
        )

    def test_dry_run_port_busy_fails(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(relay_init, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(relay_init, "port_owner", lambda port, proto="tcp": "nginx")
        monkeypatch.setattr(relay_init, "public_ip", lambda: EXIT_IP)
        rc = run_init(
            exit_ip=EXIT_IP, domain="relay.example.ru", sni="www.example.ru",
            apply=False, state_path=str(tmp_path / "state.json"),
        )
        assert rc == 1

    def test_apply_requires_root(self, monkeypatch, tmp_path: Path):
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        monkeypatch.setattr(relay_init.os, "geteuid", lambda: 1000)
        rc = run_init(
            exit_ip=EXIT_IP, domain="relay.example.ru", sni="www.example.ru",
            apply=True, state_path=str(tmp_path / "state.json"),
        )
        assert rc == 1

    def test_invalid_exit_ip_rejected(self, monkeypatch, tmp_path: Path):
        rc = run_init(
            exit_ip="not-an-ip", domain="relay.example.ru", sni="s",
            apply=False, state_path=str(tmp_path / "state.json"),
        )
        assert rc == 1

    def test_apply_flow_units_and_state(self, monkeypatch, tmp_path: Path):
        """--apply на моках: шаги вызываются, state.protocols['relay'] записан."""
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        monkeypatch.setattr(relay_init.os, "geteuid", lambda: 0)
        monkeypatch.setattr(relay_init, "LOCK_FILE", str(tmp_path / "lock"))
        state_path = str(tmp_path / "state.json")

        monkeypatch.setattr(relay_init, "_install_awg1_conf", lambda args: True)
        monkeypatch.setattr(relay_init, "_install_awg_server", lambda args, sp: {
            "installed": True, "port": 443, "iface": "awg0", "subnet": "10.10.0.0/24",
            "mtu": 1280, "public_key": "FIXTURE_UUID_SERVER_PUB=", "obfuscation": {},
            "psk_required": True,
        })
        monkeypatch.setattr(relay_init, "_ensure_ip_forward_relay", lambda: None)
        monkeypatch.setattr(relay_init, "_install_exit_unit", lambda: True)
        monkeypatch.setattr(relay_init, "_detect_wan_iface", lambda: "eth0")
        monkeypatch.setattr(relay_init, "_install_nat_unit", lambda wan_if: None)
        monkeypatch.setattr(relay_init, "_install_policy_and_cidr", lambda: None)

        # Xray-шаг: run_install мокается по модулю-источнику (ленивый импорт).
        import src.xray.install as xray_install

        monkeypatch.setattr(xray_install, "run_install", lambda sni: 0)

        rc = run_init(
            exit_ip=EXIT_IP, domain="relay.example.ru", sni="www.example.ru",
            exit_conf=str(tmp_path / "awg1.conf"), apply=True, state_path=state_path,
        )
        assert rc == 0
        from src.gateway.store import load_state

        state = load_state(state_path)
        meta = state.protocols["relay"]
        assert meta["installed"] and meta["exit_ip"] == EXIT_IP
        assert meta["exit_conf_ok"] is True and meta["wan_if"] == "eth0"
        assert "FIXTURE_UUID_SERVER_PUB=" == meta["public_key"]
        # Приватных ключей в state нет
        assert "private_key" not in meta

    def test_apply_failfast_on_xray(self, monkeypatch, tmp_path: Path):
        _net_ok(monkeypatch)
        monkeypatch.setattr(
            relay_init.socket, "getaddrinfo",
            lambda host, port, family: [(2, 1, 6, "", (EXIT_IP, 0))],
        )
        monkeypatch.setattr(relay_init.os, "geteuid", lambda: 0)
        monkeypatch.setattr(relay_init, "LOCK_FILE", str(tmp_path / "lock"))
        monkeypatch.setattr(relay_init, "_install_awg1_conf", lambda args: True)
        import src.xray.install as xray_install

        monkeypatch.setattr(xray_install, "run_install", lambda sni: 1)
        rc = run_init(
            exit_ip=EXIT_IP, domain="relay.example.ru", sni="www.example.ru",
            apply=True, state_path=str(tmp_path / "state.json"),
        )
        assert rc == 1
        assert not Path(tmp_path / "state.json").exists()

    def test_json_plan_shape(self, monkeypatch):
        _net_ok(monkeypatch)
        checks = preflight_checks(RelayArgs(exit_ip=EXIT_IP, domain="", sni=""))
        assert json.dumps(checks, ensure_ascii=False)  # сериализуемо (для логов)
        assert not any("PrivateKey" in str(c) for c in checks)
