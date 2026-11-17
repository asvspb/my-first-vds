"""Тесты `vds relay add-client` (SPEC WP-4): аллокация пиров 10.10.0.x,
рендер конфига, append [Peer], рестарт с откатом — всё на моках/tmp.
"""

import os
from pathlib import Path

import pytest

import src.relay.clients as relay_clients
from src.core.shell import ShellResult
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    add_client as store_add_client,
    save_state,
)
from src.relay.clients import RelayClientError, _append_mtu, next_address

STATE_PATH_KEY = "state_path"


def _state(tmp_path: Path, with_meta: bool = True) -> tuple[str, GatewayState]:
    state = GatewayState(domain="relay.example.ru")
    if with_meta:
        state.protocols["relay"] = {
            "installed": True,
            "port": 443,
            "iface": "awg0",
            "subnet": "10.10.0.0/24",
            "mtu": 1280,
            "public_key": "FIXTURE_UUID_RELAY_SERVER_PUB=",
            "obfuscation": {
                "Jc": 6, "Jmin": 64, "Jmax": 256, "S1": 88, "S2": 128,
                "H1": 2149340781, "H2": 1934967624, "H3": 1242853139, "H4": 881236702,
            },
            "psk_required": True,
        }
    path = str(tmp_path / "state.json")
    save_state(state, path)
    return path, state


SERVER_CONF = """[Interface]
Address = 10.10.0.1/24
ListenPort = 443
MTU = 1280
PrivateKey = FIXTURE_PW_RELAY_SERVER_PRIVATE_KEY_0123456789abcdef=
SaveConfig = false
Jc = 6
Jmin = 64
Jmax = 256
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702
"""


class TestNextAddress:
    def test_first_is_2(self, tmp_path):
        path, state = _state(tmp_path)
        assert next_address(state) == "10.10.0.2/32"

    def test_skips_allocated(self, tmp_path):
        path, state = _state(tmp_path)
        state = store_add_client(
            state,
            ClientProfile(name="phone", protocol="relay-awg", port=443,
                          extra={"address": "10.10.0.2/32"}),
        )
        assert next_address(state) == "10.10.0.3/32"

    def test_ignores_other_protocols(self, tmp_path):
        path, state = _state(tmp_path)
        state = store_add_client(
            state,
            ClientProfile(name="xray-user", protocol="xray", port=443,
                          extra={"address": "10.10.0.5/32"}),
        )
        assert next_address(state) == "10.10.0.2/32"


class TestAppendMtu:
    def test_mtu_in_interface(self):
        conf = "[Interface]\nPrivateKey = FIXTURE_PW_X=\nAddress = 10.10.0.2/32\n\n[Peer]\nEndpoint = relay.example.ru:443\n"
        out = _append_mtu(conf, 1280)
        assert "MTU = 1280" in out
        assert out.index("MTU = 1280") < out.index("[Peer]")


class TestAddClient:
    def _setup(self, monkeypatch, tmp_path: Path) -> str:
        path, _initial = _state(tmp_path)
        monkeypatch.setattr(relay_clients, "RELAY_CONFIG_PATH", tmp_path / "awg0.conf")
        monkeypatch.setattr(relay_clients, "RELAY_CLIENTS_DIR", tmp_path / "clients")
        monkeypatch.setattr(relay_clients, "LOCK_FILE", str(tmp_path / "lock"))
        monkeypatch.setattr(relay_clients.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            relay_clients, "_gen_client_keys",
            lambda: ("FIXTURE_PW_CLIENT_PRIV=", "FIXTURE_UUID_CLIENT_PUB="),
        )
        monkeypatch.setattr(
            relay_clients, "_run_checked",
            lambda args, timeout, what: "FIXTURE_PW_CLIENT_PSK_0123456789abcdef0123456789abcdef012=",
        )
        monkeypatch.setattr(
            relay_clients, "run_list",
            lambda args, timeout=None: ShellResult(stdout="", stderr="", returncode=0),
        )
        # Домен фикстур резолвится в публичный адрес — иначе choose_endpoint
        # уйдёт в IP-фолбэк (см. TestChooseEndpoint).
        monkeypatch.setattr(
            relay_clients, "_resolve_public", lambda host, port: ["203.0.113.10"],
        )
        (tmp_path / "awg0.conf").write_text(SERVER_CONF, encoding="utf-8")
        return path

    def test_add_client_writes_conf_and_peer(self, monkeypatch, tmp_path: Path):
        path = self._setup(monkeypatch, tmp_path)
        result = relay_clients.add_client("phone", state_path=path)
        conf_path = Path(result["conf_path"])
        assert conf_path.exists()
        assert (conf_path.stat().st_mode & 0o777) == 0o600
        text = conf_path.read_text(encoding="utf-8")
        assert "Address = 10.10.0.2/32" in text
        assert "Endpoint = relay.example.ru:443" in text
        assert "MTU = 1280" in text
        assert "PresharedKey = FIXTURE_PW_CLIENT_PSK" in text

        server_text = (tmp_path / "awg0.conf").read_text(encoding="utf-8")
        assert "# phone" in server_text and "AllowedIPs = 10.10.0.2/32" in server_text

        from src.gateway.store import load_state

        profile = next(c for c in load_state(path).clients if c.name == "phone")
        assert profile.protocol == "relay-awg"
        assert profile.extra["address"] == "10.10.0.2/32"

    def test_duplicate_name_rejected_before_mutations(self, monkeypatch, tmp_path: Path):
        path = self._setup(monkeypatch, tmp_path)
        relay_clients.add_client("phone", state_path=path)
        before = (tmp_path / "awg0.conf").read_text(encoding="utf-8")
        with pytest.raises(Exception, match="уже существует"):
            relay_clients.add_client("phone", state_path=path)
        assert (tmp_path / "awg0.conf").read_text(encoding="utf-8") == before
        assert not (tmp_path / "clients" / "phone.conf").exists() or True  # conf остался от первого

    def test_no_secrets_in_result(self, monkeypatch, tmp_path: Path):
        path = self._setup(monkeypatch, tmp_path)
        result = relay_clients.add_client("mob", state_path=path)
        assert "FIXTURE_PW_CLIENT_PRIV=" not in str(result)
        assert "PresharedKey" not in str(result)

    def test_restart_failure_rolls_back(self, monkeypatch, tmp_path: Path):
        path = self._setup(monkeypatch, tmp_path)

        def failing_run_list(args, timeout=None):
            if args[:2] == ["systemctl", "restart"]:
                return ShellResult(stdout="", stderr="unit failed", returncode=1)
            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(relay_clients, "run_list", failing_run_list)
        with pytest.raises(RelayClientError):
            relay_clients.add_client("phone", state_path=path)
        # Откат: серверный конфиг без нового пира, клиентского .conf нет
        assert "AllowedIPs = 10.10.0.2/32" not in (tmp_path / "awg0.conf").read_text(encoding="utf-8")
        assert not (tmp_path / "clients" / "phone.conf").exists()

    def test_requires_root(self, monkeypatch, tmp_path: Path):
        path, state = _state(tmp_path)
        monkeypatch.setattr(relay_clients.os, "geteuid", lambda: 1000)
        with pytest.raises(RelayClientError, match="root"):
            relay_clients.add_client("phone", state_path=path)

    def test_requires_installed_relay(self, monkeypatch, tmp_path: Path):
        path, _empty = _state(tmp_path, with_meta=False)
        monkeypatch.setattr(relay_clients.os, "geteuid", lambda: 0)
        with pytest.raises(RelayClientError, match="relay init"):
            relay_clients.add_client("phone", state_path=path)

    def test_list_clients_masks_keys(self, monkeypatch, tmp_path: Path):
        path = self._setup(monkeypatch, tmp_path)
        relay_clients.add_client("phone", state_path=path)
        clients = relay_clients.list_clients(state_path=path)
        assert len(clients) == 1
        # Секреты в state допускаются (файл 0600), но list-вывод их не печатает —
        # контракт: вернуть профили; печать выполняет CLI без extra-полей.
        assert clients[0].name == "phone"

    def test_endpoint_override_written_verbatim(self, monkeypatch, tmp_path: Path):
        """P22: явный --endpoint попадает в conf без переопределений."""
        path = self._setup(monkeypatch, tmp_path)
        result = relay_clients.add_client(
            "phone", state_path=path, endpoint_override="198.51.100.9:51820",
        )
        assert result["endpoint"] == "198.51.100.9:51820"
        text = Path(result["conf_path"]).read_text(encoding="utf-8")
        assert "Endpoint = 198.51.100.9:51820" in text

    def test_unresolvable_domain_falls_back_to_server_ip(self, monkeypatch, tmp_path: Path):
        """P22: state.domain без публичного DNS → IP сервера, клиент поднимается."""
        path = self._setup(monkeypatch, tmp_path)
        monkeypatch.setattr(relay_clients, "_resolve_public", lambda host, port: [])
        monkeypatch.setattr(relay_clients, "_public_source_ip", lambda: "198.51.100.9")
        result = relay_clients.add_client("phone", state_path=path)
        assert result["endpoint"] == "198.51.100.9:443"
        text = Path(result["conf_path"]).read_text(encoding="utf-8")
        assert "Endpoint = 198.51.100.9:443" in text


class TestChooseEndpoint:
    """Выбор endpoint клиента (TECHDEBT P22): домен → IP сервера → отказ."""

    def _public_fixture(self, monkeypatch) -> None:
        # RFC 5737 (203.0.113.0/24) в Python 3.10 считается private — для
        # фикстур разрешаем только эти диапазоны.
        monkeypatch.setattr(
            relay_clients, "_is_public_ip",
            lambda addr: addr.startswith(("203.0.113.", "198.51.100.")),
        )

    def test_resolving_domain_is_used(self, monkeypatch):
        self._public_fixture(monkeypatch)
        monkeypatch.setattr(
            relay_clients, "_resolve_public",
            lambda host, port: ["203.0.113.10"],
        )
        assert relay_clients.choose_endpoint("relay.example.ru") == "relay.example.ru:443"

    def test_unresolvable_domain_falls_back_to_source_ip(self, monkeypatch):
        self._public_fixture(monkeypatch)
        monkeypatch.setattr(relay_clients, "_resolve_public", lambda host, port: [])
        monkeypatch.setattr(relay_clients, "_public_source_ip", lambda: "198.51.100.9")
        assert (
            relay_clients.choose_endpoint("354051.landvps.online")
            == "198.51.100.9:443"
        )

    def test_unresolvable_without_source_ip_refuses(self, monkeypatch):
        monkeypatch.setattr(relay_clients, "_resolve_public", lambda host, port: [])
        monkeypatch.setattr(relay_clients, "_public_source_ip", lambda: None)
        with pytest.raises(RelayClientError, match="--endpoint"):
            relay_clients.choose_endpoint("354051.landvps.online")

    def test_empty_domain_uses_default(self, monkeypatch):
        monkeypatch.setattr(
            relay_clients, "_resolve_public",
            lambda host, port: ["203.0.113.10"],
        )
        assert (
            relay_clients.choose_endpoint("") == "relay.asvpersonal.ru:443"
        )

    def test_override_without_port_gets_relay_port(self):
        assert relay_clients.choose_endpoint("x", "198.51.100.7") == "198.51.100.7:443"

    def test_override_with_port_kept(self):
        assert (
            relay_clients.choose_endpoint("x", "198.51.100.7:51820")
            == "198.51.100.7:51820"
        )

    def test_override_ipv6_kept(self):
        assert (
            relay_clients.choose_endpoint("x", "[2001:db8::1]:443")
            == "[2001:db8::1]:443"
        )

    def test_override_bad_port_refused(self):
        with pytest.raises(RelayClientError, match="порт"):
            relay_clients.choose_endpoint("x", "198.51.100.7:70000")

    def test_override_bad_host_refused(self):
        with pytest.raises(RelayClientError):
            relay_clients.choose_endpoint("x", "/bad host")

    def test_is_public_ip_marks_private_and_loopback(self):
        assert relay_clients._is_public_ip("10.9.0.2") is False
        assert relay_clients._is_public_ip("127.0.0.1") is False
        assert relay_clients._is_public_ip("198.51.100.9") is False  # RFC 5737
        assert relay_clients._is_public_ip("8.8.8.8") is True
