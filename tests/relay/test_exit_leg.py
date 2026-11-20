"""Тесты `vds relay exit-leg` (ADR-015, SPEC-20261120 WP-M2 / TECHDEBT P24).

Всё на моках: ни root, ни сети, ни systemd, ни nft. Проверяются чистые
рендеры (конфиг awg2, nft-правила, UFW-строка), идемпотентность apply,
откат remove и отказ на релее. Реальный `awg-quick`/`nft` — полевая приёмка.
"""

from __future__ import annotations

import json
import random
import stat
from pathlib import Path

import pytest

import src.relay.exit_leg as exit_leg
from src.amneziawg.config import gen_obfuscation_params
from src.core.shell import ShellResult
from src.relay.exit_leg import (
    ExitLegError,
    parse_pool,
    render_exit_leg_conf,
    render_nft_leg,
    render_pool_script,
    run_install,
    run_remove,
    validate_public_key,
    validate_relay_ip,
)
from src.relay.paths import (
    EXIT_LEG_BASE_PORT,
    EXIT_LEG_IP,
    EXIT_LEG_PEER_IP,
    EXIT_LEG_POOL,
    EXIT_LEG_SUBNET,
)

RELAY_IP = "203.0.113.7"  # RFC 5737 — фикстура, не реальный адрес
RELAY_PUB = "FIXTURE_PUBKEY_RELAY_AWG1_000000000000="
EXIT_LEG_PRIV = "FIXTURE_PRIVKEY_AWG2_000000000000000000="


def _obf() -> dict:
    return gen_obfuscation_params(random.Random(20261120))


# ---------------------------------------------------------------------------
# Чистые рендеры
# ---------------------------------------------------------------------------

class TestRenderConf:
    def test_awg2_conf_single_peer_keepalive(self):
        text = render_exit_leg_conf(private_key=EXIT_LEG_PRIV, public_key=RELAY_PUB, obf=_obf())
        assert "Address = 10.11.0.1/30" in text
        assert f"ListenPort = {EXIT_LEG_BASE_PORT}" in text
        assert f"MTU = {exit_leg.EXIT_LEG_MTU}" in text
        assert text.count("[Peer]") == 1
        assert f"PublicKey = {RELAY_PUB}" in text
        assert f"AllowedIPs = {EXIT_LEG_PEER_IP}/32" in text
        assert "PersistentKeepalive = 25" in text
        assert "PresharedKey" not in text
        # Обфускация 1.5 на месте (переиспользован render_server_conf).
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            assert f"{key} = " in text

    def test_address_matches_spec_subnet(self):
        text = render_exit_leg_conf(private_key=EXIT_LEG_PRIV, public_key=RELAY_PUB, obf=_obf())
        assert EXIT_LEG_SUBNET == "10.11.0.0/30"
        assert f"Address = {EXIT_LEG_IP}/30" in text

    def test_deterministic(self):
        first = render_exit_leg_conf(private_key=EXIT_LEG_PRIV, public_key=RELAY_PUB, obf=_obf())
        second = render_exit_leg_conf(private_key=EXIT_LEG_PRIV, public_key=RELAY_PUB, obf=_obf())
        assert first == second


class TestRenderNft:
    def test_redirect_from_relay_and_silent_drop(self):
        text = render_nft_leg(RELAY_IP)
        assert f"table inet {exit_leg.EXIT_LEG_NFT_TABLE}" in text
        assert "type nat hook prerouting priority dstnat" in text
        assert (
            f"ip saddr {RELAY_IP} udp dport {EXIT_LEG_POOL} "
            f"redirect to :{EXIT_LEG_BASE_PORT}"
        ) in text
        assert f"udp dport {EXIT_LEG_POOL} drop" in text
        # REDIRECT только на P_base — пул не слушается напрямую.
        assert text.count("redirect to") == 1

    def test_external_ip_not_in_redirect(self):
        text = render_nft_leg(RELAY_IP)
        assert "198.51.100.9" not in text
        assert text.count(RELAY_IP) == 1

    def test_bad_ip_rejected(self):
        with pytest.raises(ExitLegError):
            render_nft_leg("not-an-ip")
        with pytest.raises(ExitLegError):
            render_nft_leg("2001:db8::1")


class TestRenderPoolScript:
    def test_script_applies_nft_and_ufw_single_port(self):
        text = render_pool_script(RELAY_IP)
        assert text.startswith("#!/bin/sh")
        assert "set -eu" in text
        assert f"nft -f {exit_leg.EXIT_LEG_NFT_FILE}" in text
        assert (
            f"ufw allow from {RELAY_IP} to any port {EXIT_LEG_BASE_PORT} proto udp"
        ) in text
        # Весь пул в UFW не открывается — только P_base.
        assert f"to any port {EXIT_LEG_BASE_PORT}" in text
        assert "51911" not in text.split("ufw allow")[1]
        assert "FIXTURE" not in text  # секретов в артефакте нет


class TestValidation:
    def test_pool_parsed(self):
        ports = parse_pool(EXIT_LEG_POOL)
        assert ports[0] == 51900 and ports[-1] == 51911 and len(ports) == 12

    @pytest.mark.parametrize("bad", ["", "51900", "51911-51900", "80-90", "a-b", "51900-51911-1"])
    def test_pool_rejects_garbage(self, bad):
        with pytest.raises(ValueError):
            parse_pool(bad)

    def test_relay_ip_v4_only(self):
        assert validate_relay_ip(" 203.0.113.7 ") == RELAY_IP
        with pytest.raises(ExitLegError):
            validate_relay_ip("2001:db8::1")
        with pytest.raises(ExitLegError):
            validate_relay_ip("")

    def test_public_key_single_token(self):
        assert validate_public_key(f" {RELAY_PUB} ") == RELAY_PUB
        with pytest.raises(ExitLegError):
            validate_public_key("")
        with pytest.raises(ExitLegError):
            validate_public_key("two tokens")


# ---------------------------------------------------------------------------
# Моки системы
# ---------------------------------------------------------------------------

class FakeRunner:
    """prefix-match мок `run_list`; пишет все вызовы и помечает юниты активными."""

    def __init__(self, systemd: "FakeSystemd", mapping=None):
        self.systemd = systemd
        self.mapping = mapping or {}
        self.calls: list[list[str]] = []
        self.nft_table_present = False

    def __call__(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        for key, res in self.mapping.items():
            if list(args)[: len(key)] == list(key):
                return res
        if list(args[:2]) == ["nft", "list"]:
            return ShellResult("", "", 0 if self.nft_table_present else 1)
        if list(args[:2]) == ["nft", "delete"]:
            self.nft_table_present = False
            return ShellResult("", "", 0)
        if list(args[:2]) == ["systemctl", "restart"]:
            self.systemd.active.add(args[2])
            return ShellResult("", "", 0)
        return ShellResult("", "", 0)

    def commands(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


class FakeSystemd:
    def __init__(self):
        self.active: set[str] = set()
        self.installed: list[str] = []
        self.removed: list[str] = []

    def install(self, template, name, ctx=None, root="/"):
        self.installed.append(name)
        return True

    def is_active(self, name):
        return name in self.active

    def remove(self, name, root="/"):
        self.removed.append(name)
        self.active.discard(name)
        return True


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Изолированные пути + моки systemd/run_list; узел выглядит как exit."""
    awg0 = tmp_path / "awg0.conf"
    awg0.write_text("[Interface]\nListenPort = 51825\n", encoding="utf-8")

    monkeypatch.setattr(exit_leg, "AWG_CONFIG_PATH", awg0)
    monkeypatch.setattr(exit_leg, "RELAY_EXIT_CONFIG_PATH", tmp_path / "awg1.conf")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_CONFIG_PATH", tmp_path / "amnezia" / "awg2.conf")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_NFT_FILE", tmp_path / "relay-leg.nft")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_POOL_SCRIPT", tmp_path / "pool-apply.sh")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_LOCK_FILE", str(tmp_path / "leg.lock"))
    monkeypatch.setattr(exit_leg.os, "geteuid", lambda: 0)

    runner = FakeRunner(FakeSystemd())
    systemd = runner.systemd
    monkeypatch.setattr(exit_leg, "run_list", runner)
    monkeypatch.setattr(exit_leg, "install_unit", systemd.install)
    monkeypatch.setattr(exit_leg, "unit_active", systemd.is_active)
    monkeypatch.setattr(exit_leg, "remove_unit", systemd.remove)
    monkeypatch.setattr(exit_leg, "_ufw_present", lambda: True)

    keys = []

    def fake_keys():
        keys.append(1)
        return EXIT_LEG_PRIV, "FIXTURE_PUBKEY_AWG2_NODE_0000000000="

    monkeypatch.setattr(exit_leg, "_gen_server_keys", fake_keys)

    return {
        "tmp": tmp_path,
        "runner": runner,
        "systemd": systemd,
        "keys": keys,
        "state": str(tmp_path / "state.json"),
        "awg0": awg0,
    }


def _install(env, apply=True):
    return run_install(RELAY_IP, RELAY_PUB, apply=apply, state_path=env["state"])


# ---------------------------------------------------------------------------
# install: dry-run / apply / идемпотентность
# ---------------------------------------------------------------------------

class TestInstall:
    def test_dry_run_mutates_nothing(self, env):
        assert _install(env, apply=False) == 0
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert not Path(exit_leg.EXIT_LEG_NFT_FILE).exists()
        assert env["keys"] == []
        assert env["systemd"].installed == []
        assert env["runner"].calls == []
        assert not Path(env["state"]).exists()

    def test_apply_writes_secret_conf_and_state(self, env):
        assert _install(env) == 0

        conf = Path(exit_leg.EXIT_LEG_CONFIG_PATH)
        assert conf.is_file()
        assert stat.S_IMODE(conf.stat().st_mode) == 0o600
        body = conf.read_text(encoding="utf-8")
        assert f"PublicKey = {RELAY_PUB}" in body
        assert "PersistentKeepalive = 25" in body

        nft = Path(exit_leg.EXIT_LEG_NFT_FILE)
        assert nft.is_file()
        assert f"ip saddr {RELAY_IP}" in nft.read_text(encoding="utf-8")

        script = Path(exit_leg.EXIT_LEG_POOL_SCRIPT)
        assert stat.S_IMODE(script.stat().st_mode) == 0o755
        assert "nft -f" in script.read_text(encoding="utf-8")

        assert exit_leg.EXIT_LEG_UNIT in env["systemd"].installed
        assert exit_leg.EXIT_LEG_POOL_UNIT in env["systemd"].installed

        state = json.loads(Path(env["state"]).read_text(encoding="utf-8"))
        leg = state["protocols"]["relay_leg"]
        assert leg == {
            "iface": "awg2",
            "subnet": "10.11.0.0/30",
            "exit_ip": "10.11.0.1",
            "peer_ip": "10.11.0.2",
            "base_port": 51900,
            "pool": "51900-51911",
            "relay_ip": RELAY_IP,
            "public_key": RELAY_PUB,
            "installed": True,
        }
        # Приватный ключ — только в .conf (0600), не в state.
        assert EXIT_LEG_PRIV not in Path(env["state"]).read_text(encoding="utf-8")

        ufw_calls = env["runner"].commands("ufw", "allow")
        assert ufw_calls and ufw_calls[0] == [
            "ufw", "allow", "from", RELAY_IP, "to", "any",
            "port", "51900", "proto", "udp",
        ]

    def test_client_awg0_untouched(self, env):
        assert _install(env) == 0
        for call in env["runner"].calls:
            assert "51825" not in call
            assert "awg0" not in call
        # Конфиг клиентского awg0 не перезаписывался.
        assert env["awg0"].read_text(encoding="utf-8").startswith("[Interface]")

    def test_repeat_apply_is_noop(self, env):
        assert _install(env) == 0
        conf_before = Path(exit_leg.EXIT_LEG_CONFIG_PATH).read_text(encoding="utf-8")
        state_before = Path(env["state"]).read_text(encoding="utf-8")
        restarts_before = len(env["runner"].commands("systemctl", "restart"))

        env["runner"].calls.clear()
        assert _install(env) == 0

        assert env["keys"] == [1]  # ключи не перегенерированы
        assert Path(exit_leg.EXIT_LEG_CONFIG_PATH).read_text(encoding="utf-8") == conf_before
        assert Path(env["state"]).read_text(encoding="utf-8") == state_before
        # Файлы правил не изменились и юниты активны → рестартов нет.
        assert env["runner"].commands("systemctl", "restart") == []
        assert restarts_before == 2  # первый apply: awg2 + pool

    def test_config_regenerated_when_missing_but_rest_kept(self, env):
        assert _install(env) == 0
        Path(exit_leg.EXIT_LEG_CONFIG_PATH).unlink()
        assert _install(env) == 0
        assert Path(exit_leg.EXIT_LEG_CONFIG_PATH).is_file()
        assert len(env["keys"]) == 2  # конфига не было — ключи новые


# ---------------------------------------------------------------------------
# отказ на релее / не на exit
# ---------------------------------------------------------------------------

class TestRefusal:
    def test_refuses_on_relay_marker(self, env):
        Path(env["state"]).write_text(
            json.dumps({"version": 1, "clients": [], "protocols": {"relay": {"installed": True}},
                        "ufw_lockdown": {}}),
            encoding="utf-8",
        )
        assert _install(env) == 1
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert env["keys"] == []
        assert env["systemd"].installed == []

    def test_refuses_without_client_awg0(self, env, monkeypatch):
        monkeypatch.setattr(exit_leg, "AWG_CONFIG_PATH", env["tmp"] / "missing-awg0.conf")
        assert _install(env) == 1
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()

    def test_refuses_on_relay_awg1_marker_without_state(self, env):
        # Вторая линия защиты: клиентская нога релея на месте, state пуст.
        marker = env["tmp"] / "awg1.conf"
        marker.write_text("[Interface]\n", encoding="utf-8")
        assert _install(env) == 1
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert env["systemd"].installed == []


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------

class TestRemove:
    def test_nothing_to_remove(self, env):
        assert run_remove(apply=True, state_path=env["state"]) == 0
        assert env["systemd"].removed == []

    def test_dry_run_keeps_everything(self, env):
        assert _install(env) == 0
        conf = Path(exit_leg.EXIT_LEG_CONFIG_PATH)
        assert conf.is_file()
        assert run_remove(apply=False, state_path=env["state"]) == 0
        assert conf.is_file()
        assert "relay_leg" in json.loads(Path(env["state"]).read_text(encoding="utf-8"))["protocols"]
        assert env["systemd"].removed == []

    def test_remove_rolls_back(self, env):
        assert _install(env) == 0
        env["runner"].nft_table_present = True
        env["runner"].calls.clear()

        assert run_remove(apply=True, state_path=env["state"]) == 0

        assert env["systemd"].removed == [exit_leg.EXIT_LEG_POOL_UNIT, exit_leg.EXIT_LEG_UNIT]
        assert env["runner"].commands("nft", "delete") == [
            ["nft", "delete", "table", "inet", exit_leg.EXIT_LEG_NFT_TABLE]
        ]
        assert env["runner"].commands("ufw", "delete") == [[
            "ufw", "delete", "allow", "from", RELAY_IP, "to", "any",
            "port", "51900", "proto", "udp",
        ]]
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert not Path(exit_leg.EXIT_LEG_NFT_FILE).exists()
        assert not Path(exit_leg.EXIT_LEG_POOL_SCRIPT).exists()
        state = json.loads(Path(env["state"]).read_text(encoding="utf-8"))
        assert "relay_leg" not in state["protocols"]
        # Клиентский awg0 не тронут remove'ом.
        assert env["awg0"].is_file()
        for call in env["runner"].calls:
            assert "awg0" not in call and "51825" not in call

    def test_remove_is_idempotent(self, env):
        assert _install(env) == 0
        assert run_remove(apply=True, state_path=env["state"]) == 0
        assert run_remove(apply=True, state_path=env["state"]) == 0
