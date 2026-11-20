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
    leg_key_conflict,
    parse_pool,
    render_exit_leg_client_conf,
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
EXIT_PUB = "FIXTURE_PUBKEY_AWG2_NODE_0000000000="
EXIT_PUBLIC_IP = "198.51.100.77"  # RFC 5737 (TEST-NET-2)
WAN_IFACE = "eth0"
ROUTE_OUTPUT = (
    f"1.1.1.1 via 203.0.113.1 dev {WAN_IFACE} src {EXIT_PUBLIC_IP} uid 0\n"
    "    cache\n"
)


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


class TestRenderClientTemplate:
    def test_client_leg_template_contract(self):
        obf = _obf()
        text = render_exit_leg_client_conf(
            exit_public_key=EXIT_PUB, exit_ip=EXIT_PUBLIC_IP, obf=obf
        )
        assert f"Address = {EXIT_LEG_PEER_IP}/32" in text
        assert "Table = off" in text
        assert f"MTU = {exit_leg.EXIT_LEG_MTU}" in text
        assert f"PublicKey = {EXIT_PUB}" in text
        assert f"Endpoint = {EXIT_PUBLIC_IP}:{EXIT_LEG_BASE_PORT}" in text
        assert "AllowedIPs = 0.0.0.0/0" in text
        assert "PersistentKeepalive = 25" in text
        assert "PrivateKey = <вставьте приватный ключ релея>" in text
        # Обфускация — точно от awg2 (все 9 параметров), иначе handshake мёртв.
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            assert f"{key} = {obf[key]}" in text

    def test_rejects_bad_exit_ip(self):
        with pytest.raises(ExitLegError):
            render_exit_leg_client_conf(
                exit_public_key=EXIT_PUB, exit_ip="not-an-ip", obf=_obf()
            )


class TestRenderNft:
    def _text(self) -> str:
        return render_nft_leg(RELAY_IP, wan_iface=WAN_IFACE)

    def test_redirect_only_pool_without_base_port(self):
        text = self._text()
        assert f"table inet {exit_leg.EXIT_LEG_NFT_TABLE}" in text
        assert "type nat hook prerouting priority dstnat" in text
        # REDIRECT матчит 51901–51911, но НЕ сам P_base (нет петли).
        assert (
            f"ip saddr {RELAY_IP} udp dport 51901-51911 "
            f"redirect to :{EXIT_LEG_BASE_PORT}"
        ) in text
        assert f"udp dport {EXIT_LEG_POOL} redirect" not in text
        assert text.count("redirect to") == 1

    def test_drop_is_filter_input_not_nat(self):
        text = self._text()
        prerouting, rest = text.split("chain postrouting", 1)
        assert "drop" not in prerouting  # drop не живёт в nat-цепочке
        assert "type filter hook input priority filter - 1" in text
        assert f"ip saddr != {RELAY_IP} udp dport {EXIT_LEG_POOL} drop" in text
        # ip6-вариант: пул не светится по v6.
        assert f"meta nfproto ipv6 udp dport {EXIT_LEG_POOL} drop" in rest

    def test_postrouting_masquerade_for_leg_subnet(self):
        text = self._text()
        assert "type nat hook postrouting priority srcnat" in text
        assert (
            f'ip saddr {EXIT_LEG_SUBNET} oifname "{WAN_IFACE}" masquerade' in text
        )

    def test_external_ip_not_in_rules(self):
        text = self._text()
        assert "198.51.100.9" not in text
        # Релей упомянут ровно дважды: redirect и negative-drop.
        assert text.count(RELAY_IP) == 2

    def test_bad_ip_or_wan_rejected(self):
        with pytest.raises(ExitLegError):
            render_nft_leg("not-an-ip", wan_iface=WAN_IFACE)
        with pytest.raises(ExitLegError):
            render_nft_leg("2001:db8::1", wan_iface=WAN_IFACE)
        with pytest.raises(ExitLegError):
            render_nft_leg(RELAY_IP, wan_iface="")
        with pytest.raises(ExitLegError):
            render_nft_leg(RELAY_IP, wan_iface="eth0; rm -rf /")


class TestRenderPoolScript:
    def test_script_applies_nft_and_ufw_single_port(self):
        text = render_pool_script(RELAY_IP)
        assert text.startswith("#!/bin/sh")
        assert "set -eu" in text
        # Сначала синтаксическая проверка файла, затем apply (P0-3).
        check_at = text.index(f"nft -c -f {exit_leg.EXIT_LEG_NFT_FILE}")
        apply_at = text.index(f"nft -f {exit_leg.EXIT_LEG_NFT_FILE}")
        assert check_at < apply_at
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
    template = tmp_path / "gateway" / "clients" / "relay-exit-leg.conf"
    monkeypatch.setattr(exit_leg, "EXIT_LEG_CLIENT_TEMPLATE_PATH", template)
    monkeypatch.setattr(exit_leg, "EXIT_LEG_NFT_FILE", tmp_path / "relay-leg.nft")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_POOL_SCRIPT", tmp_path / "pool-apply.sh")
    monkeypatch.setattr(exit_leg, "EXIT_LEG_LOCK_FILE", str(tmp_path / "leg.lock"))
    monkeypatch.setattr(exit_leg.os, "geteuid", lambda: 0)
    monkeypatch.setattr(exit_leg, "command_exists", lambda name: True)

    runner = FakeRunner(
        FakeSystemd(),
        mapping={
            ("ip", "route", "get"): ShellResult(ROUTE_OUTPUT, "", 0),
            ("sysctl", "-n", "net.ipv4.ip_forward"): ShellResult("1\n", "", 0),
        },
    )
    systemd = runner.systemd
    monkeypatch.setattr(exit_leg, "run_list", runner)
    monkeypatch.setattr(exit_leg, "install_unit", systemd.install)
    monkeypatch.setattr(exit_leg, "unit_active", systemd.is_active)
    monkeypatch.setattr(exit_leg, "remove_unit", systemd.remove)
    monkeypatch.setattr(exit_leg, "_ufw_present", lambda: True)

    keys = []

    def fake_keys():
        keys.append(1)
        return EXIT_LEG_PRIV, EXIT_PUB

    monkeypatch.setattr(exit_leg, "_gen_server_keys", fake_keys)

    return {
        "tmp": tmp_path,
        "runner": runner,
        "systemd": systemd,
        "keys": keys,
        "state": str(tmp_path / "state.json"),
        "awg0": awg0,
        "template": template,
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
        assert leg["iface"] == "awg2"
        assert leg["subnet"] == "10.11.0.0/30"
        assert leg["exit_ip"] == "10.11.0.1"
        assert leg["peer_ip"] == "10.11.0.2"
        assert leg["base_port"] == 51900
        assert leg["pool"] == "51900-51911"
        assert leg["relay_ip"] == RELAY_IP
        assert leg["public_key"] == RELAY_PUB
        # P0-1: релей должен получить ключ exit и точную обфускацию awg2.
        assert leg["exit_public_key"] == EXIT_PUB
        assert set(leg["obfuscation"]) == {
            "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"
        }
        assert leg["exit_public_ip"] == EXIT_PUBLIC_IP
        assert leg["wan_iface"] == WAN_IFACE
        assert leg["installed"] is True
        # Приватный ключ — только в .conf (0600), не в state.
        assert EXIT_LEG_PRIV not in Path(env["state"]).read_text(encoding="utf-8")

        # Клиентский шаблон ноги: 0600, ключ exit, плейсхолдер приватного ключа.
        tpl = Path(exit_leg.EXIT_LEG_CLIENT_TEMPLATE_PATH)
        assert tpl.is_file()
        assert stat.S_IMODE(tpl.stat().st_mode) == 0o600
        body_tpl = tpl.read_text(encoding="utf-8")
        assert f"Address = {EXIT_LEG_PEER_IP}/32" in body_tpl
        assert "Table = off" in body_tpl
        assert f"PublicKey = {EXIT_PUB}" in body_tpl
        assert f"Endpoint = {EXIT_PUBLIC_IP}:{EXIT_LEG_BASE_PORT}" in body_tpl
        assert "AllowedIPs = 0.0.0.0/0" in body_tpl
        assert "PersistentKeepalive = 25" in body_tpl
        assert EXIT_LEG_PRIV not in body_tpl
        # Обфускация шаблона совпадает с awg2.conf.
        conf_body = Path(exit_leg.EXIT_LEG_CONFIG_PATH).read_text(encoding="utf-8")
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            value = leg["obfuscation"][key]
            assert f"{key} = {value}" in conf_body
            assert f"{key} = {value}" in body_tpl

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


class TestGuards:
    def test_key_change_on_existing_conf_refused(self, env):
        """P1-3: новый --public-key поверх существующего awg2.conf — отказ."""
        assert _install(env) == 0
        conf_before = Path(exit_leg.EXIT_LEG_CONFIG_PATH).read_text(encoding="utf-8")
        state_before = Path(env["state"]).read_text(encoding="utf-8")
        env["runner"].calls.clear()

        new_key = "FIXTURE_PUBKEY_RELAY_OTHER_0000000000="
        rc = run_install(RELAY_IP, new_key, apply=True, state_path=env["state"])
        assert rc == 1
        # Ни конфиг, ни state не тронуты; мутаций нет.
        assert Path(exit_leg.EXIT_LEG_CONFIG_PATH).read_text(encoding="utf-8") == conf_before
        assert Path(env["state"]).read_text(encoding="utf-8") == state_before
        assert env["runner"].calls == []

    def test_leg_key_conflict_helper(self, env, tmp_path):
        state = exit_leg.load_state(env["state"])
        state.protocols["relay_leg"] = {"public_key": RELAY_PUB, "installed": True}
        assert leg_key_conflict(RELAY_PUB, state) is None
        msg = leg_key_conflict("OTHER_KEY", state)
        assert msg and "remove --apply" in msg

    def test_busy_pool_port_refuses_first_install(self, env):
        """P1-1: занятый чужим процессом порт пула — отказ до изменений."""
        env["runner"].mapping[("ss", "-ulnp")] = ShellResult(
            'UNCONN 0 0 0.0.0.0:51900 0.0.0.0:* users:(("nginx",pid=42,fd=6))\n',
            "",
            0,
        )
        assert _install(env) == 1
        assert env["keys"] == []  # до генерации ключей не дошли
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert env["systemd"].installed == []

    def test_free_pool_passes_preflight(self, env):
        env["runner"].mapping[("ss", "-ulnp")] = ShellResult("", "", 0)
        assert _install(env) == 0
        assert env["keys"] == [1]

    def test_ip_forward_disabled_refused(self, env):
        """P0-2: без ip_forward=1 нога не маршрутизирует — явный отказ."""
        env["runner"].mapping[("sysctl", "-n", "net.ipv4.ip_forward")] = ShellResult(
            "0\n", "", 0
        )
        assert _install(env) == 1
        assert not Path(exit_leg.EXIT_LEG_CONFIG_PATH).exists()
        assert env["keys"] == []


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
        assert not Path(exit_leg.EXIT_LEG_CLIENT_TEMPLATE_PATH).exists()
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
