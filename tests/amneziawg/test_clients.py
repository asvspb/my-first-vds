"""Тесты src/amneziawg/clients.py на моках (SPEC-20261110 WP-3, §6).

Сеть, root и awg НЕ трогаются: run_list — мок, geteuid/public_ip — моки,
пути — tmp. Секреты в фикстурах — только с префиксами FIXTURE_* и
зарезервированные IP 203.0.113.0/24 (AGENTS.md §6).
"""

import json
import os
from pathlib import Path

import pytest

import src.amneziawg.clients as clients
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, save_state

FIX_CLI_PRIV = "FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY="
FIX_CLI_PUB = "FIXTURE_PW_AWG_CLIENT_PUBLIC_KEY="
FIX_PSK = "FIXTURE_PW_AWG_CLIENT_PSK="
FIX_SRV_PUB = "FIXTURE_PW_AWG_SERVER_PUBLIC_KEY="
PUBLIC_IP = "203.0.113.10"

SERVER_OBF = {
    "Jc": 6, "Jmin": 64, "Jmax": 256,
    "S1": 88, "S2": 128,
    "H1": 2149340781, "H2": 1934967624,
    "H3": 1242853139, "H4": 881236702,
}


def _server_conf() -> str:
    return (
        "[Interface]\n"
        "Address = 10.9.0.1/24\n"
        "ListenPort = 51825\n"
        "PrivateKey = FIXTURE_PW_AWG_SERVER_PRIVATE_KEY=\n"
        "SaveConfig = false\n"
        + "".join(f"{k} = {v}\n" for k, v in SERVER_OBF.items())
    )


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.calls: list[list[str]] = []
        self.server_conf = tmp_path / "etc" / "amnezia" / "awg0.conf"
        self.clients_dir = tmp_path / "clients" / "amneziawg"
        self.state_path = str(tmp_path / "state.json")
        self.lock_file = str(tmp_path / "clients.lock")
        self.restart_fails = False

    @property
    def awg_meta(self) -> dict:
        return {
            "installed": True,
            "port": 51825,
            "iface": "awg0",
            "public_key": FIX_SRV_PUB,
            "obfuscation": dict(SERVER_OBF),
            "psk_required": True,
        }


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    e = Env(tmp_path)
    monkeypatch.setattr(clients, "AWG_CONFIG_PATH", e.server_conf)
    monkeypatch.setattr(clients, "AWG_CLIENTS_DIR", e.clients_dir)
    monkeypatch.setattr(clients, "LOCK_FILE", e.lock_file)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr("src.amneziawg.clients.public_ip", lambda: PUBLIC_IP)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        e.calls.append(args)
        key = " ".join(args)
        if args[:2] == ["systemctl", "restart"]:
            if e.restart_fails:
                return ShellResult(stdout="", stderr="mock restart failure", returncode=1)
            return ShellResult(stdout="", stderr="", returncode=0)
        if args == ["awg", "genkey"]:
            return ShellResult(stdout=FIX_CLI_PRIV + "\n", stderr="", returncode=0)
        if args == ["awg", "genpsk"]:
            return ShellResult(stdout=FIX_PSK + "\n", stderr="", returncode=0)
        if args[:2] == ["sh", "-c"] and "awg pubkey" in args[2]:
            return ShellResult(stdout=FIX_CLI_PUB + "\n", stderr="", returncode=0)
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(clients, "run_list", _run_list)

    e.server_conf.parent.mkdir(parents=True, exist_ok=True)
    e.server_conf.write_text(_server_conf(), encoding="utf-8")
    save_state(GatewayState(protocols={"amneziawg": e.awg_meta}), e.state_path)
    return e


def _read_state(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _awg_clients(state: dict) -> list[dict]:
    return [c for c in state["clients"] if c["protocol"] == "amneziawg"]


class TestAddClientHappyPath:
    def test_conf_render_and_0600(self, env: Env) -> None:
        result = clients.add_client("mob-awg", state_path=env.state_path)

        conf_file = Path(result["conf_path"])
        assert conf_file == env.clients_dir / "mob-awg.conf"
        assert os.stat(conf_file).st_mode & 0o777 == 0o600
        text = conf_file.read_text(encoding="utf-8")
        assert f"PrivateKey = {FIX_CLI_PRIV}" in text
        assert "Address = 10.9.0.2/32" in text
        assert f"PublicKey = {FIX_SRV_PUB}" in text  # [Peer] сервера
        assert f"PresharedKey = {FIX_PSK}" in text
        assert f"Endpoint = {PUBLIC_IP}:51825" in text
        assert "AllowedIPs = 0.0.0.0/0,::/0" in text
        assert "PersistentKeepalive = 25" in text
        # Серверные S1/S2/H1–H4 и клиентские J-параметры присутствуют
        for key in ("S1", "S2", "H1", "H2", "H3", "H4"):
            value = SERVER_OBF[key]
            assert f"{key} = {value}" in text
        assert "Jc = " in text and "Jmin = " in text and "Jmax = " in text
        # Возврат без секретов
        assert FIX_CLI_PRIV not in json.dumps(result)
        assert FIX_PSK not in json.dumps(result)

    def test_server_conf_peer_added(self, env: Env) -> None:
        clients.add_client("mob-awg", state_path=env.state_path)
        text = env.server_conf.read_text(encoding="utf-8")
        peer = text.split("[Peer]")[1]
        assert f"# mob-awg" in peer
        assert f"PublicKey = {FIX_CLI_PUB}" in peer
        assert f"PresharedKey = {FIX_PSK}" in peer
        assert "AllowedIPs = 10.9.0.2/32" in peer
        # Interface-часть не изменена
        assert text.startswith(_server_conf().split("[Peer]")[0].splitlines()[0])
        backup = env.server_conf.with_name("awg0.conf.bak-pre-mutation")
        assert backup.is_file()

    def test_restart_called_and_state_structure(self, env: Env) -> None:
        clients.add_client("mob-awg", state_path=env.state_path)
        assert ["systemctl", "restart", "vds-amneziawg.service"] in env.calls

        state = _read_state(env.state_path)
        awg_meta = state["protocols"]["amneziawg"]
        assert awg_meta["installed"] is True
        assert awg_meta["public_key"] == FIX_SRV_PUB  # мета не тронута
        clients_list = _awg_clients(state)
        assert len(clients_list) == 1
        entry = clients_list[0]
        assert entry["name"] == "mob-awg"
        assert entry["port"] == 51825
        extra = entry["extra"]
        assert extra["address"] == "10.9.0.2/32"
        assert extra["private_key"] == FIX_CLI_PRIV
        assert extra["psk"] == FIX_PSK
        assert extra["conf_path"].endswith("mob-awg.conf")

    def test_ip_allocation_sequence(self, env: Env) -> None:
        for i, name in enumerate(("a", "b", "c")):
            result = clients.add_client(name, state_path=env.state_path)
            assert result["address"] == f"10.9.0.{2 + i}/32"
        text = env.server_conf.read_text(encoding="utf-8")
        for i in range(3):
            assert f"AllowedIPs = 10.9.0.{2 + i}/32" in text

    def test_existing_legacy_clients_do_not_break_allocation(self, env: Env) -> None:
        state = _read_state(env.state_path)
        state["clients"].append(
            ClientProfile(name="phone", protocol="xray", port=443).model_dump()
        )
        save_state(
            GatewayState.model_validate(state),
            env.state_path,
        )
        result = clients.add_client("mob-awg", state_path=env.state_path)
        assert result["address"] == "10.9.0.2/32"

    def test_endpoint_prefers_state_domain(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _read_state(env.state_path)
        state["domain"] = "vpn.example.com"
        save_state(GatewayState.model_validate(state), env.state_path)
        clients.add_client("mob-awg", state_path=env.state_path)
        conf = (env.clients_dir / "mob-awg.conf").read_text(encoding="utf-8")
        assert "Endpoint = vpn.example.com:51825" in conf


class TestAddClientGuarded:
    def test_duplicate_name_storeerror_before_mutations(self, env: Env) -> None:
        from src.gateway.store import StoreError

        clients.add_client("mob-awg", state_path=env.state_path)
        conf_before = env.server_conf.read_bytes()
        client_conf_before = (env.clients_dir / "mob-awg.conf").read_bytes()
        calls_before = len(env.calls)
        state_before = _read_state(env.state_path)

        with pytest.raises(StoreError):
            clients.add_client("mob-awg", state_path=env.state_path)
        assert env.server_conf.read_bytes() == conf_before
        assert (env.clients_dir / "mob-awg.conf").read_bytes() == client_conf_before
        assert len(env.calls) == calls_before  # ключи не генерировались
        assert _read_state(env.state_path) == state_before

    def test_duplicate_name_against_other_protocol_ok(self, env: Env) -> None:
        """Дубль имени с клиентом другого протокола — не конфликт AWG (имя уникально
        глобально в store — здесь проверяем, что xray-клиент блокирует)."""
        from src.gateway.store import StoreError

        state = _read_state(env.state_path)
        state["clients"].append(
            ClientProfile(name="mob-awg", protocol="xray", port=443).model_dump()
        )
        save_state(GatewayState.model_validate(state), env.state_path)
        with pytest.raises(StoreError):
            clients.add_client("mob-awg", state_path=env.state_path)

    def test_not_installed_refused(self, env: Env) -> None:
        state = _read_state(env.state_path)
        del state["protocols"]["amneziawg"]
        save_state(GatewayState.model_validate(state), env.state_path)

        with pytest.raises(clients.AWGClientError, match="не установлен"):
            clients.add_client("mob", state_path=env.state_path)
        assert env.calls == []
        assert _read_state(env.state_path)["clients"] == []

    def test_missing_server_conf_refused(self, env: Env) -> None:
        env.server_conf.unlink()
        with pytest.raises(clients.AWGClientError, match="отсутствует"):
            clients.add_client("mob", state_path=env.state_path)

    def test_not_root_refused(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        with pytest.raises(clients.AWGClientError, match="root"):
            clients.add_client("mob", state_path=env.state_path)
        assert env.calls == []

    def test_broken_server_conf_no_mutation_no_restart(self, env: Env) -> None:
        env.server_conf.write_text("garbage without sections\n", encoding="utf-8")
        with pytest.raises(clients.AWGClientError, match="повреждён"):
            clients.add_client("mob", state_path=env.state_path)
        assert ["systemctl", "restart", "vds-amneziawg.service"] not in env.calls
        assert _read_state(env.state_path)["clients"] == []

    def test_restart_failure_rolls_back(self, env: Env) -> None:
        env.restart_fails = True
        conf_before = env.server_conf.read_bytes()
        with pytest.raises(clients.AWGClientError, match="перезапустить"):
            clients.add_client("mob-awg", state_path=env.state_path)
        assert env.server_conf.read_bytes() == conf_before  # откат конфига
        assert not (env.clients_dir / "mob-awg.conf").exists()
        assert _awg_clients(_read_state(env.state_path)) == []


class TestAddClientNoPsk:
    def test_no_psk_branch(self, env: Env) -> None:
        result = clients.add_client("nopsk", no_psk=True, state_path=env.state_path)
        client_conf = (env.clients_dir / "nopsk.conf").read_text(encoding="utf-8")
        assert "PresharedKey" not in client_conf
        server_text = env.server_conf.read_text(encoding="utf-8")
        peer = server_text.split("[Peer]")[1]
        assert "PresharedKey" not in peer
        assert "AllowedIPs = 10.9.0.2/32" in peer
        state = _read_state(env.state_path)
        extra = _awg_clients(state)[0]["extra"]
        assert "psk" not in extra
        assert "PresharedKey" not in json.dumps(_read_state(env.state_path))

    def test_psk_skipped_only_for_that_client(self, env: Env) -> None:
        clients.add_client("nopsk", no_psk=True, state_path=env.state_path)
        clients.add_client("withpsk", state_path=env.state_path)
        assert (env.clients_dir / "withpsk.conf").read_text(
            encoding="utf-8"
        ).count("PresharedKey = ") == 1
        assert (env.clients_dir / "nopsk.conf").read_text(
            encoding="utf-8"
        ).count("PresharedKey = ") == 0


class TestRemoveClient:
    def _add_two(self, env: Env) -> None:
        clients.add_client("alpha", state_path=env.state_path)
        clients.add_client("beta", state_path=env.state_path)

    def test_dry_run_default_changes_nothing(self, env: Env) -> None:
        self._add_two(env)
        conf_before = env.server_conf.read_bytes()
        calls_before = len(env.calls)
        state_before = _read_state(env.state_path)

        plan = clients.remove_client("alpha", state_path=env.state_path)
        assert plan["dry_run"] is True
        assert any("alpha" in step for step in plan["plan"])
        assert env.server_conf.read_bytes() == conf_before
        assert len(env.calls) == calls_before
        assert _read_state(env.state_path) == state_before
        assert (env.clients_dir / "alpha.conf").exists()

    def test_apply_removes_peer_conf_and_state(self, env: Env) -> None:
        self._add_two(env)
        result = clients.remove_client("alpha", apply=True, state_path=env.state_path)
        assert result["dry_run"] is False

        text = env.server_conf.read_text(encoding="utf-8")
        assert "# alpha" not in text
        assert "# beta" in text  # соседний peer не тронут
        assert "AllowedIPs = 10.9.0.3/32" in text
        assert "AllowedIPs = 10.9.0.2/32" not in text
        assert not (env.clients_dir / "alpha.conf").exists()
        assert (env.clients_dir / "beta.conf").exists()
        assert [c["name"] for c in _awg_clients(_read_state(env.state_path))] == ["beta"]
        assert ["systemctl", "restart", "vds-amneziawg.service"] in env.calls

    def test_apply_missing_peer_in_conf_fails_clean(self, env: Env) -> None:
        clients.add_client("alpha", state_path=env.state_path)
        # Убираем peer из конфига вручную (расхождение конфиг/state)
        env.server_conf.write_text(_server_conf(), encoding="utf-8")
        conf_before = env.server_conf.read_bytes()
        with pytest.raises(clients.AWGClientError, match="не найдена"):
            clients.remove_client("alpha", apply=True, state_path=env.state_path)
        assert env.server_conf.read_bytes() == conf_before
        assert _awg_clients(_read_state(env.state_path)) != []

    def test_unknown_client_refused(self, env: Env) -> None:
        with pytest.raises(clients.AWGClientError, match="не найден"):
            clients.remove_client("ghost", state_path=env.state_path)

    def test_remove_restarts_unit(self, env: Env) -> None:
        clients.add_client("alpha", state_path=env.state_path)
        env.calls.clear()
        clients.remove_client("alpha", apply=True, state_path=env.state_path)
        assert ["systemctl", "restart", "vds-amneziawg.service"] in env.calls
