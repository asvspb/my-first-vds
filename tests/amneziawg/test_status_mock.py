"""Тесты src/amneziawg/status.py на моках (SPEC-20261110 WP-4, §6).

Сеть, root и awg НЕ трогаются: run_list — мок, unit_active — мок, пути —
tmp. Секреты в фикстурах — только с префиксами FIXTURE_* (AGENTS.md §6).
Проверяются: happy-path, не установлен, config-vs-state рассинхрон,
маскирование ключей в journal.
"""

import shutil
from pathlib import Path

import pytest

import src.amneziawg.status as status_mod
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, save_state

FIX_SRV_PRIV = "FIXTURE_PW_AWG_SERVER_PRIVATE_KEY="
FIX_CLI_PRIV = "FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY="
FIX_PSK = "FIXTURE_PW_AWG_CLIENT_PSK="

SERVER_CONF = (
    "[Interface]\n"
    "Address = 10.9.0.1/24\n"
    "ListenPort = 51825\n"
    f"PrivateKey = {FIX_SRV_PRIV}\n"
    "SaveConfig = false\n"
    "Jc = 6\n"
    "Jmin = 64\n"
    "Jmax = 256\n"
    "S1 = 88\n"
    "S2 = 128\n"
    "H1 = 2149340781\n"
    "H2 = 1934967624\n"
    "H3 = 1242853139\n"
    "H4 = 881236702\n"
    "\n"
    "[Peer]\n"
    "# mob-awg\n"
    "PublicKey = FIXTURE_PW_AWG_CLIENT_PUBLIC_KEY=\n"
    f"PresharedKey = {FIX_PSK}\n"
    "AllowedIPs = 10.9.0.2/32\n"
)


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.awg_conf = tmp_path / "etc" / "amnezia" / "awg0.conf"
        self.clients_dir = tmp_path / "clients" / "amneziawg"
        self.state_path = str(tmp_path / "state.json")
        self.unit_file = tmp_path / "etc" / "systemd" / "system" / "vds-amneziawg.service"
        self.active = True
        self.port_listening = True
        self.journal = ""

    def save_state_with_clients(self, count: int) -> None:
        state = GatewayState()
        state.protocols["amneziawg"] = {"installed": True, "port": 51825, "iface": "awg0"}
        for i in range(count):
            state.clients.append(
                ClientProfile(
                    name=f"mob-awg{i or ''}",
                    protocol="amneziawg",
                    port=51825,
                    extra={
                        "address": f"10.9.0.{i + 2}/32",
                        "private_key": FIX_CLI_PRIV,
                        "psk": FIX_PSK,
                    },
                )
            )
        save_state(state, self.state_path)


@pytest.fixture()
def recorder(monkeypatch: pytest.MonkeyPatch) -> _ConsoleRecorder:
    rec = _ConsoleRecorder()
    monkeypatch.setattr(status_mod, "console", rec)
    return rec


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder) -> Env:
    e = Env(tmp_path)
    monkeypatch.setattr(status_mod, "AWG_CONFIG_PATH", e.awg_conf)
    monkeypatch.setattr(status_mod, "AWG_CLIENTS_DIR", e.clients_dir)
    monkeypatch.setattr(status_mod, "UNIT_FILE", e.unit_file)
    monkeypatch.setattr(status_mod, "is_service_active", lambda: e.active)
    monkeypatch.setattr(status_mod, "port_free", lambda port, proto: not e.port_listening)
    monkeypatch.setattr(
        status_mod, "port_owner", lambda port, proto: "kernel" if e.port_listening else None
    )
    monkeypatch.setattr(status_mod.shutil, "which", lambda name: "/usr/bin/awg" if name == "awg" else None)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args == ["dkms", "status"]:
            return ShellResult(
                stdout="amneziawg/1.0.0-0ppa1, 6.5.0-28-generic, x86_64: installed\n",
                stderr="", returncode=0,
            )
        if args[:3] == ["dpkg-query", "-W", "-f=${Version}"]:
            return ShellResult(stdout="1.0.0-0ppa1", stderr="", returncode=0)
        if args[0] == "journalctl":
            return ShellResult(stdout=e.journal, stderr="", returncode=0)
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(status_mod, "run_list", _run_list)
    return e


class TestRunStatus:
    def test_not_installed_exit_nonzero(self, env: Env, monkeypatch: pytest.MonkeyPatch,
                                        recorder: _ConsoleRecorder) -> None:
        monkeypatch.setattr(status_mod.shutil, "which", lambda name: None)
        assert status_mod.run_status(state_path=env.state_path) == 1
        assert any("не установлен" in line for line in recorder.lines)

    def test_happy_path(self, env: Env, recorder: _ConsoleRecorder) -> None:
        env.awg_conf.parent.mkdir(parents=True, exist_ok=True)
        env.awg_conf.write_text(SERVER_CONF, encoding="utf-8")
        env.save_state_with_clients(1)

        assert status_mod.run_status(state_path=env.state_path) == 0
        output = "\n".join(recorder.lines)
        assert "active" in output
        assert "51825/udp: слушается" in output
        assert "dkms-модуль=1.0.0-0ppa1" in output
        assert "tools=1.0.0-0ppa1" in output
        # Клиенты из state, peers из конфига — рассинхрона нет
        assert "Рассинхрон" not in output
        assert "mob-awg" in output
        assert "N/A" in output  # сертификат

    def test_desync_conf_vs_state(self, env: Env, recorder: _ConsoleRecorder) -> None:
        env.awg_conf.parent.mkdir(parents=True, exist_ok=True)
        env.awg_conf.write_text(SERVER_CONF, encoding="utf-8")  # 1 peer
        env.save_state_with_clients(2)  # 2 клиента в state

        assert status_mod.run_status(state_path=env.state_path) == 0
        assert any("Рассинхрон" in line for line in recorder.lines)

    def test_journal_secrets_masked(self, env: Env, recorder: _ConsoleRecorder) -> None:
        env.awg_conf.parent.mkdir(parents=True, exist_ok=True)
        env.awg_conf.write_text(SERVER_CONF, encoding="utf-8")
        env.save_state_with_clients(1)
        env.journal = (
            f"awg0: peer handshake failed PrivateKey = {FIX_SRV_PRIV}\n"
            f"peer dump PresharedKey = {FIX_PSK}\n"
            f"client key leaked {FIX_CLI_PRIV}\n"
        )

        assert status_mod.run_status(state_path=env.state_path) == 0
        output = "\n".join(recorder.lines)
        assert FIX_SRV_PRIV not in output
        assert FIX_PSK not in output
        assert FIX_CLI_PRIV not in output
        assert "***" in output


class TestHelpers:
    def test_mask_ini_keys(self) -> None:
        text = "PrivateKey = ABC\nPresharedKey = DEF\nAllowedIPs = 10.9.0.2/32\n"
        masked = status_mod._mask_secrets(text, [])
        assert "PrivateKey = ***" in masked
        assert "PresharedKey = ***" in masked
        assert "AllowedIPs = 10.9.0.2/32" in masked

    def test_mask_midline_keys_in_journal(self) -> None:
        text = "awg0: handshake failed, key dump PrivateKey = SECRETBASE64DATA\n"
        masked = status_mod._mask_secrets(text, [])
        assert "SECRETBASE64DATA" not in masked
        assert "PrivateKey = ***" in masked

    def test_count_peers(self) -> None:
        assert status_mod._count_peers(SERVER_CONF) == 1
        assert status_mod._count_peers("[Interface]\n") == 0
