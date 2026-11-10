"""Тесты src/amneziawg/remove.py на моках (SPEC-20261110 WP-4, §6).

Dry-run ничего не удаляет; --apply удаляет всё по плану и чистит state;
сбой remove_unit → откат из бэкапа; root-check (E8). Пути — tmp, remove_unit
— мок, ufw — через shutil.which-мок. Секреты — только FIXTURE_*.
"""

import json
import os
from pathlib import Path

import pytest

import src.amneziawg.remove as remove_mod
from src.core.shell import ShellResult
from src.gateway.store import ClientProfile, GatewayState, save_state


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


CLIENT_CONF = (
    "[Interface]\n"
    "PrivateKey = FIXTURE_PW_AWG_CLIENT_PRIVATE_KEY=\n"
    "Address = 10.9.0.2/32\n"
)


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.awg_conf = tmp_path / "etc" / "amnezia" / "awg0.conf"
        self.clients_dir = tmp_path / "clients" / "amneziawg"
        self.state_path = str(tmp_path / "state.json")
        self.unit_file = tmp_path / "etc" / "systemd" / "system" / "vds-amneziawg.service"
        self.lock_file = str(tmp_path / "remove.lock")
        self.calls: list[list[str]] = []
        self.remove_unit_ok = True
        self.unit_exists = True
        self.has_ufw = True
        self.questionary_answer = False
        self.remove_unit_calls: list[str] = []


@pytest.fixture()
def recorder(monkeypatch: pytest.MonkeyPatch) -> _ConsoleRecorder:
    rec = _ConsoleRecorder()
    monkeypatch.setattr(remove_mod, "console", rec)
    return rec


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder) -> Env:
    e = Env(tmp_path)
    monkeypatch.setattr(remove_mod, "AWG_CONFIG_PATH", e.awg_conf)
    monkeypatch.setattr(remove_mod, "AWG_CLIENTS_DIR", e.clients_dir)
    monkeypatch.setattr(remove_mod, "UNIT_FILE", e.unit_file)
    monkeypatch.setattr(remove_mod, "LOCK_FILE", e.lock_file)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(
        remove_mod.shutil, "which",
        lambda name: "/usr/sbin/ufw" if (name == "ufw" and e.has_ufw) else None,
    )
    monkeypatch.setattr(
        remove_mod, "unit_active", lambda name: e.unit_exists and e.awg_conf.is_file()
    )

    def _remove_unit(name: str, root: str = "/") -> bool:
        e.remove_unit_calls.append(name)
        if not e.remove_unit_ok:
            return False
        e.unit_exists = False
        e.unit_file.unlink(missing_ok=True)
        return True

    monkeypatch.setattr(remove_mod, "remove_unit", _remove_unit)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        e.calls.append(args)
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(remove_mod, "run_list", _run_list)

    import builtins
    import types

    real_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        """Перехват `import questionary` внутри run_remove — фейк-модуль."""
        if name == "questionary":
            module = types.ModuleType("questionary")

            def confirm(text: str, default: bool = False):
                class _Prompt:
                    def ask(self) -> bool:
                        return e.questionary_answer

                return _Prompt()

            module.confirm = confirm
            return module
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    return e


def _setup_installed(e: Env, clients: int = 1) -> None:
    e.awg_conf.parent.mkdir(parents=True, exist_ok=True)
    e.awg_conf.write_text(
        "[Interface]\nPrivateKey = FIXTURE_PW_AWG_SERVER_PRIVATE_KEY=\n"
        "ListenPort = 51825\n\n[Peer]\n# mob-awg\n",
        encoding="utf-8",
    )
    os.chmod(e.awg_conf, 0o600)
    e.clients_dir.mkdir(parents=True, exist_ok=True)
    (e.clients_dir / "mob-awg.conf").write_text(CLIENT_CONF, encoding="utf-8")
    e.unit_file.parent.mkdir(parents=True, exist_ok=True)
    e.unit_file.write_text("[Unit]\n", encoding="utf-8")

    state = GatewayState()
    state.protocols["amneziawg"] = {"installed": True, "port": 51825, "iface": "awg0"}
    for i in range(clients):
        state.clients.append(
            ClientProfile(
                name=f"mob-awg{i or ''}",
                protocol="amneziawg",
                port=51825,
                extra={"address": f"10.9.0.{i + 2}/32", "private_key": "FIXTURE_PW_K="},
            )
        )
    save_state(state, e.state_path)


class TestDryRun:
    def test_plan_printed_nothing_deleted(self, env: Env, recorder: _ConsoleRecorder) -> None:
        _setup_installed(env)
        before = env.awg_conf.read_bytes()
        assert remove_mod.run_remove(apply=False, state_path=env.state_path) == 0

        output = "\n".join(recorder.lines)
        assert "dry-run" in output
        assert "vds-amneziawg.service" in output
        assert "ufw-правило allow 51825/udp" in output
        assert "awg0.conf" in output
        assert "mob-awg" in output
        assert "НЕ трогаем: пакеты PPA" in output  # ADR-005: ручной purge
        # Ничего не удалено
        assert env.awg_conf.read_bytes() == before
        assert (env.clients_dir / "mob-awg.conf").is_file()
        assert env.unit_file.is_file()
        state = json.loads(Path(env.state_path).read_text(encoding="utf-8"))
        assert "amneziawg" in state["protocols"]

    def test_not_installed_exit_zero(self, env: Env, recorder: _ConsoleRecorder) -> None:
        assert remove_mod.run_remove(state_path=env.state_path) == 0
        assert any("нечего удалять" in line for line in recorder.lines)

    def test_not_root_apply_refused(self, env: Env, monkeypatch: pytest.MonkeyPatch,
                                    recorder: _ConsoleRecorder) -> None:
        _setup_installed(env)
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert remove_mod.run_remove(apply=True, yes=True, state_path=env.state_path) == 1
        assert env.awg_conf.is_file()  # ничего не удалено
        assert env.remove_unit_calls == []


class TestApply:
    def test_apply_removes_everything_and_cleans_state(
        self, env: Env, monkeypatch: pytest.MonkeyPatch, recorder: _ConsoleRecorder
    ) -> None:
        _setup_installed(env, clients=2)
        env.questionary_answer = True

        assert remove_mod.run_remove(apply=True, state_path=env.state_path) == 0

        assert env.remove_unit_calls == ["vds-amneziawg.service"]
        assert not env.awg_conf.exists()
        assert not env.clients_dir.exists()
        assert not env.unit_file.exists()
        assert ["ufw", "delete", "allow", "51825/udp"] in env.calls
        assert ["systemctl", "daemon-reload"] in env.calls

        state = json.loads(Path(env.state_path).read_text(encoding="utf-8"))
        assert "amneziawg" not in state["protocols"]
        assert all(c["protocol"] != "amneziawg" for c in state["clients"])

        output = "\n".join(recorder.lines)
        assert "полностью удалён" in output
        assert "ОСТАЮТСЯ" in output  # пакеты PPA — ручной purge
        assert "apt purge amneziawg-tools amneziawg-dkms" in output

    def test_apply_confirm_declined_aborts(self, env: Env) -> None:
        _setup_installed(env)
        env.questionary_answer = False
        assert remove_mod.run_remove(apply=True, state_path=env.state_path) == 1
        assert env.remove_unit_calls == []
        assert env.awg_conf.is_file()

    def test_backup_created(self, env: Env) -> None:
        _setup_installed(env)
        env.questionary_answer = True
        assert remove_mod.run_remove(apply=True, yes=True, state_path=env.state_path) == 0
        conf_backup = env.awg_conf.with_name(env.awg_conf.name + remove_mod.BACKUP_SUFFIX)
        dir_backup = env.clients_dir.with_name(env.clients_dir.name + remove_mod.BACKUP_SUFFIX)
        assert conf_backup.is_file()
        assert os.stat(conf_backup).st_mode & 0o777 == 0o600
        assert dir_backup.is_dir()
        assert (dir_backup / "mob-awg.conf").is_file()


class TestRollback:
    def test_remove_unit_fail_restores_from_backup(
        self, env: Env, recorder: _ConsoleRecorder
    ) -> None:
        _setup_installed(env, clients=1)
        conf_before = env.awg_conf.read_bytes()
        conf_path_before = env.awg_conf
        clients_before = env.clients_dir
        env.remove_unit_ok = False

        assert remove_mod.run_remove(apply=True, yes=True, state_path=env.state_path) == 1

        output = "\n".join(recorder.lines)
        assert "откатан" in output or "Откат" in output
        # Конфиг и клиенты восстановлены, state не тронут
        assert env.awg_conf.is_file()
        assert env.awg_conf.read_bytes() == conf_before
        assert env.clients_dir.is_dir()
        assert (env.clients_dir / "mob-awg.conf").is_file()
        state = json.loads(Path(env.state_path).read_text(encoding="utf-8"))
        assert "amneziawg" in state["protocols"]
        assert len(state["clients"]) == 1
