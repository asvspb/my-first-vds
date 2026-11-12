"""Тесты src/hysteria2/obfs.py (SPEC-20261112 WP-1): рендер obfs-блока,
share-link формат, state-структура, порт-конфликт до мутаций, rotate,
remove dry-run/apply — на моках по паттерну tests/hysteria2/test_install.py.
"""

import os
from pathlib import Path

import pytest

import src.hysteria2.obfs as obfs
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, load_state, save_state
from src.hysteria2.config import Hysteria2ConfigParams, render_config

AUTH_PW = "FIXTURE_PW_ObfsMainAuth"
OBFS_PW = "FIXTURE_PW_ObfsSalamander"
IP = "203.0.113.10"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True,
        "port": 443,
        "cert_cn": IP,
        "auth_password": AUTH_PW,
    }
    save_state(state, state_path)

    calls: list[list[str]] = []
    installed_units: list[tuple[str, str, dict]] = []
    removed_units: list[str] = []
    config_paths = {
        "obfs": tmp_path / "etc" / "hysteria" / "obfs.yaml",
        "main": tmp_path / "etc" / "hysteria" / "config.yaml",
    }

    monkeypatch.setattr(obfs, "run_list", lambda args, timeout=10: (
        calls.append(list(args)) or ShellResult(stdout="", stderr="", returncode=0)
    ))
    monkeypatch.setattr(
        obfs, "install_unit",
        lambda tpl, name, ctx={}, root="/": (
            installed_units.append((tpl, name, ctx)) or True
        ),
    )
    monkeypatch.setattr(
        obfs, "remove_unit",
        lambda name, root="/": (removed_units.append(name) or True),
    )
    monkeypatch.setattr(
        obfs, "port_free", lambda port, proto="udp": True
    )
    monkeypatch.setattr(obfs, "port_owner", lambda port, proto="udp": None)
    monkeypatch.setattr(obfs, "gen_password", lambda length=24: OBFS_PW)
    monkeypatch.setattr(
        obfs, "HYSTERIA2_OBFS_CONFIG_PATH", config_paths["obfs"]
    )
    monkeypatch.setattr(obfs, "HYSTERIA2_CERT_PATH", tmp_path / "cert.pem")
    monkeypatch.setattr(obfs, "HYSTERIA2_KEY_PATH", tmp_path / "key.pem")
    monkeypatch.setattr(obfs, "LOCK_FILE", str(tmp_path / "obfs.lock"))
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return {
        "state_path": state_path,
        "calls": calls,
        "installed_units": installed_units,
        "removed_units": removed_units,
        "config_paths": config_paths,
    }


class TestRenderObfsConfig:
    def test_obfs_block_rendered(self) -> None:
        rendered = obfs._render_obfs_config(AUTH_PW, 51826, OBFS_PW)
        assert "obfs:\n  type: salamander\n" f'  password: "{OBFS_PW}"\n' in rendered
        assert rendered.startswith("listen: :51826\n")

    def test_no_obfs_block_without_password(self) -> None:
        base = render_config(Hysteria2ConfigParams(password=AUTH_PW))
        rendered = render_config(
            Hysteria2ConfigParams(password=AUTH_PW, obfs_password=None)
        )
        assert rendered == base
        assert "obfs" not in rendered

    def test_auth_password_is_main_one(self) -> None:
        """Один секрет на транспорт: auth-пароль obfs-инстанса = основной."""
        rendered = obfs._render_obfs_config(AUTH_PW, 51826, OBFS_PW)
        assert f'  password: "{AUTH_PW}"' in rendered


class TestRenderObfsShareLink:
    def test_exact_format(self) -> None:
        link = obfs.render_obfs_share_link(
            host=IP, auth_password=AUTH_PW, obfs_password=OBFS_PW,
            name="phone", port=51826, insecure=True,
        )
        assert link == (
            f"hysteria2://{AUTH_PW}@{IP}:51826/"
            f"?sni={IP}&obfs=salamander&obfs-password={OBFS_PW}"
            f"&insecure=1#phone"
        )

    def test_le_variant_no_insecure_with_mport(self) -> None:
        link = obfs.render_obfs_share_link(
            host="vpn.example.invalid", auth_password=AUTH_PW,
            obfs_password=OBFS_PW, name="mob", port=51826,
            insecure=False, mport="20000-20500",
        )
        assert link == (
            f"hysteria2://{AUTH_PW}@vpn.example.invalid:51826/"
            f"?sni=vpn.example.invalid&obfs=salamander&obfs-password={OBFS_PW}"
            f"&mport=20000-20500#mob"
        )


class TestAddObfs:
    def test_happy_creates_config_unit_state(self, env: dict) -> None:
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        obfs_path: Path = env["config_paths"]["obfs"]
        assert obfs_path.is_file()
        assert obfs_path.stat().st_mode & 0o777 == 0o600
        content = obfs_path.read_text(encoding="utf-8")
        assert "listen: :51826" in content
        assert f'  password: "{AUTH_PW}"' in content
        assert f'  password: "{OBFS_PW}"' in content

        tpl, name, ctx = env["installed_units"][0]
        assert tpl == "vds-hysteria2-obfs.service.tpl"
        assert name == obfs.HYSTERIA2_OBFS_UNIT
        assert ctx["config_path"] == str(obfs_path)
        assert "systemctl" in " ".join(env["calls"][0])

        state = load_state(env["state_path"])
        meta = state.protocols[obfs.STATE_KEY]
        assert meta == {"installed": True, "port": 51826, "obfs_password": OBFS_PW}

    def test_idempotent_second_run_no_new_password(self, env: dict) -> None:
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        env["calls"].clear()
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        assert env["calls"] == []  # выход до мутаций
        state = load_state(env["state_path"])
        assert state.protocols[obfs.STATE_KEY]["obfs_password"] == OBFS_PW

    def test_port_conflict_refused_before_mutations(
        self, env: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(obfs, "port_free", lambda port, proto="udp": False)
        monkeypatch.setattr(obfs, "port_owner", lambda port, proto="udp": "quicother")
        state_before = Path(env["state_path"]).read_bytes()
        assert obfs.add_obfs(state_path=env["state_path"]) == 1
        assert env["calls"] == []
        assert not env["config_paths"]["obfs"].exists()
        assert env["installed_units"] == []
        assert Path(env["state_path"]).read_bytes() == state_before

    def test_custom_port(self, env: dict) -> None:
        assert obfs.add_obfs(port=51830, state_path=env["state_path"]) == 0
        state = load_state(env["state_path"])
        assert state.protocols[obfs.STATE_KEY]["port"] == 51830
        assert "listen: :51830" in env["config_paths"]["obfs"].read_text(encoding="utf-8")

    def test_not_root(self, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert obfs.add_obfs(state_path=env["state_path"]) == 1

    def test_main_not_installed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state_path = str(tmp_path / "state.json")
        save_state(GatewayState(), state_path)
        monkeypatch.setattr("os.geteuid", lambda: 0)
        monkeypatch.setattr(obfs, "LOCK_FILE", str(tmp_path / "obfs.lock"))
        assert obfs.add_obfs(state_path=state_path) == 1


class TestRotateObfs:
    def test_rotate_new_password_restart_state(self, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        env["calls"].clear()
        monkeypatch.setattr(obfs, "gen_password", lambda length=24: "FIXTURE_PW_ObfsNew")
        assert obfs.rotate_obfs(state_path=env["state_path"]) == 0
        content = env["config_paths"]["obfs"].read_text(encoding="utf-8")
        assert '  password: "FIXTURE_PW_ObfsNew"' in content
        assert OBFS_PW not in content
        argvs = [" ".join(c) for c in env["calls"]]
        assert f"systemctl restart {obfs.HYSTERIA2_OBFS_UNIT}" in argvs
        state = load_state(env["state_path"])
        assert state.protocols[obfs.STATE_KEY]["obfs_password"] == "FIXTURE_PW_ObfsNew"
        assert state.protocols[obfs.STATE_KEY]["port"] == 51826  # порт не менялся

    def test_rotate_without_obfs(self, env: dict) -> None:
        assert obfs.rotate_obfs(state_path=env["state_path"]) == 1
        assert env["calls"] == []


class TestRemoveObfs:
    def test_nothing_to_remove(self, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            obfs, "HYSTERIA2_OBFS_CONFIG_PATH", Path("/nonexistent/obfs.yaml")
        )
        assert obfs.remove_obfs(state_path=env["state_path"]) == 0

    def test_dry_run_no_mutations(self, env: dict) -> None:
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        env["calls"].clear()
        assert obfs.remove_obfs(apply=False, state_path=env["state_path"]) == 0
        assert env["calls"] == []
        assert env["removed_units"] == []
        assert env["config_paths"]["obfs"].is_file()
        assert obfs.STATE_KEY in load_state(env["state_path"]).protocols

    def test_apply_removes_unit_config_state(self, env: dict) -> None:
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        assert obfs.remove_obfs(apply=True, state_path=env["state_path"]) == 0
        assert env["removed_units"] == [obfs.HYSTERIA2_OBFS_UNIT]
        assert not env["config_paths"]["obfs"].exists()
        assert obfs.STATE_KEY not in load_state(env["state_path"]).protocols


class TestMainConfigUntouched:
    def test_obfs_module_never_writes_main_config(self, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        """Гейт WP-1 §3.7: obfs-код не пишет в /etc/hysteria/config.yaml."""
        main_path = env["config_paths"]["main"]
        main_path.parent.mkdir(parents=True, exist_ok=True)
        main_path.write_text("listen: :443\n", encoding="utf-8")
        assert obfs.add_obfs(state_path=env["state_path"]) == 0
        assert obfs.rotate_obfs(state_path=env["state_path"]) == 0
        assert main_path.read_text(encoding="utf-8") == "listen: :443\n"
