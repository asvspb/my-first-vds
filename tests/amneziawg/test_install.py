"""Тесты src/amneziawg/install.py на моках (SPEC-20261110 WP-2, §6).

Сеть и apt НЕ трогаются: все shell-шаги — run_list-мок, port_free/public
проверки — моки, юнит — мок install_unit. Реальный apt/PPA — только WP-6
на asv1. Секреты в фикстурах — только с префиксами FIXTURE_* (AGENTS.md §6).
"""

import json
import os
import shutil
from pathlib import Path

import pytest

import src.amneziawg.install as install
from src.core.shell import ShellResult

FIX_PRIV = "FIXTURE_PW_AWG_SERVER_PRIVATE_KEY="
FIX_PUB = "FIXTURE_PW_AWG_SERVER_PUBLIC_KEY="
FIX_PPA_VERSION = "1.0.0-0ppa1"


class Env:
    """Собранный журнал вызовов моков для проверки последовательности."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[list[str]] = []
        self.ufw_calls: list[list[str]] = []
        self.units: list[tuple[str, str, dict]] = []
        self.apt_fails: set[str] = set()  # команды, которые «падают»
        self.port_free_calls: list[tuple[int, str]] = []


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    e = Env(tmp_path)
    e.awg_config = tmp_path / "etc" / "amnezia" / "awg0.conf"
    e.state_path = str(tmp_path / "state.json")
    e.lock_file = str(tmp_path / "awg.lock")

    monkeypatch.setattr(install, "AWG_CONFIG_PATH", e.awg_config)
    monkeypatch.setattr(install, "LOCK_FILE", e.lock_file)
    monkeypatch.setattr(install, "port_free", lambda port, proto: e.port_free_calls.append((port, proto)) or True)
    monkeypatch.setattr(install, "port_owner", lambda port, proto: None)
    monkeypatch.setattr(install, "shutil", shutil)
    monkeypatch.setattr(
        install.shutil, "which",
        lambda name: "/usr/bin/awg" if name == "awg" else "/usr/sbin/ufw" if name == "ufw" else None,
    )
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        e.calls.append(args)
        key = " ".join(args)
        if key in e.apt_fails:
            return ShellResult(stdout="", stderr=f"mock failure: {key}", returncode=100)
        if args == ["awg", "genkey"]:
            return ShellResult(stdout=FIX_PRIV + "\n", stderr="", returncode=0)
        if args[:2] == ["sh", "-c"] and "awg pubkey" in args[2]:
            return ShellResult(stdout=FIX_PUB + "\n", stderr="", returncode=0)
        if args[:3] == ["dpkg-query", "-W", "-f=${Version}"]:
            return ShellResult(stdout=FIX_PPA_VERSION, stderr="", returncode=0)
        if args == ["ufw", "allow", "51825/udp"]:
            e.ufw_calls.append(args)
            return ShellResult(stdout="", stderr="", returncode=0)
        # dpkg -s …, add-apt-repository, apt-get …, apt-mark hold,
        # systemctl enable/restart — всё успешно
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(install, "run_list", _run_list)

    def _install_unit(tpl: str, name: str, ctx: dict = {}, root: str = "/") -> bool:
        e.units.append((tpl, name, dict(ctx)))
        return True

    monkeypatch.setattr(install, "install_unit", _install_unit)
    return e


def _apt_seq(e: Env) -> list[list[str]]:
    """Apt/PPA-шаги в порядке вызова (без неблокирующей headers-проверки)."""
    return [
        args for args in e.calls
        if args[0] in ("dpkg", "add-apt-repository", "apt-get", "apt-mark")
        and not (args[:2] == ["dpkg", "-s"] and args[2].startswith("linux-headers-"))
    ]


class TestPreconditions:
    def test_not_root_refused(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert install.run_install(state_path=env.state_path) == 1
        assert not env.awg_config.exists()
        assert _apt_seq(env) == []  # apt не запускался

    def test_busy_udp_port_refused_before_changes(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install, "port_free", lambda port, proto: False)
        monkeypatch.setattr(install, "port_owner", lambda port, proto: "hysteria")
        assert install.run_install(state_path=env.state_path) == 1
        # ДО изменений: ни apt, ни конфиг, ни state, ни юнит
        assert _apt_seq(env) == []
        assert not env.awg_config.exists()
        assert not Path(env.state_path).exists()
        assert env.units == []

    def test_already_installed_before_port_check(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Активный awg0 сам владеет udp/51825 — «уже установлен» раньше порта."""
        env.awg_config.parent.mkdir(parents=True, exist_ok=True)
        env.awg_config.write_text("[Interface]\nPrivateKey = FIXTURE_PW_X\n", encoding="utf-8")
        monkeypatch.setattr(install, "port_free", lambda port, proto: False)

        assert install.run_install(state_path=env.state_path) == 0
        assert env.port_free_calls == []  # порт-чек не выполнялся вовсе
        assert _apt_seq(env) == []


class TestFullInstall:
    def test_happy_path_sequence(self, env: Env) -> None:
        assert install.run_install(state_path=env.state_path) == 0

        seq = [" ".join(args) for args in _apt_seq(env)]
        assert seq == [
            "dpkg -s software-properties-common",
            "add-apt-repository -y ppa:amnezia/ppa",
            "apt-get update",
            "apt-get install -y amneziawg-tools amneziawg-dkms",
            "apt-mark hold amneziawg-tools amneziawg-dkms",
        ]
        # Ключи генерируются ТОЛЬКО после apt (бинарника awg до него нет)
        keys_idx = next(
            i for i, args in enumerate(env.calls) if args == ["awg", "genkey"]
        )
        apt_idx = env.calls.index(["apt-get", "install", "-y", "amneziawg-tools", "amneziawg-dkms"])
        assert keys_idx > apt_idx

        # pubkey через awg pubkey < tmp-file (без shell=True)
        pubkey_calls = [a for a in env.calls if a[:2] == ["sh", "-c"] and "awg pubkey" in a[2]]
        assert len(pubkey_calls) == 1

        # Конфиг 0600 с обфускацией и ключом
        assert os.stat(env.awg_config).st_mode & 0o777 == 0o600
        conf = env.awg_config.read_text(encoding="utf-8")
        assert conf.startswith("[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51825\n")
        assert f"PrivateKey = {FIX_PRIV}" in conf
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            assert f"{key} = " in conf
        assert FIX_PRIV not in json.dumps(
            json.loads(Path(env.state_path).read_text(encoding="utf-8"))
        )

        # Юнит из нашего шаблона с ctx путей
        assert env.units == [(
            "vds-amneziawg.service.tpl",
            "vds-amneziawg.service",
            {"config_path": str(env.awg_config), "iface": "awg0"},
        )]

        # UFW + enable + restart
        assert env.ufw_calls == [["ufw", "allow", "51825/udp"]]
        assert ["systemctl", "enable", "vds-amneziawg.service"] in env.calls
        assert ["systemctl", "restart", "vds-amneziawg.service"] in env.calls

    def test_state_meta_composition(self, env: Env) -> None:
        assert install.run_install(state_path=env.state_path) == 0
        meta = json.loads(Path(env.state_path).read_text(encoding="utf-8"))
        awg = meta["protocols"]["amneziawg"]
        assert awg["installed"] is True
        assert awg["port"] == 51825
        assert awg["iface"] == "awg0"
        assert awg["subnet"] == "10.9.0.0/24"
        assert awg["public_key"] == FIX_PUB
        assert awg["pkg_version"] == FIX_PPA_VERSION
        assert awg["psk_required"] is True
        assert set(awg["obfuscation"]) == {
            "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"
        }
        # Приватный ключ не в state (только в awg0.conf)
        assert FIX_PRIV not in Path(env.state_path).read_text(encoding="utf-8")


class TestFailures:
    def test_apt_install_fail_no_partial_state(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env.apt_fails.add("apt-get install -y amneziawg-tools amneziawg-dkms")
        assert install.run_install(state_path=env.state_path) == 1
        assert not env.awg_config.exists()      # конфиг не создан
        assert not Path(env.state_path).exists()  # state не записан
        assert env.units == []                   # юнит не ставился
        assert ["systemctl", "restart", "vds-amneziawg.service"] not in env.calls

    def test_ppa_fail_before_keys(self, env: Env) -> None:
        env.apt_fails.add("add-apt-repository -y ppa:amnezia/ppa")
        assert install.run_install(state_path=env.state_path) == 1
        assert ["awg", "genkey"] not in env.calls
        assert not Path(env.state_path).exists()

    def test_no_ufw_still_success(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            install.shutil, "which",
            lambda name: "/usr/bin/awg" if name == "awg" else None,
        )
        assert install.run_install(state_path=env.state_path) == 0
        assert env.ufw_calls == []


class TestIdempotency:
    def test_second_run_no_apt_no_regen(self, env: Env) -> None:
        assert install.run_install(state_path=env.state_path) == 0
        conf_before = env.awg_config.read_bytes()
        calls_first = len(env.calls)

        assert install.run_install(state_path=env.state_path) == 0
        # Ничего после первого прогона: ни apt, ни ключей, ни systemctl
        assert len(env.calls) == calls_first
        assert env.awg_config.read_bytes() == conf_before  # ключи не перегенерированы (E7)

    def test_missing_binary_reinstalls(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        """Конфиг есть, но пакеты снесены (нет бинарника awg) → установка идёт заново."""
        monkeypatch.setattr(
            install.shutil, "which",
            lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
        )
        env.awg_config.parent.mkdir(parents=True, exist_ok=True)
        env.awg_config.write_text("stale\n", encoding="utf-8")
        assert install.run_install(state_path=env.state_path) == 0
        assert _apt_seq(env) != []  # apt выполнен
        assert "stale" not in env.awg_config.read_text(encoding="utf-8")


class TestUnitTemplate:
    def test_render_with_install_ctx(self) -> None:
        from src.core.units import SYSTEMD_DIR

        rendered = (SYSTEMD_DIR / "vds-amneziawg.service.tpl").read_text(
            encoding="utf-8"
        ).format(
            config_path="/etc/amnezia/awg0.conf",
            iface="awg0",
        )
        exec_start = [ln for ln in rendered.splitlines() if ln.startswith("ExecStart=")]
        exec_stop = [ln for ln in rendered.splitlines() if ln.startswith("ExecStop=")]
        assert exec_start == ["ExecStart=/usr/bin/awg-quick up /etc/amnezia/awg0.conf"]
        # P14: down идёт по пути конфига (awg-quick down по iface ищет
        # конфиг в дефолтном каталоге — там его нет).
        assert exec_stop == ["ExecStop=/usr/bin/awg-quick down /etc/amnezia/awg0.conf"]

    def test_exec_stop_uses_config_path_not_iface(self) -> None:
        """P14-регресс: в шаблоне `down {config_path}` и НЕ `down {iface}`."""
        from src.core.units import SYSTEMD_DIR

        tpl = (SYSTEMD_DIR / "vds-amneziawg.service.tpl").read_text(
            encoding="utf-8"
        )
        exec_stop = [ln for ln in tpl.splitlines() if ln.startswith("ExecStop=")]
        assert exec_stop == ["ExecStop=/usr/bin/awg-quick down {config_path}"]
        assert "down {iface}" not in tpl


class TestStaleIfaceCleanup:
    """P14-регресс: stale-интерфейс удаляется перед enable+restart."""

    def test_happy_path_cleanup_when_iface_exists(self, env: Env) -> None:
        # Фикстурный мок возвращает rc=0 на любой команде → `ip link show`
        # означает «интерфейс есть», `ip link del` — успех, systemctl штатно.
        assert install.run_install(state_path=env.state_path) == 0
        # Мок фикстуры возвращает rc=0 на `ip link show` → интерфейс «есть»,
        # значит cleanup обязан выполниться и precede enable/restart.
        calls = env.calls
        assert ["ip", "link", "show", "awg0"] in calls
        assert ["ip", "link", "del", "awg0"] in calls
        show_idx = calls.index(["ip", "link", "show", "awg0"])
        del_idx = calls.index(["ip", "link", "del", "awg0"])
        enable_idx = calls.index(["systemctl", "enable", "vds-amneziawg.service"])
        assert show_idx < del_idx < enable_idx

    def test_no_del_when_iface_absent(self, env: Env) -> None:
        """`ip link show` вернул rc!=0 → удаления нет, установка продолжается."""
        real_run_list = install.run_list

        def _absent(args, timeout=10):
            env.calls.append(args)
            if args[:3] == ["ip", "link", "show"]:
                return ShellResult(stdout="", stderr="Device \"awg0\" does not exist.", returncode=1)
            return real_run_list(args, timeout=timeout)

        install.run_list = _absent
        try:
            assert install.run_install(state_path=env.state_path) == 0
        finally:
            install.run_list = real_run_list
        assert ["ip", "link", "show", "awg0"] in env.calls
        assert ["ip", "link", "del", "awg0"] not in env.calls

