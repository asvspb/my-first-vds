"""Тесты src/hysteria2/install.py: все сетевые/shell-шаги за моками (ADR-001)."""

import hashlib
import os
import re
import types
from pathlib import Path

import pytest

import src.hysteria2.install as install
from src.core.shell import ShellResult


class _FakeResponse:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        yield self._content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _fake_release() -> tuple[bytes, bytes]:
    """(байты бинаря, hashes.txt с корректным SHA256 этого бинаря)."""
    data = b"fake hysteria binary"
    digest = hashlib.sha256(data).hexdigest()
    asset = install._asset_name()
    hashes = f"{digest}  build/{asset}\n{'0' * 64}  build/other-asset\n".encode()
    return data, hashes


class Env:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.openssl_calls: list[list[str]] = []
        self.units: list[tuple[str, str]] = []
        self.sysctl_applied = False


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    """Tmp-пути, root, свободный udp-порт, моки requests/openssl/sysctl/юнитов."""
    bin_data, hashes = _fake_release()
    bin_url, hashes_url = install._release_urls()
    urls = {bin_url: bin_data, hashes_url: hashes}
    monkeypatch.setattr(install, "requests", types.SimpleNamespace(
        get=lambda url, **kw: _FakeResponse(urls[url])
    ))

    monkeypatch.setattr(install, "port_free", lambda port, proto="udp": True)
    monkeypatch.setattr(install, "port_owner", lambda port, proto="udp": None)
    monkeypatch.setattr(install, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr("os.geteuid", lambda: 0)

    monkeypatch.setattr(
        install, "HYSTERIA2_BIN_PATH", tmp_path / "bin" / "hysteria"
    )
    monkeypatch.setattr(
        install, "HYSTERIA2_CONFIG_PATH", tmp_path / "etc" / "hysteria" / "config.yaml"
    )
    monkeypatch.setattr(
        install, "HYSTERIA2_CERT_PATH", tmp_path / "etc" / "hysteria" / "cert.pem"
    )
    monkeypatch.setattr(install, "HYSTERIA2_KEY_PATH", tmp_path / "etc" / "hysteria" / "key.pem")
    monkeypatch.setattr(install, "LOCK_FILE", str(tmp_path / "hysteria2.lock"))

    test_env = Env(tmp_path)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[:1] == ["openssl"] and args[1:2] == ["req"]:
            # фейковая генерация сертификата: создаём файлы из -keyout/-out
            test_env.openssl_calls.append(args)
            key_out = Path(args[args.index("-keyout") + 1])
            cert_out = Path(args[args.index("-out") + 1])
            key_out.parent.mkdir(parents=True, exist_ok=True)
            key_out.write_text("FAKE KEY", encoding="utf-8")
            cert_out.write_text("FAKE CERT", encoding="utf-8")
            return ShellResult(stdout="", stderr="", returncode=0)
        if args[:2] == [str(install.HYSTERIA2_BIN_PATH), "version"]:
            return ShellResult(
                stdout=f"hysteria version {install._VERSIONplain} ...\n",
                stderr="", returncode=0,
            )
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(install, "run_list", _run_list)

    def _install_unit(tpl: str, name: str, ctx: dict = {}, root: str = "/") -> bool:
        test_env.units.append((tpl, name))
        return True

    monkeypatch.setattr(install, "install_unit", _install_unit)
    monkeypatch.setattr(install, "unit_active", lambda name: True)
    monkeypatch.setattr(
        install, "apply_sysctl",
        lambda: setattr(test_env, "sysctl_applied", True) or True,
    )
    return test_env


def _auth_password(state_path: str) -> str:
    from src.gateway.store import load_state

    return load_state(state_path).protocols["hysteria2"]["auth_password"]


class TestPreconditions:
    def test_not_root_refused(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        assert not install.HYSTERIA2_BIN_PATH.exists()

    def test_busy_udp_port_refused_before_changes(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install, "port_free", lambda port, proto="udp": False)
        monkeypatch.setattr(install, "port_owner", lambda port, proto="udp": "quicvpn")
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        # ДО любых изменений: бинарь/конфиг/сертификаты не создавались
        assert not install.HYSTERIA2_BIN_PATH.exists()
        assert not install.HYSTERIA2_CONFIG_PATH.exists()
        assert not install.HYSTERIA2_CERT_PATH.exists()
        assert env.openssl_calls == []

    def test_no_public_ip_refused(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install, "public_ip", lambda: None)
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        assert not install.HYSTERIA2_BIN_PATH.exists()


class TestFullInstall:
    def test_install_success(self, env: Env) -> None:
        state_path = str(env.root / "state.json")
        assert install.run_install(state_path=state_path) == 0

        # бинарь на месте и исполним
        assert install.HYSTERIA2_BIN_PATH.is_file()
        assert os.stat(install.HYSTERIA2_BIN_PATH).st_mode & 0o111

        # конфиг 0600: listen :443, пароль, masquerade
        assert os.stat(install.HYSTERIA2_CONFIG_PATH).st_mode & 0o777 == 0o600
        config = install.HYSTERIA2_CONFIG_PATH.read_text(encoding="utf-8")
        assert config.startswith("listen: :443\n")
        assert "masquerade:" in config
        assert "https://download.microsoft.com/" in config

        # сертификат: CN=<ip>, 10 лет, 0600
        assert env.openssl_calls and len(env.openssl_calls) == 1
        openssl_args = env.openssl_calls[0]
        assert f"/CN=203.0.113.10" in openssl_args
        assert "3650" in openssl_args
        # Регрессия (asv1, OpenSSL 3.0.13): alias ec_param_gen_curve:prime256v1
        # отвергается ("command not supported"); каноничная форма — ec_paramgen_curve:P-256
        assert "ec_paramgen_curve:P-256" in openssl_args
        assert "ec_param_gen_curve" not in openssl_args
        assert os.stat(install.HYSTERIA2_KEY_PATH).st_mode & 0o777 == 0o600

        # sysctl применён, юнит из нашего шаблона
        assert env.sysctl_applied
        assert env.units == [("vds-hysteria2.service.tpl", "vds-hysteria2.service")]

        # метаданные в store: пароль есть (секрет, state 0600)
        password = _auth_password(state_path)
        assert len(password) == 24
        assert f'password: "{password}"' in config

    def test_sha_mismatch_aborts(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        bin_data, _ = _fake_release()
        bad_hashes = ("0" * 64 + "  build/" + install._asset_name() + "\n").encode()
        bin_url, hashes_url = install._release_urls()
        urls = {bin_url: bin_data, hashes_url: bad_hashes}
        monkeypatch.setattr(
            install.requests, "get", lambda url, **kw: _FakeResponse(urls[url])
        )
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        assert not install.HYSTERIA2_BIN_PATH.exists()  # ничего не установлено


class TestIdempotency:
    def test_already_installed_no_download(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install.HYSTERIA2_BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        install.HYSTERIA2_BIN_PATH.write_text("fake", encoding="utf-8")
        install.HYSTERIA2_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        install.HYSTERIA2_CONFIG_PATH.write_text("listen: :443\n", encoding="utf-8")

        # `hysteria version` отвечает пиннутой версией — установка не нужна
        monkeypatch.setattr(
            install, "run_list",
            lambda args, timeout=10: ShellResult(
                stdout=f"hysteria version {install._VERSIONplain}\n", stderr="", returncode=0
            ),
        )
        downloads: list[str] = []
        monkeypatch.setattr(
            install.requests, "get",
            lambda url, **kw: downloads.append(url) or _FakeResponse(b""),
        )
        assert install.run_install(state_path=str(env.root / "state.json")) == 0
        assert downloads == []  # не перекачиваем

    def test_reinstall_reuses_cert_and_password(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Повторный install (бинарь потерян) НЕ перегенерирует секреты."""
        state_path = str(env.root / "state.json")
        assert install.run_install(state_path=state_path) == 0
        cert_before = install.HYSTERIA2_CERT_PATH.read_bytes()
        key_before = install.HYSTERIA2_KEY_PATH.read_bytes()
        config_before = install.HYSTERIA2_CONFIG_PATH.read_bytes()
        password_before = _auth_password(state_path)
        openssl_before = len(env.openssl_calls)

        # бинарь удалён (например, вручную) -> install пойдёт заново,
        # но существующие секреты должны переиспользоваться
        install.HYSTERIA2_BIN_PATH.unlink()
        assert install.run_install(state_path=state_path) == 0

        assert install.HYSTERIA2_CERT_PATH.read_bytes() == cert_before
        assert install.HYSTERIA2_KEY_PATH.read_bytes() == key_before
        assert install.HYSTERIA2_CONFIG_PATH.read_bytes() == config_before
        assert _auth_password(state_path) == password_before
        assert len(env.openssl_calls) == openssl_before  # openssl не вызывался

    def test_password_reused_from_config_without_state(
        self, env: Env
    ) -> None:
        """State потерян, но config.yaml с паролем есть — пароль переиспользован."""
        state_path = str(env.root / "state.json")
        assert install.run_install(state_path=state_path) == 0
        password_first = _auth_password(state_path)
        Path(state_path).unlink()
        install.HYSTERIA2_BIN_PATH.unlink()

        assert install.run_install(state_path=state_path) == 0
        assert _auth_password(state_path) == password_first

    def test_password_parsed_from_config_matches_regex(self, env: Env) -> None:
        """Реальный формат: пароль в конфиге соответствует regex переиспользования."""
        state_path = str(env.root / "state.json")
        assert install.run_install(state_path=state_path) == 0
        config_text = install.HYSTERIA2_CONFIG_PATH.read_text(encoding="utf-8")
        match = re.search(r'^\s*password:\s*"?([A-Za-z0-9]+)"?\s*$', config_text, re.M)
        assert match is not None
        assert match.group(1) == _auth_password(state_path)


class TestReleaseUrlsMirror:
    """VDS_GITHUB_MIRROR: env-переопределение базового URL релиза (off by default)."""

    def test_no_env_official_urls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env не задан — официальные URL, поведение прежнее байт-в-байт."""
        monkeypatch.delenv("VDS_GITHUB_MIRROR", raising=False)
        bin_url, hashes_url = install._release_urls()
        assert bin_url.startswith("https://github.com/")
        assert hashes_url.startswith("https://github.com/")

    def test_env_set_prefixes_both(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env задан — оба URL с gh-proxy-префиксом."""
        monkeypatch.setenv("VDS_GITHUB_MIRROR", "https://ghfast.top")
        bin_url, hashes_url = install._release_urls()
        assert bin_url.startswith("https://ghfast.top/https://github.com/")
        assert hashes_url.startswith("https://ghfast.top/https://github.com/")

    def test_env_trailing_slash_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Хвостовой `/` в значении env нормализуется."""
        monkeypatch.setenv("VDS_GITHUB_MIRROR", "https://ghfast.top/")
        bin_url, hashes_url = install._release_urls()
        assert bin_url.startswith("https://ghfast.top/https://github.com/")
        assert "//https" not in hashes_url
