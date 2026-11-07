"""Тесты src/xray/install.py: все сетевые/shell-шаги за моками (ADR-001)."""

import hashlib
import io
import json
import os
import types
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import src.xray.install as install
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


def _fake_release() -> tuple[bytes, str]:
    """(zip-байты release, текст .dgst с корректным SHA256)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("xray", "#!/bin/sh\nfake xray\n")
        archive.writestr("geoip.dat", "geoip")
        archive.writestr("geosite.dat", "geosite")
    data = buf.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    return data, f"SHA224 = aa\nSHA256 = {digest}\nSHA512 = bb\n"


@dataclass
class Env:
    root: Path
    units: list[tuple[str, str]] = field(default_factory=list)


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    """Tmp-пути, root, свободный порт, моки requests/install_unit/run_list."""
    zip_data, dgst = _fake_release()
    zip_url, dgst_url = install._release_urls()
    urls = {zip_url: zip_data, dgst_url: dgst.encode()}
    monkeypatch.setattr(install, "requests", types.SimpleNamespace(
        get=lambda url, **kw: _FakeResponse(urls[url])
    ))

    monkeypatch.setattr(install, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(install, "port_owner", lambda port, proto="tcp": None)
    monkeypatch.setattr("os.geteuid", lambda: 0)

    monkeypatch.setattr(install, "XRAY_BIN_PATH", tmp_path / "bin" / "xray")
    monkeypatch.setattr(install, "XRAY_CONFIG_PATH", tmp_path / "etc" / "xray" / "config.json")
    monkeypatch.setattr(install, "XRAY_GEODATA_DIR", tmp_path / "share" / "xray")
    monkeypatch.setattr(install, "LOCK_FILE", str(tmp_path / "xray.lock"))

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[1:] == ["x25519"]:
            return ShellResult(
                stdout="Private key: PRIVKEYABC\nPublic key: PUBKEYXYZ\n",
                stderr="",
                returncode=0,
            )
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(install, "run_list", _run_list)

    test_env = Env(root=tmp_path)

    def _install_unit(tpl: str, name: str, ctx: dict = {}, root: str = "/") -> bool:
        test_env.units.append((tpl, name))
        return True

    monkeypatch.setattr(install, "install_unit", _install_unit)
    monkeypatch.setattr(install, "unit_active", lambda name: True)
    return test_env


class TestPreconditions:
    def test_not_root_refused(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        assert not install.XRAY_BIN_PATH.exists()

    def test_busy_port_refused_before_changes(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(install, "port_owner", lambda port, proto="tcp": "nginx")
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        # ДО любых изменений: бинарь не ставился, конфиг не писался
        assert not install.XRAY_BIN_PATH.exists()
        assert not install.XRAY_CONFIG_PATH.exists()

    def test_already_installed_no_download(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        install.XRAY_BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        install.XRAY_BIN_PATH.write_text("fake", encoding="utf-8")
        install.XRAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        install.XRAY_CONFIG_PATH.write_text("{}", encoding="utf-8")

        # `xray version` отвечает пиннутой версией — установка не нужна
        monkeypatch.setattr(
            install, "run_list",
            lambda args, timeout=10: ShellResult(
                stdout=f"Xray {install.XRAY_VERSION} (custom)\n", stderr="", returncode=0
            ),
        )

        downloads: list[str] = []
        monkeypatch.setattr(
            install.requests, "get",
            lambda url, **kw: downloads.append(url) or _FakeResponse(b""),
        )

        assert install.run_install(state_path=str(env.root / "state.json")) == 0
        assert downloads == []  # идемпотентность: не перекачиваем


class TestFullInstall:
    def test_install_success(self, env: Env) -> None:
        state_path = str(env.root / "state.json")
        assert install.run_install(state_path=state_path) == 0

        # бинарь + geodata на месте
        assert install.XRAY_BIN_PATH.is_file()
        dat_files = sorted(p.name for p in install.XRAY_GEODATA_DIR.glob("*.dat"))
        assert dat_files == ["geoip.dat", "geosite.dat"]

        # конфиг 0600, Reality, приватный ключ внутри (и только там)
        assert os.stat(install.XRAY_CONFIG_PATH).st_mode & 0o777 == 0o600
        config = json.loads(install.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        stream = config["inbounds"][0]["streamSettings"]
        assert stream["security"] == "reality"
        assert stream["realitySettings"]["privateKey"] == "PRIVKEYABC"
        short_ids = stream["realitySettings"]["shortIds"]
        assert len(short_ids) == 1 and len(short_ids[0]) == 8  # hex shortId

        # юнит установлен из нашего шаблона с нужным именем
        assert env.units == [("vds-xray.service.tpl", "vds-xray.service")]

        # метаданные в store: публичный ключ есть, приватного нет
        from src.gateway.store import load_state

        meta = load_state(state_path).protocols["xray"]
        assert meta["installed"] is True
        assert meta["public_key"] == "PUBKEYXYZ"
        assert meta["sni"] == "www.google.com"
        assert "private_key" not in meta

    def test_sha_mismatch_aborts(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        zip_data, _ = _fake_release()
        bad_dgst = "SHA256 = " + "0" * 64 + "\n"
        zip_url, dgst_url = install._release_urls()
        urls = {zip_url: zip_data, dgst_url: bad_dgst.encode()}
        monkeypatch.setattr(
            install.requests, "get", lambda url, **kw: _FakeResponse(urls[url])
        )
        assert install.run_install(state_path=str(env.root / "state.json")) == 1
        assert not install.XRAY_BIN_PATH.exists()  # ничего не установлено

    def test_custom_sni_in_config(self, env: Env) -> None:
        assert install.run_install(sni="example.org", state_path=str(env.root / "state.json")) == 0
        config = json.loads(install.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["dest"] == "example.org:443"
        assert reality["serverNames"] == ["example.org"]
