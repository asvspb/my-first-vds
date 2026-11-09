"""Тесты src/acme/apply_cert.py (WP-2): apply/restore на temp-каталогах, моки shell."""

import os
from pathlib import Path

import pytest

import src.acme.apply_cert as apply_mod
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state

DOMAIN = "vpn.example.com"
SELF_CERT = "-----BEGIN CERTIFICATE----- SELF SIGNED FIXTURE -----"
SELF_KEY = "-----BEGIN PRIVATE KEY----- SELF KEY FIXTURE -----"
LE_CERT = "-----BEGIN CERTIFICATE----- LE FULLCHAIN FIXTURE -----"
LE_KEY = "-----BEGIN PRIVATE KEY----- LE KEY FIXTURE -----"


class Env:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.live = root / "etc" / "letsencrypt" / "live" / DOMAIN
        self.hys = root / "etc" / "hysteria"
        self.state_path = root / "state.json"

    @property
    def le_cert(self) -> Path:
        return self.live / "fullchain.pem"

    @property
    def le_key(self) -> Path:
        return self.live / "privkey.pem"

    @property
    def cert(self) -> Path:
        return self.hys / "cert.pem"

    @property
    def key(self) -> Path:
        return self.hys / "key.pem"

    def install_self_signed(self) -> None:
        self.hys.mkdir(parents=True, exist_ok=True)
        self.cert.write_text(SELF_CERT, encoding="utf-8")
        self.key.write_text(SELF_KEY, encoding="utf-8")
        os.chmod(self.cert, 0o600)
        os.chmod(self.key, 0o600)

    def issue_le(self) -> None:
        self.live.mkdir(parents=True, exist_ok=True)
        self.le_cert.write_text(LE_CERT, encoding="utf-8")
        self.le_key.write_text(LE_KEY, encoding="utf-8")

    def write_state(self) -> None:
        state = GatewayState()
        state.protocols["acme"] = {"installed": True, "domain": DOMAIN}
        state.protocols["hysteria2"] = {"installed": True, "port": 443}
        save_state(state, str(self.state_path))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    test_env = Env(tmp_path)
    test_env.install_self_signed()
    test_env.issue_le()
    test_env.write_state()

    monkeypatch.setattr(apply_mod, "ACME_LETSENCRYPT_LIVE", lambda d: test_env.live)
    monkeypatch.setattr(apply_mod, "HYSTERIA2_CERT_PATH", test_env.cert)
    monkeypatch.setattr(apply_mod, "HYSTERIA2_KEY_PATH", test_env.key)
    monkeypatch.setattr(apply_mod, "HYSTERIA2_UNIT", "vds-hysteria2.service")
    monkeypatch.setattr(apply_mod, "LOCK_FILE", str(tmp_path / "apply.lock"))

    systemctl_calls: list[list[str]] = []

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[:2] == ["systemctl", "restart"]:
            systemctl_calls.append(args)
            return ShellResult(stdout="", stderr="", returncode=0)
        if args[:1] == ["openssl"] and "-enddate" in args:
            return ShellResult(
                stdout="notAfter=Jan  1 00:00:00 2099 GMT\n", stderr="", returncode=0
            )
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(apply_mod, "run_list", _run_list)
    monkeypatch.setattr(apply_mod, "load_state", lambda path=None: _load(test_env))
    monkeypatch.setattr("os.geteuid", lambda: 0)
    test_env.systemctl_calls = systemctl_calls
    return test_env


def _load(env: Env):
    from src.gateway.store import load_state as _ls

    return _ls(str(env.state_path))


class TestDryRun:
    def test_dry_run_does_not_mutate(self, env: Env) -> None:
        result = apply_mod.apply_certificate(dry_run=True, state_path=str(env.state_path))
        assert result["dry_run"] is True
        assert result["domain"] == DOMAIN
        assert "backup_cert" in result and "unit" in result
        # ничего не изменилось
        assert env.cert.read_text(encoding="utf-8") == SELF_CERT
        assert env.key.read_text(encoding="utf-8") == SELF_KEY
        assert not (env.hys / "cert.pem.bak-pre-le").exists()
        assert env.systemctl_calls == []

    def test_run_apply_default_is_dry_run(self, env: Env, monkeypatch) -> None:
        class _Rec:
            lines: list[str] = []

            def print(self, *a, **k) -> None:
                self.lines.append(" ".join(str(x) for x in a))

        recorder = _Rec()
        monkeypatch.setattr(apply_mod, "console", recorder)
        assert apply_mod.run_apply(apply=False) == 0
        assert any("DRY-RUN" in line for line in recorder.lines)
        assert env.cert.read_text(encoding="utf-8") == SELF_CERT
        assert env.systemctl_calls == []


class TestApply:
    def test_apply_happy_path(self, env: Env) -> None:
        result = apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))
        assert result["dry_run"] is False
        assert result["restarted"] is True
        assert result["days_left"] is not None and result["days_left"] > 0
        assert env.cert.read_text(encoding="utf-8") == LE_CERT
        assert env.key.read_text(encoding="utf-8") == LE_KEY
        # права 0600 (E9)
        assert (os.stat(env.cert).st_mode & 0o777) == 0o600
        assert (os.stat(env.key).st_mode & 0o777) == 0o600
        # бэкап self-signed сохранён, restart вызван
        assert (env.hys / "cert.pem.bak-pre-le").read_text(encoding="utf-8") == SELF_CERT
        assert (env.hys / "key.pem.bak-pre-le").read_text(encoding="utf-8") == SELF_KEY
        assert env.systemctl_calls == [["systemctl", "restart", "vds-hysteria2.service"]]

    def test_apply_idempotent_backup_preserved(self, env: Env) -> None:
        """Повторный apply не перезаписывает бэкап исходного self-signed (E4)."""
        apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))
        apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))
        backup = env.hys / "cert.pem.bak-pre-le"
        assert backup.read_text(encoding="utf-8") == SELF_CERT

    def test_apply_restart_failure_raises_with_restore_hint(self, env: Env, monkeypatch) -> None:
        def _fail(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:2] == ["systemctl", "restart"]:
                return ShellResult(stdout="", stderr="Job failed", returncode=1)
            return ShellResult(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(apply_mod, "run_list", _fail)
        with pytest.raises(apply_mod.ApplyCertError) as excinfo:
            apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))
        assert "--restore" in str(excinfo.value)

    def test_apply_without_le_files_raises(self, env: Env) -> None:
        env.le_cert.unlink()
        with pytest.raises(apply_mod.ApplyCertError):
            apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))

    def test_apply_without_domain_raises(self, env: Env) -> None:
        env.state_path.unlink()
        save_state(GatewayState(), str(env.state_path))
        with pytest.raises(apply_mod.ApplyCertError):
            apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))


class TestRestore:
    def test_restore_returns_self_signed(self, env: Env) -> None:
        apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))
        result = apply_mod.restore_self_signed(state_path=str(env.state_path))
        assert result["restored"] is True
        assert env.cert.read_text(encoding="utf-8") == SELF_CERT
        assert env.key.read_text(encoding="utf-8") == SELF_KEY
        assert (os.stat(env.cert).st_mode & 0o777) == 0o600
        # два restart: apply + restore
        assert len(env.systemctl_calls) == 2

    def test_restore_without_backup_raises(self, env: Env) -> None:
        with pytest.raises(apply_mod.ApplyCertError):
            apply_mod.restore_self_signed(state_path=str(env.state_path))


class TestCliEntry:
    def test_run_apply_non_root_rejected(self, env: Env, monkeypatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)

        class _Rec:
            lines: list[str] = []

            def print(self, *a, **k) -> None:
                self.lines.append(" ".join(str(x) for x in a))

        recorder = _Rec()
        monkeypatch.setattr(apply_mod, "console", recorder)
        assert apply_mod.run_apply(apply=True) == 1
        assert any("root" in line for line in recorder.lines)
        assert env.cert.read_text(encoding="utf-8") == SELF_CERT

    def test_run_apply_reports_success(self, env: Env, monkeypatch) -> None:
        class _Rec:
            lines: list[str] = []

            def print(self, *a, **k) -> None:
                self.lines.append(" ".join(str(x) for x in a))

        recorder = _Rec()
        monkeypatch.setattr(apply_mod, "console", recorder)
        assert apply_mod.run_apply(apply=True) == 0
        assert env.cert.read_text(encoding="utf-8") == LE_CERT
        assert any("bak-pre-le" in line for line in recorder.lines)

    def test_run_restore_reports_success(self, env: Env, monkeypatch) -> None:
        apply_mod.apply_certificate(dry_run=False, state_path=str(env.state_path))

        class _Rec:
            lines: list[str] = []

            def print(self, *a, **k) -> None:
                self.lines.append(" ".join(str(x) for x in a))

        recorder = _Rec()
        monkeypatch.setattr(apply_mod, "console", recorder)
        assert apply_mod.run_apply(restore=True) == 0
        assert env.cert.read_text(encoding="utf-8") == SELF_CERT
