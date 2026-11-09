"""Тесты src/acme/install.py (WP-1): все shell/сетевые шаги за моками (ADR-004)."""

import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import src.acme.install as acme
from src.core.shell import ShellResult

DOMAIN_OK = "vpn.example.com"
DOMAIN_FAIL = "vpn.fail.example"  # DNS не резолвится в IP сервера (мок dns_resolves_to)
DOMAIN_CERTBOT_FAIL = "vpn.certbot-fail.example"  # DNS ок, certbot возвращает ошибку
EMAIL = "FIXTURE_EMAIL_owner@example.com"  # фиксгура: email LE-аккаунта, не секрет
NOT_AFTER_TEMPLATE = "%b %d %H:%M:%S %Y GMT"

apt_calls: list[list[str]] = []
certbot_calls: list[list[str]] = []


def _future_not_after(days: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    return "notAfter=" + expires.strftime(NOT_AFTER_TEMPLATE)


class Env:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.live_dir = root / "etc" / "letsencrypt" / "live"
        self.hooks_dir = root / "etc" / "letsencrypt" / "renewal-hooks" / "deploy"
        self.state_path = root / "state.json"

    def fullchain(self, domain: str) -> Path:
        return self.live_dir / domain / acme.FULLCHAIN_NAME

    def issue_cert(self, domain: str, days: int = 90) -> None:
        """Симулировать уже выданный сертификат (файл с будущим notAfter)."""
        self.fullchain(domain).parent.mkdir(parents=True, exist_ok=True)
        self.fullchain(domain).write_bytes(b"FIXTURE_CERT")

    def hook_path(self) -> Path:
        return self.hooks_dir / acme.ACME_HYSTERIA2_HOOK_NAME


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    """Tmp-пути certbot/hook, root, моки run_list/DNS/порта/public_ip."""
    test_env = Env(tmp_path)
    monkeypatch.setattr(acme, "ACME_LETSENCRYPT_LIVE", lambda d: test_env.live_dir / d)
    monkeypatch.setattr(acme, "ACME_HOOKS_DEPLOY_DIR", test_env.hooks_dir)
    monkeypatch.setattr(acme, "LOCK_FILE", str(tmp_path / "acme.lock"))
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(acme, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr(acme, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(acme, "port_owner", lambda port, proto="tcp": None)
    monkeypatch.setattr(acme, "dns_resolves_to", lambda d, ip: d != DOMAIN_FAIL)

    apt_calls.clear()
    certbot_calls.clear()

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[:2] == ["apt-get", "install"]:
            apt_calls.append(args)
            return ShellResult(stdout="", stderr="", returncode=0)
        if args[:2] == [acme.CERTBOT, "certonly"]:
            domain = args[args.index("-d") + 1]
            certbot_calls.append(args)
            if domain == DOMAIN_CERTBOT_FAIL:
                return ShellResult(
                    stdout="", stderr="Detail: validation failed", returncode=1
                )
            test_env.issue_cert(domain)
            return ShellResult(stdout="Successfully received certificate.", stderr="", returncode=0)
        if args[:2] == [acme.CERTBOT, "--version"]:
            # certbot появляется только после apt-get install (happy path)
            if not apt_calls:
                return ShellResult(stdout="", stderr="not found", returncode=127)
            return ShellResult(stdout="certbot 2.1.0", stderr="", returncode=0)
        if args[:1] == ["openssl"] and "-enddate" in args:
            cert = Path(args[args.index("-in") + 1])
            if not cert.is_file():
                return ShellResult(stdout="", stderr="no cert", returncode=1)
            return ShellResult(
                stdout=_future_not_after(90), stderr="", returncode=0
            )
        return ShellResult(stdout="", stderr=f"unexpected: {args}", returncode=-1)

    monkeypatch.setattr(acme, "run_list", _run_list)
    return test_env


class TestIssueCertificate:
    def test_happy_path(self, env: Env) -> None:
        with acme.console.capture() as captured:
            rc = acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path))
        assert rc == 0, captured.get()
        # certbot из apt установлен, затем вызван с HTTP-01-аргументами ADR-004
        assert len(apt_calls) == 1 and apt_calls[0][:3] == ["apt-get", "install", "-y"]
        assert len(certbot_calls) == 1
        assert "--standalone" in certbot_calls[0]
        assert "-d" in certbot_calls[0] and DOMAIN_OK in certbot_calls[0]
        assert "--keep-until-expiring" in certbot_calls[0]
        # hook на месте и исполним, домен в нём, секретов нет
        hook = env.hook_path()
        assert hook.is_file() and stat.S_IMODE(hook.stat().st_mode) & stat.S_IXUSR
        hook_text = hook.read_text(encoding="utf-8")
        assert DOMAIN_OK in hook_text
        assert "0600" in hook_text and "bak-pre-le" in hook_text
        assert "restart vds-hysteria2" in hook_text
        # метаданные acme в store: домен есть, email НЕ пишется (ADR-004)
        import json

        state = json.loads(env.state_path.read_text(encoding="utf-8"))
        assert state["protocols"]["acme"]["domain"] == DOMAIN_OK
        assert EMAIL not in env.state_path.read_text(encoding="utf-8")

    def test_already_issued_skips_certbot(self, env: Env) -> None:
        env.issue_cert(DOMAIN_OK, days=90)
        rc = acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path))
        assert rc == 0
        assert certbot_calls == []  # валидный сертификат — certbot не запускался

    def test_already_issued_message(self, env: Env) -> None:
        env.issue_cert(DOMAIN_OK, days=90)
        with acme.console.capture() as captured:
            acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path))
        assert "уже есть и валиден" in captured.get()
        assert "дн.)" in captured.get()

    def test_expired_cert_reissues(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        """Истёкший сертификат (notAfter в прошлом) — перегенерация."""
        env.issue_cert(DOMAIN_OK)
        env.fullchain(DOMAIN_OK).write_bytes(b"FIXTURE_CERT_EXPIRED")
        fixture = acme.run_list

        def _run_list_mixed(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:1] == ["openssl"] and "-enddate" in args:
                cert = Path(args[args.index("-in") + 1])
                # истёкший до повторного выпуска, свежий после (content-маркер)
                if cert.read_bytes() == b"FIXTURE_CERT_EXPIRED":
                    return ShellResult(stdout=_future_not_after(-3), stderr="", returncode=0)
                return ShellResult(stdout=_future_not_after(90), stderr="", returncode=0)
            return fixture(args, timeout=timeout)

        monkeypatch.setattr(acme, "run_list", _run_list_mixed)
        assert acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path)) == 0
        assert len(certbot_calls) == 1  # истёкший — перегенерирован

    def test_certbot_failure_readable_error(self, env: Env) -> None:
        with acme.console.capture() as captured:
            rc = acme.run_issue(domain=DOMAIN_CERTBOT_FAIL, email=EMAIL, state_path=str(env.state_path))
        assert rc == 1
        assert "validation" in captured.get() and "certbot" in captured.get()
        # сбой certbot: hook и state не записаны
        assert not env.hook_path().exists()
        assert not env.state_path.exists()
        assert certbot_calls  # попытка была, но неудачная


class TestGuards:
    def test_dry_run_does_not_mutate(self, env: Env) -> None:
        rc = acme.run_issue(domain=DOMAIN_OK, email=EMAIL, dry_run=True, state_path=str(env.state_path))
        assert rc == 0
        assert apt_calls == [] and certbot_calls == []
        assert not env.hook_path().exists()
        assert not env.state_path.exists()
        assert not env.fullchain(DOMAIN_OK).exists()

    def test_busy_port_refused_before_changes(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(acme, "port_free", lambda port, proto="tcp": False)
        monkeypatch.setattr(acme, "port_owner", lambda port, proto="tcp": "squid")
        rc = acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path))
        assert rc == 1
        assert apt_calls == [] and certbot_calls == []
        assert not env.hook_path().exists()

    def test_dns_mismatch_refused(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        rc = acme.run_issue(domain=DOMAIN_FAIL, email=EMAIL, state_path=str(env.state_path))
        assert rc == 1
        assert apt_calls == [] and certbot_calls == []
        assert not env.state_path.exists()

    def test_dns_mismatch_message(self, env: Env) -> None:
        with acme.console.capture() as captured:
            rc = acme.run_issue(domain=DOMAIN_FAIL, email=EMAIL, state_path=str(env.state_path))
        assert rc == 1
        assert "не резолвится" in captured.get()

    def test_no_root_readable_refusal(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        with acme.console.capture() as captured:
            rc = acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path))
        assert rc == 1
        assert "root" in captured.get()
        assert apt_calls == [] and certbot_calls == []

    def test_bad_domain_refused(self, env: Env) -> None:
        assert acme.run_issue(domain="not a domain", email=EMAIL) == 1
        assert apt_calls == []

    def test_certbot_missing_then_apt_fails(self, env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
        original = acme.run_list

        def _run_list_apt_fail(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:2] == ["apt-get", "install"]:
                return ShellResult(stdout="", stderr="apt locked", returncode=100)
            if args[:2] == [acme.CERTBOT, "--version"]:
                return ShellResult(stdout="", stderr="not found", returncode=127)
            return original(args, timeout=timeout)

        monkeypatch.setattr(acme, "run_list", _run_list_apt_fail)
        assert acme.run_issue(domain=DOMAIN_OK, email=EMAIL, state_path=str(env.state_path)) == 1
        assert certbot_calls == []


class TestPureFunctions:
    def test_parse_not_after(self) -> None:
        now = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
        assert acme._parse_not_after("notAfter=Mar  1 12:00:00 2027 GMT", now=now) == 112
        assert acme._parse_not_after("notAfter=Nov 9 12:00:00 2026 GMT", now=now) == 0
        assert acme._parse_not_after("notAfter=Nov 8 12:00:00 2026 GMT", now=now) == -1

    def test_render_deploy_hook_no_secrets(self) -> None:
        hook = acme.render_deploy_hook(DOMAIN_OK)
        assert hook.startswith("#!/bin/sh")
        assert DOMAIN_OK in hook
        assert acme.FULLCHAIN_NAME in hook and acme.PRIVKEY_NAME in hook
        # приватного материала в hook быть не может: только пути и команды
        assert "BEGIN" not in hook and "PRIVATE KEY" not in hook

    def test_certbot_issue_args_idempotent_flag(self) -> None:
        args = acme._certbot_issue_args(DOMAIN_OK, EMAIL)
        assert args[0] == "certbot" and "--standalone" in args
        assert args[args.index("-d") + 1] == DOMAIN_OK
        assert "--keep-until-expiring" in args
