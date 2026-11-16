"""HF-2 (SPEC-20261116-surface-hardening §2.1/§2.2): рандомизация путей
XHTTP/CDN-WS, фикс кросс-рендера, путь-секрет — T7/T8/T9/T11 + cdn_ws_path.

Все shell/DNS-зависимости мокируются; конфиг и state — tmp-каталоги.
Фикстуры: путь-секрет — фиксированный hex ("/aaaa1111bbbb2222cccc"),
UUID/IP — зарезервированные (11111111-…, 203.0.113.0/24 RFC 5737), AGENTS.md §6.
"""

import io
import json
import re
from pathlib import Path

import pytest
from rich.console import Console

import src.xray.cdn as cdn
import src.xray.clients as clients
import src.xray.install as install
from src.core.shell import ShellResult
from src.gateway.paths import CDN_WS_PATH
from src.gateway.store import GatewayState, load_state, save_state
from src.xray.config import XrayConfigParams, render_config

UUID = "11111111-2222-3333-4444-555555555555"
XHTTP_UUID = "11111111-2222-3333-4444-888888888888"
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
SNI = "www.google.com"
SERVER_IP = "203.0.113.10"
DOMAIN = "example-103-45-247-172.example.invalid"
CDN_DOMAIN = "cdn.example.invalid"
CERT_PATH = "/etc/letsencrypt/live/example.invalid/fullchain.pem"
KEY_PATH = "/etc/letsencrypt/live/example.invalid/privkey.pem"
# Фикстура «рандомного» пути-секрета: формат gen_secret_path (16..24 hex),
# зарезервированное значение — не правдоподобный секрет (AGENTS.md §6).
SECRET_PATH = "/aaaa1111bbbb2222cccc"


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], timeout: int = 10) -> ShellResult:
        self.calls.append(list(args))
        return ShellResult(stdout="", stderr="", returncode=0)


def _reality_config() -> str:
    return render_config(
        XrayConfigParams(
            client_ids=[UUID],
            private_key=PRIVATE_KEY,
            short_ids=[SHORT_ID],
            sni=SNI,
            port=443,
        )
    )


def _xhttp_config(path: str) -> str:
    return render_config(
        XrayConfigParams(
            client_ids=[UUID],
            private_key=PRIVATE_KEY,
            short_ids=[SHORT_ID],
            sni=SNI,
            port=443,
            xhttp_enabled=True,
            domain=DOMAIN,
            cert_path=CERT_PATH,
            key_path=KEY_PATH,
            xhttp_client_ids=[XHTTP_UUID],
            xhttp_mode="port",
            xhttp_path=path,
        )
    )


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp-окружение install+cdn: Reality-конфиг, LE, state; shell/DNS — моки."""
    config_path = tmp_path / "etc" / "xray" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(_reality_config(), encoding="utf-8")

    bin_path = tmp_path / "usr" / "local" / "bin" / "xray"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("#!/bin/sh\n", encoding="utf-8")

    live_dir = tmp_path / "live"
    for domain in (DOMAIN, CDN_DOMAIN):
        (live_dir / domain).mkdir(parents=True)
        (live_dir / domain / "fullchain.pem").write_text("FIXTURE_CERT\n", encoding="utf-8")
        (live_dir / domain / "privkey.pem").write_text("FIXTURE_KEY\n", encoding="utf-8")

    state_path = tmp_path / "state.json"
    state = GatewayState()
    state.protocols["xray"] = {
        "installed": True,
        "sni": SNI,
        "port": 443,
        "public_key": "FIXTURE_UUID_PUBKEY",
        "short_id": SHORT_ID,
    }
    save_state(state, str(state_path))

    recorder = _Recorder()
    for module in (install, cdn, clients):
        monkeypatch.setattr(module, "XRAY_CONFIG_PATH", config_path)
        monkeypatch.setattr(module, "run_list", recorder)
    monkeypatch.setattr(install, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(cdn, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(install, "ACME_LETSENCRYPT_LIVE", lambda d: live_dir / d)
    monkeypatch.setattr(install, "public_ip", lambda: SERVER_IP)
    monkeypatch.setattr(install, "_dns_resolves_to", lambda domain, ip: True)
    monkeypatch.setattr(install, "LOCK_FILE", str(tmp_path / "xray.lock"))
    monkeypatch.setattr(cdn, "ACME_LETSENCRYPT_LIVE", lambda d: live_dir / d)
    monkeypatch.setattr(cdn, "LOCK_FILE", str(tmp_path / "cdn.lock"))
    monkeypatch.setattr(cdn, "command_exists", lambda name: True)
    monkeypatch.setattr(cdn, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(cdn, "public_ip", lambda: SERVER_IP)
    monkeypatch.setattr(cdn, "resolve_ips", lambda domain: [SERVER_IP])
    monkeypatch.setattr(clients, "public_ip", lambda: SERVER_IP)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return tmp_path


class TestT7PathIdempotency:
    def test_add_transport_twice_path_stable(self, env: Path) -> None:
        state_path = str(env / "state.json")
        first = install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert first["dry_run"] is False
        path1 = load_state(state_path).protocols["xhttp"]["extra"]["path"]
        assert re.fullmatch(r"/[0-9a-f]{16,24}", path1)

        second = install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert second["already_enabled"] is True
        path2 = load_state(state_path).protocols["xhttp"]["extra"]["path"]
        assert path2 == path1  # существующий путь не перегенерируется (T7)

        config = json.loads((env / "etc" / "xray" / "config.json").read_text(encoding="utf-8"))
        xhttp = config["inbounds"][1]["streamSettings"]["xhttpSettings"]
        assert xhttp["path"] == path1


class TestT8CrossRender:
    def test_cdn_setup_preserves_random_xhttp_path(self, env: Path) -> None:
        """Регресс скрытого бага: рандомный path в state/config → cdn setup →
        path в config.json равен state, не сброшен на /xhttp."""
        state_path = str(env / "state.json")
        install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        secret = load_state(state_path).protocols["xhttp"]["extra"]["path"]
        assert secret != "/xhttp"

        assert cdn.install_cdn(
            cdn.CdnParams(domain=CDN_DOMAIN), state_path
        ) == 0
        config = json.loads((env / "etc" / "xray" / "config.json").read_text(encoding="utf-8"))
        xhttp_inbounds = [
            ib for ib in config["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "xhttp"
        ]
        assert len(xhttp_inbounds) == 1
        assert (
            xhttp_inbounds[0]["streamSettings"]["xhttpSettings"]["path"] == secret
        )
        # state не разошёлся с config.json
        assert load_state(state_path).protocols["xhttp"]["extra"]["path"] == secret


class TestT9XhttpFieldsMigration:
    def test_xhttp_fields_extracts_path_from_live_config(self) -> None:
        current = json.loads(_xhttp_config(SECRET_PATH))
        fields = cdn._xhttp_fields(current)
        assert fields is not None
        assert fields["path"] == SECRET_PATH

    def test_render_xhttp_config_inherits_path(self, env: Path) -> None:
        """_render_xhttp_config: state extra.path отсутствует, живой config
        имеет путь — наследуется (миграция без перевыпуска ссылок)."""
        current = json.loads(_xhttp_config(SECRET_PATH))
        rendered = install._render_xhttp_config(current, DOMAIN, "port", [])
        config = json.loads(rendered)
        assert (
            config["inbounds"][1]["streamSettings"]["xhttpSettings"]["path"]
            == SECRET_PATH
        )

    def test_resolve_path_regenerate(self, env: Path) -> None:
        current = json.loads(_xhttp_config(SECRET_PATH))
        # regenerate=True -> новый рандомный путь (отличается от существующего)
        new_path = install._resolve_xhttp_path(current, {}, regenerate=True)
        assert new_path != SECRET_PATH
        assert re.fullmatch(r"/[0-9a-f]{16,24}", new_path)
        # без regenerate: наследуется из config.json (миграция)
        assert install._resolve_xhttp_path(current, {}, regenerate=False) == SECRET_PATH
        # state extra.path приоритетнее
        assert install._resolve_xhttp_path(
            current, {"extra": {"path": "/0000ffff0000ffff"}}, regenerate=False
        ) == "/0000ffff0000ffff"


class TestCdnWsPath:
    def test_add_cdn_generates_random_path_and_keeps_it(self, env: Path) -> None:
        state_path = str(env / "state.json")
        assert cdn.add_cdn(CDN_DOMAIN, state_path=state_path) == 0
        path1 = load_state(state_path).protocols["xray-cdn"]["path"]
        assert path1 != CDN_WS_PATH
        assert re.fullmatch(r"/[0-9a-f]{16,24}", path1)
        config = json.loads((env / "etc" / "xray" / "config.json").read_text(encoding="utf-8"))
        ws = [
            ib for ib in config["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        ][0]
        assert ws["streamSettings"]["wsSettings"]["path"] == path1

        # повторный add-cdn: путь наследуется из state, идемпотентно
        assert cdn.add_cdn(CDN_DOMAIN, state_path=state_path) == 0
        assert load_state(state_path).protocols["xray-cdn"]["path"] == path1


class TestT11PathIsSecret:
    def test_path_not_printed_outside_share_link(
        self, env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path = str(env / "state.json")
        buf = io.StringIO()
        fake_console = Console(file=buf, width=250, force_terminal=False)
        monkeypatch.setattr(install, "console", fake_console)
        monkeypatch.setattr(install, "gen_secret_path", lambda: SECRET_PATH)

        assert install.run_add_transport_xhttp(
            "xhttp", DOMAIN, apply=False, yes=True, state_path=state_path
        ) == 0
        assert SECRET_PATH not in buf.getvalue()  # dry-run без пути

        assert install.run_add_transport_xhttp(
            "xhttp", DOMAIN, apply=True, yes=True, state_path=state_path
        ) == 0
        assert SECRET_PATH not in buf.getvalue()  # apply-вывод без пути

        monkeypatch.setattr(clients, "console", fake_console)
        result = clients.add_client(
            "xhttp-dev", transport="xhttp", state_path=state_path
        )
        out = buf.getvalue()
        # путь — ровно один раз и только в share-link (T11)
        assert out.count(SECRET_PATH) == 1
        assert SECRET_PATH in result["share_link"]
