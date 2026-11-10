"""Тесты src/xray/cdn.py (SPEC-20261110 WP-2, ADR-006): прекондишны,
install/remove, клиенты, идемпотентность — на моках и tmp-каталогах,
без root/сети/ufw (AGENTS.md §7).

Секретные фикстуры — только префиксы FIXTURE_* и зарезервированные
UUID/IP (203.0.113.0/24 RFC 5737, 11111111-…), AGENTS.md §6.
"""

import json
from pathlib import Path

import pytest

import src.xray.cdn as cdn
from src.core.shell import ShellResult
from src.gateway.paths import CDN_ORIGIN_PORT_DEFAULT, CDN_WS_PATH
from src.gateway.store import GatewayState, load_state, save_state
from src.xray.config import render_config, XrayConfigParams

UUID = "11111111-2222-3333-4444-555555555555"
CDN_UUID_1 = "11111111-2222-3333-4444-666666666666"
CDN_UUID_2 = "11111111-2222-3333-4444-777777777777"
XHTTP_UUID = "11111111-2222-3333-4444-888888888888"
CERT_PATH = "/etc/letsencrypt/live/example.invalid/fullchain.pem"
KEY_PATH = "/etc/letsencrypt/live/example.invalid/privkey.pem"
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
SERVER_IP = "203.0.113.10"
CF_IP = "104.16.132.229"
CDN_DOMAIN = "cdn.example.invalid"
SNI = "www.google.com"


class _CallRecorder:
    """Записывает вызовы run_list с настраиваемым исходом (гейты/ufw)."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail_on = fail_on  # подстрока argv, при которой команда «падает»

    def __call__(self, args: list[str], timeout: int = 10) -> ShellResult:
        self.calls.append(list(args))
        argv = " ".join(args)
        if self.fail_on and self.fail_on in argv:
            return ShellResult(stdout="", stderr="mock failure", returncode=1)
        return ShellResult(stdout="", stderr="", returncode=0)

    def argv_of(self, index: int) -> str:
        return " ".join(self.calls[index])


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, _CallRecorder]:
    """Tmp-конфиг/состояние/LE-каталог; shell, DNS и IP — моки (RFC 5737)."""
    config_path = tmp_path / "etc" / "xray" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        render_config(
            XrayConfigParams(
                client_ids=[UUID],
                private_key=PRIVATE_KEY,
                short_ids=[SHORT_ID],
                sni=SNI,
                port=443,
            )
        ),
        encoding="utf-8",
    )

    bin_path = tmp_path / "usr" / "local" / "bin" / "xray"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("#!/bin/sh\n", encoding="utf-8")

    live_dir = tmp_path / "live"
    (live_dir / CDN_DOMAIN).mkdir(parents=True)
    (live_dir / CDN_DOMAIN / "fullchain.pem").write_text("FIXTURE_CERT\n")
    (live_dir / CDN_DOMAIN / "privkey.pem").write_text("FIXTURE_KEY\n")

    state_path = tmp_path / "state.json"
    state = GatewayState()
    state.protocols["xray"] = {
        "installed": True,
        "sni": SNI,
        "port": 443,
        "public_key": "FIXTURE_PUBKEY",
        "short_id": SHORT_ID,
    }
    save_state(state, str(state_path))

    recorder = _CallRecorder()
    monkeypatch.setattr(cdn, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(cdn, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(cdn, "LOCK_FILE", str(tmp_path / "cdn.lock"))
    monkeypatch.setattr(cdn, "ACME_LETSENCRYPT_LIVE", lambda domain: live_dir / domain)
    monkeypatch.setattr(cdn, "run_list", recorder)
    monkeypatch.setattr(cdn, "command_exists", lambda name: True)
    monkeypatch.setattr(cdn, "port_free", lambda port, proto="tcp": True)
    monkeypatch.setattr(cdn, "public_ip", lambda: SERVER_IP)
    monkeypatch.setattr(cdn, "resolve_ips", lambda domain: [SERVER_IP])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return state_path, recorder


def _params(domain: str = CDN_DOMAIN, port: int = CDN_ORIGIN_PORT_DEFAULT) -> cdn.CdnParams:
    return cdn.CdnParams(domain=domain, port=port)


@pytest.fixture()
def env_xhttp(
    env: tuple[Path, _CallRecorder],
) -> tuple[Path, _CallRecorder]:
    """env + текущий config.json с Reality+XHTTP (mode=port, публичный 8443).

    Регресс-фикстура B-1: старый env-конфиг был без xhttp_enabled — CDN-рендер
    молча удалял XHTTP-инблэнд из живого конфига.
    """
    config_path = cdn.XRAY_CONFIG_PATH
    config_path.write_text(
        render_config(
            XrayConfigParams(
                client_ids=[UUID],
                private_key=PRIVATE_KEY,
                short_ids=[SHORT_ID],
                sni=SNI,
                port=443,
                xhttp_enabled=True,
                domain="example.invalid",
                cert_path=CERT_PATH,
                key_path=KEY_PATH,
                xhttp_client_ids=[XHTTP_UUID],
                xhttp_mode="port",
            )
        ),
        encoding="utf-8",
    )
    return env


def _xhttp_inbound(config: dict) -> dict:
    return next(
        ib for ib in config["inbounds"]
        if ib.get("streamSettings", {}).get("network") == "xhttp"
    )


def _ws_inbound(config: dict) -> dict:
    return next(
        ib for ib in config["inbounds"]
        if ib.get("streamSettings", {}).get("network") == "ws"
    )


class TestIsCloudflareIp:
    def test_cf_v4(self) -> None:
        assert cdn.is_cloudflare_ip(CF_IP) is True
        assert cdn.is_cloudflare_ip("172.64.0.1") is True
        assert cdn.is_cloudflare_ip("103.21.244.10") is True

    def test_non_cf_v4(self) -> None:
        assert cdn.is_cloudflare_ip(SERVER_IP) is False
        assert cdn.is_cloudflare_ip("8.8.8.8") is False

    def test_cf_v6(self) -> None:
        assert cdn.is_cloudflare_ip("2606:4700::6810:84e5") is True

    def test_garbage(self) -> None:
        assert cdn.is_cloudflare_ip("not-an-ip") is False

    def test_resolve_ips_mockable(self, env: tuple[Path, _CallRecorder]) -> None:
        # Сетевой примитив изолирован: resolve_ips подменяется в env-фикстуре.
        assert cdn.resolve_ips(CDN_DOMAIN) == [SERVER_IP]


class TestCheckPrerequisites:
    def test_happy_empty(self, env: tuple[Path, _CallRecorder]) -> None:
        assert cdn.check_prerequisites(_params()) == []

    def test_no_le_cert_hint(self, env: tuple[Path, _CallRecorder]) -> None:
        params = _params("cdn.other.invalid")  # live-каталог не создавался
        violations = cdn.check_prerequisites(params)
        assert any("acme issue" in v and "cdn.other.invalid" in v for v in violations)

    def test_dns_not_resolving(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cdn, "resolve_ips", lambda domain: [])
        violations = cdn.check_prerequisites(_params())
        assert any("не резолвится" in v for v in violations)

    def test_dns_mismatch(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cdn, "resolve_ips", lambda domain: ["198.51.100.7"])
        violations = cdn.check_prerequisites(_params())
        assert any("DNS-mismatch" in v for v in violations)

    def test_dns_resolves_to_cf(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> None:
        # orange cloud: домен резолвится в CF — прекондишн выполнен.
        monkeypatch.setattr(cdn, "resolve_ips", lambda domain: [CF_IP])
        assert cdn.check_prerequisites(_params()) == []

    def test_xray_not_installed(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cdn, "XRAY_BIN_PATH", Path("/nonexistent/xray"))
        violations = cdn.check_prerequisites(_params())
        assert any("xray install" in v for v in violations)


class TestInstallCdn:
    def test_happy_sequence(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        """Verbatim-последовательность happy-path: test -> restart -> ufw."""
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        argvs = [" ".join(c) for c in recorder.calls]
        expected_test = (
            f"{cdn.XRAY_BIN_PATH} run -test -config {cdn.XRAY_CONFIG_PATH}"
        )
        assert argvs == [
            expected_test,
            f"systemctl restart {cdn.XRAY_UNIT}",
            "ufw allow 2053/tcp",
        ]

        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        cdn_inbounds = [
            ib for ib in config["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        ]
        assert len(cdn_inbounds) == 1
        assert cdn_inbounds[0]["port"] == 2053
        assert cdn_inbounds[0]["settings"]["clients"] == []

        state = load_state(str(state_path))
        meta = state.protocols["xray-cdn"]
        assert meta["installed"] is True
        assert meta["domain"] == CDN_DOMAIN
        assert meta["port"] == 2053
        assert meta["path"] == CDN_WS_PATH
        assert meta["client_ids"] == []

        # Reality-инблэнд перенесён без изменений.
        reality = config["inbounds"][0]
        assert reality["streamSettings"]["realitySettings"]["privateKey"] == PRIVATE_KEY

    def test_idempotent_same_domain_no_regen(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        # Второй прогон с тем же доменом: exit 0, ни одной shell-команды.
        recorder.calls.clear()
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        assert recorder.calls == []

    def test_reconfigure_other_domain(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        recorder.calls.clear()
        live2 = cdn.ACME_LETSENCRYPT_LIVE("cdn2.example.invalid")
        live2.mkdir(parents=True, exist_ok=True)
        (live2 / "fullchain.pem").write_text("FIXTURE_CERT\n")
        (live2 / "privkey.pem").write_text("FIXTURE_KEY\n")
        other = _params("cdn2.example.invalid")
        assert cdn.install_cdn(other, str(state_path)) == 0
        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        ws_host = (
            config["inbounds"][-1]["streamSettings"]["wsSettings"]["headers"]["Host"]
        )
        assert ws_host == "cdn2.example.invalid"
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["domain"] == "cdn2.example.invalid"

    def test_xray_test_fail_rollback(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        original = cdn.XRAY_CONFIG_PATH.read_bytes()
        recorder.fail_on = "-test"
        assert cdn.install_cdn(_params(), str(state_path)) == 1
        # Конфиг откатан байт-в-байт, ufw не вызывался, state не записан.
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == original
        assert all("ufw" not in " ".join(c) for c in recorder.calls)
        state = load_state(str(state_path))
        assert "xray-cdn" not in state.protocols

    def test_restart_fail_rollback(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, recorder = env
        original = cdn.XRAY_CONFIG_PATH.read_bytes()
        recorder.fail_on = "restart"
        assert cdn.install_cdn(_params(), str(state_path)) == 1
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == original
        state = load_state(str(state_path))
        assert "xray-cdn" not in state.protocols

    def test_prerequisites_block_no_changes(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        original = cdn.XRAY_CONFIG_PATH.read_bytes()
        monkeypatch.setattr(cdn, "resolve_ips", lambda domain: ["198.51.100.7"])
        assert cdn.install_cdn(_params(), str(state_path)) == 1
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == original
        assert recorder.calls == []

    def test_root_required(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        state_path, _ = env
        assert cdn.add_cdn(CDN_DOMAIN, state_path=str(state_path)) == 1

    def test_same_domain_other_port_reconfigures(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        """B-3: домен совпал, порт другой — перенастройка, а не exit 0."""
        state_path, recorder = env
        assert cdn.install_cdn(_params(port=2053), str(state_path)) == 0
        recorder.calls.clear()
        assert cdn.install_cdn(_params(port=2087), str(state_path)) == 0
        # Перенастройка выполняла мутации (test -> restart -> ufw).
        assert recorder.calls != []
        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        assert _ws_inbound(config)["port"] == 2087
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["port"] == 2087


class TestXhttpPreserved:
    """B-1 регресс: CDN-рендер переносит XHTTP-часть из текущего config.json."""

    def test_add_cdn_preserves_xhttp_inbound(
        self, env_xhttp: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, _ = env_xhttp
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        networks = [ib["streamSettings"]["network"] for ib in config["inbounds"]]
        assert networks == ["tcp", "xhttp", "ws"]
        xhttp = _xhttp_inbound(config)
        assert xhttp["port"] == 8443
        assert xhttp["settings"]["clients"] == [{"id": XHTTP_UUID}]
        assert (
            xhttp["streamSettings"]["tlsSettings"]["certificates"][0]
            ["certificateFile"]
        ) == CERT_PATH
        assert (
            xhttp["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"]
        ) == KEY_PATH
        # Reality-инблэнд тоже перенесён.
        assert config["inbounds"][0]["streamSettings"]["realitySettings"][
            "privateKey"
        ] == PRIVATE_KEY

    def test_add_cdn_client_preserves_xhttp(
        self, env_xhttp: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, _ = env_xhttp
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        cdn.add_cdn_client("phone", str(state_path))
        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        assert _xhttp_inbound(config)["settings"]["clients"] == [{"id": XHTTP_UUID}]
        assert _ws_inbound(config)["settings"]["clients"] == [{"id": CDN_UUID_1}]

    def test_remove_cdn_keeps_xhttp(
        self, env_xhttp: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, _ = env_xhttp
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 0
        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        networks = [ib["streamSettings"]["network"] for ib in config["inbounds"]]
        assert networks == ["tcp", "xhttp"]


class TestAddCdnClient:
    def test_client_added_config_and_state(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        recorder.calls.clear()
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)

        result = cdn.add_cdn_client("phone", str(state_path))
        assert result["uuid"] == CDN_UUID_1
        assert result["share_link"] == (
            f"vless://{CDN_UUID_1}@{CDN_DOMAIN}:2053"
            f"?encryption=none&security=tls&sni={CDN_DOMAIN}"
            f"&type=ws&host={CDN_DOMAIN}&path=%2Fcdnws#phone"
        )

        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        ws_inbound = next(
            ib for ib in config["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        )
        assert ws_inbound["settings"]["clients"] == [{"id": CDN_UUID_1}]

        state = load_state(str(state_path))
        meta = state.protocols["xray-cdn"]
        assert meta["client_ids"] == [CDN_UUID_1]
        assert meta["clients"] == {"phone": CDN_UUID_1}

        # update-последовательность: test -> restart (ufw для клиента не нужен)
        argvs = [" ".join(c) for c in recorder.calls]
        assert argvs == [
            f"{cdn.XRAY_BIN_PATH} run -test -config {cdn.XRAY_CONFIG_PATH}",
            f"systemctl restart {cdn.XRAY_UNIT}",
        ]

    def test_second_client_appends(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, _ = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        cdn.add_cdn_client("phone", str(state_path))
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_2)
        cdn.add_cdn_client("mob", str(state_path))

        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        ws_inbound = next(
            ib for ib in config["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        )
        ids = [c["id"] for c in ws_inbound["settings"]["clients"]]
        assert ids == [CDN_UUID_1, CDN_UUID_2]
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["client_ids"] == [CDN_UUID_1, CDN_UUID_2]

    def test_duplicate_name(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, _ = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        cdn.add_cdn_client("phone", str(state_path))
        with pytest.raises(cdn.CdnError, match="уже существует"):
            cdn.add_cdn_client("phone", str(state_path))

    def test_no_cdn_installed(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, _ = env
        with pytest.raises(cdn.CdnError, match="не установлен"):
            cdn.add_cdn_client("phone", str(state_path))

    def test_client_fail_restart_rollback(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        before = cdn.XRAY_CONFIG_PATH.read_bytes()
        recorder.fail_on = "restart"
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        with pytest.raises(cdn.CdnError):
            cdn.add_cdn_client("phone", str(state_path))
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == before
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["client_ids"] == []


class TestRemoveCdnClient:
    """B-2: remove_cdn_client — dry-run по умолчанию, apply, несуществующий."""

    def _setup(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> tuple[Path, _CallRecorder]:
        state_path, recorder = env
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        cdn.add_cdn_client("phone", str(state_path))
        recorder.calls.clear()
        return state_path, recorder

    def test_dry_run_no_changes(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = self._setup(env, monkeypatch)
        before = cdn.XRAY_CONFIG_PATH.read_bytes()
        result = cdn.remove_cdn_client("phone", apply=False, state_path=str(state_path))
        assert result["dry_run"] is True
        assert any("phone" in item for item in result["plan"])
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == before
        assert recorder.calls == []
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["clients"] == {"phone": CDN_UUID_1}

    def test_apply_removes_from_config_and_state(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = self._setup(env, monkeypatch)
        result = cdn.remove_cdn_client("phone", apply=True, state_path=str(state_path))
        assert result["dry_run"] is False

        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        assert _ws_inbound(config)["settings"]["clients"] == []
        state = load_state(str(state_path))
        meta = state.protocols["xray-cdn"]
        assert meta["client_ids"] == []
        assert meta["clients"] == {}

        # update-последовательность: test -> restart (ufw не нужен).
        argvs = [" ".join(c) for c in recorder.calls]
        assert argvs == [
            f"{cdn.XRAY_BIN_PATH} run -test -config {cdn.XRAY_CONFIG_PATH}",
            f"systemctl restart {cdn.XRAY_UNIT}",
        ]

    def test_nonexistent_client(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = self._setup(env, monkeypatch)
        before = cdn.XRAY_CONFIG_PATH.read_bytes()
        with pytest.raises(cdn.CdnError, match="не найден"):
            cdn.remove_cdn_client("ghost", apply=True, state_path=str(state_path))
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == before
        assert recorder.calls == []

    def test_apply_restart_fail_rollback(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = self._setup(env, monkeypatch)
        # Бэкап CLIENT_BACKUP_SUFFIX создан при add_cdn_client и не
        # перезаписывается (снапшот первой операции, паттерн модуля) —
        # откат возвращает именно его содержимое.
        backup_snapshot = cdn.XRAY_CONFIG_PATH.with_name(
            cdn.XRAY_CONFIG_PATH.name + cdn.CLIENT_BACKUP_SUFFIX
        ).read_bytes()
        recorder.fail_on = "restart"
        with pytest.raises(cdn.CdnError):
            cdn.remove_cdn_client("phone", apply=True, state_path=str(state_path))
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == backup_snapshot
        state = load_state(str(state_path))
        assert state.protocols["xray-cdn"]["clients"] == {"phone": CDN_UUID_1}


class TestRemoveCdn:
    def _install(self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch) -> Path:
        state_path, _ = env
        monkeypatch.setattr(cdn, "gen_uuid", lambda: CDN_UUID_1)
        assert cdn.install_cdn(_params(), str(state_path)) == 0
        cdn.add_cdn_client("phone", str(state_path))
        return state_path

    def test_nothing_to_remove(self, env: tuple[Path, _CallRecorder]) -> None:
        state_path, recorder = env
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 0
        assert recorder.calls == []

    def test_dry_run_no_changes(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        self._install(env, monkeypatch)
        before = cdn.XRAY_CONFIG_PATH.read_bytes()
        assert cdn.remove_cdn(apply=False, state_path=str(state_path)) == 0
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == before
        state = load_state(str(state_path))
        assert "xray-cdn" in state.protocols
        # dry-run не добавляет новых команд (recorder содержит только
        # вызовы install/add-client из _install).
        remove_calls_start = len(recorder.calls)
        cdn.remove_cdn(apply=False, state_path=str(state_path))
        assert len(recorder.calls) == remove_calls_start

    def test_apply_removes_inbound_state_ufw(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        self._install(env, monkeypatch)
        recorder.calls.clear()
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 0

        config = json.loads(cdn.XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
        networks = [ib["streamSettings"]["network"] for ib in config["inbounds"]]
        assert networks == ["tcp"]  # Reality остался, ws-инблэнд снят
        reality = config["inbounds"][0]
        assert reality["streamSettings"]["realitySettings"]["privateKey"] == PRIVATE_KEY
        assert reality["settings"]["clients"] == [
            {"id": UUID, "flow": "xtls-rprx-vision"}
        ]

        state = load_state(str(state_path))
        assert "xray-cdn" not in state.protocols
        # Reality-клиенты не затронуты (store-клиенты cdn — только meta-ключ).

        argvs = [" ".join(c) for c in recorder.calls]
        assert argvs == [
            f"{cdn.XRAY_BIN_PATH} run -test -config {cdn.XRAY_CONFIG_PATH}",
            f"systemctl restart {cdn.XRAY_UNIT}",
            "ufw delete allow 2053/tcp",
        ]

    def test_apply_idempotent_twice(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, _ = env
        self._install(env, monkeypatch)
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 0
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 0

    def test_apply_xray_test_fail_keeps_cdn(
        self, env: tuple[Path, _CallRecorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path, recorder = env
        self._install(env, monkeypatch)
        before = cdn.XRAY_CONFIG_PATH.read_bytes()
        recorder.fail_on = "-test"
        assert cdn.remove_cdn(apply=True, yes=True, state_path=str(state_path)) == 1
        assert cdn.XRAY_CONFIG_PATH.read_bytes() == before
        state = load_state(str(state_path))
        assert "xray-cdn" in state.protocols


class TestStateFormat:
    def test_state_key_and_fields(
        self, env: tuple[Path, _CallRecorder]
    ) -> None:
        state_path, _ = env
        assert cdn.install_cdn(_params(port=2053), str(state_path)) == 0
        state = load_state(str(state_path))
        meta = state.protocols["xray-cdn"]
        assert set(meta) == {"installed", "domain", "port", "path", "client_ids", "clients"}
        assert meta["installed"] is True
        assert meta["port"] == 2053
