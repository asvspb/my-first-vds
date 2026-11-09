"""Тесты XHTTP: add/remove-transport (идемпотентность, бэкап, откат, E-кейсы)
и share-link `security=tls&network=xhttp` (SPEC WP-3, REQ FR-1.x).

Все shell/DNS-зависимости мокируются; конфиг и state — в tmp-каталогах
(фикстуры: FIXTURE_UUID_/203.0.113.x RFC 5737 — AGENTS.md §6).
"""

import json
from pathlib import Path

import pytest

import src.xray.clients as clients
import src.xray.install as install
import src.xray.remove as remove_mod
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state
from src.xray.config import XrayConfigParams, render_config

UUID = "11111111-2222-3333-4444-555555555555"  # зарезервированный fixture-UUID
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
SNI = "www.google.com"
DOMAIN = "example-103-45-247-172.example.invalid"


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(stdout=stdout, stderr="", returncode=0)


@pytest.fixture()
def xray_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp-конфиг (Reality, без XHTTP) + tmp-state; shell/DNS/lock — моки."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        render_config(
            XrayConfigParams(
                private_key=PRIVATE_KEY,
                short_ids=[SHORT_ID],
                sni=SNI,
                port=443,
            )
        ),
        encoding="utf-8",
    )
    live_dir = tmp_path / "letsencrypt" / "live" / DOMAIN
    live_dir.mkdir(parents=True)
    (live_dir / "fullchain.pem").write_text("FIXTURE_CERT\n", encoding="utf-8")
    (live_dir / "privkey.pem").write_text("FIXTURE_KEY\n", encoding="utf-8")
    bin_path = tmp_path / "xray"
    bin_path.write_text("#!/bin/sh\n", encoding="utf-8")

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

    monkeypatch.setattr(install, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(install, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(install, "ACME_LETSENCRYPT_LIVE", lambda d: tmp_path / "letsencrypt" / "live" / d)
    monkeypatch.setattr(install, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr(install, "_dns_resolves_to", lambda domain, ip: True)
    monkeypatch.setattr(install, "LOCK_FILE", str(tmp_path / "xray.lock"))
    monkeypatch.setattr(install, "run_list", lambda args, timeout=10: _ok())

    monkeypatch.setattr(remove_mod, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(remove_mod, "XRAY_BIN_PATH", bin_path)
    monkeypatch.setattr(remove_mod, "XHTTP_LOCK_FILE", str(tmp_path / "xray.lock"))
    monkeypatch.setattr(remove_mod, "run_list", lambda args, timeout=10: _ok())

    monkeypatch.setattr(clients, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(clients, "run_list", lambda args, timeout=10: _ok())
    monkeypatch.setattr(clients, "public_ip", lambda: "203.0.113.10")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return tmp_path


class TestAddTransportXHTTP:
    def test_dry_run_changes_nothing(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        before = (xray_env / "config.json").read_text(encoding="utf-8")
        info = install.add_transport_xhttp(DOMAIN, state_path=state_path)
        assert info["dry_run"] is True
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before
        assert not (xray_env / "config.json.bak-pre-xhttp").exists()

    def test_apply_writes_fallbacks_and_state(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        info = install.add_transport_xhttp(
            DOMAIN, state_path=state_path, apply=True
        )
        assert info["dry_run"] is False
        config = json.loads((xray_env / "config.json").read_text(encoding="utf-8"))
        assert len(config["inbounds"]) == 2
        stream = config["inbounds"][0]["streamSettings"]
        assert stream["fallbacks"] == [
            {"alpn": ["http/1.1", "h2"], "dest": "127.0.0.1:8443"}
        ]
        internal = config["inbounds"][1]
        assert internal["listen"] == "127.0.0.1"
        assert internal["port"] == 8443
        # Reality-поля не изменились
        reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["privateKey"] == PRIVATE_KEY
        assert reality["dest"] == f"{SNI}:443"

        from src.gateway.store import load_state

        meta = load_state(state_path).protocols["xhttp"]
        assert meta == {
            "installed": True,
            "port": 8443,
            "mode": "fallback",
            "domain": DOMAIN,
            "extra": {"path": "/xhttp"},
        }
        assert (xray_env / "config.json.bak-pre-xhttp").is_file()

    def test_idempotent_second_apply(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        first = install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert first["dry_run"] is False
        after_first = (xray_env / "config.json").read_text(encoding="utf-8")
        second = install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert second["already_enabled"] is True
        assert (
            xray_env / "config.json"
        ).read_text(encoding="utf-8") == after_first

    def test_missing_le_cert_refuses_with_acme_hint(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        (xray_env / "letsencrypt" / "live" / DOMAIN / "fullchain.pem").unlink()
        before = (xray_env / "config.json").read_text(encoding="utf-8")
        with pytest.raises(install.InstallError) as excinfo:
            install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert "vds acme issue" in str(excinfo.value)
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before

    def test_dns_mismatch_refused_e1(self, xray_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state_path = str(xray_env / "state.json")
        monkeypatch.setattr(install, "_dns_resolves_to", lambda domain, ip: False)
        before = (xray_env / "config.json").read_text(encoding="utf-8")
        with pytest.raises(install.InstallError) as excinfo:
            install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert "E1" in str(excinfo.value)
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before

    def test_xray_test_fail_rolls_back_e8(
        self, xray_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path = str(xray_env / "state.json")
        before = (xray_env / "config.json").read_text(encoding="utf-8")

        def _fail_on_test(args: list[str], timeout: int = 10) -> ShellResult:
            if "run" in args and "-test" in args:
                return ShellResult(
                    stdout="", stderr="failed to parse config", returncode=1
                )
            return _ok()

        monkeypatch.setattr(install, "run_list", _fail_on_test)
        with pytest.raises(install.InstallError) as excinfo:
            install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        assert "откатан" in str(excinfo.value)
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before


class TestRemoveTransportXHTTP:
    def test_not_root_refused(
        self, xray_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        assert (
            remove_mod.remove_transport_xhttp(
                state_path=str(xray_env / "state.json")
            )
            == 1
        )

    def _installed(self, xray_env: Path) -> str:
        state_path = str(xray_env / "state.json")
        install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        return state_path

    def test_dry_run_by_default(self, xray_env: Path) -> None:
        state_path = self._installed(xray_env)
        before = (xray_env / "config.json").read_text(encoding="utf-8")
        assert remove_mod.remove_transport_xhttp(state_path=state_path) == 0
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before

    def test_apply_strips_fallbacks_inbound_and_state(self, xray_env: Path) -> None:
        state_path = self._installed(xray_env)
        # добавим XHTTP-клиента, чтобы проверить вычитание из store
        clients.add_client("xhttp-dev", transport="xhttp", state_path=state_path)

        assert remove_mod.remove_transport_xhttp(
            state_path=state_path, apply=True, yes=True
        ) == 0

        config = json.loads((xray_env / "config.json").read_text(encoding="utf-8"))
        assert len(config["inbounds"]) == 1
        assert "fallbacks" not in config["inbounds"][0]["streamSettings"]
        reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["privateKey"] == PRIVATE_KEY

        from src.gateway.store import load_state

        state = load_state(state_path)
        assert "xhttp" not in state.protocols
        names = [c.name for c in state.clients]
        assert names == [] or all(c.extra.get("transport") != "xhttp" for c in state.clients)

    def test_idempotent_nothing_to_remove(self, xray_env: Path) -> None:
        state_path = self._installed(xray_env)
        remove_mod.remove_transport_xhttp(state_path=state_path, apply=True, yes=True)
        assert remove_mod.remove_transport_xhttp(
            state_path=state_path, apply=True, yes=True
        ) == 0

    def test_re_add_after_remove_writes_installed_true(
        self, xray_env: Path
    ) -> None:
        """Регрессия TECHDEBT P13 (asv1): remove вычищает весь ключ
        protocols['xhttp'], повторный add должен вернуть meta с
        installed=True — иначе gateway status показывает «not installed».
        """
        from src.gateway.store import load_state

        state_path = str(xray_env / "state.json")
        install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        remove_mod.remove_transport_xhttp(
            state_path=state_path, apply=True, yes=True
        )
        assert "xhttp" not in load_state(state_path).protocols
        info = install.add_transport_xhttp(
            DOMAIN, state_path=state_path, apply=True
        )
        assert info["dry_run"] is False
        meta = load_state(state_path).protocols["xhttp"]
        assert meta["installed"] is True
        assert meta["port"] == 8443
        assert meta["domain"] == DOMAIN

    def test_restart_fail_rolls_back(self, xray_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state_path = self._installed(xray_env)
        before = (xray_env / "config.json").read_text(encoding="utf-8")

        def _fail_on_restart(args: list[str], timeout: int = 10) -> ShellResult:
            if args[:2] == ["systemctl", "restart"]:
                return ShellResult(stdout="", stderr="restart failed", returncode=1)
            return _ok()

        monkeypatch.setattr(remove_mod, "run_list", _fail_on_restart)
        assert remove_mod.remove_transport_xhttp(
            state_path=state_path, apply=True, yes=True
        ) == 1
        assert (xray_env / "config.json").read_text(encoding="utf-8") == before


class TestXHTTPShareLink:
    def test_exact_format(self) -> None:
        link = clients.render_xhttp_share_link(
            domain=DOMAIN, client_uuid=UUID, name="xhttp-dev"
        )
        assert link == (
            f"vless://{UUID}@{DOMAIN}:443"
            f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
            f"&path=/xhttp&type=xhttp#xhttp-dev"
        )

    def test_no_secrets_or_cert_paths_in_link(self) -> None:
        link = clients.render_xhttp_share_link(
            domain=DOMAIN, client_uuid=UUID, name="n"
        )
        assert "PRIVATEKEY" not in link
        assert "fullchain" not in link
        assert "privkey" not in link

    def test_port_mode_link_uses_8443(self) -> None:
        link = clients.render_xhttp_share_link(
            domain=DOMAIN, client_uuid=UUID, name="n", port=8443
        )
        assert f"@{DOMAIN}:8443?" in link

    def test_add_client_xhttp_writes_second_inbound(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        result = clients.add_client(
            "xhttp-dev", transport="xhttp", state_path=state_path
        )
        assert result["transport"] == "xhttp"
        assert result["share_link"] == (
            f"vless://{result['uuid']}@{DOMAIN}:443"
            f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
            f"&path=/xhttp&type=xhttp#xhttp-dev"
        )
        config = json.loads((xray_env / "config.json").read_text(encoding="utf-8"))
        xhttp_clients = config["inbounds"][1]["settings"]["clients"]
        assert xhttp_clients == [{"id": result["uuid"]}]

    def test_state_stores_extra_path(self, xray_env: Path) -> None:
        from src.gateway.store import load_state

        state_path = str(xray_env / "state.json")
        install.add_transport_xhttp(DOMAIN, state_path=state_path, apply=True)
        meta = load_state(state_path).protocols["xhttp"]
        assert meta["extra"] == {"path": "/xhttp"}

    def test_add_client_xhttp_without_transport_refuses(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        with pytest.raises(clients.XrayError) as excinfo:
            clients.add_client("xhttp-dev", transport="xhttp", state_path=state_path)
        assert "add-transport xhttp" in str(excinfo.value)

    def test_add_client_reality_unaffected(self, xray_env: Path) -> None:
        state_path = str(xray_env / "state.json")
        result = clients.add_client("phone", state_path=state_path)
        assert "security=reality" in result["share_link"]
        assert result["share_link"] == (
            f"vless://{result['uuid']}@203.0.113.10:443"
            f"?security=reality&sni={SNI}&fp=chrome"
            f"&pbk=FIXTURE_UUID_PUBKEY&sid={SHORT_ID}"
            f"&flow=xtls-rprx-vision#phone"
        )
