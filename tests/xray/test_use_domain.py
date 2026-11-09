"""Тесты `vds xray use-domain` (SPEC WP-4, OQ-3, REQ FR-3).

Инварианты: config.json не меняется (dest/serverNames Reality не содержат
домен), идемпотентность, E1 DNS-mismatch до изменений, адрес Reality-ссылки
= state.domain если задан, иначе прежний IP байт-в-байт.
"""

from pathlib import Path

import pytest

import src.xray.clients as clients
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state
from src.xray.config import render_config, XrayConfigParams

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "PUBKEYXYZ"
SID = "abcd1234"
SNI = "www.google.com"
DOMAIN = "103-45-247-172.eu-cloud-xip.com"
IP = "203.0.113.10"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp-конфиг + tmp-state с установленным xray; shell/DNS/ip — моки."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        render_config(XrayConfigParams(private_key="PRIVKEY123", short_ids=[SID])),
        encoding="utf-8",
    )
    state_path = tmp_path / "state.json"
    state = GatewayState()
    state.protocols["xray"] = {
        "installed": True,
        "sni": SNI,
        "port": 443,
        "public_key": PBK,
        "short_id": SID,
    }
    save_state(state, str(state_path))

    monkeypatch.setattr(clients, "XRAY_CONFIG_PATH", config_path)
    monkeypatch.setattr(clients, "LOCK_FILE", str(tmp_path / "domain.lock"))
    monkeypatch.setattr(clients, "public_ip", lambda: IP)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(clients, "dns_resolves_to", lambda d, ip: d == DOMAIN and ip == IP)

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(clients, "run_list", _run_list)
    return tmp_path


def _state_path(env: Path) -> str:
    return str(env / "state.json")


class TestUseDomain:
    def test_happy_sets_domain_and_regen_links(self, env: Path) -> None:
        result = clients.use_domain(DOMAIN, state_path=_state_path(env))

        assert result == {"domain": DOMAIN, "changed": True, "links": result["links"]}
        assert len(result["links"]) == 0  # клиентов ещё нет

        from src.gateway.store import load_state

        assert load_state(_state_path(env)).domain == DOMAIN

    def test_config_untouched_domain_not_in_dest_servernames(self, env: Path) -> None:
        """DoD WP-4: рендер Reality-конфига при use-domain не содержит домена
        в dest/serverNames; конфиг байт-в-байт прежний."""
        before = (env / "config.json").read_text(encoding="utf-8")
        import json

        clients.use_domain(DOMAIN, state_path=_state_path(env))

        after_text = (env / "config.json").read_text(encoding="utf-8")
        assert after_text == before  # config.json не тронут вовсе
        config = json.loads(after_text)
        reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        assert DOMAIN not in reality["dest"]
        assert DOMAIN not in reality["serverNames"]
        assert all(DOMAIN not in name for name in reality["serverNames"])

    def test_regen_reality_links_use_domain(self, env: Path) -> None:
        from src.gateway.store import ClientProfile, load_state

        state = load_state(_state_path(env))
        state.clients.append(
            ClientProfile(
                name="phone",
                protocol="xray",
                port=443,
                uuid=UUID,
                sni=SNI,
                extra={"public_key": PBK, "short_id": SID},
            )
        )
        save_state(state, _state_path(env))

        result = clients.use_domain(DOMAIN, state_path=_state_path(env))
        assert result["changed"] is True
        assert len(result["links"]) == 1
        link = result["links"][0]["share_link"]
        assert link == (
            f"vless://{UUID}@{DOMAIN}:443"
            f"?security=reality&sni={SNI}&fp=chrome"
            f"&pbk={PBK}&sid={SID}&flow=xtls-rprx-vision#phone"
        )
        # «перегенерация» — только вывод: конфиг по-прежнему прежний
        import json

        config = json.loads((env / "config.json").read_text(encoding="utf-8"))
        assert config["inbounds"][0]["settings"]["clients"] == []

    def test_idempotent_second_run(self, env: Path) -> None:
        state_path = _state_path(env)
        clients.use_domain(DOMAIN, state_path=state_path)
        state_after_first = Path(state_path).read_text(encoding="utf-8")

        result = clients.use_domain(DOMAIN, state_path=state_path)

        assert result["changed"] is False
        assert Path(state_path).read_text(encoding="utf-8") == state_after_first

    def test_dns_mismatch_rejects_before_changes(self, env: Path) -> None:
        """E1: домен не резолвится в IP сервера — отказ до изменений."""
        state_path = _state_path(env)
        state_before = Path(state_path).read_text(encoding="utf-8")

        with pytest.raises(clients.XrayError, match="E1"):
            clients.use_domain("wrong.example.com", state_path=state_path)

        from src.gateway.store import load_state

        assert load_state(state_path).domain == ""  # состояние не изменялось
        assert Path(state_path).read_text(encoding="utf-8") == state_before

    def test_bad_format_rejected(self, env: Path) -> None:
        with pytest.raises(clients.XrayError, match="Некорректный домен"):
            clients.use_domain("not a domain", state_path=_state_path(env))

    def test_not_installed_raises(self, env: Path) -> None:
        from src.gateway.store import load_state

        state_path = _state_path(env)
        state = load_state(state_path)
        state.protocols.pop("xray")
        save_state(state, state_path)

        with pytest.raises(clients.XrayError, match="не установлен"):
            clients.use_domain(DOMAIN, state_path=state_path)

    def test_not_root_refused(
        self, env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        with pytest.raises(clients.XrayError, match="Требуется root"):
            clients.use_domain(DOMAIN, state_path=_state_path(env))
        from src.gateway.store import load_state

        assert load_state(_state_path(env)).domain == ""


class TestRealityLinkHost:
    def test_link_without_domain_is_byte_identical_to_old(self, env: Path) -> None:
        """Без state.domain — прежнее поведение по умолчанию (IP), байт-в-байт."""
        result = clients.add_client("phone", state_path=_state_path(env))
        assert result["share_link"] == (
            f"vless://{result['uuid']}@{IP}:443"
            f"?security=reality&sni={SNI}&fp=chrome&pbk={PBK}&sid={SID}"
            f"&flow=xtls-rprx-vision#phone"
        )

    def test_link_with_domain_uses_state_domain(self, env: Path) -> None:
        clients.use_domain(DOMAIN, state_path=_state_path(env))
        result = clients.add_client("tablet", state_path=_state_path(env))
        assert result["share_link"] == (
            f"vless://{result['uuid']}@{DOMAIN}:443"
            f"?security=reality&sni={SNI}&fp=chrome&pbk={PBK}&sid={SID}"
            f"&flow=xtls-rprx-vision#tablet"
        )

    def test_regen_after_domain_prefers_domain_over_ip(self, env: Path) -> None:
        from src.gateway.store import ClientProfile, load_state

        state_path = _state_path(env)
        state = load_state(state_path)
        state.clients.append(
            ClientProfile(
                name="phone", protocol="xray", port=443, uuid=UUID, sni=SNI,
                extra={"public_key": PBK, "short_id": SID},
            )
        )
        save_state(state, state_path)

        # до use-domain: IP
        links_before = clients.regen_reality_links(state_path)
        assert f"@{IP}:443" in links_before[0]["share_link"]

        clients.use_domain(DOMAIN, state_path=state_path)
        links_after = clients.regen_reality_links(state_path)
        assert f"@{DOMAIN}:443" in links_after[0]["share_link"]
        # uuid/sni/pbk/sid не изменились — только адрес
        assert links_after[0]["share_link"].split("?")[0].split("//")[1].split("@")[0] == UUID
