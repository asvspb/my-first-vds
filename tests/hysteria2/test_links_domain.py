"""WP-2: share-link Hysteria2 с доменом+LE (без insecure=1) и без домена (SPEC FR-2.2).

Старое поведение (self-signed, insecure=1) должно продолжать рендериться
байт-в-байт как раньше — инвариант REQ §4 «Не ломать» (E11).
"""

import src.hysteria2.clients as clients
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    load_state,
    save_state,
)

PASSWORD = "FIXTURE_PW_Hysteria123"
IP = "203.0.113.10"
DOMAIN = "vpn.example.com"


class TestShareLinkDomain:
    def test_le_link_no_insecure_sni_domain(self) -> None:
        """Домен+LE: hysteria2://pw@домен:443/?sni=домен#name — без insecure=1."""
        link = clients.render_share_link(
            host=DOMAIN, password=PASSWORD, name="phone", port=443, insecure=False
        )
        assert link == f"hysteria2://{PASSWORD}@{DOMAIN}:443/?sni={DOMAIN}#phone"
        assert "insecure" not in link
        assert f"sni={DOMAIN}" in link

    def test_legacy_link_renders_unchanged(self) -> None:
        """Без домена — прежняя insecure-ссылка байт-в-байт (инвариант E11)."""
        link = clients.render_share_link(host=IP, password=PASSWORD, name="mob")
        assert link == f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#mob"

    def test_le_link_name_quoted(self) -> None:
        link = clients.render_share_link(
            host=DOMAIN, password=PASSWORD, name="my phone", insecure=False
        )
        assert link.endswith("#my%20phone")


class TestAddClientDomain:
    def _state_with_le(self, state_path: str, with_domain: bool) -> None:
        state = GatewayState()
        state.protocols["hysteria2"] = {
            "installed": True, "port": 443, "auth_password": PASSWORD,
        }
        if with_domain:
            state.protocols["acme"] = {"installed": True, "domain": DOMAIN}
        save_state(state, state_path)

    def test_add_client_with_domain_uses_le_link(
        self, tmp_path, monkeypatch
    ) -> None:
        state_path = str(tmp_path / "state.json")
        self._state_with_le(state_path, with_domain=True)
        monkeypatch.setattr(clients, "public_ip", lambda: IP)

        result = clients.add_client("newle", state_path=state_path)
        # адрес — домен, не IP; sni=домен; insecure=1 отсутствует
        assert result["share_link"] == (
            f"hysteria2://{PASSWORD}@{DOMAIN}:443/?sni={DOMAIN}#newle"
        )
        assert result["sni"] == DOMAIN
        profile = load_state(state_path).clients[-1]
        assert profile.name == "newle"
        assert profile.sni == DOMAIN
        assert profile.extra.get("tls") == "le"

    def test_add_client_without_domain_keeps_legacy_link(
        self, tmp_path, monkeypatch
    ) -> None:
        state_path = str(tmp_path / "state.json")
        self._state_with_le(state_path, with_domain=False)
        monkeypatch.setattr(clients, "public_ip", lambda: IP)

        result = clients.add_client("oldstyle", state_path=state_path)
        assert result["share_link"] == (
            f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#oldstyle"
        )
        profile = load_state(state_path).clients[-1]
        assert profile.sni == IP
        assert "tls" not in profile.extra


class TestLegacyProfilesUnchanged:
    def test_existing_client_profile_not_rewritten(self, tmp_path, monkeypatch) -> None:
        """Старый профиль (sni=IP) остаётся в store при добавлении нового."""
        state_path = str(tmp_path / "state.json")
        state = GatewayState()
        state.protocols["hysteria2"] = {
            "installed": True, "port": 443, "auth_password": PASSWORD,
        }
        state.clients.append(
            ClientProfile(
                name="mob", protocol="hysteria2", port=443,
                password=PASSWORD, sni=IP,
            )
        )
        state.protocols["acme"] = {"installed": True, "domain": DOMAIN}
        save_state(state, state_path)
        monkeypatch.setattr(clients, "public_ip", lambda: IP)

        clients.add_client("newle", state_path=state_path)
        final = load_state(state_path)
        mob = [c for c in final.clients if c.name == "mob"][0]
        assert mob.sni == IP
        assert mob.password == PASSWORD
