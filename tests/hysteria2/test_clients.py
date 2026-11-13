"""Тесты src/hysteria2/clients.py: share-link, дубликат имени, маскировка пароля."""

from pathlib import Path

import pytest

import src.hysteria2.clients as clients
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    StoreError,
    load_state,
    save_state,
)

PASSWORD = "FIXTURE_PW_Hysteria123"
IP = "203.0.113.10"


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Tmp-state с установленным hysteria2 (общий пароль); ip — мок."""
    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {
        "installed": True,
        "port": 443,
        "cert_cn": IP,
        "auth_password": PASSWORD,
    }
    state.clients.append(
        ClientProfile(name="xuser", protocol="xray", port=443, uuid="u-1")
    )
    save_state(state, state_path)

    monkeypatch.setattr(clients, "public_ip", lambda: IP)
    recorder = _ConsoleRecorder()
    monkeypatch.setattr(clients, "console", recorder)
    return {"state_path": state_path, "recorder": recorder}


class TestRenderShareLink:
    def test_exact_format_with_insecure(self) -> None:
        link = clients.render_share_link(
            host=IP, password=PASSWORD, name="phone", port=443
        )
        assert link == (
            f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#phone"
        )

    def test_insecure_one_and_sni_is_ip(self) -> None:
        link = clients.render_share_link(host=IP, password=PASSWORD, name="n")
        assert "insecure=1" in link
        assert f"sni={IP}" in link
        assert "insecure=0" not in link

    def test_name_with_spaces_is_quoted(self) -> None:
        link = clients.render_share_link(host=IP, password=PASSWORD, name="my phone")
        assert link.endswith("#my%20phone")


class TestRenderShareLinkHopObfs:
    """mport/obfs-параметры ссылки (SPEC-20261112 WP-1)."""

    def test_mport_appended_after_insecure(self) -> None:
        link = clients.render_share_link(
            host=IP, password=PASSWORD, name="phone", port=443,
            insecure=True, mport="20000-20500",
        )
        assert link == (
            f"hysteria2://{PASSWORD}@{IP}:443/"
            f"?sni={IP}&insecure=1&mport=20000-20500#phone"
        )

    def test_mport_without_insecure_le(self) -> None:
        link = clients.render_share_link(
            host="vpn.example.invalid", password=PASSWORD, name="mob",
            port=443, insecure=False, mport="30000-30100",
        )
        assert link == (
            f"hysteria2://{PASSWORD}@vpn.example.invalid:443/"
            f"?sni=vpn.example.invalid&mport=30000-30100#mob"
        )

    def test_no_mport_without_param(self) -> None:
        assert "mport" not in clients.render_share_link(
            host=IP, password=PASSWORD, name="n"
        )

    def test_obfs_link_format(self) -> None:
        link = clients.render_share_link(
            host=IP, password=PASSWORD, name="phone", port=51826,
            insecure=True, obfs_password="FIXTURE_PW_Obfs",
        )
        assert link == (
            f"hysteria2://{PASSWORD}@{IP}:51826/"
            f"?sni={IP}&obfs=salamander&obfs-password=FIXTURE_PW_Obfs"
            f"&insecure=1#phone"
        )

    def test_obfs_link_with_mport(self) -> None:
        link = clients.render_share_link(
            host=IP, password=PASSWORD, name="phone", port=51826,
            insecure=True, obfs_password="FIXTURE_PW_Obfs",
            mport="20000-20500",
        )
        assert link.endswith(
            "&obfs-password=FIXTURE_PW_Obfs&insecure=1&mport=20000-20500#phone"
        )


class TestAddClient:
    def test_add_client_profile_and_link(self, env) -> None:
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["name"] == "laptop"
        assert result["protocol"] == "hysteria2"
        assert result["password"] == PASSWORD  # общий пароль инбаунда
        assert result["share_link"].startswith(f"hysteria2://{PASSWORD}@{IP}:443/")

        state = load_state(env["state_path"])
        hy = [c for c in state.clients if c.protocol == "hysteria2"]
        assert [c.name for c in hy] == ["laptop"]
        assert hy[0].password == PASSWORD
        assert hy[0].sni == IP
        # xray-клиент не тронут
        assert any(c.protocol == "xray" for c in state.clients)

    def test_duplicate_name_store_error(self, env) -> None:
        clients.add_client("laptop", state_path=env["state_path"])
        with pytest.raises(StoreError):
            clients.add_client("laptop", state_path=env["state_path"])

    def test_not_installed_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        empty_state = str(tmp_path / "empty.json")
        save_state(GatewayState(), empty_state)
        with pytest.raises(clients.Hysteria2Error):
            clients.add_client("n", state_path=empty_state)

    def test_password_only_in_share_link_line(self, env) -> None:
        """Пароль в выводе встречается только внутри share-link (SPEC §5)."""
        clients.add_client("laptop", state_path=env["state_path"])
        occurrences = [
            line for line in env["recorder"].lines if PASSWORD in line
        ]
        assert len(occurrences) == 1
        # единственная строка с паролем — это сам share-link (с rich-тегом [change])
        assert occurrences[0] == (
            f"[change]hysteria2://{PASSWORD}@{IP}:443/"
            f"?sni={IP}&insecure=1#laptop[/change]"
        )

    def test_mport_included_iff_hop_ports_in_state(self, env) -> None:
        """mport попадает в ссылку iff hop_ports есть в state (WP-1)."""
        # без hop_ports — обычная ссылка
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert "mport" not in result["share_link"]
        # с hop_ports — mport в основной ссылке
        from src.gateway.store import load_state, save_state

        state = load_state(env["state_path"])
        state.protocols["hysteria2"]["hop_ports"] = "20000-20500"
        save_state(state, env["state_path"])
        result = clients.add_client("phone", state_path=env["state_path"])
        assert result["share_link"].endswith(
            "&insecure=1&mport=20000-20500#phone"
        )

    def test_obfs_link_printed_when_obfs_installed(self, env) -> None:
        from src.gateway.store import load_state, save_state

        state = load_state(env["state_path"])
        state.protocols["hysteria2-obfs"] = {
            "installed": True, "port": 51826,
            "obfs_password": "FIXTURE_PW_Obfs",
        }
        save_state(state, env["state_path"])
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["obfs_share_link"] == (
            f"hysteria2://{PASSWORD}@{IP}:51826/"
            f"?sni={IP}&obfs=salamander&obfs-password=FIXTURE_PW_Obfs"
            f"&insecure=1#laptop"
        )
        obfs_lines = [
            line for line in env["recorder"].lines if "obfs=salamander" in line
        ]
        assert obfs_lines == [f"[change]{result['obfs_share_link']}[/change]"]

    def test_no_obfs_link_without_obfs_instance(self, env) -> None:
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert "obfs_share_link" not in result
        assert not any(
            "obfs" in line for line in env["recorder"].lines
        )


class TestLeDomainResolution:
    """Хост LE-ссылки: сертификат hysteria2 может быть выпущен не для
    `acme.domain` (тот уходит на CDN-фронт), а для `state.domain`; чужой sni в
    клиенте даёт CRYPTO_ERROR 0x150 (найдено на asv1)."""

    def _with_acme(self, env: dict, acme_domain: str, state_domain: str) -> None:
        state = load_state(env["state_path"])
        state.protocols["acme"] = {"installed": True, "domain": acme_domain}
        state.domain = state_domain
        save_state(state, env["state_path"])

    def test_acme_domain_when_same_as_state_domain(
        self, env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._with_acme(env, "vpn.example.com", "vpn.example.com")
        monkeypatch.setattr(clients, "cert_exists", lambda d: True)
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["sni"] == "vpn.example.com"
        assert "insecure=1" not in result["share_link"]
        assert "@vpn.example.com:443/?sni=vpn.example.com" in result["share_link"]

    def test_state_domain_wins_when_acme_domain_is_cdn_front(
        self, env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Регресс asv1: acme.domain=CDN-фронт, сертификат — на state.domain."""
        self._with_acme(env, "asvpersonal.ru", "vds.example.com")
        checked: list[str] = []

        def _cert_exists(domain: str) -> bool:
            checked.append(domain)
            return True

        monkeypatch.setattr(clients, "cert_exists", _cert_exists)
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert checked == ["vds.example.com"]
        assert result["sni"] == "vds.example.com"
        assert result["share_link"].startswith(
            f"hysteria2://{PASSWORD}@vds.example.com:443/?sni=vds.example.com"
        )
        assert "insecure=1" not in result["share_link"]

    def test_falls_back_to_acme_domain_without_state_domain_cert(
        self, env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._with_acme(env, "vpn.example.com", "other.example.com")
        monkeypatch.setattr(clients, "cert_exists", lambda d: False)
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["sni"] == "vpn.example.com"

    def test_legacy_ip_link_without_acme(self, env) -> None:
        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["sni"] == IP
        assert "insecure=1" in result["share_link"]


class TestCertDomainSplit:
    """GR-10: host (адрес) и sni (домен сертификата) — разные поля ссылки."""

    def test_render_link_with_separate_sni(self) -> None:
        link = clients.render_share_link(
            host="vds.example.com", password=PASSWORD, name="n",
            port=443, insecure=False, sni="vpn.example.com",
        )
        assert link == (
            f"hysteria2://{PASSWORD}@vds.example.com:443/"
            f"?sni=vpn.example.com#n"
        )

    def test_le_domain_prefers_cert_domain(self, env) -> None:
        """cert_domain важнее эвристики state.domain/acme.domain (инцидент asv1)."""
        state = load_state(env["state_path"])
        state.domain = "vds.example.com"
        state.protocols["acme"] = {"installed": True, "domain": "front.example.ru"}
        state.protocols["hysteria2"]["cert_domain"] = "vpn.example.com"
        save_state(state, env["state_path"])

        result = clients.add_client("laptop", state_path=env["state_path"])
        assert result["sni"] == "vpn.example.com"
        assert "@vds.example.com:443/?sni=vpn.example.com" in result["share_link"]
        assert "insecure=1" not in result["share_link"]

    def test_set_cert_domain_roundtrip(
        self, env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            clients, "CERT_DOMAIN_LOCK", str(tmp_path / "cert-domain.lock")
        )
        assert clients.set_cert_domain("vpn.example.com", env["state_path"]) == 0
        assert (
            load_state(env["state_path"]).protocols["hysteria2"]["cert_domain"]
            == "vpn.example.com"
        )
        assert clients.set_cert_domain(None, env["state_path"]) == 0
        assert (
            load_state(env["state_path"]).protocols["hysteria2"]["cert_domain"] == ""
        )


class TestRemoveClient:
    def test_remove_only_hysteria2_client(self, env) -> None:
        clients.add_client("laptop", state_path=env["state_path"])
        assert clients.remove_client("laptop", state_path=env["state_path"]) == 0
        state = load_state(env["state_path"])
        assert [c.protocol for c in state.clients] == ["xray"]

    def test_remove_unknown_raises(self, env) -> None:
        with pytest.raises(StoreError):
            clients.remove_client("ghost", state_path=env["state_path"])


class TestAdapterShareLinks:
    def test_adapter_render_share_links(self) -> None:
        from src.hysteria2.adapter import HysteriaAdapter

        adapter = HysteriaAdapter()
        assert adapter.name == "hysteria2"
        assert adapter.transport == "udp"
        links = adapter.render_share_links(
            {"name": "phone", "password": PASSWORD, "sni": IP, "port": 443}
        )
        assert links == [f"hysteria2://{PASSWORD}@{IP}:443/?sni={IP}&insecure=1#phone"]
