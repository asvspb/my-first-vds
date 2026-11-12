"""Снапшот-тесты рендера config.yaml (SPEC §3, VPN-PROTOCOLS §2.3)."""

from src.hysteria2.config import Hysteria2ConfigParams, render_config

PASSWORD = "FIXTURE_PW_Config"


def _params(**overrides) -> Hysteria2ConfigParams:
    base = dict(password=PASSWORD)
    base.update(overrides)
    return Hysteria2ConfigParams(**base)


class TestRenderConfigSnapshot:
    def test_snapshot_exact(self) -> None:
        expected = (
            "listen: :443\n"
            "\n"
            "tls:\n"
            "  cert: /etc/hysteria/cert.pem\n"
            "  key: /etc/hysteria/key.pem\n"
            "\n"
            "auth:\n"
            "  type: password\n"
            f'  password: "{PASSWORD}"\n'
            "\n"
            "bandwidth:\n"
            "  up: 100 mbps\n"
            "  down: 200 mbps\n"
            "\n"
            "masquerade:\n"
            "  type: proxy\n"
            "  proxy:\n"
            "    url: https://download.microsoft.com/\n"
            "    rewrite: true\n"
        )
        assert render_config(_params()) == expected

    def test_same_input_same_output(self) -> None:
        assert render_config(_params()) == render_config(_params())

    def test_password_is_parameter_not_generated(self) -> None:
        # Детерминированность: пароль приходит снаружи, рендер не генерирует.
        assert 'password: "aaa"' in render_config(_params(password="aaa"))
        assert 'password: "bbb"' in render_config(_params(password="bbb"))

    def test_custom_port_and_cert_paths(self) -> None:
        rendered = render_config(
            _params(port=8443, cert_path="/x/c.pem", key_path="/x/k.pem")
        )
        assert rendered.startswith("listen: :8443\n")
        assert "  cert: /x/c.pem\n" in rendered
        assert "  key: /x/k.pem\n" in rendered

    def test_defaults_match_spec(self) -> None:
        params = Hysteria2ConfigParams(password="x")
        assert params.port == 443
        assert params.bandwidth_up == "100 mbps"
        assert params.bandwidth_down == "200 mbps"
        assert params.masquerade_url == "https://download.microsoft.com/"
        assert params.obfs_password is None


class TestObfsRender:
    """SPEC-20261112 WP-1: блок obfs только при заданном пароле; без —
    рендер байт-в-байт прежний (golden-регресс)."""

    OBFS_PASSWORD = "FIXTURE_PW_Salamander"

    def test_obfs_block_rendered(self) -> None:
        rendered = render_config(_params(obfs_password=self.OBFS_PASSWORD))
        assert (
            "obfs:\n"
            "  type: salamander\n"
            "  salamander:\n"
            f'    password: "{self.OBFS_PASSWORD}"\n'
        ) in rendered

    def test_obfs_block_position_after_auth(self) -> None:
        rendered = render_config(_params(obfs_password=self.OBFS_PASSWORD))
        auth_pos = rendered.index('  password: "')
        obfs_pos = rendered.index("obfs:")
        bandwidth_pos = rendered.index("bandwidth:")
        assert auth_pos < obfs_pos < bandwidth_pos

    def test_without_obfs_byte_identical_to_legacy(self) -> None:
        """Регресс: obfs_password=None — вывод совпадает со старым рендером."""
        legacy = (
            "listen: :443\n"
            "\n"
            "tls:\n"
            "  cert: /etc/hysteria/cert.pem\n"
            "  key: /etc/hysteria/key.pem\n"
            "\n"
            "auth:\n"
            "  type: password\n"
            f'  password: "{PASSWORD}"\n'
            "\n"
            "bandwidth:\n"
            "  up: 100 mbps\n"
            "  down: 200 mbps\n"
            "\n"
            "masquerade:\n"
            "  type: proxy\n"
            "  proxy:\n"
            "    url: https://download.microsoft.com/\n"
            "    rewrite: true\n"
        )
        assert render_config(_params()) == legacy
        assert render_config(_params(obfs_password=None)) == legacy

    def test_obfs_deterministic(self) -> None:
        a = render_config(_params(obfs_password=self.OBFS_PASSWORD))
        b = render_config(_params(obfs_password=self.OBFS_PASSWORD))
        assert a == b


class TestMasqueradeUrl:
    """--masquerade-url (WP-1): URL конфигурируем, дефолт прежний."""

    def test_custom_url_rendered(self) -> None:
        rendered = render_config(
            _params(masquerade_url="https://cdn.example.invalid/file")
        )
        assert "url: https://cdn.example.invalid/file\n" in rendered
        assert "download.microsoft.com" not in rendered
