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
