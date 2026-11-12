"""Рендер /etc/hysteria/config.yaml для Hysteria2 (VPN-PROTOCOLS §2.3, SPEC §3).

Формат: QUIC (UDP 443), TLS = self-signed сертификат (CN=<ip>, ADR-002),
auth.type=password, masquerade proxy на https://download.microsoft.com/
(маскировка при зондировании), bandwidth из SPEC. Рендер чистый и
детерминированный: одинаковые входы дают байт-в-байт одинаковый YAML.
"""

from dataclasses import dataclass

DEFAULT_PORT = 443
MASQUERADE_URL = "https://download.microsoft.com/"
BANDWIDTH_UP = "100 mbps"
BANDWIDTH_DOWN = "200 mbps"


@dataclass(frozen=True)
class Hysteria2ConfigParams:
    """Входы рендера config.yaml.

    password: общий auth-пароль инбаунда (hysteria2 поддерживает один пароль
        на инстанс — см. clients.py); только в config.yaml/state.json (0600).
    cert_path/key_path: пути self-signed сертификата (ADR-002).
    bandwidth_up/down: ограничения канала (формат hysteria: "<n> mbps").
    masquerade_url: сайт-маскировка для зондирования.
    obfs_password: пароль obfs salamander (SPEC-20261112 WP-1); None —
        блок `obfs:` не рендерится (основной инстанс не меняется).
    """

    password: str
    port: int = DEFAULT_PORT
    cert_path: str = "/etc/hysteria/cert.pem"
    key_path: str = "/etc/hysteria/key.pem"
    bandwidth_up: str = BANDWIDTH_UP
    bandwidth_down: str = BANDWIDTH_DOWN
    masquerade_url: str = MASQUERADE_URL
    obfs_password: str | None = None


def render_config(params: Hysteria2ConfigParams) -> str:
    """Вернуть валидный YAML конфига Hysteria2 (строка, детерминированно).

    Пароль — буквенно-цифровой (core.secrets.gen_password), поэтому двойных
    кавычек достаточно без экранирования.
    """
    return (
        f"listen: :{params.port}\n"
        "\n"
        "tls:\n"
        f"  cert: {params.cert_path}\n"
        f"  key: {params.key_path}\n"
        "\n"
        "auth:\n"
        "  type: password\n"
        f'  password: "{params.password}"\n'
        "\n"
        + (
            # Блок obfs — только при заданном пароле (SPEC-20261112 WP-1);
            # без поля рендер байт-в-байт прежний (золотой тест).
            # Схема hysteria v2: пароль вложен в ключ типа обфускатора
            # (`obfs.salamander.password`), плоский `obfs.password` ядро
            # игнорирует и падает с «PSK must be at least 4 bytes».
            "obfs:\n"
            "  type: salamander\n"
            "  salamander:\n"
            f'    password: "{params.obfs_password}"\n'
            "\n"
            if params.obfs_password
            else ""
        )
        + "bandwidth:\n"
        f"  up: {params.bandwidth_up}\n"
        f"  down: {params.bandwidth_down}\n"
        "\n"
        "masquerade:\n"
        "  type: proxy\n"
        "  proxy:\n"
        f"    url: {params.masquerade_url}\n"
        "    rewrite: true\n"
    )
