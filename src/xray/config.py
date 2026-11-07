"""Рендер /usr/local/etc/xray/config.json для Xray VLESS Reality.

Формат — VPN-PROTOCOLS §2.1 / SPEC §3: Reality, Vision flow, `dest` и
`serverNames` строятся из SNI. Рендер чистый и детерминированный: одинаковые
входы дают байт-в-байт одинаковый JSON (порядок ключей фиксирован литералами).
"""

import json
from dataclasses import dataclass, field

DEFAULT_SNI = "www.google.com"
DEFAULT_PORT = 443
FLOW = "xtls-rprx-vision"


@dataclass(frozen=True)
class XrayConfigParams:
    """Входы рендера config.json.

    client_ids: UUID клиентов (VLESS id); пусто на свежей установке.
    private_key: приватный x25519-ключ Reality (только в config.json, 0600).
    short_ids: Reality shortIds (hex-строки).
    sni: SNI-маскировки; из него же строятся dest и serverNames.
    """

    client_ids: list[str] = field(default_factory=list)
    private_key: str = ""
    short_ids: list[str] = field(default_factory=list)
    sni: str = DEFAULT_SNI
    port: int = DEFAULT_PORT


def render_config(params: XrayConfigParams) -> str:
    """Вернуть валидный JSON конфига Xray (строка, детерминированно)."""
    config = {
        "inbounds": [
            {
                "port": params.port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": client_id, "flow": FLOW}
                        for client_id in params.client_ids
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": f"{params.sni}:{params.port}",
                        "serverNames": [params.sni],
                        "privateKey": params.private_key,
                        "shortIds": list(params.short_ids),
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"
