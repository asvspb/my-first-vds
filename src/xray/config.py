"""Рендер /usr/local/etc/xray/config.json для Xray VLESS Reality (+ XHTTP).

Формат — VPN-PROTOCOLS §2.1 / SPEC §3: Reality, Vision flow, `dest` и
`serverNames` строятся из SNI. Рендер чистый и детерминированный: одинаковые
входы дают байт-в-байт одинаковый JSON (порядок ключей фиксирован литералами).

XHTTP (SPEC-20261109, ADR-003): при `xhttp_enabled` к Reality-inbound
добавляется `fallbacks` в streamSettings (mode=fallback) и второй инблэнд
vless+xhttp+tls, слушающий на XRAY_HTTP_BIND:XHTTP_INTERNAL_PORT (loopback,
наружу не торчит) с LE-сертификатом домена. Без xhttp-полей рендер
байт-в-байт совпадает с прежним (золотой снапшот-тест). mode=port — без
fallbacks, XHTTP-inbound слушает на всех интерфейсах (публичный 8443,
fallback-план ADR-003).

CDN (SPEC-20261110, ADR-006): при `cdn_enabled` добавляется третий инблэнд
vless+ws+tls на CDN_ORIGIN_PORT_DEFAULT (TCP 2053) с LE-сертификатом
cdn-домена (все интерфейсы, за Cloudflare proxy). Без cdn-полей рендер
байт-в-байт прежний (золотой снапшот-тест).
"""

import json
from dataclasses import dataclass, field

from src.gateway.paths import (
    CDN_ORIGIN_PORT_DEFAULT,
    CDN_WS_PATH,
    XHTTP_INTERNAL_PORT,
    XRAY_HTTP_BIND,
)
from urllib.parse import quote

DEFAULT_SNI = "www.google.com"
DEFAULT_PORT = 443
FLOW = "xtls-rprx-vision"
XHTTP_MODES = ("fallback", "port")
# Фиксированный path XHTTP (дельта WP-3, вердикт архитектора 2026-11-09):
# без параметризации в этом цикле; смена — коммитом + state (extra.path).
XHTTP_PATH = "/xhttp"

CDN_DEFAULT_PORT = CDN_ORIGIN_PORT_DEFAULT
CDN_DEFAULT_WS_PATH = CDN_WS_PATH


@dataclass(frozen=True)
class XrayConfigParams:
    """Входы рендера config.json.

    client_ids: UUID клиентов Reality (VLESS id); пусто на свежей установке.
    private_key: приватный x25519-ключ Reality (только в config.json, 0600).
    short_ids: Reality shortIds (hex-строки).
    sni: SNI-маскировки; из него же строятся dest и serverNames.
    xhttp_enabled: включить XHTTP (SPEC WP-3); False — рендер как раньше.
    domain: домен XHTTP (SNI TLS-инблэнда и сертификата).
    cert_path/key_path: LE fullchain/privkey для tlsSettings.
    xhttp_client_ids: UUID XHTTP-клиентов (второй инблэнд, без flow).
    xhttp_mode: "fallback" (SNI-разделение за Reality на 443) или "port"
      (публичный порт XHTTP_INTERNAL_PORT, fallback-план ADR-003).
    """

    client_ids: list[str] = field(default_factory=list)
    private_key: str = ""
    short_ids: list[str] = field(default_factory=list)
    sni: str = DEFAULT_SNI
    port: int = DEFAULT_PORT
    xhttp_enabled: bool = False
    domain: str = ""
    cert_path: str = ""
    key_path: str = ""
    xhttp_client_ids: list[str] = field(default_factory=list)
    xhttp_mode: str = "fallback"
    xhttp_port: int = XHTTP_INTERNAL_PORT
    xhttp_bind: str = XRAY_HTTP_BIND
    cdn_enabled: bool = False
    cdn_domain: str = ""
    cdn_port: int = CDN_ORIGIN_PORT_DEFAULT
    cdn_ws_path: str = CDN_WS_PATH
    cdn_client_ids: list[str] = field(default_factory=list)
    cdn_cert_path: str = ""
    cdn_key_path: str = ""


def _xhttp_inbound(params: XrayConfigParams) -> dict:
    """Второй инблэнд vless+xhttp+tls (ADR-003); слушать loopback или все."""
    stream: dict = {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {"path": XHTTP_PATH},
        "tlsSettings": {
            "certificates": [
                {
                    "certificateFile": params.cert_path,
                    "keyFile": params.key_path,
                }
            ]
        },
    }
    inbound: dict = {
        "port": params.xhttp_port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": client_id} for client_id in params.xhttp_client_ids],
            "decryption": "none",
        },
        "streamSettings": stream,
    }
    if params.xhttp_mode == "fallback":
        inbound["listen"] = params.xhttp_bind
    return inbound


def _cdn_inbound(params: XrayConfigParams) -> dict:
    """Инблэнд vless+ws+tls за Cloudflare (SPEC-20261110, ADR-006): TCP 2053,
    ws path /cdnws, TLS на LE-сертификате cdn-домена. Все интерфейсы
    (CF→origin соединяется извне)."""
    return {
        "port": params.cdn_port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": client_id} for client_id in params.cdn_client_ids],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": params.cdn_ws_path,
                "headers": {"Host": params.cdn_domain},
            },
            "tlsSettings": {
                "certificates": [
                    {
                        "certificateFile": params.cdn_cert_path,
                        "keyFile": params.cdn_key_path,
                    }
                ]
            },
        },
    }


def render_cdn_share_link(uuid: str, cdn_domain: str, cdn_port: int, cdn_ws_path: str, name: str) -> str:
    """VLESS share-link CDN-клиента (формат — SPEC §3, юнит-тест WP-1).

    `vless://<uuid>@<cdn-domain>:<port>?encryption=none&security=tls&sni=<domain>&type=ws&host=<domain>&path=<encoded>#<name>`
    """
    return (
        f"vless://{uuid}@{cdn_domain}:{cdn_port}"
        f"?encryption=none&security=tls&sni={cdn_domain}"
        f"&type=ws&host={cdn_domain}&path={quote(cdn_ws_path, safe='')}"
        f"#{name}"
    )


def render_config(params: XrayConfigParams) -> str:
    """Вернуть валидный JSON конфига Xray (строка, детерминированно)."""
    stream = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": f"{params.sni}:{params.port}",
            "serverNames": [params.sni],
            "privateKey": params.private_key,
            "shortIds": list(params.short_ids),
        },
    }
    if params.xhttp_enabled and params.xhttp_mode == "fallback":
        # ADR-003: фолбэк срабатывает только на не-Reality TLS ClientHello.
        stream["fallbacks"] = [
            {"alpn": ["http/1.1", "h2"], "dest": f"{params.xhttp_bind}:{params.xhttp_port}"}
        ]

    inbounds: list[dict] = [
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
            "streamSettings": stream,
        }
    ]
    if params.xhttp_enabled:
        inbounds.append(_xhttp_inbound(params))
    if params.cdn_enabled:
        inbounds.append(_cdn_inbound(params))

    config = {
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom"}],
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"
