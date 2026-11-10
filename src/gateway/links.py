"""Рендер клиентских share-links из gateway state (WP-A: `vds gateway links`).

Чистая функция render_all_links читает state.json и для каждого клиента
возвращает (name, protocol, share_link), используя существующие рендеры:
  - Xray Reality   — src.xray.clients.render_share_link
                     (host = state.domain или публичный IP, как в regen_reality_links);
  - Xray XHTTP     — src.xray.clients.render_xhttp_share_link
                     (домен/порт/path из protocols["xhttp"]);
  - Hysteria2      — src.hysteria2.clients.render_share_link
                     (LE-домен из protocols["acme"]["domain"] — без insecure;
                     иначе legacy self-signed формат).

Секреты: ссылки — продукт команды; privateKey Reality и state целиком не
печатаются и не логируются. Клиенты без uuid/password (битые профили)
пропускаются, а не роняют команду.
"""
from typing import Optional

from src.gateway.store import GatewayState, load_state


def render_all_links(
    state_path: Optional[str] = None,
    protocol: Optional[str] = None,
) -> list[tuple[str, str, str]]:
    """Для каждого клиента state — (name, protocol, share_link); порядок
    стабилен (порядок списка клиентов). protocol — фильтр
    ("xray" | "hysteria2"); None — все протоколы.

    Пустой state (нет клиентов) — пустой список. Host Reality при недоступном
    публичном IP — "SERVER_IP" (прежнее поведение regen_reality_links).
    """
    from src.core.netcheck import public_ip
    from src.hysteria2.clients import render_share_link as render_hy_link
    from src.xray.clients import render_share_link as render_reality_link
    from src.xray.clients import render_xhttp_share_link

    state: GatewayState = load_state(state_path)
    if protocol is not None and protocol not in ("xray", "hysteria2", "amneziawg"):
        raise ValueError(
            f"Неизвестный протокол {protocol!r} "
            "(поддерживаются: xray, hysteria2, amneziawg)."
        )

    result: list[tuple[str, str, str]] = []
    for client in state.clients:
        if protocol is not None and client.protocol != protocol:
            continue
        if client.protocol == "xray":
            if not client.uuid:
                continue
            if client.extra.get("transport") == "xhttp":
                xhttp_meta = state.protocols.get("xhttp") or {}
                domain = str(xhttp_meta.get("domain") or "")
                if not domain:
                    continue  # XHTTP-транспорт не установлен — ссылку не собрать
                port = 443 if xhttp_meta.get("mode") == "fallback" else int(
                    xhttp_meta.get("port", 8443)
                )
                path = str(xhttp_meta.get("extra", {}).get("path", "/xhttp"))
                link = render_xhttp_share_link(
                    domain=domain,
                    client_uuid=client.uuid,
                    name=client.name,
                    port=port,
                    path=path,
                )
            else:
                meta = state.protocols.get("xray") or {}
                host = state.domain or public_ip() or "SERVER_IP"
                link = render_reality_link(
                    host=host,
                    client_uuid=client.uuid,
                    sni=str(meta.get("sni", "www.google.com")),
                    public_key=str(
                        client.extra.get("public_key", meta.get("public_key", ""))
                    ),
                    short_id=str(
                        client.extra.get("short_id", meta.get("short_id", ""))
                    ),
                    name=client.name,
                    port=int(meta.get("port", 443)),
                )
            result.append((client.name, "xray", link))
        elif client.protocol == "hysteria2":
            meta = state.protocols.get("hysteria2") or {}
            password = client.password or meta.get("auth_password", "")
            if not password:
                continue
            port = int(client.port if client.port else meta.get("port", 443))
            le_domain = str((state.protocols.get("acme") or {}).get("domain") or "")
            if le_domain:
                link = render_hy_link(
                    host=le_domain, password=password, name=client.name,
                    port=port, insecure=False,
                )
            else:
                host = client.sni or meta.get("cert_cn") or "SERVER_IP"
                link = render_hy_link(
                    host=host, password=password, name=client.name,
                    port=port, insecure=True,
                )
            result.append((client.name, "hysteria2", link))
        elif client.protocol == "amneziawg":
            # AWG не имеет share-link-формата (SPEC FR-5): строка-плейсхолдер
            # с путём к .conf, без секретов (ключи — только в .conf/state).
            conf_path = str(client.extra.get("conf_path", ""))
            if not conf_path:
                continue
            result.append(
                (
                    client.name,
                    "amneziawg",
                    f"amneziawg client '{client.name}': conf {conf_path}",
                )
            )
        # прочие протоколы: рендеры не определены — пропускаем
    return result
