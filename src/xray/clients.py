"""Клиенты Xray VLESS Reality: добавление/удаление, share-links.

Поток add_client: store.add_client (дубликат имени -> StoreError) -> uuid
через secrets.gen_uuid -> обновление списка clients в config.json (атомарно,
0600) -> перезапуск юнита (при сбое — откат конфига) -> сохранение состояния.
Приватный ключ Reality не покидает config.json: в share-link попадают только
клиентские поля (uuid/pbk/sid — по назначению, SPEC §5).
"""

import json
import os
from urllib.parse import quote

from src.acme.install import dns_resolves_to
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import public_ip
from src.core.secrets import gen_uuid, write_secret_atomic
from src.core.shell import run_list
from src.gateway.paths import XRAY_CONFIG_PATH, XRAY_UNIT
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    StoreError,
    add_client as store_add_client,
    load_state,
    remove_client as store_remove_client,
    save_state,
)
from src.xray.config import FLOW, XHTTP_PATH


class XrayError(Exception):
    """Сбой клиентской операции Xray (не установлен, конфиг, перезапуск)."""


LOCK_FILE = "/var/run/vds-xray-domain.lock"


def render_share_link(
    host: str,
    client_uuid: str,
    sni: str,
    public_key: str,
    short_id: str,
    name: str,
    port: int = 443,
) -> str:
    """Клиентская ссылка VLESS Reality (SPEC §3, VPN-PROTOCOLS §2.1).

    Формат:
      vless://<uuid>@<ip>:443?security=reality&sni=<sni>&fp=chrome&pbk=<public>&sid=<shortId>&flow=xtls-rprx-vision#<name>
    Приватный ключ в ссылку не входит никогда.
    """
    return (
        f"vless://{client_uuid}@{host}:{port}"
        f"?security=reality&sni={sni}&fp=chrome"
        f"&pbk={public_key}&sid={short_id}"
        f"&flow={FLOW}#{quote(name)}"
    )


def render_xhttp_share_link(
    domain: str,
    client_uuid: str,
    name: str,
    port: int = 443,
    path: str = XHTTP_PATH,
) -> str:
    """Клиентская ссылка VLESS XHTTP (SPEC WP-3 + дельта: path/type).

    Формат:
      vless://<uuid>@<домен>:443?security=tls&network=xhttp&sni=<домен>&fp=chrome&path=/xhttp&type=xhttp#<name>
    Домен — адрес XHTTP (fallback: 443; mode=port: 8443); path — из
    protocols["xhttp"]["extra"]["path"]. Никаких секретов, путей
    сертификата или ключей в ссылке нет.
    """
    return (
        f"vless://{client_uuid}@{domain}:{port}"
        f"?security=tls&network=xhttp&sni={domain}&fp=chrome"
        f"&path={path}&type=xhttp"
        f"#{quote(name)}"
    )


def _xray_uuids(state: GatewayState) -> list[str]:
    """UUID всех xray-клиентов состояния (порядок стабилен — порядок списка)."""
    return [
        client.uuid
        for client in state.clients
        if client.protocol == "xray"
        and client.uuid
        and client.extra.get("transport") != "xhttp"
    ]


def _xhttp_uuids(state: GatewayState) -> list[str]:
    """UUID XHTTP-клиентов (extra.transport == "xhttp")."""
    return [
        client.uuid
        for client in state.clients
        if client.protocol == "xray"
        and client.uuid
        and client.extra.get("transport") == "xhttp"
    ]


def _rewrite_clients(reality_uuids: list[str], xhttp_uuids: list[str] | None = None) -> None:
    """Перезаписать списки clients в config.json (Reality-inbound #0 и, если
    есть, XHTTP-inbound)."""
    if not XRAY_CONFIG_PATH.is_file():
        raise XrayError(
            f"Конфиг {XRAY_CONFIG_PATH} не найден — сначала `vds xray install`."
        )
    config = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        inbound = config["inbounds"][0]
        inbound["settings"]["clients"] = [
            {"id": client_uuid, "flow": FLOW} for client_uuid in reality_uuids
        ]
        if xhttp_uuids:
            # XHTTP-inbound может отсутствовать (транспорт ещё не добавлен) —
            # в этом случае список просто не обновляем.
            xhttp_inbound = next(
                (
                    ib
                    for ib in config["inbounds"]
                    if ib.get("streamSettings", {}).get("network") == "xhttp"
                ),
                None,
            )
            if xhttp_inbound is not None:
                xhttp_inbound["settings"]["clients"] = [
                    {"id": client_uuid} for client_uuid in xhttp_uuids
                ]
    except (KeyError, IndexError, StopIteration) as exc:
        raise XrayError(
            f"Неожиданная структура {XRAY_CONFIG_PATH}: {exc!r}."
        ) from exc
    payload = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    if not write_secret_atomic(str(XRAY_CONFIG_PATH), payload, mode=0o600):
        raise XrayError(f"Не удалось записать {XRAY_CONFIG_PATH}.")


def _restart_unit() -> None:
    result = run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
    if not result.ok:
        raise XrayError(
            f"Не удалось перезапустить {XRAY_UNIT}: {result.stderr.strip()}"
        )


def _xray_meta(state: GatewayState) -> dict:
    meta = state.protocols.get("xray")
    if not meta or not meta.get("installed"):
        raise XrayError("Xray не установлен — сначала выполните `vds xray install`.")
    return meta


def add_client(
    name: str,
    transport: str = "reality",
    state_path: str | None = None,
) -> dict:
    """Добавить клиента (transport: reality|xhttp); вернуть dict с share-link.

    Дубликат имени — StoreError (до записи конфига). Для xhttp — запись
    uuid в XHTTP-inbound конфига и ссылка security=tls&network=xhttp.
    """
    state = load_state(state_path)
    meta = _xray_meta(state)
    sni = meta.get("sni", "www.google.com")
    port = int(meta.get("port", 443))
    public_key = meta.get("public_key", "")
    short_id = meta.get("short_id", "")

    if transport == "xhttp":
        xhttp_meta = state.protocols.get("xhttp")
        if not xhttp_meta or not xhttp_meta.get("domain"):
            raise XrayError(
                "XHTTP не установлен — сначала выполните "
                "`vds xray add-transport xhttp --domain <домен>`."
            )
        link_domain = str(xhttp_meta["domain"])
        link_port = 443 if xhttp_meta.get("mode") == "fallback" else int(
            xhttp_meta.get("port", 8443)
        )
    elif transport == "reality":
        link_port = port
        # SPEC WP-4 (OQ-3): адрес Reality-ссылки = state.domain если задан,
        # иначе прежнее поведение — публичный IP (не ломаем старый вывод).
        link_host_state = state.domain or ""
    else:
        raise XrayError(
            f"Неизвестный transport {transport!r} (поддерживаются: reality, xhttp)."
        )

    client_uuid = gen_uuid()
    extra = {"public_key": public_key, "short_id": short_id}
    if transport == "xhttp":
        extra["transport"] = "xhttp"
    profile = ClientProfile(
        name=name,
        protocol="xray",
        port=port,
        uuid=client_uuid,
        sni=sni,
        extra=extra,
    )
    new_state = store_add_client(state, profile)  # StoreError: дубликат имени

    old_config = XRAY_CONFIG_PATH.read_text(encoding="utf-8")
    _rewrite_clients(_xray_uuids(new_state), _xhttp_uuids(new_state))
    try:
        _restart_unit()
    except XrayError:
        # Откат конфига: сервис не перезапущен — клиенты не должны «теряться».
        write_secret_atomic(str(XRAY_CONFIG_PATH), old_config, mode=0o600)
        raise

    save_state(new_state, state_path)

    if transport == "xhttp":
        share_link = render_xhttp_share_link(
            domain=link_domain,
            client_uuid=client_uuid,
            name=name,
            port=link_port,
            path=str(xhttp_meta.get("extra", {}).get("path", XHTTP_PATH)),
        )
    else:
        host = link_host_state or public_ip() or "SERVER_IP"
        share_link = render_share_link(
            host=host,
            client_uuid=client_uuid,
            sni=sni,
            public_key=public_key,
            short_id=short_id,
            name=name,
            port=port,
        )
    console.print(f"[success][xray] Клиент '{name}' добавлен ({transport}).[/success]")
    console.print(f"[change]{share_link}[/change]")
    return {
        "name": name,
        "protocol": "xray",
        "transport": transport,
        "port": port,
        "uuid": client_uuid,
        "sni": sni,
        "share_link": share_link,
    }


def remove_client(name: str, state_path: str | None = None) -> int:
    """Удалить клиента по имени (StoreError, если не найден). 0 — успех."""
    state = load_state(state_path)
    _xray_meta(state)
    new_state = store_remove_client(state, name)  # StoreError: не найден

    old_config = XRAY_CONFIG_PATH.read_text(encoding="utf-8")
    _rewrite_clients(_xray_uuids(new_state), _xhttp_uuids(new_state))
    try:
        _restart_unit()
    except XrayError:
        write_secret_atomic(str(XRAY_CONFIG_PATH), old_config, mode=0o600)
        raise

    save_state(new_state, state_path)
    console.print(f"[change][xray] Клиент '{name}' удалён.[/change]")
    return 0


def list_clients(state_path: str | None = None) -> list[ClientProfile]:
    """Xray-клиенты из gateway store."""
    return [c for c in load_state(state_path).clients if c.protocol == "xray"]


def _validate_domain(domain: str) -> bool:
    """Формат домена (те же правила, что acme.install._validate_domain): без
    пробелов/схем, минимум две непустые метки; DNS-чек отдельно (E1)."""
    if not domain or " " in domain or "/" in domain or "@" in domain:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 2 and all(labels)


def regen_reality_links(state_path: str | None = None) -> list[dict]:
    """Перерендерить Reality share-links существующих клиентов (SPEC WP-4).

    Ссылки в store не хранятся — «перегенерация» это вывод по текущему
    состоянию: адрес = state.domain если задан, иначе публичный IP (прежнее
    поведение по умолчанию). XHTTP-клиенты не входят (их адрес — домен
    XHTTP-транспорта из protocols["xhttp"]).
    """
    state = load_state(state_path)
    meta = _xray_meta(state)
    host = state.domain or public_ip() or "SERVER_IP"
    sni = meta.get("sni", "www.google.com")
    port = int(meta.get("port", 443))
    links: list[dict] = []
    for client in state.clients:
        if (
            client.protocol != "xray"
            or not client.uuid
            or client.extra.get("transport") == "xhttp"
        ):
            continue
        links.append(
            {
                "name": client.name,
                "share_link": render_share_link(
                    host=host,
                    client_uuid=client.uuid,
                    sni=sni,
                    public_key=str(
                        client.extra.get("public_key", meta.get("public_key", ""))
                    ),
                    short_id=str(
                        client.extra.get("short_id", meta.get("short_id", ""))
                    ),
                    name=client.name,
                    port=port,
                ),
            }
        )
    return links


def use_domain(domain: str, state_path: str | None = None) -> dict:
    """`vds xray use-domain` (SPEC WP-4, OQ-3 включён): адрес Reality-ссылок
    становится доменом.

    Формат домена + E1 (DNS -> публичный IP сервера, до любых изменений,
    переиспользует acme.install.dns_resolves_to) -> запись state.domain ->
    перегенерация Reality-ссылок существующих клиентов. config.json НЕ
    меняется: `dest`/`serverNames` Reality не трогаются (чужой сайт-маска,
    REQ FR-3). Повторный запуск с тем же доменом — идемпотентен (exit 0,
    состояние не перезаписывается).

    Возвращает {"domain": ..., "changed": bool, "links": [...]}.
    """
    if os.geteuid() != 0:
        raise XrayError("Требуется root (запустите через sudo).")
    if not _validate_domain(domain):
        raise XrayError(
            f"Некорректный домен: {domain!r} (ожидалось имя вида example.com)."
        )
    state = load_state(state_path)
    _xray_meta(state)

    if state.domain == domain:
        links = regen_reality_links(state_path)
        console.print(
            f"[info][xray] Домен {domain} уже установлен — состояние "
            "не изменялось (идемпотентно).[/info]"
        )
        for item in links:
            console.print(f"[change]{item['share_link']}[/change]")
        return {"domain": domain, "changed": False, "links": links}

    ip = public_ip()
    if not ip:
        raise XrayError(
            "Не удалось определить публичный IP (api.ipify.org) — он нужен "
            "для сверки с DNS-записью домена (E1)."
        )
    if not dns_resolves_to(domain, ip):
        raise XrayError(
            f"Домен {domain} не резолвится в {ip} (E1). Исправьте DNS-запись "
            "и повторите — изменения не производились."
        )

    with FileLock(LOCK_FILE):
        # Перечитать под блокировкой: между проверкой и записью состояние
        # могло измениться (другой процесс).
        state = load_state(state_path)
        _xray_meta(state)
        state.domain = domain
        try:
            save_state(state, state_path)
        except OSError as exc:
            raise XrayError(f"Не удалось сохранить состояние: {exc}") from exc

    links = regen_reality_links(state_path)
    console.print(
        f"[success][xray] Домен {domain} установлен: Reality-ссылки теперь "
        "с адресом-доменом (dest/serverNames не менялись).[/success]"
    )
    for item in links:
        console.print(f"[change]{item['share_link']}[/change]")
    return {"domain": domain, "changed": True, "links": links}
