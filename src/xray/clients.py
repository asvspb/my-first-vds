"""Клиенты Xray VLESS Reality: добавление/удаление, share-links.

Поток add_client: store.add_client (дубликат имени -> StoreError) -> uuid
через secrets.gen_uuid -> обновление списка clients в config.json (атомарно,
0600) -> перезапуск юнита (при сбое — откат конфига) -> сохранение состояния.
Приватный ключ Reality не покидает config.json: в share-link попадают только
клиентские поля (uuid/pbk/sid — по назначению, SPEC §5).
"""

import json
from urllib.parse import quote

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
from src.xray.config import FLOW


class XrayError(Exception):
    """Сбой клиентской операции Xray (не установлен, конфиг, перезапуск)."""


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


def _xray_uuids(state: GatewayState) -> list[str]:
    """UUID всех xray-клиентов состояния (порядок стабилен — порядок списка)."""
    return [
        client.uuid
        for client in state.clients
        if client.protocol == "xray" and client.uuid
    ]


def _rewrite_clients(uuids: list[str]) -> None:
    """Перезаписать список clients в config.json, сохранив остальные поля."""
    if not XRAY_CONFIG_PATH.is_file():
        raise XrayError(
            f"Конфиг {XRAY_CONFIG_PATH} не найден — сначала `vds xray install`."
        )
    config = json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        inbound = config["inbounds"][0]
        inbound["settings"]["clients"] = [
            {"id": client_uuid, "flow": FLOW} for client_uuid in uuids
        ]
    except (KeyError, IndexError) as exc:
        raise XrayError(
            f"Неожиданная структура {XRAY_CONFIG_PATH}: {exc}."
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


def add_client(name: str, state_path: str | None = None) -> dict:
    """Добавить клиента; вернуть профиль dict с share-link.

    Дубликат имени — StoreError (до записи конфига).
    """
    state = load_state(state_path)
    meta = _xray_meta(state)
    sni = meta.get("sni", "www.google.com")
    port = int(meta.get("port", 443))
    public_key = meta.get("public_key", "")
    short_id = meta.get("short_id", "")

    client_uuid = gen_uuid()
    profile = ClientProfile(
        name=name,
        protocol="xray",
        port=port,
        uuid=client_uuid,
        sni=sni,
        extra={"public_key": public_key, "short_id": short_id},
    )
    new_state = store_add_client(state, profile)  # StoreError: дубликат имени

    old_config = XRAY_CONFIG_PATH.read_text(encoding="utf-8")
    _rewrite_clients(_xray_uuids(new_state))
    try:
        _restart_unit()
    except XrayError:
        # Откат конфига: сервис не перезапущен — клиенты не должны «теряться».
        write_secret_atomic(str(XRAY_CONFIG_PATH), old_config, mode=0o600)
        raise

    save_state(new_state, state_path)

    host = public_ip() or "SERVER_IP"
    share_link = render_share_link(
        host=host,
        client_uuid=client_uuid,
        sni=sni,
        public_key=public_key,
        short_id=short_id,
        name=name,
        port=port,
    )
    console.print(f"[success][xray] Клиент '{name}' добавлен.[/success]")
    console.print(f"[change]{share_link}[/change]")
    return {
        "name": name,
        "protocol": "xray",
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
    _rewrite_clients(_xray_uuids(new_state))
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
