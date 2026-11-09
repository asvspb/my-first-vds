"""Клиенты Hysteria2: добавление/удаление, share-links.

Модель аутентификации: hysteria2 (апстрим v2) поддерживает на одном инбаунде
ОДИН auth-пароль (`auth: {type: password, password: ...}`); многопользовательский
режим возможен только через внешний HTTP-auth, что вне MVP. Поэтому используется
общий пароль инбаунда: он генерируется на install, хранится в config.yaml и
state.json (0600), а каждый клиент получает профиль в gateway store со ссылкой
на этот пароль (ClientProfile.password). Следствия (by design):

- добавление/удаление клиента НЕ меняет config.yaml и НЕ требует перезапуска
  сервиса (пароль уже в конфиге);
- смена пароля (rotate) = новый пароль для ВСЕХ клиентов; в MVP не реализована.

Поток add_client: store.add_client (дубликат имени -> StoreError) -> профиль со
ссылкой на общий пароль -> share-link в stdout. Пароль не печатается нигде,
кроме самого share-link (клиентское поле по назначению, SPEC §5).
"""

from urllib.parse import quote

from src.core.logger import console
from src.core.netcheck import public_ip
from src.gateway.store import (
    ClientProfile,
    StoreError,
    add_client as store_add_client,
    load_state,
    remove_client as store_remove_client,
    save_state,
)


class Hysteria2Error(Exception):
    """Сбой клиентской операции Hysteria2 (не установлен, состояние)."""


def render_share_link(
    host: str,
    password: str,
    name: str,
    port: int = 443,
    insecure: bool = True,
) -> str:
    """Клиентская ссылка Hysteria2 (SPEC §3, VPN-PROTOCOLS §2.3).

    Формат self-signed (insecure=True, по умолчанию — прежнее поведение):
      hysteria2://<password>@<ip>:443/?sni=<ip>&insecure=1#<name>

    Формат LE (SPEC WP-2, FR-2.2): при домене + подменённом LE-сертификате
    ссылка рендерится без `insecure=1`, sni=домен:
      hysteria2://<password>@<домен>:443/?sni=<домен>#<name>

    Пароль — буквенно-цифровой (gen_password), URL-экранирование не требуется.
    """
    insecure_part = "&insecure=1" if insecure else ""
    return (
        f"hysteria2://{password}@{host}:{port}/"
        f"?sni={host}{insecure_part}#{quote(name)}"
    )


def _le_domain(state) -> str:
    """Домен с выданным LE-сертификатом из state (WP-1); пусто — его нет."""
    meta = state.protocols.get("acme") or {}
    return str(meta.get("domain") or "")


def _hysteria2_meta(state) -> dict:
    meta = state.protocols.get("hysteria2")
    if not meta or not meta.get("installed"):
        raise Hysteria2Error(
            "Hysteria2 не установлен — сначала выполните `vds hysteria2 install`."
        )
    return meta


def add_client(name: str, state_path: str | None = None) -> dict:
    """Добавить клиента; вернуть профиль dict с share-link.

    Дубликат имени — StoreError (из store.add_client).
    """
    state = load_state(state_path)
    meta = _hysteria2_meta(state)
    port = int(meta.get("port", 443))
    password = meta.get("auth_password", "")
    if not password:
        raise Hysteria2Error(
            "В состоянии нет auth-пароля Hysteria2 — переустановите "
            "`vds hysteria2 install`."
        )

    le_domain = _le_domain(state)
    if le_domain:
        # LE-сертификат выдан (WP-1): адрес — домен, sni=домен, без insecure=1
        # (SPEC WP-2). Самоподменённый сертификат: подмена через apply-cert.
        host = le_domain
        insecure = False
    else:
        host = public_ip() or meta.get("cert_cn") or "SERVER_IP"
        insecure = True
    profile = ClientProfile(
        name=name,
        protocol="hysteria2",
        port=port,
        password=password,  # общий пароль инбаунда (см. docstring модуля)
        sni=host,           # sni = IP (self-signed) или домен (LE)
        extra={"tls": "le"} if le_domain else {},
    )
    new_state = store_add_client(state, profile)  # StoreError: дубликат имени
    save_state(new_state, state_path)

    share_link = render_share_link(
        host=host, password=password, name=name, port=port, insecure=insecure
    )
    console.print(f"[success][hysteria2] Клиент '{name}' добавлен.[/success]")
    console.print(f"[change]{share_link}[/change]")
    return {
        "name": name,
        "protocol": "hysteria2",
        "port": port,
        "password": password,
        "sni": host,
        "share_link": share_link,
    }


def remove_client(name: str, state_path: str | None = None) -> int:
    """Удалить клиента по имени (StoreError, если не найден). 0 — успех.

    Конфиг не меняется: общий пароль инбаунда остаётся действующим для
    остальных клиентов (см. docstring модуля).
    """
    state = load_state(state_path)
    _hysteria2_meta(state)
    new_state = store_remove_client(state, name)  # StoreError: не найден
    save_state(new_state, state_path)
    console.print(f"[change][hysteria2] Клиент '{name}' удалён.[/change]")
    return 0


def list_clients(state_path: str | None = None) -> list[ClientProfile]:
    """Hysteria2-клиенты из gateway store."""
    return [c for c in load_state(state_path).clients if c.protocol == "hysteria2"]
