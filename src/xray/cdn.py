"""CDN-транспорт VLESS+WS+TLS за Cloudflare proxy (SPEC-20261110 WP-2, ADR-006).

Пятый канал gateway-стека: отдельный proxied-DNS-элемент cdn.<домен>
(orange cloud), Xray-инблэнд vless+ws+tls на TCP 2053 с LE-сертификатом
cdn-домена. Рендер инблэнда — `src/xray/config.py` (WP-1, `_cdn_inbound`);
этот модуль — прекондишны, install/remove, клиенты и state.

Поток `add_cdn`: root -> xray установлен -> LE-сертификат cdn-домена
(ACME_LETSENCRYPT_LIVE, иначе отказ с подсказкой `vds acme issue`) ->
DNS cdn-домена резолвится в Cloudflare ИЛИ в публичный IP сервера
(grey-фаза развёртывания, SPEC §4.2 шаг 3) -> рендер из текущего
config.json + cdn-параметров -> под FileLock: бэкап config.json ->
атомарная запись 0600 -> `xray -test` гейт (fail: откат из бэкапа) ->
restart vds-xray (fail: откат + рестарт на прежнем конфиге) -> UFW allow
{port}/tcp -> state.protocols["xray-cdn"].

Идемпотентность: protocols["xray-cdn"].installed=True и домен совпадает —
«уже настроен», exit 0 без перегенерации uuid; другой домен — перенастройка
(перерендер конфига с новым доменом).

Reality/XHTTP-поля конфига CDN-кодом не читаются и не пишутся напрямую —
они переносятся из текущего config.json в рендер без изменений (SPEC §4.1).
Shell — только run_list; FileLock на все мутации; секреты (uuid) — только
в state.json (0600) и share-link в выводе команды (SPEC §5).
"""

import ipaddress
import json
import os
import shutil
import socket
from dataclasses import dataclass
from pathlib import Path

from src.acme.install import FULLCHAIN_NAME, PRIVKEY_NAME
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.secrets import gen_uuid, write_secret_atomic
from src.core.shell import command_exists, run_list
from src.gateway.paths import (
    CDN_ORIGIN_PORT_DEFAULT,
    CDN_WS_PATH,
    ACME_LETSENCRYPT_LIVE,
    XRAY_BIN_PATH,
    XRAY_CONFIG_PATH,
    XRAY_UNIT,
)
from src.gateway.store import GatewayState, StoreError, load_state, save_state
from src.xray.config import XrayConfigParams, render_cdn_share_link, render_config

STATE_KEY = "xray-cdn"
LOCK_FILE = "/var/run/vds-xray.lock"

# Суффиксы бэкапов config.json (существующий бэкап не перезаписывается —
# остаётся снапшотом момента первой операции, паттерн install.XHTTP_BACKUP_SUFFIX).
INSTALL_BACKUP_SUFFIX = ".bak-pre-cdn"
CLIENT_BACKUP_SUFFIX = ".bak-cdn-update"
REMOVE_BACKUP_SUFFIX = ".bak-remove-cdn"

# Диапазоны Cloudflare (https://www.cloudflare.com/ips/, зашито константой,
# обновляется коммитом — SPEC §3 check_prerequisites).
CLOUDFLARE_NETWORKS_V4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)
CLOUDFLARE_NETWORKS_V6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)
_CLOUDFLARE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in CLOUDFLARE_NETWORKS_V4 + CLOUDFLARE_NETWORKS_V6
)


class CdnError(Exception):
    """Сбой операции CDN-транспорта (прекондишны, конфиг, перезапуск)."""


@dataclass(frozen=True)
class CdnParams:
    """Параметры CDN-канала (SPEC §3)."""

    domain: str
    port: int = CDN_ORIGIN_PORT_DEFAULT
    ws_path: str = CDN_WS_PATH


def is_cloudflare_ip(ip: str) -> bool:
    """IP принадлежит диапазонам Cloudflare (SPEC §3; мусорная строка — False)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUDFLARE_NETWORKS)


def resolve_ips(domain: str) -> list[str]:
    """A/AAAA-записи домена (сетевой примитив — мокируется в тестах).

    Сбой резолва — пустой список (консервативно, как в acme.install).
    """
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def _cdn_cert_paths(domain: str) -> tuple[Path, Path]:
    """Пути LE fullchain/privkey cdn-домена (ADR-004)."""
    live = ACME_LETSENCRYPT_LIVE(domain)
    return live / FULLCHAIN_NAME, live / PRIVKEY_NAME


def _xray_installed(config_path: Path) -> bool:
    return XRAY_BIN_PATH.is_file() and config_path.is_file()


def check_prerequisites(params: CdnParams, config_path: Path | None = None) -> list[str]:
    """Список нарушений прекондишнов (пусто = ок) — SPEC §3.

    Порядок: root -> xray установлен -> LE-сертификат -> порт свободен
    -> DNS (CF-диапазоны или публичный IP сервера для grey-фазы).
    """
    config_path = config_path if config_path is not None else XRAY_CONFIG_PATH
    violations: list[str] = []
    if os.geteuid() != 0:
        violations.append("требуется root (запустите через sudo)")
    if not _xray_installed(config_path):
        violations.append(
            "Xray не установлен — сначала выполните `vds xray install`"
        )
    cert_path, key_path = _cdn_cert_paths(params.domain)
    missing = [str(p) for p in (cert_path, key_path) if not p.is_file()]
    if missing:
        violations.append(
            "файлы LE-сертификата не найдены: " + ", ".join(missing)
            + " — сначала выполните `vds acme issue --domain "
            + params.domain + "`"
        )
    if not port_free(params.port, "tcp"):
        owner = port_owner(params.port, "tcp")
        owner_info = f" (владелец: {owner})" if owner else ""
        violations.append(
            f"порт {params.port}/tcp занят{owner_info} (E9)"
        )
    ips = resolve_ips(params.domain)
    if not ips:
        violations.append(
            f"E1: домен {params.domain} не резолвится — исправьте DNS-запись"
        )
    else:
        server_ip = public_ip() or ""
        ok = any(is_cloudflare_ip(ip) or ip == server_ip for ip in ips)
        if not ok:
            violations.append(
                f"E1: домен {params.domain} резолвится в {', '.join(ips)} — "
                "ни Cloudflare, ни публичный IP этого сервера "
                f"({server_ip or 'неизвестен'}); DNS-mismatch, отклонено"
            )
    return violations


def _read_config(config_path: Path) -> dict:
    """Прочитать текущий config.json (E8: битый — CdnError, не меняем)."""
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CdnError(
            f"Не удалось прочитать {config_path}: {exc} (E8: битый конфиг — "
            "не меняю; восстановите из бэкапа)."
        ) from exc


def _reality_fields(current: dict) -> dict:
    """Reality-поля inbound#0 из текущего конфига (переносятся как есть)."""
    try:
        inbound = current["inbounds"][0]
        reality = inbound["streamSettings"]["realitySettings"]
        return {
            "client_ids": [c["id"] for c in inbound["settings"].get("clients", [])],
            "private_key": reality["privateKey"],
            "short_ids": list(reality["shortIds"]),
            "sni": reality["serverNames"][0],
            "port": int(inbound["port"]),
        }
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise CdnError(
            f"Неожиданная структура {XRAY_CONFIG_PATH}: {exc} (E8: не меняю)."
        ) from exc


def _render_with_cdn(
    current: dict, params: CdnParams, cdn_client_ids: list[str]
) -> str:
    """Полный рендер: Reality+XHTTP из текущего конфига + CDN-инблэнд (WP-1)."""
    reality = _reality_fields(current)
    cert_path, key_path = _cdn_cert_paths(params.domain)
    render_params = XrayConfigParams(
        client_ids=reality["client_ids"],
        private_key=reality["private_key"],
        short_ids=reality["short_ids"],
        sni=reality["sni"],
        port=reality["port"],
        cdn_enabled=True,
        cdn_domain=params.domain,
        cdn_port=params.port,
        cdn_ws_path=params.ws_path,
        cdn_client_ids=cdn_client_ids,
        cdn_cert_path=str(cert_path),
        cdn_key_path=str(key_path),
    )
    return render_config(render_params)


def _backup_config(config_path: Path, backup_path: Path) -> bool:
    """Бэкап config.json (0600); существующий не перезаписывается."""
    if not config_path.is_file() or backup_path.exists():
        return False
    shutil.copy2(config_path, backup_path)
    os.chmod(backup_path, 0o600)
    return True


def _rollback(backup_path: Path) -> None:
    """Откат конфига из бэкапа + рестарт на прежнем конфиге."""
    shutil.copy2(backup_path, XRAY_CONFIG_PATH)
    os.chmod(XRAY_CONFIG_PATH, 0o600)
    run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)


def _gate_and_restart(backup_path: Path) -> None:
    """`xray -test` гейт + рестарт; при сбое — откат из бэкапа (E8)."""
    test = run_list(
        [str(XRAY_BIN_PATH), "run", "-test", "-config", str(XRAY_CONFIG_PATH)],
        timeout=15,
    )
    if not test.ok:
        _rollback(backup_path)
        raise CdnError(
            "xray -test не прошёл, конфиг откатан из бэкапа "
            f"({backup_path}): {test.stderr.strip() or test.stdout.strip()}"
        )
    restart = run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
    if not restart.ok:
        _rollback(backup_path)
        raise CdnError(
            f"systemctl restart {XRAY_UNIT} не удался, конфиг откатан из "
            f"бэкапа ({backup_path}): "
            f"{restart.stderr.strip() or restart.stdout.strip()}"
        )


def _ufw_allow(port: int) -> None:
    if not command_exists("ufw"):
        return
    result = run_list(["ufw", "allow", f"{port}/tcp"], timeout=15)
    if not result.ok:
        raise CdnError(
            f"ufw allow {port}/tcp не удался: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def _ufw_delete(port: int) -> None:
    if not command_exists("ufw"):
        return
    result = run_list(["ufw", "delete", "allow", f"{port}/tcp"], timeout=15)
    if not result.ok:
        raise CdnError(
            f"ufw delete allow {port}/tcp не удался: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def _cdn_meta(state_path: str | None) -> tuple[dict, GatewayState]:
    """Meta protocols[STATE_KEY] + состояние; не установлен — CdnError."""
    state = load_state(state_path)
    meta = state.protocols.get(STATE_KEY)
    if not meta or not meta.get("installed"):
        raise CdnError(
            "CDN-транспорт не установлен — сначала выполните "
            "`vds xray add-cdn --domain <cdn-домен>`."
        )
    return meta, state


def install_cdn(params: CdnParams, state_path: str | None = None) -> int:
    """Установить/перенастроить CDN-инблэнд (SPEC §3 install_cdn). 0 — успех.

    FileLock; бэкап config.json; render+запись атомарно 0600; `xray -test`
    (fail: откат); рестарт vds-xray (fail: откат); UFW allow; state
    protocols["xray-cdn"] = {installed, domain, port, path, client_ids,
    clients}. Повторный запуск с тем же доменом — идемпотентный exit 0.
    """
    violations = check_prerequisites(params, XRAY_CONFIG_PATH)
    if violations:
        for item in violations:
            console.print(f"[error][xray-cdn] {item}[/error]")
        return 1

    try:
        current = _read_config(XRAY_CONFIG_PATH)
        state = load_state(state_path)
    except (CdnError, StoreError) as exc:
        console.print(f"[error][xray-cdn] {exc}[/error]")
        return 1

    meta = state.protocols.get(STATE_KEY)
    if meta and meta.get("installed") and meta.get("domain") == params.domain:
        console.print(
            f"[success][xray-cdn] CDN-транспорт уже настроен на "
            f"{params.domain}:{params.port} — изменений не требуется "
            "(идемпотентно).[/success]"
        )
        return 0
    reconfigure = bool(meta and meta.get("installed"))
    cdn_client_ids: list[str] = list(meta.get("client_ids", [])) if meta else []
    cdn_clients: dict[str, str] = dict(meta.get("clients", {})) if meta else {}

    rendered = _render_with_cdn(current, params, cdn_client_ids)
    backup_path = XRAY_CONFIG_PATH.with_name(
        XRAY_CONFIG_PATH.name + INSTALL_BACKUP_SUFFIX
    )

    with FileLock(LOCK_FILE):
        _backup_config(XRAY_CONFIG_PATH, backup_path)
        if not write_secret_atomic(str(XRAY_CONFIG_PATH), rendered, mode=0o600):
            console.print(
                f"[error][xray-cdn] Не удалось записать {XRAY_CONFIG_PATH}.[/error]"
            )
            return 1
        try:
            _gate_and_restart(backup_path)
        except CdnError as exc:
            console.print(f"[error][xray-cdn] {exc}[/error]")
            return 1
        try:
            _ufw_allow(params.port)
        except CdnError as exc:
            # Конфиг применён и сервис работает; правило фаервола добавить не
            # удалось — канал снаружи недоступен, сообщаем и возвращаем 1.
            console.print(
                f"[error][xray-cdn] Конфиг применён, но {exc} — канал "
                "недоступен снаружи, откройте порт вручную.[/error]"
            )
            return 1

        state.protocols[STATE_KEY] = {
            "installed": True,
            "domain": params.domain,
            "port": params.port,
            "path": params.ws_path,
            "client_ids": cdn_client_ids,
            "clients": cdn_clients,
        }
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][xray-cdn] Конфиг применён, но состояние не "
                f"сохранено: {exc}[/error]"
            )
            return 1

    verb = "перенастроен" if reconfigure else "установлен"
    console.print(
        f"[success][xray-cdn] CDN-транспорт {verb}: {params.domain}:"
        f"{params.port} (ws {params.ws_path}), UFW allow {params.port}/tcp, "
        f"{XRAY_UNIT} перезапущен.[/success]"
    )
    console.print(
        "[info][xray-cdn] Reality (TCP 443) и XHTTP не изменены. Клиенты: "
        "`vds xray add-cdn-client NAME`. Если запись ещё DNS-only (grey) — "
        "переключите в proxied (orange cloud) и SSL/TLS Full (strict), "
        "чеклист SPEC §7.1 шаги 7–8.[/info]"
    )
    return 0


def add_cdn(domain: str, port: int = CDN_ORIGIN_PORT_DEFAULT, state_path: str | None = None) -> int:
    """Точка входа `vds xray add-cdn` (root-check здесь). 0 — успех."""
    if os.geteuid() != 0:
        console.print("[error][xray-cdn] Требуется root (запустите через sudo).[/error]")
        return 1
    return install_cdn(CdnParams(domain=domain, port=port), state_path)


def add_cdn_client(name: str, state_path: str | None = None) -> dict:
    """Добавить CDN-клиента: uuid -> config (бэкап -> гейт -> рестарт) -> state.

    Возвращает dict с share-link (render_cdn_share_link, WP-1). Дубликат
    имени — CdnError до записи конфига.
    """
    if os.geteuid() != 0:
        raise CdnError("Требуется root (запустите через sudo).")

    meta, state = _cdn_meta(state_path)
    clients_map: dict[str, str] = dict(meta.get("clients", {}))
    if name in clients_map:
        raise CdnError(f"CDN-клиент с именем '{name}' уже существует.")

    params = CdnParams(
        domain=str(meta["domain"]),
        port=int(meta.get("port", CDN_ORIGIN_PORT_DEFAULT)),
        ws_path=str(meta.get("path", CDN_WS_PATH)),
    )
    current = _read_config(XRAY_CONFIG_PATH)
    client_uuid = gen_uuid()
    cdn_client_ids = list(meta.get("client_ids", [])) + [client_uuid]
    rendered = _render_with_cdn(current, params, cdn_client_ids)

    backup_path = XRAY_CONFIG_PATH.with_name(
        XRAY_CONFIG_PATH.name + CLIENT_BACKUP_SUFFIX
    )
    with FileLock(LOCK_FILE):
        _backup_config(XRAY_CONFIG_PATH, backup_path)
        if not write_secret_atomic(str(XRAY_CONFIG_PATH), rendered, mode=0o600):
            raise CdnError(f"Не удалось записать {XRAY_CONFIG_PATH}.")
        _gate_and_restart(backup_path)

        clients_map[name] = client_uuid
        meta.update(
            {
                "client_ids": cdn_client_ids,
                "clients": clients_map,
            }
        )
        state.protocols[STATE_KEY] = meta
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            raise CdnError(
                f"Конфиг обновлён, но состояние не сохранено: {exc}"
            ) from exc

    share_link = render_cdn_share_link(
        client_uuid, params.domain, params.port, params.ws_path, name
    )
    console.print(f"[success][xray-cdn] Клиент '{name}' добавлен (cdn).[/success]")
    console.print(f"[change]{share_link}[/change]")
    return {
        "name": name,
        "transport": "cdn",
        "domain": params.domain,
        "port": params.port,
        "uuid": client_uuid,
        "share_link": share_link,
    }


def _strip_cdn(config: dict) -> tuple[dict, list[str]]:
    """Вычесть CDN-инблэнды (network=ws) из конфига — чистая функция.

    Reality (TCP 443) и XHTTP не трогаются (SPEC §5). Возвращает
    (новый конфиг, список действий).
    """
    actions: list[str] = []
    new_config = json.loads(json.dumps(config))  # deep copy
    kept: list[dict] = []
    for inbound in new_config.get("inbounds", []):
        if inbound.get("streamSettings", {}).get("network") == "ws":
            actions.append(
                f"инблэнд vless+ws ({inbound.get('listen', '*')}:"
                f"{inbound.get('port')})"
            )
            continue
        kept.append(inbound)
    new_config["inbounds"] = kept
    return new_config, actions


def remove_cdn(
    apply: bool = False,
    yes: bool = False,
    state_path: str | None = None,
) -> int:
    """Снять CDN-транспорт (SPEC §3 remove_cdn). Dry-run по умолчанию.

    План: CDN-инблэнд из config.json, CDN-клиенты из state, UFW delete,
    запись protocols["xray-cdn"]. Reality/XHTTP/Hysteria2 не затрагиваются.
    Идемпотентно: нечего снимать — exit 0.
    """
    if os.geteuid() != 0:
        console.print("[error][xray-cdn] Требуется root (запустите через sudo).[/error]")
        return 1

    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][xray-cdn] {exc}[/error]")
        return 1
    meta = state.protocols.get(STATE_KEY)

    # Конфиг-часть плана: ws-инблэнды в config.json (независимо от state —
    # после полусломанной установки meta может отсутствовать при живом инблэнде).
    clean_payload: str | None = None
    backup_path_str = ""
    config_actions: list[str] = []
    if XRAY_CONFIG_PATH.is_file():
        try:
            current = _read_config(XRAY_CONFIG_PATH)
        except CdnError as exc:
            console.print(f"[error][xray-cdn] {exc}[/error]")
            return 1
        clean, config_actions = _strip_cdn(current)
        if config_actions:
            clean_payload = json.dumps(clean, indent=2, ensure_ascii=False) + "\n"
            backup_path_str = str(XRAY_CONFIG_PATH) + REMOVE_BACKUP_SUFFIX

    port = int(meta.get("port", CDN_ORIGIN_PORT_DEFAULT)) if meta else CDN_ORIGIN_PORT_DEFAULT
    plan: list[str] = list(config_actions)
    if meta:
        cdn_clients = list(meta.get("clients", {}).keys())
        if cdn_clients:
            plan.append(f"CDN-клиенты из state: {', '.join(cdn_clients)}")
        plan.append("запись protocols['xray-cdn'] из store")
    plan.append(f"UFW delete allow {port}/tcp")

    if not config_actions and not meta:
        console.print("[info][xray-cdn] CDN не установлен — нечего снимать.[/info]")
        return 0
    plan.append("(Reality TCP 443 / XHTTP 8443 / Hysteria2 UDP 443 не затрагиваются)")

    console.print("[warning][xray-cdn] План снятия CDN (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    if clean_payload is not None:
        console.print(f"  - бэкап config.json: {backup_path_str}")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: `vds xray remove-cdn --apply`[/info]"
        )
        return 0

    if not yes:
        import questionary

        if not questionary.confirm(
            "Снять CDN-транспорт? CDN-клиенты потеряют доступ; direct-каналы "
            "(Reality, XHTTP, Hysteria2) продолжат работу.",
            default=False,
        ).ask():
            console.print("[info][xray-cdn] Операция отменена.[/info]")
            return 1

    if clean_payload is not None:
        backup_path = Path(backup_path_str)
        with FileLock(LOCK_FILE):
            _backup_config(XRAY_CONFIG_PATH, backup_path)
            if not write_secret_atomic(str(XRAY_CONFIG_PATH), clean_payload, mode=0o600):
                console.print(
                    f"[error][xray-cdn] Не удалось записать {XRAY_CONFIG_PATH}.[/error]"
                )
                return 1
            try:
                _gate_and_restart(backup_path)
            except CdnError as exc:
                console.print(f"[error][xray-cdn] {exc}[/error]")
                return 1
            try:
                _ufw_delete(port)
            except CdnError as exc:
                console.print(
                    f"[error][xray-cdn] Конфиг обновлён, но {exc} — удалите "
                    "правило вручную.[/error]"
                )
                return 1

    try:
        state = load_state(state_path)
        state.protocols.pop(STATE_KEY, None)
        save_state(state, state_path)
    except (StoreError, OSError) as exc:
        console.print(
            f"[error][xray-cdn] Конфиг обновлён, но store не изменён: {exc}[/error]"
        )
        return 1

    console.print(
        "[change][xray-cdn] CDN-транспорт снят; Reality (TCP 443), XHTTP и "
        "Hysteria2 не затронуты.[/change]"
    )
    return 0


def render_cdn_link(uuid: str, params: CdnParams, name: str) -> str:
    """Share-link CDN-клиента (делегация в рендер WP-1, SPEC §3)."""
    return render_cdn_share_link(uuid, params.domain, params.port, params.ws_path, name)
