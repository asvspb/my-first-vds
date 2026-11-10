"""Клиенты AmneziaWG: add-client / remove-client (SPEC-20261110 WP-3).

Поток add_client: root-check → installed-чек (state.protocols["amneziawg"])
→ store.add_client (дубль имени — StoreError ДО мутаций, паттерн E4)
→ next IP из 10.9.0.0/24 (свободный, клиенты с .2) → клиентские ключи
(`awg genkey`/`awg pubkey`, PSK `awg genpsk` при psk_required и без --no-psk)
→ рендер клиентского .conf (WP-1 функции: серверные S1/S2/H1–H4 из
state-меты, свои J-параметры, Endpoint = state.domain | публичный IP) →
запись .conf 0600 в AWG_CLIENTS_DIR → [Peer]-секция в серверный
/etc/amnezia/awg0.conf (бэкап .bak-pre-mutation, 0600) → рестарт юнита
(SPEC §2: единственный допустимый downtime; при сбое — откат конфига и
удаление клиентского .conf) → сохранение state.

Секреты: клиентский private_key и PSK — только в state.json (0600) и
клиентском .conf (0600); в stdout/выводе — только пути и адреса (SPEC §5).

remove_client: dry-run по умолчанию (SPEC §5) — возвращает план; `--apply`
удаляет [Peer] из серверного .conf, клиентский .conf и запись из state,
рестарт юнита с откатом при сбое.
"""

import os
import random
import tempfile
from pathlib import Path
from typing import Optional

from src.amneziawg.config import (
    DEFAULT_CLIENT_ALLOWED_IPS,
    ClientParams,
    gen_obfuscation_params,
    render_client_conf,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import public_ip
from src.core.secrets import write_secret_atomic
from src.core.shell import ShellResult, run_list
from src.gateway.paths import (
    AWG_CLIENTS_DIR,
    AWG_CONFIG_PATH,
    AWG_UNIT,
)
from src.gateway.store import (
    ClientProfile,
    GatewayState,
    add_client as store_add_client,
    load_state,
    remove_client as store_remove_client,
    save_state,
)

LOCK_FILE = "/var/run/vds-amneziawg-clients.lock"

# Первый адрес, раздаваемый клиентам (10.9.0.1 — сервер, SPEC §3).
FIRST_CLIENT_HOST = 2

BACKUP_SUFFIX = ".bak-pre-mutation"


class AWGClientError(Exception):
    """Сбой клиентской операции AmneziaWG (не установлен, конфиг, рестарт)."""


def _run_checked(args: list[str], timeout: int, what: str) -> ShellResult:
    """run_list с читаемой ошибкой AWGClientError при неуспехе (без traceback)."""
    result = run_list(args, timeout=timeout)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or f"rc={result.returncode}"
        raise AWGClientError(f"{what}: {detail}")
    return result


def _meta(state: GatewayState) -> dict:
    """Метаданные protocols["amneziawg"]; не установлен — читаемый отказ."""
    meta = state.protocols.get("amneziawg")
    if not meta or not meta.get("installed"):
        raise AWGClientError(
            "AmneziaWG не установлен — сначала выполните `vds amneziawg install`."
        )
    if not AWG_CONFIG_PATH.is_file():
        raise AWGClientError(
            f"Серверный конфиг {AWG_CONFIG_PATH} отсутствует — переустановите "
            "`vds amneziawg install`."
        )
    return meta


def _allocated_hosts(state: GatewayState) -> list[int]:
    """Хост-части 10.9.0.x, занятые amneziawg-клиентами в state."""
    hosts: list[int] = []
    for client in state.clients:
        if client.protocol != "amneziawg":
            continue
        address = str(client.extra.get("address", ""))
        parts = address.split("/")
        if len(parts) != 2 or not parts[0].startswith("10.9.0."):
            continue
        try:
            hosts.append(int(parts[0].rsplit(".", 1)[1]))
        except ValueError:
            continue
    return hosts


def _next_address(state: GatewayState) -> str:
    """Первый свободный адрес 10.9.0.x/32 (x >= 2). Подсеть /24 — максимум
    253 клиента; переполнение — читаемый отказ (частичной мутации нет)."""
    taken = set(_allocated_hosts(state))
    for host in range(FIRST_CLIENT_HOST, 255):
        if host not in taken:
            return f"10.9.0.{host}/32"
    raise AWGClientError(
        "Подсеть 10.9.0.0/24 исчерпана (253 клиента) — новые клиенты невозможны."
    )


def _gen_client_keys() -> tuple[str, str]:
    """Клиентская пара ключей: (private_key, public_key) через awg genkey/pubkey.

    Приватный ключ проходит через tmp-файл 0600 только для `awg pubkey < file`;
    файл удаляется вместе с tmp-каталогом (паттерн src/amneziawg/install.py).
    """
    priv = _run_checked(["awg", "genkey"], timeout=10, what="awg genkey").output
    with tempfile.TemporaryDirectory(prefix="vds-awg-cli-") as tmp:
        priv_file = Path(tmp) / "client-priv.tmp"
        fd = os.open(priv_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(priv + "\n")
        pub = _run_checked(
            ["sh", "-c", f"awg pubkey < {os.path.abspath(priv_file)}"],
            timeout=10,
            what="awg pubkey",
        ).output
    return priv, pub


def _validate_server_conf(text: str) -> None:
    """Минимальная проверка серверного .conf (E6): битый — отказ до мутаций."""
    if "[Interface]" not in text or "PrivateKey = " not in text:
        raise AWGClientError(
            f"Серверный конфиг {AWG_CONFIG_PATH} повреждён (нет [Interface]/PrivateKey). "
            "Изменения не выполнялись; восстановите конфиг (бэкапы .bak-pre-*)."
        )


def _append_peer(server_conf_text: str, name: str, public_key: str,
                 psk: Optional[str], address: str) -> str:
    """Добавить [Peer]-секцию клиента к тексту серверного .conf.

    Коллизия адреса в самом конфиге — отказ (конфиг расходится с state:
    править молча нельзя).
    """
    if f"AllowedIPs = {address}" in server_conf_text:
        raise AWGClientError(
            f"Адрес {address} уже присутствует в {AWG_CONFIG_PATH}, но отсутствует "
            "в state — конфиг и state расходятся. Разберите расхождение вручную."
        )
    lines = ["", "[Peer]", f"# {name}", f"PublicKey = {public_key}"]
    if psk is not None:
        lines.append(f"PresharedKey = {psk}")
    lines.append(f"AllowedIPs = {address}")
    return server_conf_text.rstrip("\n") + "\n" + "\n".join(lines) + "\n"


def _peer_block_bounds(text: str, name: str) -> Optional[tuple[int, int]]:
    """Границы (start, end) [Peer]-блока клиента `name` (комментарий `# name`)
    в тексте серверного .conf; end — за последней строкой блока. None — нет."""
    lines = text.split("\n")
    peer_indices = [i for i, ln in enumerate(lines) if ln.strip() == "[Peer]"]
    for idx, start in enumerate(peer_indices):
        end = peer_indices[idx + 1] if idx + 1 < len(peer_indices) else len(lines)
        block = lines[start:end]
        if any(ln.strip() == f"# {name}" for ln in block):
            return start, end
    return None


def _remove_peer(server_conf_text: str, name: str) -> str:
    """Убрать [Peer]-блок клиента `name`; нет блока — отказ до мутаций."""
    lines = server_conf_text.split("\n")
    bounds = _peer_block_bounds(server_conf_text, name)
    if bounds is None:
        raise AWGClientError(
            f"Peer-секция клиента '{name}' не найдена в {AWG_CONFIG_PATH}. "
            "Изменения не выполнялись."
        )
    start, end = bounds
    del lines[start:end]
    return "\n".join(lines).rstrip("\n") + "\n"


def _restart_unit() -> None:
    result = run_list(["systemctl", "restart", AWG_UNIT], timeout=30)
    if not result.ok:
        raise AWGClientError(
            f"Не удалось перезапустить {AWG_UNIT}: {result.stderr.strip()}"
        )


def _endpoint_host(state: GatewayState) -> str:
    """Хост Endpoint: state.domain, иначе публичный IP (паттерн xray reality-host)."""
    return state.domain or public_ip() or "SERVER_IP"


def add_client(
    name: str,
    no_psk: bool = False,
    state_path: Optional[str] = None,
) -> dict:
    """Добавить amneziawg-клиента; вернуть dict с conf_path (без секретов).

    Дубликат имени — StoreError (store.add_client, до любых мутаций).
    """
    if os.geteuid() != 0:
        raise AWGClientError("Требуется root (запустите через sudo).")

    state = load_state(state_path)
    meta = _meta(state)
    port = int(meta.get("port", 51825))
    server_pubkey = str(meta.get("public_key", ""))
    if not server_pubkey:
        raise AWGClientError(
            "В state нет public_key сервера AmneziaWG — переустановите "
            "`vds amneziawg install`."
        )
    server_obf = dict(meta.get("obfuscation") or {})
    psk_required = bool(meta.get("psk_required", True))

    # Дубль имени и аллокация адреса — до любых мутаций (паттерн E4).
    probe = ClientProfile(name=name, protocol="amneziawg", port=port)
    new_state = store_add_client(state, probe)  # StoreError: дубль имени
    address = _next_address(state)

    priv, pub = _gen_client_keys()
    use_psk = psk_required and not no_psk
    psk = (
        _run_checked(["awg", "genpsk"], timeout=10, what="awg genpsk").output
        if use_psk
        else None
    )
    junk = gen_obfuscation_params(random.Random())

    conf_path = AWG_CLIENTS_DIR / f"{name}.conf"
    client_conf = render_client_conf(
        ClientParams(
            private_key=priv,
            address=address,
            server_pubkey=server_pubkey,
            endpoint=f"{_endpoint_host(state)}:{port}",
            junk={k: junk[k] for k in ("Jc", "Jmin", "Jmax")},
            obf=server_obf,
            psk=psk,
            allowed_ips=DEFAULT_CLIENT_ALLOWED_IPS,
        )
    )
    profile = ClientProfile(
        name=name,
        protocol="amneziawg",
        port=port,
        extra={
            "address": address,
            "private_key": priv,
            "public_key": pub,
            "conf_path": str(conf_path),
            "allowed_ips": DEFAULT_CLIENT_ALLOWED_IPS,
            **({"psk": psk} if psk is not None else {}),
        },
    )

    with FileLock(LOCK_FILE):
        server_text = AWG_CONFIG_PATH.read_text(encoding="utf-8")
        _validate_server_conf(server_text)
        new_server_text = _append_peer(server_text, name, pub, psk, address)

        backup_path = AWG_CONFIG_PATH.with_name(AWG_CONFIG_PATH.name + BACKUP_SUFFIX)
        write_secret_atomic(str(backup_path), server_text, mode=0o600)

        AWG_CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
        if not write_secret_atomic(str(conf_path), client_conf, mode=0o600):
            raise AWGClientError(f"Не удалось записать {conf_path}.")

        write_secret_atomic(str(AWG_CONFIG_PATH), new_server_text, mode=0o600)
        try:
            _restart_unit()
        except AWGClientError:
            # Откат: сервис не перезапущен — возвращаем серверный конфиг и
            # убираем клиентский .conf; state не трогаем.
            write_secret_atomic(str(AWG_CONFIG_PATH), server_text, mode=0o600)
            Path(conf_path).unlink(missing_ok=True)
            raise

    new_state.clients[-1] = profile  # заменяем probe-профиль полным
    save_state(new_state, state_path)

    console.print(f"[success][amneziawg] Клиент '{name}' добавлен: {address}.[/success]")
    console.print(
        f"[change]Конфиг: {conf_path} — импортируйте в AmneziaVPN (OQ-2).[/change]"
    )
    console.print(
        f"[info][amneziawg] Юнит {AWG_UNIT} перезапущен (краткий downtime — SPEC §2).[/info]"
    )
    return {"name": name, "protocol": "amneziawg", "port": port,
            "address": address, "conf_path": str(conf_path)}


def remove_client(
    name: str,
    apply: bool = False,
    state_path: Optional[str] = None,
) -> dict:
    """Удалить amneziawg-клиента. Dry-run по умолчанию (SPEC §5): план без
    изменений; apply=True — [Peer] из серверного .conf, клиентский .conf,
    запись из state, рестарт юнита (откат конфига при сбое)."""
    if os.geteuid() != 0:
        raise AWGClientError("Требуется root (запустите через sudo).")

    state = load_state(state_path)
    _meta(state)
    profile = next(
        (c for c in state.clients if c.name == name and c.protocol == "amneziawg"),
        None,
    )
    if profile is None:
        raise AWGClientError(f"AmneziaWG-клиент с именем '{name}' не найден.")
    conf_path = str(profile.extra.get("conf_path", ""))
    address = str(profile.extra.get("address", ""))
    plan = [
        f"peer '{name}' ({address}) из {AWG_CONFIG_PATH}",
        f"конфиг {conf_path}" if conf_path else "клиентский .conf (путь не записан)",
        f"запись '{name}' из state.json",
        f"рестарт {AWG_UNIT}",
    ]
    if not apply:
        return {"name": name, "dry_run": True, "plan": plan, "conf_path": conf_path}

    with FileLock(LOCK_FILE):
        server_text = AWG_CONFIG_PATH.read_text(encoding="utf-8")
        _validate_server_conf(server_text)
        new_server_text = _remove_peer(server_text, name)

        backup_path = AWG_CONFIG_PATH.with_name(AWG_CONFIG_PATH.name + BACKUP_SUFFIX)
        write_secret_atomic(str(backup_path), server_text, mode=0o600)

        write_secret_atomic(str(AWG_CONFIG_PATH), new_server_text, mode=0o600)
        if conf_path:
            Path(conf_path).unlink(missing_ok=True)
        try:
            _restart_unit()
        except AWGClientError:
            write_secret_atomic(str(AWG_CONFIG_PATH), server_text, mode=0o600)
            raise

        new_state = store_remove_client(state, name)  # StoreError: не найден
        save_state(new_state, state_path)

    console.print(f"[change][amneziawg] Клиент '{name}' удалён ({address}).[/change]")
    return {"name": name, "dry_run": False, "plan": plan, "conf_path": conf_path}


def list_clients(state_path: Optional[str] = None) -> list[ClientProfile]:
    """AmneziaWG-клиенты из gateway store."""
    return [c for c in load_state(state_path).clients if c.protocol == "amneziawg"]
