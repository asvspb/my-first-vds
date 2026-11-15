"""Клиенты AWG-сервера релея: `vds relay add-client` (SPEC FR-4).

Поток add_client: root-check → сервер релея установлен (state.protocols['relay'])
→ store.add_client (дубль имени — StoreError ДО мутаций) → первый свободный
10.10.0.x (x >= 2) → ключи (`awg genkey`/`pubkey`/`genpsk`) → клиентский
.conf (endpoint = relay-домен:443, MTU 1280 — двойная инкапсуляция, разрешён
 AllowedIPs 0.0.0.0/0: DNS и весь трафик клиента уходит на релей и там
режется policy-routing по ADR-007) → запись .conf 0600 → [Peer] в
/etc/amnezia/awg0.conf (бэкап .bak-pre-mutation) → рестарт vds-relay-awg
(при сбое — откат конфига и удаление .conf) → state.

Секреты: private_key/PSK — только в state.json (0600) и клиентском .conf
(0600); stdout — пути и адреса. QR не рендерится (не в зависимостях v1;
конфиг копируется с сервера по ssh — DEPLOY-RU-RELAY §Клиенты).
"""

import os
import random
import tempfile
from pathlib import Path
from typing import Optional

from src.amneziawg.clients import _append_peer, _gen_client_keys, _validate_server_conf
from src.amneziawg.config import (
    DEFAULT_CLIENT_ALLOWED_IPS,
    ClientParams,
    gen_obfuscation_params,
    render_client_conf,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.gateway.paths import AWG_CLIENTS_DIR  # тот же каталог ссылок клиентов
from src.gateway.store import (
    ClientProfile,
    add_client as store_add_client,
    load_state,
    save_state,
)
from src.relay.paths import (
    LOCK_FILE,
    RELAY_CLIENTS_DIR,
    RELAY_CONFIG_PATH,
    RELAY_MTU,
    RELAY_PORT,
    RELAY_SUBNET,
    RELAY_UNIT,
)

FIRST_CLIENT_HOST = 2  # 10.10.0.1 — сервер (SPEC §2)
BACKUP_SUFFIX = ".bak-pre-mutation"


class RelayClientError(Exception):
    """Сбой клиентской операции релея (не установлен, конфиг, рестарт)."""


def _run_checked(args: list[str], timeout: int, what: str) -> str:
    result = run_list(args, timeout=timeout)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or f"rc={result.returncode}"
        raise RelayClientError(f"{what}: {detail}")
    return result.output


def _meta(state, state_path: Optional[str]) -> dict:
    """Метаданные релея из state; сервер не установлен — читаемый отказ."""
    meta = state.protocols.get("relay") or {}
    if not meta.get("installed") or not RELAY_CONFIG_PATH.is_file():
        raise RelayClientError(
            "RU-relay не установлен — сначала `sudo vds relay init --apply ...` "
            "(SPEC-20261114-ru-relay)."
        )
    if not meta.get("public_key"):
        raise RelayClientError(
            "В state.protocols['relay'] нет public_key — переустановите relay init --apply."
        )
    return meta


def _allocated_hosts(state) -> list[int]:
    """Занятые хост-части 10.10.0.x (клиенты protocol='relay-awg')."""
    hosts: list[int] = []
    for client in state.clients:
        if client.protocol != "relay-awg":
            continue
        address = str(client.extra.get("address", ""))
        if not address.startswith("10.10.0."):
            continue
        try:
            hosts.append(int(address.split("/")[0].rsplit(".", 1)[1]))
        except (ValueError, IndexError):
            continue
    return hosts


def next_address(state) -> str:
    """Первый свободный 10.10.0.x/32 (x >= 2); исчерпание — читаемый отказ."""
    taken = set(_allocated_hosts(state))
    for host in range(FIRST_CLIENT_HOST, 255):
        if host not in taken:
            return f"10.10.0.{host}/32"
    raise RelayClientError(
        f"Подсеть {RELAY_SUBNET} исчерпана (253 клиента) — новые клиенты невозможны."
    )


def _append_mtu(client_conf: str, mtu: int) -> str:
    """MTU в [Interface] клиентского conf (render_client_conf MTU не пишет)."""
    lines = client_conf.split("\n")
    out: list[str] = []
    for line in lines:
        out.append(line)
        if line.strip().startswith("Address = "):
            out.append(f"MTU = {mtu}")
    return "\n".join(out)


def add_client(
    name: str,
    no_psk: bool = False,
    keepalive: Optional[int] = None,
    state_path: Optional[str] = None,
) -> dict:
    """Добавить пир awg0; вернуть dict с conf_path (без секретов)."""
    if os.geteuid() != 0:
        raise RelayClientError("Требуется root (запустите через sudo).")

    state = load_state(state_path)
    meta = _meta(state, state_path)
    server_pubkey = str(meta["public_key"])
    server_obf = dict(meta.get("obfuscation") or {})
    psk_required = bool(meta.get("psk_required", True))
    domain = str(state.domain or meta.get("domain") or "")

    # Дубль имени и аллокация адреса — до мутаций (паттерн E4).
    probe = ClientProfile(name=name, protocol="relay-awg", port=RELAY_PORT)
    new_state = store_add_client(state, probe)
    address = next_address(state)

    priv, pub = _gen_client_keys()
    use_psk = psk_required and not no_psk
    psk = _run_checked(["awg", "genpsk"], timeout=10, what="awg genpsk") if use_psk else None
    junk = gen_obfuscation_params(random.Random())
    endpoint = f"{domain or 'relay.asvpersonal.ru'}:{RELAY_PORT}"

    conf_path = RELAY_CLIENTS_DIR / f"{name}.conf"
    client_conf = _append_mtu(
        render_client_conf(
            ClientParams(
                private_key=priv,
                address=address,
                server_pubkey=server_pubkey,
                endpoint=endpoint,
                junk={k: junk[k] for k in ("Jc", "Jmin", "Jmax")},
                obf=server_obf,
                psk=psk,
                allowed_ips=DEFAULT_CLIENT_ALLOWED_IPS,
                keepalive=keepalive,
            )
        ),
        RELAY_MTU,
    )
    profile = ClientProfile(
        name=name,
        protocol="relay-awg",
        port=RELAY_PORT,
        extra={
            "address": address,
            "private_key": priv,
            "public_key": pub,
            "conf_path": str(conf_path),
            "endpoint": endpoint,
            "mtu": RELAY_MTU,
            "allowed_ips": DEFAULT_CLIENT_ALLOWED_IPS,
            **({"psk": psk} if psk is not None else {}),
        },
    )

    with FileLock(LOCK_FILE):
        server_text = RELAY_CONFIG_PATH.read_text(encoding="utf-8")
        _validate_server_conf(server_text)
        new_server_text = _append_peer(server_text, name, pub, psk, address)

        backup = RELAY_CONFIG_PATH.with_name(RELAY_CONFIG_PATH.name + BACKUP_SUFFIX)
        write_secret_atomic(str(backup), server_text, mode=0o600)

        RELAY_CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
        if not write_secret_atomic(str(conf_path), client_conf, mode=0o600):
            raise RelayClientError(f"Не удалось записать {conf_path}.")

        write_secret_atomic(str(RELAY_CONFIG_PATH), new_server_text, mode=0o600)
        try:
            restart = run_list(["systemctl", "restart", RELAY_UNIT], timeout=30)
            if not restart.ok:
                raise RelayClientError(
                    f"Рестарт {RELAY_UNIT}: {restart.stderr.strip()}"
                )
        except RelayClientError:
            write_secret_atomic(str(RELAY_CONFIG_PATH), server_text, mode=0o600)
            Path(conf_path).unlink(missing_ok=True)
            raise

    new_state.clients[-1] = profile
    save_state(new_state, state_path)

    console.print(f"[success][relay] Пир '{name}' добавлен: {address}.[/success]")
    console.print(
        f"[change]Конфиг: {conf_path} (0600) — скопируйте с сервера по ssh и "
        f"импортируйте в AmneziaVPN; endpoint {endpoint}, MTU {RELAY_MTU}.[/change]"
    )
    console.print(
        f"[info][relay] DNS клиента уходит на релей (AllowedIPs 0.0.0.0/0): "
        "RU-CIDR идёт напрямую, прочее — через awg1 до asv1 (ADR-007).[/info]"
    )
    return {"name": name, "protocol": "relay-awg", "address": address,
            "conf_path": str(conf_path), "endpoint": endpoint}


def list_clients(state_path: Optional[str] = None):
    """Пиры awg0 из gateway store (для будущего remove; вывод без секретов)."""
    state = load_state(state_path)
    return [c for c in state.clients if c.protocol == "relay-awg"]
