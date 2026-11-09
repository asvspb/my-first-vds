"""Статус Hysteria2: юнит, UDP 443, сертификат, journal без секретов.

Не установлен — читаемое сообщение и exit != 0. Вывод журнала маскируется:
auth-пароль из state.json/config.yaml заменяется на `***` (SPEC §5).
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.shell import run_list
from src.gateway.paths import (
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_CONFIG_PATH,
    HYSTERIA2_UNIT,
)
from src.gateway.store import StoreError, load_state
from src.hysteria2.install import HYSTERIA2_BIN_PATH, is_service_active

UNIT_FILE = Path("/etc/systemd/system") / HYSTERIA2_UNIT

_PASSWORD_YAML_RE = re.compile(r'^(\s*password:\s*"?)[A-Za-z0-9]+("?\s*)$', re.M)
_OPENSSL_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _mask_secrets(text: str, secrets: Iterable[str]) -> str:
    """Заменить известные секретные значения и password в YAML-дампах."""
    masked = text
    for value in secrets:
        if value:
            masked = masked.replace(value, "***")
    return _PASSWORD_YAML_RE.sub(r"\1***\2", masked)


def _known_secrets() -> list[str]:
    """Auth-пароли для маскирования (status не должен падать на битых файлах)."""
    values: list[str] = []
    try:
        meta = load_state().protocols.get("hysteria2", {})
        password = meta.get("auth_password")
        if password:
            values.append(password)
    except StoreError:
        pass
    if HYSTERIA2_CONFIG_PATH.is_file():
        try:
            text = HYSTERIA2_CONFIG_PATH.read_text(encoding="utf-8")
            match = re.search(r'^\s*password:\s*"?([A-Za-z0-9]+)"?\s*$', text, re.M)
            if match:
                values.append(match.group(1))
        except OSError:
            pass
    return [v for v in values if v]


def _cert_info() -> dict:
    """Тип и срок сертификата из одного вызова openssl (WP-2, E10).

    Тип: "le" — издатель Let's Encrypt (сертификат подменён apply-cert),
    "self-signed" — издатель не LE (исходный openssl req -x509),
    None — сертификат не прочитан. days_left — остаток дней или None.
    """
    result = run_list(
        [
            "openssl", "x509", "-issuer", "-enddate", "-noout",
            "-in", str(HYSTERIA2_CERT_PATH),
        ],
        timeout=10,
    )
    if not result.ok:
        return {"cert_type": None, "days_left": None}
    cert_type: str | None = None
    days_left: int | None = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("issuer="):
            cert_type = "le" if "Let's Encrypt" in line else "self-signed"
        elif line.startswith("notAfter="):
            try:
                not_after = datetime.strptime(
                    line.split("=", 1)[1].strip(), _OPENSSL_DATE_FMT
                ).replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
            except ValueError:
                days_left = None
    return {"cert_type": cert_type, "days_left": days_left}


def collect_status() -> dict:
    """Собрать состояние Hysteria2 как dict (для adapter и вывода)."""
    installed = HYSTERIA2_BIN_PATH.is_file()
    active = is_service_active() if installed else False
    port = 443
    port_listening = not port_free(port, "udp")
    owner = port_owner(port, "udp")
    cert_type: str | None = None
    cert_days: int | None = None
    if HYSTERIA2_CERT_PATH.is_file():
        info = _cert_info()
        cert_type = info["cert_type"]
        cert_days = info["days_left"]
    client_names: list[str] = []
    acme_domain = ""
    state_error: str | None = None
    try:
        state = load_state()
        client_names = [c.name for c in state.clients if c.protocol == "hysteria2"]
        acme_meta = state.protocols.get("acme") or {}
        acme_domain = str(acme_meta.get("domain") or "")
    except StoreError as exc:
        state_error = str(exc)
    # E10: домен выдан (LE в state), но у Hysteria2 всё ещё self-signed —
    # смешанное состояние: новые ссылки без insecure=1 не проходят валидацию.
    domain_mismatch = bool(acme_domain) and cert_type is not None and cert_type != "le"
    return {
        "installed": installed,
        "unit_active": active,
        "config_path": str(HYSTERIA2_CONFIG_PATH),
        "port": port,
        "port_listening": port_listening,
        "port_owner": owner,
        "cert_days_left": cert_days,
        "cert_type": cert_type,
        "acme_domain": acme_domain,
        "domain_mismatch": domain_mismatch,
        "clients": client_names,
        "state_error": state_error,
    }


def run_status() -> int:
    """Точка входа `vds hysteria2 status`. 0 — установлен; 1 — не установлен."""
    if not HYSTERIA2_BIN_PATH.is_file():
        console.print(
            f"[warning][hysteria2] Hysteria2 не установлен (нет {HYSTERIA2_BIN_PATH}).[/warning]"
        )
        console.print("[info][hysteria2] Установите: `vds hysteria2 install`[/info]")
        return 1

    info = collect_status()
    console.print(f"[info][hysteria2] Бинарь:[/info] {HYSTERIA2_BIN_PATH}")
    console.print(
        f"[info][hysteria2] Юнит {HYSTERIA2_UNIT}:[/info] "
        + ("[success]active[/success]" if info["unit_active"] else "[error]inactive[/error]")
    )

    if info["cert_days_left"] is None:
        console.print(
            f"[warning][hysteria2] Сертификат {HYSTERIA2_CERT_PATH} не прочитан.[/warning]"
        )
    else:
        days = info["cert_days_left"]
        tag = "success" if days > 30 else "warning"
        cert_label = {
            "le": "LE (Let's Encrypt)",
            "self-signed": "self-signed",
            None: "тип не определён",
        }[info["cert_type"]]
        console.print(
            f"[{tag}][hysteria2] Сертификат ({cert_label}): осталось {days} дн.[/{tag}]"
        )
        if info["cert_type"] == "le" and info["acme_domain"]:
            console.print(
                f"[info][hysteria2] Домен: {info['acme_domain']} "
                "(автопродление certbot.timer + deploy-hook).[/info]"
            )

    if info.get("domain_mismatch"):
        console.print(
            f"[warning][hysteria2] E10: домен {info['acme_domain']} выдан, но "
            "у Hysteria2 ещё self-signed — LE-сертификат не применён. "
            "Выполните `vds hysteria2 apply-cert --apply`.[/warning]"
        )

    if info["port_listening"]:
        owner = f" (владелец: {info['port_owner']})" if info["port_owner"] else ""
        console.print(f"[info][hysteria2] Порт {info['port']}/udp: слушается{owner}.[/info]")
    else:
        console.print(
            f"[warning][hysteria2] Порт {info['port']}/udp не слушается.[/warning]"
        )

    if info["state_error"]:
        console.print(f"[error][hysteria2] {info['state_error']}[/error]")
    elif info["clients"]:
        names = ", ".join(info["clients"])
        console.print(
            f"[info][hysteria2] Клиенты ({len(info['clients'])}):[/info] {names}"
        )
    else:
        console.print("[info][hysteria2] Клиентов нет (`vds hysteria2 add-client NAME`).[/info]")

    journal = run_list(
        ["journalctl", "-u", HYSTERIA2_UNIT, "-n", "20", "--no-pager", "-p", "warning"],
        timeout=10,
    )
    if journal.ok and journal.stdout.strip():
        masked = _mask_secrets(journal.stdout, _known_secrets())
        console.print("[info][hysteria2] Последние записи journal (секреты маскированы):[/info]")
        for line in masked.splitlines():
            console.print(f"  {line}")
    return 0
