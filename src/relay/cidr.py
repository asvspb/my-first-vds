"""Обновление RU-CIDR-агрегата для policy-routing релея (ADR-007, SPEC WP-2).

Поток `python -m src.relay.cidr update` (вызывается таймером
vds-relay-cidr.timer еженедельно): загрузка ipdeny ru.zone → агрегация
(ipaddress.collapse_addresses — соседние /24 склеиваются, сет меньше) →
запись /etc/vds-relay/ru-cidrs.txt (0644, атомарно — не секрет) → рендер
nft-файла → `nft -f` (идемпотентно, таблица флушится декларацией).
Сбой загрузки — читаемый отказ (exit 1) без повреждения существующего
агрегата: старый файл остаётся на месте.

Без root/network-зависимостей на импорте — тестируется моками.
"""
import ipaddress
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

import requests

from src.core.logger import console
from src.core.shell import run_list
from src.relay.config import render_nft_policy
from src.relay.paths import (
    RELAY_CIDR_LIST,
    RELAY_CIDR_SOURCE,
    RELAY_DIR,
    RELAY_NFT_POLICY_FILE,
)


def aggregate(cidrs: Iterable[str]) -> list[str]:
    """Агрегировать список CIDR: collapse_addresses, только IPv4, строгий вывод.

    Некорректный CIDR или IPv6-элемент — ValueError (читаемо, до мутаций).
    """
    networks: list[ipaddress.IPv4Network] = []
    for item in cidrs:
        net = ipaddress.ip_network(item.strip(), strict=False)
        if net.version != 4:
            raise ValueError(f"не IPv4-CIDR: {item!r}")
        networks.append(net)
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(net) for net in sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))]


def fetch(timeout: int = 60) -> list[str]:
    """Загрузить ru.zone с ipdeny; неуспех — RuntimeError с читаемым текстом."""
    resp = requests.get(RELAY_CIDR_SOURCE, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(
            f"{RELAY_CIDR_SOURCE}: HTTP {resp.status_code} — RU-CIDR не обновлён, "
            "работаем на прежнем агрегате."
        )
    lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"{RELAY_CIDR_SOURCE}: пустой ответ — RU-CIDR не обновлён.")
    return lines


def _atomic_write_preserving_mode(path: Path, text: str, mode: int) -> None:
    """Атомарная запись не-секретного файла с фиксацией прав (паттерн amneziawg)."""
    target_mode = path.stat().st_mode & 0o777 if path.exists() else mode
    tmp = path.with_name(path.name + ".vds.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, target_mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError:
        Path(tmp).unlink(missing_ok=True)
        raise


def update(timeout: int = 60, state_path: Optional[Path] = None) -> int:
    """Обновить агрегат + nft-файл и применить (`nft -f`). 0 — успех, 1 — отказ."""
    del state_path  # зарезервировано для метаданных последнего обновления (state)
    try:
        raw = fetch(timeout=timeout)
        cidrs = aggregate(raw)
    except (RuntimeError, ValueError, requests.RequestException) as exc:
        console.print(f"[error][relay-cidr] {exc}[/error]")
        return 1

    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write_preserving_mode(RELAY_CIDR_LIST, "\n".join(cidrs) + "\n", 0o644)
    _atomic_write_preserving_mode(RELAY_NFT_POLICY_FILE, render_nft_policy(cidrs), 0o644)

    apply_res = run_list(["nft", "-f", str(RELAY_NFT_POLICY_FILE)], timeout=30)
    if not apply_res.ok:
        detail = apply_res.stderr.strip() or apply_res.stdout.strip() or f"rc={apply_res.returncode}"
        console.print(
            f"[error][relay-cidr] nft -f {RELAY_NFT_POLICY_FILE}: {detail} — "
            "файлы обновлены, таблица не применена (см. vds-relay-policy.service).[/error]"
        )
        return 1

    console.print(
        f"[success][relay-cidr] RU-CIDR обновлён: {len(cidrs)} агрегатов, "
        f"nft-таблица применена ({RELAY_NFT_POLICY_FILE}).[/success]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(update())
