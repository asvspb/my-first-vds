"""`vds relay status` — состояние релея (SPEC-20261114-ru-relay FR-3).

Read-only сводка: юниты (awg-сервер, awg1-нога, NAT, policy, CIDR-таймер,
xray), интерфейсы awg0/awg1, живость ноги до exit (handshake-возраст из
`awg show awg1 latest-handshakes`), nft-таблица и ip rule, размер/возраст
RU-CIDR-агрегата, прослушивание 443. Парсер awg show — чистая функция
(src/relay/config.parse_awg_show), тестируется без сети. Секретов в выводе
нет: печатаются только публичные ключи (хвост) и метаданные.
"""

import time
from pathlib import Path
from typing import Optional

from src.core.logger import console
from src.core.shell import run_list
from src.core.units import unit_active
from src.relay.config import handshake_age, parse_awg_show
from src.relay.paths import (
    RELAY_CIDR_LIST,
    RELAY_CIDR_TIMER,
    RELAY_CONFIG_PATH,
    RELAY_EXIT_CONFIG_PATH,
    RELAY_EXIT_IFACE,
    RELAY_EXIT_UNIT,
    RELAY_IFACE,
    RELAY_MARK,
    RELAY_NAT_UNIT,
    RELAY_NFT_TABLE,
    RELAY_POLICY_UNIT,
    RELAY_PORT,
    RELAY_SUBNET,
    RELAY_TABLE,
    RELAY_UNIT,
)
from src.gateway.store import load_state

_UNITS = (
    (RELAY_UNIT, "AWG-сервер udp/443 (awg0)"),
    (RELAY_EXIT_UNIT, "awg1-нога до exit"),
    (RELAY_NAT_UNIT, "MASQUERADE (awg1/eth0)"),
    (RELAY_POLICY_UNIT, "policy-routing (nft/fwmark)"),
    (RELAY_CIDR_TIMER, "RU-CIDR таймер"),
)


def _iface_up(name: str) -> bool:
    return run_list(["ip", "link", "show", name], timeout=10).ok


def _exit_handshake_age() -> Optional[int]:
    """Возраст (сек) последнего handshake awg1 → exit; None — нет данных."""
    if not RELAY_EXIT_CONFIG_PATH.is_file():
        return None
    res = run_list(["awg", "show", RELAY_EXIT_IFACE, "latest-handshakes"], timeout=10)
    if not res.ok:
        return None
    peers = parse_awg_show(res.stdout)
    if not peers:
        return None
    epoch = max(p["latest_handshake"] for p in peers.values())
    return handshake_age(epoch, int(time.time()))


def _policy_ok() -> tuple[bool, bool]:
    """(ip rule fwmark на месте, nft-таблица применилась)."""
    rules = run_list(["ip", "rule", "show"], timeout=10)
    rule_ok = rules.ok and f"fwmark {RELAY_MARK} lookup {RELAY_TABLE}" in rules.stdout
    nft = run_list(["nft", "list", "table", "inet", RELAY_NFT_TABLE], timeout=10)
    return rule_ok, nft.ok


def _cidr_meta() -> tuple[str, str]:
    if not RELAY_CIDR_LIST.is_file():
        return "—", "нет файла"
    st = RELAY_CIDR_LIST.stat()
    count = sum(1 for ln in RELAY_CIDR_LIST.read_text(encoding="utf-8").splitlines() if ln.strip())
    age_h = int((time.time() - st.st_mtime) / 3600)
    return f"{count} агрегатов", f"обновлён {age_h} ч назад"


def collect_status() -> dict:
    """Машиночитаемый снимок (для --json); без секретов."""
    state = load_state()
    meta = state.protocols.get("relay", {})
    units = {name: unit_active(name) for name, _label in _UNITS}
    units["vds-xray.service"] = unit_active("vds-xray.service")
    rule_ok, nft_ok = _policy_ok()
    hs = _exit_handshake_age()
    cidr_count, cidr_age = _cidr_meta()
    udp = run_list(["ss", "-ulnp", f"sport = :{RELAY_PORT}"], timeout=10).ok
    tcp = run_list(["ss", "-tlnp", f"sport = :{RELAY_PORT}"], timeout=10).ok
    return {
        "domain": meta.get("domain", ""),
        "exit_ip": meta.get("exit_ip", ""),
        "exit_port": meta.get("exit_port", 51825),
        "units": units,
        "ifaces": {"awg0": _iface_up(RELAY_IFACE), "awg1": _iface_up(RELAY_EXIT_IFACE)},
        "exit_handshake_age_sec": hs,
        "policy": {"ip_rule": rule_ok, "nft_table": nft_ok},
        "cidr": {"count": cidr_count, "age": cidr_age},
        "listen_443": {"udp": udp, "tcp": tcp},
        "subnet": meta.get("subnet", RELAY_SUBNET),
    }


def _fmt_age(seconds: Optional[int]) -> str:
    if seconds is None:
        return "нет данных (awg1-конфиг отсутствует или нога не поднята)"
    if seconds < 0:
        return "handshake ещё не было (пир настроен, трафика нет)"
    if seconds < 180:
        return f"{seconds} с — живая"
    minutes = seconds // 60
    if minutes < 60 * 6:
        return f"{minutes} мин — в пределах PersistentKeepalive/25*3"
    hours = seconds // 3600
    return f"{hours} ч — ПОДОЗРИТЕЛЬНО: нога, вероятно, мертва/шейпится"


def run_status(json_output: bool = False, state_path: Optional[str] = None) -> int:
    """CLI-вход `vds relay status`. Exit 0 всегда (статус — не ошибка)."""
    del state_path
    snapshot = collect_status()

    if json_output:
        import json as _json

        print(_json.dumps(snapshot, ensure_ascii=False, indent=2))
        return 0

    console.print("[info][relay] ══ RU-relay status (ADR-007) ══[/info]")
    console.print(
        f"[info] Домен:[/info] {snapshot['domain'] or '—'}   "
        f"[info]Exit-нода:[/info] {snapshot['exit_ip'] or '—'}:{snapshot['exit_port']}"
    )
    for name, label in _UNITS:
        tag = "success" if snapshot["units"].get(name) else "warning"
        console.print(f"  [{tag}]{'●' if snapshot['units'].get(name) else '○'}[/] {name} — {label}")
    xray_tag = "success" if snapshot["units"].get("vds-xray.service") else "warning"
    console.print(
        f"  [{xray_tag}]{'●' if snapshot['units'].get('vds-xray.service') else '○'}[/] "
        "vds-xray.service — Reality tcp/443 (фолбэк)"
    )
    for iface, up in snapshot["ifaces"].items():
        tag = "success" if up else "warning"
        console.print(f"  [{tag}]iface {iface}: {'up' if up else 'down'}[/]")
    console.print(
        f"[info] Нога до exit (handshake):[/info] {_fmt_age(snapshot['exit_handshake_age_sec'])}"
    )
    p = snapshot["policy"]
    console.print(
        f"[info] Policy:[/info] ip rule fwmark {RELAY_MARK}→{RELAY_TABLE}: "
        f"{'есть' if p['ip_rule'] else 'НЕТ'}, nft {RELAY_NFT_TABLE}: "
        f"{'есть' if p['nft_table'] else 'НЕТ'}, "
        f"CIDR: {snapshot['cidr']['count']} ({snapshot['cidr']['age']})"
    )
    l = snapshot["listen_443"]
    console.print(
        f"[info] Слушание 443:[/info] udp {'да' if l['udp'] else 'НЕТ'} / tcp {'да' if l['tcp'] else 'НЕТ'}"
    )
    console.print(
        "[info] Проверки runbook:[/info] curl --interface awg1 ifconfig.me (должен быть "
        "IP exit-ноды); SNI-домен — мимо awg1 (tcpdump/mtr); reboot-тест — юниты и правила на месте."
    )
    return 0
