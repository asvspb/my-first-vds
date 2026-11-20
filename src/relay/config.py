"""Чистые рендеры и парсеры RU-relay (SPEC-20261114-ru-relay §3).

Все функции детерминированные и без побочных эффектов: одинаковые входы дают
байт-в-байт одинаковый вывод — это контракт для unit-тестов (tests/relay).
Обфускация/ключи релея переиспользуют src/amneziawg/config.py (ADR-005,
линия 1.5). Секреты проходят через функции, но никогда не попадают в план
dry-run (build_plan) и в сообщения об ошибках.
"""
import ipaddress
from dataclasses import dataclass
from typing import Optional

from src.amneziawg.config import ServerParams, render_server_conf
from src.relay.paths import (
    RELAY_EXIT_IFACE,
    RELAY_EXIT_MTU,
    RELAY_MARK,
    RELAY_NFT_TABLE,
    RELAY_SUBNET,
    RELAY_TABLE,
)

# Метаданные шагов dry-run-плана: рендеры только составляют тексты, порядок
# шагов фиксирует build_plan (SPEC §3: CLI повторяет ранбук 1:1).


@dataclass(frozen=True)
class RelayArgs:
    """Входы `vds relay init` (CLI-флаги) — без секретов."""

    exit_ip: str  # публичный IPv4 asv1 (103.45.247.172)
    exit_port: int = 51825
    domain: str = ""  # relay.asvpersonal.ru (DNS-only, A-запись)
    sni: str = ""  # RU-сайт same-DC для Reality-фолбэка
    exit_conf: Optional[str] = None  # путь к клиентскому .conf с asv1
    mtu: int = 1280


def render_relay_server_conf(params: ServerParams, mtu: int = 1280) -> str:
    """Серверный .conf awg0 (UDP 443, подсеть 10.10.0.0/24, MTU 1280).

    Переиспользует render_server_conf (валидация 1.5-обфускации, детерминизм)
    и вставляет MTU после ListenPort — awg-quick применит MTU к awg0.
    """
    base = render_server_conf(params)
    lines = base.split("\n")
    out: list[str] = []
    for line in lines:
        out.append(line)
        if line.startswith("ListenPort = "):
            out.append(f"MTU = {mtu}")
    return "\n".join(out)


def sanitize_exit_conf(text: str, mtu: int = RELAY_EXIT_MTU) -> str:
    """Подготовить клиентский .conf с asv1 к запуску как awg1 на релее.

    Критично (SPEC §8): add-client на asv1 выдаёт AllowedIPs = 0.0.0.0/0 —
    wg-quick с настройками по умолчанию положил бы default-маршрут в main-table
    релея и отрезал бы ssh. sanitize добавляет `Table = off` (маршруты ведёт
    policy-юнит через fwmark/table 100) и фиксирует MTU. Отсутствие
    [Interface]/PrivateKey — ValueError (битый conf не запускаем).
    """
    if "[Interface]" not in text or "PrivateKey = " not in text:
        raise ValueError(
            "awg1-конфиг повреждён: нет секции [Interface] или PrivateKey — "
            "перенесите свежий конфиг с asv1 (`vds amneziawg add-client relay`)."
        )
    lines = text.split("\n")
    out: list[str] = []
    has_table = any(ln.strip().startswith("Table = ") for ln in lines)
    has_mtu = any(ln.strip().startswith("MTU = ") for ln in lines)
    for line in lines:
        out.append(line)
        if line.strip() == "Address = " or line.strip().startswith("Address = "):
            if not has_table:
                out.append("Table = off")
            if not has_mtu:
                out.append(f"MTU = {mtu}")
    return "\n".join(out)


def render_nft_policy(cidrs: list[str]) -> str:
    """nftables-файл policy-routing релея (SPEC §1.3, ADR-007 девиации).

    Таблица inet vds_relay:
    - set ru_cidr (ipv4_addr, interval) — RU-агрегат из ipdeny;
    - prerouting (mangle): трафик с awg0 на НЕ-RU dst → mark 0x1
      (policy: `ip rule fwmark 0x1 table 100` → default dev awg1);
    - nat postrouting: MASQUERADE awg1 (вся awg0-подсеть к asv1-ноге) и
      eth0 (RU-direct из awg0-подсети).
    Файл применяется целиком (`nft -f`), поэтому идемпотентен: старая
    таблица флушится декларацией `table ... { }` + правила.
    """
    v4: list[ipaddress.IPv4Network] = []
    for item in cidrs:
        net = ipaddress.ip_network(item, strict=False)
        if net.version == 4:
            v4.append(net)
    elements = ",\n        ".join(str(net) for net in v4) or ""
    return (
        f"#!/usr/sbin/nft -f\n"
        f"# RU-relay policy-routing (генерируется: python -m src.relay.cidr update)\n"
        f"# не править руками — перезаписывается еженедельным таймером\n"
        f"table inet {RELAY_NFT_TABLE}\n"
        f"flush table inet {RELAY_NFT_TABLE}\n"
        f"table inet {RELAY_NFT_TABLE} {{\n"
        f"    set ru_cidr {{\n"
        f"        type ipv4_addr\n"
        f"        flags interval\n"
        f"        elements = {{ {elements} }}\n"
        f"    }}\n"
        f"    chain prerouting {{\n"
        f"        type filter hook prerouting priority mangle; policy accept;\n"
        f"        iifname \"{RELAY_EXIT_IFACE}\" return\n"
        # ADR-016: второй носитель p2p — трафик wg-ws0 не метится (идёт своим
        # маршрутом через селектор), иначе уедет в table 100 по fwmark.
        f"        iifname \"wg-ws0\" return\n"
        f"        iifname \"awg0\" ip daddr @ru_cidr return\n"
        f"        iifname \"awg0\" ip daddr 10.10.0.0/24 return\n"
        f"        iifname \"awg0\" meta mark set {RELAY_MARK}\n"
        f"    }}\n"
        f"    chain postrouting {{\n"
        f"        type nat hook postrouting priority srcnat; policy accept;\n"
        f"        oifname \"{RELAY_EXIT_IFACE}\" ip saddr {RELAY_SUBNET} masquerade\n"
        f"        oifname \"eth0\" ip saddr {RELAY_SUBNET} masquerade\n"
        f"    }}\n"
        # ADR-016: MSS-clamp для второго носителя (WG поверх TLS/TCP/WS):
        # без него клиентские HTTPS-фреймы упираются в PMTUD-blackhole.
        f"    chain forward {{\n"
        f"        type filter hook forward priority filter; policy accept;\n"
        f"        tcp flags syn tcp option maxseg size set rt mtu\n"
        f"    }}\n"
        f"}}\n"
    )


def render_policy_rule_args() -> list[list[str]]:
    """Аргументы ip rule/ip route для policy-таблицы (проверяются юнитом).

    Возвращает две команды: ip rule fwmark→table и default dev awg1 в таблице.
    Единая точка правды для template-юнита и тестов.
    """
    return [
        ["ip", "rule", "add", "fwmark", RELAY_MARK, "table", RELAY_TABLE],
        ["ip", "route", "replace", "default", "dev", RELAY_EXIT_IFACE, "table", RELAY_TABLE],
    ]


def render_dnsmasq_proposal(
    ru_dns: str = "77.88.8.8",
    foreign_dns: str = "1.1.1.1",
    exit_iface: str = RELAY_EXIT_IFACE,
) -> str:
    """ПРЕДЛОЖЕНИЕ DNS-политики релея (REQ FR / ADR-007 девиации; исполнение — OQ).

    Заблокированные домены не должны резолвиться через RU-резолверы:
    - RU-TLD (.ru/.su/.рф) → RU-резолвер напрямую (eth0);
    - всё прочее → форвард через awg1 (`@<iface>` — source-bind, запросы
      уходят в туннель до asv1, NXDOMAIN-подмена не видна).
    Файл не устанавливается init'ом — только рендерится и показывается
    в ранбуке (dnsmasq на релее ставится руками после полевой проверки).
    """
    return (
        "# dnsmasq на релее: RU→direct, прочее→форвард через awg1 (ADR-007)\n"
        "# предложение v1 — НЕ устанавливается `vds relay init`, см. DEPLOY-RU-RELAY §DNS\n"
        "listen-address=127.0.0.1\n"
        "bind-interfaces\n"
        "no-resolv\n"
        f"server=/ru/{ru_dns}\n"
        f"server=/su/{ru_dns}\n"
        f"server=/{foreign_dns}@{exit_iface}\n"
        "cache-size=1000\n"
        "no-negcache\n"
    )


def build_plan(
    args: RelayArgs,
    checks: list[dict],
    exit_conf_ok: bool,
) -> list[dict]:
    """Dry-run план `vds relay init` (SPEC §1.5, ранбук Фаза 2 1:1).

    checks — результат preflight (список dict с ключами name/ok/detail);
    план НЕ содержит секретов и путей ключей. Порядок шагов = порядок
    исполнения --apply.
    """
    plan: list[dict] = []
    for check in checks:
        plan.append({"step": "preflight", "name": check["name"], "detail": check["detail"]})
    plan.append(
        {
            "step": "awg1-conf",
            "name": "awg1-конфиг (нога до exit)",
            "detail": (
                f"sanitize + запись {args.exit_conf} → /etc/amnezia/awg1.conf (Table = off, MTU {RELAY_EXIT_MTU})"
                if args.exit_conf
                else "не предоставлен (--exit-conf): перенесите с exit-ноды "
                "(`vds amneziawg add-client relay`) и перезапустите `vds relay init --apply --exit-conf ...`"
            ),
        }
    )
    plan.append(
        {
            "step": "xray-reality",
            "name": "Xray Reality TCP 443 (фолбэк)",
            "detail": f"src/xray install, SNI={args.sni or '(не задан)'}",
        }
    )
    plan.append(
        {
            "step": "awg-server",
            "name": "AWG-сервер UDP 443",
            "detail": f"awg0, {RELAY_SUBNET}, MTU {args.mtu}, PPA-пакеты, юнит vds-relay-awg, ufw allow 443/udp",
        }
    )
    plan.append(
        {
            "step": "ip-forward",
            "name": "ip_forward=1 (sysctl + persist)",
            "detail": "net.ipv4.ip_forward=1, /etc/sysctl.d/99-vds-relay-forward.conf",
        }
    )
    plan.append(
        {
            "step": "exit-unit",
            "name": "юнит awg1 (vds-relay-exit)",
            "detail": "awg-quick up /etc/amnezia/awg1.conf; зависит от шага awg1-conf",
        }
    )
    plan.append(
        {
            "step": "nat",
            "name": "MASQUERADE (vds-relay-nat)",
            "detail": f"{RELAY_SUBNET} → awg1 и {RELAY_SUBNET} → eth0, persist-юнит "
                "(iptables доустанавливается при отсутствии)",
        }
    )
    plan.append(
        {
            "step": "policy",
            "name": "policy-routing (vds-relay-policy)",
            "detail": (
                f"nft {RELAY_NFT_TABLE}: set ru_cidr + mark {RELAY_MARK}; "
                f"ip rule fwmark {RELAY_MARK} table {RELAY_TABLE}; "
                f"table {RELAY_TABLE}: default dev {RELAY_EXIT_IFACE}"
            ),
        }
    )
    plan.append(
        {
            "step": "cidr",
            "name": "RU-CIDR обновление + таймер",
            "detail": "ipdeny ru.zone → агрегат → /etc/vds-relay/ru-cidrs.txt; vds-relay-cidr.timer (еженедельно)",
        }
    )
    plan.append(
        {
            "step": "state",
            "name": "метаданные в gateway store",
            "detail": "protocols['relay'] (public_key/обфускация; приватных ключей нет)",
        }
    )
    plan.append(
        {
            "step": "verify",
            "name": "проверки (runbook DEPLOY-RU-RELAY)",
            "detail": (
                "curl --interface awg1 ifconfig.me == exit-IP; SNI-домен мимо awg1; "
                f"awg0 handshake клиентов; endpoint {args.domain or 'relay-домен'}:443"
                + ("" if exit_conf_ok else "; ВНИМАНИЕ: awg1-конфиг ещё не перенесён — нога не проверяется")
            ),
        }
    )
    return plan


def parse_awg_show(text: str) -> dict[str, dict]:
    """Парсер `awg show <iface> latest-handshakes` (строки "<pubkey> <epoch>").

    Публичный ключ — идентификатор пира, не секрет (маскировать не нужно;
    приватных ключей в выводе нет по определению). Пустой/битый вывод → {}.
    """
    peers: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0] == "peer":
            continue
        try:
            epoch = int(parts[-1])
        except ValueError:
            continue
        peers[parts[0]] = {"latest_handshake": epoch}
    return peers


def handshake_age(epoch: int, now: int) -> int:
    """Возраст последнего handshake в секундах; 0-эпоха (нет handshake) → -1."""
    if epoch <= 0:
        return -1
    return max(0, now - epoch)
