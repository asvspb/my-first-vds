"""Port hopping Hysteria2 (SPEC-20261112 WP-1, ADR-008).

Механизм: именованная цепочка nat-таблицы `VDS_HY2_HOP` с одним правилом
`-p udp --dport <start>:<end> -j REDIRECT --to-ports 443` + jump из
PREROUTING. Nat-правило срабатывает до UFW-фильтрации, поэтому дополнительно
открывается ровно одно UFW-правило на диапазон. Персистентность (ребут):
идемпотентный apply-скрипт `/usr/local/sbin/vds-hy2-hop-apply.sh` (0755, без
секретов) + oneshot-юнит из шаблона `systemd/vds-hysteria2-hop.service.tpl`.

Живой udp/443 не прерывается ни на одном шаге — правило только добавляет
путь. Клиент получает `mport=<range>` в share-link (стандартный параметр
hysteria2/sing-box). Все shell-вызовы — через run_list; мутации — dry-run по
умолчанию, применение — `--apply`.
"""

import os
from pathlib import Path

from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit
from src.gateway.paths import (
    HYSTERIA2_HOP_CHAIN,
    HYSTERIA2_HOP_SCRIPT,
    HYSTERIA2_HOP_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

LOCK_FILE = "/var/run/vds-hy2-hop.lock"
# ADR-008 §4: ширина диапазона 1..1000 портов; значения по умолчанию нет —
# диапазон всегда явный аргумент.
MAX_RANGE_WIDTH = 1000
LISTEN_PORT = 443  # слушающий порт Hysteria2 (REDIRECT --to-ports)


class HopError(Exception):
    """Сбой настройки port hopping (диапазон, файрвол, юнит)."""


def parse_port_range(raw: str) -> tuple[int, int]:
    """'20000-20500' -> (20000, 20500).

    ValueError: мусорный формат, start >= end, ширина > 1000 портов
    (ADR-008 §4), порт вне 1024-65535.
    """
    parts = raw.strip().split("-")
    if len(parts) != 2 or not all(p.strip().isdigit() for p in parts):
        raise ValueError(
            f"Некорректный диапазон {raw!r}: ожидался формат START-END "
            "(например, 20000-20500)."
        )
    start, end = int(parts[0]), int(parts[1])
    if not (1024 <= start <= 65535) or not (1024 <= end <= 65535):
        raise ValueError(
            f"Порты диапазона {raw!r} должны быть в 1024-65535."
        )
    if start >= end:
        raise ValueError(
            f"Начало диапазона ({start}) должно быть меньше конца ({end})."
        )
    if end - start + 1 > MAX_RANGE_WIDTH:
        raise ValueError(
            f"Диапазон {raw!r} шире {MAX_RANGE_WIDTH} портов — уменьшите "
            "(защита от случайного «открыть всё», ADR-008)."
        )
    return start, end


def render_hop_script(start: int, end: int, listen_port: int, chain: str) -> str:
    """Идемпотентный sh apply-скрипт (ADR-008): -N цепочки (если нет),
    -C||-A правило и jump. Без секретов; детерминирован (золотой тест).
    """
    return (
        "#!/bin/sh\n"
        "# VDS Hysteria2 port hopping (ADR-008). Артефакт команды\n"
        "# `vds hysteria2 add-hop-ports` — перегенерируется, руками не править.\n"
        "set -eu\n"
        f"iptables -t nat -N {chain} 2>/dev/null || true\n"
        f"iptables -t nat -C {chain} -p udp --dport {start}:{end} "
        f"-j REDIRECT --to-ports {listen_port} 2>/dev/null || \\\n"
        f"  iptables -t nat -A {chain} -p udp --dport {start}:{end} "
        f"-j REDIRECT --to-ports {listen_port}\n"
        f"iptables -t nat -C PREROUTING -j {chain} 2>/dev/null || \\\n"
        f"  iptables -t nat -A PREROUTING -j {chain}\n"
    )


def _rule_check_args(start: int, end: int) -> list[str]:
    return [
        "iptables", "-t", "nat", "-C", HYSTERIA2_HOP_CHAIN,
        "-p", "udp", "--dport", f"{start}:{end}",
        "-j", "REDIRECT", "--to-ports", str(LISTEN_PORT),
    ]


def _rule_add_args(start: int, end: int) -> list[str]:
    return [
        "iptables", "-t", "nat", "-A", HYSTERIA2_HOP_CHAIN,
        "-p", "udp", "--dport", f"{start}:{end}",
        "-j", "REDIRECT", "--to-ports", str(LISTEN_PORT),
    ]


def _jump_check_args() -> list[str]:
    return ["iptables", "-t", "nat", "-C", "PREROUTING", "-j", HYSTERIA2_HOP_CHAIN]


def _jump_add_args() -> list[str]:
    return ["iptables", "-t", "nat", "-A", "PREROUTING", "-j", HYSTERIA2_HOP_CHAIN]


def _range_ports_listening(start: int, end: int, listen_port: int) -> list[int]:
    """Порты диапазона, слушаемые кем-либо, кроме listen_port (один вызов ss).

    Сбой ss — консервативно считаем ВЕСЬ диапазон занятым (как port_free).
    """
    result = run_list(["ss", "-Hlunp"], timeout=5)
    if not result.ok:
        return list(range(start, end + 1))
    busy: list[int] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        port_str = parts[3].rsplit(":", 1)[-1]
        if not port_str.isdigit():
            continue
        port = int(port_str)
        if start <= port <= end and port != listen_port:
            busy.append(port)
    return sorted(set(busy))


def _hysteria2_installed(state) -> bool:
    meta = state.protocols.get("hysteria2") or {}
    return bool(meta.get("installed"))


def _write_hop_script(content: str) -> bool:
    """Атомарно записать apply-скрипт с правами 0755."""
    target = Path(HYSTERIA2_HOP_SCRIPT)
    tmp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, 0o755)
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def add_hop_ports(
    raw_range: str,
    apply: bool = False,
    state_path: str | None = None,
) -> int:
    """Настроить port hopping на диапазон. 0 — успех (в т.ч. «уже настроено»).

    Поток: root -> hysteria2 установлен -> parse_port_range -> порты диапазона
    свободны/равны listen (ss) -> план [цепочка, jump, UFW allow, скрипт+юнит]
    -> dry-run по умолчанию; apply — немедленное применение тех же команд.
    Идемпотентно: тот же диапазон в state + правило и jump на месте -> exit 0.
    """
    if os.geteuid() != 0:
        console.print("[error][hysteria2-hop] Требуется root (запустите через sudo).[/error]")
        return 1

    try:
        start, end = parse_port_range(raw_range)
    except ValueError as exc:
        console.print(f"[error][hysteria2-hop] {exc}[/error]")
        return 1

    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][hysteria2-hop] {exc}[/error]")
        return 1
    if not _hysteria2_installed(state):
        console.print(
            "[error][hysteria2-hop] Hysteria2 не установлен — сначала "
            "`vds hysteria2 install`.[/error]"
        )
        return 1

    port_range = f"{start}-{end}"
    with FileLock(LOCK_FILE):
        # Идемпотентность: правило и jump уже на месте и диапазон совпадает.
        rule_ok = run_list(_rule_check_args(start, end), timeout=10).ok
        jump_ok = run_list(_jump_check_args(), timeout=10).ok
        meta = state.protocols.get("hysteria2") or {}
        if rule_ok and jump_ok and meta.get("hop_ports") == port_range:
            console.print(
                f"[success][hysteria2-hop] Port hopping {port_range} уже "
                "настроен — изменений не требуется (идемпотентно).[/success]"
            )
            return 0

        busy = _range_ports_listening(start, end, LISTEN_PORT)
        if busy:
            preview = ", ".join(str(p) for p in busy[:5])
            suffix = " …" if len(busy) > 5 else ""
            console.print(
                f"[error][hysteria2-hop] Порты диапазона заняты (кроме "
                f"{LISTEN_PORT}/udp): {preview}{suffix}. Освободите или "
                "выберите другой диапазон.[/error]"
            )
            return 1

        plan = [
            f"цепочка nat/{HYSTERIA2_HOP_CHAIN} + правило REDIRECT "
            f"{port_range}/udp -> {LISTEN_PORT} (iptables)",
            f"jump PREROUTING -> {HYSTERIA2_HOP_CHAIN}",
            f"ufw allow {start}:{end}/udp",
            f"apply-скрипт {HYSTERIA2_HOP_SCRIPT} (0755)",
            f"oneshot-юнит {HYSTERIA2_HOP_UNIT} (переживает ребут)",
            f"state.protocols['hysteria2']['hop_ports'] = '{port_range}'",
        ]
        console.print(f"[warning][hysteria2-hop] План port hopping {port_range} (dry-run):[/warning]")
        for item in plan:
            console.print(f"  - {item}")
        if not apply:
            console.print(
                "[info]Это dry-run. Для применения: "
                f"`vds hysteria2 add-hop-ports {port_range} --apply`[/info]"
            )
            return 0

        if not rule_ok:
            # -N терпит уже существующую цепочку (rc!=0 «exists») — это не ошибка.
            chain_res = run_list(
                ["iptables", "-t", "nat", "-N", HYSTERIA2_HOP_CHAIN], timeout=10
            )
            if not chain_res.ok and "already exists" not in chain_res.stderr:
                console.print(
                    f"[error][hysteria2-hop] Не удалось создать цепочку "
                    f"{HYSTERIA2_HOP_CHAIN}: {chain_res.stderr.strip()}[/error]"
                )
                return 1
            add_res = run_list(_rule_add_args(start, end), timeout=10)
            if not add_res.ok:
                console.print(
                    f"[error][hysteria2-hop] Не удалось добавить REDIRECT-правило: "
                    f"{add_res.stderr.strip()}[/error]"
                )
                return 1
        if not jump_ok:
            jump_res = run_list(_jump_add_args(), timeout=10)
            if not jump_res.ok:
                console.print(
                    f"[error][hysteria2-hop] Не удалось добавить jump из "
                    f"PREROUTING: {jump_res.stderr.strip()}[/error]"
                )
                return 1

        ufw = run_list(["ufw", "allow", f"{start}:{end}/udp"], timeout=15)
        if not ufw.ok:
            console.print(
                f"[error][hysteria2-hop] ufw allow {start}:{end}/udp не удался: "
                f"{ufw.stderr.strip() or ufw.stdout.strip()} — откройте диапазон "
                "вручную.[/error]"
            )
            return 1

        script = render_hop_script(start, end, LISTEN_PORT, HYSTERIA2_HOP_CHAIN)
        if not _write_hop_script(script):
            console.print(
                f"[error][hysteria2-hop] Не удалось записать {HYSTERIA2_HOP_SCRIPT}.[/error]"
            )
            return 1

        if not install_unit(
            "vds-hysteria2-hop.service.tpl",
            HYSTERIA2_HOP_UNIT,
            ctx={"hop_script": str(HYSTERIA2_HOP_SCRIPT)},
        ):
            console.print(
                f"[error][hysteria2-hop] Не удалось установить юнит "
                f"{HYSTERIA2_HOP_UNIT}.[/error]"
            )
            return 1

        state.protocols["hysteria2"]["hop_ports"] = port_range
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][hysteria2-hop] Правила применены, но состояние не "
                f"сохранено: {exc}[/error]"
            )
            return 1

    console.print(
        f"[success][hysteria2-hop] Port hopping {port_range}/udp -> "
        f"{LISTEN_PORT} настроен: цепочка {HYSTERIA2_HOP_CHAIN}, UFW allow, "
        f"юнит {HYSTERIA2_HOP_UNIT}. Канал udp/{LISTEN_PORT} не прерывался.[/success]"
    )
    console.print(
        "[info][hysteria2-hop] Новые ссылки клиентов получат mport="
        f"{port_range} (`vds hysteria2 add-client NAME`).[/info]"
    )
    return 0


def remove_hop_ports(apply: bool = False, state_path: str | None = None) -> int:
    """Снять port hopping (jump + цепочка + UFW + юнит + скрипт + state).

    Dry-run по умолчанию; нечего снимать (нет state-записи, правила нет) —
    exit 0. Живой udp/443 не затрагивается (ADR-008 «Как откатить»).
    """
    if os.geteuid() != 0:
        console.print("[error][hysteria2-hop] Требуется root (запустите через sudo).[/error]")
        return 1

    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][hysteria2-hop] {exc}[/error]")
        return 1

    meta = state.protocols.get("hysteria2") or {}
    port_range = str(meta.get("hop_ports") or "")
    rule_present = False
    jump_present = False
    if port_range:
        try:
            start, end = parse_port_range(port_range)
        except ValueError:
            start, end = 0, 0
        if start:
            rule_present = run_list(_rule_check_args(start, end), timeout=10).ok
            jump_present = run_list(_jump_check_args(), timeout=10).ok

    if not port_range and not rule_present and not jump_present:
        console.print("[info][hysteria2-hop] Port hopping не настроен — нечего снимать.[/info]")
        return 0

    plan = [
        f"iptables -t nat -D PREROUTING -j {HYSTERIA2_HOP_CHAIN}",
        f"iptables -t nat -F {HYSTERIA2_HOP_CHAIN} && iptables -t nat -X {HYSTERIA2_HOP_CHAIN}",
    ]
    if port_range:
        start, end = parse_port_range(port_range)
        plan.append(f"ufw delete allow {start}:{end}/udp")
    plan.append(f"systemctl stop/disable + удаление юнита {HYSTERIA2_HOP_UNIT}")
    plan.append(f"удаление apply-скрипта {HYSTERIA2_HOP_SCRIPT}")
    plan.append("state.protocols['hysteria2'].hop_ports = null")
    plan.append("(живой udp/443 не затрагивается)")

    console.print("[warning][hysteria2-hop] План снятия port hopping (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: `vds hysteria2 remove-hop-ports --apply`[/info]"
        )
        return 0

    with FileLock(LOCK_FILE):
        run_list(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", HYSTERIA2_HOP_CHAIN], timeout=10)
        run_list(["iptables", "-t", "nat", "-F", HYSTERIA2_HOP_CHAIN], timeout=10)
        run_list(["iptables", "-t", "nat", "-X", HYSTERIA2_HOP_CHAIN], timeout=10)
        if port_range:
            start, end = parse_port_range(port_range)
            run_list(["ufw", "delete", "allow", f"{start}:{end}/udp"], timeout=15)
        if not remove_unit(HYSTERIA2_HOP_UNIT):
            console.print(
                f"[warning][hysteria2-hop] Не удалось снять юнит "
                f"{HYSTERIA2_HOP_UNIT} — снимите вручную.[/warning]"
            )
        try:
            Path(HYSTERIA2_HOP_SCRIPT).unlink(missing_ok=True)
        except OSError as exc:
            console.print(
                f"[warning][hysteria2-hop] Не удалось удалить "
                f"{HYSTERIA2_HOP_SCRIPT}: {exc}[/warning]"
            )
        try:
            state = load_state(state_path)
            if "hysteria2" in state.protocols:
                state.protocols["hysteria2"].pop("hop_ports", None)
                save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][hysteria2-hop] Правила сняты, но состояние не "
                f"сохранено: {exc}[/error]"
            )
            return 1

    console.print(
        "[change][hysteria2-hop] Port hopping снят: цепочка удалена, UFW-правило "
        "и юнит убраны; udp/443 не затронут.[/change]"
    )
    return 0
