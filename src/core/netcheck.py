"""Сетевые проверки перед установкой сервисов (SPEC FR-0.4).

Все функции возвращают значение и не бросают исключений: `run_list` уже
гасит сбои запуска в ShellResult, а HTTP-ошибки перехватываются явно.
Консервативная семантика при сбое проверки: считаем порт занятым
(`port_free -> False`), чтобы установка не ломала существующие сервисы.
"""

import re
import time
from typing import Literal

import requests

from src.core.shell import ShellResult, run_list

_SS_OWNER_RE = re.compile(r'users:\(\("([^"]+)"')


def _ss(port: int, proto: str) -> ShellResult:
    """`ss -Hl<proto>np`; для невалидных аргументов — ShellResult с rc != 0."""
    if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
        return ShellResult(stdout="", stderr="invalid port or proto", returncode=-1)
    return run_list(["ss", f"-Hl{proto[0]}np"], timeout=5)


def _port_in_output(port: int, output: str) -> bool:
    """Есть ли порт среди слушающих: локальный адрес — 4-е поле (`*:443`, `[::]:443`)."""
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        port_str = parts[3].rsplit(":", 1)[-1]
        if port_str.isdigit() and int(port_str) == port:
            return True
    return False


def port_free(port: int, proto: str = "tcp") -> bool:
    """Свободен ли порт. При сбое `ss`/некорректных аргументах — False (занят)."""
    result = _ss(port, proto)
    if not result.ok:
        return False
    return not _port_in_output(port, result.stdout)


def port_owner(port: int, proto: str = "tcp") -> str | None:
    """Имя процесса-владельца порта (для сообщений об ошибке) или None."""
    result = _ss(port, proto)
    if not result.ok:
        return None
    output = result.stdout
    for line in output.splitlines():
        if not _port_in_output(port, line):
            continue
        parts = line.split()
        if len(parts) >= 6:
            match = _SS_OWNER_RE.search(parts[5])
            if match:
                return match.group(1)
    return None


def public_ip() -> str | None:
    """Публичный IP через api.ipify.org; None при любой ошибке сети."""
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        ip = response.text.strip()
        return ip or None
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Blockcheck (SPEC-20261112 WP-3): «блок нашего IP» vs «глобальная деградация»
# vs «локальная проблема». Локальная проба сравнивается с внешней
# (check-host.net); контрольный запрос на сторонний хост отличает «наш IP
# мёртв» от «у самого check-host проблемы». Клиент API изолирован в одной
# функции с None-семантикой: любой сбой → unknown, классификация не гадает.
# ---------------------------------------------------------------------------

BlockVerdict = Literal[
    "ok", "ip_block_likely", "ru_segment_block_likely",
    "global_degradation", "local_problem", "unknown",
]

# Контрольный «широко доступный» хост (example.com, RFC-постоянный IP);
# обновляется константой при устаревании.
BLOCKCHECK_CONTROL_HOST = "93.184.216.34"
CHECK_HOST_API = "https://check-host.net"
_POLL_INTERVAL = 3.0


def classify_block(
    local_tcp_ok: bool | None,
    target_external_ok: bool | None,
    control_external_ok: bool | None,
    ru_nodes_ok: int | None = None,
    ru_nodes_total: int = 0,
) -> BlockVerdict:
    """Чистая функция-классификатор (таблица истинности — в тестах).

    - target None (API молчит/timeout)            -> unknown
    - local None/False + target ok                -> local_problem
    - local falsy + target fail + control ok      -> ip_block_likely
    - local ok + control ok + target ok:
        ru_total>0 and ru_ok==0                   -> ru_segment_block_likely
        иначе                                     -> ok
    - local ok + control ok + target fail         -> ip_block_likely
    - control fail/None + target fail             -> global_degradation
    - local ok + control fail/None + target ok    -> ok (check-host
                                                     деградировал частично,
                                                     наш IP жив)
    """
    if target_external_ok is None:
        return "unknown"
    local_ok = bool(local_tcp_ok)
    target_ok = bool(target_external_ok)
    control_ok = bool(control_external_ok)

    if not local_ok and target_ok:
        return "local_problem"
    if not target_ok:
        if not control_ok:
            return "global_degradation"
        return "ip_block_likely"
    # target_ok is True
    if not local_ok:  # unreachable: покрыто выше — защита от изменений
        return "local_problem"
    if (
        ru_nodes_total > 0
        and ru_nodes_ok is not None
        and ru_nodes_ok == 0
    ):
        return "ru_segment_block_likely"
    return "ok"


def _parse_check_host_nodes(payload: dict) -> dict:
    """Агрегировать ответ check-result: {'nodes': {name: bool}, 'ru_ok': int,
    'ru_total': int, 'world_ok': int, 'world_total': int}.

    Узел без результата к моменту таймаута (null) считается не-ok; RU-узлы
    определяются по префиксу имени 'ru.'.
    """
    nodes: dict[str, bool] = {}
    ru_ok = ru_total = world_ok = world_total = 0
    for name, value in (payload or {}).items():
        ok = bool(value) and not (isinstance(value, dict) and "error" in value)
        nodes[str(name)] = ok
        if str(name).startswith("ru."):
            ru_total += 1
            ru_ok += 1 if ok else 0
        else:
            world_total += 1
            world_ok += 1 if ok else 0
    return {
        "nodes": nodes,
        "ru_ok": ru_ok,
        "ru_total": ru_total,
        "world_ok": world_ok,
        "world_total": world_total,
    }


def check_host_tcp(
    host: str,
    port: int = 443,
    timeout: float = 30.0,
    max_nodes: int = 5,
) -> dict | None:
    """check-host.net: TCP-проба host:port с внешних узлов (RU и мир).

    GET check-tcp?host=<host>:<port>&max_nodes=N (Accept: application/json)
    -> poll GET check-result/<id> (интервал 3с, до timeout) -> агрегат
    {'nodes', 'ru_ok', 'ru_total', 'world_ok', 'world_total'}.

    None при любом сбое сети/API (offline-режим): RequestException, нет
    request_id, JSON без узлов. Пассивный запрос — наружу уходит только
    host:port; node group не задаём, RU определяем по префиксу 'ru.'.
    """
    try:
        submit = requests.get(
            f"{CHECK_HOST_API}/check-tcp",
            params={"host": f"{host}:{port}", "max_nodes": str(max_nodes)},
            headers={"Accept": "application/json"},
            timeout=10,
        )
        submit.raise_for_status()
        request_id = str(submit.json().get("request_id") or "")
        if not request_id:
            return None
    except requests.RequestException:
        return None
    except ValueError:  # битый JSON
        return None

    deadline = time.monotonic() + max(timeout, _POLL_INTERVAL)
    while time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL)
        try:
            poll = requests.get(
                f"{CHECK_HOST_API}/check-result/{request_id}",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            poll.raise_for_status()
            payload = poll.json()
        except requests.RequestException:
            return None
        except ValueError:
            return None
        if not isinstance(payload, dict) or not payload:
            continue
        # check-host отдаёт {node: null} пока проба не выполнена; узлы
        # появляются постепенно — ждём либо все результаты, либо дедлайн
        # (null к дедлайну считается не-ok, см. _parse_check_host_nodes).
        if payload and all(value is not None for value in payload.values()):
            return _parse_check_host_nodes(payload)
    # Дедлайн: агрегируем то, что ответило (пусто/нет узлов — API-сбой).
    if isinstance(payload, dict) and payload:
        return _parse_check_host_nodes(payload)
    return None


def _local_tcp_probe(ip: str, port: int = 443, timeout: float = 5.0) -> bool | None:
    """Локальная проба своего публичного TCP-порта. None при сбое сокета."""
    import socket

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_blockcheck(timeout: float = 30.0) -> tuple[BlockVerdict, dict]:
    """Собрать evidences и классифицировать. Никогда не бросает исключений.

    local_tcp_ok: socket к public_ip():443 + unit_active vds-xray;
    target: check_host_tcp(public_ip()); control: check_host_tcp(<константа>).
    """
    from src.core.units import unit_active

    ip = public_ip() or ""
    local_tcp_ok: bool | None = None
    if ip:
        local_tcp_ok = _local_tcp_probe(ip, 443, timeout=min(5.0, timeout))
    unit_active_flag = unit_active("vds-xray.service")

    target = check_host_tcp(ip, 443, timeout=timeout) if ip else None
    control = check_host_tcp(BLOCKCHECK_CONTROL_HOST, 443, timeout=timeout)

    target_external_ok: bool | None = None
    if target is not None:
        total = target["ru_total"] + target["world_total"]
        target_external_ok = total > 0 and (
            target["ru_ok"] + target["world_ok"]
        ) > 0
    control_external_ok: bool | None = None
    if control is not None:
        total = control["ru_total"] + control["world_total"]
        control_external_ok = total > 0 and (
            control["ru_ok"] + control["world_ok"]
        ) > 0

    verdict = classify_block(
        local_tcp_ok=local_tcp_ok,
        target_external_ok=target_external_ok,
        control_external_ok=control_external_ok,
        ru_nodes_ok=target["ru_ok"] if target else None,
        ru_nodes_total=(target["ru_total"] if target else 0),
    )
    evidence = {
        "public_ip": ip,
        "local_tcp_ok": local_tcp_ok,
        "unit_active": unit_active_flag,
        "target": target,
        "control": control,
    }
    return verdict, evidence
