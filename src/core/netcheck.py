"""Сетевые проверки перед установкой сервисов (SPEC FR-0.4).

Все функции возвращают значение и не бросают исключений: `run_list` уже
гасит сбои запуска в ShellResult, а HTTP-ошибки перехватываются явно.
Консервативная семантика при сбое проверки: считаем порт занятым
(`port_free -> False`), чтобы установка не ломала существующие сервисы.
"""

import re

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
