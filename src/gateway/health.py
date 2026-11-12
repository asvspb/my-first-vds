"""Healthcheck gateway: юниты, порты, срок сертификата (GR-18/GR-12, W1).

`vds gateway healthcheck` — страховка от тихих сбоев: сбой юнита или истекающий
сертификат замечаются таймером, а не вручную. Чек-лист:

- юниты по state.protocols (vds-xray, vds-hysteria2, vds-hysteria2-obfs —
  опционален: попадает в проверку только если установлен по state);
- занятость портов, соответствующих установленным протоколам (443/tcp для
  xray, 8443/tcp для xhttp, порт xray-cdn, 443/udp для hysteria2, порт obfs);
- упавший юнит — рестарт с rate-limit (максимум MAX_RESTARTS_PER_HOUR за час
  на юнит, паттерн vds-watchdog: файл меток времени, окно 1 час);
- срок LE-сертификата (GR-12): <14 дней — warning, <7 — error.

Семантика exit-кодов:
- ручной режим (по умолчанию): rc 1, если есть error-level находка, иначе 0;
- `--unit` (из systemd-таймера): rc 0 всегда, кроме катастрофы (state.json
  не читается) — таймер не должен «роняться» находками, которые сам же чинит.

Сam healthcheck read-only, кроме рестарта упавшего юнита (rate-limited).
Все shell-вызовы — run_list; мутации — под FileLock. Секретов не касается.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Literal, Optional

from src.core.lock import FileLock, LockError
from src.core.logger import console
from src.core.shell import run_list
from src.core.units import unit_active
from src.gateway.paths import (
    CDN_ORIGIN_PORT_DEFAULT,
    HYSTERIA2_OBFS_PORT_DEFAULT,
    HYSTERIA2_OBFS_UNIT,
    HYSTERIA2_UNIT,
    XHTTP_INTERNAL_PORT,
    XRAY_UNIT,
)
from src.gateway.store import GatewayState, StoreError, load_state

# systemd-юниты healthcheck-таймера (шаблоны systemd/vds-gateway-health.*.tpl).
HEALTH_SERVICE_UNIT = "vds-gateway-health.service"
HEALTH_TIMER_UNIT = "vds-gateway-health.timer"

LOCK_FILE = "/var/run/vds-gateway-health.lock"

# Rate-limit рестартов: паттерн vds-watchdog (файл меток, окно 1 час).
STATE_DIR = "/var/lib/vds"
RESTART_STATE_FILE = os.path.join(STATE_DIR, "gateway-health-restarts")
MAX_RESTARTS_PER_HOUR = 3

# Grace после рестарта перед port-чеком (демон должен успеть bind'нуть порт).
PORT_GRACE_SECONDS = 3

# GR-12: пороги срока сертификата (дней до истечения).
CERT_WARN_DAYS = 14
CERT_ERROR_DAYS = 7

Level = Literal["ok", "change", "warning", "error"]


@dataclass
class Finding:
    """Одна находка healthcheck: уровень + текст (без секретов)."""

    level: Level
    text: str


@dataclass
class UnitCheck:
    """Юнит и порты, которые он обязан слушать (по state.protocols)."""

    unit: str
    label: str
    ports: list[tuple[int, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Чистые функции (легко тестируются)
# ---------------------------------------------------------------------------

def collect_targets(state: GatewayState) -> list[UnitCheck]:
    """Собрать юниты/порты по установленным протоколам (не хардкод вслепую).

    hysteria2-obfs опционален — попадает в список только при
    protocols['hysteria2-obfs'].installed. xhttp и xray-cdn — инбаунды внутри
    процесса vds-xray, их порты добавляются к юниту vds-xray.
    """
    targets: list[UnitCheck] = []

    xray_meta = state.protocols.get("xray") or {}
    if xray_meta.get("installed"):
        ports = [(int(xray_meta.get("port") or 443), "tcp")]
        if (state.protocols.get("xhttp") or {}).get("installed"):
            ports.append((XHTTP_INTERNAL_PORT, "tcp"))
        cdn_meta = state.protocols.get("xray-cdn") or {}
        if cdn_meta.get("installed"):
            ports.append((int(cdn_meta.get("port") or CDN_ORIGIN_PORT_DEFAULT), "tcp"))
        targets.append(UnitCheck(unit=XRAY_UNIT, label="xray", ports=ports))

    hy2_meta = state.protocols.get("hysteria2") or {}
    if hy2_meta.get("installed"):
        targets.append(
            UnitCheck(
                unit=HYSTERIA2_UNIT,
                label="hysteria2",
                ports=[(int(hy2_meta.get("port") or 443), "udp")],
            )
        )

    obfs_meta = state.protocols.get("hysteria2-obfs") or {}
    if obfs_meta.get("installed"):
        targets.append(
            UnitCheck(
                unit=HYSTERIA2_OBFS_UNIT,
                label="hysteria2-obfs",
                ports=[(int(obfs_meta.get("port") or HYSTERIA2_OBFS_PORT_DEFAULT), "udp")],
            )
        )

    return targets


def classify_cert_days(days_left: Optional[int]) -> tuple[Level, str]:
    """GR-12: классифицировать срок сертификата. None — не прочитался."""
    if days_left is None:
        return "warning", "не удалось прочитать срок сертификата (openssl)"
    if days_left < CERT_ERROR_DAYS:
        return "error", f"сертификат истекает через {days_left} дн. (<{CERT_ERROR_DAYS})"
    if days_left < CERT_WARN_DAYS:
        return "warning", f"сертификат истекает через {days_left} дн. (<{CERT_WARN_DAYS})"
    return "ok", f"сертификат: {days_left} дн. до истечения"


# ---------------------------------------------------------------------------
# Rate-limit рестартов (паттерн vds-watchdog: метки времени в файле, окно 1ч)
# ---------------------------------------------------------------------------

class RestartRateLimiter:
    """Лимит рестартов на юнит: MAX_RESTARTS_PER_HOUR за скользящий час.

    Файл-состояние: строки `<YYYY-MM-DD HH:MM:SS> <unit>` (0600, каталог 0700,
    как zt-watchdog). `now` инъектируется для тестов. Ошибки чтения/записи
    файла трактуются консервативно: читать не можем — считаем 0 (позволяем
    рестарт), записать не можем — рестарт всё равно выполняется.
    """

    def __init__(
        self,
        state_file: str = RESTART_STATE_FILE,
        max_restarts: int = MAX_RESTARTS_PER_HOUR,
        window: timedelta = timedelta(hours=1),
        now: Callable[[], datetime] = datetime.now,
    ) -> None:
        self._state_file = state_file
        self.max_restarts = max_restarts
        self._window = window
        self._now = now

    def _entries(self) -> list[tuple[datetime, str]]:
        cutoff = self._now() - self._window
        entries: list[tuple[datetime, str]] = []
        if not os.path.isfile(self._state_file):
            return entries
        try:
            with open(self._state_file, encoding="utf-8") as fh:
                for line in fh:
                    parts = line.strip().rsplit(" ", 1)
                    if len(parts) != 2:
                        continue
                    try:
                        ts = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue
                    if ts >= cutoff:
                        entries.append((ts, parts[1]))
        except OSError:
            return []
        return entries

    def recent_count(self, unit: str) -> int:
        """Рестартов юнита за последнее окно."""
        return sum(1 for _, entry_unit in self._entries() if entry_unit == unit)

    def allow(self, unit: str) -> bool:
        """Не превышен ли лимит для юнита."""
        return self.recent_count(unit) < self.max_restarts

    def record(self, unit: str) -> None:
        """Записать метку рестарта (с очисткой устаревших записей)."""
        now = self._now()
        entries = self._entries()
        entries.append((now, unit))
        try:
            os.makedirs(os.path.dirname(self._state_file) or ".", mode=0o700, exist_ok=True)
            payload = "\n".join(
                f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {u}" for ts, u in entries
            ) + "\n"
            fd = os.open(self._state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
        except OSError:
            # Не записали метку — рестарт выполняется, лимит считаем по тому,
            # что удалось прочитать. Тихих падений healthcheck из-за этого нет.
            return


# ---------------------------------------------------------------------------
# Проверки (каждая возвращает находки, не бросает исключений)
# ---------------------------------------------------------------------------

def port_listening(port: int, proto: str) -> Optional[bool]:
    """Слушается ли порт (`ss -Hl<tcp|udp>np`). None — проверить не удалось.

    Отличается от netcheck.port_free (консервативной «занят» при сбое ss):
    healthcheck должен отличать «порт свободен» от «инструмент сломался».
    """
    if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
        return None
    result = run_list(["ss", f"-Hl{proto[0]}np"], timeout=5)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        port_str = parts[3].rsplit(":", 1)[-1]
        if port_str.isdigit() and int(port_str) == port:
            return True
    return False


def check_units(
    state: GatewayState,
    limiter: RestartRateLimiter,
    restart: bool = True,
) -> list[Finding]:
    """Юниты по state: активен ли; упавший — рестарт с rate-limit."""
    findings: list[Finding] = []
    can_restart = restart and os.geteuid() == 0
    for target in collect_targets(state):
        if unit_active(target.unit):
            findings.append(Finding("ok", f"{target.unit}: активен"))
            continue
        if not can_restart:
            findings.append(
                Finding("error", f"{target.unit}: не активен (рестарт требует root)")
            )
            continue
        recent = limiter.recent_count(target.unit)
        if not limiter.allow(target.unit):
            findings.append(
                Finding(
                    "error",
                    f"{target.unit}: не активен, рестарт заблокирован rate-limit "
                    f"({recent}/{limiter.max_restarts} за час)",
                )
            )
            continue
        restart_res = run_list(["systemctl", "restart", target.unit], timeout=30)
        if restart_res.ok:
            limiter.record(target.unit)
            if unit_active(target.unit):
                findings.append(
                    Finding(
                        "change",
                        f"{target.unit}: не был активен — перезапущен "
                        f"(рестарт {recent + 1}/{limiter.max_restarts} за час)",
                    )
                )
            else:
                findings.append(
                    Finding("error", f"{target.unit}: рестарт выполнен, но юнит не активен")
                )
        else:
            findings.append(
                Finding(
                    "error",
                    f"{target.unit}: рестарт не удался: "
                    f"{restart_res.stderr.strip() or restart_res.stdout.strip()}",
                )
            )
    return findings


def check_ports(state: GatewayState) -> list[Finding]:
    """Порты установленных протоколов: слушаются ли (read-only диагностика)."""
    findings: list[Finding] = []
    for target in collect_targets(state):
        for port, proto in target.ports:
            listening = port_listening(port, proto)
            if listening is True:
                findings.append(Finding("ok", f"порт {port}/{proto}: слушается"))
            elif listening is None:
                findings.append(
                    Finding("warning", f"порт {port}/{proto}: проверить не удалось (ss)")
                )
            else:
                findings.append(
                    Finding("error", f"порт {port}/{proto} не слушается ({target.label})")
                )
    return findings


def check_cert(state: GatewayState) -> list[Finding]:
    """GR-12: срок LE-сертификата по protocols['acme'].cert_path."""
    acme_meta = state.protocols.get("acme") or {}
    if not acme_meta.get("installed"):
        return []
    cert_path = acme_meta.get("cert_path")
    if not cert_path:
        return [Finding("warning", "acme: в state нет cert_path — срок не проверен")]
    from src.acme.install import cert_days_left  # лениво: gateway не тянет acme

    level, text = classify_cert_days(cert_days_left(Path(cert_path)))
    return [Finding(level, text)]


# ---------------------------------------------------------------------------
# Таймер (systemd-шаблоны systemd/vds-gateway-health.*.tpl)
# ---------------------------------------------------------------------------

def install_health_timer(root: str = "/") -> bool:
    """Установить service+timer из шаблонов и запустить таймер. Идемпотентно.

    True — успех. Использует core.units.install_unit (daemon-reload + enable);
    отдельно стартует timer (enable у oneshot-сервиса смысла не имеет —
    паттерн zerotier/install.py: enable+start именно таймера).
    """
    from src.core.units import install_unit

    ctx: dict[str, str] = {}
    if not install_unit(
        "vds-gateway-health.service.tpl", HEALTH_SERVICE_UNIT, ctx, root
    ):
        return False
    if not install_unit("vds-gateway-health.timer.tpl", HEALTH_TIMER_UNIT, ctx, root):
        return False
    start_res = run_list(["systemctl", "start", HEALTH_TIMER_UNIT], timeout=15)
    if not start_res.ok:
        console.print(
            f"[error][health] Не удалось запустить {HEALTH_TIMER_UNIT}: "
            f"{start_res.stderr.strip()}[/error]"
        )
        return False
    console.print(
        f"[success][health] Таймер {HEALTH_TIMER_UNIT} установлен и запущен "
        "(healthcheck каждые 5 мин; журнал: journalctl -u "
        f"{HEALTH_SERVICE_UNIT}).[/success]"
    )
    return True


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def _print_findings(findings: list[Finding]) -> None:
    for item in findings:
        console.print(f"[{item.level}][health] {item.text}[/{item.level}]")


def run_healthcheck(
    state_path: Optional[str] = None,
    restart: bool = True,
    unit_mode: bool = False,
    limiter: Optional[RestartRateLimiter] = None,
) -> int:
    """Прогнать все проверки; вернуть exit-код (семантика — в докстринге модуля).

    unit_mode=True (из таймера): rc 0 всегда, кроме нечитаемого state.json.
    """
    rate = limiter or RestartRateLimiter()
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][health] {exc}[/error]")
        return 1  # катастрофа: роняем даже unit-режим

    findings: list[Finding] = []

    # Рестарты — мутация: под FileLock, чтобы таймер и ручной запуск не
    # дублировали рестарт и не гонялись за rate-limit-файлом.
    restarted = False
    if restart and os.geteuid() == 0:
        try:
            with FileLock(LOCK_FILE):
                unit_findings = check_units(state, rate, restart=True)
        except LockError:
            # Параллельный прогон (таймер + ручной): рестарты отданы ему —
            # здесь read-only проверки, чтобы unit-режим не «падал».
            console.print(
                "[warning][health] Параллельный прогон healthcheck — "
                "рестарты отданы ему, проверки без рестартов.[/warning]"
            )
            unit_findings = check_units(state, rate, restart=False)
        restarted = any(
            f.level == "change" and "перезапущен" in f.text for f in unit_findings
        )
        findings.extend(unit_findings)
    else:
        if restart:
            console.print(
                "[info][health] Не root — проверка без рестартов (см. --help).[/info]"
            )
        findings.extend(check_units(state, rate, restart=False))

    if restarted:
        # Grace: только что перезапущенный демон мог не успеть bind'нуть порт.
        time.sleep(PORT_GRACE_SECONDS)
    findings.extend(check_ports(state))
    findings.extend(check_cert(state))

    if not findings:
        console.print(
            "[warning][health] Протоколы не установлены (state пуст) — "
            "проверять нечего.[/warning]"
        )
        return 0

    _print_findings(findings)
    has_errors = any(f.level == "error" for f in findings)
    if unit_mode:
        return 0
    return 1 if has_errors else 0
