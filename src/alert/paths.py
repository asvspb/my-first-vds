"""Пути и имена сторожа (SPEC-20261117-alert-watch §3).

Все пути фиксируются здесь и только здесь. Секреты — единственный носитель
`/etc/vds/alert.env` (0600, root); состояние — `/var/lib/vds/alert-state.json`
(0600, root; пишет только сторож). `probe-watch.json` и `state.json` — только
чтение (SPEC §3.2, §9.2).
"""
from pathlib import Path

# Конфигурация каналов и параметров (единственное место с секретами, 0600).
ALERT_ENV_PATH = "/etc/vds/alert.env"

# Состояние сторожа (0600, атомарная запись, FileLock на запись).
ALERT_STATE_PATH = Path("/var/lib/vds/alert-state.json")

# Лок тика сторожа. Отдельный от `vds-probe-watch.lock`: пересечения нет.
ALERT_LOCK_FILE = "/var/run/vds-alert-watch.lock"

# systemd-юниты (шаблоны `systemd/vds-alert-watch.{service,timer}.tpl`).
ALERT_UNIT = "vds-alert-watch.service"
ALERT_TIMER = "vds-alert-watch.timer"

# Зеркало `src.gateway.probing.SNAPSHOT_PATH` (SPEC §3.2): путь дублируется
# осознанно — сторож не импортирует 2300-строчный `probing`. Дрейф ловит
# unit-тест `tests/alert/test_checks.py::test_snapshot_path_matches_probing`.
PROBE_WATCH_PATH = Path("/var/lib/vds/probe-watch.json")
