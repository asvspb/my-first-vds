"""Пути и имена DMS-пинга (SPEC-20261124-quiet-exit §5).

Все пути фиксируются здесь и только здесь. Секрет — единственный носитель
`/etc/vds/dms.env` (0600, root): `DMS_PING_URL` + роль узла. Отдельного
state-файла нет — DMS stateless (Healthchecks сам считает просрочку).
"""
from pathlib import Path

# Конфигурация (единственное место с секретом, 0600).
DMS_ENV_PATH = "/etc/vds/dms.env"

# Лок тика пинга (oneshot может пересечься при зависшей сети).
DMS_LOCK_FILE = "/var/run/vds-dms-ping.lock"

# systemd-юниты (шаблоны `systemd/vds-dms-ping.{service,timer}.tpl`).
DMS_UNIT = "vds-dms-ping.service"
DMS_TIMER = "vds-dms-ping.timer"

# Путь к конфигу как Path (для тестового префикса root).
DMS_ENV = Path(DMS_ENV_PATH)
