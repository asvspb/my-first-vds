"""Схема `/etc/vds/dms.env` (SPEC-20261124-quiet-exit §5).

Формат `KEY=VALUE` — разбирается `core.shell.load_env` (свой парсер не пишем).
Запись — `core.secrets.write_secret_atomic` (mode 0600) из `cli.py`.

Инвариант: **`DMS_PING_URL` не печатается нигде** — ни в stdout, ни в journal,
ни в `status --json`. Единственный путь показа конфига —
`render_env(with_secrets=False)`, где URL заменён маской (как в `src/alert/env.py`).
"""
from __future__ import annotations

from dataclasses import dataclass

from src.core.shell import load_env
from src.dms.paths import DMS_ENV_PATH

# Маска вместо значения секрета (`render_env(with_secrets=False)` и status).
SECRET_MASK = "***"

# Допустимые роли узла: exit — exit-сервер, relay — RU-релей (ADR-007).
ROLE_EXIT = "exit"
ROLE_RELAY = "relay"
ROLES = (ROLE_EXIT, ROLE_RELAY)


@dataclass(frozen=True)
class DmsConfig:
    """Параметры DMS. `ping_url` — секрет, наружу только через маску."""

    ping_url: str = ""
    role: str = ""
    exit_host: str = ""


def load_config(path: str = DMS_ENV_PATH) -> DmsConfig:
    """Прочитать `dms.env`; отсутствие файла — дефолты (пустой конфиг)."""
    env = load_env(path)
    role = (env.get("DMS_ROLE") or "").strip().lower()
    if role not in ROLES:
        role = ""
    return DmsConfig(
        ping_url=(env.get("DMS_PING_URL") or "").strip(),
        role=role,
        exit_host=(env.get("DMS_EXIT_HOST") or "").strip(),
    )


def role_valid(cfg: DmsConfig) -> bool:
    return cfg.role in ROLES


def url_configured(cfg: DmsConfig) -> bool:
    return bool(cfg.ping_url)


def mask_url(cfg: DmsConfig) -> str:
    """URL наружу — только маской; пустой конфиг — пустая строка."""
    return SECRET_MASK if cfg.ping_url else ""


def config_warnings(cfg: DmsConfig) -> list[str]:
    """Человекочитаемые предупреждения о неполной конфигурации (без URL)."""
    warnings: list[str] = []
    if not cfg.ping_url:
        warnings.append("нет DMS_PING_URL — заполните /etc/vds/dms.env")
    if not cfg.role:
        warnings.append("нет DMS_ROLE (exit|relay) — gate не определён")
    elif not role_valid(cfg):
        warnings.append(f"DMS_ROLE={cfg.role} — ожидался exit|relay")
    return warnings


def render_env(cfg: DmsConfig, *, with_secrets: bool) -> str:
    """Отрендерить содержимое `dms.env`.

    `with_secrets=False` — единственный допустимый путь для показа конфига:
    `DMS_PING_URL` выводится маской (или пусто, если не задан).
    """
    url = ""
    if cfg.ping_url:
        url = cfg.ping_url if with_secrets else SECRET_MASK
    lines = [
        "# vds dms — dead-man-switch (P37, SPEC-20261124-quiet-exit §5). 0600.",
        "# Заполните DMS_PING_URL (уникальный URL Healthchecks). Значения не печатать.",
        f"DMS_PING_URL={url}",
        f"DMS_ROLE={cfg.role}",
        f"DMS_EXIT_HOST={cfg.exit_host}",
        "",
    ]
    return "\n".join(lines)
