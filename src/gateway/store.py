"""Хранилище состояния gateway: pydantic-модели + атомарный JSON (ADR-002).

Секреты клиентов (uuid/password) живут только в state.json (0600) и конфигах
протоколов; в логи и share-links попадают лишь клиентские поля по назначению.
Ошибки — через StoreError (перехватывается в CLI, выводится без traceback).
"""
import copy
import json
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from src.gateway.paths import STATE_PATH

STATE_VERSION = 1


class StoreError(Exception):
    """Ошибка хранилища: битый JSON, неизвестная версия, дубликат/отсутствие клиента."""


class ClientProfile(BaseModel):
    """Профиль клиента протокола (Xray VLESS / Hysteria2)."""

    name: str
    protocol: str
    port: int
    uuid: Optional[str] = None
    password: Optional[str] = None
    sni: Optional[str] = None
    extra: dict = Field(default_factory=dict)


class GatewayState(BaseModel):
    """Состояние gateway; формат версионируется (version=1)."""

    version: int = 1
    domain: str = ""
    clients: list[ClientProfile] = Field(default_factory=list)
    protocols: dict[str, dict] = Field(default_factory=dict)


def load_state(path: Optional[str] = None) -> GatewayState:
    """Загрузить состояние; отсутствие файла — пустое состояние (не ошибка).

    Битый JSON или неизвестная версия — StoreError с читаемым сообщением.
    """
    state_path = Path(path) if path is not None else STATE_PATH
    if not state_path.exists():
        return GatewayState()
    try:
        raw = state_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StoreError(
            f"Не удалось прочитать {state_path}: повреждённый JSON ({exc}). "
            "Восстановите файл вручную или удалите его (клиенты будут потеряны)."
        ) from exc
    if not isinstance(data, dict):
        raise StoreError(
            f"Не удалось прочитать {state_path}: ожидался JSON-объект, "
            f"получено {type(data).__name__}."
        )
    version = data.get("version")
    if version != STATE_VERSION:
        raise StoreError(
            f"Неизвестная версия состояния {version!r} в {state_path} "
            f"(поддерживается только {STATE_VERSION})."
        )
    try:
        return GatewayState.model_validate(data)
    except Exception as exc:  # pydantic ValidationError: читаемо оборачиваем
        raise StoreError(f"Некорректная структура {state_path}: {exc}") from exc


def save_state(state: GatewayState, path: Optional[str] = None) -> bool:
    """Атомарно сохранить состояние (tmp + os.replace), права 0600."""
    state_path = Path(path) if path is not None else STATE_PATH
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_name(state_path.name + ".tmp")
    payload = state.model_dump_json(indent=2)
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp_path, state_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return True


def add_client(state: GatewayState, profile: ClientProfile) -> GatewayState:
    """Чистая функция: вернуть новое состояние с добавленным клиентом.

    Дубликат имени — StoreError, исходное состояние не меняется.
    """
    if any(c.name == profile.name for c in state.clients):
        raise StoreError(f"Клиент с именем '{profile.name}' уже существует.")
    new_state = copy.deepcopy(state)
    new_state.clients.append(profile)
    return new_state


def remove_client(state: GatewayState, name: str) -> GatewayState:
    """Чистая функция: вернуть новое состояние без клиента `name`.

    Несуществующий клиент — StoreError, исходное состояние не меняется.
    """
    if not any(c.name == name for c in state.clients):
        raise StoreError(f"Клиент с именем '{name}' не найден.")
    new_state = copy.deepcopy(state)
    new_state.clients = [c for c in new_state.clients if c.name != name]
    return new_state
