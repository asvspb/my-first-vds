"""Генерация секретов и атомарная запись файлов 0600 (SPEC FR-0.5).

Содержимое секретов никогда не логируется и не выводится в консоль.
"""

import os
import secrets
import string
import uuid
from pathlib import Path

_ALPHABET = string.ascii_letters + string.digits


def gen_uuid() -> str:
    """Случайный UUID4 (для VLESS id и подобных клиентских идентификаторов)."""
    return str(uuid.uuid4())


def gen_password(length: int = 24) -> str:
    """Случайный пароль из букв/digits заданной длины (криптографический ГСЧ)."""
    if length < 1:
        raise ValueError("length must be >= 1")
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def write_secret_atomic(path: str, data: str, mode: int = 0o600) -> bool:
    """Атомарно записать строку в файл с правами `mode`.

    Пишем во временный файл рядом с целевым, выставляем права, затем
    `os.replace` — при обрыве не остаётся частичного файла. True — успех,
    False — ошибка (значением, не исключением).
    """
    target = Path(path)
    tmp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
