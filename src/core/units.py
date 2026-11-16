"""Установка/проверка/удаление systemd-юнитов из шаблонов `systemd/` (SPEC FR-0.6).

Все shell-вызовы — через `core.shell.run_list`. Параметр `root` (по умолчанию
"/") задаёт префикс файловой системы: в тестах это tmp-каталог, файлы
кладутся в `<root>/etc/systemd/system/`, а systemctl-вызовы мокаются.

Мутирующие операции под `FileLock`; при `root != "/"` (тестовый префикс)
блокировка не берётся.
"""

import os
import shutil
import sys
from pathlib import Path

from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import run_list

# systemd/ — каталог шаблонов в корне репозитория (src/core/units.py -> ../../systemd)
SYSTEMD_DIR = Path(__file__).resolve().parents[2] / "systemd"

LOCK_FILE = "/var/run/vds-units.lock"


def _unit_path(name: str, root: str) -> Path:
    return Path(root) / "etc" / "systemd" / "system" / name


def resolve_python(install_dir: str | None = None) -> str:
    """Интерпретатор для `{python}` в systemd-шаблонах.

    Порядок: venv внутри INSTALL_DIR → текущий `sys.executable` → PATH.
    Причина: `sudo vds … install` запускает CLI из venv, но `PATH` под sudo
    не содержит venv, поэтому `shutil.which("python3")` возвращал системный
    интерпретатор без зависимостей (живой дефект asv2 2026-11-16).
    """
    base = Path(install_dir or os.environ.get("INSTALL_DIR", "/opt/my-vds"))
    venv_py = base / "venv" / "bin" / "python3"
    if venv_py.is_file() and os.access(venv_py, os.X_OK):
        return str(venv_py)
    if sys.executable and Path(sys.executable).is_file():
        return sys.executable
    return shutil.which("python3") or "/usr/bin/python3"


def install_unit(
    template: str,
    name: str,
    ctx: dict[str, str] = {},
    root: str = "/",
) -> bool:
    """Отрендерить шаблон `systemd/<template>` и установить как юнит `name`.

    Идемпотентно: повторный вызов перезаписывает тот же файл и повторно
    делает daemon-reload + enable. True — успех, False — ошибка (значением).
    """
    def _install() -> bool:
        tpl = SYSTEMD_DIR / template
        if not tpl.is_file():
            console.print(f"[error]Шаблон юнита не найден: {tpl}[/error]")
            return False
        try:
            rendered = tpl.read_text(encoding="utf-8").format(**ctx)
        except (KeyError, OSError, ValueError) as e:
            console.print(f"[error]Ошибка рендера шаблона {template}: {e}[/error]")
            return False

        dest = _unit_path(name, root)
        tmp = dest.with_name(f".{dest.name}.tmp.{os.getpid()}")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(rendered)
            os.chmod(tmp, 0o644)
            os.replace(tmp, dest)
        except OSError as e:
            console.print(f"[error]Не удалось записать юнит {dest}: {e}[/error]")
            return False

        reload_res = run_list(["systemctl", "daemon-reload"], timeout=10)
        enable_res = run_list(["systemctl", "enable", name], timeout=10)
        if not (reload_res.ok and enable_res.ok):
            console.print(
                f"[error]systemctl не смог включить {name}: "
                f"{enable_res.stderr.strip() or reload_res.stderr.strip()}[/error]"
            )
            return False
        console.print(f"[change]Юнит {name} установлен и включён[/change]")
        return True

    if root != "/":
        return _install()
    with FileLock(LOCK_FILE):
        return _install()


def unit_active(name: str) -> bool:
    """Активен ли юнит (`systemctl is-active` == "active")."""
    result = run_list(["systemctl", "is-active", name], timeout=10)
    return result.ok and result.output == "active"


def remove_unit(name: str, root: str = "/") -> bool:
    """Остановить, выключить и удалить юнит. Идемпотентно (нет файла — успех).

    True — успех, False — ошибка (значением).
    """
    def _remove() -> bool:
        run_list(["systemctl", "stop", name], timeout=30)
        run_list(["systemctl", "disable", name], timeout=10)
        dest = _unit_path(name, root)
        try:
            dest.unlink(missing_ok=True)
        except OSError as e:
            console.print(f"[error]Не удалось удалить юнит-файл {dest}: {e}[/error]")
            return False
        reload_res = run_list(["systemctl", "daemon-reload"], timeout=10)
        if not reload_res.ok:
            console.print(f"[error]daemon-reload не удался: {reload_res.stderr.strip()}[/error]")
            return False
        console.print(f"[change]Юнит {name} остановлен и удалён[/change]")
        return True

    if root != "/":
        return _remove()
    with FileLock(LOCK_FILE):
        return _remove()
