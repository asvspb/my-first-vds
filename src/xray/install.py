"""Установка Xray-core (ADR-001, вариант B: пин версии + SHA256 из .dgst).

Поток: root-check -> port_free(443) ДО любых изменений -> FileLock ->
загрузка release zip + .dgst из GitHub -> проверка SHA256 -> распаковка во
временный каталог -> установка бинаря и geodata -> генерация ключей
(uuid/secrets, x25519 вызовом установленного бинаря) -> рендер и запись
config.json (0600) -> юнит из шаблона systemd/vds-xray.service.tpl ->
перезапуск -> сохранение метаданных в gateway store.

Идемпотентность: если пиннутая версия уже установлена и конфиг на месте —
повторный install не перекачивает (exit 0). Шаги, требующие сети, вынесены в
отдельные функции — в тестах они заменяются моками; реальная установка
выполняется только на [VDS].
"""

import hashlib
import json
import os
import platform
import re
import secrets as pysecrets
import shutil
import tempfile
import zipfile
from pathlib import Path

import requests

from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, unit_active
from src.gateway.paths import (
    XRAY_BIN_PATH,
    XRAY_CONFIG_PATH,
    XRAY_GEODATA_DIR,
    XRAY_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state
from src.xray.config import DEFAULT_SNI, XrayConfigParams, render_config

# Пин версии Xray-core (ADR-001): обновляется только коммитом.
XRAY_VERSION = "v25.1.1"

XRAY_PORT = 443
GITHUB_BASE = "https://github.com/XTLS/Xray-core/releases/download"
LOCK_FILE = "/var/run/vds-xray.lock"

_ARCH_MAP = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
}

_X25519_PRIVATE_RE = re.compile(r"Private key:\s*([A-Za-z0-9_-]+)")
_X25519_PUBLIC_RE = re.compile(r"Public key:\s*([A-Za-z0-9_-]+)")


class InstallError(Exception):
    """Сбой установки Xray (сеть, контрольная сумма, ключи, юнит)."""


def _asset_arch() -> str:
    """Архитектурный суффикс release-ассетов под текущую машину."""
    return _ARCH_MAP.get(platform.machine().lower(), "64")


def _release_urls() -> tuple[str, str]:
    asset = f"Xray-linux-{_asset_arch()}.zip"
    base = f"{GITHUB_BASE}/{XRAY_VERSION}/{asset}"
    return base, base + ".dgst"


def _download_to(url: str, dest: Path) -> None:
    """Скачать файл в `dest` (стриминг). Ошибка сети — InstallError."""
    try:
        with requests.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        fh.write(chunk)
    except requests.RequestException as exc:
        raise InstallError(
            f"Не удалось скачать {url}: {exc}. "
            "Проверьте доступность GitHub с сервера (ADR-001: mirror вне MVP)."
        ) from exc


def _sha256_from_dgst(dgst_text: str) -> str:
    """Извлечь SHA256 из содержимого .dgst-ассета (подписан апстримом)."""
    for line in dgst_text.splitlines():
        parts = line.split("=", 1)
        if len(parts) == 2 and parts[0].strip().upper() == "SHA256":
            return parts[1].strip().lower()
    raise InstallError("SHA256 не найден в .dgst-ассете release.")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed() -> bool:
    """Установлена ли пиннутая версия (бинарь + конфиг на месте)."""
    if not (XRAY_BIN_PATH.is_file() and XRAY_CONFIG_PATH.is_file()):
        return False
    result = run_list([str(XRAY_BIN_PATH), "version"], timeout=15)
    return result.ok and XRAY_VERSION in result.stdout


def _gen_x25519() -> tuple[str, str]:
    """Пара (private, public) x25519 вызовом установленного бинаря."""
    result = run_list([str(XRAY_BIN_PATH), "x25519"], timeout=15)
    if not result.ok:
        raise InstallError(
            f"Не удалось сгенерировать x25519 ({XRAY_BIN_PATH} x25519): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    private_match = _X25519_PRIVATE_RE.search(result.stdout)
    public_match = _X25519_PUBLIC_RE.search(result.stdout)
    if not (private_match and public_match):
        raise InstallError(
            f"Неожиданный вывод `xray x25519`: {result.stdout.strip()!r}"
        )
    return private_match.group(1), public_match.group(1)


def _fetch_and_install_binary() -> None:
    """Скачать zip release, сверить SHA256, поставить бинарь и geodata."""
    zip_url, dgst_url = _release_urls()
    with tempfile.TemporaryDirectory(prefix="vds-xray-") as tmp:
        tmp_dir = Path(tmp)
        zip_path = tmp_dir / "xray.zip"
        dgst_path = tmp_dir / "xray.zip.dgst"

        _download_to(zip_url, zip_path)
        _download_to(dgst_url, dgst_path)

        expected = _sha256_from_dgst(dgst_path.read_text(encoding="utf-8"))
        actual = _file_sha256(zip_path)
        if expected != actual:
            raise InstallError(
                "SHA256 загруженного архива не совпал с .dgst-ассетом "
                f"(ожидался {expected}, получен {actual}). Установка прервана."
            )

        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(zip_path) as archive:
            # Содержимое архива верифицировано SHA256 из .dgst-ассета.
            archive.extractall(extract_dir)

        XRAY_GEODATA_DIR.mkdir(parents=True, exist_ok=True)
        for dat_file in extract_dir.glob("*.dat"):
            shutil.move(str(dat_file), XRAY_GEODATA_DIR / dat_file.name)
        bin_src = extract_dir / "xray"
        if not bin_src.is_file():
            raise InstallError("В release-архиве нет бинаря xray.")
        XRAY_BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(bin_src), XRAY_BIN_PATH)
        os.chmod(XRAY_BIN_PATH, 0o755)


def _write_config(private_key: str, short_id: str, sni: str, port: int) -> None:
    """Срендерить и атомарно записать config.json (0600)."""
    rendered = render_config(
        XrayConfigParams(
            client_ids=[],
            private_key=private_key,
            short_ids=[short_id],
            sni=sni,
            port=port,
        )
    )
    XRAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not write_secret_atomic(str(XRAY_CONFIG_PATH), rendered, mode=0o600):
        raise InstallError(f"Не удалось записать {XRAY_CONFIG_PATH}.")


def _save_state_meta(
    sni: str,
    port: int,
    public_key: str,
    short_id: str,
    state_path: str | None = None,
) -> None:
    """Записать метаданные xray в gateway store (приватный ключ — нет)."""
    state = load_state(state_path)
    state.protocols["xray"] = {
        "installed": True,
        "version": XRAY_VERSION,
        "sni": sni,
        "port": port,
        "public_key": public_key,
        "short_id": short_id,
    }
    save_state(state, state_path)


def _install_locked(sni: str, port: int, state_path: str | None) -> int:
    try:
        _fetch_and_install_binary()
        private_key, public_key = _gen_x25519()
        short_id = pysecrets.token_hex(4)
        _write_config(private_key, short_id, sni, port)
    except (InstallError, OSError) as exc:
        console.print(f"[error][xray] {exc}[/error]")
        return 1

    unit_ok = install_unit(
        "vds-xray.service.tpl",
        XRAY_UNIT,
        ctx={
            "name": "VLESS Reality",
            "bin_path": str(XRAY_BIN_PATH),
            "config_path": str(XRAY_CONFIG_PATH),
        },
    )
    if not unit_ok:
        console.print("[error][xray] Не удалось установить юнит vds-xray.service[/error]")
        return 1

    restart = run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
    if not restart.ok:
        console.print(
            f"[error][xray] Сервис {XRAY_UNIT} не запустился: "
            f"{restart.stderr.strip()}[/error]"
        )
        return 1

    try:
        _save_state_meta(sni, port, public_key, short_id, state_path)
    except (StoreError, OSError) as exc:
        console.print(f"[error][xray] Не удалось сохранить состояние: {exc}[/error]")
        return 1

    console.print(
        f"[success][xray] Xray {XRAY_VERSION} установлен: VLESS Reality "
        f"на {sni}:{port}, юнит {XRAY_UNIT} активен.[/success]"
    )
    console.print("[info][xray] Клиенты: `vds xray add-client NAME`[/info]")
    return 0


def run_install(
    sni: str = DEFAULT_SNI,
    port: int = XRAY_PORT,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds xray install`. 0 — успех (в т.ч. «уже установлено»)."""
    if os.geteuid() != 0:
        console.print("[error][xray] Требуется root (запустите через sudo).[/error]")
        return 1

    # Проверка порта — ДО любых изменений (SPEC §5, AC E1).
    if not port_free(port, "tcp"):
        owner = port_owner(port, "tcp")
        owner_info = f" (владелец: {owner})" if owner else ""
        console.print(
            f"[error][xray] Порт {port}/tcp занят{owner_info}. "
            "Освободите порт или остановите сервис и повторите.[/error]"
        )
        return 1

    # Идемпотентность (ADR-001): пиннутая версия на месте — не перекачиваем.
    if _installed():
        console.print(
            f"[success][xray] Xray {XRAY_VERSION} уже установлен "
            f"(бинарь и конфиг на месте) — повторная установка не требуется.[/success]"
        )
        return 0

    with FileLock(LOCK_FILE):
        return _install_locked(sni, port, state_path)


def is_service_active() -> bool:
    """Обёртка для adapter/status: активен ли юнит vds-xray.service."""
    return unit_active(XRAY_UNIT)


def config_json() -> dict:
    """Прочитать текущий config.json как dict (для diagnostics)."""
    return json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))
