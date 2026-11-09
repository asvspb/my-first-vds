"""Установка Hysteria2 (ADR-001, вариант B: пин версии + SHA256 из hashes.txt).

Поток: root-check -> port_free(443/udp) ДО любых изменений -> FileLock ->
загрузка бинаря + hashes.txt из GitHub release -> проверка SHA256 -> установка
бинаря в /usr/local/bin/hysteria -> self-signed сертификат (openssl req -x509,
CN=<public_ip>, 10 лет, 0600) -> auth-пароль (core.secrets.gen_password) ->
рендер и запись config.yaml (0600) -> sysctl-тюнинг -> юнит из шаблона
systemd/vds-hysteria2.service.tpl -> перезапуск -> метаданные в gateway store.

Идемпотентность: если пиннутая версия установлена и конфиг на месте —
повторный install не перекачивает (exit 0); существующие сертификаты и
auth-пароль переиспользуются и НИКОГДА не перегенерируются молча. Шаги,
требующие сети, вынесены в отдельные функции — в тестах они заменяются
моками; реальная установка выполняется только на [VDS].
"""

import hashlib
import os
import platform
import re
import shutil
import tempfile
from pathlib import Path

import requests

from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.secrets import gen_password, write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, unit_active
from src.gateway.paths import (
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_CONFIG_PATH,
    HYSTERIA2_KEY_PATH,
    HYSTERIA2_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state
from src.hysteria2.config import DEFAULT_PORT, Hysteria2ConfigParams, render_config
from src.hysteria2.sysctl import apply_sysctl

# Пин версии Hysteria (ADR-001): обновляется только коммитом.
HYSTERIA2_VERSION = "app/v2.13.0"
# Строка версии в выводе `hysteria version` (tag = app/vX.Y.Z).
_VERSIONplain = HYSTERIA2_VERSION.split("/", 1)[-1]

HYSTERIA2_PORT = DEFAULT_PORT
GITHUB_BASE = "https://github.com/apernet/hysteria/releases/download"
LOCK_FILE = "/var/run/vds-hysteria2.lock"

# ADR-002 фиксирует конфиг/сертификаты; бинарь — апстрим-конвенция /usr/local/bin
# (единая точка путей — paths.py, пути бинарей туда добавит следующий ADR).
HYSTERIA2_BIN_PATH = Path("/usr/local/bin/hysteria")

CERT_DAYS = 3650  # 10 лет (SPEC §3)

_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}

# Пароль в существующем config.yaml (переиспользование при повторном install).
_PASSWORD_YAML_RE = re.compile(r'^\s*password:\s*"?([A-Za-z0-9]+)"?\s*$', re.M)


class InstallError(Exception):
    """Сбой установки Hysteria2 (сеть, контрольная сумма, сертификат, юнит)."""


def _asset_name() -> str:
    """Имя release-ассета под текущую архитектуру."""
    arch = _ARCH_MAP.get(platform.machine().lower(), "amd64")
    return f"hysteria-linux-{arch}"


def _release_urls() -> tuple[str, str]:
    base = f"{GITHUB_BASE}/{HYSTERIA2_VERSION}/{_asset_name()}"
    return base, f"{GITHUB_BASE}/{HYSTERIA2_VERSION}/hashes.txt"


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


def _sha256_from_hashes(hashes_text: str, asset: str) -> str:
    """SHA256 ассета из hashes.txt релиза (формат: `<sha256>  build/<asset>`)."""
    for line in hashes_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and Path(parts[1]).name == asset:
            return parts[0].lower()
    raise InstallError(f"SHA256 для {asset} не найден в hashes.txt релиза.")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed() -> bool:
    """Установлена ли пиннутая версия (бинарь + конфиг на месте)."""
    if not (HYSTERIA2_BIN_PATH.is_file() and HYSTERIA2_CONFIG_PATH.is_file()):
        return False
    result = run_list([str(HYSTERIA2_BIN_PATH), "version"], timeout=15)
    return result.ok and _VERSIONplain in result.stdout


def _fetch_and_install_binary() -> None:
    """Скачать бинарь, сверить SHA256 (hashes.txt), установить в /usr/local/bin."""
    bin_url, hashes_url = _release_urls()
    with tempfile.TemporaryDirectory(prefix="vds-hysteria2-") as tmp:
        tmp_dir = Path(tmp)
        bin_path = tmp_dir / "hysteria"
        hashes_path = tmp_dir / "hashes.txt"

        _download_to(bin_url, bin_path)
        _download_to(hashes_url, hashes_path)

        expected = _sha256_from_hashes(
            hashes_path.read_text(encoding="utf-8"), _asset_name()
        )
        actual = _file_sha256(bin_path)
        if expected != actual:
            raise InstallError(
                "SHA256 загруженного бинаря не совпал с hashes.txt релиза "
                f"(ожидался {expected}, получен {actual}). Установка прервана."
            )

        HYSTERIA2_BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(bin_path), HYSTERIA2_BIN_PATH)
        os.chmod(HYSTERIA2_BIN_PATH, 0o755)


def _ensure_certificate(ip: str) -> None:
    """Self-signed сертификат CN=<ip> на 10 лет; существующий — переиспользуем."""
    if HYSTERIA2_CERT_PATH.is_file() and HYSTERIA2_KEY_PATH.is_file():
        console.print(
            "[info][hysteria2] Существующий сертификат переиспользуется "
            f"({HYSTERIA2_CERT_PATH}).[/info]"
        )
        return
    HYSTERIA2_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    result = run_list(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(HYSTERIA2_KEY_PATH),
            "-out", str(HYSTERIA2_CERT_PATH),
            "-days", str(CERT_DAYS), "-nodes",
            "-subj", f"/CN={ip}",
        ],
        timeout=30,
    )
    if not result.ok or not (
        HYSTERIA2_CERT_PATH.is_file() and HYSTERIA2_KEY_PATH.is_file()
    ):
        raise InstallError(
            f"Не удалось сгенерировать self-signed сертификат: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    os.chmod(HYSTERIA2_KEY_PATH, 0o600)
    os.chmod(HYSTERIA2_CERT_PATH, 0o600)


def _existing_password(state_path: str | None) -> str | None:
    """Ранее использованный auth-пароль: state.json, затем config.yaml."""
    try:
        state = load_state(state_path)
    except StoreError:
        state = None
    if state is not None:
        saved = state.protocols.get("hysteria2", {}).get("auth_password")
        if saved:
            return saved
    if HYSTERIA2_CONFIG_PATH.is_file():
        try:
            match = _PASSWORD_YAML_RE.search(
                HYSTERIA2_CONFIG_PATH.read_text(encoding="utf-8")
            )
        except OSError:
            return None
        if match:
            return match.group(1)
    return None


def _ensure_password(state_path: str | None) -> str:
    """Переиспользовать существующий auth-пароль или сгенерировать новый."""
    saved = _existing_password(state_path)
    if saved:
        console.print(
            "[info][hysteria2] Существующий auth-пароль переиспользуется.[/info]"
        )
        return saved
    return gen_password()


def _write_config(password: str, port: int) -> None:
    """Срендерить и атомарно записать config.yaml (0600)."""
    rendered = render_config(
        Hysteria2ConfigParams(
            password=password,
            port=port,
            cert_path=str(HYSTERIA2_CERT_PATH),
            key_path=str(HYSTERIA2_KEY_PATH),
        )
    )
    HYSTERIA2_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not write_secret_atomic(str(HYSTERIA2_CONFIG_PATH), rendered, mode=0o600):
        raise InstallError(f"Не удалось записать {HYSTERIA2_CONFIG_PATH}.")


def _save_state_meta(
    ip: str,
    port: int,
    password: str,
    state_path: str | None = None,
) -> None:
    """Записать метаданные hysteria2 в gateway store (пароль — только тут)."""
    state = load_state(state_path)
    state.protocols["hysteria2"] = {
        "installed": True,
        "version": HYSTERIA2_VERSION,
        "port": port,
        "cert_cn": ip,
        "auth_password": password,  # секрет: state.json 0600 (SPEC §5)
    }
    save_state(state, state_path)


def _install_locked(ip: str, port: int, state_path: str | None) -> int:
    try:
        _fetch_and_install_binary()
        _ensure_certificate(ip)
        password = _ensure_password(state_path)
        _write_config(password, port)
    except (InstallError, OSError) as exc:
        console.print(f"[error][hysteria2] {exc}[/error]")
        return 1

    if not apply_sysctl():
        return 1

    unit_ok = install_unit(
        "vds-hysteria2.service.tpl",
        HYSTERIA2_UNIT,
        ctx={
            "name": "QUIC masquerade",
            "bin_path": str(HYSTERIA2_BIN_PATH),
            "config_path": str(HYSTERIA2_CONFIG_PATH),
        },
    )
    if not unit_ok:
        console.print(
            f"[error][hysteria2] Не удалось установить юнит {HYSTERIA2_UNIT}[/error]"
        )
        return 1

    restart = run_list(["systemctl", "restart", HYSTERIA2_UNIT], timeout=30)
    if not restart.ok:
        console.print(
            f"[error][hysteria2] Сервис {HYSTERIA2_UNIT} не запустился: "
            f"{restart.stderr.strip()}[/error]"
        )
        return 1

    try:
        _save_state_meta(ip, port, password, state_path)
    except (StoreError, OSError) as exc:
        console.print(f"[error][hysteria2] Не удалось сохранить состояние: {exc}[/error]")
        return 1

    console.print(
        f"[success][hysteria2] Hysteria2 {HYSTERIA2_VERSION} установлен: QUIC на "
        f"udp/{port}, сертификат CN={ip} ({CERT_DAYS // 365} лет), юнит "
        f"{HYSTERIA2_UNIT} активен.[/success]"
    )
    console.print("[info][hysteria2] Клиенты: `vds hysteria2 add-client NAME`[/info]")
    return 0


def run_install(
    port: int = HYSTERIA2_PORT,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds hysteria2 install`. 0 — успех (в т.ч. «уже установлено»)."""
    if os.geteuid() != 0:
        console.print("[error][hysteria2] Требуется root (запустите через sudo).[/error]")
        return 1

    # Проверка порта — ДО любых изменений (SPEC §5, AC E1); QUIC = UDP.
    if not port_free(port, "udp"):
        owner = port_owner(port, "udp")
        owner_info = f" (владелец: {owner})" if owner else ""
        console.print(
            f"[error][hysteria2] Порт {port}/udp занят{owner_info}. "
            "Освободите порт или остановите сервис и повторите.[/error]"
        )
        return 1

    # Идемпотентность (ADR-001): пиннутая версия на месте — не перекачиваем.
    if _installed():
        console.print(
            f"[success][hysteria2] Hysteria2 {HYSTERIA2_VERSION} уже установлен "
            "(бинарь и конфиг на месте) — повторная установка не требуется.[/success]"
        )
        return 0

    ip = public_ip()
    if not ip:
        console.print(
            "[error][hysteria2] Не удалось определить публичный IP "
            "(api.ipify.org) — он нужен для CN=self-signed сертификата.[/error]"
        )
        return 1

    with FileLock(LOCK_FILE):
        return _install_locked(ip, port, state_path)


def is_service_active() -> bool:
    """Обёртка для adapter/status: активен ли юнит vds-hysteria2.service."""
    return unit_active(HYSTERIA2_UNIT)
