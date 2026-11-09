"""Установка Xray-core (ADR-001, вариант B: пин версии + SHA256 из .dgst).

Поток: root-check -> already-installed (идемпотентность) -> port_free(443)
ДО любых изменений -> FileLock ->
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
import socket
import tempfile
import zipfile
from pathlib import Path

import requests

from src.acme.install import FULLCHAIN_NAME, PRIVKEY_NAME
from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, unit_active
from src.gateway.paths import (
    ACME_LETSENCRYPT_LIVE,
    XHTTP_INTERNAL_PORT,
    XRAY_BIN_PATH,
    XRAY_CONFIG_PATH,
    XRAY_GEODATA_DIR,
    XRAY_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state
from src.xray.config import (
    DEFAULT_SNI,
    XHTTP_MODES,
    XHTTP_PATH,
    XrayConfigParams,
    render_config,
)

# Пин версии Xray-core (ADR-001): обновляется только коммитом.
XRAY_VERSION = "v25.1.1"

XRAY_PORT = 443
GITHUB_BASE = "https://github.com/XTLS/Xray-core/releases/download"
LOCK_FILE = "/var/run/vds-xray.lock"

# XHTTP (SPEC WP-3, ADR-003): суффикс бэкапа config.json перед добавлением
# транспорта; существующий бэкап не перезаписывается (остаётся до-xhttp).
XHTTP_BACKUP_SUFFIX = ".bak-pre-xhttp"

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
    """URL zip-ассета и .dgst-файла релиза Xray.

    Env-переопределение `VDS_GITHUB_MIRROR` (gh-proxy-конвенция: зеркало
    префиксует оригинальный URL целиком), применяется в конце ко всем
    возвращённым URL, чтобы производные (.dgst) не разошлись. При заданном
    зеркале доверие смещается на зеркало для обоих ассетов (хеш-файл и
    бинарь идут через один и тот же mirror; GPG-проверки в коде нет);
    env-флаг — сознательный trade-off оператора, по умолчанию выключен.
    """
    asset = f"Xray-linux-{_asset_arch()}.zip"
    base = f"{GITHUB_BASE}/{XRAY_VERSION}/{asset}"
    urls = (base, base + ".dgst")
    mirror = os.environ.get("VDS_GITHUB_MIRROR", "").strip().rstrip("/")
    if not mirror:
        return urls
    return tuple(f"{mirror}/{url}" for url in urls)


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
        if len(parts) != 2:
            continue
        # Апстрим метит SHA256 как `SHA2-256=`, исторически ожидаем и `SHA256=`;
        # сравниваем без пробелов, регистр не важен.
        label = parts[0].strip().upper().replace(" ", "")
        if label in ("SHA256", "SHA2-256"):
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
    # Реальный вывод `xray version` — «Xray 25.1.1 ...» без ведущего «v»;
    # пин хранится как «v25.1.1» (тег release). Сравниваем без «v».
    return result.ok and XRAY_VERSION.lstrip("v") in result.stdout


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

    # Идемпотентность (ADR-001): пиннутая версия на месте — не перекачиваем.
    # ДО проверки порта: активный сервис владеет 443 сам, «порт занят (xray)»
    # на повторном install — ложный отказ и блокировка восстановления state.
    if _installed():
        console.print(
            f"[success][xray] Xray {XRAY_VERSION} уже установлен "
            f"(бинарь и конфиг на месте) — повторная установка не требуется.[/success]"
        )
        return 0

    # Проверка порта — ДО любых изменений (SPEC §5, AC E1).
    if not port_free(port, "tcp"):
        owner = port_owner(port, "tcp")
        owner_info = f" (владелец: {owner})" if owner else ""
        console.print(
            f"[error][xray] Порт {port}/tcp занят{owner_info}. "
            "Освободите порт или остановите сервис и повторите.[/error]"
        )
        return 1

    with FileLock(LOCK_FILE):
        return _install_locked(sni, port, state_path)


def is_service_active() -> bool:
    """Обёртка для adapter/status: активен ли юнит vds-xray.service."""
    return unit_active(XRAY_UNIT)


def config_json() -> dict:
    """Прочитать текущий config.json как dict (для diagnostics)."""
    return json.loads(XRAY_CONFIG_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# XHTTP-транспорт (SPEC WP-3, ADR-003)
# ---------------------------------------------------------------------------


def _dns_resolves_to(domain: str, expected_ip: str) -> bool:
    """A-запись домена указывает на expected_ip (E1; мокируемо в тестах)."""
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
    except socket.gaierror:
        return False
    return any(info[4][0] == expected_ip for info in infos)


def _le_cert_paths(domain: str) -> tuple[Path, Path]:
    """Пути LE fullchain/privkey для домена (ADR-004)."""
    live = ACME_LETSENCRYPT_LIVE(domain)
    return live / FULLCHAIN_NAME, live / PRIVKEY_NAME


def _xhttp_precheck(domain: str, mode: str, config_path: Path) -> tuple[dict, Path]:
    """Валидации ДО любых изменений; вернуть (текущий конфиг, путь бэкапа).

    Порядок SPEC §5: xray установлен -> LE-сертификат есть -> DNS==IP (E1).
    """
    if mode not in XHTTP_MODES:
        raise InstallError(
            f"Неизвестный mode {mode!r} — поддерживаются: {', '.join(XHTTP_MODES)}."
        )
    if not (XRAY_BIN_PATH.is_file() and config_path.is_file()):
        raise InstallError(
            "Xray не установлен — сначала выполните `vds xray install`."
        )
    le_cert, le_key = _le_cert_paths(domain)
    missing = [str(p) for p in (le_cert, le_key) if not p.is_file()]
    if missing:
        raise InstallError(
            "Файлы LE-сертификата не найдены: " + ", ".join(missing)
            + " — сначала выполните `vds acme issue --domain "
            + domain + "`."
        )
    server_ip = public_ip()
    if not server_ip or not _dns_resolves_to(domain, server_ip):
        raise InstallError(
            f"E1: домен {domain} не указывает на IP этого сервера "
            f"({server_ip or 'неизвестен'}) — отклонено до изменений."
        )
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise InstallError(
            f"Не удалось прочитать {config_path}: {exc} (E8: битый конфиг — "
            "не меняю; восстановите из бэкапа)."
        ) from exc
    return config, config_path.with_name(config_path.name + XHTTP_BACKUP_SUFFIX)


def _render_xhttp_config(
    current: dict, domain: str, mode: str, xhttp_uuids: list[str]
) -> str:
    """Отрендерить конфиг с XHTTP из текущего config.json + state-meta.

    Reality-поля (realitySettings, клиенты inbound#0) берутся из текущего
    конфига байт-в-байт-эквивалентно (те же значения), fallbacks/инблэнд —
    детерминированный рендер render_config.
    """
    try:
        inbound = current["inbounds"][0]
        reality = inbound["streamSettings"]["realitySettings"]
        sni = reality["serverNames"][0]
        reality_port = int(inbound["port"])
        params = XrayConfigParams(
            client_ids=[c["id"] for c in inbound["settings"].get("clients", [])],
            private_key=reality["privateKey"],
            short_ids=list(reality["shortIds"]),
            sni=sni,
            port=reality_port,
            xhttp_enabled=True,
            domain=domain,
            cert_path=str(_le_cert_paths(domain)[0]),
            key_path=str(_le_cert_paths(domain)[1]),
            xhttp_client_ids=xhttp_uuids,
            xhttp_mode=mode,
        )
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise InstallError(
            f"Неожиданная структура {XRAY_CONFIG_PATH}: {exc} (E8: не меняю)."
        ) from exc
    return render_config(params)


def add_transport_xhttp(
    domain: str,
    mode: str = "fallback",
    state_path: str | None = None,
    apply: bool = False,
) -> dict:
    """Добавить XHTTP к живому Xray (SPEC WP-3, ADR-003).

    apply=False — dry-run: план без изменений. apply=True: бэкап config.json
    (существующий `.bak-pre-xhttp` не перезаписывается) -> рендер -> запись
    0600 -> `xray -test` (fail: откат из бэкапа, E8) -> restart vds-xray
    (fail: откат) -> state.protocols["xhttp"]. Идемпотентно (E4).
    """
    current, backup_path = _xhttp_precheck(domain, mode, XRAY_CONFIG_PATH)

    if any(
        ib.get("streamSettings", {}).get("network") == "xhttp"
        for ib in current.get("inbounds", [])
    ):
        return {
            "already_enabled": True,
            "dry_run": not apply,
            "config_path": str(XRAY_CONFIG_PATH),
            "backup_path": str(backup_path),
        }

    try:
        state = load_state(state_path)
    except StoreError as exc:
        raise InstallError(f"Не удалось прочитать состояние: {exc}") from exc
    xhttp_uuids = [
        c.uuid
        for c in state.clients
        if c.protocol == "xray" and c.extra.get("transport") == "xhttp" and c.uuid
    ]

    plan = {
        "domain": domain,
        "mode": mode,
        "path": XHTTP_PATH,
        "config_path": str(XRAY_CONFIG_PATH),
        "backup_path": str(backup_path),
        "internal_port": XHTTP_INTERNAL_PORT,
        "xhttp_clients": len(xhttp_uuids),
    }
    if not apply:
        return dict(plan, dry_run=True)

    rendered = _render_xhttp_config(current, domain, mode, xhttp_uuids)
    with FileLock(LOCK_FILE):
        if XRAY_CONFIG_PATH.is_file() and not backup_path.exists():
            shutil.copy2(XRAY_CONFIG_PATH, backup_path)
            os.chmod(backup_path, 0o600)

        if not write_secret_atomic(str(XRAY_CONFIG_PATH), rendered, mode=0o600):
            raise InstallError(f"Не удалось записать {XRAY_CONFIG_PATH}.")

        test = run_list(
            [str(XRAY_BIN_PATH), "run", "-test", "-config", str(XRAY_CONFIG_PATH)],
            timeout=15,
        )
        if not test.ok:
            shutil.copy2(backup_path, XRAY_CONFIG_PATH)
            os.chmod(XRAY_CONFIG_PATH, 0o600)
            raise InstallError(
                "xray -test не прошёл, конфиг откатан из бэкапа "
                f"({backup_path}): {test.stderr.strip() or test.stdout.strip()}"
            )

        restart = run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
        if not restart.ok:
            shutil.copy2(backup_path, XRAY_CONFIG_PATH)
            os.chmod(XRAY_CONFIG_PATH, 0o600)
            run_list(["systemctl", "restart", XRAY_UNIT], timeout=30)
            raise InstallError(
                f"systemctl restart {XRAY_UNIT} не удался, конфиг откатан из "
                f"бэкапа ({backup_path}): "
                f"{restart.stderr.strip() or restart.stdout.strip()}"
            )

        # "installed": True обязателен — remove-transport вычищает весь ключ,
        # без флага `vds gateway status` показывает «not installed» на живом
        # транспорте (TECHDEBT P13, найдено на asv1).
        state.protocols["xhttp"] = {
            "installed": True,
            "port": XHTTP_INTERNAL_PORT,
            "mode": mode,
            "domain": domain,
            "extra": {"path": XHTTP_PATH},
        }
        save_state(state, state_path)

    return dict(plan, dry_run=False, restarted=True)


def run_add_transport_xhttp(
    transport: str,
    domain: str,
    mode: str = "fallback",
    apply: bool = False,
    yes: bool = False,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds xray add-transport xhttp`. 0 — успех (в т.ч. dry-run)."""
    if os.geteuid() != 0:
        console.print("[error][xray] Требуется root (запустите через sudo).[/error]")
        return 1
    if transport != "xhttp":
        console.print(
            f"[error][xray] Неизвестный транспорт {transport!r} "
            "(поддерживается: xhttp).[/error]"
        )
        return 1

    if apply and not yes:
        import questionary

        if not questionary.confirm(
            "Добавить XHTTP к живому Xray? Будет перезапущен vds-xray "
            "(короткий TCP-downtime); Reality должен продолжить работу.",
            default=False,
        ).ask():
            console.print("[info][xray] Операция отменена.[/info]")
            return 1

    try:
        info = add_transport_xhttp(domain, mode=mode, state_path=state_path, apply=apply)
    except (InstallError, StoreError) as exc:
        console.print(f"[error][xray] {exc}[/error]")
        return 1

    if info.get("already_enabled"):
        console.print(
            "[success][xray] XHTTP уже включён — изменений не требуется "
            "(идемпотентно).[/success]"
        )
        return 0

    if info["dry_run"]:
        console.print(
            f"[info][xray] DRY-RUN. План добавления XHTTP ({info['mode']})[/info]\n"
            f"[info][xray] Домен: {info['domain']}[/info]\n"
            f"[info][xray] Бэкап config.json: {info['backup_path']}[/info]\n"
            f"[info][xray] Gates: `xray -test` -> restart {XRAY_UNIT}[/info]\n"
            f"[info][xray] Reality (TCP 443) остаётся без изменений в "
            "realitySettings; verify-гейт: проверьте клиента `phone` по старой "
            "ссылке сразу после --apply.[/info]"
        )
        console.print(
            "[warning][xray] Для применения: `vds xray add-transport xhttp "
            f"--domain {info['domain']} --apply`[/warning]"
        )
        return 0

    console.print(
        f"[success][xray] XHTTP добавлен ({info['mode']}, {info['domain']}): "
        f"внутренний порт {info['internal_port']}, юнит {XRAY_UNIT} перезапущен.[/success]"
    )
    console.print(
        f"[info][xray] Бэкап: {info['backup_path']}. "
        "СЕЙЧАС проверьте Reality-клиент по старой ссылке; если сломался — "
        "`vds xray remove-transport xhttp --apply` (ADR-003 откат).[/info]"
    )
    return 0
