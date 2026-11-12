"""Obfs-инстанс Hysteria2 (salamander, SPEC-20261112 WP-1, REQ FR-1..5).

Параллельный инстанс hysteria2 на отдельном UDP-порту (по умолчанию 51826,
вне занятых 443/8443/2053/51825) с обфускацией salamander: голый QUIC —
самый заметный фингерпринт, obfs-инстанс прячет его в неопознаваемый поток.
Auth-пароль — ТОТ ЖЕ общий пароль основного инстанса (один секрет на
транспорт, переиспользуем из state); obfs-пароль — отдельный генерируемый
секрет. Собственный конфиг /etc/hysteria/obfs.yaml (0600, тот же сертификат)
и юнит из шаблона systemd/vds-hysteria2-obfs.service.tpl. Основной 443-инстанс
не трогается вовсе: soft rollout по построению (SPEC §3.1).

rotate-obfs: новый obfs-пароль + рестарт obfs-инстанса на ТОМ ЖЕ порту
(девиация FR-5, SPEC §3.6): клиенты пере-импортируют ссылку, разрыв ~5 с.
Смена порта = remove-obfs + add-obfs --port N.
"""

import os

from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner
from src.core.secrets import gen_password, write_secret_atomic
from src.core.shell import run_list
from src.core.units import install_unit, remove_unit
from src.gateway.paths import (
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_KEY_PATH,
    HYSTERIA2_OBFS_CONFIG_PATH,
    HYSTERIA2_OBFS_PORT_DEFAULT,
    HYSTERIA2_OBFS_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state
from src.hysteria2.config import Hysteria2ConfigParams, render_config
from src.hysteria2.install import HYSTERIA2_BIN_PATH

LOCK_FILE = "/var/run/vds-hy2-obfs.lock"
STATE_KEY = "hysteria2-obfs"


class ObfsError(Exception):
    """Сбой obfs-инстанса (не установлен, порт, конфиг, юнит)."""


def _main_meta(state) -> dict:
    """Meta основного инстанса hysteria2; не установлен — ObfsError."""
    meta = state.protocols.get("hysteria2")
    if not meta or not meta.get("installed"):
        raise ObfsError(
            "Hysteria2 не установлен — сначала выполните `vds hysteria2 install`."
        )
    return meta


def _obfs_meta(state) -> dict | None:
    meta = state.protocols.get(STATE_KEY)
    if meta and meta.get("installed"):
        return meta
    return None


def _ensure_obfs_password(meta: dict | None) -> str:
    """Существующий obfs-пароль (паттерн _ensure_password) или новый."""
    if meta:
        saved = meta.get("obfs_password")
        if saved:
            return saved
    return gen_password()


def _render_obfs_config(auth_password: str, port: int, obfs_password: str) -> str:
    """Конфиг obfs-инстанса: тот же сертификат/masquerade, + блок obfs."""
    return render_config(
        Hysteria2ConfigParams(
            password=auth_password,
            port=port,
            cert_path=str(HYSTERIA2_CERT_PATH),
            key_path=str(HYSTERIA2_KEY_PATH),
            obfs_password=obfs_password,
        )
    )


def render_obfs_share_link(
    host: str,
    auth_password: str,
    obfs_password: str,
    name: str,
    port: int,
    insecure: bool,
    mport: str | None = None,
) -> str:
    """hysteria2://<auth>@<host>:<port>/?sni=..&obfs=salamander
    &obfs-password=<obfs>[&insecure=1][&mport=..]#<name> (SPEC §3.3)."""
    from src.hysteria2.clients import render_share_link

    return render_share_link(
        host=host,
        password=auth_password,
        name=name,
        port=port,
        insecure=insecure,
        mport=mport,
        obfs_password=obfs_password,
    )


def add_obfs(
    port: int = HYSTERIA2_OBFS_PORT_DEFAULT,
    state_path: str | None = None,
) -> int:
    """Установить obfs-инстанс. 0 — успех (в т.ч. «уже установлен»).

    Поток: root -> hysteria2 установлен -> port_free(port,'udp') ДО мутаций
    -> obfs-пароль (переиспользуется, не перегенерируется) -> render_config
    (obfs_password=...) -> obfs.yaml 0600 -> юнит из шаблона -> restart ->
    state.protocols['hysteria2-obfs'].
    """
    if os.geteuid() != 0:
        console.print("[error][hysteria2-obfs] Требуется root (запустите через sudo).[/error]")
        return 1

    with FileLock(LOCK_FILE):
        try:
            state = load_state(state_path)
        except StoreError as exc:
            console.print(f"[error][hysteria2-obfs] {exc}[/error]")
            return 1
        try:
            main_meta = _main_meta(state)
        except ObfsError as exc:
            console.print(f"[error][hysteria2-obfs] {exc}[/error]")
            return 1

        existing = _obfs_meta(state)
        if existing and int(existing.get("port", port)) == port:
            console.print(
                f"[success][hysteria2-obfs] Obfs-инстанс уже установлен на "
                f"udp/{port} — изменений не требуется (идемпотентно).[/success]"
            )
            return 0

        auth_password = str(main_meta.get("auth_password") or "")
        if not auth_password:
            console.print(
                "[error][hysteria2-obfs] В состоянии нет auth-пароля "
                "Hysteria2 — переустановите `vds hysteria2 install`.[/error]"
            )
            return 1

        # Проверка порта — ДО любых изменений (AC E1-паттерн install).
        if not port_free(port, "udp"):
            owner = port_owner(port, "udp")
            owner_info = f" (владелец: {owner})" if owner else ""
            console.print(
                f"[error][hysteria2-obfs] Порт {port}/udp занят{owner_info}. "
                "Выберите другой: `vds hysteria2 add-obfs --port N`.[/error]"
            )
            return 1

        obfs_password = _ensure_obfs_password(existing)
        rendered = _render_obfs_config(auth_password, port, obfs_password)
        # Основной config.yaml не пишем вообще (гейт WP-1 §3.7).
        try:
            HYSTERIA2_OBFS_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            console.print(
                f"[error][hysteria2-obfs] Не удалось создать каталог "
                f"{HYSTERIA2_OBFS_CONFIG_PATH.parent}: {exc}[/error]"
            )
            return 1
        if not write_secret_atomic(str(HYSTERIA2_OBFS_CONFIG_PATH), rendered, mode=0o600):
            console.print(
                f"[error][hysteria2-obfs] Не удалось записать "
                f"{HYSTERIA2_OBFS_CONFIG_PATH}.[/error]"
            )
            return 1

        if not install_unit(
            "vds-hysteria2-obfs.service.tpl",
            HYSTERIA2_OBFS_UNIT,
            ctx={
                "name": "obfs salamander",
                "bin_path": str(HYSTERIA2_BIN_PATH),
                "config_path": str(HYSTERIA2_OBFS_CONFIG_PATH),
            },
        ):
            console.print(
                f"[error][hysteria2-obfs] Не удалось установить юнит "
                f"{HYSTERIA2_OBFS_UNIT}.[/error]"
            )
            return 1

        restart = run_list(["systemctl", "restart", HYSTERIA2_OBFS_UNIT], timeout=30)
        if not restart.ok:
            console.print(
                f"[error][hysteria2-obfs] Сервис {HYSTERIA2_OBFS_UNIT} не "
                f"запустился: {restart.stderr.strip()}[/error]"
            )
            return 1

        state.protocols[STATE_KEY] = {
            "installed": True,
            "port": port,
            "obfs_password": obfs_password,  # секрет: state.json 0600
        }
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][hysteria2-obfs] Инстанс запущен, но состояние не "
                f"сохранено: {exc}[/error]"
            )
            return 1

    console.print(
        f"[success][hysteria2-obfs] Obfs-инстанс (salamander) запущен на "
        f"udp/{port}: конфиг {HYSTERIA2_OBFS_CONFIG_PATH} (0600), юнит "
        f"{HYSTERIA2_OBFS_UNIT}. Основной udp/443 не изменён.[/success]"
    )
    console.print(
        "[info][hysteria2-obfs] Ссылка с obfs: `vds hysteria2 add-client NAME` "
        "(печатает обе ссылки — обычную и obfs). Ротация пароля: "
        "`vds hysteria2 rotate-obfs`.[/info]"
    )
    return 0


def remove_obfs(apply: bool = False, state_path: str | None = None) -> int:
    """Снять obfs-инстанс (юнит, конфиг, state). Dry-run по умолчанию.

    Основной 443-инстанс не затрагивается. Нечего снимать — exit 0.
    """
    if os.geteuid() != 0:
        console.print("[error][hysteria2-obfs] Требуется root (запустите через sudo).[/error]")
        return 1

    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][hysteria2-obfs] {exc}[/error]")
        return 1
    meta = _obfs_meta(state)
    if not meta and not HYSTERIA2_OBFS_CONFIG_PATH.is_file():
        console.print("[info][hysteria2-obfs] Obfs-инстанс не установлен — нечего снимать.[/info]")
        return 0
    port = int(meta.get("port", HYSTERIA2_OBFS_PORT_DEFAULT)) if meta else HYSTERIA2_OBFS_PORT_DEFAULT

    plan = [
        f"остановка и удаление юнита {HYSTERIA2_OBFS_UNIT}",
        f"удаление конфига {HYSTERIA2_OBFS_CONFIG_PATH}",
        f"state.protocols['{STATE_KEY}'] из store",
        "(основной udp/443 не затрагивается)",
    ]
    console.print("[warning][hysteria2-obfs] План снятия obfs-инстанса (dry-run):[/warning]")
    for item in plan:
        console.print(f"  - {item}")
    console.print(f"[info]Порт obfs-инстанса: udp/{port}.[/info]")
    if not apply:
        console.print(
            "[info]Это dry-run. Для применения: `vds hysteria2 remove-obfs --apply`[/info]"
        )
        return 0

    with FileLock(LOCK_FILE):
        if not remove_unit(HYSTERIA2_OBFS_UNIT):
            console.print(
                f"[warning][hysteria2-obfs] Не удалось снять юнит "
                f"{HYSTERIA2_OBFS_UNIT} — снимите вручную.[/warning]"
            )
        try:
            HYSTERIA2_OBFS_CONFIG_PATH.unlink(missing_ok=True)
        except OSError as exc:
            console.print(
                f"[warning][hysteria2-obfs] Не удалось удалить "
                f"{HYSTERIA2_OBFS_CONFIG_PATH}: {exc}[/warning]"
            )
        try:
            state = load_state(state_path)
            state.protocols.pop(STATE_KEY, None)
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][hysteria2-obfs] Юнит и конфиг сняты, но состояние "
                f"не сохранено: {exc}[/error]"
            )
            return 1

    console.print(
        "[change][hysteria2-obfs] Obfs-инстанс снят; основной udp/443 не затронут.[/change]"
    )
    return 0


def rotate_obfs(state_path: str | None = None) -> int:
    """Ротация obfs-пароля на том же порту (девиация FR-5, SPEC §3.6).

    Новый obfs-пароль -> перезапись obfs.yaml (write_secret_atomic) ->
    restart obfs-инстанса. Клиентам нужен ре-импорт ссылки (разрыв ~5 с).
    """
    if os.geteuid() != 0:
        console.print("[error][hysteria2-obfs] Требуется root (запустите через sudo).[/error]")
        return 1

    with FileLock(LOCK_FILE):
        try:
            state = load_state(state_path)
        except StoreError as exc:
            console.print(f"[error][hysteria2-obfs] {exc}[/error]")
            return 1
        try:
            main_meta = _main_meta(state)
        except ObfsError as exc:
            console.print(f"[error][hysteria2-obfs] {exc}[/error]")
            return 1
        meta = _obfs_meta(state)
        if not meta:
            console.print(
                "[error][hysteria2-obfs] Obfs-инстанс не установлен — "
                "ротация не нужна (`vds hysteria2 add-obfs`).[/error]"
            )
            return 1

        auth_password = str(main_meta.get("auth_password") or "")
        if not auth_password:
            console.print(
                "[error][hysteria2-obfs] В состоянии нет auth-пароля "
                "Hysteria2.[/error]"
            )
            return 1

        port = int(meta.get("port", HYSTERIA2_OBFS_PORT_DEFAULT))
        new_password = gen_password()
        rendered = _render_obfs_config(auth_password, port, new_password)
        if not write_secret_atomic(str(HYSTERIA2_OBFS_CONFIG_PATH), rendered, mode=0o600):
            console.print(
                f"[error][hysteria2-obfs] Не удалось записать "
                f"{HYSTERIA2_OBFS_CONFIG_PATH}.[/error]"
            )
            return 1

        restart = run_list(["systemctl", "restart", HYSTERIA2_OBFS_UNIT], timeout=30)
        if not restart.ok:
            console.print(
                f"[error][hysteria2-obfs] Сервис {HYSTERIA2_OBFS_UNIT} не "
                f"перезапустился: {restart.stderr.strip()}[/error]"
            )
            return 1

        meta["obfs_password"] = new_password
        state.protocols[STATE_KEY] = meta
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(
                f"[error][hysteria2-obfs] Пароль сменён, но состояние не "
                f"сохранено: {exc}[/error]"
            )
            return 1

    console.print(
        f"[change][hysteria2-obfs] Obfs-пароль ротирован (порт udp/{port} не "
        "менялся, инстанс перезапущен).[/change]"
    )
    console.print(
        "[warning][hysteria2-obfs] Клиентам нужен ре-импорт obfs-ссылки: "
        "`vds hysteria2 add-client NAME` (разрыв ~5 с).[/warning]"
    )
    return 0
