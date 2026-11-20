"""wstunnel — носитель №2 p2p-плеча relay↔exit (ADR-016, SPEC-20261120 §2.2).

Зачем: L4-ортогональный резерв к `awg` (UDP). Клиент/сервер `wstunnel` говорят
по **WSS/TLS** (порт 9443), внутри — UDP-форвард на локальный порт AWG
(`wg-ws0`). Клиент подключается по **hostname** `ws.<domain>`: это даёт валидацию
LE-сертификата и настоящий SNI (ради него домен и заводится — пассивный DPI на
магистрали не видит самоподписи/пустого SNI).

Пиннинг (OQ-1): версия и SHA256 зафиксированы константами; скачивание только с
GitHub Releases, проверка sha256 **до** распаковки, атомарная установка 0755.
Никаких `latest` и `curl | sh`.

Секрет (path-prefix) не попадает в `argv`: обе стороны читают его из
`EnvironmentFile` (`WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX` /
`WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX` — имена есть в README v11.1.0).

Флаги сверены по README тега v11.1.0:
- server: `wstunnel server wss://0.0.0.0:<port> --restrict-to HOST:PORT
  --tls-certificate <pem> --tls-private-key <pem>`;
- client: `wstunnel client -L 'udp://<local>:localhost:<port>?timeout_sec=0'
  [--tls-verify-certificate] wss://<host>:<port>`.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Callable, Optional

from src.core.logger import console
from src.core.secrets import gen_password, write_secret_atomic
from src.core.shell import ShellResult, run_list

# --- пиннинг релиза (OQ-1) -------------------------------------------------
WSTUNNEL_VERSION = "11.1.0"
#: sha256 ассетов по архитектурам. arm64 пока не проверен — отсутствие в
#: словаре означает «эта архитектура не поддерживается» (а не «любой хэш»).
WSTUNNEL_SHA256_BY_ARCH = {
    "amd64": "512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23",
}
WSTUNNEL_SHA256 = WSTUNNEL_SHA256_BY_ARCH["amd64"]  # обратная совместимость
WSTUNNEL_RELEASE_URL = (
    "https://github.com/erebe/wstunnel/releases/download/v{version}/"
    "wstunnel_{version}_linux_{arch}.tar.gz"
)
WSTUNNEL_BIN = Path("/usr/local/bin/wstunnel")

# --- пути/имена ------------------------------------------------------------
WS_ENV_DIR = Path("/etc/vds")
WS_SERVER_ENV = WS_ENV_DIR / "wstunnel-server.env"
WS_CLIENT_ENV = WS_ENV_DIR / "wstunnel-client.env"
WS_SERVER_UNIT = "vds-wstunnel-server.service"
WS_CLIENT_UNIT = "vds-wstunnel-client.service"

# nft exit-стороны и конфиг AWG интерфейса (одинаковый путь на обоих узлах)
EXIT_NFT_TABLE = "vds_relay_wstun"
EXIT_NFT_FILE = Path("/etc/vds/wstunnel-exit.nft")
WG_WS_CONF = Path("/etc/amnezia/wg-ws0.conf")
WG_WS_UNIT = "vds-awg-wg-ws0.service"

# --- сетевые константы носителя №2 ----------------------------------------
WS_PORT_DEFAULT = 9443          # TCP/TLS, свободен на обоих узлах (SPEC §1)
WG_WS_IFACE = "wg-ws0"
WG_WS_PORT_DEFAULT = 51821      # AWG-порт, слушает 0.0.0.0 → закрыт nft (кроме lo)
WG_WS_LOCAL_UDP_DEFAULT = 51822  # локальный UDP-порт wstunnel-клиента на релее
WG_WS_NET = "10.12.0.0/30"
WG_WS_EXIT_ADDR = "10.12.0.1/30"
WG_WS_RELAY_ADDR = "10.12.0.2/30"
WG_WS_RELAY_PEER = "10.12.0.2/32"  # AllowedIPs пира на exit-стороне
WG_WS_MTU = 1240

_PREFIX_BYTES = 18  # ~24 символа base62 — как в README-примере


class WstunnelError(RuntimeError):
    """Ошибка вендоринга/рендера wstunnel (сообщение — для оператора)."""


def asset_name(version: str = WSTUNNEL_VERSION, arch: Optional[str] = None) -> str:
    """Имя архива релиза: `wstunnel_<ver>_linux_<arch>.tar.gz`."""
    return f"wstunnel_{version}_linux_{arch or detect_arch()}.tar.gz"


def detect_arch(machine: Optional[str] = None) -> str:
    """`uname -m` → суффикс ассета релиза (amd64/arm64)."""
    raw = (machine or platform.machine()).lower()
    mapping = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if raw not in mapping:
        raise WstunnelError(f"архитектура {raw!r} не поддерживается (amd64/arm64)")
    return mapping[raw]


def download_url(version: str = WSTUNNEL_VERSION, arch: Optional[str] = None) -> str:
    return WSTUNNEL_RELEASE_URL.format(version=version, arch=arch or detect_arch())


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sha256(arch: Optional[str] = None) -> str:
    """sha256 для архитектуры; неподдерживаемая — явная ошибка."""
    key = arch or detect_arch()
    digest = WSTUNNEL_SHA256_BY_ARCH.get(key)
    if not digest:
        raise WstunnelError(
            f"архитектура {key} не поддерживается: нет проверенного sha256 "
            f"(есть: {', '.join(sorted(WSTUNNEL_SHA256_BY_ARCH))})"
        )
    return digest


def verify_archive(path: Path, expected: Optional[str] = None) -> None:
    """Сверить sha256 ДО распаковки; несовпадение — WstunnelError."""
    expected = expected or expected_sha256()
    actual = sha256_of(path)
    if actual != expected:
        raise WstunnelError(
            "sha256 архива wstunnel не совпал: "
            f"ожидался {expected}, получен {actual} — установка отменена"
        )


def extract_binary(archive: Path, dest: Path = WSTUNNEL_BIN) -> Path:
    """Достать `wstunnel` из tar.gz безопасно и положить атомарно (0755).

    Защита: только regular-файл с именем `wstunnel`, без абсолютных путей и
    `..`; никаких симлинков/устройств из архива.
    """
    try:
        with tarfile.open(archive, "r:gz") as tar:
            member = None
            for item in tar.getmembers():
                name = item.name
                if not name.endswith("/wstunnel") and name != "wstunnel":
                    continue
                if not item.isfile():
                    continue
                if name.startswith("/") or ".." in Path(name).parts:
                    raise WstunnelError(f"подозрительный путь в архиве: {name}")
                member = item
                break
            if member is None:
                raise WstunnelError("в архиве нет файла wstunnel")
            payload = tar.extractfile(member)
            if payload is None:
                raise WstunnelError("не удалось прочитать wstunnel из архива")
            data = payload.read()
    except tarfile.TarError as exc:
        raise WstunnelError(f"битый архив wstunnel: {exc}") from exc

    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), prefix=".wstunnel.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_name, 0o755)
        os.replace(tmp_name, dest)
    except OSError as exc:
        Path(tmp_name).unlink(missing_ok=True)
        raise WstunnelError(f"не удалось установить {dest}: {exc}") from exc
    return dest


def installed_version(run: Callable[..., ShellResult] = run_list) -> Optional[str]:
    """Версия установленного бинарника (`wstunnel --version`); None — нет/битый."""
    if not WSTUNNEL_BIN.is_file():
        return None
    result = run([str(WSTUNNEL_BIN), "--version"], timeout=5)
    if not result.ok:
        return None
    raw = (result.stdout or "").strip()
    for token in raw.split():
        cleaned = token.lstrip("v")
        if cleaned and cleaned[0].isdigit():
            return cleaned
    return None


def gen_path_prefix() -> str:
    """Случайный path-prefix (секрет): base62 из `gen_password`."""
    return gen_password(_PREFIX_BYTES)


def render_server_env(prefix: str) -> str:
    """Env-файл сервера: только секрет-префикс (TLS-пути — в argv, не секрет)."""
    return (
        "# vds wstunnel server — секреты (0600). WSTUNNEL_* читается wstunnel v11\n"
        f"WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX={prefix}\n"
    )


def render_client_env(prefix: str) -> str:
    return (
        "# vds wstunnel client — секреты (0600). WSTUNNEL_* читается wstunnel v11\n"
        f"WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX={prefix}\n"
    )


def server_argv(
    *,
    ws_port: int = WS_PORT_DEFAULT,
    wg_port: int = WG_WS_PORT_DEFAULT,
    cert_path: str,
    key_path: str,
) -> list[str]:
    """argv сервера на exit: wss на 0.0.0.0:<ws_port>, форвард только на lo."""
    if not cert_path or not key_path:
        raise WstunnelError("нужны --tls-certificate и --tls-private-key (LE)")
    return [
        str(WSTUNNEL_BIN), "server", f"wss://0.0.0.0:{int(ws_port)}",
        "--restrict-to", f"127.0.0.1:{int(wg_port)}",
        "--tls-certificate", str(cert_path),
        "--tls-private-key", str(key_path),
    ]


_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def _validate_hostname(domain: str) -> str:
    """Строгая проверка: hostname (FQDN), не IP, без схемы/пути/пробелов.

    `ipaddress` ловит IP-литералы (включая IPv6 в скобках), regex — остальное
    (`ws.example.net/x`, пробелы, подчёркивания недопустимы в TLS-SNI).
    """
    host = (domain or "").strip().strip("[]").lower()
    try:
        import ipaddress

        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WstunnelError(
            "нужен hostname домена (ws.<domain>), а не IP: иначе LE не валидируется "
            "и SNI не уходит"
        )
    if not _HOSTNAME_RE.fullmatch(host):
        raise WstunnelError(
            f"{domain!r} не похож на hostname формата ws.<domain> "
            "(без схемы, пути и пробелов)"
        )
    return host


def client_argv(
    *,
    domain: str,
    ws_port: int = WS_PORT_DEFAULT,
    local_udp: int = WG_WS_LOCAL_UDP_DEFAULT,
    wg_port: int = WG_WS_PORT_DEFAULT,
) -> list[str]:
    """argv клиента на релее: UDP-форвард на локальный AWG-порт.

    Подключение — по hostname (`wss://<domain>:<port>`): LE валидируется, SNI
    уходит настоящий. `--tls-verify-certificate` обязателен: по умолчанию
    wstunnel доверяет любому сертификату.
    """
    host = _validate_hostname(domain)
    return [
        str(WSTUNNEL_BIN), "client",
        # target — ровно `127.0.0.1:<wg_port>`: `--restrict-to` матчит строку,
        # а `localhost` может резолвиться в ::1 и не совпасть.
        "-L", f"udp://127.0.0.1:{int(local_udp)}:127.0.0.1:{int(wg_port)}?timeout_sec=0",
        "--tls-verify-certificate",
        f"wss://{host}:{int(ws_port)}",
    ]


def render_exit_conf(
    *,
    private_key: str,
    peer_public_key: str,
    wg_port: int = WG_WS_PORT_DEFAULT,
    keepalive: int = 25,
) -> str:
    """Серверный .conf exit-стороны: `wg-ws0` 10.12.0.1/30, plain (без obf).

    Обфускация выключена: интерфейс живёт **внутри** wstunnel/WSS, junk только
    съедает MTU и TCP-окно. Пир — релей (10.12.0.2/32) с keepalive 25, чтобы
    сессия не умирала на NAT/промежуточных устройствах.
    """
    from src.amneziawg.config import ServerParams, ServerPeer, render_server_conf

    peer = ServerPeer(
        public_key=peer_public_key,
        allowed_ips=WG_WS_RELAY_PEER,
        name="relay-wstunnel",
        keepalive=keepalive,
    )
    return render_server_conf(
        ServerParams(
            private_key=private_key,
            address=WG_WS_EXIT_ADDR,
            port=int(wg_port),
            obf={},
            peers=(peer,),
        )
    )


def render_relay_conf(
    *,
    private_key: str,
    server_public_key: str,
    local_udp: int = WG_WS_LOCAL_UDP_DEFAULT,
    mtu: int = WG_WS_MTU,
    keepalive: int = 25,
) -> str:
    """Клиентский .conf релея: `wg-ws0` 10.12.0.2/30 поверх локального UDP.

    Ключевое (ADR-016 I-3):
    * `Endpoint = 127.0.0.1:<local_udp>` — порт, который слушает wstunnel client;
    * **`Table = off`** — маршруты ведёт селектор (table 100), иначе wg-quick
      перезапишет default в main и отрежет SSH (урок sanitize_exit_conf);
    * `MTU` — из SPEC §4 (1240), поверх TLS/TCP/WS.
    """
    if not private_key or not server_public_key:
        raise WstunnelError("нужны приватный ключ релея и публичный ключ exit")
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {WG_WS_RELAY_ADDR}",
        f"MTU = {int(mtu)}",
        "Table = off",
        "SaveConfig = false",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"Endpoint = 127.0.0.1:{int(local_udp)}",
        "AllowedIPs = 0.0.0.0/0",
        f"PersistentKeepalive = {int(keepalive)}",
    ]
    return "\n".join(lines) + "\n"


def render_exit_nft(
    *,
    relay_ip: str,
    wan_iface: str,
    ws_port: int = WS_PORT_DEFAULT,
    wg_port: int = WG_WS_PORT_DEFAULT,
    table: str = EXIT_NFT_TABLE,
) -> str:
    """nft exit-стороны (ADR-016 §2.2): NAT подсети + изоляция портов.

    * `postrouting` — MASQUERADE 10.12.0.0/30 на WAN (иначе приватный src уйдёт
      в интернет);
    * `input` (priority filter − 1) — WSS-порт только с IP релея; WG-порт
      **только через lo** (kernel AWG не умеет bind на loopback — nft замещает);
    Forward-цепочки здесь НЕТ намеренно: на exit `DEFAULT_FORWARD_POLICY=ACCEPT`
    («allow (routed)» — проверено на живом узле), ровно поэтому работает и
    `awg2` без правил. Отдельная `chain forward policy accept` была бы no-op
    (и не обошла бы чужой DROP на том же хуке). Если политика станет `DROP` —
    нужен `ufw route allow in on wg-ws0 out on <wan>`, а не nft-иллюзия.
    """
    from src.relay.exit_leg import validate_relay_ip, validate_wan_iface

    ip = validate_relay_ip(relay_ip)
    wan = validate_wan_iface(wan_iface)
    return (
        "#!/usr/sbin/nft -f\n"
        "# VDS p2p carrier 2 (ADR-016): wstunnel/WG. Генерируется\n"
        "# `vds relay wstunnel` — руками на сервере не править.\n"
        f"table inet {table}\n"
        f"flush table inet {table}\n"
        f"table inet {table} {{\n"
        "    chain postrouting {\n"
        "        type nat hook postrouting priority srcnat; policy accept;\n"
        f'        ip saddr {WG_WS_NET} oifname "{wan}" masquerade\n'
        "    }\n"
        "    chain input {\n"
        "        type filter hook input priority filter - 1; policy accept;\n"
        f"        ip saddr != {ip} tcp dport {int(ws_port)} drop\n"
        f"        meta nfproto ipv6 tcp dport {int(ws_port)} drop\n"
        f'        iifname != "lo" udp dport {int(wg_port)} drop\n'
        "    }\n"
        "}\n"
    )


def write_env(path: Path, text: str) -> None:
    """Атомарная запись env-файла 0600 (секрет не попадает в лог)."""
    write_secret_atomic(path, text)


def run_install(
    *,
    archive: Path,
    dry_run: bool = True,
    apply: bool = False,
    run: Callable[..., ShellResult] = run_list,
) -> int:
    """Установить бинарник из локального архива (сеть — отдельным шагом).

    Сеть намеренно вне модуля: архив скачивает оператор (или будущий curl-шаг),
    модуль отвечает за **проверку** sha256 и атомарную установку.
    """
    checks = [
        f"архив: {archive}",
        f"ожидаемый sha256: {WSTUNNEL_SHA256}",
        f"куда: {WSTUNNEL_BIN}",
    ]
    for line in checks:
        console.print(f"[info][wstunnel] {line}[/info]")
    if dry_run and not apply:
        console.print("[info][wstunnel] dry-run: без --apply ничего не меняем[/info]")
        return 0
    if not archive.is_file():
        raise WstunnelError(f"архив не найден: {archive}")
    verify_archive(archive)
    extract_binary(archive)
    console.print(f"[success][wstunnel] установлен {WSTUNNEL_BIN} (v{WSTUNNEL_VERSION})[/success]")
    version = installed_version(run)
    if version and version != WSTUNNEL_VERSION:
        console.print(
            f"[warning][wstunnel] бинарник сообщает версию {version}, "
            f"ожидалась {WSTUNNEL_VERSION}[/warning]"
        )
    return 0


def run_status(run: Callable[..., ShellResult] = run_list) -> dict[str, object]:
    """Состояние вендоринга: версия, наличие env-файлов и юнитов."""
    env_server = WS_SERVER_ENV.is_file()
    env_client = WS_CLIENT_ENV.is_file()
    return {
        "pinned_version": WSTUNNEL_VERSION,
        "installed_version": installed_version(run),
        "binary": str(WSTUNNEL_BIN),
        "env_server": env_server,
        "env_client": env_client,
    }


__all__ = [
    "WSTUNNEL_VERSION",
    "WSTUNNEL_SHA256",
    "WSTUNNEL_BIN",
    "WS_SERVER_ENV",
    "WS_CLIENT_ENV",
    "WS_SERVER_UNIT",
    "WS_CLIENT_UNIT",
    "WS_PORT_DEFAULT",
    "WG_WS_IFACE",
    "WG_WS_PORT_DEFAULT",
    "WG_WS_LOCAL_UDP_DEFAULT",
    "WG_WS_NET",
    "WG_WS_EXIT_ADDR",
    "WG_WS_RELAY_ADDR",
    "WG_WS_RELAY_PEER",
    "WG_WS_MTU",
    "WstunnelError",
    "asset_name",
    "detect_arch",
    "download_url",
    "sha256_of",
    "expected_sha256",
    "WSTUNNEL_SHA256_BY_ARCH",
    "verify_archive",
    "extract_binary",
    "installed_version",
    "gen_path_prefix",
    "EXIT_NFT_TABLE",
    "EXIT_NFT_FILE",
    "WG_WS_CONF",
    "WG_WS_UNIT",
    "render_exit_conf",
    "render_relay_conf",
    "render_exit_nft",
    "render_server_env",
    "render_client_env",
    "server_argv",
    "client_argv",
    "write_env",
    "run_install",
    "run_status",
]
