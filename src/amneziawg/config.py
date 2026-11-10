"""Генерация и рендер .conf для AmneziaWG (SPEC-20261110 §3, ADR-005).

AWG = обфусцированный WireGuard (awg-quick формат). Поддерживается ТОЛЬКО
1.5-набор обфускации (OQ-4): Jc/Jmin/Jmax + S1/S2 + H1–H4 (одиночные uint32,
попарно различимые). AWG 2.0-параметры (S3/S4, диапазонные H,
HeaderProtectionKey) отклоняются с ValueError «не поддерживается (ADR-005:
линия 1.5)».

Рендеры чистые и детерминированные: одинаковые входы дают байт-в-байт
одинаковый .conf. Случайная часть (параметры обфускации) генерируется
отдельно через gen_obfuscation_params(rng) — детерминизм обеспечивается
seed-ированным random.Random. Генерация ключей (awg genkey/genpsk) —
на уровне install/clients (WP-2/3); здесь только тонкие обёртки-заготовки.

Секреты (PrivateKey, PresharedKey) проходят через эти функции, но не
логируются и не попадают в вывод — только в возвращаемую строку .conf.
"""

import random
from dataclasses import dataclass, field
from typing import Optional

# Дефолты OQ-1/ADR-005 (локализация путей — gateway/paths.py, WP-2).
DEFAULT_PORT = 51825
DEFAULT_ADDRESS = "10.9.0.1/24"
DEFAULT_CLIENT_ALLOWED_IPS = "0.0.0.0/0,::/0"
PERSISTENT_KEEPALIVE = 25

# Ограничения обфускации (SPEC §3: Jmin<=Jmax, Jmax < MTU-128; 1.5-набор).
_JC_MIN, _JC_MAX = 3, 10
_MTU_DEFAULT = 1420
_JMAX_LIMIT = _MTU_DEFAULT - 128  # 1292
_UINT32_MAX = 2**32 - 1

# Ровно этот набор ключей — 1.5-линия (OQ-4). Всё прочее — 2.0+ → отказ.
_OBF_KEYS = {"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}
_REJECTED_20_KEYS = {
    "S3", "S4",
    "H1_MIN", "H1_MAX", "H2_MIN", "H2_MAX",
    "H3_MIN", "H3_MAX", "H4_MIN", "H4_MAX",
    "HEADER_PROTECTION_KEY",
}


def _reject_20_param(name: str) -> ValueError:
    return ValueError(
        f"параметр обфускации {name} не поддерживается (ADR-005: линия 1.5)"
    )


def validate_obfuscation(obf: dict) -> None:
    """Валидировать 1.5-набор обфускации; нарушение → ValueError с понятным текстом.

    Проверки: ровно ключи {Jc,Jmin,Jmax,S1,S2,H1..H4}; S3/S4 и диапазонные
    H-параметры (AWG 2.0) → отказ; Jc ∈ [3,10]; 0 <= Jmin < Jmax < MTU-128;
    S1/S2 — неотрицательные int; H1..H4 — uint32, попарно различимы.
    """
    unknown = set(obf) - _OBF_KEYS
    rejected = sorted(unknown & _REJECTED_20_KEYS)
    if rejected:
        raise _reject_20_param(", ".join(rejected))
    if unknown:
        raise ValueError(f"неизвестные параметры обфускации: {sorted(unknown)}")
    missing = _OBF_KEYS - set(obf)
    if missing:
        raise ValueError(f"неполный 1.5-набор обфускации, отсутствуют: {sorted(missing)}")

    jc = obf["Jc"]
    if not isinstance(jc, int) or not (_JC_MIN <= jc <= _JC_MAX):
        raise ValueError(f"Jc должен быть int в [{_JC_MIN}, {_JC_MAX}], получено {jc!r}")

    for key in ("Jmin", "Jmax", "S1", "S2"):
        val = obf[key]
        if not isinstance(val, int) or val < 0:
            raise ValueError(f"{key} должен быть неотрицательным int, получено {val!r}")
    if obf["Jmin"] >= obf["Jmax"]:
        raise ValueError(
            f"Jmin ({obf['Jmin']}) должен быть меньше Jmax ({obf['Jmax']})"
        )
    if obf["Jmax"] >= _JMAX_LIMIT:
        raise ValueError(
            f"Jmax ({obf['Jmax']}) должен быть < MTU-128 ({_JMAX_LIMIT})"
        )

    headers: list[int] = []
    for key in ("H1", "H2", "H3", "H4"):
        val = obf[key]
        if not isinstance(val, int) or not (0 <= val <= _UINT32_MAX):
            raise ValueError(f"{key} должен быть uint32, получено {val!r}")
        if val in headers:
            raise ValueError(f"{key} ({val}) повторяет ранее встреченный H-параметр")
        headers.append(val)


def gen_obfuscation_params(rng: random.Random) -> dict:
    """Сгенерировать 1.5-набор обфускации; детерминизм — от переданного rng.

    Возвращает dict с ключами Jc/Jmin/Jmax/S1/S2/H1..H4. Ограничения те же,
    что в validate_obfuscation (проверяются после генерации — генератор
    обязан давать валидный набор).
    """
    jc = rng.randint(_JC_MIN, _JC_MAX)
    jmin = rng.randint(32, 120)
    jmax = rng.randint(jmin + 32, 512)
    s1 = rng.randint(15, 90)
    s2 = rng.randint(15, 150)
    h = rng.sample(range(1, _UINT32_MAX + 1), 4)
    obf = {
        "Jc": jc, "Jmin": jmin, "Jmax": jmax, "S1": s1, "S2": s2,
        "H1": h[0], "H2": h[1], "H3": h[2], "H4": h[3],
    }
    validate_obfuscation(obf)
    return obf


@dataclass(frozen=True)
class ServerPeer:
    """Peer серверного .conf (клиент). psk=None → строка без PresharedKey."""

    public_key: str
    allowed_ips: str
    psk: Optional[str] = None
    name: str = ""  # комментарий "# <name>" над peer


@dataclass(frozen=True)
class ServerParams:
    """Входы рендера серверного awg-quick .conf (SPEC §3, пример формы)."""

    private_key: str
    address: str = DEFAULT_ADDRESS
    port: int = DEFAULT_PORT
    obf: dict = field(default_factory=dict)
    peers: tuple[ServerPeer, ...] = ()


@dataclass(frozen=True)
class ClientParams:
    """Входы рендера клиентского .conf.

    obf — серверные S1/S2/H1–H4 (идентичные серверу); junk — клиентские
    Jc/Jmin/Jmax (независимы от серверных — факт REQ/vpnsmith).
    """

    private_key: str
    address: str
    server_pubkey: str
    endpoint: str  # host:port
    junk: dict  # Jc/Jmin/Jmax клиента
    obf: dict  # серверные S1/S2/H1..H4
    psk: Optional[str] = None
    allowed_ips: str = DEFAULT_CLIENT_ALLOWED_IPS
    keepalive: int = PERSISTENT_KEEPALIVE


def render_server_conf(params: ServerParams) -> str:
    """Вернуть валидный awg-quick .conf сервера (строка, детерминированно)."""
    validate_obfuscation(params.obf)
    lines = [
        "[Interface]",
        f"Address = {params.address}",
        f"ListenPort = {params.port}",
        f"PrivateKey = {params.private_key}",
        "SaveConfig = false",
    ]
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
        lines.append(f"{key} = {params.obf[key]}")
    for peer in params.peers:
        lines += ["", "[Peer]"]
        if peer.name:
            lines.append(f"# {peer.name}")
        lines.append(f"PublicKey = {peer.public_key}")
        if peer.psk is not None:
            lines.append(f"PresharedKey = {peer.psk}")
        lines.append(f"AllowedIPs = {peer.allowed_ips}")
    return "\n".join(lines) + "\n"


def render_client_conf(params: ClientParams) -> str:
    """Вернуть валидный awg-quick .conf клиента (строка, детерминированно).

    S1/S2/H1–H4 берутся из params.obf (те же, что на сервере); Jc/Jmin/Jmax —
    клиентские (params.junk, свой набор).
    """
    junk = {k: params.junk[k] for k in ("Jc", "Jmin", "Jmax")}
    validate_obfuscation({**params.obf, **junk})
    lines = [
        "[Interface]",
        f"PrivateKey = {params.private_key}",
        f"Address = {params.address}",
    ]
    for key in ("Jc", "Jmin", "Jmax"):
        lines.append(f"{key} = {junk[key]}")
    for key in ("S1", "S2", "H1", "H2", "H3", "H4"):
        lines.append(f"{key} = {params.obf[key]}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {params.server_pubkey}",
    ]
    if params.psk is not None:
        lines.append(f"PresharedKey = {params.psk}")
    lines += [
        f"Endpoint = {params.endpoint}",
        f"AllowedIPs = {params.allowed_ips}",
        f"PersistentKeepalive = {params.keepalive}",
    ]
    return "\n".join(lines) + "\n"


def gen_private_key(tool: str = "awg") -> str:
    """Обёртка-заготовка: `awg genkey` (ключ читается из stdin генерации wg-формата).

    Реальное использование — install.py/clients.py (WP-2/3). Возвращается
    приватный ключ без завершающего перевода строки; неуспех команды —
    subprocess.CalledProcessError (check=True).
    """
    from src.core.shell import run_list  # лениво: тяжёлый импорт не нужен при рендерах

    res = run_list([tool, "genkey"], check=True)
    return res.output


def gen_psk(tool: str = "awg") -> str:
    """Обёртка-заготовка: `awg genpsk` — preshared key (аналог wg genpsk)."""
    from src.core.shell import run_list

    res = run_list([tool, "genpsk"], check=True)
    return res.output
