"""Серверный монитор активного зондирования (Active Probing), исполнитель И33 v1
+ серверная реакция SPEC-20261116-probe-response (threat-level, auto-lockdown).

Ранний сигнал перед TSPU-блокировкой: TSPU перед блоком обычно зондирует
порт протокола. `vds gateway probe-watch` измеряет зондирование боевых
TCP-портов {443, 8443, 2053} (W1-1, SPEC-20261116-probe-coverage) без
изменения конфигов xray/hysteria2 (loglevel/access-log — вне WP):

- nft-таблица `inet vds_probe` (install --apply): счётчики syn_bare (все SYNs
  на 443) и syn_valid (SYNs с пакетом длиннее минимальных 40 б — клиентский
  SYN всегда несёт TCP-опции; голый SYN-сканер (masscan/zmap) — ровно 40),
  аддитивные syn_valid_extra/syn_bare_extra (суммарно 8443+2053, W1-1),
  set probers4 — src-IP зондирований (tcp {443, 8443, 2053}) с per-element
  counter и timeout 1h;
- `watch` (read-only): дельта счётчиков против снапшота
  /var/lib/vds/probe-watch.json (атомарная запись 0600, FileLock) +
  journal-сигнатуры (см. JOURNAL_PATTERNS — только реальные сигнатуры,
  «нелишнее» не парсится: plain-TLS-пробы к 443 уходят в Reality
  dest-fallback и в журнал не пишутся — проверено на asv2);
- verified_session_ips (SPEC-20261116-surface-hardening §1.2, HF-1): IP с
  верифицированными двусторонними сессиями на серверных портах (TCP 443/8443/
  2053 через `ss -tniH` по порогам bytes_acked/bytes_received; UDP 443/51826
  через /proc/net/nf_conntrack по [ASSURED]+bytes) исключаются из new_ru_ips
  вместе с AWG/allow-ips; кэш verified-IP в снапшоте с TTL 24 ч (аффинность
  между тиками — клиент закрыл ноутбук до тика таймера);
- быстрый контур (W1-1, SPEC-20261116-probe-coverage §2): fast_contour_check
  — хук 5-мин сэмплера vds-logs-sample; дельта probers4 за окно сэмпла,
  при >= FAST_CONTOUR_PROBERS уникальных IP — только journal-тег
  FAST-CONTOUR (авто-действий НЕТ); verified-IP пишутся в сайдкар-кэш
  /var/lib/vds/probe-fast-cache.json (0600), часовой watch вливает его в
  own_ips_cache при record (короткие сессии между тиками не теряются);
- RU-классификация IP: если есть агрегат /etc/vds-relay/ru-cidrs.txt
  (пишет relay-cidr или `probe-watch ru-cidr install`), помечает «[RU]»;
  иначе geo: unknown — честно;
- threat-level машина (SPEC §2): quiet/elevated/high с гистерезисом
  (high = RU-PROBE-SUSPECT 2 окна подряд; BURST — максимум elevated),
  decay-выходом из high (72 окна без новых RU-IP, ЗАМОРОЖЕН при активном
  локе 443 — §9.A) и flapping-защитой (даунгрейд не раньше 2 окон после
  апгрейда); собственные клиенты (AWG endpoints + серверный IP + whitelist
  /etc/vds-probe-watch/allow-ips.txt) из new_ru_ips исключаются (§11);
- авто-реакция (opt-in, SPEC §4.2): `config --auto-lockdown on` + тик таймера
  при high → lock-443 (внутренний вызов src/system/ufw); TTL-автоснятие и
  продление — там же (§9.A/§11); downgrade лок НЕ снимает (OQ-3);
- `--explain` (команда explain): честная карта покрытия сигналов на этом
  сервере (что активно, что слепо).

IPv6-пробы — non-goal v1 (см. explain). Read-only watch; мутации —
install/remove/ru-cidr/config с --apply + dry-run по умолчанию; блокировки
FileLock; shell — только run_list.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from rich.markup import escape

from src.core.logger import console
from src.core.shell import ShellResult, run_list

# ---------------------------------------------------------------------------
# Константы (смена — новый ADR, паттерн gateway/paths)
# ---------------------------------------------------------------------------

NFT_TABLE = "vds_probe"
PROBERS_SET = "probers4"
PROBE_NFT_FILE = Path("/etc/vds-probe-watch/nft-probe.conf")
SNAPSHOT_PATH = Path("/var/lib/vds/probe-watch.json")
LOCK_FILE = "/var/run/vds-probe-watch.lock"

PROBE_WATCH_UNIT = "vds-probe-watch.service"
PROBE_WATCH_TIMER = "vds-probe-watch.timer"

# RU-CIDR без релея (SPEC §3): юниты ставит probing_rucidr (импортирует отсюда).
PROBE_RUCIDR_UNIT = "vds-probe-rucidr.service"
PROBE_RUCIDR_TIMER = "vds-probe-rucidr.timer"

XRAY_UNIT = "vds-xray.service"
HYSTERIA2_UNIT = "vds-hysteria2.service"

WATCH_PORT = 443
# SPEC-20261116-probe-coverage W1-1: probers4 и extra-счётчики покрывают
# ВСЕ боевые TCP-порты (Reality 443 + XHTTP 8443 + CDN origin 2053).
# PROBE-BURST-калибровка (syn_valid/syn_bare) остаётся на 443; 8443/2053 —
# аддитивные счётчики syn_valid_extra/syn_bare_extra + тот же set probers4.
EXTRA_TCP_PORTS: tuple[int, ...] = (8443, 2053)
PROBER_TCP_PORTS: tuple[int, ...] = (WATCH_PORT, *EXTRA_TCP_PORTS)
# Минимальный IPv4 SYN: 20 (IP) + 20 (TCP) = 40 б. Клиентский SYN всегда
# длиннее (TCP-опции MSS/SACK/timestamps; TLS-in-SYN у проб — ещё больше).
MIN_CLIENT_SYN_LEN = 40
SET_TIMEOUT = "1h"

DEFAULT_THRESHOLD = 50       # unique probers за окно для PROBE-BURST
BURST_RATIO = 0.90           # доля bare-SYN без payload
BURST_MIN_VOLUME = 100       # минимальный объём SYNs для ratio-критерия
DEFAULT_WINDOW_HOURS = 1
NEW_RU_IPS_THRESHOLD = 2     # новых RU-IP за окно для RU-PROBE-SUSPECT

# --- verified_session_ips (SPEC-20261116-surface-hardening §1.2, HF-1) ---
# Инвариант против «бот ТСПУ проходит handshake»: бот устанавливает
# ESTABLISHED и шлёт ClientHello, но авторизацию VLESS/XHTTP не проходит и
# двусторонний трафик не качает — пороги отсекают его fail-closed.
VERIFIED_TCP_PORTS: tuple[int, ...] = (443, 8443, 2053)  # серверные TCP-порты
VERIFIED_BYTES_ACKED = 16384    # отправлено клиенту (Reality/XHTTP ответ)
VERIFIED_BYTES_RECEIVED = 4096  # получено от клиента
VERIFIED_UDP_PORTS: tuple[int, ...] = (443, 51826)  # Hy2 443/udp + hop
CONNTRACK_BYTES_MIN = 32768     # bytes_orig+bytes_reply при nf_conntrack_acct=1
NF_CONNTRACK_PROC = Path("/proc/net/nf_conntrack")
OWN_IPS_CACHE_TTL_H = 24        # аффинность verified-IP между тиками watch

# --- быстрый контур детекта серий ТСПУ (SPEC-20261116-probe-coverage §2) ---
# Хук в 5-мин сэмплере vds-logs-sample (ADR-012), НЕ новый демон и НЕ новая
# реакция: только телеметрия-тег в journal, авто-lockdown остаётся
# прерогативой часового probe-watch. Кэш сайдкара — ОТДЕЛЬНЫЙ файл; снапшот
# probe-watch.json быстрый контур не пишет никогда (инвариант ADR-014:
# watch --json без --record не мутирует snapshot).
FAST_CONTOUR_PROBERS = 10       # уникальных probers/5 мин для тега (потом конфиг)
FAST_CACHE_PATH = Path("/var/lib/vds/probe-fast-cache.json")
FAST_LOCK_FILE = "/var/run/vds-probe-fast.lock"

# --- threat-level машина (SPEC-20261116-probe-response §2, §9.A, §11) ---
THREAT_QUIET = "quiet"
THREAT_ELEVATED = "elevated"
THREAT_HIGH = "high"
HIGH_STREAK = 2              # окон RU-PROBE-SUSPECT подряд для входа в high
HIGH_EXIT_WINDOWS = 72       # окнов без новых RU-IP для выхода из high (decay)
ELEVATED_QUIET_EXIT = 3      # тихих окон подряд для выхода из elevated
FLAP_GUARD_WINDOWS = 2       # даунгрейд не раньше 2 окон после апгрейда

# Ручной whitelist «своих» IP (§11): по строке IP, комментарии #.
OWN_IPS_FILE = Path("/etc/vds-probe-watch/allow-ips.txt")

# RU-CIDR-агрегат пишется relay-модулем (src/relay/cidr.py) или командой
# `probe-watch ru-cidr install` (probing_rucidr.py, SPEC §3). Зависимость
# НЕ ставится: читаем только файл по пути (тот же контракт агрегации).
RU_CIDR_FILE = Path("/etc/vds-relay/ru-cidrs.txt")

# Паттерны журнала — ТОЛЬКО реальные сигнатуры (документированы):
# - xray: plain-TLS-пробы к 443 в журнал не пишутся (loglevel warning, access
#   log выключен — проверено на asv2, Xray 26.1.23); "REALITY: processed
#   invalid connection" появляется только при повышенном loglevel — паттерн
#   держим на будущее, в explain помечаем как невидимый при default.
# - hysteria2: квантум auth-ошибок от одного IP.
# - kernel: UFW BLOCK на 443 пачками от одного IP.
JOURNAL_PATTERNS: dict[str, list[dict[str, Any]]] = {
    XRAY_UNIT: [
        {
            "name": "reality_invalid",
            "pattern": re.compile(r"REALITY.*processed invalid connection", re.IGNORECASE),
            "note": "виден только при повышенном loglevel (default warning не пишет)",
        },
    ],
    HYSTERIA2_UNIT: [
        {
            "name": "hysteria_auth_fail",
            "pattern": re.compile(
                r"(?i)(auth(entication)?[^.]{0,20}(fail|denied|invalid)|unknown (user|identity|client))"
            ),
            "note": "auth-ошибки — зондирование с неверным паролем",
        },
    ],
    "kernel": [
        {
            "name": "ufw_block_443",
            "pattern": re.compile(r"\[UFW BLOCK\].*\bDPT=443\b"),
            "note": "kernel-лог: пачка DROP на 443 от одного IP",
        },
    ],
}

UFW_SRC_RE = re.compile(r"\bSRC=(\d{1,3}(?:\.\d{1,3}){3})")

RunFn = Callable[..., ShellResult]


# ---------------------------------------------------------------------------
# Чистые функции (тестируются без root/сети)
# ---------------------------------------------------------------------------

def render_nft(per_element_counter: bool = True) -> str:
    """Текст nft-файла (источник истины таблицы inet vds_probe).

    Ревью 2026-11-15 (живая установка на asv2): анонимные counter в правилах
    НЕ инкрементируют именованные объекты — все правила используют
    `counter name "<имя>"`; set-элемент обновляется через `update @set
    { ip saddr }` (инкремент встроенного счётчика элемента + refresh
    timeout), БЕЗ слова counter внутри (иначе "counter counter"). Set:
    `flags dynamic, timeout` (dynamic обязателен для добавления из правила)
    + `size 65535`; декларация counter в set — один раз при
    per_element_counter=True.

    per_element_counter=False — fallback для ядер без counter в set-элементе
    (тогда только уникальные IP, без счётчиков на IP; explain честно покажет).
    Файл применяется целиком (`nft -f`): install предварительно удаляет
    существующую таблицу — повторный apply даёт то же состояние (счётчики
    сбрасываются, что для монитора нештатно только при переустановке).
    """
    set_counter = "        counter\n" if per_element_counter else ""
    # W1-1: один named set на все боевые TCP-порты; фильтр ip length > 40 —
    # в probers4 идут только «клиентоподобные» SYN (с TCP-опциями/payload),
    # голый masscan-шум в set не попадает (объём шума виден по счётчикам).
    prober_ports = ", ".join(str(p) for p in PROBER_TCP_PORTS)
    prober_rule = (
        f"tcp dport {{ {prober_ports} }} tcp flags & (fin|syn|rst|ack) == syn "
        f"ip length > {MIN_CLIENT_SYN_LEN} update @{PROBERS_SET} {{ ip saddr }}"
    )
    # Правила для 443 — БАЙТ-В-БАЙТ прежние (калибровка PROBE-BURST и
    # история порогов не ломаются); extra-счётчики — по тому же принципу
    # (syn_bare_extra, как и syn_bare, БЕЗ ip-length-фильтра: bare+valid).
    extra_ports = ", ".join(str(p) for p in EXTRA_TCP_PORTS)
    return (
        "#!/usr/sbin/nft -f\n"
        "# Managed by `vds gateway probe-watch install` — DO NOT EDIT.\n"
        "# Монитор активного зондирования tcp/{443,8443,2053} + udp/443 (IPv4, non-goal v6).\n"
        "table inet " + NFT_TABLE + " {\n"
        f"    counter syn_bare {{ }}\n"
        f"    counter syn_valid {{ }}\n"
        f"    counter udp_443 {{ }}\n"
        f"    counter syn_valid_extra {{ }}\n"
        f"    counter syn_bare_extra {{ }}\n"
        f"    set {PROBERS_SET} {{\n"
        "        type ipv4_addr\n"
        "        flags dynamic, timeout\n"
        f"        timeout {SET_TIMEOUT}\n"
        f"{set_counter}"
        "        size 65535\n"
        "    }\n"
        "    chain input_hook {\n"
        "        type filter hook input priority -140; policy accept;\n"
        f"        {prober_rule}\n"
        f"        tcp dport {WATCH_PORT} tcp flags & (fin|syn|rst|ack) == syn "
        f"ip length > {MIN_CLIENT_SYN_LEN} counter name \"syn_valid\"\n"
        f"        tcp dport {WATCH_PORT} tcp flags & (fin|syn|rst|ack) == syn "
        f"counter name \"syn_bare\"\n"
        f"        tcp dport {{ {extra_ports} }} tcp flags & (fin|syn|rst|ack) == syn "
        f"ip length > {MIN_CLIENT_SYN_LEN} counter name \"syn_valid_extra\"\n"
        f"        tcp dport {{ {extra_ports} }} tcp flags & (fin|syn|rst|ack) == syn "
        f"counter name \"syn_bare_extra\"\n"
        f"        udp dport {WATCH_PORT} counter name \"udp_443\"\n"
        "    }\n"
        "}\n"
    )


_COUNTER_RE = re.compile(
    r"counter\s+(\w+)\s*\{[^}]*?packets\s+(\d+)\s+bytes\s+(\d+)", re.DOTALL
)
_ELEMENTS_BLOCK_RE = re.compile(r"elements\s*=\s*\{([^}]*)\}", re.DOTALL)
_ELEMENT_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})(?:\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+))?"
)


def _set_has_counter_decl(text: str) -> bool:
    """Декларирован ли per-element `counter` в блоке `set probers4 { ... }`.

    Ревью 2026-11-16, edge-case 2: признак определяем по ДЕКЛАРАЦИИ, а не по
    наличию элементов — пустой set с counter в декларации поддерживает
    счётчики на IP (explain не должен врать «не поддерживается ядром»).
    """
    idx = text.find(f"set {PROBERS_SET} {{")
    if idx == -1:
        return False
    rest = text[idx:]
    # Граница блока set: следующая топ-секция таблицы (chain) или конец таблицы.
    m = re.search(r"\n\s*(chain |}\s*$)", rest, re.MULTILINE)
    block = rest[: m.start()] if m else rest
    return re.search(r"^\s+counter\s*$", block, re.MULTILINE) is not None


@dataclass
class NftState:
    """Распарсенное состояние nft-таблицы монитора (read-only)."""

    syn_bare: int = 0
    syn_valid: int = 0
    udp_443: int = 0
    # W1-1 (аддитивно): 8443+2053 суммарно; в старых таблицах (до W1-1) — 0.
    syn_valid_extra: int = 0
    syn_bare_extra: int = 0
    probers: dict[str, int] = field(default_factory=dict)  # ip -> packets
    per_element_counters: bool = False


def parse_nft_table(text: str) -> NftState:
    """Разобрать вывод `nft list table inet vds_probe`.

    per_element_counters — по декларации `counter` в блоке set (см.
    _set_has_counter_decl): пустой set с декларацией = счётчики на IP
    поддерживаются. Элементы без счётчиков (fallback-вариант) — packets=0.
    """
    state = NftState()
    state.per_element_counters = _set_has_counter_decl(text)
    for match in _COUNTER_RE.finditer(text):
        name, packets = match.group(1), int(match.group(2))
        if name == "syn_bare":
            state.syn_bare = packets
        elif name == "syn_valid":
            state.syn_valid = packets
        elif name == "udp_443":
            state.udp_443 = packets
        elif name == "syn_valid_extra":
            state.syn_valid_extra = packets
        elif name == "syn_bare_extra":
            state.syn_bare_extra = packets
    block = _ELEMENTS_BLOCK_RE.search(text)
    if block:
        for item in _ELEMENT_RE.finditer(block.group(1)):
            ip = item.group(1)
            packets = int(item.group(2) or 0)
            state.probers[ip] = packets
    return state


def nft_table_exists(run: RunFn = run_list) -> bool:
    """Есть ли таблица в `nft list tables` (read-only)."""
    res = run(["nft", "list", "tables"], timeout=10)
    return res.ok and f"table inet {NFT_TABLE}" in res.stdout


def list_nft_table(run: RunFn = run_list) -> Optional[NftState]:
    """Текущее состояние таблицы; None — таблица отсутствует/не читается."""
    res = run(["nft", "list", "table", "inet", NFT_TABLE], timeout=15)
    if not res.ok:
        return None
    return parse_nft_table(res.stdout)


# ---------------------------------------------------------------------------
# Снапшот (атомарная запись 0600, читается watch-ом)
# ---------------------------------------------------------------------------

SNAPSHOT_VERSION = 2  # v2: + threat/config/own_ips (SPEC-20261116-probe-response)


def _empty_snapshot() -> dict[str, object]:
    """База снапшота: все нули + пустые threat/config/own_ips (не ошибка)."""
    return {
        "version": SNAPSHOT_VERSION,
        "ts": "",
        "syn_bare": 0,
        "syn_valid": 0,
        "udp_443": 0,
        "syn_valid_extra": 0,
        "syn_bare_extra": 0,
        "probers": {},
        "threat": {},
        "config": {},
        "own_ips": {},
        "own_ips_cache": [],
    }


def load_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, object]:
    """Прочитать снапшот; отсутствует/бит — пустой (все нули, не ошибка).

    v1-снапшоты (без threat/config/own_ips) читаются: недостающие ключи
    добираются пустыми — состояние переживает эволюцию формата.
    """
    if not path.is_file():
        return _empty_snapshot()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return _empty_snapshot()
    if not isinstance(data, dict):
        return _empty_snapshot()
    probers = data.get("probers")
    if not isinstance(probers, dict):
        probers = {}
    threat = data.get("threat")
    config = data.get("config")
    own_ips = data.get("own_ips")
    snap = {
        "version": data.get("version", SNAPSHOT_VERSION),
        "ts": str(data.get("ts", "")),
        "syn_bare": int(data.get("syn_bare", 0) or 0),
        "syn_valid": int(data.get("syn_valid", 0) or 0),
        "udp_443": int(data.get("udp_443", 0) or 0),
        "syn_valid_extra": int(data.get("syn_valid_extra", 0) or 0),
        "syn_bare_extra": int(data.get("syn_bare_extra", 0) or 0),
        "probers": {str(k): int(v or 0) for k, v in probers.items()},
        "threat": threat if isinstance(threat, dict) else {},
        "config": config if isinstance(config, dict) else {},
        "own_ips": own_ips if isinstance(own_ips, dict) else {},
    }
    snap["own_ips_cache"] = own_ips_cache_entries(data)
    return snap


def write_snapshot_payload(payload: dict[str, object], path: Path) -> bool:
    """Атомарно записать произвольный payload снапшота (0600). True — успех."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        console.print(f"[error][probe] Не удалось записать снапшот {path}: {exc}[/error]")
        return False


def save_snapshot(
    current: NftState,
    path: Path = SNAPSHOT_PATH,
    extra: Optional[dict[str, object]] = None,
) -> bool:
    """Атомарно записать снапшот (tmp + os.replace, права 0600). True — успех.

    extra — дополнительные ключи поверх счётчиков (threat/config/own_ips):
    тик таймера передаёт обновлённую машину threat-level и конфиг, чтобы
    состояние переживало рестарт юнита (SPEC §2).
    """
    payload: dict[str, object] = {
        "version": SNAPSHOT_VERSION,
        "ts": datetime.now().isoformat(timespec="seconds"),
        "syn_bare": current.syn_bare,
        "syn_valid": current.syn_valid,
        "udp_443": current.udp_443,
        "syn_valid_extra": current.syn_valid_extra,
        "syn_bare_extra": current.syn_bare_extra,
        "probers": current.probers,
    }
    if extra:
        payload.update(extra)
    return write_snapshot_payload(payload, path)


@dataclass
class Delta:
    """Дельта счётчиков за окно (текущее минус снапшот).

    syn_valid_extra/syn_bare_extra — аддитивная телеметрия 8443+2053
    (W1-1): в вердиктах НЕ участвуют (PROBE-BURST-калибровка — только 443).
    """

    syn_bare: int
    syn_valid: int
    udp_443: int
    bare_no_payload: int
    ratio_no_payload: Optional[float]
    unique_probers: int
    syn_valid_extra: int = 0
    syn_bare_extra: int = 0
    top: list[tuple[str, int]] = field(default_factory=list)  # (ip, delta)


def compute_delta(current: NftState, snapshot: dict[str, object]) -> Delta:
    """Дельта за окно; у снапшота всё как честные нули, если он пуст/бит.

    unique_probers: с per-element счётчиками — IP с положительной дельтой;
    без них (packets=0 у всех) — размер set (элементы живут timeout 1h,
    т.е. множество ≈ пробы за последний час) — это fallback, объясняем
    в выводе.

    Протухший элемент (packets < значения в снапшоте): элемент истёк по
    timeout и пересоздан `update @set` — его дельта = packets (не терять IP).
    """
    raw_probers = snapshot.get("probers")
    snap_probers: dict[str, int] = (
        {str(k): int(v) for k, v in dict(raw_probers).items()}
        if isinstance(raw_probers, dict)
        else {}
    )

    def _win(cur: int, prev: int) -> int:
        # Ревью 2026-11-16, edge-case 3a: cur < prev — счётчики сброшены
        # (ребут/переустановка таблицы), вся текущая часть — за окно
        # (те же правила, что для протухшего set-элемента).
        return cur if cur < prev else cur - prev

    delta_bare = _win(current.syn_bare, int(snapshot.get("syn_bare", 0)))
    delta_valid = _win(current.syn_valid, int(snapshot.get("syn_valid", 0)))
    delta_udp = _win(current.udp_443, int(snapshot.get("udp_443", 0)))
    delta_valid_extra = _win(
        current.syn_valid_extra, int(snapshot.get("syn_valid_extra", 0))
    )
    delta_bare_extra = _win(
        current.syn_bare_extra, int(snapshot.get("syn_bare_extra", 0))
    )
    bare_no_payload = max(0, delta_bare - delta_valid)
    ratio = bare_no_payload / delta_bare if delta_bare > 0 else None

    per_element = current.per_element_counters
    deltas: dict[str, int] = {}
    if per_element:
        for ip, packets in current.probers.items():
            prev = snap_probers.get(ip, 0)
            # Ревью 2026-11-15: packets < prev — элемент протух/пересоздан,
            # его счётчик заново с нуля; вся часть packets — за окно.
            d = packets if packets < prev else packets - prev
            if d > 0:
                deltas[ip] = d
    else:
        # Fallback: per-element счётчиков нет — считаем по составу set.
        deltas = {ip: 0 for ip in current.probers}
    unique = len(deltas)
    top = sorted(deltas.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return Delta(
        syn_bare=delta_bare,
        syn_valid=delta_valid,
        udp_443=delta_udp,
        bare_no_payload=bare_no_payload,
        ratio_no_payload=ratio,
        unique_probers=unique,
        syn_valid_extra=delta_valid_extra,
        syn_bare_extra=delta_bare_extra,
        top=top,
    )


@dataclass
class Verdict:
    """Вердикт по окну: RU-PROBE-SUSPECT / PROBE-BURST / quiet + причины."""

    name: str  # "RU-PROBE-SUSPECT" | "PROBE-BURST" | "quiet"
    reasons: list[str] = field(default_factory=list)


def compute_verdict(
    delta: Delta,
    threshold: int,
    new_ru_ips: Optional[list[str]] = None,
    ru_available: bool = False,
    syn_valid_total: int = 0,
) -> Verdict:
    """Вердикты окна (границы тестируются):

    - **RU-PROBE-SUSPECT** (приоритет): RU-CIDR доступен, в окне были
      легитимные (длиннее 40 б) SYN — syn_valid_total=delta.syn_valid > 0
      (окно, не аптайм; окно из одних голых masscan-SYN SUSPECT не даёт,
      ревью 2026-11-16 3c-iii) — и новых IP из RU-зоны (не из снапшота,
      не свой IP сервера) >= NEW_RU_IPS_THRESHOLD. Ловит профиль ТСПУ:
      точечное зондирование с RU-адресов даже при 2–5 шт/час.
    - **PROBE-BURST**: unique_probers >= threshold ИЛИ ratio bare-no-payload
      >= 0.90 при объёме SYNs > 100.
    - иначе quiet. При одновременном срабатывании — RU-PROBE-SUSPECT с
      обеими группами причин.
    """
    reasons: list[str] = []
    if delta.unique_probers >= threshold:
        reasons.append(
            f"уникальных пробующих IP за окно {delta.unique_probers} >= {threshold}"
        )
    if (
        delta.ratio_no_payload is not None
        and delta.ratio_no_payload >= BURST_RATIO
        and delta.syn_bare > BURST_MIN_VOLUME
    ):
        reasons.append(
            f"доля bare-SYN без payload {delta.ratio_no_payload:.0%} "
            f"(объём {delta.syn_bare} > {BURST_MIN_VOLUME})"
        )
    burst = bool(reasons)

    new_ru = list(new_ru_ips or [])
    if ru_available and syn_valid_total > 0 and len(new_ru) >= NEW_RU_IPS_THRESHOLD:
        reasons.insert(
            0,
            f"новых IP из RU-зоны за окно: {len(new_ru)} >= {NEW_RU_IPS_THRESHOLD} "
            f"({', '.join(new_ru[:5])}{'…' if len(new_ru) > 5 else ''})",
        )
        return Verdict("RU-PROBE-SUSPECT", reasons)
    return Verdict("PROBE-BURST" if burst else "quiet", reasons)


# ---------------------------------------------------------------------------
# Машина threat-level (SPEC-20261116-probe-response §2, §9.A, §10, §11)
# ---------------------------------------------------------------------------


@dataclass
class ThreatState:
    """Состояние машины threat-level; переживает рестарт юнита (в снапшоте).

    - ru_streak: окон RU-PROBE-SUSPECT подряд (гистерезис входа в high);
    - quiet_streak: тихих окон подряд (выход из elevated: 3);
    - decay: окнов в high без новых RU-IP (выход: 72; ЗАМОРОЖЕН при
      lockdown.active — §9.A: лок ослепляет syn_valid, RU-SUSPECT повторно
      не сработает, счётчик должен тикать только после unlock);
    - windows_at_level: окон, проведённых на текущем уровне (flapping-защита:
      даунгрейд не раньше 2 окон после апгрейда).
    """

    level: str = THREAT_QUIET
    reason: str = ""
    since: str = ""
    ru_streak: int = 0
    quiet_streak: int = 0
    decay: int = 0
    windows_at_level: int = 0
    updated: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "reason": self.reason,
            "since": self.since,
            "ru_streak": self.ru_streak,
            "quiet_streak": self.quiet_streak,
            "decay": self.decay,
            "windows_at_level": self.windows_at_level,
            "updated": self.updated,
        }

    @classmethod
    def from_dict(cls, data: object) -> "ThreatState":
        raw = data if isinstance(data, dict) else {}
        level = str(raw.get("level", THREAT_QUIET))
        if level not in (THREAT_QUIET, THREAT_ELEVATED, THREAT_HIGH):
            level = THREAT_QUIET
        return cls(
            level=level,
            reason=str(raw.get("reason", "")),
            since=str(raw.get("since", "")),
            ru_streak=int(raw.get("ru_streak", 0) or 0),
            quiet_streak=int(raw.get("quiet_streak", 0) or 0),
            decay=int(raw.get("decay", 0) or 0),
            windows_at_level=int(raw.get("windows_at_level", 0) or 0),
            updated=str(raw.get("updated", "")),
        )


def update_threat(
    prev: ThreatState,
    *,
    verdict: str,
    new_ru_count: int,
    ru_available: bool,
    lockdown_active: bool,
    now: Optional[datetime] = None,
) -> ThreatState:
    """Один переход машины (чистая функция, тестируется без root/сети).

    Правила SPEC §2 + §9.A + §10 + §11:
    - elevated: 1 окно PROBE-BURST ИЛИ 1 окно RU-PROBE-SUSPECT; выход —
      3 тихих окна подряд;
    - high: RU-PROBE-SUSPECT 2 окна подряд (BURST сам по себе — шум,
      максимум elevated); выход — 72 окна без новых RU-IP → elevated →
      ещё 3 тихих → quiet; decay заморожен при lockdown.active;
    - high недостижим при geo unknown (threat_reason объясняет);
    - flapping-защита: даунгрейд не раньше 2 окон после апгрейда.
    """
    ru_hit = verdict == "RU-PROBE-SUSPECT"
    burst = verdict == "PROBE-BURST"
    quiet = verdict == "quiet"
    stamp = (now or datetime.now()).isoformat(timespec="seconds")
    nxt = ThreatState(**{**prev.to_dict()})  # копия; from_dict уже нормализована
    nxt.updated = stamp

    def _enter(level: str, reason: str) -> None:
        nxt.level = level
        nxt.reason = reason
        nxt.since = stamp
        nxt.ru_streak = 0
        nxt.quiet_streak = 0
        nxt.decay = 0
        nxt.windows_at_level = 0

    if not ru_available and ru_hit:
        # защита от рассинхрона: вердикт SUSPECT без RU-агрегата не бывает
        # (compute_verdict гейтит), но машина не зависит от этого заказа.
        ru_hit = False

    if prev.level == THREAT_QUIET:
        if ru_hit:
            _enter(THREAT_ELEVATED, "RU-PROBE-SUSPECT (1 окно)")
            nxt.ru_streak = 1
        elif burst:
            _enter(THREAT_ELEVATED, "PROBE-BURST")
        else:
            nxt.reason = ""
        _note_geo_unknown(nxt, ru_available)
        return nxt

    if prev.level == THREAT_ELEVATED:
        if ru_hit:
            nxt.ru_streak = prev.ru_streak + 1
            nxt.quiet_streak = 0
            nxt.windows_at_level = prev.windows_at_level + 1
            if nxt.ru_streak >= HIGH_STREAK:
                _enter(THREAT_HIGH, f"RU-PROBE-SUSPECT {nxt.ru_streak} окна подряд")
            else:
                nxt.reason = f"RU-PROBE-SUSPECT ({nxt.ru_streak} окн.)"
            _note_geo_unknown(nxt, ru_available)
            return nxt
        if burst:
            nxt.quiet_streak = 0
            nxt.ru_streak = 0
            nxt.windows_at_level = prev.windows_at_level + 1
            nxt.reason = "PROBE-BURST"
            return nxt
        # тихое окно: кандидат на exit — flap-guard не даёт даунгрейд раньше 2 окон
        nxt.quiet_streak = prev.quiet_streak + 1
        nxt.ru_streak = 0
        nxt.windows_at_level = prev.windows_at_level + 1
        if nxt.quiet_streak >= ELEVATED_QUIET_EXIT and nxt.windows_at_level >= FLAP_GUARD_WINDOWS:
            _enter(THREAT_QUIET, "")
        else:
            nxt.reason = prev.reason or "elevated"
        _note_geo_unknown(nxt, ru_available)
        return nxt

    # prev.level == high
    if new_ru_count > 0:
        # любой новый RU-IP (даже ниже порога SUSPECT) обнуляет decay-отсчёт
        nxt.decay = 0
        nxt.reason = prev.reason or "high"
    elif lockdown_active:
        # §9.A: заморозка decay — лок ослепляет syn_valid, тикать начнёт
        # только после unlock; окно не считается «тихим без новых RU».
        nxt.reason = (prev.reason or "high") + " [decay заморожен: lockdown]"
    else:
        nxt.decay = prev.decay + 1
        nxt.reason = prev.reason or "high"
    nxt.ru_streak = prev.ru_streak
    nxt.quiet_streak = 0
    nxt.windows_at_level = prev.windows_at_level + 1
    if ru_hit:
        nxt.ru_streak = prev.ru_streak + 1
    if (
        not lockdown_active
        and nxt.decay >= HIGH_EXIT_WINDOWS
        and nxt.windows_at_level >= FLAP_GUARD_WINDOWS
    ):
        _enter(THREAT_ELEVATED, f"выход из high: {HIGH_EXIT_WINDOWS} окон без новых RU-IP")
    return nxt


def _note_geo_unknown(state: ThreatState, ru_available: bool) -> None:
    """§2: при geo unknown high недостижим — threat_reason обязан объяснить почему."""
    if ru_available or state.level != THREAT_ELEVATED:
        return
    if "недостижим" not in state.reason:
        state.reason = (
            f"{state.reason} " if state.reason else ""
        ) + "geo: unknown (RU-CIDR недоступен) — high недостижим"


# ---------------------------------------------------------------------------
# Исключение собственных клиентов из new_ru_ips (SPEC §11)
# ---------------------------------------------------------------------------

_ENDPOINT_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):\d+\b")


def parse_awg_endpoints(text: str) -> list[str]:
    """`awg show <iface> endpoints` → endpoint-IP пиров (без портов).

    Формат вывода — строка на пира: "<pubkey>\\t<ip>:<port>" (или '(none)');
    нужен ТОЛЬКО endpoint-IP, ключи не читаются (§11: без root-чтения секретов).
    Битые/loopback строки пропускаются построчно.
    """
    ips: list[str] = []
    for line in text.splitlines():
        for match in _ENDPOINT_IP_RE.finditer(line):
            ip = match.group(1)
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            if ip not in ips:
                ips.append(ip)
    return ips


def read_awg_endpoints(run: RunFn = run_list, iface: str = "awg0") -> list[str]:
    """Endpoint-IP активных AWG-пиров (root; сбой → [] — используем кэш снапшота)."""
    res = run(["awg", "show", iface, "endpoints"], timeout=10)
    if not res.ok:
        return []
    return parse_awg_endpoints(res.stdout)


def load_own_ips(path: Optional[Path] = None) -> set[str]:
    """Ручной whitelist своих IP: по строке IP, комментарии #/пустые — пропуск."""
    path = path or OWN_IPS_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    own: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue  # мусорная строка — пропуск, не валим файл
        if not addr.is_loopback:
            own.add(line)
    return own


def cached_own_ips(snapshot: dict[str, object]) -> list[str]:
    """Кэш AWG-endpoints из снапшота (ручной watch без root читает кэш тика)."""
    raw = snapshot.get("own_ips")
    if not isinstance(raw, dict):
        return []
    ips = raw.get("ips")
    return [str(i) for i in ips] if isinstance(ips, list) else []


# ---------------------------------------------------------------------------
# verified_session_ips (SPEC-20261116-surface-hardening §1.2, HF-1)
# ---------------------------------------------------------------------------

_SS_BYTES_ACKED_RE = re.compile(r"\bbytes_acked:(\d+)\b")
_SS_BYTES_RECEIVED_RE = re.compile(r"\bbytes_received:(\d+)\b")
_CT_SRC_RE = re.compile(r"\bsrc=(\d{1,3}(?:\.\d{1,3}){3})\b")
_CT_DPORT_RE = re.compile(r"\bdport=(\d+)\b")
# Реальное ядро Linux в /proc/net/nf_conntrack печатает ДВА кортежа (original
# и reply) с одинаковым полем bytes= в одной строке: "bytes=12345 ... bytes=0".
# Суффиксированные формы (bytes_orig=/bytes_reply=) встречаются в выводе
# утилиты conntrack — поддерживаем обе (регресс-фикс ревью HF-1).
_CT_BYTES_RE = re.compile(r"\bbytes(?:_orig|_reply)?=(\d+)\b")


def _normalize_client_ip(host: str) -> Optional[str]:
    """IPv4-ключ probers4 из адреса ss/conntrack: срезать ::ffff: (dual-stack
    listener Xray/Hy2 показывает клиента как IPv4-mapped IPv6), взять только
    IPv4 (v6 — non-goal v1); loopback/мусор — None."""
    host = host.strip().strip("[]")
    if host.startswith("::ffff:"):
        host = host[len("::ffff:"):]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.version != 4 or addr.is_loopback:
        return None
    return host


def parse_ss_verified(
    text: str, ports: tuple[int, ...] = VERIFIED_TCP_PORTS
) -> set[str]:
    """Парсер `ss -tniH`: IP пиров с двусторонним трафиком (fail-closed).

    Строки ss идут ПАРАМИ: адресная строка + индентированная строка метрик
    сокета (bytes_acked/bytes_received печатаются только на второй). Регулярка
    склеивает пару: адресная строка запоминает (local, peer), метрики
    подтверждают. Строка метрик без ОБОИХ bytes-полей (кривой вывод, не -ti) —
    сокет игнорируется (fail-closed, не исключение): голый ESTABLISHED бот
    ТСПУ не должен верифицироваться. Локальный порт обязан быть серверным
    (443/8443/2053) — исходящие сессии сервера не считаются.
    """
    portset = {str(p) for p in ports}
    verified: set[str] = set()
    pending: Optional[tuple[str, str]] = None  # (local addr:port, peer addr:port)
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        indented = raw_line[:1] in (" ", "\t")
        if not indented:
            # Адресная строка: ... local_addr:port peer_addr:port (последние
            # два токена; ss не печатает заголовок при -H).
            parts = raw_line.split()
            if len(parts) < 2:
                pending = None
                continue
            pending = (parts[-2], parts[-1])
            continue
        if pending is None:
            continue
        acked = _SS_BYTES_ACKED_RE.search(raw_line)
        received = _SS_BYTES_RECEIVED_RE.search(raw_line)
        local, peer = pending
        pending = None
        if acked is None or received is None:
            continue  # fail-closed: без обоих bytes-полей сокет не верифицируем
        _, _, local_port = local.rpartition(":")
        peer_host, _, _ = peer.rpartition(":")
        if local_port not in portset:
            continue
        ip = _normalize_client_ip(peer_host)
        if ip is None:
            continue
        if (
            int(acked.group(1)) >= VERIFIED_BYTES_ACKED
            and int(received.group(1)) >= VERIFIED_BYTES_RECEIVED
        ):
            verified.add(ip)
    return verified


def read_verified_session_ips(
    ports: tuple[int, ...] = VERIFIED_TCP_PORTS, run: RunFn = run_list
) -> set[str]:
    """IP с верифицированными TCP-сессиями на серверных портах (root, read-only).

    Сбой ss — пустое множество (тихая деградация: остаётся AWG+allow+кэш).
    """
    sport_expr = " or ".join(f"sport = :{p}" for p in ports)
    res = run(
        ["ss", "-tniH", "state", "established", f"( {sport_expr} )"], timeout=15
    )
    if not res.ok:
        return set()
    return parse_ss_verified(res.stdout, ports)


def parse_conntrack_udp(
    text: str, udp_ports: tuple[int, ...] = VERIFIED_UDP_PORTS
) -> set[str]:
    """Парсер /proc/net/nf_conntrack: src-IP UDP-сессий на серверные порты.

    Первая пара src=/dport= в строке — направление клиент→сервер. Требования
    (SPEC §1.2): [ASSURED] всегда; при наличии bytes_orig+bytes_reply
    (nf_conntrack_acct=1) — их сумма > CONNTRACK_BYTES_MIN; полей нет
    (acct=0) — фолбэк на один [ASSURED] (ядро ставит его только при
    двустороннем обмене — в QUIC/Hysteria2 это признак живого клиента).
    Битые строки пропускаются построчно (fail-closed, не исключение).
    """
    portset = {str(p) for p in udp_ports}
    verified: set[str] = set()
    for line in text.splitlines():
        tokens = line.split()
        if "udp" not in tokens[:5]:
            continue
        src = _CT_SRC_RE.search(line)
        dport = _CT_DPORT_RE.search(line)
        if src is None or dport is None or dport.group(1) not in portset:
            continue
        if "[ASSURED]" not in line:
            continue
        byte_values = _CT_BYTES_RE.findall(line)
        if len(byte_values) >= 2:
            # Ядро: bytes=<orig> ... bytes=<reply> (два кортежа в строке);
            # conntrack(8): bytes_orig=<n> bytes_reply=<n>. Сравниваем с порогом
            # сумму первых двух значений (orig+reply).
            if int(byte_values[0]) + int(byte_values[1]) <= CONNTRACK_BYTES_MIN:
                continue
        elif len(byte_values) == 1:
            continue  # кривая строка (одно поле) — fail-closed
        ip = _normalize_client_ip(src.group(1))
        if ip is not None:
            verified.add(ip)
    return verified


def read_conntrack_verified(
    path: Path = NF_CONNTRACK_PROC,
) -> tuple[set[str], bool]:
    """(verified-UDP-IP, файл доступен). Файла нет / не читается —
    (пусто, False): тихая деградация до TCP+AWG+кэш (тег в выводе watch)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set(), False
    return parse_conntrack_udp(text), True


def own_ips_cache_entries(snapshot: dict[str, object]) -> list[list[str]]:
    """Нормализованный кэш verified-IP из снапшота: [[ip, last_seen_iso], ...].

    Битые записи (не пара строк) отбрасываются построчно — кэш переживает
    эволюцию формата и ручные правки файла.
    """
    raw = snapshot.get("own_ips_cache")
    if not isinstance(raw, list):
        return []
    entries: list[list[str]] = []
    for item in raw:
        if (
            isinstance(item, (list, tuple))
            and len(item) == 2
            and isinstance(item[0], str)
            and isinstance(item[1], str)
        ):
            entries.append([item[0], item[1]])
    return entries


def _cache_seen(ts: str, now: datetime) -> bool:
    """last_seen внутри TTL 24 ч; битая/несовместимая метка — считаем протухшей."""
    try:
        seen = datetime.fromisoformat(ts)
        return now - seen <= timedelta(hours=OWN_IPS_CACHE_TTL_H)
    except (ValueError, TypeError):
        return False


def active_cache_ips(entries: list[list[str]], now: datetime) -> set[str]:
    """IP кэша с непротухшим last_seen (< 24 ч)."""
    return {ip for ip, ts in entries if _cache_seen(ts, now)}


def merge_own_ips_cache(
    entries: list[list[str]], verified: set[str], now: datetime
) -> list[list[str]]:
    """Новый кэш для записи: живые (< 24 ч) записи + свежие verified.

    last_seen верифицированного в этом окне IP обновляется на now — кэш не
    протухает у постоянно подключённого клиента даже когда сокет закрылся
    между тиками. Записи старше TTL и битые метки удаляются (чистка при
    каждом record-тике). Сортировка по IP — детерминизм файла.
    """
    stamp = now.isoformat(timespec="seconds")
    merged: dict[str, str] = {}
    for ip, ts in entries:
        if ip in verified:
            continue  # перезапишется свежей меткой ниже
        if _cache_seen(ts, now):
            merged[ip] = ts
    for ip in verified:
        merged[ip] = stamp
    return [[ip, merged[ip]] for ip in sorted(merged)]


def merge_cache_entries(
    a: list[list[str]], b: list[list[str]]
) -> list[list[str]]:
    """Объединение двух кэшей [[ip, last_seen_iso], ...] по ip с max(last_seen).

    ISO-метки лексикографически сортируемы (timespec=seconds) — сравнение
    строк корректно. Битые записи отфильтрованы ранее (own_ips_cache_entries);
    здесь на всякий случай пропускаются не-пары. Детерминизм — сортировка IP.
    """
    merged: dict[str, str] = {}
    for ip, ts in list(a) + list(b):
        if ip not in merged or ts > merged[ip]:
            merged[ip] = ts
    return [[ip, merged[ip]] for ip in sorted(merged)]


# ---------------------------------------------------------------------------
# Быстрый контур детекта серий ТСПУ (SPEC-20261116-probe-coverage §2)
# ---------------------------------------------------------------------------


def read_fast_cache(path: Optional[Path] = None) -> dict[str, object]:
    """Сайдкар-кэш сэмплера (read-only); отсутствует/бит — пустой dict."""
    path = path or FAST_CACHE_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def fast_cache_verified_entries(
    path: Optional[Path] = None,
) -> list[list[str]]:
    """verified-записи [[ip, last_seen], ...] из сайдкар-кэша сэмплера."""
    return own_ips_cache_entries(read_fast_cache(path))


@dataclass
class FastContourResult:
    """Итог одного 5-мин прогона быстрого контура.

    skipped=True — nft-таблицы нет (probe-watch не установлен) — тихий скип
    без записи кэша и тега. alert=True — всплеск >= FAST_CONTOUR_PROBERS
    уникальных probers за окно сэмпла (тег уже напечатан в journal/stdout).
    """

    skipped: bool = False
    probers_window: int = 0
    alert: bool = False
    cache_written: bool = False


def fast_contour_check(
    run: RunFn = run_list,
    cache_path: Optional[Path] = None,
    lock_file: Optional[str] = None,
    now: Optional[datetime] = None,
) -> FastContourResult:
    """Один тик быстрого контура (вызывается сэмплером vds-logs-sample, 5 мин).

    Лёгкое nft-чтение (list_nft_table) + verified_session_ips с тем же
    инвариантом HF-1 (TCP ss по 443/8443/2053 + UDP conntrack). Пишет ТОЛЬКО
    сайдкар-кэш сэмплера {FAST_CACHE_PATH} (0600, атомарно, FileLock): базу
    per-IP счётчиков probers4 для 5-мин дельты и verified-IP (ip, last_seen,
    TTL 24 ч) — их подхватывает часовой cmd_watch (объединение при record).
    Снапшот probe-watch.json НЕ пишется никогда (инвариант ADR-014).

    АВТО-ДЕЙСТВИЙ НЕТ: при >= FAST_CONTOUR_PROBERS уникальных probers за
    окно — только тег `[warning] [probe] FAST-CONTOUR: N probers/5min` в
    journal/stdout сэмплера (для `vds logs`); lockdown — исключительная
    прерогатива часового probe-watch с его гейтами.

    Дельта probers: per-element счётчики — IP с положительной дельтой против
    кэша; фолбэк (счётчиков нет) — новые IP в set (timeout 1h ≈ окно часа,
    консервативная оценка). Ошибки чтения/записи — тихая деградация (тег в
    console), не исключение: сбой сэмплера не должен ронять сбор телеметрии.
    """
    from src.core.lock import FileLock, LockError

    cache_path = cache_path or FAST_CACHE_PATH
    lock_file = lock_file or FAST_LOCK_FILE
    current = list_nft_table(run)
    if current is None:
        return FastContourResult(skipped=True)  # нет таблицы — тихий скип

    stamp = now or datetime.now()
    verified_tcp = read_verified_session_ips(run=run)
    verified_udp, _ct = read_conntrack_verified()
    verified = verified_tcp | verified_udp

    try:
        with FileLock(lock_file):
            cache = read_fast_cache(cache_path)
            raw_prev = cache.get("probers")
            prev_probers: dict[str, int] = (
                {str(k): int(v) for k, v in dict(raw_prev).items()}
                if isinstance(raw_prev, dict)
                else {}
            )
            if current.per_element_counters:
                window_ips = [
                    ip
                    for ip, packets in current.probers.items()
                    if (packets if packets < prev_probers.get(ip, 0)
                        else packets - prev_probers.get(ip, 0)) > 0
                ]
            else:
                # Фолбэк: счётчиков на IP нет — «новые в окне» = новые элементы
                # set (timeout 1h) против прошлой базы кэша.
                window_ips = [ip for ip in current.probers if ip not in prev_probers]
            entries = merge_own_ips_cache(
                own_ips_cache_entries(cache), verified, stamp
            )
            payload: dict[str, object] = {
                "version": 1,
                "ts": stamp.isoformat(timespec="seconds"),
                "probers": dict(current.probers),
                "own_ips_cache": entries,
            }
            cache_written = write_snapshot_payload(payload, cache_path)
    except LockError:
        console.print(
            "[warning][probe] FAST-CONTOUR: параллельный прогон — тик пропущен.[/warning]"
        )
        return FastContourResult(probers_window=0, alert=False, cache_written=False)

    result = FastContourResult(
        probers_window=len(window_ips),
        alert=len(window_ips) >= FAST_CONTOUR_PROBERS,
        cache_written=cache_written,
    )
    if result.alert:
        console.print(
            f"[warning][probe] FAST-CONTOUR: {result.probers_window} "
            f"probers/5min (порог {FAST_CONTOUR_PROBERS}) — телеметрия, "
            "авто-действий нет (lockdown — только часовой probe-watch).[/warning]"
        )
    return result


# ---------------------------------------------------------------------------
# Journal-сигнатуры
# ---------------------------------------------------------------------------

@dataclass
class JournalHit:
    """Совпадения одной сигнатуры в одном источнике журнала."""

    source: str       # unit или "kernel"
    pattern_name: str
    count: int
    ips: list[str] = field(default_factory=list)  # SRC= (kernel/UFW)
    note: str = ""


def _journal_since_args(source: str, since: str) -> list[str]:
    if source == "kernel":
        base = ["journalctl", "-k"]
    else:
        base = ["journalctl", "-u", source]
    return base + ["--since", since, "--no-pager", "-q"]


def scan_journal(
    since: str,
    run: RunFn = run_list,
    sources: Optional[list[str]] = None,
    patterns: Optional[dict[str, list[dict[str, object]]]] = None,
) -> list[JournalHit]:
    """Прочитать journal по источникам и применить JOURNAL_PATTERNS.

    `since` — аргумент journalctl --since (например "2026-11-15 09:00:00" или
    "-1 hour"). Сбой чтения журнала — пустой hit не создаётся, консольная
    запись не дублируется (возвращаем только находки).
    """
    pats = patterns if patterns is not None else JOURNAL_PATTERNS
    hits: list[JournalHit] = []
    for source in (sources if sources is not None else list(pats.keys())):
        for spec in pats.get(source, []):
            regex: re.Pattern[str] = spec["pattern"]
            note = str(spec.get("note", ""))
            res = run(_journal_since_args(source, since), timeout=60)
            if not res.ok:
                continue
            count = 0
            ips: list[str] = []
            for line in res.stdout.splitlines():
                if not regex.search(line):
                    continue
                count += 1
                src = UFW_SRC_RE.search(line)
                if src:
                    ips.append(src.group(1))
            if count:
                hits.append(
                    JournalHit(source, str(spec["name"]), count, sorted(set(ips)), note)
                )
    return hits


# ---------------------------------------------------------------------------
# RU-классификация (без зависимости от relay-модуля: только файл)
# ---------------------------------------------------------------------------

def load_ru_cidrs(path: Optional[Path] = None) -> Optional[list[ipaddress.IPv4Network]]:
    """Загрузить RU-CIDR-агрегат.

    None — файла нет (geo unknown). Пустой список — файл ЕСТЬ, но v4-агрегат
    пуст (сплошь IPv6/мусор): geo unknown, но geo_source скажет честно
    «файл есть, v4-агрегат пуст». Битая строка пропускается по-строчно —
    остальной агрегат не теряется (ревью 2026-11-16, edge-case 1).
    """
    path = path or RU_CIDR_FILE
    if not path.is_file():
        return None
    networks: list[ipaddress.IPv4Network] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return networks
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue  # мусорная строка — пропуск, не валим весь файл
        if not isinstance(net, ipaddress.IPv4Network):
            continue  # IPv6-строки игнорируем, но файл читаем (не None)
        networks.append(net)
    return networks


def classify_ip(
    ip: str,
    networks: Optional[list[ipaddress.IPv4Network]],
    cache: Optional[dict[str, str]] = None,
) -> str:
    """geo-метка IP: "[RU]" если IP в RU-агрегате, иначе "unknown".

    cache — dict ip→verdict на один run (топ-10 повторов): линейный перебор
    остаётся, но повторные IP не перебираются заново.
    """
    if cache is not None and ip in cache:
        return cache[ip]
    result = "unknown"
    if networks:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None and addr.version == 4:
            for net in networks:
                if addr in net:
                    result = "[RU]"
                    break
    if cache is not None:
        cache[ip] = result
    return result


# ---------------------------------------------------------------------------
# Watch (read-only) и explain
# ---------------------------------------------------------------------------

@dataclass
class WatchReport:
    """Итог одного watch-прогона (вывод и в человекочитаемом виде, и в JSON)."""

    now: str
    window: str
    delta: Delta
    verdict: Verdict
    threshold: int
    per_element_counters: bool
    geo_source: str  # "ru-cidrs" | "unknown (файл /etc/vds-relay/ru-cidrs.txt отсутствует)"
    journal_hits: list[JournalHit] = field(default_factory=list)
    new_ru_ips: list[str] = field(default_factory=list)  # триггер вердикта (новые)
    ru_hits: list[RuIpHit] = field(default_factory=list)  # все активные RU-IP окна
    threat: ThreatState = field(default_factory=ThreatState)  # post-update уровень окна
    lockdown: dict[str, object] = field(default_factory=dict)  # {active,since,ttl_until,allow_from}
    ru_syn_new: list[str] = field(default_factory=list)  # §9.A: наблюдательное поле
    # HF-1: теги источников own_ips этого прогона (verified-tcp/udp, деградация
    # conntrack) — заполняет cmd_watch; расширение JSON-контракта, не смена.
    own_sources: list[str] = field(default_factory=list)

    def geo(self, ip: str) -> str:
        """geo-метка с кэшем на один run (top-10 повторов)."""
        return classify_ip(ip, self._ru_networks, cache=self._geo_cache)

    def to_json(self) -> dict[str, object]:
        top = [
            {"ip": ip, "packets": cnt, "geo": self.geo(ip)}
            for ip, cnt in self.delta.top
        ]
        ru_top = [
            {
                "ip": hit.ip,
                "packets": hit.packets,
                "delta": hit.delta,
                "returned": hit.returned,
                "geo": "[RU]",
            }
            for hit in sorted(
                self.ru_hits, key=lambda h: (-h.delta, -h.packets, h.ip)
            )
        ]
        return {
            "now": self.now,
            "window": self.window,
            "verdict": self.verdict.name,
            "reasons": self.verdict.reasons,
            "threshold": self.threshold,
            "syn_bare": self.delta.syn_bare,
            "syn_valid": self.delta.syn_valid,
            "udp_443": self.delta.udp_443,
            # W1-1 (аддитивно, SPEC-20261116-probe-coverage §1.3): телеметрия
            # 8443+2053; старые ключи и их семантика НЕ меняются — guard sync
            # старой версией клиента работает без ошибок.
            "syn_valid_extra": self.delta.syn_valid_extra,
            "syn_bare_extra": self.delta.syn_bare_extra,
            "extra_ports": list(EXTRA_TCP_PORTS),
            "bare_no_payload": self.delta.bare_no_payload,
            "ratio_no_payload": self.delta.ratio_no_payload,
            "unique_probers": self.delta.unique_probers,
            "per_element_counters": self.per_element_counters,
            "geo_source": self.geo_source,
            "top": top,
            "new_ru_ips": list(self.new_ru_ips),
            "ru_top": ru_top,
            "journal": [
                {
                    "source": h.source,
                    "pattern": h.pattern_name,
                    "count": h.count,
                    "ips": h.ips,
                    "note": h.note,
                }
                for h in self.journal_hits
            ],
            # Стабильный контракт монитор-поллинга (SPEC §5/§9.A):
            "threat_level": self.threat.level,
            "threat_reason": self.threat.reason,
            "ru_syn_new": list(self.ru_syn_new),
            "own_ips_sources": list(self.own_sources),
            "lockdown": {
                "active": bool(self.lockdown.get("active")),
                "since": str(self.lockdown.get("since", "")),
                "ttl_until": str(self.lockdown.get("ttl_until", "")),
                "allow_from": list(self.lockdown.get("allow_from") or []),
            },
        }

    _ru_networks: Optional[list[ipaddress.IPv4Network]] = None
    _geo_cache: dict[str, str] = field(default_factory=dict)


@dataclass
class RuIpHit:
    """Активный в окне RU-IP (для ru_top).

    returned=True — IP был в снапшоте, но снова активен (положительная
    дельта); returned=False — впервые появился в окне (кандидат SUSPECT).
    На фолбэке (без per-element счётчиков) delta=packets=0: присутствие
    в set с timeout 1h само по себе означает активность в окне.
    """

    ip: str
    delta: int
    packets: int
    returned: bool


def _server_public_ip() -> str:
    """Публичный IP сервера (исключение из «новых RU-IP»); '' — не определился."""
    from src.core.netcheck import public_ip  # лениво: gateway не тянет сеть

    return public_ip() or ""


def build_report(
    current: NftState,
    since_hours: int = DEFAULT_WINDOW_HOURS,
    threshold: int = DEFAULT_THRESHOLD,
    run: RunFn = run_list,
    snapshot_path: Path = SNAPSHOT_PATH,
    now: Callable[[], datetime] = datetime.now,
    server_ip: Optional[str] = None,
    lockdown: Optional[dict[str, object]] = None,
    own_ips: Optional[list[str]] = None,
) -> WatchReport:
    """Собрать отчёт из уже прочитанного состояния таблицы (тестируемо).

    server_ip — публичный адрес сервера; None → определить через netcheck
    (в тестах подменяется).

    RU-логика (ревю 2026-11-16, edge-case 3c; фикс 2026-11-16 ревью 3):
    - активность за окно — по ДЕЛЬТЕ per-IP (для отсутствовавших в снапшоте
      дельта = current packets);
    - на фолбэке (per_element_counters=False) все элементы set с нулевыми
      счётчиками: присутствие в set (timeout 1h) = активность в окне —
      ru_hits включают IP с delta=0, new_ru_ips = новые IP сета за ~час;
    - ru_top: новые (returned=False) и «вернувшиеся» (были в снапшоте,
      снова активны — returned=True);
    - триггер SUSPECT — только НОВЫЕ RU-IP (не из снапшота) >= 2 при
      delta.syn_valid > 0: окно из одних голых masscan-SYN (delta.syn_valid
      = 0) SUSPECT не даёт. Ограничение (в explain): probers4 включает и
      masscan-IP — раздельный per-SYN-тип учёт невозможен на nft-уровне,
      SUSPECT гасится условием delta.syn_valid > 0.

    SPEC-20261116-probe-response:
    - own_ips — исключаются из new_ru_ips: endpoint-IP активных AWG-пиров
      (кэш снапшота, §11), серверный IP, whitelist /etc/vds-probe-watch/
      allow-ips.txt и — с HF-1 (SPEC-20261116-surface-hardening §1.2) —
      verified_session_ips (кэш снапшота 24 ч + свежие сессии; передаются
      вызывающим в own_ips одним множеством);
    - lockdown — нормализованный dict лока 443: активный лок ослепляет
      syn_valid (§9.A) → threat-decay замирает, а новые RU-IP по SYN идут
      в наблюдательное поле ru_syn_new (продлевает TTL, вердикт не поднимает);
    - threat — машина threat-level (§2): отчёт несёт post-update уровень
      этого окна (тик таймера персистит его в снапшот).
    """
    snapshot = load_snapshot(snapshot_path)
    delta = compute_delta(current, snapshot)

    raw_probers = snapshot.get("probers")
    snap_probers: dict[str, int] = (
        {str(k): int(v) for k, v in dict(raw_probers).items()}
        if isinstance(raw_probers, dict)
        else {}
    )
    snapshot_keys = set(snap_probers)

    ru_networks = load_ru_cidrs()
    geo_cache: dict[str, str] = {}
    new_ru_ips: list[str] = []
    ru_hits: list[RuIpHit] = []
    if ru_networks and current.probers:
        # Ревью 2026-11-16 (чистка): server_ip нужен только когда есть что
        # фильтровать — сетевой вызов не происходит на пустом set.
        if server_ip is None:
            server_ip = _server_public_ip()
        own_set = load_own_ips() | set(own_ips or [])
        for ip, packets in current.probers.items():
            if current.per_element_counters:
                prev = snap_probers.get(ip, 0)
                d = packets if packets < prev else packets - prev
                if d <= 0:
                    continue  # не активен в окне
            else:
                # Фолбэк: счётчиков нет, но элемент в set с timeout 1h —
                # значит зондировал/коннектился в пределах последнего часа.
                d = 0
            if ip == server_ip or ip in own_set:
                continue  # свой (сервер / AWG-клиент / whitelist) — не «новый RU»
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            if classify_ip(ip, ru_networks, cache=geo_cache) != "[RU]":
                continue
            returned = ip in snapshot_keys
            ru_hits.append(RuIpHit(ip=ip, delta=d, packets=packets, returned=returned))
            if not returned:
                new_ru_ips.append(ip)

    verdict = compute_verdict(
        delta,
        threshold,
        new_ru_ips=new_ru_ips,
        ru_available=bool(ru_networks),
        syn_valid_total=delta.syn_valid + delta.syn_valid_extra,  # окно, не аптайм; extra-порты в SUSPECT, PROBE-BURST — только 443
    )

    end = now()
    start = end - timedelta(hours=since_hours)
    since = start.strftime("%Y-%m-%d %H:%M:%S")
    hits = scan_journal(since, run)

    lockdown = dict(lockdown or {})
    threat = update_threat(
        ThreatState.from_dict(snapshot.get("threat")),
        verdict=verdict.name,
        new_ru_count=len(new_ru_ips),
        ru_available=bool(ru_networks),
        lockdown_active=bool(lockdown.get("active")),
        now=end,
    )
    # §9.A: в локе syn_valid=0 (SYN роняет UFW после hook −140) — SUSPECT
    # повторно не сработает; новые RU-IP по SYN наблюдаем отдельно.
    ru_syn_new = list(new_ru_ips) if lockdown.get("active") else []

    if ru_networks is None:
        geo_source = "unknown (файл /etc/vds-relay/ru-cidrs.txt отсутствует)"
    elif not ru_networks:
        geo_source = (
            "файл /etc/vds-relay/ru-cidrs.txt есть, но IPv4-агрегат пуст "
            "(сплошь IPv6/мусор) — geo unknown"
        )
    else:
        geo_source = "ru-cidrs (/etc/vds-relay/ru-cidrs.txt)"
    report = WatchReport(
        now=end.isoformat(timespec="seconds"),
        window=f"{start.isoformat(timespec='seconds')} .. {end.isoformat(timespec='seconds')}",
        delta=delta,
        verdict=verdict,
        threshold=threshold,
        per_element_counters=current.per_element_counters,
        geo_source=geo_source,
        journal_hits=hits,
        new_ru_ips=new_ru_ips,
        ru_hits=ru_hits,
        threat=threat,
        lockdown=lockdown,
        ru_syn_new=ru_syn_new,
    )
    report._ru_networks = ru_networks
    report._geo_cache = geo_cache
    return report


def run_watch(
    since_hours: int = DEFAULT_WINDOW_HOURS,
    threshold: int = DEFAULT_THRESHOLD,
    run: RunFn = run_list,
    snapshot_path: Path = SNAPSHOT_PATH,
    now: Callable[[], datetime] = datetime.now,
    lockdown: Optional[dict[str, object]] = None,
    own_ips: Optional[list[str]] = None,
) -> tuple[Optional[WatchReport], Optional[NftState]]:
    """Прочитать nft-таблицу и собрать отчёт.

    Возвращает (report, current); (None, None) — таблица отсутствует
    (подсказка install). current отдаётся для записи снапшота без повторного
    вызова nft. lockdown/own_ips — состояние лока 443 и кэш своих IP
    (SPEC-20261116-probe-response §9.A/§11), передаётся вызывающим.
    """
    current = list_nft_table(run)
    if current is None:
        return None, None
    report = build_report(
        current,
        since_hours=since_hours,
        threshold=threshold,
        run=run,
        snapshot_path=snapshot_path,
        now=now,
        lockdown=lockdown,
        own_ips=own_ips,
    )
    return report, current


def _load_lockdown(state_path: Optional[str] = None) -> dict[str, object]:
    """Нормализованный dict лока 443 из gateway state; ошибка чтения — неактивен."""
    from src.gateway.store import StoreError, load_state  # лениво: слой gateway
    from src.system.ufw import get_lockdown

    try:
        state = load_state(state_path)
    except StoreError:
        return {"active": False, "since": "", "ttl_until": "", "allow_from": []}
    return dict(get_lockdown(state))


def print_report(report: WatchReport) -> None:
    """Человекочитаемый вывод: одна сводка + топ-10 + сигналы журнала."""
    v = report.verdict.name
    if v == "RU-PROBE-SUSPECT":
        console.print("[error][probe] Вердикт: RU-PROBE-SUSPECT[/error]")
        for reason in report.verdict.reasons:
            console.print(f"[error][probe]   — {escape(reason)}[/error]")
    elif v == "PROBE-BURST":
        console.print("[error][probe] Вердикт: PROBE-BURST[/error]")
        for reason in report.verdict.reasons:
            console.print(f"[error][probe]   — {escape(reason)}[/error]")
    else:
        console.print("[success][probe] Вердикт: quiet[/success]")
    tag = {
        THREAT_QUIET: "success",
        THREAT_ELEVATED: "warning",
        THREAT_HIGH: "error",
    }[report.threat.level]
    reason = f" ({report.threat.reason})" if report.threat.reason else ""
    console.print(f"[{tag}][probe] threat-level: {report.threat.level}{escape(reason)}[/{tag}]")
    if report.lockdown.get("active"):
        console.print(
            f"[warning][probe] lock-443 АКТИВЕН: since {escape(str(report.lockdown.get('since', '')))}, "
            f"до {escape(str(report.lockdown.get('ttl_until', '')))}, allow_from: "
            f"{', '.join(str(i) for i in report.lockdown.get('allow_from') or []) or '— (443 закрыт всем)'}[/warning]"
        )
        if report.threat.level != THREAT_HIGH:
            console.print(
                "[warning][probe] лок активен, уровень снизился — авто-снятие "
                "запрещено (SPEC §10 OQ-3): снимите `vds system ufw lock-443 --unlock --apply` "
                "или дождитесь TTL.[/warning]"
            )
    if report.ru_syn_new:
        console.print(
            f"[warning][probe] ru_syn_new: {len(report.ru_syn_new)} новых RU-IP по SYN "
            "при активном локе (наблюдательное, продлевает TTL; вердикт не поднимает, §9.A)[/warning]"
        )
    console.print(f"[info][probe] Окно: {escape(report.window)}[/info]")
    console.print(
        f"[info][probe] syn_bare={report.delta.syn_bare} "
        f"syn_valid={report.delta.syn_valid} "
        f"udp_443={report.delta.udp_443} "
        f"bare-no-payload={report.delta.bare_no_payload} "
        f"(ratio={report.delta.ratio_no_payload if report.delta.ratio_no_payload is not None else 'n/a'})"
        f"[/info]"
    )
    counter_note = (
        "per-element счётчики доступны"
        if report.per_element_counters
        else "per-element счётчиков НЕТ — unique_probers по составу set (≈последний час)"
    )
    console.print(
        f"[info][probe] Уникальных пробующих IP: {report.delta.unique_probers} "
        f"(порог {report.threshold}; {counter_note})[/info]"
    )
    console.print(f"[info][probe] geo: {escape(report.geo_source)}[/info]")
    if report.own_sources:
        console.print(
            f"[info][probe] own_ips источники: awg + allow-ips + кэш; "
            f"verified: {', '.join(escape(s) for s in report.own_sources)}[/info]"
        )
    if report.ru_hits:
        console.print(
            f"[warning][probe] Активные RU-IP за окно ({len(report.ru_hits)}):[/warning]"
        )
        for hit in sorted(report.ru_hits, key=lambda h: (-h.delta, -h.packets, h.ip)):
            mark = " [вернувшийся]" if hit.returned else " [новый]"
            console.print(
                f"[warning][probe]   {escape(hit.ip)}{escape(mark)}: "
                f"delta={hit.delta}[/warning]"
            )
    if report.delta.top:
        console.print("[info][probe] Топ-10 пробующих IP:[/info]")
        for ip, cnt in report.delta.top:
            geo = report.geo(ip)
            label = f" {geo}" if geo == "[RU]" else ""
            console.print(f"[info][probe]   {escape(ip + label)}: {cnt}[/info]")
    if report.journal_hits:
        console.print("[info][probe] Сигналы журнала:[/info]")
        for hit in report.journal_hits:
            extra = f" (SRC: {', '.join(hit.ips[:5])})" if hit.ips else ""
            console.print(
                f"[warning][probe]   {escape(hit.source)} / {escape(hit.pattern_name)}: "
                f"{hit.count}{escape(extra)}[/warning]"
            )
    else:
        console.print("[info][probe] Сигналов журнала за окно нет.[/info]")


@dataclass
class ExplainRow:
    """Строка карты покрытия explain: что меряется, статус, примечание."""

    item: str
    status: str  # "ok" | "missing" | "warn"
    note: str


def build_explain(
    run: RunFn = run_list,
    ru_cidr_path: Path = RU_CIDR_FILE,
) -> list[ExplainRow]:
    """Честная карта покрытия сигналов на этом сервере (для explain).

    Только факты: что установлено, что слепо. Без root тоже работает
    (read-only проверки, отказ shell — честный "нет/не доступно").

    RU-строки — по ТРЁМ состояниям load_ru_cidrs (ревью 2026-11-16):
    None (файла нет) → missing; [] (файл есть, v4-агрегат пуст) → warn
    «RU-SUSPECT отключён»; непустой → ok.
    """
    rows: list[ExplainRow] = []
    ru_nets = load_ru_cidrs(ru_cidr_path)

    if nft_table_exists(run):
        rows.append(ExplainRow("nft-таблица inet vds_probe", "ok", "установлена"))
        state = list_nft_table(run)
        if state is not None and state.per_element_counters:
            rows.append(
                ExplainRow("per-element counter в set probers4", "ok", "счётчики на IP доступны")
            )
        elif state is not None:
            rows.append(
                ExplainRow(
                    "per-element counter в set probers4",
                    "missing",
                    "не поддерживается этим ядром — unique_probers по составу set (≈1ч)",
                )
            )
        # W1-1 (SPEC-20261116-probe-coverage §1.5): честная карта портов.
        rows.append(
            ExplainRow(
                "охват TCP-портов (probers4 + счётчики)",
                "ok",
                f"probers4 собирает SYN (ip length > {MIN_CLIENT_SYN_LEN}) с "
                f"tcp/{{443, 8443, 2053}} одним set — сканер XHTTP/CDN виден в "
                "new_ru_ips → RU-PROBE-SUSPECT; syn_valid/syn_bare (база "
                "PROBE-BURST) — по-прежнему ТОЛЬКО 443; 8443+2053 — аддитивные "
                "syn_valid_extra/syn_bare_extra (телеметрия watch --json)",
            )
        )
        rows.append(
            ExplainRow(
                "UDP-порты (443 QUIC / 51826 AWG)",
                "missing",
                "слепы на уровне probers4 (QUIC-клиенты дали бы ложные срабатывания): "
                "UDP виден только объёмным счётчиком udp_443 и verified-conntrack; "
                "per-element UDP-счётчики — вне скоупа v1",
            )
        )
        rows.append(
            ExplainRow(
                "быстрый контур (5-мин, vds-logs-sample)",
                "ok",
                f"fast_contour_check: >= {FAST_CONTOUR_PROBERS} уникальных probers/5 мин "
                f"→ тег FAST-CONTOUR в journal; verified-IP пишутся в сайдкар-кэш "
                f"{FAST_CACHE_PATH} (TTL 24 ч), часовой watch подхватывает при record; "
                "АВТО-ДЕЙСТВИЙ НЕТ (lockdown — только часовой probe-watch)",
            )
        )
    else:
        rows.append(
            ExplainRow(
                "nft-таблица inet vds_probe",
                "missing",
                "не установлена — выполните `vds gateway probe-watch install --apply`",
            )
        )

    for unit, label in ((XRAY_UNIT, "xray"), (HYSTERIA2_UNIT, "hysteria2")):
        res = run(["systemctl", "list-unit-files", unit], timeout=10)
        exists = res.ok and unit in res.stdout
        rows.append(
            ExplainRow(
                f"юнит {unit}",
                "ok" if exists else "missing",
                "присутствует" if exists else "не установлен",
            )
        )
        if exists:
            for spec in JOURNAL_PATTERNS.get(unit, []):
                rows.append(
                    ExplainRow(
                        f"journal-паттерн {spec['name']} ({label})",
                        "warn",
                        str(spec.get("note", "")),
                    )
                )

    rows.append(
        ExplainRow(
            "journal-паттерн ufw_block_443 (kernel)",
            "warn",
            "UFW-лог из `journalctl -k`: пачки DROP на 443 от одного IP; активен при включённом UFW",
        )
    )

    rows.append(
        ExplainRow(
            "счётчик udp_443 (Hysteria2/QUIC)",
            "warn",
            "QUIC-Initial зонды различить от легитимного UDP нельзя на nft-уровне — "
            "счётчик даёт объём, аномалия = объём/окно",
        )
    )

    if ru_nets:
        rows.append(
            ExplainRow(
                "вердикт RU-PROBE-SUSPECT",
                "ok",
                f"{ru_cidr_path} присутствует — новые RU-IP (>= {NEW_RU_IPS_THRESHOLD}/окно) "
                "сигнализируют точечное RU-зондирование; триггер гасится при delta.syn_valid=0 "
                "(окно из одних masscan-SYN). Ограничение: probers4 включает и masscan-IP "
                "(update на все SYN) — раздельный per-SYN-тип учёт невозможен на nft-уровне",
            )
        )
    elif ru_nets is not None:
        rows.append(
            ExplainRow(
                "вердикт RU-PROBE-SUSPECT",
                "warn",
                f"{ru_cidr_path} есть, но валидного v4-агрегата нет (сплошь IPv6/мусор) — "
                "RU-SUSPECT отключён; обновите агрегат (`probe-watch ru-cidr update --apply` "
                "или relay-cidr)",
            )
        )
    else:
        rows.append(
            ExplainRow(
                "вердикт RU-PROBE-SUSPECT",
                "missing",
                f"без {ru_cidr_path} вердикт недоступен (geo: unknown) — ставится "
                "`vds gateway probe-watch ru-cidr install --apply` (SPEC §3) или relay-модулем",
            )
        )

    # threat-level машина (SPEC-20261116-probe-response §2)
    threat_row_note = (
        "quiet→elevated (BURST/RU-SUSPECT 1 окно)→high (RU-SUSPECT 2 подряд); "
        "decay high = 72 окна без новых RU-IP, заморожен при lockdown; "
        "исключаются свои: AWG-endpoints + серверный IP + "
        f"{OWN_IPS_FILE}"
    )
    if ru_nets:
        rows.append(ExplainRow("threat-level машина", "ok", threat_row_note))
    else:
        rows.append(
            ExplainRow(
                "threat-level машина",
                "warn",
                threat_row_note + " — НО geo: unknown, high недостижим (BURST-максимум elevated)",
            )
        )

    rows.append(
        ExplainRow(
            "xray access-log / loglevel",
            "warn",
            "access-log выключен — сигнатуры invalid-auth не видны; включение = отдельный WP (владелец)",
        )
    )

    if ru_nets:
        rows.append(
            ExplainRow(
                "RU-CIDR агрегат",
                "ok",
                f"{ru_cidr_path} присутствует — пробующие IP помечаются [RU]",
            )
        )
    elif ru_nets is not None:
        rows.append(
            ExplainRow(
                "RU-CIDR агрегат",
                "warn",
                f"{ru_cidr_path} есть, но валидного v4-агрегата нет — geo: unknown",
            )
        )
    else:
        rows.append(
            ExplainRow(
                "RU-CIDR агрегат",
                "missing",
                f"{ru_cidr_path} отсутствует — geo: unknown "
                "(`vds gateway probe-watch ru-cidr install --apply`; на релее — relay init)",
            )
        )

    rures = run(["systemctl", "list-unit-files", PROBE_RUCIDR_TIMER], timeout=10)
    rows.append(
        ExplainRow(
            f"таймер {PROBE_RUCIDR_TIMER}",
            "ok" if (rures.ok and PROBE_RUCIDR_TIMER in rures.stdout) else "missing",
            "еженедельное обновление RU-CIDR" if (rures.ok and PROBE_RUCIDR_TIMER in rures.stdout)
            else "не установлен (ru-cidr install --apply)",
        )
    )

    rows.append(
        ExplainRow(
            "IPv6-пробы",
            "missing",
            "non-goal v1: наблюдение только tcp/{443, 8443, 2053} IPv4 "
            "(v6-зондирование не меряется)",
        )
    )

    tres = run(["systemctl", "list-unit-files", PROBE_WATCH_TIMER], timeout=10)
    rows.append(
        ExplainRow(
            f"таймер {PROBE_WATCH_TIMER}",
            "ok" if (tres.ok and PROBE_WATCH_TIMER in tres.stdout) else "missing",
            "часовой тик watch" if (tres.ok and PROBE_WATCH_TIMER in tres.stdout) else "не установлен (install --apply)",
        )
    )
    return rows


def print_explain(rows: list[ExplainRow]) -> None:
    """Печать карты покрытия (теги logger, одна строка на пункт)."""
    console.print("[info][probe] Карта покрытия сигналов активного зондирования:[/info]")
    for row in rows:
        tag = {"ok": "success", "missing": "error", "warn": "warning"}[row.status]
        console.print(
            f"[{tag}][probe]   {escape(row.item)}: {escape(row.note)}[/{tag}]"
        )


def cmd_explain(run: RunFn = run_list) -> int:
    print_explain(build_explain(run))
    return 0


# ---------------------------------------------------------------------------
# install / remove (мутации: --apply, dry-run по умолчанию, FileLock)
# ---------------------------------------------------------------------------

def _unit_ctx() -> dict[str, str]:
    """Контекст рендера systemd-шаблонов (паттерн relay/init.py)."""
    from src.core.units import resolve_python

    repo_dir = Path(__file__).resolve().parents[2]
    return {
        "python": resolve_python(),
        "repo_dir": str(repo_dir),
        "install_dir": os.environ.get("INSTALL_DIR", "/opt/my-vds"),
        "nft_file": str(PROBE_NFT_FILE),
    }


def _atomic_write(path: Path, text: str, mode: int) -> bool:
    """Атомарная запись не-секретного файла с фиксацией прав. True — успех."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        console.print(f"[error][probe] Не удалось записать {path}: {exc}[/error]")
        return False


def _apply_nft(per_element_counter: bool) -> tuple[bool, bool]:
    """Удалить старую таблицу (если есть) и применить файл.

    Возвращает (успех, per_element_counter в факте применённой таблицы).
    """
    if nft_table_exists():
        del_res = run_list(["nft", "delete", "table", "inet", NFT_TABLE], timeout=15)
        if not del_res.ok:
            console.print(
                f"[error][probe] nft delete table inet {NFT_TABLE}: "
                f"{del_res.stderr.strip() or del_res.stdout.strip()}[/error]"
            )
            return False, per_element_counter
    apply_res = run_list(["nft", "-f", str(PROBE_NFT_FILE)], timeout=30)
    if not apply_res.ok:
        return False, per_element_counter
    if not nft_table_exists():
        console.print("[error][probe] Таблица не применилась (не найдена в nft list tables)[/error]")
        return False, per_element_counter
    return True, per_element_counter


def cmd_install(apply: bool = False) -> int:
    """install: dry-run печатает план; --apply ставит таблицу + юниты + таймер."""
    if not apply:
        console.print("[info][probe] DRY-RUN план install:[/info]")
        console.print(f"[info][probe]   1. nft-файл {PROBE_NFT_FILE} (0644) + `nft -f` (таблица inet {NFT_TABLE})[/info]")
        console.print(f"[info][probe]   2. счётчики syn_bare/syn_valid/udp_443 + syn_valid_extra/syn_bare_extra (8443+2053), set {PROBERS_SET} на tcp {{443, 8443, 2053}} (flags dynamic,timeout, size 65535, timeout {SET_TIMEOUT}, per-element counter; при отказе ядра — fallback без счётчиков на IP)[/info]")
        console.print(f"[info][probe]   3. юниты {PROBE_WATCH_UNIT} + {PROBE_WATCH_TIMER} из systemd-шаблонов (часовой тик watch)[/info]")
        console.print("[info][probe] Запустите с --apply для исполнения.[/info]")
        return 0

    from src.core.lock import FileLock

    from src.core.units import install_unit

    with FileLock(LOCK_FILE):
        if not _atomic_write(PROBE_NFT_FILE, render_nft(True), 0o644):
            return 1
        ok, used_counter = _apply_nft(True)
        if not ok:
            console.print("[warning][probe] Вариант с per-element counter не применился — пробую fallback без счётчиков на IP.[/warning]")
            if not _atomic_write(PROBE_NFT_FILE, render_nft(False), 0o644):
                return 1
            ok, used_counter = _apply_nft(False)
            if not ok:
                return 1
        console.print(
            f"[success][probe] nft-таблица inet {NFT_TABLE} применена "
            f"(per-element counter: {'да' if used_counter else 'НЕТ — счётчики на IP недоступны'}).[/success]"
        )
        # Ревью 2026-11-16, edge-case 3d: после переустановки счётчики в ядре
        # с нуля — сбрасываем снапшот, иначе первый watch дал бы ложную
        # «отрицательную дельту» (0-до-догона против старых 5000).
        # Счётчики сбрасываются, но threat/config/own_ips переживают
        # переустановку (SPEC §2: состояние — в снапшоте).
        old = load_snapshot(SNAPSHOT_PATH)
        save_snapshot(
            NftState(per_element_counters=used_counter), SNAPSHOT_PATH,
            extra={
                "threat": old.get("threat", {}),
                "config": old.get("config", {}),
                "own_ips": old.get("own_ips", {}),
                "own_ips_cache": old.get("own_ips_cache", []),
            },
        )

        ctx = _unit_ctx()
        if not install_unit("vds-probe-watch.service.tpl", PROBE_WATCH_UNIT, ctx):
            return 1
        if not install_unit("vds-probe-watch.timer.tpl", PROBE_WATCH_TIMER, ctx):
            return 1
        start_res = run_list(["systemctl", "start", PROBE_WATCH_TIMER], timeout=15)
        if not start_res.ok:
            console.print(
                f"[error][probe] Не удалось запустить {PROBE_WATCH_TIMER}: "
                f"{start_res.stderr.strip()}[/error]"
            )
            return 1
    console.print(
        f"[success][probe] Монитор зондирования установлен: таймер {PROBE_WATCH_TIMER} "
        f"запущен (hourly). Смотреть: `vds gateway probe-watch watch`. "
        f"Персистентность после ребута: ExecStartPre юнита {PROBE_WATCH_UNIT} "
        f"сам применит {PROBE_NFT_FILE}, если таблицы нет (счётчики с нуля).[/success]"
    )
    return 0


def cmd_remove(apply: bool = False) -> int:
    """remove: dry-run печатает план; --apply демонтирует таблицу и юниты."""
    if not apply:
        console.print("[info][probe] DRY-RUN план remove:[/info]")
        console.print(f"[info][probe]   1. nft delete table inet {NFT_TABLE}[/info]")
        console.print(f"[info][probe]   2. удалить {PROBE_NFT_FILE}[/info]")
        console.print(f"[info][probe]   3. удалить юниты {PROBE_WATCH_UNIT}, {PROBE_WATCH_TIMER}[/info]")
        console.print("[info][probe] Запустите с --apply для исполнения.[/info]")
        return 0

    from src.core.lock import FileLock

    from src.core.units import remove_unit

    with FileLock(LOCK_FILE):
        if nft_table_exists():
            del_res = run_list(["nft", "delete", "table", "inet", NFT_TABLE], timeout=15)
            if not del_res.ok:
                console.print(
                    f"[error][probe] nft delete table inet {NFT_TABLE}: "
                    f"{del_res.stderr.strip() or del_res.stdout.strip()}[/error]"
                )
                return 1
            console.print(f"[change][probe] nft-таблица inet {NFT_TABLE} удалена[/change]")
        else:
            console.print(f"[info][probe] Таблица inet {NFT_TABLE} отсутствует (идемпотентно)[/info]")
        try:
            PROBE_NFT_FILE.unlink(missing_ok=True)
        except OSError as exc:
            console.print(f"[error][probe] Не удалось удалить {PROBE_NFT_FILE}: {exc}[/error]")
            return 1
        if not remove_unit(PROBE_WATCH_UNIT):
            return 1
        if not remove_unit(PROBE_WATCH_TIMER):
            return 1
    console.print("[success][probe] Монитор зондирования демонтирован (снапшот /var/lib/vds/probe-watch.json сохранён).[/success]")
    return 0


def run_auto_reactions(
    report: WatchReport,
    cfg: dict[str, object],
    state_path: Optional[str] = None,
    now: Optional[datetime] = None,
) -> None:
    """Авто-реакции часового тика probe-watch (SPEC §4.2 + §9.A + §11).

    Вызывается ТОЛЬКО из --record-прогона (юнит таймера, root):
    (а) threat high + auto on → lock-443 (reason auto:RU-SUSPECT); повторный
        high/ru_syn_new при активном локе → продление TTL, НЕ дубль правил;
    (б) TTL-чек: now >= ttl_until → auto-unlock reason=ttl-expired
        (внутренний вызов ufw-модуля; отдельный systemd-timer не плодим — §11);
    (в) downgrade ниже high лок НЕ снимает (§10 OQ-3 — «мигалка» закрылся→
        открылся→пробы→закрылся; warning печатает watch).
    """
    from src.system import ufw as ufw_mod  # лениво: gateway → system только в тике

    now = now or datetime.now(timezone.utc)
    ld = _load_lockdown(state_path)
    if ld.get("active") and ufw_mod.lockdown_ttl_expired(ld, now):
        if ufw_mod.auto_unlock_expired(state_path=state_path, now=now, reason="ttl-expired"):
            ld = _load_lockdown(state_path)
    high = report.threat.level == THREAT_HIGH
    if ld.get("active"):
        if high or report.ru_syn_new:
            ufw_mod.extend_lockdown_ttl(state_path=state_path, now=now)
    elif high and cfg.get("auto_lockdown"):
        ufw_mod.apply_auto_lockdown(
            state_path=state_path,
            allow_ips=[str(i) for i in (cfg.get("lockdown_allow") or [])],
            ttl_hours=int(cfg.get("lockdown_ttl_hours") or ufw_mod.LOCKDOWN_TTL_DEFAULT_H),
            reason="auto:RU-SUSPECT",
        )


def cmd_watch(
    since_hours: int = DEFAULT_WINDOW_HOURS,
    threshold: int = DEFAULT_THRESHOLD,
    json_out: bool = False,
    record: bool = False,
    snapshot_path: Optional[Path] = None,
    run: RunFn = run_list,
    state_path: Optional[str] = None,
    now: Optional[datetime] = None,
    fast_cache_path: Optional[Path] = None,
) -> int:
    """watch: отчёт за окно; read-only по умолчанию.

    record=True — только для юнита таймера: после отчёта снапшот
    перезаписывается текущими счётчиками (базой следующего окна) + машиной
    threat-level, обновляется кэш AWG-endpoints (root) и кэш verified-IP
    (own_ips_cache, TTL 24 ч, SPEC-20261116-surface-hardening §1.2) и
    выполняются авто-реакции локa (SPEC §4.2/§11). Ручной `watch` без
    --record ничего не пишет и реакций не триггерит: свежие verified-IP
    объединяются с кэшем ТОЛЬКО в памяти для текущего отчёта (стык с
    vpn guard ADR-014/M1: файл не мутируется).

    W1-1 (SPEC-20261116-probe-coverage §2): own_ips_cache читается ИЗ
    снапшота, И из сайдкар-кэша сэмплера (fast_cache_path; verified-IP с
    5-мин тиков — короткие сессии между часовыми тиками не теряются),
    объединение по ip с max(last_seen). При record=True объединённый кэш
    вливается в snapshot["own_ips_cache"] (с чисткой TTL 24 ч); при
    record=False — только в памяти для отчёта, оба файла не мутируются.
    """
    snapshot_path = snapshot_path or SNAPSHOT_PATH
    from src.core.lock import FileLock, LockError

    now_fn: Callable[[], datetime] = (lambda: now) if now is not None else datetime.now
    snapshot = load_snapshot(snapshot_path)
    cfg = dict(snapshot.get("config") or {})
    # verified_session_ips (HF-1): read-only, для record и ручного watch alike
    verified_tcp = read_verified_session_ips(run=run)
    verified_udp, ct_available = read_conntrack_verified()
    verified = verified_tcp | verified_udp
    snapshot_cache = own_ips_cache_entries(snapshot)
    # W1-1: сайдкар-кэш сэмплера (5-мин verified) поверх кэша снапшота.
    cache_entries = merge_cache_entries(
        snapshot_cache, fast_cache_verified_entries(fast_cache_path)
    )
    if record:
        # Тик (root): свежие endpoint-IP пиров; сбой awg → кэш снапшота (§11)
        endpoints = read_awg_endpoints(run)
        awg_ips = endpoints if endpoints else cached_own_ips(snapshot)
        stamp = now_fn()
        # merge чистит TTL (протухшие из обоих источников удаляются) и
        # обновляет last_seen свежих verified; fast-кэш вливается сюда.
        new_cache = merge_own_ips_cache(cache_entries, verified, stamp)
        own_ips = sorted(
            {*awg_ips, *active_cache_ips(new_cache, stamp)}  # verified уже в кэше
        )
        own_cache: dict[str, object] = {
            "ips": awg_ips,
            "ts": stamp.isoformat(timespec="seconds"),
        }
    else:
        awg_ips = cached_own_ips(snapshot)
        # В памяти только: свежие verified и fast-кэш не пишутся на диск
        # (AC-16/M1-стык; инвариант ADR-014 — snapshot не мутируется).
        own_ips = sorted(
            {
                *awg_ips,
                *active_cache_ips(cache_entries, now_fn()),
                *verified,
            }
        )
        own_cache = dict(snapshot.get("own_ips") or {})
        new_cache = snapshot_cache  # без record снапшот не трогаем
    sources = [
        f"tcp/ss: {len(verified_tcp)} IP",
        (
            f"udp/conntrack: {len(verified_udp)} IP"
            if ct_available
            else "udp: /proc/net/nf_conntrack недоступен (TCP+AWG+кэш)"
        ),
    ]
    try:
        with FileLock(LOCK_FILE):
            report, current = run_watch(
                since_hours=since_hours, threshold=threshold, run=run,
                snapshot_path=snapshot_path,
                lockdown=_load_lockdown(state_path),
                own_ips=own_ips,
                now=now_fn,
            )
            if report is None or current is None:
                console.print(
                    f"[error][probe] nft-таблица inet {NFT_TABLE} отсутствует — "
                    "выполните `vds gateway probe-watch install --apply`.[/error]"
                )
                return 1
            report.own_sources = sources
            if record:
                # реакции ДО вывода: json отдаёт пост-реакционное состояние лока
                run_auto_reactions(report, cfg, state_path=state_path)
                report.lockdown = _load_lockdown(state_path)
            if json_out:
                print(json.dumps(report.to_json(), ensure_ascii=False))
            else:
                print_report(report)
            if record:
                save_snapshot(
                    current, snapshot_path,
                    extra={
                        "threat": report.threat.to_dict(),
                        "config": cfg,
                        "own_ips": own_cache,
                        "own_ips_cache": new_cache,
                    },
                )
    except LockError:
        console.print(
            "[warning][probe] Параллельный прогон probe-watch — отчёт отдан "
            "ему, повторный запуск не выполнен.[/warning]"
        )
        return 1
    return 0


def cmd_config(
    auto_lockdown: Optional[str] = None,
    lockdown_allow: Optional[str] = None,
    lockdown_ttl: Optional[str] = None,
    apply: bool = False,
    snapshot_path: Optional[Path] = None,
    state_path: Optional[str] = None,
) -> int:
    """config: связка auto-lockdown (SPEC §4.2; default off — §10 OQ-1).

    Без параметров — показать текущий конфиг (read-only). Fail-fast §4.2
    (ужесточение HF-1, SPEC-20261116-surface-hardening §1.3): `--auto-lockdown on`
    требует НЕПУСТОЙ allow-list — заполненный /etc/vds-probe-watch/allow-ips.txt
    достаточен без --lockdown-allow; наличие 51825/2053 в state.protocols
    больше НЕ основание (резервный канал без allow-IP всё равно закрывает
    владельцу 443). Dry-run по умолчанию.
    """
    from src.core.lock import FileLock, LockError
    from src.system import ufw as ufw_mod

    snapshot_path = snapshot_path or SNAPSHOT_PATH
    snapshot = load_snapshot(snapshot_path)
    current = dict(snapshot.get("config") or {})
    default_view = {"auto_lockdown": False}
    console.print(f"[info][probe] Текущий конфиг: {current or default_view}[/info]")
    if auto_lockdown is None and lockdown_allow is None and lockdown_ttl is None:
        return 0  # статус-режим: показать и выйти

    if auto_lockdown is not None and auto_lockdown not in ("on", "off"):
        console.print(
            f"[error][probe] --auto-lockdown: ожидалось on|off, получено {auto_lockdown!r}[/error]"
        )
        return 2
    try:
        allow_ips = (
            ufw_mod.parse_allow_from(lockdown_allow)
            if lockdown_allow is not None
            else [str(i) for i in (current.get("lockdown_allow") or [])]
        )
        ttl_hours = (
            ufw_mod.parse_ttl_hours(lockdown_ttl)
            if lockdown_ttl is not None
            else int(current.get("lockdown_ttl_hours") or ufw_mod.LOCKDOWN_TTL_DEFAULT_H)
        )
    except ufw_mod.UfwError as exc:
        console.print(f"[error][probe] {exc}[/error]")
        return 2

    planned = {
        "auto_lockdown": (
            auto_lockdown == "on" if auto_lockdown is not None
            else bool(current.get("auto_lockdown"))
        ),
        "lockdown_allow": allow_ips,
        "lockdown_ttl_hours": ttl_hours,
    }
    if planned["auto_lockdown"] and not (planned["lockdown_allow"] or load_own_ips()):
        console.print(
            "[error][probe] --auto-lockdown on отклонён (fail-fast SPEC §4.2, "
            "ужесточение HF-1): allow-list пуст — нет --lockdown-allow, а "
            f"{OWN_IPS_FILE} отсутствует/пуст. Авто-лок 443 без allow-IP закрыл бы "
            "владельцу весь прямой доступ (резервные порты в state больше не "
            "считаются основанием). Укажите --lockdown-allow IP[,IP…] или заполните "
            "allow-ips.txt.[/error]"
        )
        return 1
    console.print(f"[info][probe] Планируемый конфиг: {planned}[/info]")
    if not apply:
        console.print("[info][probe] Dry-run: ничего не изменено. Для применения — --apply.[/info]")
        return 0

    payload = dict(snapshot)
    payload["config"] = planned
    payload["ts"] = datetime.now().isoformat(timespec="seconds")
    try:
        with FileLock(LOCK_FILE):
            if not write_snapshot_payload(payload, snapshot_path):
                return 1
    except LockError:
        console.print("[error][probe] Параллельный прогон probe-watch — конфиг не записан.[/error]")
        return 1
    console.print(
        "[success][probe] Конфиг probe-watch записан (в снапшот; переживает рестарт юнита).[/success]"
    )
    return 0
