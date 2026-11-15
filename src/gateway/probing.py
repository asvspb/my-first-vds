"""Серверный монитор активного зондирования (Active Probing), исполнитель И33 v1.

Ранний сигнал перед TSPU-блокировкой: TSPU перед блоком обычно зондирует
порт протокола. `vds gateway probe-watch` измеряет tcp/443-зондирование без
изменения конфигов xray/hysteria2 (loglevel/access-log — вне WP):

- nft-таблица `inet vds_probe` (install --apply): счётчики syn_bare (все SYNs
  на 443) и syn_valid (SYNs с пакетом длиннее минимальных 40 б — клиентский
  SYN всегда несёт TCP-опции; голый SYN-сканер (masscan/zmap) — ровно 40);
  set probers4 — src-IP зондирований с per-element counter и timeout 1h;
- `watch` (read-only): дельта счётчиков против снапшота
  /var/lib/vds/probe-watch.json (атомарная запись 0600, FileLock) +
  journal-сигнатуры (см. JOURNAL_PATTERNS — только реальные сигнатуры,
  «нелишнее» не парсится: plain-TLS-пробы к 443 уходят в Reality
  dest-fallback и в журнал не пишутся — проверено на asv2);
- RU-классификация IP: если есть агрегат /etc/vds-relay/ru-cidrs.txt
  (пишет relay-cidr), помечает «[RU]»; иначе geo: unknown — честно;
- `--explain` (команда explain): честная карта покрытия сигналов на этом
  сервере (что активно, что слепо).

IPv6-пробы — non-goal v1 (см. explain). Read-only watch; мутации —
install/remove с --apply + dry-run по умолчанию; блокировки FileLock;
shell — только run_list.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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

XRAY_UNIT = "vds-xray.service"
HYSTERIA2_UNIT = "vds-hysteria2.service"

WATCH_PORT = 443
# Минимальный IPv4 SYN: 20 (IP) + 20 (TCP) = 40 б. Клиентский SYN всегда
# длиннее (TCP-опции MSS/SACK/timestamps; TLS-in-SYN у проб — ещё больше).
MIN_CLIENT_SYN_LEN = 40
SET_TIMEOUT = "1h"

DEFAULT_THRESHOLD = 50       # unique probers за окно для PROBE-BURST
BURST_RATIO = 0.90           # доля bare-SYN без payload
BURST_MIN_VOLUME = 100       # минимальный объём SYNs для ratio-критерия
DEFAULT_WINDOW_HOURS = 1
NEW_RU_IPS_THRESHOLD = 2     # новых RU-IP за окно для RU-PROBE-SUSPECT

# RU-CIDR-агрегат пишется relay-модулем (src/relay/cidr.py). Зависимость
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
    prober_rule = (
        f"tcp dport {WATCH_PORT} tcp flags & (fin|syn|rst|ack) == syn "
        f"update @{PROBERS_SET} {{ ip saddr }}"
    )
    return (
        "#!/usr/sbin/nft -f\n"
        "# Managed by `vds gateway probe-watch install` — DO NOT EDIT.\n"
        "# Монитор активного зондирования tcp/443 + udp/443 (IPv4, non-goal v6).\n"
        "table inet " + NFT_TABLE + " {\n"
        f"    counter syn_bare {{ }}\n"
        f"    counter syn_valid {{ }}\n"
        f"    counter udp_443 {{ }}\n"
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


@dataclass
class NftState:
    """Распарсенное состояние nft-таблицы монитора (read-only)."""

    syn_bare: int = 0
    syn_valid: int = 0
    udp_443: int = 0
    probers: dict[str, int] = field(default_factory=dict)  # ip -> packets
    per_element_counters: bool = False


def parse_nft_table(text: str) -> NftState:
    """Разобрать вывод `nft list table inet vds_probe`.

    per_element_counters=True, когда в set-элементах есть счётчики
    (`counter packets N bytes M`); иначе IP без счётчиков (packets=0).
    """
    state = NftState()
    for match in _COUNTER_RE.finditer(text):
        name, packets = match.group(1), int(match.group(2))
        if name == "syn_bare":
            state.syn_bare = packets
        elif name == "syn_valid":
            state.syn_valid = packets
        elif name == "udp_443":
            state.udp_443 = packets
    block = _ELEMENTS_BLOCK_RE.search(text)
    if block:
        for item in _ELEMENT_RE.finditer(block.group(1)):
            ip = item.group(1)
            packets = int(item.group(2) or 0)
            state.probers[ip] = packets
            if item.group(2) is not None:
                state.per_element_counters = True
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

SNAPSHOT_VERSION = 1


def load_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, object]:
    """Прочитать снапшот; отсутствует/бит — пустой (все нули, не ошибка)."""
    if not path.is_file():
        return {
            "version": SNAPSHOT_VERSION,
            "ts": "",
            "syn_bare": 0,
            "syn_valid": 0,
            "udp_443": 0,
            "probers": {},
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {
            "version": SNAPSHOT_VERSION,
            "ts": "",
            "syn_bare": 0,
            "syn_valid": 0,
            "udp_443": 0,
            "probers": {},
        }
    if not isinstance(data, dict):
        return {
            "version": SNAPSHOT_VERSION,
            "ts": "",
            "syn_bare": 0,
            "syn_valid": 0,
            "udp_443": 0,
            "probers": {},
        }
    probers = data.get("probers")
    if not isinstance(probers, dict):
        probers = {}
    return {
        "version": data.get("version", SNAPSHOT_VERSION),
        "ts": str(data.get("ts", "")),
        "syn_bare": int(data.get("syn_bare", 0) or 0),
        "syn_valid": int(data.get("syn_valid", 0) or 0),
        "udp_443": int(data.get("udp_443", 0) or 0),
        "probers": {str(k): int(v or 0) for k, v in probers.items()},
    }


def save_snapshot(current: NftState, path: Path = SNAPSHOT_PATH) -> bool:
    """Атомарно записать снапшот (tmp + os.replace, права 0600). True — успех."""
    payload = {
        "version": SNAPSHOT_VERSION,
        "ts": datetime.now().isoformat(timespec="seconds"),
        "syn_bare": current.syn_bare,
        "syn_valid": current.syn_valid,
        "udp_443": current.udp_443,
        "probers": current.probers,
    }
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


@dataclass
class Delta:
    """Дельта счётчиков за окно (текущее минус снапшот)."""

    syn_bare: int
    syn_valid: int
    udp_443: int
    bare_no_payload: int
    ratio_no_payload: Optional[float]
    unique_probers: int
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

    delta_bare = max(0, current.syn_bare - int(snapshot.get("syn_bare", 0)))
    delta_valid = max(0, current.syn_valid - int(snapshot.get("syn_valid", 0)))
    delta_udp = max(0, current.udp_443 - int(snapshot.get("udp_443", 0)))
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

    - **RU-PROBE-SUSPECT** (приоритет): RU-CIDR доступен, есть базовая
      активность (syn_valid_total > 0 — таблица работает на живом сервере
      с клиентами) и новых IP из RU-зоны (не из снапшота, не свой IP
      сервера) >= NEW_RU_IPS_THRESHOLD. Ловит профиль ТСПУ: точечное
      зондирование с RU-адресов даже при 2–5 шт/час.
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
    """Загрузить RU-CIDR-агрегат; None — файла нет (geo unknown — честно)."""
    path = path or RU_CIDR_FILE
    if not path.is_file():
        return None
    networks: list[ipaddress.IPv4Network] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            networks.append(ipaddress.ip_network(line, strict=False))
    except (ValueError, OSError):
        return networks  # частичный/битый агрегат: что распарсили — то вернули
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
    new_ru_ips: list[str] = field(default_factory=list)

    def geo(self, ip: str) -> str:
        """geo-метка с кэшем на один run (top-10 повторов)."""
        return classify_ip(ip, self._ru_networks, cache=self._geo_cache)

    def to_json(self) -> dict[str, object]:
        top = [
            {"ip": ip, "packets": cnt, "geo": self.geo(ip)}
            for ip, cnt in self.delta.top
        ]
        ru_top = [
            {"ip": ip, "packets": self._current_probers.get(ip, 0), "geo": "[RU]"}
            for ip in sorted(self.new_ru_ips, key=lambda i: (-self._current_probers.get(i, 0), i))
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
        }

    _ru_networks: Optional[list[ipaddress.IPv4Network]] = None
    _geo_cache: dict[str, str] = field(default_factory=dict)
    _current_probers: dict[str, int] = field(default_factory=dict)


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
) -> WatchReport:
    """Собрать отчёт из уже прочитанного состояния таблицы (тестируемо).

    server_ip — публичный адрес сервера; None → определить через netcheck
    (в тестах подменяется). Новые RU-IP: IP есть в set сейчас, отсутствовал
    в снапшоте, не сервер и не loopback.
    """
    snapshot = load_snapshot(snapshot_path)
    delta = compute_delta(current, snapshot)

    if server_ip is None:
        server_ip = _server_public_ip()
    snapshot_keys = set(snapshot.get("probers", {}))
    new_ru_ips: list[str] = []
    ru_networks = load_ru_cidrs()
    geo_cache: dict[str, str] = {}
    if ru_networks:
        for ip in current.probers:
            if ip in snapshot_keys or ip == server_ip:
                continue
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            if classify_ip(ip, ru_networks, cache=geo_cache) == "[RU]":
                new_ru_ips.append(ip)

    verdict = compute_verdict(
        delta,
        threshold,
        new_ru_ips=new_ru_ips,
        ru_available=bool(ru_networks),
        syn_valid_total=current.syn_valid,
    )

    end = now()
    start = end - timedelta(hours=since_hours)
    since = start.strftime("%Y-%m-%d %H:%M:%S")
    hits = scan_journal(since, run)

    geo_source = (
        "ru-cidrs (/etc/vds-relay/ru-cidrs.txt)"
        if ru_networks
        else "unknown (файл /etc/vds-relay/ru-cidrs.txt отсутствует)"
    )
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
    )
    report._ru_networks = ru_networks
    report._geo_cache = geo_cache
    report._current_probers = dict(current.probers)
    return report


def run_watch(
    since_hours: int = DEFAULT_WINDOW_HOURS,
    threshold: int = DEFAULT_THRESHOLD,
    run: RunFn = run_list,
    snapshot_path: Path = SNAPSHOT_PATH,
    now: Callable[[], datetime] = datetime.now,
) -> tuple[Optional[WatchReport], Optional[NftState]]:
    """Прочитать nft-таблицу и собрать отчёт.

    Возвращает (report, current); (None, None) — таблица отсутствует
    (подсказка install). current отдаётся для записи снапшота без повторного
    вызова nft.
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
    )
    return report, current


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
    if report.new_ru_ips:
        console.print(
            f"[warning][probe] Новые RU-IP за окно ({len(report.new_ru_ips)}):[/warning]"
        )
        for ip in sorted(
            report.new_ru_ips,
            key=lambda i: (-report._current_probers.get(i, 0), i),
        ):
            console.print(
                f"[warning][probe]   {escape(ip)}: "
                f"{report._current_probers.get(ip, 0)}[/warning]"
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
    """
    rows: list[ExplainRow] = []

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

    if ru_cidr_path.is_file():
        rows.append(
            ExplainRow(
                "вердикт RU-PROBE-SUSPECT",
                "ok",
                f"{ru_cidr_path} присутствует — новые RU-IP (>= {NEW_RU_IPS_THRESHOLD}/окно) "
                "сигнализируют точечное RU-зондирование; при отсутствии файла вердикт недоступен",
            )
        )
    else:
        rows.append(
            ExplainRow(
                "вердикт RU-PROBE-SUSPECT",
                "missing",
                f"без {ru_cidr_path} вердикт недоступен (geo: unknown) — ставится relay-модулем",
            )
        )

    rows.append(
        ExplainRow(
            "xray access-log / loglevel",
            "warn",
            "access-log выключен — сигнатуры invalid-auth не видны; включение = отдельный WP (владелец)",
        )
    )

    if ru_cidr_path.is_file():
        rows.append(
            ExplainRow(
                "RU-CIDR агрегат",
                "ok",
                f"{ru_cidr_path} присутствует — пробующие IP помечаются [RU]",
            )
        )
    else:
        rows.append(
            ExplainRow(
                "RU-CIDR агрегат",
                "missing",
                f"{ru_cidr_path} отсутствует — geo: unknown (ставится relay-модулем)",
            )
        )

    rows.append(
        ExplainRow(
            "IPv6-пробы",
            "missing",
            "non-goal v1: наблюдение только tcp/443 IPv4 (v6-зондирование не меряется)",
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
    repo_dir = Path(__file__).resolve().parents[2]
    return {
        "python": shutil.which("python3") or "/usr/bin/python3",
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
        console.print(f"[info][probe]   2. счётчики syn_bare/syn_valid/udp_443, set {PROBERS_SET} (flags dynamic,timeout, size 65535, timeout {SET_TIMEOUT}, per-element counter; при отказе ядра — fallback без счётчиков на IP)[/info]")
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


def cmd_watch(
    since_hours: int = DEFAULT_WINDOW_HOURS,
    threshold: int = DEFAULT_THRESHOLD,
    json_out: bool = False,
    record: bool = False,
    snapshot_path: Optional[Path] = None,
    run: RunFn = run_list,
) -> int:
    """watch: отчёт за окно; read-only по умолчанию.

    record=True — только для юнита таймера: после отчёта снапшот
    перезаписывается текущими счётчиками (базой следующего окна). Ручной
    `watch` без --record ничего не пишет.
    """
    snapshot_path = snapshot_path or SNAPSHOT_PATH
    from src.core.lock import FileLock, LockError

    try:
        with FileLock(LOCK_FILE):
            report, current = run_watch(
                since_hours=since_hours, threshold=threshold, run=run,
                snapshot_path=snapshot_path,
            )
            if report is None or current is None:
                console.print(
                    f"[error][probe] nft-таблица inet {NFT_TABLE} отсутствует — "
                    "выполните `vds gateway probe-watch install --apply`.[/error]"
                )
                return 1
            if json_out:
                print(json.dumps(report.to_json(), ensure_ascii=False))
            else:
                print_report(report)
            if record:
                save_snapshot(current, snapshot_path)
    except LockError:
        console.print(
            "[warning][probe] Параллельный прогон probe-watch — отчёт отдан "
            "ему, повторный запуск не выполнен.[/warning]"
        )
        return 1
    return 0
