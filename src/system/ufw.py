"""UFW hardening (SPEC-20261116): план-билдер + apply/undo + двухфазный ssh-port.

Принципы:
- dry-run по умолчанию; мутирующие шаги — только при ``--apply`` под FileLock.
- ``ufw reset`` запрещён; существующие правила (relay init, amneziawg install,
  hysteria2 hop, xray cdn) детектируются парсером ``ufw status`` и не дублируются.
- Fail-safe порядок (SPEC §1.10): defaults → ssh-лимит (первым из allow-набора)
  → сервисные порты → forwarding-конфиг → ``ufw --force enable`` строго последним,
  только после подтверждения наличия ssh-правила.
- ICMP не трогаем (решение владельца 2026-11-16): никакого drop echo-request —
  обоснование «Правило знаний: ICMP и диагностика маршрута» (SERVER-BASELINE §5).
- Docker обходит UFW (nat PREROUTING/DOCKER раньше ufw) — слушающие порты вне
  плана печатаются как [warning].
- ssh-перенос двухфазный: Фаза A (limit N + sshd-конфиг + restart) НЕ закрывает
  22; 22 удаляет только ``--finalize`` после подтверждения владельцем входа на N.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import ShellResult, command_exists, run_list
from src.gateway.paths import STATE_PATH
from src.gateway.store import GatewayState, StoreError, load_state, save_state

# Пути (тесты monkeypatch'ат на tmp).
UFW_SSHD_CONF = Path("/etc/ssh/sshd_config.d/99-vds-port.conf")
UFW_SOCKET_DROPIN = Path("/etc/systemd/system/ssh.socket.d/99-port.conf")
UFW_DEFAULTS = Path("/etc/default/ufw")
RUN_SSHD_DIR = Path("/run/sshd")  # sshd -t падает без privilege separation dir
LOCK_PATH = "/var/run/vds.lock"

# Правило знаний (SPEC §1.4): harden не трогает nft-таблицу inet vds_probe
# (probe-watch) и не выполняет nft flush — ufw (iptables-nft) живёт в своих
# стандартных цепочках INPUT/FORWARD/OUTPUT, таблицы nft независимы.
# Правило знаний (SPEC §1.5): Docker обходит UFW — слушающие порты вне плана
# сравниваются с `ss -tlnp` / `ss -ulnp` и печатаются [warning].

SSH_PORT_PENDING_KEY = "ufw-ssh-port"
UFW_META_KEY = "ufw"
LEGACY_SSH_PORT = 22

# Официальные IPv4-подсети Cloudflare (https://www.cloudflare.com/ips-v4,
# 15 CIDR; обновление — правкой кода коммитом, SPEC-20261116-surface-hardening
# §2.2). CDN-порт Xray (2053/tcp) открывается только для них: origin слушает
# за CF proxy; v6 — вне скоупа.
CLOUDFLARE_CIDRS_V4: tuple[str, ...] = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)


class UfwError(Exception):
    """Ошибка harden/ssh-port: читаемо выводится в CLI, без traceback."""


@dataclass
class UfwRule:
    """Нормализованное правило ufw (canonical-строка для детекции дублей)."""

    canonical: str  # "allow 443/tcp", "limit 22/tcp", "allow from IP to any port 443 proto tcp"
    action: str  # allow | limit | deny | reject
    port: str  # "443" | "20000:20500" | "" (from-only/Anywhere)
    proto: str  # tcp | udp | ""
    src: str  # "any" или IP
    raw: str = ""  # исходная строка вывода

    def matches_plan(self, action: str, spec: str, src: str = "any") -> bool:
        """spec: "443/tcp", "20000:20500/udp" или from-строка ("from IP to any port 443 proto tcp")."""
        if spec.startswith("from "):
            return self.canonical == f"{action} {spec}"
        want_port, _, want_proto = spec.partition("/")
        return (
            self.action == action
            and self.port == want_port
            and self.proto == want_proto
            and self.src == src
        )


@dataclass
class UfwSnapshot:
    """Состояние ufw из текстового вывода status (+verbose для дефолтов)."""

    status: str = "inactive"  # active | inactive
    default_incoming: str = ""
    default_outgoing: str = ""
    default_routed: str = ""
    rules: list[UfwRule] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)

    def has(self, action: str, spec: str, src: str = "any") -> bool:
        return any(r.matches_plan(action, spec, src) for r in self.rules)


def cf_cidr_specs(port: str | int) -> list[str]:
    """from-спеки CF-CIDR-набора для порта CDN (SPEC §2.2). Полный набор —
    штатное покрытие порта: широкое ``allow <port>/tcp`` не требуется."""
    return [
        f"from {cidr} to any port {port} proto tcp"
        for cidr in CLOUDFLARE_CIDRS_V4
    ]


def snapshot_cf_covered(snapshot: UfwSnapshot, port: str | int) -> bool:
    """Порт полностью покрыт CF-CIDR-набором (все 15 правил на месте)?"""
    return all(snapshot.has("allow", spec) for spec in cf_cidr_specs(port))


def cdn_port_of(state: GatewayState) -> str | None:
    """CDN-порт из state.protocols['xray-cdn'] (установлен — иначе None)."""
    meta = state.protocols.get("xray-cdn") or {}
    if not meta.get("installed"):
        return None
    return str(meta.get("port") or "2053")


@dataclass
class PlanItem:
    """Шаг плана: rule|config|enable|check; action add|skip|warn."""

    kind: str  # rule | config | enable | check
    detail: str  # human-readable, напр. "ufw limit 22/tcp"
    action: str = "add"  # add | skip | warn
    meta: dict = field(default_factory=dict)

    @property
    def is_enable(self) -> bool:
        return self.kind == "enable"

    @property
    def is_ssh_rule(self) -> bool:
        return self.kind == "rule" and self.meta.get("ssh") is True

    @property
    def cli_args(self) -> list[str]:
        """Аргументы run_list для apply (rule/config/enable)."""
        if self.kind == "rule":
            spec = self.meta["spec"]
            src = self.meta.get("src", "any")
            action = self.meta["action"]
            if spec.startswith("from "):
                toks = ["ufw", action] + spec.split()
            else:
                toks = ["ufw", action, spec]
            if src != "any" and not spec.startswith("from "):
                toks = toks + ["from", src]
            return toks
        if self.kind == "enable":
            return ["ufw", "--force", "enable"]
        return []  # config/check выполняются специализированными функциями


@dataclass
class HardeningOpts:
    allow_from: Optional[str] = None  # IP релея для exit-cascade
    ssh_port: Optional[int] = None  # переопределение; иначе из state (pending/final)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Парсер ufw status / status verbose
# ---------------------------------------------------------------------------

# Формат колонок ufw status: `To  Action  From` — «22/tcp  LIMIT IN  Anywhere».
_FROM_RE = re.compile(r"^(\S+)\s+(LIMIT|ALLOW|DENY|REJECT)\s+IN\s+(.+)$")


def _canonical_from_to(to_field: str, from_field: str, action_word: str) -> UfwRule:
    """Строка вывода ufw -> UfwRule с canonical-строкой."""
    src = from_field.replace(" (v6)", "").strip()
    src = re.sub(r"\s*\(v6\)\s*$", "", src).strip()
    if src == "Anywhere":
        src = "any"
    to_field = to_field.strip()
    if to_field == "Anywhere":
        # from-only правило: allow from <ip>
        canonical = f"{action_word} from {src}" if src != "any" else f"{action_word} (anywhere)"
        return UfwRule(canonical, action_word, "", "", src)
    port_part = to_field.replace(" (v6)", "").strip()
    port, _, proto = port_part.partition("/")
    proto = proto.strip() or ""
    if src == "any":
        canonical = f"{action_word} {port}/{proto}" if proto else f"{action_word} {port}"
    else:
        canonical = f"{action_word} from {src} to any port {port}"
        if proto:
            canonical += f" proto {proto}"
    return UfwRule(canonical, action_word, port, proto, src)


def parse_ufw_status(text: str) -> UfwSnapshot:
    """Парсить текст `ufw status` или `ufw status verbose` (LC_ALL=C).

    Нераспознанные содержательные строки попадают в snapshot.unparsed —
    вызывающая сторона печатает [warning] (риск другой локали/версии).
    """
    snap = UfwSnapshot()
    m = re.search(r"^Status:\s*(active|inactive)\s*$", text, re.MULTILINE)
    if m:
        snap.status = m.group(1)
    md = re.search(
        r"^Default:\s*(\S+)[^,]*,\s*(\S+)\s*\(outgoing\)(?:,\s*(\S+)\s*\(routed\))?",
        text,
        re.MULTILINE,
    )
    if md:
        snap.default_incoming = md.group(1)
        snap.default_outgoing = md.group(2)
        snap.default_routed = md.group(3) or ""
    header_seen = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Status:") or stripped.startswith("Default:"):
            continue
        if stripped.startswith("--"):
            header_seen = True
            continue
        if stripped.startswith("To ") or stripped.startswith("To\t") or stripped == "To":
            continue
        if stripped.startswith("Logging:"):
            continue
        if not header_seen:
            continue
        mm = _FROM_RE.match(stripped)
        if mm:
            action_word = mm.group(2).lower()
            snap.rules.append(_canonical_from_to(mm.group(1), mm.group(3), action_word))
            continue
        snap.unparsed.append(stripped)
    return snap


def _ufw_status_text() -> str:
    """`ufw status verbose` с LC_ALL=C (риск другой локали — SPEC §9)."""
    with _env({"LC_ALL": "C"}):
        res = run_list(["ufw", "status", "verbose"], timeout=15)
    if not res.ok:
        raise UfwError(
            f"ufw status verbose не удался: {res.stderr.strip() or res.stdout.strip()}"
        )
    return res.stdout


_ADDED_RE = re.compile(
    r"^ufw\s+(limit|allow|deny|reject)\s+(.+)$"
)


def parse_ufw_added(text: str) -> list[UfwRule]:
    """Парсить `ufw show added` (работает и при inactive).

    При Status: inactive обычный `ufw status` НЕ показывает прописанные
    правила — детекция существующих комбинируется: status (active) +
    show added (обоих состояний). Строки: `ufw limit 22/tcp`,
    `ufw allow from 203.0.113.10 to any port 443 proto tcp`,
    `ufw allow 20000:20500/udp`.
    """
    rules: list[UfwRule] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Added:") or stripped.startswith("###") or not stripped:
            continue
        mm = _ADDED_RE.match(stripped)
        if not mm:
            continue
        action, rest = mm.group(1), mm.group(2).strip()
        # rest: "443/tcp" | "20000:20500/udp" | "22" | "from IP to any port 443 proto tcp"
        if rest.startswith("from "):
            toks = rest.split()
            try:
                src = toks[1]
                port = toks[toks.index("port") + 1]
                proto = toks[toks.index("proto") + 1] if "proto" in toks else ""
            except (ValueError, IndexError):
                continue
            canonical = f"{action} from {src} to any port {port}"
            if proto:
                canonical += f" proto {proto}"
            rules.append(UfwRule(canonical, action, port, proto, src))
        else:
            port, _, proto = rest.partition("/")
            proto = proto.strip()
            canonical = f"{action} {port}/{proto}" if proto else f"{action} {port}"
            rules.append(UfwRule(canonical, action, port, proto, "any"))
    return rules


def _ufw_snapshot_combined() -> UfwSnapshot:
    """status verbose + (при inactive) `ufw show added` — существующие правила
    не теряются до enable (техлид-уточнение 2026-11-16, п.1)."""
    snap = parse_ufw_status(_ufw_status_text())
    if snap.status == "inactive":
        with _env({"LC_ALL": "C"}):
            res = run_list(["ufw", "show", "added"], timeout=15)
        if res.ok:
            added = parse_ufw_added(res.stdout)
            known = {r.canonical for r in snap.rules}
            for r in added:
                if r.canonical not in known:
                    snap.rules.append(r)
    return snap


@contextmanager
def _env(overrides: dict[str, str]) -> Iterator[None]:
    """Временно подменить os.environ (run_list наследует окружение процесса)."""
    saved = {k: os.environ.get(k) for k in overrides}
    try:
        os.environ.update(overrides)
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# Порт-набор профиля из state.protocols
# ---------------------------------------------------------------------------

# Отображение state.protocols -> правило. port берётся из meta ("port"), если нет — дефолт.
_PROTOCOL_RULES: dict[str, tuple[str, str]] = {
    # ключ state: (spec-шаблон "port/proto" или фикс, дефолтный порт)
    "xray": ("tcp", "443"),
    "hysteria2": ("udp", "443"),
    "hysteria2-obfs": ("udp", "51826"),
    "amneziawg": ("udp", "51825"),
    "xhttp": ("tcp", "8443"),
    "xray-cdn": ("tcp", "2053"),
    "acme": ("tcp", "80"),
}


def profile_service_specs(state: GatewayState, profile: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Набор правил профиля: [(spec|from-spec, src)], 443-транспорты для каскада.

    Возвращает (specs, cascade_443) где cascade_443 = [("tcp"|"udp", transport)].
    """
    protocols = state.protocols
    specs: list[str] = []
    cascade_443: list[tuple[str, str]] = []
    if profile == "relay":
        # ADR-007: AWG udp/443 + Reality tcp/443; relay init сам делает
        # `ufw allow 443/udp` — harden детектирует и печатает [skip].
        specs = ["443/udp", "443/tcp"]
        return specs, []
    # gateway / exit-cascade
    for key, (proto, default_port) in _PROTOCOL_RULES.items():
        meta = protocols.get(key) or {}
        if not meta.get("installed"):
            continue
        port = str(meta.get("port") or default_port)
        spec = f"{port}/{proto}"
        if profile == "exit-cascade" and port == "443":
            cascade_443.append((proto, key))
        else:
            specs.append(spec)
    hop = (protocols.get("hysteria2") or {}).get("hop_ports")
    if hop:
        # state хранит "-" (share-link mport), UFW требует ":" в диапазоне.
        hop_spec = str(hop).strip().replace("-", ":")
        # одно правило на весь диапазон, напр. "20000:20500/udp" (SPEC §9)
        specs.append(hop_spec if "/" in hop_spec else f"{hop_spec}/udp")
    return specs, cascade_443


def resolve_ssh_ports(state: GatewayState, opts: HardeningOpts) -> list[int]:
    """Итоговый ssh-порт(ы) для limit: 22; N после finalize; N+22 при pending."""
    if opts.ssh_port is not None:
        return [opts.ssh_port]
    meta = state.protocols.get(SSH_PORT_PENDING_KEY) or {}
    port = meta.get("port")
    if port and meta.get("pending"):
        return [int(port), LEGACY_SSH_PORT]  # SPEC §1.10.3: limit на ОБА порта
    if port and not meta.get("pending") and not meta.get("legacy_22_still_open"):
        return [int(port)]
    return [LEGACY_SSH_PORT]


def final_ssh_port(state: GatewayState) -> int:
    """Один итоговый ssh-порт (для подписей/undo)."""
    return resolve_ssh_ports(state, HardeningOpts())[-1]


# ---------------------------------------------------------------------------
# План
# ---------------------------------------------------------------------------


def _rule_item(action: str, spec: str, snapshot: UfwSnapshot, *, src: str = "any", ssh: bool = False) -> PlanItem:
    if snapshot.has(action, spec, src):
        detail = f"ufw {action} {spec}"
        return PlanItem("rule", detail + (" [уже есть]" if not ssh else ""), "skip",
                        {"action": action, "spec": spec, "src": src, "ssh": ssh})
    detail = f"ufw {action} {spec}"
    return PlanItem("rule", detail, "add", {"action": action, "spec": spec, "src": src, "ssh": ssh})


def build_plan(
    profile: str,
    state: GatewayState,
    snapshot: UfwSnapshot,
    opts: HardeningOpts,
    ss_lines: Optional[list[str]] = None,
) -> list[PlanItem]:
    """План hardening: defaults → ssh-лимит → сервисные порты → forwarding → enable."""
    if profile not in ("gateway", "relay", "exit-cascade"):
        raise UfwError(f"Неизвестный профиль {profile!r} (gateway|relay|exit-cascade)")
    plan: list[PlanItem] = []

    # 1. defaults (до enable не активны — SPEC §1.10.2)
    if snapshot.default_incoming and snapshot.default_incoming == "deny":
        plan.append(PlanItem("config", "ufw default deny incoming [уже установлен]", "skip"))
    else:
        plan.append(PlanItem("config", "ufw default deny incoming", "add",
                             {"config": "default-incoming"}))
    if snapshot.default_outgoing and snapshot.default_outgoing == "allow":
        plan.append(PlanItem("config", "ufw default allow outgoing [уже установлен]", "skip"))
    else:
        plan.append(PlanItem("config", "ufw default allow outgoing", "add",
                             {"config": "default-outgoing"}))

    # 2. ssh-лимит — всегда первым из allow-набора (SPEC §1.10.3)
    for port in resolve_ssh_ports(state, opts):
        plan.append(_rule_item("limit", f"{port}/tcp", snapshot, ssh=True))

    # 3. сервисные порты профиля (SPEC §1.10.4)
    specs, cascade_443 = profile_service_specs(state, profile)
    if profile == "exit-cascade":
        if not opts.allow_from:
            raise UfwError(
                "Профиль exit-cascade требует --allow-from <relay-ip>: без него "
                "443 либо откроется всем, либо каскад потеряет ingress."
            )
        # ЗАМЕНЯЮЩАЯ семантика: широкие (Anywhere) 443-правила прежнего
        # gateway-профиля удаляются — 443 остаётся только для релея
        # (техлид-уточнение 2026-11-16, п.4)
        for wide in snapshot.rules:
            if wide.action == "allow" and wide.port == "443" and wide.src == "any" and wide.proto in ("tcp", "udp"):
                plan.append(PlanItem(
                    "rule",
                    f"ufw delete allow 443/{wide.proto} [широкое Anywhere-правило → заменяется from-правилом]",
                    "add",
                    {"action": "allow", "spec": f"443/{wide.proto}", "delete": True},
                ))
        for proto, key in cascade_443:
            from_spec = f"from {opts.allow_from} to any port 443 proto {proto}"
            plan.append(_rule_item("allow", from_spec, snapshot))
        if not cascade_443:
            plan.append(PlanItem(
                "check",
                "exit-cascade: в state нет установленных 443-транспортов (xray/hysteria2) — "
                "from-правила для 443 не добавлены",
                "warn",
            ))
        for spec in specs:
            plan.append(_rule_item("allow", spec, snapshot))
    else:
        cdn_port = cdn_port_of(state)
        for spec in specs:
            if cdn_port is not None and spec == f"{cdn_port}/tcp":
                # CDN-порт — только Cloudflare (SPEC §2.2): CF-CIDR-набор
                # признаётся штатным покрытием. Миграция: СНАЧАЛА все CIDR,
                # только после них — удаление широкого правила (живая сессия
                # через CDN не должна мигнуть); порядок в плане = порядок apply.
                for from_spec in cf_cidr_specs(cdn_port):
                    plan.append(_rule_item("allow", from_spec, snapshot))
                if snapshot.has("allow", spec):
                    plan.append(PlanItem(
                        "rule",
                        f"ufw delete allow {spec} [широкое CDN-правило → CF-CIDR-набор]",
                        "add",
                        {"action": "allow", "spec": spec, "delete": True},
                    ))
                continue
            plan.append(_rule_item("allow", spec, snapshot))

    # 4. forwarding-конфиг (SPEC §1.10.5) + ip_forward-проверка
    plan.append(PlanItem("config", "DEFAULT_FORWARD_POLICY=ACCEPT в /etc/default/ufw", "add",
                         {"config": "forward-policy"}))
    plan.append(PlanItem(
        "check",
        "ip_forward должен быть 1 (persist в sysctl.d от amneziawg/relay; harden его НЕ пишет)",
        "add",
        {"check": "ip_forward"},
    ))

    # 5. listeners-сверка (Docker обходит UFW — SPEC §1.5)
    if ss_lines is not None:
        ports = set(specs)
        if profile == "exit-cascade":
            ports = {f"443/{proto}" for proto, _ in cascade_443} | ports
        for port in resolve_ssh_ports(state, opts):
            ports.add(f"{port}/tcp")
        for warn in diff_listeners(ports, ss_lines):
            plan.append(PlanItem("check", warn, "warn"))

    # 6. enable — строго последним (SPEC §1.10.6)
    if snapshot.status == "active":
        plan.append(PlanItem("enable", "ufw --force enable [уже active — skip]", "skip"))
    else:
        plan.append(PlanItem("enable", "ufw --force enable (последний шаг)", "add"))

    return order_steps(plan)


def order_steps(plan: list[PlanItem]) -> list[PlanItem]:
    """Fail-safe: enable-шаг всегда последним (unit-тест на индекс enable)."""
    non_enable = [p for p in plan if not p.is_enable]
    enables = [p for p in plan if p.is_enable]
    return non_enable + enables


def diff_listeners(profile_ports: set[str], ss_lines: list[str]) -> list[str]:
    """Порты, слушающиеся на 0.0.0.0/::, но отсутствующие в плане — [warning]-строки.

    Docker обходит UFW (nat PREROUTING/DOCKER раньше ufw-before-input), поэтому
    docker-proxy попадает в предупреждение отдельной пометкой.
    """
    warns: list[str] = []
    for line in ss_lines:
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("LISTEN", "UNCONN"):
            continue
        local = parts[3]
        if "@" not in local and local.count(":") == 0:
            continue
        try:
            port = local.rsplit(":", 1)[1]
        except IndexError:
            continue
        if not port.isdigit():
            continue
        users = line[line.find("users:("):] if "users:(" in line else ""
        pname = ""
        mu = re.search(r'\(\("([^"]+)"', users)
        if mu:
            pname = mu.group(1)
        is_loopback = (
            local.startswith("127.")
            or local.startswith("[::1]")
            or local.startswith("::1")
        )
        if is_loopback:
            continue
        for proto in ("tcp", "udp"):
            if f"{port}/{proto}" in profile_ports:
                break
        else:
            mark = " (docker-proxy — обходит UFW!)" if pname == "docker-proxy" else ""
            who = f" [{pname}]" if pname else ""
            warns.append(f"порт {port} слушается{who}, но не открыт в UFW-плане{mark}")
    return warns


def listeners_ss_lines() -> Optional[list[str]]:
    """Собрать `ss -tlnp` + `ss -ulnp`; недоступно — None (проверка пропускается)."""
    if not command_exists("ss"):
        return None
    lines: list[str] = []
    for flags in (["-tlnp"], ["-ulnp"]):
        res = run_list(["ss"] + flags, timeout=10)
        if res.ok:
            lines.extend(res.stdout.splitlines())
    return lines


# ---------------------------------------------------------------------------
# Apply / undo
# ---------------------------------------------------------------------------


def _apply_config_item(item: PlanItem, root_prefix: str = "") -> str:
    """Исполнить config-шаги: ufw default …, DEFAULT_FORWARD_POLICY, ip_forward-чек."""
    cfg = item.meta.get("config", "")
    if cfg == "default-incoming":
        res = run_list(["ufw", "default", "deny", "incoming"], timeout=15)
        _check(res, "ufw default deny incoming")
        return "ufw default deny incoming"
    if cfg == "default-outgoing":
        res = run_list(["ufw", "default", "allow", "outgoing"], timeout=15)
        _check(res, "ufw default allow outgoing")
        return "ufw default allow outgoing"
    if cfg == "forward-policy":
        return "DEFAULT_FORWARD_POLICY=ACCEPT (/etc/default/ufw)" if _set_forward_policy(UFW_DEFAULTS) else ""
    return item.detail


def _check(res: ShellResult, what: str) -> None:
    if not res.ok:
        raise UfwError(f"{what} не удался: {res.stderr.strip() or res.stdout.strip()}")


def _set_forward_policy(path: Path) -> bool:
    """sed-guard DEFAULT_FORWARD_POLICY в /etc/default/ufw (атомарно; без reset).

    Возвращает True, если файл изменён (False = уже ACCEPT — идемпотентно)."""
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if re.search(r'^DEFAULT_FORWARD_POLICY="ACCEPT"\s*$', text, flags=re.MULTILINE):
        return False
    new_text = re.sub(
        r"^DEFAULT_FORWARD_POLICY=.*$",
        'DEFAULT_FORWARD_POLICY="ACCEPT"',
        text,
        flags=re.MULTILINE,
    )
    if "DEFAULT_FORWARD_POLICY" not in text:
        new_text = text.rstrip("\n") + '\nDEFAULT_FORWARD_POLICY="ACCEPT"\n'
    tmp = path.with_name(path.name + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(new_text, encoding="utf-8")
    os.replace(tmp, path)
    return True


def _check_ip_forward() -> str:
    res = run_list(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)
    return res.output if res.ok else "?"


def _ssh_rule_satisfied(plan: list[PlanItem], snapshot: UfwSnapshot) -> bool:
    """Fail-fast перед enable: ssh-правило либо уже есть, либо добавлено в этом прогоне."""
    for item in plan:
        if item.is_ssh_rule and item.action in ("add", "skip"):
            return True
    # fallback: прямая проверка снапшота
    for item in plan:
        if item.is_ssh_rule:
            meta = item.meta
            if snapshot.has(meta["action"], meta["spec"], meta.get("src", "any")):
                return True
    return False


def run_harden(
    profile: str,
    apply: bool = False,
    undo: bool = False,
    opts: Optional[HardeningOpts] = None,
    state_path: Optional[str] = None,
    lock_path: Optional[str] = None,
    include_ss: bool = True,
    force: bool = False,
) -> int:
    """CLI-движок `system ufw harden`: dry-run по умолчанию, --apply под FileLock."""
    opts = opts or HardeningOpts()
    if not command_exists("ufw"):
        console.print("[error][ufw] ufw не установлен: apt install -y ufw[/error]")
        return 1
    if apply and os.geteuid() != 0:
        console.print("[error][ufw] --apply требует root (sudo).[/error]")
        return 2
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1

    _print_pending_warning(state)

    if undo:
        return run_undo(state_path=state_path, lock_path=lock_path)

    # Guard SPEC §9.C: harden при активном локе 443 — отказ (журналы не смешиваются);
    # обход только осознанным --force с записью в журнал лока.
    ld_state = get_lockdown(state)
    if ld_state["active"]:
        if apply and not force:
            console.print(
                "[error][ufw] Активен lock-443 — harden отказан (SPEC §9.C: смесь журналов "
                "сломала бы undo обоих). Сначала `sudo vds system ufw lock-443 --unlock --apply`, "
                "затем harden; осознанный обход — `harden --force --apply`.[/error]"
            )
            return 1
        if force:
            console.print(
                "[warning][ufw] harden выполняется ПРИ активном локе 443 (--force) — "
                "событие записывается в журнал лока.[/warning]"
            )
            state.ufw_lockdown["events"] = _append_event(
                dict(state.ufw_lockdown), "harden-force", "harden при активном lock-443 (--force)"
            )
        else:
            console.print(
                "[warning][ufw] Активен lock-443 — показан dry-run план; apply потребует "
                "сначала --unlock либо --force (SPEC §9.C).[/warning]"
            )

    snapshot = _ufw_snapshot_combined()
    for line in snapshot.unparsed:
        console.print(f"[warning][ufw] Нераспознанная строка ufw status: {line!r}[/warning]")

    ss_lines = listeners_ss_lines() if include_ss else None
    try:
        plan = build_plan(profile, state, snapshot, opts, ss_lines)
    except UfwError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1

    adds = sum(1 for p in plan if p.action == "add")
    skips = sum(1 for p in plan if p.action == "skip")
    warns = sum(1 for p in plan if p.action == "warn")
    console.print(f"[info][ufw] План профиля {profile}: {adds} add / {skips} skip / {warns} warn[/info]")
    for item in plan:
        tag = {"add": "add", "skip": "skip", "warn": "warning"}[item.action]
        console.print(f"  [{tag}] {item.detail}")
    if not apply:
        console.print("[info][ufw] Dry-run: ничего не изменено. Для применения — --apply.[/info]")
        return 0

    with FileLock(lock_path or LOCK_PATH):
        snapshot = _ufw_snapshot_combined()
        was_active = snapshot.status == "active"
        plan = build_plan(profile, state, snapshot, opts, ss_lines)
        applied_rules: list[str] = []
        for item in plan:
            if item.action == "skip":
                continue
            if item.kind == "rule":
                if item.meta.get("delete"):
                    # ЗАМЕНЯЮЩАЯ семантика каскада: удалить широкое правило,
                    # запомнить в undo-журнале для восстановления
                    res = run_list(["ufw", "delete"] + item.cli_args[1:], timeout=15)
                    if not res.ok:
                        out = (res.stdout + res.stderr).lower()
                        if "could not" in out or "not found" in out:
                            console.print(f"[info][ufw] правило уже удалено: {item.detail}[/info]")
                        else:
                            console.print(
                                f"[error][ufw] {item.detail} не удался: "
                                f"{res.stderr.strip() or res.stdout.strip()}[/error]"
                            )
                            return 1
                    applied_rules.append(f"__deleted__ {item.meta['action']} {item.meta['spec']}")
                    console.print(f"[success][ufw] применено: {item.detail}[/success]")
                    continue
                res = run_list(item.cli_args, timeout=15)
                if not res.ok:
                    out = (res.stdout + res.stderr).lower()
                    # существующее правило -> ufw возвращает неуспех (SPEC §1.3):
                    # совпадение строки считаем идемпотентным успехом
                    if "skipping adding" in out or "rule added" in out:
                        console.print(f"[info][ufw] идемпотентно: {item.detail}[/info]")
                    else:
                        console.print(
                            f"[error][ufw] {item.detail} не удался: "
                            f"{res.stderr.strip() or res.stdout.strip()}[/error]"
                        )
                        return 1
                spec = item.meta["spec"]
                applied_rules.append(
                    f"{item.meta['action']} {spec}"
                    + (f" from {item.meta['src']}" if item.meta.get("src") not in (None, "any") else "")
                )
                console.print(f"[success][ufw] применено: {item.detail}[/success]")
            elif item.kind == "config":
                try:
                    outcome = _apply_config_item(item)
                except (UfwError, OSError) as exc:
                    console.print(f"[error][ufw] {item.detail}: {exc}[/error]")
                    return 1
                if not outcome:
                    console.print(f"[info][ufw] идемпотентно: {item.detail} (уже применено)[/info]")
                    continue
                if item.meta.get("config") == "forward-policy":
                    applied_rules.append("DEFAULT_FORWARD_POLICY=ACCEPT")
                    # правка /etc/default/ufw не применяется действующим ufw:
                    # при повторном прогоне (ufw уже active) нужен reload
                    # (техлид-уточнение 2026-11-16, п.5)
                    if was_active:
                        r = run_list(["ufw", "reload"], timeout=30)
                        _check(r, "ufw reload (правка DEFAULT_FORWARD_POLICY при active)")
                        console.print("[success][ufw] ufw reload: политика forward применена.[/success]")
                        applied_rules.append("__reload__")
                console.print(f"[success][ufw] применено: {item.detail}[/success]")
            elif item.kind == "check":
                if item.meta.get("check") == "ip_forward":
                    val = _check_ip_forward()
                    if val != "1":
                        console.print(
                            f"[warning][ufw] net.ipv4.ip_forward = {val} (ожидался 1). "
                            "Маршрутизация каскада/релея не заработает: включите через "
                            "sysctl.d (amneziawg/relay install) и повторите.[/warning]"
                        )

        # Fail-safe: enable строго последним и только при подтверждённом ssh-правиле
        enables = [p for p in plan if p.is_enable and p.action == "add"]
        if enables:
            if not _ssh_rule_satisfied(plan, snapshot):
                console.print(
                    "[error][ufw] ssh-правило отсутствует в наборе — enable ОТМЕНЁН "
                    "(fail-safe SPEC §1.10.6). Проверьте план вручную.[/error]"
                )
                return 1
            res = run_list(["ufw", "--force", "enable"], timeout=30)
            if not res.ok:
                console.print(
                    f"[error][ufw] ufw enable не удался: {res.stderr.strip() or res.stdout.strip()}. "
                    f"Откат: ufw disable; удалите добавленные правила: {applied_rules}[/error]"
                )
                return 1
            console.print("[success][ufw] ufw включён.[/success]")
            applied_rules.append("__enabled__")

        # meta в state (без секретов)
        meta = dict(state.protocols.get(UFW_META_KEY) or {})
        meta.update({
            "installed": True,
            "profile": profile,
            "ssh_port": final_ssh_port(state),
            "applied_rules": applied_rules,
            "ufw_was_active": snapshot.status == "active" or bool(enables) is False,
            "ts": _now_iso(),
        })
        state.protocols[UFW_META_KEY] = meta
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error][ufw] Правила применены, но state не сохранён: {exc}[/error]")
            return 1
    console.print("[success][ufw] Hardening применён (undo: `vds system ufw harden --undo --apply`).[/success]")
    return 0


def _print_pending_warning(state: GatewayState) -> None:
    meta = state.protocols.get(SSH_PORT_PENDING_KEY) or {}
    if meta.get("pending"):
        port = meta.get("port", "?")
        console.print(
            f"[warning][ufw] Перенос ssh-порта начат, порт 22 ещё открыт — выполните "
            f"`sudo vds system ufw ssh-port --finalize` после проверки входа на {port} "
            "со ВТОРОГО терминала.[/warning]"
        )


def run_undo(
    state_path: Optional[str] = None,
    lock_path: Optional[str] = None,
    apply: bool = False,
) -> int:
    """`harden --undo`: снять ровно то, что harden добавил (журнал applied_rules)."""
    if apply and os.geteuid() != 0:
        console.print("[error][ufw] --apply требует root (sudo).[/error]")
        return 2
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1
    meta = state.protocols.get(UFW_META_KEY) or {}
    if not meta.get("installed"):
        console.print("[warning][ufw] Откатывать нечего: meta ufw в state пуста.[/warning]")
        return 0
    applied: list[str] = list(meta.get("applied_rules") or [])
    removal_plan: list[str] = []
    for r in applied:
        if r.startswith("__deleted__"):
            removal_plan.append(f"ufw {r.split('__deleted__ ', 1)[1]} (восстановление после cascade)")
        elif not r.startswith("__") and r != "DEFAULT_FORWARD_POLICY=ACCEPT":
            removal_plan.append(f"ufw delete {r}")
    if meta.get("ufw_was_active") is False:
        removal_plan.append("ufw disable (ufw был inactive до harden)")
    console.print(f"[info][ufw] План отката ({len(removal_plan)} шагов):[/info]")
    for step in removal_plan:
        console.print(f"  [add] {step}")
    if not apply:
        console.print("[info][ufw] Dry-run: ничего не изменено. Для отката — --undo --apply.[/info]")
        return 0

    with FileLock(lock_path or LOCK_PATH):
        for rule in reversed(applied):
            if rule.startswith("__deleted__"):
                # каскад удалял широкое 443-правило — undo восстанавливает его
                restored = rule.split("__deleted__ ", 1)[1]
                res = run_list(["ufw"] + restored.split(), timeout=15)
                _check(res, f"ufw {restored} (восстановление после cascade)")
                console.print(f"[success][ufw] восстановлено: ufw {restored}[/success]")
                continue
            if rule.startswith("__"):
                continue  # __enabled__ / __reload__ — статусные маркеры
            if rule == "DEFAULT_FORWARD_POLICY=ACCEPT":
                # forwarding-policy не откатываем к deny: её мог выставить relay init;
                # снятие этого конфига не возвращает исходного значения надёжно.
                console.print("[info][ufw] skip: DEFAULT_FORWARD_POLICY остаётся (не в before.rules)[/info]")
                continue
            toks = ["ufw", "delete"] + rule.split()
            res = run_list(toks, timeout=15)
            out = (res.stdout + res.stderr).lower()
            if res.ok or "could not" in out or "not found" in out or "does not exist" in out:
                console.print(f"[success][ufw] удалено: ufw delete {rule}[/success]")
            else:
                console.print(
                    f"[error][ufw] ufw delete {rule} не удался: "
                    f"{res.stderr.strip() or res.stdout.strip()}[/error]"
                )
                return 1
        if meta.get("ufw_was_active") is False:
            res = run_list(["ufw", "disable"], timeout=15)
            if not res.ok:
                console.print(
                    f"[error][ufw] ufw disable не удался: {res.stderr.strip()} — "
                    "ufw остался active; снимите правила руками (SERVER-BASELINE §5).[/error]"
                )
                return 1
            console.print("[success][ufw] ufw выключен (был inactive до harden).[/success]")
        state.protocols[UFW_META_KEY] = {"installed": False, "ts": _now_iso()}
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error][ufw] Правила сняты, но state не сохранён: {exc}[/error]")
            return 1
    console.print("[success][ufw] Откат завершён.[/success]")
    return 0


# ---------------------------------------------------------------------------
# ssh-port: двухфазный перенос (WP-2b)
# ---------------------------------------------------------------------------


def ssh_socket_active() -> bool:
    """Ubuntu 24.04 socket-activation: активен ли ssh.socket."""
    return run_list(["systemctl", "is-active", "--quiet", "ssh.socket"], timeout=10).ok


def render_sshd_port_conf(port: int, keep_22: bool = True) -> str:
    """Фаза A (keep_22=True): ОБА порта — вход по 22 гарантированно жив во
    время dual-listen (техлид-уточнение п.3: при режущем 49222 hoster-файрволе
    запись только Port 49222 отрезает доступ в Фазе 1). Фаза B: только N.
    """
    if keep_22:
        return f"Port {LEGACY_SSH_PORT}\nPort {port}\n"
    return f"Port {port}\n"


def render_socket_dropin(port: int, keep_22: bool = True) -> str:
    """Пустой ListenStream= сбрасывает дефолт, затем явные ListenStream (SPEC §1.7).
    Фаза A: 22 + N (dual-listen); Фаза B: только N."""
    ports = [LEGACY_SSH_PORT, port] if keep_22 else [port]
    lines = "\n".join(f"ListenStream={p}" for p in ports)
    return f"[Socket]\nListenStream=\n{lines}\n"


def _write_0600(
    path: Path, content: str, backup_dir: Path, mode: int = 0o600
) -> Optional[str]:
    """Атомарная запись (по умолчанию 0600) + бэкап прежнего содержимого.

    Unit drop-in-ы systemd обязаны быть 0644: 0600 даёт предупреждение
    «world-inaccessible» и может привести к отказу юнита.
    """
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path: Optional[Path] = None
    if path.is_file():
        backup_path = backup_dir / (path.name + ".vds-backup")
        shutil.copy2(path, backup_path)
        old = path.read_text(encoding="utf-8")
        if old == content:
            return backup_path.as_posix() if backup_path else None  # идемпотентно
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise
    return backup_path.as_posix() if backup_path else None


def _restore(path: Path, backup_path: Optional[str], existed_backup: bool) -> None:
    """Откат конфига: восстановить из бэкапа, либо удалить созданный файл."""
    if backup_path and existed_backup:
        shutil.copy2(backup_path, path)
    else:
        path.unlink(missing_ok=True)


def port_listening(port: int) -> bool:
    """Проверка `ss -tlnp`: порт слушается (не loopback)?"""
    if not command_exists("ss"):
        return False
    res = run_list(["ss", "-tlnp"], timeout=10)
    if not res.ok:
        return False
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "LISTEN":
            continue
        local = parts[3]
        if local.rsplit(":", 1)[-1] == str(port):
            if local.startswith("127.") or local.startswith("[::1]") or local.startswith("::1"):
                continue
            return True
    return False


def run_ssh_port(
    to: Optional[int],
    finalize: bool,
    apply: bool = False,
    state_path: Optional[str] = None,
    lock_path: Optional[str] = None,
) -> int:
    """Двухфазный перенос ssh-порта (SPEC §1.7).

    Фаза A (--to N --apply): limit N + sshd_config + restart + ss-чек + pending-маркер,
    СТОП: 22 не закрывается в этой операции (железное требование).
    Фаза B (--finalize --apply): ss-чек N -> удаление правил 22 -> pending=False.
    """
    if to is None and not finalize:
        console.print(
            "[error][ufw-ssh] Укажите --to N либо --finalize "
            "(одновременно — нельзя: Фаза A не закрывает 22).[/error]"
        )
        return 2
    if to is not None and finalize:
        console.print(
            "[error][ufw-ssh] Перенос и финализация — разные операции (двухфазность): "
            "сначала `ssh-port --to N --apply`, после проверки входа на N со второго "
            "терминала — `ssh-port --finalize --apply`.[/error]"
        )
        return 2
    if to is not None and not (1 <= to <= 65535):
        console.print("[error][ufw-ssh] Порт вне диапазона 1-65535.[/error]")
        return 2
    if apply and os.geteuid() != 0:
        console.print("[error][ufw-ssh] --apply требует root (sudo).[/error]")
        return 2
    if not command_exists("ufw"):
        console.print("[error][ufw-ssh] ufw не установлен.[/error]")
        return 1
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw-ssh] {exc}[/error]")
        return 1

    if finalize:
        return _ssh_finalize(state, apply, state_path, lock_path or LOCK_PATH)
    assert to is not None
    return _ssh_phase_a(state, to, apply, state_path, lock_path or LOCK_PATH)


def _ssh_finalize(state: GatewayState, apply: bool, state_path: Optional[str], lock_path: str) -> int:
    meta = state.protocols.get(SSH_PORT_PENDING_KEY) or {}
    if not meta.get("pending"):
        console.print(
            "[error][ufw-ssh] Финализация без выполненной Фазы A невозможна: "
            "нет pending-маркера в state (перенос не начинался либо уже "
            "финализирован).[/error]"
        )
        return 1
    port = int(meta.get("port") or 0)
    console.print(f"[info][ufw-ssh] Финализация: порт {port} становится единственным ssh-портом.[/info]")

    listening = port_listening(port)
    snapshot = _ufw_snapshot_combined()
    plan: list[PlanItem] = [
        PlanItem("config", f"sshd-конфиг → только Port {port} (dual-listen 22 снимается)", "add",
                 {"config": "sshd-final"}),
        PlanItem("check", "sshd -t + restart/daemon-reload + ss-чек", "add", {"check": "restart-final"}),
    ]
    if not listening:
        plan.insert(0, PlanItem("check", f"порт {port} НЕ слушается — финализация отклонена", "warn"))
    for action in ("limit", "allow"):
        for spec in (f"{LEGACY_SSH_PORT}/tcp", str(LEGACY_SSH_PORT)):
            if snapshot.has(action, spec):
                plan.append(PlanItem("rule", f"ufw delete {action} {spec}", "add",
                                     {"action": action, "spec": spec, "delete": True}))
    console.print(f"[info][ufw-ssh] План финализации (порядок: sshd-правка → restart → ufw delete):[/info]")
    for item in plan:
        console.print(f"  [{item.action}] {item.detail}")
    if not listening:
        console.print(
            f"[error][ufw-ssh] Порт {port} не слушается — отказ (22 сохраняется). "
            "Восстановите sshd-конфиг из бэкапов (SERVER-BASELINE §5) и повторите Фазу A.[/error]"
        )
        return 1
    if not apply:
        console.print("[info][ufw-ssh] Dry-run: ничего не изменено. Для финализации — --apply.[/info]")
        return 0

    with FileLock(lock_path):
        backup_dir = Path(state_path or STATE_PATH).parent / "ufw-ssh-backups"
        try:
            # порядок Фазы B (техлид п.3): sshd-правка → restart → ufw delete
            _write_0600(UFW_SSHD_CONF, render_sshd_port_conf(port, keep_22=False), backup_dir)
            RUN_SSHD_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
            res = run_list(["sshd", "-t"], timeout=10)
            _check(res, "sshd -t (финальный конфиг)")
            if ssh_socket_active():
                _write_0600(UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=False), backup_dir, mode=0o644)
                for args in (["systemctl", "daemon-reload"], ["systemctl", "restart", "ssh.socket"]):
                    r = run_list(args, timeout=20)
                    _check(r, " ".join(args))
            else:
                r = run_list(["systemctl", "restart", "ssh"], timeout=20)
                _check(r, "systemctl restart ssh")
            if not port_listening(port):
                raise UfwError(f"порт {port} не слушается после final-restart — откат к dual-listen")
            console.print(f"[success][ufw-ssh] sshd слушает только {port}; 22 в sshd снят.[/success]")
        except (UfwError, OSError) as exc:
            console.print(f"[error][ufw-ssh] Финализация прервана на шаге sshd: {exc}. "
                          "Правила 22 НЕ удалялись — вход по 22 сохранён.[/error]")
            # откат к dual-listen (22+N), чтобы вход по 22 оставался живым
            try:
                _write_0600(UFW_SSHD_CONF, render_sshd_port_conf(port, keep_22=True), backup_dir)
                if ssh_socket_active():
                    _write_0600(UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=True), backup_dir, mode=0o644)
                    run_list(["systemctl", "daemon-reload"], timeout=20)
                    run_list(["systemctl", "restart", "ssh.socket"], timeout=20)
                else:
                    run_list(["systemctl", "restart", "ssh"], timeout=20)
            except OSError as exc2:
                console.print(f"[error][ufw-ssh] Откат к dual-listen не удался: {exc2}. "
                              "Восстановите вручную из бэкапов (SERVER-BASELINE §5).[/error]")
            return 1
        for item in plan:
            if item.kind != "rule":
                continue
            spec = item.meta["spec"]
            action = item.meta["action"]
            res = run_list(["ufw", "delete", action, spec], timeout=15)
            out = (res.stdout + res.stderr).lower()
            if res.ok or "could not" in out or "not found" in out:
                console.print(f"[success][ufw-ssh] удалено: ufw delete {action} {spec}[/success]")
            else:
                console.print(
                    f"[error][ufw-ssh] ufw delete {action} {spec} не удался: "
                    f"{res.stderr.strip() or res.stdout.strip()} — прервано, 22 может "
                    "остаться открытым. Снимите правило руками.[/error]"
                )
                return 1
        meta.update({
            "pending": False,
            "legacy_22_still_open": False,
            "dual_listen": False,
            "ts": _now_iso(),
        })
        state.protocols[SSH_PORT_PENDING_KEY] = meta
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error][ufw-ssh] state не сохранён: {exc}[/error]")
            return 1
    console.print(
        f"[success][ufw-ssh] Готово: ssh только на {port}/tcp (limit), правила 22 удалены.[/success]"
    )
    return 0


def _ssh_phase_a(state: GatewayState, port: int, apply: bool, state_path: Optional[str], lock_path: str) -> int:
    if port == LEGACY_SSH_PORT:
        console.print("[error][ufw-ssh] Перенос на 22 не имеет смысла.[/error]")
        return 2
    pending_meta = state.protocols.get(SSH_PORT_PENDING_KEY) or {}
    if pending_meta.get("pending") and int(pending_meta.get("port") or 0) != port:
        console.print(
            f"[error][ufw-ssh] Уже есть незавершённый перенос на порт "
            f"{pending_meta.get('port')} — сначала finalize или откатите конфиги.[/error]"
        )
        return 1
    snapshot = parse_ufw_status(_ufw_status_text())
    plan: list[PlanItem] = [
        _rule_item("limit", f"{port}/tcp", snapshot, ssh=True),
        PlanItem(
            "config",
            f"/etc/ssh/sshd_config.d/99-vds-port.conf → Port 22 + Port {port} "
            "(dual-listen: 22 жив до finalize)",
            "add",
            {"config": "sshd-port"},
        ),
        PlanItem("check", "sshd -t (конфиг валиден)", "add", {"check": "sshd-t"}),
        PlanItem(
            "config",
            "ssh.socket drop-in (ListenStream 22 + N) + daemon-reload + restart, "
            "либо restart ssh.service (вне socket-activation)",
            "add",
            {"config": "socket-or-service"},
        ),
        PlanItem("check", f"ss -tlnp: порт {port} слушается", "add", {"check": "ss"}),
        PlanItem("config", "pending-маркер в state (22 остаётся открытым до finalize)", "add",
                 {"config": "pending-marker"}),
    ]
    console.print(f"[info][ufw-ssh] Фаза A: перенос ssh на {port}/tcp (22 НЕ закрывается).[/info]")
    for item in plan:
        console.print(f"  [{item.action}] {item.detail}")
    if not apply:
        console.print(
            "[info][ufw-ssh] Dry-run: ничего не изменено. Для Фазы A — --apply; "
            "после проверки входа на новый порт со ВТОРОГО терминала — "
            "`sudo vds system ufw ssh-port --finalize`.[/info]"
        )
        return 0

    with FileLock(lock_path):
        # Фиксируем режим ДО restart: после падения ssh.socket is-active уже
        # вернёт False, и откат выберет не тот юнит (пост-мортем asv1).
        was_socket = ssh_socket_active()
        backup_dir = Path(state_path or STATE_PATH).parent / "ufw-ssh-backups"
        sshd_backup: Optional[str] = None
        sshd_had_backup = False
        socket_backup: Optional[str] = None
        socket_had_backup = False
        try:
            # 1) ufw limit N ДО переноса (SPEC §1.7.1)
            item = plan[0]
            if item.action == "add":
                res = run_list(["ufw", "limit", f"{port}/tcp"], timeout=15)
                _check(res, f"ufw limit {port}/tcp")
            console.print(f"[success][ufw-ssh] ufw limit {port}/tcp подтверждён.[/success]")

            # 2) sshd_config.d/99-vds-port.conf (dual-listen 22+N, атомарно 0600,
            #    бэкап) + sshd -t. keep_22=True: вход по 22 гарантированно жив
            #    во время pending (техлид-уточнение п.3)
            sshd_backup = _write_0600(
                UFW_SSHD_CONF, render_sshd_port_conf(port, keep_22=True), backup_dir
            )
            sshd_had_backup = sshd_backup is not None
            RUN_SSHD_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)  # иначе «Missing privilege
            # separation directory: /run/sshd» на свежей системе
            res = run_list(["sshd", "-t"], timeout=10)
            if not res.ok:
                raise UfwError(
                    f"sshd -t вернул ошибку: {res.stderr.strip() or res.stdout.strip()}"
                )
            console.print("[success][ufw-ssh] sshd -t: конфиг валиден.[/success]")

            # 3) Ubuntu 24.04 socket-activation ветвление (SPEC §1.7.3);
            #    drop-in dual-listen: ListenStream= 22 и N
            if was_socket:
                socket_backup = _write_0600(
                    UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=True),
                    backup_dir, mode=0o644,
                )
                socket_had_backup = socket_backup is not None
                for args in (
                    ["systemctl", "daemon-reload"],
                    ["systemctl", "restart", "ssh.socket"],
                ):
                    r = run_list(args, timeout=20)
                    _check(r, " ".join(args))
                console.print("[success][ufw-ssh] ssh.socket переопределён и перезапущен.[/success]")
            else:
                r = run_list(["systemctl", "restart", "ssh"], timeout=20)
                _check(r, "systemctl restart ssh")
                console.print("[success][ufw-ssh] ssh.service перезапущен.[/success]")

            # 4) ss-чек: порт слушается, иначе откат конфигов (SPEC §1.7.4)
            if not port_listening(port):
                raise UfwError(f"порт {port} не слушается после restart — откат конфигов")

            # 5) pending-маркер (SPEC §1.7.5) — dual-listen 22+N активен,
            #    22 закрывается только finalize'ом
            state.protocols[SSH_PORT_PENDING_KEY] = {
                "pending": True,
                "port": port,
                "legacy_22_still_open": True,
                "dual_listen": True,
                "sshd_conf_backup": sshd_backup or "",
                "socket_dropin": UFW_SOCKET_DROPIN.as_posix() if was_socket else "",
                "ts": _now_iso(),
            }
            save_state(state, state_path)
        except (UfwError, OSError, StoreError) as exc:
            console.print(f"[error][ufw-ssh] Фаза A прервана: {exc}[/error]")
            if apply:
                _restore(UFW_SSHD_CONF, sshd_backup, sshd_had_backup)
                _restore(UFW_SOCKET_DROPIN, socket_backup, socket_had_backup)
                # HF-SSH (пост-мортем asv1): откат обязан сам поднять демон.
                # Иначе после падения ssh.socket узел остаётся без 22/49222
                # и текущая сессия — последняя.
                run_list(["systemctl", "daemon-reload"], timeout=20)
                if was_socket:
                    run_list(["systemctl", "restart", "ssh.socket"], timeout=20)
                else:
                    run_list(["systemctl", "restart", "ssh"], timeout=20)
                if not port_listening(LEGACY_SSH_PORT):
                    run_list(["systemctl", "start", "ssh"], timeout=20)
                if port_listening(LEGACY_SSH_PORT):
                    console.print(
                        "[success][ufw-ssh] Конфиги восстановлены; ssh на 22 "
                        "поднят автоматически.[/success]"
                    )
                else:
                    console.print(
                        "[error][ufw-ssh] Конфиги восстановлены, но 22 не слушается — "
                        "нужен консольный доступ: systemctl restart ssh.service "
                        "(или ssh.socket).[/error]"
                    )
            return 1

    console.print(
        f"[success][ufw-ssh] Фаза A применена. Порт 22 ОСТАЁТСЯ открытым. Проверьте "
        f"вход на порт {port} со ВТОРОГО терминала, затем выполните "
        f"`sudo vds system ufw ssh-port --finalize`.[/success]"
    )
    return 0


# ---------------------------------------------------------------------------
# status: pending-предупреждение + сводка meta (SPEC §4)
# ---------------------------------------------------------------------------


def run_status(state_path: Optional[str] = None) -> int:
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1
    _print_pending_warning(state)
    meta = state.protocols.get(UFW_META_KEY) or {}
    if meta.get("installed"):
        console.print(
            f"[info][ufw] meta: профиль={meta.get('profile')}, ssh_port={meta.get('ssh_port')}, "
            f"applied_rules={len(meta.get('applied_rules') or [])}, ts={meta.get('ts')}[/info]"
        )
    else:
        console.print("[info][ufw] harden не применялся (meta отсутствует).[/info]")
    if command_exists("ufw"):
        snap = parse_ufw_status(_ufw_status_text())
        console.print(
            f"[info][ufw] live: {snap.status}, default in={snap.default_incoming or '?'} "
            f"out={snap.default_outgoing or '?'}, правил: {len(snap.rules)}[/info]"
        )
        for rule in snap.rules:
            console.print(f"  [info]-[/info] {rule.canonical}")
    else:
        console.print("[warning][ufw] ufw не установлен.[/warning]")
    return 0


# ---------------------------------------------------------------------------
# lock-443: изоляция 443 по вердиктам probe-watch
# (SPEC-20261116-probe-response §4.1, §9.B/C/D, §10 OQ-2, §11)
# ---------------------------------------------------------------------------

# Состояние лока — топ-уровень state.json["ufw_lockdown"] (§9.C), отдельно от
# applied_rules harden-меты: undo каждого — свой журнал.
LOCKDOWN_TTL_DEFAULT_H = 48
LOCKDOWN_TTL_MIN_H = 1
LOCKDOWN_TTL_MAX_H = 168


def parse_ttl_hours(ttl: str) -> int:
    """'48h' -> 48; валидация 1h..168h (SPEC §10 OQ-2)."""
    match = re.fullmatch(r"\s*(\d+)\s*h\s*", ttl or "")
    if not match:
        raise UfwError(f"TTL: ожидался формат Nh (например 48h), получено {ttl!r}")
    hours = int(match.group(1))
    if not (LOCKDOWN_TTL_MIN_H <= hours <= LOCKDOWN_TTL_MAX_H):
        raise UfwError(
            f"TTL {hours}h вне диапазона {LOCKDOWN_TTL_MIN_H}h..{LOCKDOWN_TTL_MAX_H}h "
            "(SPEC §10 OQ-2)"
        )
    return hours


def parse_allow_from(value: Optional[str]) -> list[str]:
    """'IP,IP' -> [IP]; только IPv4 (§9.D: v6-443 на время лока закрыт)."""
    if not value or not value.strip():
        return []
    ips: list[str] = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            addr = ipaddress.ip_address(token)
        except ValueError as exc:
            raise UfwError(f"--allow-from: некорректный IP {token!r} ({exc})") from exc
        if addr.version != 4:
            raise UfwError(
                f"--allow-from: {token!r} не IPv4 — v6-443 остаётся закрытым на время "
                "лока (§9.D), v6-allow-list не поддерживается v1"
            )
        if token not in ips:
            ips.append(token)
    return ips


def get_lockdown(state: GatewayState) -> dict:
    """Нормализованное состояние лока (стабильный контракт для probe-watch --json)."""
    raw = dict(state.ufw_lockdown or {})

    def _str_list(key: str) -> list[str]:
        val = raw.get(key)
        return [str(v) for v in val] if isinstance(val, list) else []

    try:
        ttl_hours = int(raw.get("ttl_hours") or 0)
    except (TypeError, ValueError):
        ttl_hours = 0
    return {
        "active": bool(raw.get("active")),
        "since": str(raw.get("since", "")),
        "ttl_until": str(raw.get("ttl_until", "")),
        "ttl_hours": ttl_hours,
        "allow_from": _str_list("allow_from"),
        "reason": str(raw.get("reason", "")),
        "removed_wide": _str_list("removed_wide"),
        "added_from": _str_list("added_from"),
    }


def lockdown_ttl_expired(ld: dict, now: Optional[datetime] = None) -> bool:
    """now >= ttl_until (§11: TTL-чек в тике probe-watch). Непарсящийся TTL — False."""
    if not ld.get("active") or not ld.get("ttl_until"):
        return False
    try:
        until = datetime.fromisoformat(str(ld["ttl_until"]))
    except ValueError:
        return False
    return (now or datetime.now(timezone.utc)) >= until


def has_non_443_channel(state: GatewayState) -> bool:
    """Жив прямой канал кроме 443? (AWG 51825 / CDN 2053 — fail-fast §4.2)."""
    awg = state.protocols.get("amneziawg") or {}
    cdn = state.protocols.get("xray-cdn") or {}
    return bool(awg.get("installed")) or bool(cdn.get("installed"))


def detect_hop(state: GatewayState, snapshot: UfwSnapshot) -> bool:
    """Hy2 port hopping на сервере? (state.protocols + широкое udp-правило-диапазон, §9.B)."""
    if (state.protocols.get("hysteria2") or {}).get("hop_ports"):
        return True
    return any(
        r.action == "allow" and r.proto == "udp" and ":" in r.port and r.src == "any"
        for r in snapshot.rules
    )


def _ttl_expires_at(now: datetime, hours: int) -> str:
    return (now + timedelta(hours=hours)).isoformat(timespec="seconds")


def _append_event(raw_lockdown: dict, event: str, detail: str) -> list[dict]:
    """Журнал событий лока (lock/extend/unlock/harden-force); окно — последние 50."""
    events = [dict(e) for e in (raw_lockdown.get("events") or []) if isinstance(e, dict)]
    events.append({"event": event, "detail": detail, "ts": _now_iso()})
    return events[-50:]


def _delete_wide_item(spec: str, snapshot: UfwSnapshot) -> PlanItem:
    """Шаг удаления широкого 443-правила (в undo-журнал); отсутствующее — skip."""
    present = snapshot.has("allow", spec)
    return PlanItem(
        "rule",
        f"ufw delete allow {spec}"
        + ("" if present else " [широкого правила нет — идемпотентно]"),
        "add" if present else "skip",
        {"action": "allow", "spec": spec, "delete": True},
    )


def build_lockdown_plan(
    state: GatewayState,
    snapshot: UfwSnapshot,
    allow_ips: list[str],
    with_udp: bool,
) -> list[PlanItem]:
    """План lock-443: from-правила ПЕРВЫМИ (fail-safe: сначала доступ, потом изоляция).

    По умолчанию закрывается ТОЛЬКО 443/tcp (§9.B): 443/udp и hop-диапазон
    не трогаются (при обнаруженном hop — warning «канал уклонения остаётся»);
    --with-udp закрывает и их, записав оба в undo-журнал. Повторный apply
    ЗАМЕНЯЕТ allow-from: устаревшие from-правила предыдущего лока удаляются.
    """
    plan: list[PlanItem] = []
    for ip in allow_ips:
        plan.append(_rule_item("allow", f"from {ip} to any port 443 proto tcp", snapshot))
    plan.append(_delete_wide_item("443/tcp", snapshot))
    if with_udp:
        plan.append(_delete_wide_item("443/udp", snapshot))
        seen_ranges: set[str] = set()
        for rule in snapshot.rules:
            if (
                rule.action == "allow" and rule.proto == "udp"
                and ":" in rule.port and rule.src == "any"
            ):
                spec = f"{rule.port}/udp"
                if spec not in seen_ranges:
                    seen_ranges.add(spec)
                    plan.append(_delete_wide_item(spec, snapshot))
    elif detect_hop(state, snapshot):
        plan.append(PlanItem(
            "check",
            "443/udp и hop-диапазон НЕ трогаются: Hy2-hop остаётся открытым "
            "(канал уклонения, §9.B); полное молчание — явным --with-udp",
            "warn",
        ))
    else:
        plan.append(PlanItem(
            "check",
            "443/udp не трогается (hop не обнаружен; полное молчание — явным --with-udp)",
            "warn",
        ))
    # Замена allow-from (§4.1): from-правила прошлого лока вне нового списка — в удаление.
    keep = {f"allow from {ip} to any port 443 proto tcp" for ip in allow_ips}
    prev_added = [
        str(r) for r in ((state.ufw_lockdown or {}).get("added_from") or [])
        if isinstance(r, str)
    ]
    for old in prev_added:
        if old in keep:
            continue
        toks = old.split()
        action_word = toks[0] if toks and toks[0] in ("allow", "limit", "deny", "reject") else "allow"
        spec_rest = " ".join(toks[1:]) if action_word != "allow" or old.startswith("allow ") else old
        present = snapshot.has(action_word, spec_rest)
        plan.append(PlanItem(
            "rule",
            f"ufw delete {old} [замена allow-from]"
            + ("" if present else " [правила уже нет — идемпотентно]"),
            "add" if present else "skip",
            {"action": action_word, "spec": spec_rest, "delete": True},
        ))
    return plan


def _execute_lock_plan(
    state: GatewayState,
    plan: list[PlanItem],
    previous: dict,
    allow_ips: list[str],
    ttl_hours: int,
    reason: str,
) -> None:
    """Исполнить план лока (вызывающий держит FileLock + root); мутации + журнал."""
    removed_wide = [str(r) for r in (previous.get("removed_wide") or [])]
    for item in plan:
        if item.kind != "rule" or item.action == "skip":
            continue
        spec = str(item.meta["spec"])
        if item.meta.get("delete"):
            res = run_list(["ufw", "delete", "allow", spec], timeout=15)
            if not res.ok:
                out = (res.stdout + res.stderr).lower()
                if "could not" not in out and "not found" not in out:
                    raise UfwError(
                        f"ufw delete allow {spec}: {res.stderr.strip() or res.stdout.strip()}"
                    )
                console.print(f"[info][ufw] правило уже удалено: allow {spec}[/info]")
            else:
                kind = "замена allow-from" if spec.startswith("from ") else "undo-журнал лока"
                console.print(f"[success][ufw] удалено ({kind}): allow {spec}[/success]")
            if not spec.startswith("from ") and spec not in removed_wide:
                removed_wide.append(spec)
            continue
        res = run_list(item.cli_args, timeout=15)
        if not res.ok:
            out = (res.stdout + res.stderr).lower()
            if "skipping adding" not in out and "rule added" not in out:
                raise UfwError(
                    f"{item.detail}: {res.stderr.strip() or res.stdout.strip()}"
                )
        console.print(f"[success][ufw] применено: {item.detail}[/success]")
    # added_from — канонический список ТЕКУЩЕГО allow-list (замена, §4.1);
    # удаление устаревших from-правил выше уже в плане.
    added_from = [f"allow from {ip} to any port 443 proto tcp" for ip in allow_ips]
    state.ufw_lockdown = {
        "active": True,
        # повторный apply = продление (since сохраняется), не «новый» лок
        "since": str(previous.get("since") or "") or _now_iso(),
        "ttl_until": _ttl_expires_at(datetime.now(timezone.utc), ttl_hours),
        "ttl_hours": ttl_hours,
        "allow_from": list(allow_ips),
        "reason": reason,
        "removed_wide": removed_wide,
        "added_from": added_from,
        "events": _append_event(previous, "lock", reason or "manual"),
    }


def _execute_unlock(state: GatewayState, reason: str) -> None:
    """Снять лок: восстановить ровно снимок широких правил, убрать from-правила.

    §9.D: стандартный `ufw allow 443/tcp|udp` идемпотентно воссоздаёт v4+v6
    пары (IPV6=yes); сверка со снимком после восстановления. 443-правила,
    изменённые владельцем во время лока, НЕ перезаписываются — merge-подсказка.
    """
    ld = get_lockdown(state)
    live = _ufw_snapshot_combined()
    known = set(ld["added_from"]) | {f"allow {spec}" for spec in ld["removed_wide"]}
    manual = sorted({
        r.canonical for r in live.rules
        if r.action == "allow" and r.port == "443" and r.canonical not in known
    })
    if manual:
        console.print(
            "[warning][ufw] 443-правила вне журнала лока (владелец менял во время лока?): "
            f"{', '.join(manual)} — НЕ перезаписываются, выполните merge вручную.[/warning]"
        )
    for spec in ld["removed_wide"]:
        res = run_list(["ufw", "allow", spec], timeout=15)
        _check(res, f"ufw allow {spec} (восстановление после lock-443)")
        console.print(f"[success][ufw] восстановлено: ufw allow {spec}[/success]")
    for canonical in ld["added_from"]:
        res = run_list(["ufw", "delete"] + canonical.split(), timeout=15)
        out = (res.stdout + res.stderr).lower()
        if res.ok or "could not" in out or "not found" in out or "does not exist" in out:
            console.print(f"[success][ufw] снято: ufw delete {canonical}[/success]")
        else:
            raise UfwError(
                f"ufw delete {canonical}: {res.stderr.strip() or res.stdout.strip()}"
            )
    restored = _ufw_snapshot_combined()
    missing = [s for s in ld["removed_wide"] if not restored.has("allow", s)]
    if missing:
        raise UfwError(
            f"после unlock не найдены восстановленные широкие правила: {missing} — "
            "проверьте `ufw status` и добейте вручную"
        )
    leftover = [c for c in ld["added_from"] if c in {r.canonical for r in restored.rules}]
    if leftover:
        console.print(
            f"[warning][ufw] from-правила ещё живы (владелец переиспользовал?): "
            f"{leftover} — оставлены.[/warning]"
        )
    console.print(
        "[info][ufw] Сверка со снимком пройдена: широкие 443-правила на месте "
        "(v4+v6 пары воссоздаются стандартным ufw allow, §9.D).[/info]"
    )
    raw = dict(state.ufw_lockdown)
    raw["active"] = False
    raw["events"] = _append_event(raw, "unlock", reason)
    state.ufw_lockdown = raw


def _print_lockdown_status(state: GatewayState) -> int:
    ld = get_lockdown(state)
    if not ld["active"]:
        console.print("[info][ufw] lock-443: не активен.[/info]")
        return 0
    remaining = ""
    try:
        until = datetime.fromisoformat(ld["ttl_until"])
        seconds = (until - datetime.now(timezone.utc)).total_seconds()
        if seconds <= 0:
            remaining = ", TTL ИСТЁК (снимет ближайший тик probe-watch)"
        else:
            remaining = f", осталось ~{int(seconds // 3600)}ч{int((seconds % 3600) // 60):02d}м"
    except ValueError:
        remaining = ", ttl_until не читается"
    console.print(
        f"[info][ufw] lock-443: АКТИВЕН (since {ld['since']}, до {ld['ttl_until']}{remaining}; "
        f"allow_from: {', '.join(ld['allow_from']) or '— (443/tcp закрыт всем)'}; "
        f"reason: {ld['reason'] or '—'})[/info]"
    )
    console.print(
        f"[info][ufw] undo-журнал: removed_wide={ld['removed_wide']}, "
        f"added_from={ld['added_from']}[/info]"
    )
    return 0


def run_lock443(
    allow_from: Optional[str] = None,
    ttl: str = "48h",
    reason: str = "",
    with_udp: bool = False,
    status: bool = False,
    unlock: bool = False,
    apply: bool = False,
    state_path: Optional[str] = None,
    lock_path: Optional[str] = None,
) -> int:
    """CLI-движок `system ufw lock-443` (SPEC-20261116-probe-response §4.1).

    Dry-run по умолчанию; повторный --apply идемпотентен: продлевает TTL,
    список allow-from заменяется. Снятие: --unlock --apply (ровно снимок) или
    TTL-автоснятие тиком probe-watch (§11).
    """
    if not command_exists("ufw"):
        console.print("[error][ufw] ufw не установлен: apt install -y ufw[/error]")
        return 1
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1
    if status:
        return _print_lockdown_status(state)
    if unlock:
        return run_unlock443(apply=apply, state_path=state_path, lock_path=lock_path)
    try:
        ttl_hours = parse_ttl_hours(ttl)
        allow_ips = parse_allow_from(allow_from)
    except UfwError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 2
    if not allow_ips and not has_non_443_channel(state):
        console.print(
            "[error][ufw] Пустой --allow-from при профиле без 51825/2053: лок закрыл бы "
            "всё входящее (fail-fast SPEC §4.2). Укажите --allow-from IP[,IP…] или держите "
            "канал AWG/CDN живым.[/error]"
        )
        return 1
    ld = get_lockdown(state)
    snapshot = _ufw_snapshot_combined()
    plan = build_lockdown_plan(state, snapshot, allow_ips, with_udp)
    mode = "ПРОДЛЕНИЕ: TTL + замена allow-from" if ld["active"] else "лок"
    console.print(f"[info][ufw] План lock-443 ({mode}; TTL {ttl_hours}h):[/info]")
    for item in plan:
        tag = {"add": "add", "skip": "skip", "warn": "warning"}[item.action]
        console.print(f"  [{tag}] {item.detail}")
    if not allow_ips:
        console.print(
            "  [warning] allow-from пуст: 443/tcp закрывается ВСЕМ "
            "(AWG 51825/udp и ssh не трогаются)[/warning]"
        )
    if not apply:
        console.print("[info][ufw] Dry-run: ничего не изменено. Для применения — --apply.[/info]")
        return 0
    if os.geteuid() != 0:
        console.print("[error][ufw] --apply требует root (sudo).[/error]")
        return 2
    with FileLock(lock_path or LOCK_PATH):
        snapshot = _ufw_snapshot_combined()  # свежий снимок под блокировкой
        plan = build_lockdown_plan(state, snapshot, allow_ips, with_udp)
        try:
            _execute_lock_plan(
                state, plan, dict(state.ufw_lockdown or {}), allow_ips, ttl_hours, reason
            )
            save_state(state, state_path)
        except (UfwError, StoreError, OSError) as exc:
            console.print(f"[error][ufw] {exc}[/error]")
            return 1
    console.print(
        f"[success][ufw] lock-443 активен до {state.ufw_lockdown.get('ttl_until')} "
        "(снятие: `lock-443 --unlock --apply` или TTL-тик probe-watch).[/success]"
    )
    return 0


def run_unlock443(
    apply: bool = False,
    state_path: Optional[str] = None,
    lock_path: Optional[str] = None,
    reason: str = "manual",
) -> int:
    """Досрочное снятие лока: восстановление ровно снимка из журнала (§4.1/§9.D)."""
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] {exc}[/error]")
        return 1
    ld = get_lockdown(state)
    if not ld["active"]:
        console.print("[info][ufw] lock-443 не активен (идемпотентно).[/info]")
        return 0
    console.print("[info][ufw] План unlock (ровно снимок до лока; v4+v6 — §9.D):[/info]")
    for spec in ld["removed_wide"]:
        console.print(f"  [add] ufw allow {spec}")
    for canonical in ld["added_from"]:
        console.print(f"  [add] ufw delete {canonical}")
    if not apply:
        console.print("[info][ufw] Dry-run: ничего не изменено. Для снятия — --unlock --apply.[/info]")
        return 0
    if os.geteuid() != 0:
        console.print("[error][ufw] --apply требует root (sudo).[/error]")
        return 2
    with FileLock(lock_path or LOCK_PATH):
        try:
            _execute_unlock(state, reason)
            save_state(state, state_path)
        except (UfwError, StoreError, OSError) as exc:
            console.print(f"[error][ufw] {exc}[/error]")
            return 1
    console.print("[success][ufw] lock-443 снят: широкие 443-правила восстановлены из журнала.[/success]")
    return 0


# --- внутренние вызовы из часового тика probe-watch (§4.2, §11) ---


def apply_auto_lockdown(
    state_path: Optional[str] = None,
    allow_ips: Optional[list[str]] = None,
    ttl_hours: int = LOCKDOWN_TTL_DEFAULT_H,
    reason: str = "auto:RU-SUSPECT",
    with_udp: bool = False,
    lock_path: Optional[str] = None,
) -> bool:
    """Лок 443 из тика probe-watch при threat high (SPEC §4.2). False — отказ."""
    if os.geteuid() != 0:
        console.print("[error][ufw] auto-lockdown требует root (тик таймера).[/error]")
        return False
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] auto-lockdown: {exc}[/error]")
        return False
    ips = list(allow_ips or [])
    if not ips and not has_non_443_channel(state):
        console.print(
            "[error][ufw] auto-lockdown отказан: allow-list пуст и нет 51825/2053 — "
            "лок закрыл бы всё входящее (fail-fast SPEC §4.2).[/error]"
        )
        return False
    with FileLock(lock_path or LOCK_PATH):
        snapshot = _ufw_snapshot_combined()
        plan = build_lockdown_plan(state, snapshot, ips, with_udp)
        try:
            _execute_lock_plan(
                state, plan, dict(state.ufw_lockdown or {}), ips, ttl_hours, reason
            )
            save_state(state, state_path)
        except (UfwError, StoreError, OSError) as exc:
            console.print(f"[error][ufw] auto-lockdown: {exc}[/error]")
            return False
    console.print(
        f"[change][ufw] AUTO-LOCK 443 ({reason}) до {state.ufw_lockdown.get('ttl_until')}.[/change]"
    )
    return True


def extend_lockdown_ttl(
    state_path: Optional[str] = None,
    now: Optional[datetime] = None,
    lock_path: Optional[str] = None,
) -> bool:
    """Продление активного лока (повторный high / ru_syn_new): TTL re-arm, без дубля правил."""
    if os.geteuid() != 0:
        console.print("[error][ufw] продление лока требует root (тик таймера).[/error]")
        return False
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] продление лока: {exc}[/error]")
        return False
    ld = get_lockdown(state)
    if not ld["active"]:
        return False
    hours = ld["ttl_hours"] or LOCKDOWN_TTL_DEFAULT_H
    with FileLock(lock_path or LOCK_PATH):
        state.ufw_lockdown["ttl_until"] = _ttl_expires_at(
            now or datetime.now(timezone.utc), hours
        )
        state.ufw_lockdown["events"] = _append_event(
            dict(state.ufw_lockdown), "extend", "продление: high/ru_syn_new при активном локе"
        )
        try:
            save_state(state, state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error][ufw] продление лока: {exc}[/error]")
            return False
    console.print(f"[change][ufw] TTL лока продлён до {state.ufw_lockdown['ttl_until']}.[/change]")
    return True


def auto_unlock_expired(
    state_path: Optional[str] = None,
    now: Optional[datetime] = None,
    reason: str = "ttl-expired",
    lock_path: Optional[str] = None,
) -> bool:
    """TTL-чек тика probe-watch (§11): now >= ttl_until → авто-снятие (reason=ttl-expired)."""
    if os.geteuid() != 0:
        console.print("[error][ufw] auto-unlock требует root (тик таймера).[/error]")
        return False
    try:
        state = load_state(state_path)
    except StoreError as exc:
        console.print(f"[error][ufw] auto-unlock: {exc}[/error]")
        return False
    ld = get_lockdown(state)
    if not (ld["active"] and lockdown_ttl_expired(ld, now)):
        return False
    with FileLock(lock_path or LOCK_PATH):
        try:
            _execute_unlock(state, reason)
            save_state(state, state_path)
        except (UfwError, StoreError, OSError) as exc:
            console.print(f"[error][ufw] auto-unlock: {exc}[/error]")
            return False
    console.print(f"[change][ufw] AUTO-UNLOCK 443 ({reason}): TTL истёк, снимок восстановлен.[/change]")
    return True
