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

import json
import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
        # одно правило на весь диапазон, напр. "20000:20500/udp" (SPEC §9)
        specs.append(hop if "/" in hop else f"{hop}/udp")
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
        for spec in specs:
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


def _write_0600(path: Path, content: str, backup_dir: Path) -> Optional[str]:
    """Атомарная запись 0600 + бэкап прежнего содержимого; возвращает путь бэкапа или None."""
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
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
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
                _write_0600(UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=False), backup_dir)
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
                    _write_0600(UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=True), backup_dir)
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
            if ssh_socket_active():
                socket_backup = _write_0600(
                    UFW_SOCKET_DROPIN, render_socket_dropin(port, keep_22=True), backup_dir
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
                "socket_dropin": UFW_SOCKET_DROPIN.as_posix() if ssh_socket_active() else "",
                "ts": _now_iso(),
            }
            save_state(state, state_path)
        except (UfwError, OSError, StoreError) as exc:
            console.print(f"[error][ufw-ssh] Фаза A прервана: {exc}[/error]")
            if apply:
                _restore(UFW_SSHD_CONF, sshd_backup, sshd_had_backup)
                _restore(UFW_SOCKET_DROPIN, socket_backup, socket_had_backup)
                console.print(
                    "[info][ufw-ssh] Конфиги восстановлены из бэкапов; выполните "
                    f"`systemctl restart ssh{'.socket' if ssh_socket_active() else ''}` вручную.[/info]"
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
