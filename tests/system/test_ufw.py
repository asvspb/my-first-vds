"""Unit-тесты src/system/ufw.py (SPEC-20261116 WP-2/2b/3).

Без root/сети/реального ufw: fake-run (диспетчер команд) + tmp-пути +
monkeypatch os.geteuid. Секретные фикстуры — только RESERVED-константы
(203.0.113.0/24, RFC 5737) и FIXTURE_-префиксы.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import src.system.ufw as ufw
from src.gateway.store import GatewayState, load_state, save_state

RELAY_IP = "203.0.113.10"  # RFC 5737 TEST-NET — разрешённая RESERVED-фикстура


def _ok(stdout: str = "") -> "object":
    from src.core.shell import ShellResult
    return ShellResult(stdout=stdout, stderr="", returncode=0)


class FakeUfw:
    """Диспетчер run_list: состояния ufw/sshd/ss/systemctl + журнал вызовов."""

    def __init__(
        self,
        rules: list[str] | None = None,
        active: bool = False,
        defaults: tuple[str, str] = ("", ""),
        ip_forward: str = "1",
        ss_lines: list[str] | None = None,
        sshd_t_fails: bool = False,
        ssh_socket: bool = False,
    ) -> None:
        self.rules = list(rules or [])  # canonical: "limit 22/tcp", "allow 443/udp", ...
        self.active = active
        self.default_in, self.default_out = defaults
        self.ip_forward = ip_forward
        self.ss_lines = ss_lines or []
        self.sshd_t_fails = sshd_t_fails
        self.ssh_socket = ssh_socket
        self.calls: list[list[str]] = []

    # --- рендеры вывода ---

    def _status_text(self) -> str:
        if not self.active:
            return "Status: inactive\n"
        lines = [
            "Status: active",
            "Logging: on (low)",
            f"Default: {self.default_in or 'deny'} (incoming), {self.default_out or 'allow'} (outgoing), disabled (routed)",
            "",
            "To                         Action      From",
            "--                         ------      ----",
        ]
        for r in self.rules:
            action, _, rest = r.partition(" ")
            word = {"allow": "ALLOW", "limit": "LIMIT", "deny": "DENY", "reject": "REJECT"}.get(action, "ALLOW")
            if rest.startswith("from "):
                toks = rest.split()
                src = toks[1]
                port = toks[toks.index("port") + 1] if "port" in toks else ""
                to_field = f"{port}/{toks[toks.index('proto') + 1]}" if "proto" in toks else (port or "Anywhere")
                lines.append(f"{to_field:<26} {word} IN    {src}")
            else:
                lines.append(f"{rest:<26} {word} IN    Anywhere")
        return "\n".join(lines) + "\n"

    def _added_text(self) -> str:
        return "Added user rules (see 'ufw status' for running firewall):\n" + "\n".join(
            f"ufw {r}" for r in self.rules
        ) + "\n"

    def _canonical(self, args: list[str]) -> str:
        # args после "ufw": [action, ...rest]
        action, rest = args[0], args[1:]
        if rest and rest[0] == "from":
            # allow from IP to any port P proto X / from IP
            return f"{action} {' '.join(rest)}"
        return f"{action} {' '.join(rest)}"

    # --- диспетчер ---

    def run(self, args: list[str], timeout: int = 10):
        from src.core.shell import ShellResult

        self.calls.append(list(args))
        cmd = args[0]
        if cmd == "ufw":
            if args[1:] == ["status", "verbose"]:
                return ShellResult(stdout=self._status_text(), stderr="", returncode=0)
            if args[1:] == ["show", "added"]:
                return ShellResult(stdout=self._added_text(), stderr="", returncode=0)
            if args[1:] == ["--force", "enable"]:
                if not self.active:
                    self.active = True
                return ShellResult(stdout="Firewall is active and enabled on system startup", stderr="", returncode=0)
            if args[1:] == ["reload"]:
                return ShellResult(stdout="", stderr="", returncode=0)
            if args[1] == "default":
                if args[2] == "deny" and args[3] == "incoming":
                    self.default_in = "deny"
                elif args[2] == "allow" and args[3] == "outgoing":
                    self.default_out = "allow"
                return ShellResult(stdout="Default policy changed", stderr="", returncode=0)
            if args[1] == "delete":
                canon = self._canonical(args[2:])
                if canon in self.rules:
                    self.rules.remove(canon)
                    return ShellResult(stdout="", stderr="", returncode=0)
                return ShellResult(stdout="", stderr="Could not delete non-existent rule", returncode=1)
            if args[1] == "disable":
                self.active = False
                return ShellResult(stdout="Firewall stopped and disabled on system startup", stderr="", returncode=0)
            canon = self._canonical(args[1:])
            if canon in self.rules:
                return ShellResult(stdout="", stderr="Skipping adding existing rule", returncode=1)
            self.rules.append(canon)
            return ShellResult(stdout="Rule added", stderr="", returncode=0)
        if cmd == "ss":
            proto = "tcp" if any(f.startswith("-t") for f in args[1:]) else "udp"
            lines = [l for l in self.ss_lines if l.split()[0] in (("LISTEN",) if proto == "tcp" else ("UNCONN",))]
            header = "State  Recv-Q  Send-Q  Local  Peer  Process"
            return ShellResult(stdout="\n".join([header] + lines), stderr="", returncode=0)
        if cmd == "sshd":
            if self.sshd_t_fails:
                return ShellResult(stdout="", stderr="/etc/ssh/sshd_config.d/99-vds-port.conf: bad option", returncode=1)
            return ShellResult(stdout="", stderr="", returncode=0)
        if cmd == "systemctl":
            if args[1] == "is-active":
                return ShellResult(stdout="active", stderr="", returncode=0 if self.ssh_socket else 3)
            return ShellResult(stdout="", stderr="", returncode=0)
        if cmd == "sysctl":
            return ShellResult(stdout=self.ip_forward, stderr="", returncode=0)
        return ShellResult(stdout="", stderr=f"fake: unknown {args[0]}", returncode=127)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Все мутируемые пути — в tmp."""
    monkeypatch.setattr(ufw, "UFW_SSHD_CONF", tmp_path / "etc" / "ssh" / "sshd_config.d" / "99-vds-port.conf")
    monkeypatch.setattr(ufw, "UFW_SOCKET_DROPIN", tmp_path / "etc" / "systemd" / "system" / "ssh.socket.d" / "99-port.conf")
    monkeypatch.setattr(ufw, "UFW_DEFAULTS", tmp_path / "etc" / "default" / "ufw")
    monkeypatch.setattr(ufw, "RUN_SSHD_DIR", tmp_path / "run" / "sshd")
    monkeypatch.setattr(ufw, "LOCK_PATH", str(tmp_path / "vds.lock"))
    return tmp_path


@pytest.fixture()
def root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ufw.os, "geteuid", lambda: 0)


def _gateway_state() -> GatewayState:
    st = GatewayState()
    st.protocols = {
        "xray": {"installed": True, "port": 443},
        "hysteria2": {"installed": True, "port": 443, "hop_ports": "20000:20500/udp"},
        "hysteria2-obfs": {"installed": True, "port": 51826},
        "amneziawg": {"installed": True, "port": 51825},
        "xhttp": {"installed": True, "port": 8443},
        "xray-cdn": {"installed": True, "port": 2053},
        "acme": {"installed": True, "port": 80},
    }
    return st


GATEWAY_SPECS = {
    "443/tcp", "443/udp", "51826/udp", "51825/udp",
    "8443/tcp", "2053/tcp", "80/tcp", "20000:20500/udp",
}


def _wire(fake: FakeUfw, monkeypatch: pytest.MonkeyPatch) -> FakeUfw:
    monkeypatch.setattr(ufw, "run_list", fake.run)
    monkeypatch.setattr(ufw, "command_exists", lambda name: name in ("ufw", "ss", "sshd"))
    return fake


def _read_only(call: list[str]) -> bool:
    """Чтение статуса/слушателей — не мутация."""
    if call[0] == "ufw" and call[1] in ("status", "show"):
        return True
    if call[0] == "ss" and any(f.startswith(("-t", "-u")) for f in call[1:]):
        return True
    if call[0] == "sysctl":
        return True
    return False


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------


class TestParseStatus:
    def test_inactive_no_rules_in_status(self) -> None:
        # техлид п.1: при inactive `ufw status` правил НЕ показывает
        snap = ufw.parse_ufw_status("Status: inactive\n")
        assert snap.status == "inactive"
        assert snap.rules == []

    def test_active_verbose_rules_and_defaults(self) -> None:
        text = (
            "Status: active\n"
            "Logging: on (low)\n"
            "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
            "\n"
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "22/tcp                     LIMIT IN    Anywhere\n"
            "443/udp                    ALLOW IN    Anywhere\n"
            "20000:20500/udp            ALLOW IN    Anywhere\n"
            "443/tcp                    ALLOW IN    203.0.113.10\n"
        )
        snap = ufw.parse_ufw_status(text)
        assert snap.status == "active"
        assert (snap.default_incoming, snap.default_outgoing) == ("deny", "allow")
        assert snap.has("limit", "22/tcp")
        assert snap.has("allow", "443/udp")
        assert snap.has("allow", "20000:20500/udp")
        assert snap.has("allow", "443/tcp", "203.0.113.10")
        assert snap.unparsed == []

    def test_unparsed_line_collected(self) -> None:
        snap = ufw.parse_ufw_status(
            "Status: active\nTo Action From\n-- ------ ----\n443/tcp ALLOW UNK weird line\n"
        )
        assert snap.unparsed

    def test_parse_ufw_added(self) -> None:
        text = (
            "Added user rules (see 'ufw status' for running firewall):\n"
            "ufw limit 22/tcp\n"
            "ufw allow 20000:20500/udp\n"
            "ufw allow from 203.0.113.10 to any port 443 proto udp\n"
            "ufw deny 9993/tcp\n"
        )
        rules = ufw.parse_ufw_added(text)
        canons = {r.canonical for r in rules}
        assert "limit 22/tcp" in canons
        assert "allow 20000:20500/udp" in canons
        assert "allow from 203.0.113.10 to any port 443 proto udp" in canons
        assert "deny 9993/tcp" in canons

    def test_combined_snapshot_merges_added_when_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/udp"], active=False), monkeypatch)
        snap = ufw._ufw_snapshot_combined()
        # inactive-статус пуст, но show added знает правило релея
        assert snap.has("allow", "443/udp")


# ---------------------------------------------------------------------------
# План профилей
# ---------------------------------------------------------------------------


class TestBuildPlan:
    def test_gateway_full_plan_ssh_first_enable_last(self) -> None:
        snap = ufw.parse_ufw_status("Status: inactive\n")
        plan = ufw.build_plan("gateway", _gateway_state(), snap, ufw.HardeningOpts())
        adds = [p for p in plan if p.action == "add"]
        rule_specs = {p.meta["spec"] for p in adds if p.kind == "rule" and not p.meta.get("delete")}
        assert GATEWAY_SPECS <= rule_specs
        assert any(p.is_ssh_rule and p.meta["spec"] == "22/tcp" for p in adds)
        # порядок: ssh-правило раньше enable, enable — последний элемент
        enable_idx = [i for i, p in enumerate(plan) if p.is_enable]
        ssh_idx = [i for i, p in enumerate(plan) if p.is_ssh_rule]
        assert enable_idx and ssh_idx and ssh_idx[0] < enable_idx[0]
        assert plan[-1].is_enable

    def test_order_steps_moves_enable_last(self) -> None:
        plan = [
            ufw.PlanItem("enable", "ufw --force enable", "add"),
            ufw.PlanItem("rule", "ufw limit 22/tcp", "add", {"action": "limit", "spec": "22/tcp", "ssh": True}),
            ufw.PlanItem("config", "default", "add"),
        ]
        ordered = ufw.order_steps(plan)
        assert ordered[-1].is_enable
        assert not ordered[0].is_enable

    def test_relay_detects_existing_443_udp(self) -> None:
        snap = ufw.parse_ufw_status(
            "Status: active\nTo Action From\n-- ------ ----\n443/udp ALLOW IN Anywhere\n"
        )
        st = GatewayState()
        st.protocols = {"relay": {"installed": True}}
        plan = ufw.build_plan("relay", st, snap, ufw.HardeningOpts())
        by_spec = {p.meta.get("spec"): p.action for p in plan if p.kind == "rule"}
        assert by_spec.get("443/udp") == "skip"  # relay init уже открыл — не дублируем
        assert by_spec.get("443/tcp") == "add"

    def test_exit_cascade_requires_allow_from(self) -> None:
        snap = ufw.parse_ufw_status("Status: inactive\n")
        with pytest.raises(ufw.UfwError, match="--allow-from"):
            ufw.build_plan("exit-cascade", _gateway_state(), snap, ufw.HardeningOpts())

    def test_exit_cascade_replaces_wide_443_with_from_rules(self) -> None:
        snap = ufw.parse_ufw_status(
            "Status: active\nTo Action From\n-- ------ ----\n"
            "443/tcp ALLOW IN Anywhere\n443/udp ALLOW IN Anywhere\n"
        )
        st = _gateway_state()
        plan = ufw.build_plan(
            "exit-cascade", st, snap, ufw.HardeningOpts(allow_from=RELAY_IP)
        )
        deletes = [p for p in plan if p.meta.get("delete")]
        assert {p.meta["spec"] for p in deletes} == {"443/tcp", "443/udp"}
        from_specs = {
            p.meta["spec"] for p in plan if p.kind == "rule" and p.meta.get("spec", "").startswith("from ")
        }
        assert from_specs == {
            f"from {RELAY_IP} to any port 443 proto tcp",
            f"from {RELAY_IP} to any port 443 proto udp",
        }
        plain_adds = {
            p.meta["spec"] for p in plan
            if p.kind == "rule" and p.action == "add" and not p.meta.get("delete")
            and "/" in p.meta.get("spec", "")
        }
        assert "443/tcp" not in plain_adds and "443/udp" not in plain_adds

    def test_idempotent_second_plan_all_skip(self) -> None:
        st = _gateway_state()
        specs = GATEWAY_SPECS
        rule_lines = "\n".join(
            f"{spec} ALLOW IN Anywhere" for spec in specs if "/udp" in spec or "/tcp" in spec
        )
        snap = ufw.parse_ufw_status(
            "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
            "To Action From\n-- ------ ----\n" + rule_lines + "\n22/tcp LIMIT IN Anywhere\n"
        )
        plan = ufw.build_plan("gateway", st, snap, ufw.HardeningOpts())
        adds = [p for p in plan if p.action == "add"]
        assert [p for p in adds if p.kind == "rule"] == []
        assert [p for p in plan if p.is_enable and p.action == "add"] == []

    def test_pending_ssh_transfer_limits_both_ports(self) -> None:
        st = _gateway_state()
        st.protocols["ufw-ssh-port"] = {"pending": True, "port": 49222, "legacy_22_still_open": True}
        snap = ufw.parse_ufw_status("Status: inactive\n")
        plan = ufw.build_plan("gateway", st, snap, ufw.HardeningOpts())
        ssh_specs = {p.meta["spec"] for p in plan if p.is_ssh_rule}
        assert ssh_specs == {"49222/tcp", "22/tcp"}  # SPEC §1.10.3: limit на ОБА

    def test_finalized_ssh_transfer_limits_only_new_port(self) -> None:
        st = _gateway_state()
        st.protocols["ufw-ssh-port"] = {"pending": False, "port": 49222, "legacy_22_still_open": False}
        snap = ufw.parse_ufw_status("Status: inactive\n")
        plan = ufw.build_plan("gateway", st, snap, ufw.HardeningOpts())
        ssh_specs = {p.meta["spec"] for p in plan if p.is_ssh_rule}
        assert ssh_specs == {"49222/tcp"}


class TestDiffListeners:
    def test_foreign_port_warned(self) -> None:
        ss_lines = [
            "LISTEN 0 128 0.0.0.0:9993 0.0.0.0:* users:((\"zt-edge\",pid=1))",
        ]
        warns = ufw.diff_listeners({"443/tcp"}, ss_lines)
        assert len(warns) == 1 and "9993" in warns[0]

    def test_docker_proxy_flagged(self) -> None:
        ss_lines = ["LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"docker-proxy\",pid=2))"]
        warns = ufw.diff_listeners(set(), ss_lines)
        assert warns and "docker" in warns[0]

    def test_loopback_ignored_profile_ports_not_warned(self) -> None:
        ss_lines = [
            "LISTEN 0 128 127.0.0.1:8443 0.0.0.0:* users:((\"xray\",pid=3))",
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"xray\",pid=4))",
        ]
        assert ufw.diff_listeners({"443/tcp", "8443/tcp"}, ss_lines) == []


# ---------------------------------------------------------------------------
# run_harden: apply / undo / dry-run
# ---------------------------------------------------------------------------


class TestRunHardenApply:
    def test_apply_enable_last_and_meta_written(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_harden("gateway", apply=True, state_path=state_path)
        assert rc == 0
        # enable был вызван и ПОСЛЕ limit 22
        calls = fake.calls
        enable_idx = calls.index(["ufw", "--force", "enable"])
        limit_idx = calls.index(["ufw", "limit", "22/tcp"])
        assert limit_idx < enable_idx
        state = load_state(state_path)
        meta = state.protocols["ufw"]
        assert meta["installed"] is True and meta["profile"] == "gateway"
        assert "limit 22/tcp" in meta["applied_rules"]
        assert meta["ufw_was_active"] is False

    def test_double_apply_idempotent(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_harden("gateway", apply=True, state_path=state_path) == 0
        adds_before = len(fake.calls)
        assert ufw.run_harden("gateway", apply=True, state_path=state_path) == 0
        # второй прогон: только чтение статуса/слушателей, ни одного add/enable
        mut2 = [c for c in fake.calls[adds_before:] if not _read_only(c)]
        assert mut2 == []

    def test_enable_failfast_without_ssh_rule(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(), monkeypatch)
        # имитируем отказ добавления ssh-правила
        orig_run = fake.run

        def failing(args, timeout=10):
            if args[:2] == ["ufw", "limit"]:
                from src.core.shell import ShellResult
                fake.calls.append(list(args))
                return ShellResult(stdout="", stderr="ERROR: Could not add rule", returncode=1)
            return orig_run(args, timeout=timeout)

        monkeypatch.setattr(ufw, "run_list", failing)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_harden("gateway", apply=True, state_path=state_path)
        assert rc == 1
        assert ["ufw", "--force", "enable"] not in fake.calls

    def test_forward_policy_reload_when_was_active(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # техлид п.5: при уже-active ufw правка /etc/default/ufw требует reload
        fake = _wire(FakeUfw(active=True, defaults=("deny", "allow")), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_harden("gateway", apply=True, state_path=state_path)
        assert rc == 0
        assert ["ufw", "reload"] in fake.calls
        assert ["ufw", "--force", "enable"] not in fake.calls  # уже active — enable skip

    def test_forward_policy_no_reload_when_was_inactive(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(active=False), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_harden("gateway", apply=True, state_path=state_path) == 0
        assert ["ufw", "reload"] not in fake.calls
        assert ["ufw", "--force", "enable"] in fake.calls  # был inactive — enable последним

    def test_dry_run_does_not_mutate(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        state_before = Path(state_path).read_text()
        rc = ufw.run_harden("gateway", apply=False, state_path=state_path)
        assert rc == 0
        mut = [c for c in fake.calls if not _read_only(c)]
        assert mut == []
        assert Path(state_path).read_text() == state_before


class TestRunUndo:
    def test_undo_reverses_and_disables(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["limit 22/tcp", "allow 443/udp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        st = _gateway_state()
        st.protocols["ufw"] = {
            "installed": True, "profile": "gateway", "ssh_port": 22,
            "applied_rules": ["limit 22/tcp", "allow 443/udp", "__enabled__"],
            "ufw_was_active": False, "ts": "t",
        }
        save_state(st, state_path)
        rc = ufw.run_undo(state_path=state_path, apply=True)
        assert rc == 0
        assert fake.rules == []  # оба правила сняты (реверс)
        assert ["ufw", "disable"] in fake.calls  # был inactive до harden
        state = load_state(state_path)
        assert state.protocols["ufw"]["installed"] is False

    def test_undo_restores_cascade_deleted_wide_rule(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow from 203.0.113.10 to any port 443 proto tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        st = GatewayState()
        st.protocols["ufw"] = {
            "installed": True, "profile": "exit-cascade", "ssh_port": 22,
            "applied_rules": ["allow from 203.0.113.10 to any port 443 proto tcp",
                              "__deleted__ allow 443/tcp", "__enabled__"],
            "ufw_was_active": True, "ts": "t",
        }
        save_state(st, state_path)
        assert ufw.run_undo(state_path=state_path, apply=True) == 0
        assert "allow 443/tcp" in fake.rules  # широкое правило восстановлено
        assert ["ufw", "disable"] not in fake.calls  # ufw был active — не выключаем

    def test_undo_without_meta_is_noop(self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(GatewayState(), state_path)
        assert ufw.run_undo(state_path=state_path, apply=False) == 0


# ---------------------------------------------------------------------------
# ssh-port: двухфазность (WP-2b + техлид п.3)
# ---------------------------------------------------------------------------


class TestSshPortRenders:
    def test_phase_a_conf_dual_listen(self) -> None:
        conf = ufw.render_sshd_port_conf(49222, keep_22=True)
        assert "Port 22" in conf and "Port 49222" in conf

    def test_phase_a_dropin_dual_listen(self) -> None:
        dropin = ufw.render_socket_dropin(49222, keep_22=True)
        assert "ListenStream=" in dropin  # пустой = сброс дефолта
        assert "ListenStream=22" in dropin and "ListenStream=49222" in dropin

    def test_phase_b_conf_only_new_port(self) -> None:
        assert ufw.render_sshd_port_conf(49222, keep_22=False) == "Port 49222\n"
        dropin = ufw.render_socket_dropin(49222, keep_22=False)
        assert "ListenStream=22" not in dropin and "ListenStream=49222" in dropin


def _pending_state(state_path: str, port: int = 49222) -> None:
    st = _gateway_state()
    st.protocols["ufw-ssh-port"] = {
        "pending": True, "port": port, "legacy_22_still_open": True,
        "dual_listen": True, "sshd_conf_backup": "", "socket_dropin": "", "ts": "t",
    }
    st.protocols["ufw"] = {"installed": True, "profile": "gateway", "ssh_port": 22,
                           "applied_rules": ["limit 22/tcp", f"limit {port}/tcp"], "ts": "t"}
    save_state(st, state_path)


class TestSshPortPhaseA:
    def test_apply_writes_dual_listen_and_pending_marker(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(ss_lines=["LISTEN 0 128 0.0.0.0:49222 0.0.0.0:* users:((\"sshd\",pid=9))"]), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_ssh_port(49222, finalize=False, apply=True, state_path=state_path)
        assert rc == 0
        conf = ufw.UFW_SSHD_CONF.read_text()
        assert "Port 22" in conf and "Port 49222" in conf
        state = load_state(state_path)
        marker = state.protocols["ufw-ssh-port"]
        assert marker["pending"] is True and marker["legacy_22_still_open"] is True
        assert marker["dual_listen"] is True
        # Фаза A не удаляет правила 22
        assert not any(c[0] == "ufw" and c[1] == "delete" for c in fake.calls)
        assert ["ufw", "limit", "49222/tcp"] in fake.calls
        assert ufw.RUN_SSHD_DIR.is_dir()  # техлид п.2: /run/sshd перед sshd -t

    def test_dry_run_writes_nothing(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_ssh_port(49222, finalize=False, apply=False, state_path=state_path)
        assert rc == 0
        assert not ufw.UFW_SSHD_CONF.exists()
        mut = [c for c in fake.calls if not _read_only(c)]
        assert mut == []

    def test_sshd_t_failure_aborts_and_restores(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(sshd_t_fails=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_ssh_port(49222, finalize=False, apply=True, state_path=state_path)
        assert rc == 1
        state = load_state(state_path)
        assert "ufw-ssh-port" not in state.protocols  # маркер не выставлен
        assert not ufw.UFW_SSHD_CONF.exists()  # откат: созданный файл удалён

    def test_port_not_listening_aborts_with_rollback(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ss не показывает 49222 -> abort + откат конфигов
        fake = _wire(FakeUfw(ss_lines=[]), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_ssh_port(49222, finalize=False, apply=True, state_path=state_path)
        assert rc == 1
        assert "ufw-ssh-port" not in load_state(state_path).protocols

    def test_transfer_and_finalize_not_combinable(self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(GatewayState(), state_path)
        assert ufw.run_ssh_port(49222, finalize=True, apply=False, state_path=state_path) == 2
        # одна команда не может закрыть 22 (двухфазность — железное требование)

    def test_requires_to_or_finalize(self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire(FakeUfw(), monkeypatch)
        assert ufw.run_ssh_port(None, finalize=False, apply=False) == 2


class TestSshPortFinalize:
    def test_finalize_without_pending_is_error(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(ss_lines=["LISTEN 0 128 0.0.0.0:49222 0.0.0.0:* users:((\"sshd\",pid=9))"]), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(GatewayState(), state_path)
        rc = ufw.run_ssh_port(None, finalize=True, apply=False, state_path=state_path)
        assert rc == 1

    def test_finalize_order_config_restart_then_delete_22(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(
            rules=["limit 22/tcp", "allow 22/tcp", "limit 49222/tcp"],
            ss_lines=["LISTEN 0 128 0.0.0.0:49222 0.0.0.0:* users:((\"sshd\",pid=9))"],
        ), monkeypatch)
        state_path = str(fake_paths / "state.json")
        _pending_state(state_path)
        rc = ufw.run_ssh_port(None, finalize=True, apply=True, state_path=state_path)
        assert rc == 0
        # порядок: sshd-правка -> restart -> ufw delete (техлид п.3)
        calls = fake.calls
        conf_write_idx = next(i for i, c in enumerate(calls) if c[0] == "sshd" and c[1] == "-t")
        restart_idx = calls.index(["systemctl", "restart", "ssh"])
        del_idx = next(i for i, c in enumerate(calls) if c[:2] == ["ufw", "delete"])
        assert conf_write_idx < restart_idx < del_idx
        # удалены только 22-правила, limit 49222 жив
        assert "limit 22/tcp" not in fake.rules and "allow 22/tcp" not in fake.rules
        assert "limit 49222/tcp" in fake.rules
        conf = ufw.UFW_SSHD_CONF.read_text()
        assert "Port 22" not in conf and "Port 49222" in conf
        state = load_state(state_path)
        marker = state.protocols["ufw-ssh-port"]
        assert marker["pending"] is False and marker["legacy_22_still_open"] is False

    def test_finalize_refuses_when_port_not_listening(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["limit 22/tcp"]), monkeypatch)
        state_path = str(fake_paths / "state.json")
        _pending_state(state_path)
        rc = ufw.run_ssh_port(None, finalize=True, apply=True, state_path=state_path)
        assert rc == 1
        # 22 сохраняется
        assert "limit 22/tcp" in fake.rules
        assert load_state(state_path).protocols["ufw-ssh-port"]["pending"] is True


class TestStatusPendingWarning:
    def test_status_prints_pending_warning(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _wire(FakeUfw(), monkeypatch)
        state_path = str(fake_paths / "state.json")
        _pending_state(state_path)
        rc = ufw.run_status(state_path=state_path)
        assert rc == 0
        assert "finalize" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# lock-443 (SPEC-20261116-probe-response §4.1, §9.B/C/D, §10 OQ-2, §11)
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

def _only_443_state() -> GatewayState:
    """Профиль «только 443»: xray без AWG/CDN — fail-fast §4.2 обязан сработать."""
    st = GatewayState()
    st.protocols = {"xray": {"installed": True, "port": 443}}
    return st


class TestTtlAndAllowParsing:
    def test_ttl_ok_and_bounds(self) -> None:
        assert ufw.parse_ttl_hours("48h") == 48
        assert ufw.parse_ttl_hours("1h") == 1
        assert ufw.parse_ttl_hours("168h") == 168
        assert ufw.parse_ttl_hours(" 24h ") == 24

    def test_ttl_bad_format(self) -> None:
        for bad in ("", "48", "2d", "h48", "4.5h"):
            with pytest.raises(ufw.UfwError):
                ufw.parse_ttl_hours(bad)

    def test_ttl_out_of_range(self) -> None:
        for bad in ("0h", "169h", "99999h"):
            with pytest.raises(ufw.UfwError, match="1h..168h"):
                ufw.parse_ttl_hours(bad)

    def test_allow_from_ok(self) -> None:
        assert ufw.parse_allow_from(None) == []
        assert ufw.parse_allow_from("203.0.113.10") == ["203.0.113.10"]
        assert ufw.parse_allow_from("203.0.113.10, 203.0.113.11,203.0.113.10") == [
            "203.0.113.10", "203.0.113.11",
        ]

    def test_allow_from_rejects_garbage_and_v6(self) -> None:
        with pytest.raises(ufw.UfwError, match="некорректный IP"):
            ufw.parse_allow_from("not-an-ip")
        with pytest.raises(ufw.UfwError, match="не IPv4"):
            ufw.parse_allow_from("2001:db8::1")


class TestLockdownHelpers:
    def test_get_lockdown_normalizes(self) -> None:
        st = GatewayState()
        st.ufw_lockdown = {
            "active": 1, "since": "2026-11-16T10:00:00+00:00",
            "ttl_until": "2026-11-18T10:00:00+00:00", "ttl_hours": "48",
            "allow_from": ["203.0.113.10"], "reason": "auto:RU-SUSPECT",
            "removed_wide": ["allow 443/tcp"], "added_from": ["allow from 203.0.113.10 to any port 443 proto tcp"],
        }
        ld = ufw.get_lockdown(st)
        assert ld["active"] is True
        assert ld["ttl_hours"] == 48  # int-нормализация из строки
        assert ld["allow_from"] == ["203.0.113.10"]

    def test_get_lockdown_empty_state(self) -> None:
        ld = ufw.get_lockdown(GatewayState())
        assert ld == {
            "active": False, "since": "", "ttl_until": "", "ttl_hours": 0,
            "allow_from": [], "reason": "", "removed_wide": [], "added_from": [],
        }

    def test_ttl_expired(self) -> None:
        now = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
        past = {"active": True, "ttl_until": "2026-11-18T10:00:00+00:00"}
        future = {"active": True, "ttl_until": "2026-11-18T14:00:00+00:00"}
        assert ufw.lockdown_ttl_expired(past, now) is True
        assert ufw.lockdown_ttl_expired(future, now) is False
        assert ufw.lockdown_ttl_expired({"active": False, "ttl_until": past["ttl_until"]}, now) is False
        assert ufw.lockdown_ttl_expired({"active": True, "ttl_until": "не-дата"}, now) is False

    def test_has_non_443_channel(self) -> None:
        assert ufw.has_non_443_channel(_gateway_state()) is True  # есть awg+cdn
        assert ufw.has_non_443_channel(_only_443_state()) is False

    def test_detect_hop(self) -> None:
        st = _gateway_state()
        snap = ufw.parse_ufw_status("Status: inactive\n")
        assert ufw.detect_hop(st, snap) is True  # hop_ports в state.protocols
        st2 = GatewayState()
        st2.protocols = {"hysteria2": {"installed": True}}
        snap_range = ufw.parse_ufw_status(
            "Status: active\nTo Action From\n-- ------ ----\n20000:20500/udp ALLOW IN Anywhere\n"
        )
        assert ufw.detect_hop(st2, snap_range) is True  # широкое udp-правило-диапазон
        snap_plain = ufw.parse_ufw_status(
            "Status: active\nTo Action From\n-- ------ ----\n443/udp ALLOW IN Anywhere\n"
        )
        assert ufw.detect_hop(st2, snap_plain) is False


class TestBuildLockdownPlan:
    def _snap(self, rules: list[str]) -> ufw.UfwSnapshot:
        lines = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n" \
                "To Action From\n-- ------ ----\n" + "\n".join(
                    f"{r.split(' ', 1)[1]:<26} {r.split(' ', 1)[0].upper():<6} IN    Anywhere"
                    for r in rules
                ) + "\n"
        return ufw.parse_ufw_status(lines)

    def test_from_rules_first_then_tcp_delete_hop_warning(self) -> None:
        st = _gateway_state()  # hop_ports есть → hop-детект
        snap = self._snap(["allow 443/tcp", "allow 443/udp", "allow 20000:20500/udp"])
        plan = ufw.build_lockdown_plan(st, snap, ["203.0.113.10"], with_udp=False)
        rules = [p for p in plan if p.kind == "rule"]
        # from-правило ПЕРВЫМ (fail-safe: сначала доступ, потом изоляция)
        assert rules[0].meta["spec"] == "from 203.0.113.10 to any port 443 proto tcp"
        deletes = [p.meta["spec"] for p in rules if p.meta.get("delete")]
        assert deletes == ["443/tcp"]  # §9.B: по умолчанию ТОЛЬКО tcp
        warns = [p for p in plan if p.kind == "check" and p.action == "warn"]
        assert warns and "Hy2-hop" in warns[0].detail

    def test_with_udp_closes_udp_and_hop_range(self) -> None:
        st = _gateway_state()
        snap = self._snap(["allow 443/tcp", "allow 443/udp", "allow 20000:20500/udp"])
        plan = ufw.build_lockdown_plan(st, snap, [], with_udp=True)
        deletes = [p.meta["spec"] for p in plan if p.kind == "rule" and p.meta.get("delete")]
        assert deletes == ["443/tcp", "443/udp", "20000:20500/udp"]

    def test_no_hop_no_with_udp_touches_only_tcp(self) -> None:
        st = GatewayState()
        st.protocols = {"xray": {"installed": True, "port": 443}, "amneziawg": {"installed": True, "port": 51825}}
        snap = self._snap(["allow 443/tcp", "allow 443/udp"])
        plan = ufw.build_lockdown_plan(st, snap, [], with_udp=False)
        deletes = [p.meta["spec"] for p in plan if p.kind == "rule" and p.meta.get("delete")]
        assert deletes == ["443/tcp"]

    def test_absent_wide_rule_is_skip(self) -> None:
        st = GatewayState()
        snap = ufw.parse_ufw_status("Status: inactive\n")
        plan = ufw.build_lockdown_plan(st, snap, [], with_udp=False)
        tcp_delete = next(p for p in plan if p.kind == "rule" and p.meta.get("delete"))
        assert tcp_delete.action == "skip"  # идемпотентно: удалять нечего


class TestLock443:
    def test_dry_run_does_not_mutate(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp", "allow 443/udp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        state_before = Path(state_path).read_text()
        rc = ufw.run_lock443(allow_from=RELAY_IP, apply=False, state_path=state_path)
        assert rc == 0
        mut = [c for c in fake.calls if not _read_only(c)]
        assert mut == []
        assert "allow 443/tcp" in fake.rules
        assert Path(state_path).read_text() == state_before  # state не тронут

    def test_apply_locks_tcp_journal_and_ttl(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(
            FakeUfw(rules=["allow 443/tcp", "allow 443/udp", "allow 20000:20500/udp"], active=True),
            monkeypatch,
        )
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_lock443(
            allow_from=RELAY_IP, ttl="24h", reason="RU-PROBE-SUSPECT", apply=True,
            state_path=state_path,
        )
        assert rc == 0
        # широкее 443/tcp удалено; udp/hop НЕ тронуты (§9.B)
        assert "allow 443/tcp" not in fake.rules
        assert "allow 443/udp" in fake.rules
        assert "allow 20000:20500/udp" in fake.rules
        # allow-from добавлен
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" in fake.rules
        state = load_state(state_path)
        ld = ufw.get_lockdown(state)
        assert ld["active"] is True
        assert ld["allow_from"] == [RELAY_IP]
        assert ld["reason"] == "RU-PROBE-SUSPECT"
        assert ld["removed_wide"] == ["443/tcp"]
        assert ld["added_from"] == [f"allow from {RELAY_IP} to any port 443 proto tcp"]
        # TTL ≈ now+24h
        until = datetime.fromisoformat(ld["ttl_until"])
        delta = until - datetime.now(timezone.utc)
        assert timedelta(hours=23, minutes=55) < delta < timedelta(hours=24, minutes=5)

    def test_reapply_extends_ttl_and_replaces_allow(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_lock443(allow_from=RELAY_IP, ttl="1h", apply=True, state_path=state_path) == 0
        first_until = load_state(state_path).ufw_lockdown["ttl_until"]
        first_since = load_state(state_path).ufw_lockdown["since"]
        # повторный apply: allow-from ЗАМЕНЯЕТСЯ, TTL продлевается, since сохраняется
        rc = ufw.run_lock443(allow_from="203.0.113.11", ttl="48h", apply=True, state_path=state_path)
        assert rc == 0
        state = load_state(state_path)
        ld = ufw.get_lockdown(state)
        assert ld["allow_from"] == ["203.0.113.11"]
        assert ld["since"] == first_since  # это продление, не «новый» лок
        assert ld["ttl_until"] > first_until
        # старый from-rule снят, новый на месте, дублей нет
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" not in fake.rules
        assert "allow from 203.0.113.11 to any port 443 proto tcp" in fake.rules
        assert len([r for r in fake.rules if r.startswith("allow from")]) == 1
        # removed_wide не дублируется
        assert ld["removed_wide"] == ["443/tcp"]

    def test_only_443_profile_empty_allow_failfast(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(rules=["allow 443/tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_only_443_state(), state_path)
        rc = ufw.run_lock443(apply=False, state_path=state_path)  # даже dry-run отказан
        assert rc == 1

    def test_bad_ttl_returns_2(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_lock443(ttl="9000h", apply=False, state_path=state_path) == 2
        assert ufw.run_lock443(ttl="nope", apply=False, state_path=state_path) == 2

    def test_unlock_restores_exactly(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp", "allow 443/udp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_lock443(allow_from=RELAY_IP, apply=True, state_path=state_path) == 0
        assert "allow 443/tcp" not in fake.rules
        rc = ufw.run_lock443(unlock=True, apply=True, state_path=state_path)
        assert rc == 0
        # ровно снимок: широкие восстановлены, from-правило снято
        assert "allow 443/tcp" in fake.rules
        assert "allow 443/udp" in fake.rules
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" not in fake.rules
        state = load_state(state_path)
        assert ufw.get_lockdown(state)["active"] is False
        events = state.ufw_lockdown.get("events") or []
        assert any(e.get("event") == "unlock" for e in events)

    def test_unlock_merge_hint_for_manual_changes(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_lock443(allow_from=RELAY_IP, apply=True, state_path=state_path) == 0
        # владелец вручную переоткрыл 443/udp во время лока (вне журнала)
        fake.rules.append("allow 443/udp")
        rc = ufw.run_lock443(unlock=True, apply=True, state_path=state_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "вне журнала лока" in out  # merge-подсказка, не молчаливая перезапись
        assert "allow 443/udp" in fake.rules  # ручное правило сохранено

    def test_unlock_idempotent_when_inactive(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.run_lock443(unlock=True, apply=True, state_path=state_path) == 0
        assert "allow 443/tcp" in fake.rules  # не тронуто: лока не было

    def test_status_prints_lockdown(
        self, fake_paths: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _wire(FakeUfw(active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        rc = ufw.run_lock443(status=True, state_path=state_path)
        assert rc == 0
        assert "не активен" in capsys.readouterr().out


class TestHardenGuard:
    def _locked_state(self, state_path: str) -> None:
        st = _gateway_state()
        st.ufw_lockdown = {
            "active": True, "since": "t", "ttl_until": "2999-01-01T00:00:00+00:00",
            "ttl_hours": 48, "allow_from": [], "reason": "drill",
            "removed_wide": ["443/tcp"], "added_from": [],
        }
        save_state(st, state_path)

    def test_harden_refused_during_lockdown(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(active=True, defaults=("deny", "allow")), monkeypatch)
        state_path = str(fake_paths / "state.json")
        self._locked_state(state_path)
        rc = ufw.run_harden("gateway", apply=True, state_path=state_path)
        assert rc == 1

    def test_harden_force_proceeds_and_journals(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(active=True, defaults=("deny", "allow")), monkeypatch)
        state_path = str(fake_paths / "state.json")
        self._locked_state(state_path)
        rc = ufw.run_harden("gateway", apply=True, state_path=state_path, force=True)
        assert rc == 0
        assert ["ufw", "--force", "enable"] not in fake.calls  # уже active
        events = load_state(state_path).ufw_lockdown.get("events") or []
        assert any(e.get("event") == "harden-force" for e in events)


class TestAutoLockdownApi:
    def test_apply_auto_lockdown_uses_allow_and_ttl(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=["allow 443/tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        ok = ufw.apply_auto_lockdown(
            state_path=state_path, allow_ips=[RELAY_IP], ttl_hours=24, reason="auto:RU-SUSPECT"
        )
        assert ok is True
        assert "allow 443/tcp" not in fake.rules
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" in fake.rules
        ld = ufw.get_lockdown(load_state(state_path))
        assert ld["active"] is True and ld["reason"] == "auto:RU-SUSPECT"

    def test_apply_auto_lockdown_failfast_only_443(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_only_443_state(), state_path)
        assert ufw.apply_auto_lockdown(state_path=state_path, allow_ips=[]) is False

    def test_extend_lockdown_ttl_rearms(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        st = _gateway_state()
        st.ufw_lockdown = {
            "active": True, "since": "t", "ttl_until": "2026-11-16T12:00:00+00:00",
            "ttl_hours": 48, "allow_from": [], "removed_wide": [], "added_from": [],
        }
        save_state(st, state_path)
        now = datetime(2026, 11, 17, 0, 0, 0, tzinfo=timezone.utc)
        assert ufw.extend_lockdown_ttl(state_path=state_path, now=now) is True
        assert load_state(state_path).ufw_lockdown["ttl_until"] == "2026-11-19T00:00:00+00:00"
        events = load_state(state_path).ufw_lockdown.get("events") or []
        assert any(e.get("event") == "extend" for e in events)

    def test_extend_inactive_is_noop(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire(FakeUfw(active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        save_state(_gateway_state(), state_path)
        assert ufw.extend_lockdown_ttl(state_path=state_path) is False

    def test_auto_unlock_expired_restores(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=[f"allow from {RELAY_IP} to any port 443 proto tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        st = _gateway_state()
        st.ufw_lockdown = {
            "active": True, "since": "t", "ttl_until": "2026-11-16T11:00:00+00:00",
            "ttl_hours": 48, "allow_from": [RELAY_IP], "reason": "auto:RU-SUSPECT",
            "removed_wide": ["443/tcp"],
            "added_from": [f"allow from {RELAY_IP} to any port 443 proto tcp"],
        }
        save_state(st, state_path)
        now = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        assert ufw.auto_unlock_expired(state_path=state_path, now=now) is True
        assert "allow 443/tcp" in fake.rules
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" not in fake.rules
        ld = ufw.get_lockdown(load_state(state_path))
        assert ld["active"] is False

    def test_auto_unlock_not_expired_noop(
        self, fake_paths: Path, root: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _wire(FakeUfw(rules=[f"allow from {RELAY_IP} to any port 443 proto tcp"], active=True), monkeypatch)
        state_path = str(fake_paths / "state.json")
        st = _gateway_state()
        st.ufw_lockdown = {
            "active": True, "ttl_until": "2999-01-01T00:00:00+00:00",
            "removed_wide": ["443/tcp"], "added_from": [],
        }
        save_state(st, state_path)
        assert ufw.auto_unlock_expired(state_path=state_path) is False
        assert f"allow from {RELAY_IP} to any port 443 proto tcp" in fake.rules
