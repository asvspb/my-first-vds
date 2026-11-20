"""Тесты tools/docsync.py (SPEC-20261116-doc-sync, WP-1/WP-2).

Unit-часть импортирует docsync напрямую; интеграционные сценарии (§12.2:
1,2,4,5 — WP-1; 3,7,8,9 — WP-2) разворачиваются во временном git-репо
(`git init` в tempfile, без сети). Реальный src/main.py используется
только для чтения (AST-фикстура).

Сценарии 6 и 10 (§12.2) — вне WP-1/WP-2 (WP-4, WP-3).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCSYNC = REPO / "tools" / "docsync.py"


def _load_docsync():
    spec = importlib.util.spec_from_file_location("docsync_under_test", DOCSYNC)
    mod = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


ds = _load_docsync()


# ---------------------------------------------------------------------------
# фикстуры временного репо
# ---------------------------------------------------------------------------

MINI_REGISTRY = {
    "version": 1,
    # сценарии §12.2 проверяют блокирующую семантику (mode=block);
    # warn-режим тестируется отдельно (WP-4).
    "mode": "block",
    "classes": {
        "living": ["README.md", "AGENTS.md", "TECHDEBT.md", "docs/SERVER-BASELINE.md"],
        "status": ["docs/team/STATUS.md"],
        "adr": ["docs/adr/ADR-*.md"],
        "snapshot": ["docs/team/specs/**"],
        "template": [],
    },
    "rules": [
        {
            "id": "ufw",
            "match": ["src/system/ufw.py"],
            "require": ["README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"],
            "consider": [],
            "why": "порты/профили",
        }
    ],
    "reverse": {
        "commands_from": "src/main.py",
        "commands_docs": ["README.md", "AGENTS.md"],
        "legacy_commands_allowlist": [],
        "units_docs": ["README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"],
        "generated_units_allowlist": [],
        "adr_docs": ["AGENTS.md", "README.md"],
        "agents_docs": ["docs/TEAM.md", "AGENTS.md", "README.md"],
        "version_docs": ["README.md", "AGENTS.md"],
        "links": True,
        "banned_test_counts": True,
    },
    "freshness": {"status_days": 7, "living_days": 30, "source_lag": "warn"},
    "escape": {"trailer": "Docs: none", "require_reason": True, "require_debt_ref": True},
}

MINI_MAIN_PY = textwrap.dedent(
    """
    import typer
    app = typer.Typer(name="vds", invoke_without_command=True)
    gw_app = typer.Typer()
    app.add_typer(gw_app, name="gateway")

    @app.callback(invoke_without_command=True)
    def main_menu(ctx: typer.Context):
        if ctx.invoked_subcommand is not None:
            return

    @app.command()
    def sysinfo():
        pass

    @gw_app.command("healthcheck")
    def gateway_healthcheck():
        pass
    """
)

MINI_README = "# vds\n\nВерсия: 1.0.0. Команды: `vds sysinfo`, `vds gateway healthcheck`.\n"
MINI_AGENTS = "# AGENTS\n\nВерсия 1.0.0. Команды: vds sysinfo, vds gateway healthcheck.\n"
MINI_BASELINE = "# SERVER-BASELINE\n\nПорты и профили.\n"
MINI_STATUS = "# STATUS\n\nЦикл закрыт.\n"
MINI_TECHDEBT = "# TECHDEBT\n\n## P4 — тестовый долг\n\nТекст.\n"


def write(repo: Path, rel: str, content: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def git_cmd(repo: Path, args: list[str], env_extra: dict | None = None) -> str:
    import os

    env = dict(os.environ)
    env.update(env_extra or {})
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args, capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, f"git {args}: {proc.stderr}"
    return proc.stdout


def make_repo(tmp: Path, *, commit_date: str | None = None) -> Path:
    """Baseline-репо, на котором audit зелёный (кроме тестируемого аспекта)."""
    repo = tmp / "repo"
    repo.mkdir()
    git_cmd(repo, ["init", "-q"])
    git_cmd(repo, ["config", "user.email", "test@example.com"])
    git_cmd(repo, ["config", "user.name", "T"])
    write(repo, "docs/doc-sync.json", json.dumps(MINI_REGISTRY, indent=2))
    write(repo, "src/main.py", MINI_MAIN_PY)
    write(repo, "README.md", MINI_README)
    write(repo, "AGENTS.md", MINI_AGENTS)
    write(repo, "TECHDEBT.md", MINI_TECHDEBT)
    write(repo, "docs/SERVER-BASELINE.md", MINI_BASELINE)
    write(repo, "docs/team/STATUS.md", MINI_STATUS)
    write(repo, "pyproject.toml", '[project]\nname = "vds-cli"\nversion = "1.0.0"\n')
    write(repo, "docs/TEAM.md", "# TEAM\n\nРоль: vds-coder.\n")
    write(repo, ".zcode/agents/vds-coder.md", "# coder\n")
    env = {"GIT_COMMITTER_DATE": commit_date, "GIT_AUTHOR_DATE": commit_date} if commit_date else None
    git_cmd(repo, ["add", "-A"], env)
    git_cmd(repo, ["commit", "-q", "-m", "init"], env)
    return repo


def run_docsync(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DOCSYNC), "--repo", str(repo)] + args,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )


def stage(repo: Path, rel: str, content: str) -> None:
    write(repo, rel, content)
    git_cmd(repo, ["add", rel])


def commit_msg_file(tmp: Path, message: str) -> Path:
    p = tmp / "msg.txt"
    p.write_text(message, encoding="utf-8")
    return p


OLD_DATE = "2026-10-01T12:00:00"


# ---------------------------------------------------------------------------
# §12.1 unit: матчинг правил
# ---------------------------------------------------------------------------

def test_match_path_glob_and_normalization() -> None:
    assert ds.match_path("src/relay/init.py", "src/relay/**")
    assert ds.match_path("src\\relay\\init.py", "src/relay/**")  # нормализация \
    assert ds.match_path("src/main.py", "src/main.py")
    assert not ds.match_path("src/relayx/a.py", "src/relay/**")
    assert ds.match_path("systemd/sysctl/x.tpl", "systemd/**")


def test_rules_union_require(tmp_path: Path) -> None:
    reg = ds.Registry.load(REPO)
    # два правила: ufw + systemd → union require
    changed = ["src/system/ufw.py", "systemd/vds-x.service.tpl", "AGENTS.md", "docs/SERVER-BASELINE.md"]
    required, missing, warnings = ds.compute_sync(reg, changed)
    assert set(required) == {"README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"}
    assert missing == ["README.md"]
    assert "docs/DEPLOY.md" in warnings and "docs/MIGRATE-VDS.md" in warnings


def test_docs_only_commit_no_rules(tmp_path: Path) -> None:
    reg = ds.Registry.load(REPO)
    required, missing, _ = ds.compute_sync(reg, ["README.md", "docs/DEPLOY.md"])
    assert required == [] and missing == []


# ---------------------------------------------------------------------------
# §12.1 unit: escape
# ---------------------------------------------------------------------------

def test_escape_valid() -> None:
    ok, reason = ds.parse_escape(
        "refactor\n\nDocs: none — refactor без изменения поверхности (TECHDEBT P19)\n",
        {19},
    )
    assert ok and reason and "refactor" in reason


def test_escape_without_reason_fails() -> None:
    ok, _ = ds.parse_escape("x\n\nDocs: none\n", {19})
    assert not ok


def test_escape_fictional_debt_ref_fails() -> None:
    ok, _ = ds.parse_escape("x\n\nDocs: none — причины нет (TECHDEBT P99)\n", {19})
    assert not ok


# ---------------------------------------------------------------------------
# §12.1 unit: AST-команды на реальном src/main.py (read-only)
# ---------------------------------------------------------------------------

def test_extract_commands_real_main_py() -> None:
    cmds = ds.extract_leaf_commands(REPO / "src" / "main.py")
    # 76 @command-декораторов (в т.ч. 6 logs + 3 logs capture,
    # SPEC-20261116-log-forensics/ADR-012) + probe-watch iwc-leaf
    # + 5 alert-команд (SPEC-20261117-alert-watch)
    # + 2 relay exit-leg (SPEC-20261120-relay-maneuver WP-M2 / ADR-015)
    # + 7 relay maneuver (status/history/step/rollback — WP-M3;
    #   tick/install/remove — opt-in таймер, WP-M4 / ADR-015)
    # + 5 relay wstunnel (install/status — WP-P2P-1; init/server/client — WP-P2P-2 ч.2)
    assert len(cmds) == 96
    assert len(set(cmds)) == len(cmds)
    assert "vds sysinfo" in cmds and "vds cleanup" in cmds and "vds server-setup" in cmds
    assert "vds gateway probe-watch" in cmds  # iwc-leaf
    assert "vds gateway probe-watch ru-cidr update" in cmds  # вложенность 3 уровня
    assert "vds logs sample" in cmds and "vds logs capture start" in cmds  # logs (ADR-012)
    assert "vds alert watch" in cmds and "vds alert test" in cmds  # alert-watch
    assert "vds relay exit-leg install" in cmds  # ADR-015/P24 (exit-сторона)
    assert "vds relay exit-leg remove" in cmds
    allowlist = json.loads((REPO / "docs" / "doc-sync.json").read_text())["reverse"]["legacy_commands_allowlist"]
    assert set(allowlist) <= set(cmds)  # allowlist не протух


def test_extract_commands_zero_guard(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    main.write_text("import typer\napp = typer.Typer()\n", encoding="utf-8")
    assert ds.extract_leaf_commands(main) == []


# ---------------------------------------------------------------------------
# §12.1 unit: banned counts / links / version regex
# ---------------------------------------------------------------------------

def test_banned_counts_detection(tmp_path: Path) -> None:
    doc = tmp_path / "R.md"
    doc.write_text(
        "843 passed\nдва теста назад: 499 тестов\n"
        "<!-- docsync:ignore --> 843 passed\nобычный текст\n",
        encoding="utf-8",
    )
    found = ds.check_banned_counts(tmp_path, "R.md")
    assert len(found) == 2


def test_links_relative(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "ok.md").write_text("x", encoding="utf-8")
    (tmp_path / "docs" / "a.md").write_text(
        "[ok](ok.md) [вверх](../README.md) [битая](nope.md) "
        "[web](https://example.com/x) [якорь](#sec)\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("r", encoding="utf-8")
    problems = ds.check_doc_links(tmp_path, "docs/a.md")
    assert problems == ["docs/a.md: битая ссылка -> nope.md"]


def test_version_regex() -> None:
    m = ds.PYPROJECT_VERSION_RE.search('[project]\nname = "vds-cli"\nversion = "3.0.0"\n')
    assert m is not None and m.group(1) == "3.0.0"


# ---------------------------------------------------------------------------
# §12.2 сценарий 1: ufw.py без доков → blocked
# ---------------------------------------------------------------------------

def test_scenario_1_code_without_docs_blocked(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "feat(ufw): new profile")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 1
    for doc in ("README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"):
        assert doc in proc.stdout


# ---------------------------------------------------------------------------
# §12.2 сценарий 2: + 3 обязательных дока → pass
# ---------------------------------------------------------------------------

def test_scenario_2_code_plus_docs_pass(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    stage(repo, "README.md", MINI_README + " ufw\n")
    stage(repo, "AGENTS.md", MINI_AGENTS + " ufw\n")
    stage(repo, "docs/SERVER-BASELINE.md", MINI_BASELINE + " ufw\n")
    msg = commit_msg_file(tmp_path, "feat(ufw): new profile")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 0, proc.stdout


# ---------------------------------------------------------------------------
# §12.2 сценарий 4: docs-only коммит → pass
# ---------------------------------------------------------------------------

def test_scenario_4_docs_only_pass(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "README.md", MINI_README + " правка\n")
    msg = commit_msg_file(tmp_path, "docs: tweak")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 0


# ---------------------------------------------------------------------------
# §12.2 сценарий 5: escape с долгом → pass + запись в debt
# ---------------------------------------------------------------------------

def test_scenario_5_escape_and_debt(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    message = "refactor(ufw): internals\n\nDocs: none — рефакторинг без изменения поверхности (TECHDEBT P4)\n"
    msg = commit_msg_file(tmp_path, message)
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg), "--json"])
    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["status"] == "warn" and payload["missing"] == []

    git_cmd(repo, ["commit", "-q", "-F", str(msg)])
    debt = run_docsync(repo, ["debt"])
    assert debt.returncode == 0
    assert "debt: 1" in debt.stdout
    assert "refactor(ufw): internals" in debt.stdout  # коммит виден аудиту


def test_debt_ignores_docs_only_trailer(tmp_path: Path) -> None:
    """Трейлер `Docs: none` в docs-only коммите — не долг: пропускать было нечего."""
    repo = make_repo(tmp_path)
    stage(repo, "README.md", MINI_README + " правка\n")
    msg = commit_msg_file(tmp_path, "docs: tweak\n\nDocs: none — только доки\n")
    git_cmd(repo, ["commit", "-q", "-F", str(msg)])
    debt = run_docsync(repo, ["debt"])
    assert debt.returncode == 0
    assert "пусто" in debt.stdout, debt.stdout


def test_escape_fictional_debt_blocked(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "x\n\nDocs: none — причина (TECHDEBT P99)\n")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 1
    assert "P99" in proc.stdout


# ---------------------------------------------------------------------------
# §12.1: staged-семантика (merge, JSON, no origin/main)
# ---------------------------------------------------------------------------

def test_merge_commit_skipped(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "Merge branch 'feature/x' into main\n")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 0
    assert "merge" in proc.stdout.lower()


def test_check_json_contract(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "feat(x)")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg), "--json"])
    payload = json.loads(proc.stdout)
    assert set(payload) == {"status", "changed", "required", "missing", "warnings", "checks"}
    assert payload["status"] == "fail"
    assert payload["changed"] == ["src/system/ufw.py"]
    assert set(payload["missing"]) == {"README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"}
    # стабильность схемы: второй прогон даёт ту же структуру
    again = json.loads(run_docsync(repo, ["check", "--staged", "--message", str(msg), "--json"]).stdout)
    assert set(again) == set(payload)


def test_check_range_no_origin_warning_skip(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    proc = run_docsync(repo, ["check", "--range", "origin/main..HEAD", "--json"])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert any("origin/main" in w for w in payload["warnings"])


def test_check_range_catches_undoced_commit(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/system/ufw.py", "# ufw\n")
    git_cmd(repo, ["add", "src/system/ufw.py"])
    git_cmd(repo, ["commit", "-q", "-m", "feat(ufw): no docs"])
    proc = run_docsync(repo, ["check", "--range", "HEAD~1..HEAD", "--json"])
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any("не хватает доков" in d for c in payload["checks"] for d in c["details"])


def test_check_range_escapes_allowed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/system/ufw.py", "# ufw\n")
    git_cmd(repo, ["add", "src/system/ufw.py"])
    git_cmd(repo, ["commit", "-q", "-m", "refactor\n\nDocs: none — т hopping (TECHDEBT P4)"])
    proc = run_docsync(repo, ["check", "--range", "HEAD~1..HEAD", "--json"])
    assert proc.returncode == 0


# ---------------------------------------------------------------------------
# §12.2 сценарии WP-2: audit
# ---------------------------------------------------------------------------

def test_audit_baseline_green(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    proc = run_docsync(repo, ["audit", "--json"])
    payload = json.loads(proc.stdout)
    assert payload["status"] in ("ok", "warn"), proc.stdout
    assert all(c["status"] != "fail" for c in payload["checks"])


def test_scenario_3_new_unit_undocumented(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "systemd/vds-foo.service.tpl", "[Unit]\nDescription=x\n")
    git_cmd(repo, ["commit", "-q", "-m", "feat: unit"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "vds-foo.service.tpl" in proc.stdout


def test_scenario_7_new_adr_range_stale(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "AGENTS.md", MINI_AGENTS + "\nДиапазон ADR-001…001.\n")
    write(repo, "docs/adr/ADR-001-x.md", "# ADR-001\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: adr"])
    write(repo, "docs/adr/ADR-002-y.md", "# ADR-002\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: adr2"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "ADR-002" in proc.stdout


def test_adr_phantom_mention_fails(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "AGENTS.md", MINI_AGENTS + "\nСм. ADR-009.\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: adr ref"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "ADR-009" in proc.stdout


def test_scenario_8_new_agent_not_in_team(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, ".zcode/agents/vds-foo.md", "# foo\n")
    git_cmd(repo, ["commit", "-q", "-m", "feat: agent"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "vds-foo" in proc.stdout


def test_scenario_9_version_mismatch(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "pyproject.toml", '[project]\nname = "vds-cli"\nversion = "2.0.0"\n')
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "chore: bump"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "2.0.0" in proc.stdout


def test_audit_zero_commands_exit_2(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/main.py", "import typer\napp = typer.Typer()\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "refactor: empty cli"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 2
    assert "0 leaf-команд" in proc.stdout + proc.stderr


def test_audit_legacy_allowlist_passes(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/main.py", MINI_MAIN_PY.replace("name=\"gateway\"", "name=\"zerotier\""))
    write(repo, "README.md", "# vds\n\nВерсия 1.0.0. Команда `vds sysinfo`.\n")
    write(repo, "AGENTS.md", "# AGENTS\n\nВерсия 1.0.0.\n")
    reg = dict(MINI_REGISTRY)
    reg["reverse"] = dict(MINI_REGISTRY["reverse"])
    reg["reverse"]["legacy_commands_allowlist"] = ["vds zerotier healthcheck"]
    write(repo, "docs/doc-sync.json", json.dumps(reg))
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "chore: allowlist"])
    proc = run_docsync(repo, ["audit", "--json"])
    payload = json.loads(proc.stdout)
    assert all("недокументированная" not in d for c in payload["checks"] for d in c["details"])


def test_audit_banned_count_in_living_fails(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "README.md", MINI_README + "\nПрогон: 843 passed\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: count"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "843 passed" in proc.stdout


def test_audit_broken_link_fails(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "README.md", MINI_README + "\nСм. [деплой](docs/DEPLOY-missing.md).\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: link"])
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 1
    assert "DEPLOY-missing.md" in proc.stdout


# ---------------------------------------------------------------------------
# §12.1: freshness (подмена дат коммитов)
# ---------------------------------------------------------------------------

def test_freshness_status_stale_warns(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, commit_date=OLD_DATE)
    proc = run_docsync(repo, ["audit", "--json"])
    payload = json.loads(proc.stdout)
    # статус стар и старше последнего feat — warnings, но не fail
    assert any("STATUS" in w for w in payload["warnings"])
    assert all(c["status"] != "fail" for c in payload["checks"])


def test_freshness_source_lag_warn_then_strict_fail(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, commit_date=OLD_DATE)
    # источник (ufw.py) новее living-дока SERVER-BASELINE
    write(repo, "src/system/ufw.py", "# ufw v2\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "refactor(ufw): v2"])
    soft = run_docsync(repo, ["audit", "--json"])
    payload = json.loads(soft.stdout)
    assert soft.returncode == 0
    assert any("SERVER-BASELINE" in w and "source_lag" in w for w in payload["warnings"])
    strict = run_docsync(repo, ["audit", "--strict"])
    assert strict.returncode == 1
    assert "source_lag" in strict.stdout


def test_freshness_synced_no_lag(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/system/ufw.py", "# ufw v2\n")
    write(repo, "docs/SERVER-BASELINE.md", MINI_BASELINE + " v2\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "feat(ufw): v2 + docs"])
    proc = run_docsync(repo, ["audit", "--strict"])
    assert proc.returncode == 0, proc.stdout


# ---------------------------------------------------------------------------
# §12.1: производительность + debt --since
# ---------------------------------------------------------------------------

def test_perf_check_staged_under_300ms(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    stage(repo, "README.md", MINI_README + " p\n")
    t0 = time.monotonic()
    proc = run_docsync(repo, ["check", "--staged"])
    elapsed = time.monotonic() - t0
    assert proc.returncode == 0
    assert elapsed < 0.300 + 0.250  # бюджет + запас на холодный старт интерпретатора


def test_perf_audit_under_2s() -> None:
    t0 = time.monotonic()
    proc = run_docsync(REPO, ["audit"])
    elapsed = time.monotonic() - t0
    # живой репо в дрейфе (до WP-3) — exit 1 допустим, важен бюджет
    assert proc.returncode in (0, 1)
    assert elapsed < 2.0


def test_debt_since_filters_old(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    write(repo, "src/system/ufw.py", "# ufw\n")
    git_cmd(repo, ["add", "src/system/ufw.py"])
    old = "2026-10-01T12:00:00"
    git_cmd(repo, ["commit", "-q", "-m", "refactor\n\nDocs: none — старое (TECHDEBT P4)"],
            {"GIT_COMMITTER_DATE": old, "GIT_AUTHOR_DATE": old})
    fresh = run_docsync(repo, ["debt"])
    assert fresh.returncode == 0 and "1" in fresh.stdout
    window = run_docsync(repo, ["debt", "--since", "1d"])
    assert window.returncode == 0
    assert "пусто" in window.stdout


def test_debt_bad_since_exit_2(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    proc = run_docsync(repo, ["debt", "--since", "bogus"])
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

def test_explain_known_and_unknown_path(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    known = run_docsync(repo, ["explain", "src/system/ufw.py"])
    assert known.returncode == 0
    assert "rule ufw" in known.stdout and "README.md" in known.stdout
    unknown = run_docsync(repo, ["explain", "src/core/logger.py"])
    assert unknown.returncode == 0
    assert "не требуется" in unknown.stdout


# ---------------------------------------------------------------------------
# WP-4: режим mode=warn | block (SPEC §11)
# ---------------------------------------------------------------------------

def set_mode(repo: Path, mode: str) -> None:
    reg = dict(MINI_REGISTRY)
    reg["mode"] = mode
    write(repo, "docs/doc-sync.json", json.dumps(reg, indent=2))
    git_cmd(repo, ["add", "docs/doc-sync.json"])
    dirty = git_cmd(repo, ["status", "--porcelain", "--untracked-files=no"]).strip()
    if dirty:  # mode совпадает с текущим — коммитить нечего
        git_cmd(repo, ["commit", "-q", "-m", "chore: mode"])


def test_mode_warn_check_staged_exits_zero(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    set_mode(repo, "warn")
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "feat(ufw): new profile")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    # нарушения видны (missing печатаются), но не блокируют
    assert proc.returncode == 0, proc.stdout
    assert "missing" in proc.stdout and "README.md" in proc.stdout
    assert "warn-mode" in proc.stdout


def test_mode_warn_json_status_fail_exit_zero(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    set_mode(repo, "warn")
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "feat(ufw): new profile")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg), "--json"])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    # JSON-контракт не меняется: status отражает реальность, exit — политику
    assert payload["status"] == "fail"
    assert set(payload) == {"status", "changed", "required", "missing", "warnings", "checks"}


def test_mode_block_check_staged_exits_one(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    set_mode(repo, "block")
    stage(repo, "src/system/ufw.py", "# ufw\n")
    msg = commit_msg_file(tmp_path, "feat(ufw): new profile")
    proc = run_docsync(repo, ["check", "--staged", "--message", str(msg)])
    assert proc.returncode == 1


def test_mode_warn_audit_suppressed_but_strict_blocks(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    set_mode(repo, "warn")
    # детерминированное нарушение audit: запрещённый счётчик в living-доке
    write(repo, "README.md", MINI_README + "\nПрогон: 843 passed\n")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "docs: count"])
    soft = run_docsync(repo, ["audit"])
    assert soft.returncode == 0
    assert "843 passed" in soft.stdout and "warn-mode" in soft.stdout
    strict = run_docsync(repo, ["audit", "--strict"])
    assert strict.returncode == 1
    assert "843 passed" in strict.stdout


def test_mode_invalid_exit_2(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    set_mode(repo, "maybe")
    proc = run_docsync(repo, ["audit"])
    assert proc.returncode == 2
    assert "mode" in proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# §12.2 сценарий 6 (WP-4): --no-verify коммит без доков → pre-push fail
# ---------------------------------------------------------------------------

def test_scenario_6_no_verify_caught_by_pre_push(tmp_path: Path) -> None:
    import shutil

    repo = make_repo(tmp_path)  # mode=block
    # настоящие хуки из репозитория
    (repo / ".githooks").mkdir()
    for hook in ("commit-msg", "pre-push"):
        shutil.copy2(REPO / ".githooks" / hook, repo / ".githooks" / hook)
        (repo / ".githooks" / hook).chmod(0o755)
    (repo / "tools").mkdir(exist_ok=True)
    shutil.copy2(DOCSYNC, repo / "tools" / "docsync.py")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "chore: hooks"])
    git_cmd(repo, ["config", "core.hooksPath", ".githooks"])

    # локальный «origin» (bare), чтобы origin/main существовал
    origin = tmp_path / "origin.git"
    git_cmd(tmp_path, ["init", "-q", "--bare", str(origin)])
    git_cmd(repo, ["remote", "add", "origin", str(origin)])
    git_cmd(repo, ["push", "-q", "origin", "HEAD:refs/heads/main"])
    git_cmd(repo, ["fetch", "-q", "origin"])
    branch = git_cmd(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()

    # (a) честный коммит без доков блокируется commit-msg
    stage(repo, "src/system/ufw.py", "# ufw\n")
    blocked = subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "feat(ufw): no docs"],
        capture_output=True, text=True,
    )
    assert blocked.returncode != 0
    assert "docsync" in (blocked.stdout + blocked.stderr)
    assert "missing" in (blocked.stdout + blocked.stderr)

    # (b) тот же коммит с --no-verify проходит, но push ловит pre-push
    slipped = subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "--no-verify", "-m", "feat(ufw): no docs"],
        capture_output=True, text=True,
    )
    assert slipped.returncode == 0
    push = subprocess.run(
        ["git", "-C", str(repo), "push", "origin", f"{branch}:refs/heads/main"],
        capture_output=True, text=True,
    )
    assert push.returncode != 0
    combined = push.stdout + push.stderr
    assert "docsync" in combined and "не хватает доков" in combined


def test_scenario_6_warn_mode_push_not_blocked(tmp_path: Path) -> None:
    """В mode=warn тот же --no-verify путь: нарушения печатаются, push проходит."""
    import shutil

    repo = make_repo(tmp_path)
    set_mode(repo, "warn")
    (repo / ".githooks").mkdir()
    for hook in ("commit-msg", "pre-push"):
        shutil.copy2(REPO / ".githooks" / hook, repo / ".githooks" / hook)
        (repo / ".githooks" / hook).chmod(0o755)
    (repo / "tools").mkdir(exist_ok=True)
    shutil.copy2(DOCSYNC, repo / "tools" / "docsync.py")
    git_cmd(repo, ["add", "-A"])
    git_cmd(repo, ["commit", "-q", "-m", "chore: hooks"])
    git_cmd(repo, ["config", "core.hooksPath", ".githooks"])

    origin = tmp_path / "origin.git"
    git_cmd(tmp_path, ["init", "-q", "--bare", str(origin)])
    git_cmd(repo, ["remote", "add", "origin", str(origin)])
    git_cmd(repo, ["push", "-q", "origin", "HEAD:refs/heads/main"])
    git_cmd(repo, ["fetch", "-q", "origin"])

    stage(repo, "src/system/ufw.py", "# ufw\n")
    git_cmd(repo, ["commit", "-q", "-m", "feat(ufw): no docs"])  # commit-msg: warn → exit 0
    push = subprocess.run(
        ["git", "-C", str(repo), "push", "origin", "HEAD:refs/heads/main"],
        capture_output=True, text=True,
    )
    assert push.returncode == 0, push.stdout + push.stderr
    assert "warn-mode" in push.stdout + push.stderr
