#!/usr/bin/env python3
"""docsync — проверка синхронизации живой документации с кодом (SPEC-20261116-doc-sync).

Dev-инструмент, не часть `vds` CLI. Только stdlib (json/ast/pathlib/re/subprocess/
argparse/fnmatch), без сети, root, Docker и импорта кода проекта (AST-парсинг).

Команды:
    check --staged [--message FILE] [--json]   commit-msg семантика (WP-1)
    check --range A..B [--json]                синхро-история диапазона
    audit [--strict] [--range A..B] [--json]   reverse-инварианты + ссылки + свежесть
    explain <path>                             какие доки требует путь
    debt [--since Nd]                          список коммитов с «Docs: none»

Exit codes: 0 — ok (warnings допустимы); 1 — нарушения; 2 — ошибка конфига/инструмента/git.

Режим `mode` в реестре (SPEC §11): `warn` — нарушения печатаются, но check/audit
выходят 0 (хуки не блокируют); `block` — честный exit 1. `audit --strict`
(G4/G6) блокирует всегда, независимо от mode. JSON-payload при этом не меняется:
status отражает реальность, exit-код — политику.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

TAG = "[docsync]"

BANNED_COUNT_RE = re.compile(r"\d+\s+(?:passed|тестов|теста)\b")
DOCSYNC_IGNORE = "<!-- docsync:ignore -->"
ESCAPE_LINE_RE = re.compile(r"^Docs:\s*none\s*[—-]\s*(.+?)\s*\(TECHDEBT\s+P(\d+)\)\s*$", re.M)
TECHDEBT_ID_RE = re.compile(r"^##\s+P(\d+)", re.M)
PYPROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
ADR_RANGE_RE = re.compile(r"ADR-001\s*(?:…|\.\.|–|—|-)\s*(\d+)")


class DocsyncError(Exception):
    """Ошибка конфигурации/инструмента/git — exit 2."""


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------

def git(repo: Path, args: list[str], check: bool = True) -> str:
    """git-вызов списком аргументов, без shell=True (AGENTS §5.2)."""
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args, capture_output=True, text=True
    )
    if check and proc.returncode != 0:
        raise DocsyncError(f"git {' '.join(args)}: {proc.stderr.strip() or proc.returncode}")
    return proc.stdout


def git_ok(repo: Path, args: list[str]) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args, capture_output=True, text=True
    )
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

class Registry:
    """Загруженный docs/doc-sync.json (схема v1, SPEC §5)."""

    def __init__(self, data: dict, repo: Path) -> None:
        if not isinstance(data, dict) or data.get("version") != 1:
            raise DocsyncError("doc-sync.json: ожидается схема version 1")
        try:
            self.classes: dict[str, list[str]] = data["classes"]
            self.rules: list[dict] = data["rules"]
            self.reverse: dict = data["reverse"]
            self.freshness: dict = data["freshness"]
            self.escape: dict = data["escape"]
        except KeyError as exc:
            raise DocsyncError(f"doc-sync.json: отсутствует секция {exc}") from exc
        mode = data.get("mode", "warn")
        if mode not in ("warn", "block"):
            raise DocsyncError(f"doc-sync.json: mode должен быть 'warn' или 'block', получено: {mode!r}")
        self.mode: str = mode
        self.repo = repo

    @classmethod
    def load(cls, repo: Path) -> "Registry":
        path = repo / "docs" / "doc-sync.json"
        if not path.is_file():
            raise DocsyncError(f"реестр не найден: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise DocsyncError(f"doc-sync.json: некорректный JSON: {exc}") from exc
        return cls(data, repo)

    # -- правила ------------------------------------------------------------

    def rules_for(self, changed: list[str]) -> list[dict]:
        """Правила, сработавшие хотя бы по одному файлу из changed."""
        return [r for r in self.rules if any(match_path(f, g) for f in changed for g in r["match"])]

    def class_of(self, path: str) -> Optional[str]:
        for cls, patterns in self.classes.items():
            if any(match_path(path, p) for p in patterns):
                return cls
        return None

    def living_files(self) -> list[str]:
        """Существующие living-доки (по реестру)."""
        return [p for p in self.classes.get("living", []) if (self.repo / p).is_file()]

    def status_files(self) -> list[str]:
        return [p for p in self.classes.get("status", []) if (self.repo / p).is_file()]

    def sync_docs(self) -> list[str]:
        """Все .md, подлежащие проверке ссылок: living+status+adr+snapshot."""
        out: list[str] = []
        for cls in ("living", "status", "adr", "snapshot"):
            out.extend(self.classes.get(cls, []))
        return [p for p in out if (self.repo / p).is_file()]


def match_path(path: str, pattern: str) -> bool:
    """Glob-матчинг с нормализацией разделителей (fnmatch: `*`/`**`跨界)."""
    return fnmatch.fnmatch(path.replace("\\", "/"), pattern.replace("\\", "/"))


# ---------------------------------------------------------------------------
# escape-трейлер
# ---------------------------------------------------------------------------

def parse_escape(message: str, techdebt_ids: set[int]) -> tuple[bool, Optional[str]]:
    """Валидация `Docs: none — причина (TECHDEBT Pxx)`.

    Returns:
        (valid, reason): valid=True — обход легален; reason — текст причины
        (для вывода/debt). Escape-строка есть, но невалидна → valid=False,
        reason описывает проблему.
    """
    m = ESCAPE_LINE_RE.search(message)
    if m is None:
        if re.search(r"^Docs:\s*none", message, re.M):
            return False, "escape без причины и/или без ссылки (TECHDEBT Pxx)"
        return False, None
    pid = int(m.group(2))
    if pid not in techdebt_ids:
        return False, f"TECHDEBT P{pid} не существует (фиктивная ссылка на долг)"
    return True, m.group(1)


def load_techdebt_ids(repo: Path) -> set[int]:
    path = repo / "TECHDEBT.md"
    if not path.is_file():
        return set()
    return {int(m) for m in TECHDEBT_ID_RE.findall(path.read_text(encoding="utf-8"))}


# ---------------------------------------------------------------------------
# staged / range sync-проверка (WP-1)
# ---------------------------------------------------------------------------

def staged_files(repo: Path) -> list[str]:
    out = git(repo, ["diff", "--cached", "--name-only"])
    return [l for l in out.splitlines() if l.strip()]


def merge_in_progress(repo: Path, message: str) -> bool:
    first = next((l for l in message.splitlines() if l.strip()), "")
    if first.startswith("Merge "):
        return True
    return any(
        (repo / ".git" / d).exists()
        for d in ("MERGE_HEAD", "rebase-merge", "rebase-apply")
    )


def compute_sync(registry: Registry, changed: list[str]) -> tuple[list[str], list[str], list[dict]]:
    """union require / missing / consider-warnings по сработавшим правилам."""
    rules = registry.rules_for(changed)
    required: list[str] = []
    consider: list[str] = []
    for r in rules:
        for d in r["require"]:
            if d not in required:
                required.append(d)
        for d in r.get("consider", []):
            if d not in consider:
                consider.append(d)
    missing = [d for d in required if d not in changed]
    warnings = [d for d in consider if d not in changed]
    return required, missing, warnings


def cmd_check_staged(repo: Path, registry: Registry, message_file: Optional[Path], as_json: bool) -> int:
    message = message_file.read_text(encoding="utf-8") if message_file else ""
    changed = staged_files(repo)

    if merge_in_progress(repo, message):
        return finish(as_json, "ok", changed, [], [], ["merge/rebase — sync-проверка пропущена (ловит audit)"], [])

    required, missing, warnings = compute_sync(registry, changed)

    techdebt_ids = load_techdebt_ids(repo)
    escape_valid, escape_reason = parse_escape(message, techdebt_ids)
    escape_present = re.search(r"^Docs:\s*none", message, re.M) is not None

    checks: list[dict] = []
    if missing and escape_valid:
        warnings = warnings + [f"Docs: none — {escape_reason}; пропущены: {', '.join(missing)}"]
        missing = []
    elif missing and escape_present and not escape_valid:
        checks.append({"check": "escape", "status": "fail", "details": [escape_reason or "некорректный escape"]})
        return finish(as_json, "fail", changed, required, missing, warnings, checks,
                      warn_mode=registry.mode == "warn")

    # quick_checks по staged-докам: ссылки + запрещённые счётчики тестов
    checks.extend(quick_checks(repo, registry, [f for f in changed if f.endswith(".md")]))

    has_fail = missing or any(c["status"] == "fail" for c in checks)
    return finish(
        as_json,
        "fail" if has_fail else ("warn" if warnings else "ok"),
        changed, required, missing, warnings, checks,
        warn_mode=registry.mode == "warn",
    )


def cmd_check_range_impl(repo: Path, registry: Registry, rng: str, as_json: bool) -> int:
    base = rng.split("..")[0]
    if base.startswith("origin/") and not git_ok(repo, ["rev-parse", "--verify", base]):
        return finish(as_json, "warn", [], [], [],
                      [f"{base} не найден (fresh clone / офлайн) — range-проверка пропущена"], [])
    shas = [s for s in git(repo, ["rev-list", "--no-merges", "--reverse", rng]).splitlines() if s.strip()]
    errors: list[str] = []
    warnings: list[str] = []
    techdebt_ids = load_techdebt_ids(repo)
    for sha in shas:
        files = [l for l in git(repo, ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha]).splitlines() if l.strip()]
        _, missing, _ = compute_sync(registry, files)
        if not missing:
            continue
        msg = git(repo, ["log", "-n1", "--format=%B", sha])
        valid, _ = parse_escape(msg, techdebt_ids)
        if valid:
            warnings.append(f"{sha[:8]}: Docs: none (легальный обход)")
        else:
            errors.append(f"{sha[:8]}: не хватает доков: {', '.join(missing)}")
    checks = [{"check": "range-sync", "status": "fail" if errors else "pass", "details": errors}]
    return finish(as_json, "fail" if errors else ("warn" if warnings else "ok"),
                  [], [], [], warnings, checks, warn_mode=registry.mode == "warn")


# ---------------------------------------------------------------------------
# quick checks: ссылки + запрещённые счётчики
# ---------------------------------------------------------------------------

def check_doc_links(repo: Path, doc: str) -> list[str]:
    """Относительные markdown-ссылки должны разрешаться в существующий файл."""
    path = repo / doc
    if not path.is_file():
        return [f"{doc}: файл отсутствует"]
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    for m in MD_LINK_RE.finditer(text):
        target = m.group(1)
        if target.startswith(("http://", "https://", "#", "mailto:", "irc://")):
            continue
        file_part = target.split("#", 1)[0]
        if not file_part:
            continue
        resolved = Path(repo / doc).parent / file_part
        if not resolved.exists():
            problems.append(f"{doc}: битая ссылка -> {target}")
    return problems


def check_banned_counts(repo: Path, doc: str) -> list[str]:
    """Hardcoded-счётчики тестов в living/status-доках запрещены (кроме docsync:ignore)."""
    path = repo / doc
    if not path.is_file():
        return []
    problems: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if DOCSYNC_IGNORE in line:
            continue
        m = BANNED_COUNT_RE.search(line)
        if m:
            problems.append(f"{doc}: запрещённый счётчик тестов '{m.group(0)}'")
    return problems


def quick_checks(repo: Path, registry: Registry, docs: list[str]) -> list[dict]:
    checks: list[dict] = []
    if registry.reverse.get("links", True):
        details: list[str] = []
        for d in docs:
            details.extend(check_doc_links(repo, d))
        checks.append({"check": "links", "status": "fail" if details else "pass", "details": details})
    if registry.reverse.get("banned_test_counts", True):
        details = []
        for d in docs:
            if registry.class_of(d) in ("living", "status"):
                details.extend(check_banned_counts(repo, d))
        checks.append({"check": "banned-test-counts", "status": "fail" if details else "pass", "details": details})
    return checks


# ---------------------------------------------------------------------------
# reverse-инварианты (WP-2)
# ---------------------------------------------------------------------------

def extract_leaf_commands(main_py: Path) -> list[str]:
    """AST-извлечение leaf-команд из src/main.py (SPEC §7.2).

    - `<var> = typer.Typer(...)` из модуль-уровня Assign;
    - дерево из `<parent>.add_typer(<child>, name=...)` (name по умолчанию =
      имя переменной, `_`→`-`), вложенность любая;
    - leaf = `@<var>.command("name")` на FunctionDef (имя по умолчанию =
      def-имя, `_`→`-`); имя может быть позиционным аргументом декоратора;
    - корневой callback (TUI) исключается; sub-app с
      invoke_without_command=True (в Typer(...) или в @callback) — сам leaf;
    - корень = переменная, ни разу не переданная в add_typer; префикс корня — `vds`.
    """

    def const(kws: list[ast.keyword], arg: str, default=None):
        for k in kws:
            if k.arg == arg and isinstance(k.value, ast.Constant):
                return k.value.value
        return default

    tree = ast.parse(main_py.read_text(encoding="utf-8"))
    typers: dict[str, dict] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "Typer"
                and node.targets
                and isinstance(node.targets[0], ast.Name)
            ):
                typers[node.targets[0].id] = {
                    "iwc": const(node.value.keywords, "invoke_without_command", False) is True
                }
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "callback"
                and isinstance(dec.func.value, ast.Name)
                and const(dec.keywords, "invoke_without_command", False) is True
            ):
                typers.setdefault(dec.func.value.id, {})["iwc"] = True

    children: dict[str, list[tuple[str, str]]] = {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "add_typer"
                and isinstance(call.func.value, ast.Name)
                and call.args
                and isinstance(call.args[0], ast.Name)
            ):
                child = call.args[0].id
                name = const(call.keywords, "name") or child.replace("_", "-")
                children.setdefault(call.func.value.id, []).append((child, name))

    roots = [v for v in typers if not any(v == ch for chs in children.values() for ch, _ in chs)]
    if len(roots) != 1:
        raise DocsyncError(f"ожидался один корневой Typer-приложение, найдено {len(roots)}: {roots}")
    root = roots[0]
    prefix = {root: "vds"}

    def pref(var: str) -> str:
        if var in prefix:
            return prefix[var]
        for parent, chs in children.items():
            for ch, name in chs:
                if ch == var:
                    parent_prefix = pref(parent)
                    prefix[var] = f"{parent_prefix} {name}".strip()
                    return prefix[var]
        return ""

    leaves: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "command"
                and isinstance(dec.func.value, ast.Name)
            ):
                var = dec.func.value.id
                name: Optional[str] = None
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    name = dec.args[0].value
                name = name or const(dec.keywords, "name") or node.name.replace("_", "-")
                leaves.append(" ".join(x for x in (pref(var), str(name)) if x))
    for var, info in typers.items():
        if var != root and info.get("iwc") and pref(var):
            leaves.append(pref(var))
    return sorted(set(leaves))


def read_doc(repo: Path, rel: str) -> str:
    path = repo / rel
    if not path.is_file():
        raise DocsyncError(f"документ из реестра отсутствует: {rel}")
    return path.read_text(encoding="utf-8")


def check_commands(repo: Path, registry: Registry) -> dict:
    main_py = repo / registry.reverse["commands_from"]
    if not main_py.is_file():
        raise DocsyncError(f"commands_from не найден: {main_py}")
    leaves = extract_leaf_commands(main_py)
    if not leaves:
        raise DocsyncError(
            f"из {registry.reverse['commands_from']} извлечено 0 leaf-команд "
            "(команды вынесены в другой модуль?) — audit прерван"
        )
    allowlist = set(registry.reverse.get("legacy_commands_allowlist", []))
    docs_text = "\n".join(read_doc(repo, d) for d in registry.reverse["commands_docs"])
    details = [
        f"недокументированная команда: '{c}' (не найдена в {', '.join(registry.reverse['commands_docs'])})"
        for c in leaves
        if c not in allowlist and c not in docs_text
    ]
    return {
        "check": "reverse-commands",
        "status": "fail" if details else "pass",
        "details": details,
        "meta": {"leaf_commands": len(leaves)},
    }


def check_units(repo: Path, registry: Registry) -> dict:
    tpl_files = sorted((repo / "systemd").glob("*.tpl")) if (repo / "systemd").is_dir() else []
    allowlist = set(registry.reverse.get("generated_units_allowlist", []))
    docs_text = "\n".join(read_doc(repo, d) for d in registry.reverse["units_docs"])
    details = [
        f"юнит {p.name} не упомянут в {', '.join(registry.reverse['units_docs'])}"
        for p in tpl_files
        if p.name not in allowlist and p.name not in docs_text
    ]
    return {"check": "reverse-units", "status": "fail" if details else "pass", "details": details}


def check_adr(repo: Path, registry: Registry) -> dict:
    details: list[str] = []
    adr_dir = repo / "docs" / "adr"
    existing: set[int] = set()
    if adr_dir.is_dir():
        for p in adr_dir.glob("ADR-*.md"):
            m = re.match(r"ADR-(\d{3})", p.name)
            if m:
                existing.add(int(m.group(1)))
    max_actual = max(existing) if existing else 0
    for doc in registry.living_files():
        text = (repo / doc).read_text(encoding="utf-8")
        for m in re.finditer(r"ADR-(\d{3})", text):
            if int(m.group(1)) not in existing:
                details.append(f"{doc}: упоминается {m.group(0)}, но файла нет в docs/adr/")
    for doc in registry.reverse.get("adr_docs", []):
        text = read_doc(repo, doc)
        m = ADR_RANGE_RE.search(text)
        if m and int(m.group(1)) != max_actual:
            details.append(
                f"{doc}: диапазон ADR-001…{m.group(1)}, фактический максимум — "
                f"ADR-{max_actual:03d}"
            )
    return {"check": "reverse-adr", "status": "fail" if details else "pass", "details": details}


def check_agents(repo: Path, registry: Registry) -> dict:
    agents_dir = repo / ".zcode" / "agents"
    agents = sorted(agents_dir.glob("vds-*.md")) if agents_dir.is_dir() else []
    team = read_doc(repo, "docs/TEAM.md")
    details = [
        f"агент {p.stem} не упомянут в docs/TEAM.md" for p in agents if p.stem not in team
    ]
    return {"check": "reverse-agents", "status": "fail" if details else "pass", "details": details}


def check_version(repo: Path, registry: Registry) -> dict:
    pyproject = repo / "pyproject.toml"
    if not pyproject.is_file():
        return {"check": "reverse-version", "status": "pass", "details": []}
    m = PYPROJECT_VERSION_RE.search(pyproject.read_text(encoding="utf-8"))
    if not m:
        return {
            "check": "reverse-version",
            "status": "fail",
            "details": ["pyproject.toml: строка version = \"...\" не найдена"],
        }
    version = m.group(1)
    details = [
        f"{doc}: версия {version} из pyproject.toml не найдена"
        for doc in registry.reverse.get("version_docs", [])
        if version not in read_doc(repo, doc)
    ]
    return {"check": "reverse-version", "status": "fail" if details else "pass", "details": details}


# ---------------------------------------------------------------------------
# freshness (WP-2)
# ---------------------------------------------------------------------------

def last_commit_time(repo: Path, pathspec: str) -> Optional[int]:
    out = git(repo, ["log", "-n1", "--format=%ct", "--", pathspec], check=False)
    out = out.strip()
    return int(out) if out.isdigit() else None


def check_freshness(repo: Path, registry: Registry, strict: bool) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    checks: list[dict] = []
    now = int(time.time())
    status_days = int(registry.freshness.get("status_days", 7))

    status_details: list[str] = []
    # последний feat-коммит по всему репо (по subject)
    out = git(repo, ["log", "-n1", "--format=%ct", "--grep=^feat"], check=False).strip()
    feat_time = int(out) if out.isdigit() else None
    for doc in registry.status_files():
        t = last_commit_time(repo, doc)
        if t is None:
            continue
        age_days = (now - t) / 86400
        if age_days > status_days:
            status_details.append(f"{doc}: не обновлялся {age_days:.0f} дн (порог {status_days})")
        if feat_time is not None and t < feat_time:
            status_details.append(f"{doc}: старше последнего feat-коммита")
    checks.append({"check": "freshness-status", "status": "warn" if status_details else "pass",
                   "details": status_details})
    warnings.extend(status_details)

    # source_lag: living-док старше самого свежего mapped-источника
    lag_details: list[str] = []
    for doc in registry.living_files():
        doc_t = last_commit_time(repo, doc)
        if doc_t is None:
            continue
        mapped = [g for r in registry.rules if doc in r["require"] for g in r["match"]]
        src_t = max((t for t in (last_commit_time(repo, g) for g in mapped) if t), default=None)
        if src_t is not None and src_t > doc_t:
            lag_details.append(f"{doc}: источник новее документа (source_lag)")
    lag_status = "fail" if (strict and lag_details) else ("warn" if lag_details else "pass")
    checks.append({"check": "freshness-source-lag", "status": lag_status, "details": lag_details})
    warnings.extend(lag_details)
    return checks, warnings


# ---------------------------------------------------------------------------
# audit (WP-2)
# ---------------------------------------------------------------------------

def cmd_audit(repo: Path, registry: Registry, strict: bool, rng: Optional[str], as_json: bool) -> int:
    checks: list[dict] = []
    warnings: list[str] = []

    checks.append(check_commands(repo, registry))
    checks.append(check_units(repo, registry))
    checks.append(check_adr(repo, registry))
    checks.append(check_agents(repo, registry))
    checks.append(check_version(repo, registry))
    checks.extend(quick_checks(repo, registry, registry.sync_docs()))
    fresh_checks, fresh_warnings = check_freshness(repo, registry, strict)
    checks.extend(fresh_checks)
    warnings.extend(fresh_warnings)

    if rng:
        base = rng.split("..")[0]
        if base.startswith("origin/") and not git_ok(repo, ["rev-parse", "--verify", base]):
            warnings.append(f"{base} не найден (fresh clone / офлайн) — range-часть audit пропущена")
        else:
            shas = [s for s in git(repo, ["rev-list", "--no-merges", "--reverse", rng]).splitlines() if s.strip()]
            techdebt_ids = load_techdebt_ids(repo)
            errors: list[str] = []
            for sha in shas:
                files = [l for l in git(repo, ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha]).splitlines() if l.strip()]
                _, missing, _ = compute_sync(registry, files)
                if not missing:
                    continue
                msg = git(repo, ["log", "-n1", "--format=%B", sha])
                valid, _ = parse_escape(msg, techdebt_ids)
                if valid:
                    warnings.append(f"{sha[:8]}: Docs: none (легальный обход)")
                else:
                    errors.append(f"{sha[:8]}: не хватает доков: {', '.join(missing)}")
            checks.append({"check": "range-sync", "status": "fail" if errors else "pass", "details": errors})

    has_fail = any(c["status"] == "fail" for c in checks)
    # audit --strict (G4/G6, SPEC §9) блокирует всегда, даже в mode=warn.
    return finish(as_json, "fail" if has_fail else ("warn" if warnings else "ok"),
                  [], [], [], warnings, checks,
                  warn_mode=(registry.mode == "warn" and not strict))


# ---------------------------------------------------------------------------
# explain / debt
# ---------------------------------------------------------------------------

def cmd_explain(repo: Path, registry: Registry, path: str) -> int:
    path = path.replace("\\", "/")
    rules = [r for r in registry.rules if any(match_path(path, g) for g in r["match"])]
    print(f"{TAG} path: {path} (class: {registry.class_of(path) or 'unregistered'})")
    if not rules:
        print(f"{TAG} ни одно правило не сработало — синхронизация не требуется")
        return EXIT_OK
    for r in rules:
        print(f"{TAG} rule {r['id']} ({r.get('why', '')})")
        print(f"{TAG}   require:   {', '.join(r['require'])}")
        if r.get("consider"):
            print(f"{TAG}   consider:  {', '.join(r['consider'])}")
    return EXIT_OK


def cmd_debt(repo: Path, since: Optional[str], registry: Registry) -> int:
    """Список легальных обходов, которые РЕАЛЬНО пропустили обязательные доки.

    Трейлер `Docs: none` в docs-only коммите ничего не пропускает: `compute_sync`
    для такого набора файлов не находит missing. Такие коммиты в долг не попадают,
    иначе счётчик пухнет фантомами и перестаёт быть сигналом для G6.
    """
    args = ["log", "--format=%H|%ct|%s", "--grep=^Docs:\\s*none", "-i"]
    if since:
        m = re.fullmatch(r"(\d+)d", since)
        if not m:
            raise DocsyncError(f"--since ожидает формат Nd (дней), получено: {since}")
        args.append(f"--since={int(m.group(1))} days ago")
    out = git(repo, args, check=False)
    entries: list[str] = []
    for e in (l for l in out.splitlines() if l.strip()):
        sha = e.split("|", 1)[0]
        # `-m --first-parent`: у merge-коммита diff-tree без них вернул бы пусто
        # и обход в мерже стал бы невидим; first-parent — «что принёс мерж».
        files = [l for l in git(repo, ["diff-tree", "--root", "--no-commit-id",
                                       "--name-only", "-r", "-m", "--first-parent",
                                       sha]).splitlines() if l.strip()]
        _, missing, _ = compute_sync(registry, files)
        if not missing:
            continue
        entries.append(e)
    if not entries:
        print(f"{TAG} debt: пусто — легальных обходов нет")
        return EXIT_OK
    print(f"{TAG} debt: {len(entries)} коммит(ов) с 'Docs: none'")
    for e in entries:
        sha, ct, subject = e.split("|", 2)
        days = (int(time.time()) - int(ct)) // 86400
        print(f"{TAG}   {sha[:8]} ({days} дн назад) {subject}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# вывод / JSON
# ---------------------------------------------------------------------------

def finish(as_json: bool, status: str, changed: list[str], required: list[str],
           missing: list[str], warnings: list[str], checks: list[dict],
           warn_mode: bool = False) -> int:
    payload = {
        "status": status,
        "changed": changed,
        "required": required,
        "missing": missing,
        "warnings": warnings,
        "checks": checks,
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        emit_text(payload)
    if status == "fail":
        if warn_mode:
            # mode=warn (SPEC §11): нарушения видны, но не блокируют хуки.
            if not as_json:
                print(f"{TAG} warn-mode: нарушения не блокируют (mode=warn в docs/doc-sync.json); "
                      "audit --strict блокирует всегда")
            return EXIT_OK
        return EXIT_FAIL
    return EXIT_OK


def emit_text(payload: dict) -> None:
    status = payload["status"]
    if payload["changed"]:
        print(f"{TAG} staged: {', '.join(payload['changed'])}")
    if payload["required"]:
        print(f"{TAG} required: {', '.join(payload['required'])}")
    if payload["missing"]:
        print(f"{TAG} missing: {', '.join(payload['missing'])}")
        print(f"{TAG} hint: python3 tools/docsync.py explain <path> — какие доки требует изменение")
    for c in payload["checks"]:
        if c["status"] != "fail":
            continue
        label = c["check"]
        for d in c["details"]:
            print(f"{TAG} [fail] {label}: {d}")
    for w in payload["warnings"]:
        print(f"{TAG} [warning] {w}")
    if status == "fail":
        n_err = sum(1 for c in payload["checks"] if c["status"] == "fail")
        if payload["missing"]:
            print(f"{TAG} FAIL ({len(payload['missing'])} required doc(s) not staged)")
        else:
            print(f"{TAG} FAIL ({n_err} check(s) failed)")
    elif status == "warn":
        print(f"{TAG} OK (with warnings)")
    else:
        print(f"{TAG} OK")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="docsync", description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=".", help="путь к репозиторию (по умолчанию cwd)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="sync-проверка индекса или диапазона")
    mode = p_check.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--range", dest="range_")
    p_check.add_argument("--message", type=Path, help="файл сообщения коммита (commit-msg)")
    p_check.add_argument("--json", action="store_true")

    p_audit = sub.add_parser("audit", help="reverse-инварианты + ссылки + свежесть")
    p_audit.add_argument("--strict", action="store_true")
    p_audit.add_argument("--range", dest="range_")
    p_audit.add_argument("--json", action="store_true")

    p_explain = sub.add_parser("explain", help="какие доки требует путь")
    p_explain.add_argument("path")

    p_debt = sub.add_parser("debt", help="список коммитов с Docs: none")
    p_debt.add_argument("--since", help="окно в днях, напр. 30d")

    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"{TAG} [error] каталог не найден: {repo}", file=sys.stderr)
        return EXIT_ERROR
    try:
        if args.cmd == "explain":
            return cmd_explain(repo, Registry.load(repo), args.path)
        if args.cmd == "debt":
            return cmd_debt(repo, args.since, Registry.load(repo))
        registry = Registry.load(repo)
        if args.cmd == "check":
            if args.staged:
                return cmd_check_staged(repo, registry, args.message, args.json)
            return cmd_check_range_impl(repo, registry, args.range_, args.json)
        if args.cmd == "audit":
            return cmd_audit(repo, registry, args.strict, args.range_, args.json)
    except DocsyncError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"{TAG} [error] {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
