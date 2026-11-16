#!/usr/bin/env python3
"""Экспорт ролей `vds-*` из `.zcode/agents/` в OpenCode V2 (`.opencode/agents/`).

Источник истины — `.zcode/agents/vds-*.md` (там же процесс и модели Zcode).
OpenCode-зеркало — **генерируемые** файлы: модель не фиксируется (наследуется
от сессии), режим и права задаются здесь.

Команды:
    python3 tools/export_opencode_agents.py --write   # пересобрать зеркало
    python3 tools/export_opencode_agents.py --check   # exit 1 при рассинхроне

Формат OpenCode V2: frontmatter `description`/`mode`/`model`/`permissions`,
тело файла — системный промпт роли.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SRC_DIR = REPO / ".zcode" / "agents"
DST_DIR = REPO / ".opencode" / "agents"

GENERATED_NOTE = (
    "<!-- GENERATED from .zcode/agents/{name}.md by "
    "tools/export_opencode_agents.py; edit the source, not this file. -->"
)

# Права: последнее совпавшее правило выигрывает, поэтому широкий deny идёт
# первым, а узкий allow — после него.
_DENY_EDIT = {"action": "edit", "resource": "*", "effect": "deny"}
_ASK_MUTATIONS = [
    {"action": "shell", "resource": "*--apply*", "effect": "ask"},
    {"action": "shell", "resource": "rm *", "effect": "ask"},
    {"action": "shell", "resource": "git push *", "effect": "ask"},
    {"action": "shell", "resource": "systemctl *", "effect": "ask"},
    {"action": "shell", "resource": "ufw *", "effect": "ask"},
    {"action": "shell", "resource": "iptables *", "effect": "ask"},
    {"action": "shell", "resource": "nft *", "effect": "ask"},
]

ROLE_CONFIG: dict[str, dict[str, Any]] = {
    "vds-owner": {
        "mode": "primary",
        "permissions": [
            _DENY_EDIT,
            {"action": "shell", "resource": "*", "effect": "deny"},
            {"action": "shell", "resource": "git status*", "effect": "allow"},
            {"action": "shell", "resource": "git log*", "effect": "allow"},
            {"action": "shell", "resource": "git diff*", "effect": "allow"},
        ],
    },
    "vds-orchestrator": {
        "mode": "primary",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/team/STATUS.md", "effect": "allow"},
            {"action": "edit", "resource": "docs/team/reports/**", "effect": "allow"},
            *_ASK_MUTATIONS,
        ],
    },
    "vds-analyst": {
        "mode": "all",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/team/requirements/**", "effect": "allow"},
            {"action": "edit", "resource": "docs/team/ideas/**", "effect": "allow"},
            *_ASK_MUTATIONS,
        ],
    },
    "vds-architect": {
        "mode": "all",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/team/specs/**", "effect": "allow"},
            {"action": "edit", "resource": "docs/adr/**", "effect": "allow"},
            {"action": "edit", "resource": "docs/GROWTH-POINTS.md", "effect": "allow"},
            *_ASK_MUTATIONS,
        ],
    },
    "vds-coder": {
        "mode": "all",
        "permissions": [*_ASK_MUTATIONS],
    },
    "vds-debugger": {
        "mode": "all",
        "permissions": [*_ASK_MUTATIONS],
    },
    "vds-tester": {
        "mode": "subagent",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/team/reports/**", "effect": "allow"},
            {"action": "shell", "resource": "*--apply*", "effect": "deny"},
            {"action": "shell", "resource": "git push *", "effect": "deny"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
        ],
    },
    "vds-docs": {
        "mode": "all",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/**", "effect": "allow"},
            {"action": "edit", "resource": "README.md", "effect": "allow"},
            {"action": "edit", "resource": "AGENTS.md", "effect": "allow"},
            *_ASK_MUTATIONS,
        ],
    },
    "vds-agent-smith": {
        "mode": "subagent",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": ".zcode/agents/**", "effect": "allow"},
            {"action": "edit", "resource": ".opencode/agents/**", "effect": "allow"},
            {"action": "edit", "resource": "docs/**", "effect": "allow"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
        ],
    },
    "vds-youtube-scout": {
        "mode": "subagent",
        "permissions": [
            _DENY_EDIT,
            {"action": "edit", "resource": "docs/research/**", "effect": "allow"},
            {"action": "subagent", "resource": "*", "effect": "deny"},
        ],
    },
}


class ExportError(RuntimeError):
    """Ошибка формата источника."""


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Разобрать простой YAML-frontmatter `.zcode/agents` (без PyYAML)."""
    if not text.startswith("---\n"):
        raise ExportError("frontmatter должен начинаться с '---'")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ExportError("frontmatter не закрыт '---'")
    meta: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        meta[key.strip()] = value
    body = text[end + len("\n---\n") :].lstrip("\n")
    return meta, body


def render_agent(name: str, meta: dict[str, str], body: str, cfg: dict[str, Any]) -> str:
    """Собрать OpenCode-агент: frontmatter + generated-note + тело роли."""
    description = meta.get("description") or f"vds role: {name}"
    lines = [
        "---",
        f"description: {json.dumps(description, ensure_ascii=False)}",
        f"mode: {cfg['mode']}",
    ]
    permissions = cfg.get("permissions") or []
    if permissions:
        lines.append("permissions:")
        for rule in permissions:
            lines.append(f"  - action: {rule['action']}")
            lines.append(
                f"    resource: {json.dumps(rule['resource'], ensure_ascii=False)}"
            )
            lines.append(f"    effect: {rule['effect']}")
    lines.append("---")
    header = GENERATED_NOTE.format(name=name)
    return "\n".join(lines) + "\n\n" + header + "\n\n" + body.rstrip() + "\n"


def build_all(src_dir: Path = SRC_DIR) -> dict[Path, str]:
    """Сгенерировать ожидаемое содержимое зеркала (путь → текст)."""
    if not src_dir.is_dir():
        raise ExportError(f"каталог источников не найден: {src_dir}")
    result: dict[Path, str] = {}
    for src in sorted(src_dir.glob("vds-*.md")):
        name = src.stem
        cfg = ROLE_CONFIG.get(name)
        if cfg is None:
            raise ExportError(
                f"{src}: роль {name!r} отсутствует в ROLE_CONFIG — добавь режим/права"
            )
        meta, body = parse_frontmatter(src.read_text(encoding="utf-8"))
        result[DST_DIR / f"{name}.md"] = render_agent(name, meta, body, cfg)
    return result


def check(dst_dir: Path = DST_DIR, src_dir: Path = SRC_DIR) -> list[str]:
    """Вернуть список рассинхронов (пусто — зеркало актуально)."""
    problems: list[str] = []
    expected = build_all(src_dir)
    if not dst_dir.is_dir():
        return [f"нет каталога зеркала: {dst_dir}"]
    existing = sorted(p.name for p in dst_dir.glob("vds-*.md"))
    expected_names = sorted(p.name for p in expected)
    for name in expected_names:
        if name not in existing:
            problems.append(f"нет файла: {name}")
    for name in existing:
        if name not in expected_names:
            problems.append(f"лишний файл: {name}")
    for path, content in expected.items():
        if not path.is_file():
            continue
        current = path.read_text(encoding="utf-8")
        if current != content:
            problems.append(f"рассинхрон: {path.relative_to(REPO)}")
    return problems


def write(dst_dir: Path = DST_DIR) -> list[Path]:
    """Записать зеркало; вернуть список изменённых файлов."""
    expected = build_all()
    changed: list[Path] = []
    dst_dir.mkdir(parents=True, exist_ok=True)
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != content:
            path.write_text(content, encoding="utf-8")
            changed.append(path)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="пересобрать зеркало")
    group.add_argument("--check", action="store_true", help="проверить рассинхрон")
    args = parser.parse_args(argv)

    try:
        if args.write:
            changed = write()
            if changed:
                for path in changed:
                    print(f"[write] {path.relative_to(REPO)}")
            else:
                print("[ok] зеркало уже актуально")
            return 0
        problems = check()
        if problems:
            for problem in problems:
                print(f"[fail] {problem}", file=sys.stderr)
            print(
                "пересобери: python3 tools/export_opencode_agents.py --write",
                file=sys.stderr,
            )
            return 1
        print("[ok] .opencode/agents синхронизирован с .zcode/agents")
        return 0
    except ExportError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
