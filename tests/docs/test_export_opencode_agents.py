"""Тесты `tools/export_opencode_agents.py` (зеркало ролей для OpenCode V2).

Проверяем: парсинг frontmatter, отсутствие фиксации модели, режимы/права
по ролям и — главное — что `.opencode/agents` не отстаёт от `.zcode/agents`.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXPORTER = REPO / "tools" / "export_opencode_agents.py"


def _load_exporter():
    spec = importlib.util.spec_from_file_location("exporter_under_test", EXPORTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ex = _load_exporter()


def test_repo_mirror_is_in_sync() -> None:
    assert ex.check() == [], (
        "расхождение .opencode/agents и .zcode/agents; "
        "запусти python3 tools/export_opencode_agents.py --write"
    )


def test_render_inherits_model_and_keeps_permissions() -> None:
    agents = ex.build_all()
    tester = agents[ex.DST_DIR / "vds-tester.md"]
    assert "model:" not in tester  # модель наследуется от сессии
    assert "mode: subagent" in tester
    assert 'resource: "docs/team/reports/**"' in tester
    assert "GENERATED from .zcode/agents/vds-tester.md" in tester
    assert "# РОЛЬ: Тестировщик" in tester


def test_parse_frontmatter_handles_quotes_and_colons() -> None:
    text = '---\nname: "vds-x"\ndescription: "vds-x: роль — с двоеточием: ок"\n---\n\nТело\n'
    meta, body = ex.parse_frontmatter(text)
    assert meta["name"] == "vds-x"
    assert meta["description"] == "vds-x: роль — с двоеточием: ок"
    assert body == "Тело\n"


def test_unknown_role_requires_explicit_config(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "vds-unknown.md").write_text(
        '---\nname: "vds-unknown"\ndescription: "x"\n---\n\nТело\n', encoding="utf-8"
    )
    with pytest.raises(ex.ExportError, match="ROLE_CONFIG"):
        ex.build_all(src)
