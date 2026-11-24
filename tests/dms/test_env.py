"""Тесты схемы /etc/vds/dms.env: парсинг, маска URL, 0600 (SPEC §5)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from src.core.secrets import write_secret_atomic
from src.dms.env import (
    SECRET_MASK,
    DmsConfig,
    config_warnings,
    load_config,
    mask_url,
    render_env,
)

# Фикстура с зарезервированным префиксом (AGENTS §6: детекторы секретов).
FIXTURE_URL = "https://hc-ping.com/FIXTURE_PW_DMS_URL"


def _write_env(tmp_path: Path, body: str) -> str:
    path = tmp_path / "dms.env"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_load_config_parses_keys(tmp_path):
    path = _write_env(
        tmp_path,
        f"DMS_PING_URL={FIXTURE_URL}\nDMS_ROLE=exit\nDMS_EXIT_HOST=exit.example.test\n",
    )
    cfg = load_config(path)
    assert cfg.ping_url == FIXTURE_URL
    assert cfg.role == "exit"
    assert cfg.exit_host == "exit.example.test"


def test_load_config_missing_file_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "absent.env"))
    assert cfg == DmsConfig()


def test_role_normalized_and_invalid_empty(tmp_path):
    assert load_config(_write_env(tmp_path, "DMS_ROLE=EXIT\n")).role == "exit"
    assert load_config(_write_env(tmp_path, "DMS_ROLE=banana\n")).role == ""


def test_mask_url():
    assert mask_url(DmsConfig(ping_url=FIXTURE_URL)) == SECRET_MASK
    assert mask_url(DmsConfig()) == ""


def test_render_env_masks_url():
    cfg = DmsConfig(ping_url=FIXTURE_URL, role="relay")
    masked = render_env(cfg, with_secrets=False)
    assert FIXTURE_URL not in masked
    assert SECRET_MASK in masked
    full = render_env(cfg, with_secrets=True)
    assert FIXTURE_URL in full


def test_config_warnings_on_empty_config():
    warnings = config_warnings(DmsConfig())
    assert any("DMS_PING_URL" in w for w in warnings)
    assert any("DMS_ROLE" in w for w in warnings)


def test_config_warnings_clean_when_configured():
    assert config_warnings(DmsConfig(ping_url=FIXTURE_URL, role="exit")) == []


def test_write_secret_atomic_mode_0600(tmp_path):
    path = tmp_path / "dms.env"
    assert write_secret_atomic(str(path), render_env(DmsConfig(role="exit"), with_secrets=False))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
