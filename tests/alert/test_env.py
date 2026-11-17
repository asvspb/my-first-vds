"""Тесты схемы `alert.env` (SPEC §3.3/§3.5, §6).

Секреты — только FIXTURE_*-фикстуры (AGENTS §6), значения не печатаются.
"""
from __future__ import annotations

import pytest

from src.alert.env import (
    SECRET_MASK,
    AlertConfig,
    active_channels,
    config_warnings,
    load_config,
    parse_duration,
    render_env,
)

TG_TOKEN = "FIXTURE_TG_BOT_TOKEN"
SMTP_PASS = "FIXTURE_PW_SMTP"
FROM = "alert-test@example.com"
TO = "owner@example.com,second@example.com"


def _cfg(**over) -> AlertConfig:
    base = dict(
        channels=("tg", "smtp"),
        tg_token=TG_TOKEN,
        tg_chat_id="111111111",
        smtp_host="smtp.example.com",
        smtp_port=465,
        smtp_user=FROM,
        smtp_pass=SMTP_PASS,
        smtp_from=FROM,
        smtp_to=("owner@example.com", "second@example.com"),
        smtp_starttls=False,
        site_name="asv2",
        relay_peer="relay",
    )
    base.update(over)
    return AlertConfig(**base)


@pytest.mark.parametrize(
    "text,expected",
    [("30s", 30), ("2m", 120), ("24h", 86400), ("1d", 86400), ("45", 45), (" 5m ", 300)],
)
def test_parse_duration_ok(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "10x", "-5s", "0s", "1.5h", "m"])
def test_parse_duration_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_duration(text)


def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "absent.env"))
    assert cfg.channels == ()
    assert cfg.handshake_threshold_s == 300
    assert cfg.smtp_port == 465
    assert cfg.relay_peer == "relay"
    assert cfg.enabled_checks == ("threat", "relay_pulse", "lockdown")


def test_render_env_roundtrip(tmp_path):
    src = _cfg()
    path = tmp_path / "alert.env"
    path.write_text(render_env(src, with_secrets=True), encoding="utf-8")

    loaded = load_config(str(path))

    assert loaded == src


def test_masked_render_contains_no_secret_values(tmp_path):
    rendered = render_env(_cfg(), with_secrets=False)
    assert TG_TOKEN not in rendered
    assert SMTP_PASS not in rendered
    assert SECRET_MASK in rendered
    assert "TG_CHAT_ID=111111111" in rendered


def test_masked_render_hides_secrets_after_roundtrip(tmp_path):
    """Маска — единственный путь показа конфига: после записи в файл секретов нет."""
    path = tmp_path / "alert.env"
    path.write_text(render_env(_cfg(), with_secrets=False), encoding="utf-8")
    loaded = load_config(str(path))
    assert loaded.tg_token == SECRET_MASK
    assert loaded.smtp_pass == SECRET_MASK
    # и в самом файле значений нет
    text = path.read_text(encoding="utf-8")
    assert TG_TOKEN not in text and SMTP_PASS not in text


def test_active_channels_by_configured_pairs():
    assert active_channels(_cfg()) == ("tg", "smtp")
    assert active_channels(_cfg(tg_chat_id="")) == ("smtp",)
    assert active_channels(_cfg(smtp_to=())) == ("tg",)
    assert active_channels(_cfg(tg_token="", smtp_to=())) == ()
    # порядок берётся из ALERT_CHANNELS
    assert active_channels(_cfg(channels=("smtp", "tg"))) == ("smtp", "tg")


def test_partially_configured_channel_dropped():
    """ALERT_CHANNELS задан, но канал недоконфигурирован — он отбрасывается."""
    cfg = _cfg(channels=("tg",), tg_chat_id="")
    assert active_channels(cfg) == ()


def test_config_warnings_lists_missing_keys():
    cfg = _cfg(channels=("tg", "smtp"), tg_chat_id="", smtp_to=())
    warnings = config_warnings(cfg)
    assert any("нет TG_CHAT_ID" in w for w in warnings)
    assert any("нет SMTP_TO" in w for w in warnings)
    assert not any("нет TG_BOT_TOKEN" in w for w in warnings)


def test_config_warnings_when_no_channels():
    cfg = _cfg(channels=("tg",), tg_token="", tg_chat_id="")
    warnings = config_warnings(cfg)
    assert any("уведомления выключены" in w for w in warnings)


def test_enabled_checks_parsed_from_csv(tmp_path):
    path = tmp_path / "alert.env"
    path.write_text("ALERT_CHECKS=threat,lockdown\n", encoding="utf-8")
    assert load_config(str(path)).enabled_checks == ("threat", "lockdown")
