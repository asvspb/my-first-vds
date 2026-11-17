"""Тесты каналов доставки (SPEC §3.3, §6). Сеть не используется — всё инжектируется."""
from __future__ import annotations

import smtplib
import socket
import urllib.error

import pytest

from src.alert import channels
from src.alert.channels import (
    ChannelResult,
    backoff_delay_sec,
    send_all,
    send_smtp,
    send_telegram,
)
from src.alert.env import AlertConfig

TG_TOKEN = "FIXTURE_TG_BOT_TOKEN"
SMTP_PASS = "FIXTURE_PW_SMTP"
FROM = "alert-test@example.com"


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
    )
    base.update(over)
    return AlertConfig(**base)


class FakeSMTP:
    """Минимальный SMTP-клиент: те же методы, что зовёт send_smtp."""

    instances: list["FakeSMTP"] = []
    fail_init: Exception | None = None
    fail_login: Exception | None = None
    fail_send: Exception | None = None

    def __init__(self, host, port, timeout=None):
        if FakeSMTP.fail_init is not None:
            raise FakeSMTP.fail_init
        self.host, self.port, self.timeout = host, port, timeout
        self.started = False
        self.logged = None
        self.sent = []
        self.closed = False
        FakeSMTP.instances.append(self)

    def starttls(self):
        self.started = True

    def login(self, user, password):
        if FakeSMTP.fail_login is not None:
            raise FakeSMTP.fail_login
        self.logged = (user, password)

    def send_message(self, message):
        if FakeSMTP.fail_send is not None:
            raise FakeSMTP.fail_send
        self.sent.append(message)

    def quit(self):
        self.closed = True


class FakeSMTPSSL(FakeSMTP):
    """SMTP_SSL-ветка (порт 465)."""


class FakeSMTPPlain(FakeSMTP):
    """SMTP-ветка (SMTP_STARTTLS=1)."""


@pytest.fixture(autouse=True)
def _patch_smtp(monkeypatch):
    """Все SMTP-вызовы — в FakeSMTP: ни один тест не ходит в сеть."""
    monkeypatch.setattr(channels.smtplib, "SMTP_SSL", FakeSMTPSSL)
    monkeypatch.setattr(channels.smtplib, "SMTP", FakeSMTPPlain)
    FakeSMTP.instances = []
    FakeSMTP.fail_init = None
    FakeSMTP.fail_login = None
    FakeSMTP.fail_send = None
    yield
    FakeSMTP.instances = []


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def test_smtp_uses_smtp_ssl_by_default():
    result = send_smtp(_cfg(), "subject", "body")
    assert result == ChannelResult("smtp", True, "")
    assert len(FakeSMTP.instances) == 1
    client = FakeSMTP.instances[0]
    assert isinstance(client, FakeSMTPSSL)
    assert (client.host, client.port) == ("smtp.example.com", 465)
    assert client.started is False
    assert client.logged == (FROM, SMTP_PASS)


def test_smtp_starttls_uses_plain_smtp():
    result = send_smtp(_cfg(smtp_starttls=True, smtp_port=587), "subject", "body")
    assert result.ok is True
    client = FakeSMTP.instances[0]
    assert isinstance(client, FakeSMTPPlain)
    assert client.started is True


def test_smtp_message_headers():
    result = send_smtp(_cfg(), "тема письма", "тело")
    assert result.ok is True
    msg = FakeSMTP.instances[0].sent[0]
    assert msg["Subject"] == "тема письма"
    assert msg["From"] == FROM
    assert msg["To"] == "owner@example.com, second@example.com"
    assert "тело" in msg.get_content()


def test_smtp_auth_error_classified():
    FakeSMTP.fail_login = smtplib.SMTPAuthenticationError(535, b"bad credentials")
    result = send_smtp(_cfg(), "s", "b")
    assert result.ok is False
    assert result.errclass == "auth"


def test_smtp_connect_timeout_classified():
    FakeSMTP.fail_init = TimeoutError("timed out")
    assert send_smtp(_cfg(), "s", "b").errclass == "timeout"


def test_smtp_dns_error_classified():
    FakeSMTP.fail_init = socket.gaierror(-2, "name resolution")
    assert send_smtp(_cfg(), "s", "b").errclass == "dns"


def test_smtp_connection_error_classified():
    FakeSMTP.fail_init = ConnectionRefusedError("refused")
    assert send_smtp(_cfg(), "s", "b").errclass == "conn"


def test_smtp_send_failure_classified():
    FakeSMTP.fail_send = smtplib.SMTPServerDisconnected("gone")
    assert send_smtp(_cfg(), "s", "b").errclass == "conn"


def test_smtp_not_configured():
    result = send_smtp(_cfg(smtp_to=()), "s", "b")
    assert result == ChannelResult("smtp", False, "config")
    assert FakeSMTP.instances == []


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200):
        self.status = status
        self.closed = False

    def close(self):
        self.closed = True


def test_telegram_success():
    calls = []

    def opener(request, timeout=None):
        calls.append((request, timeout))
        return FakeResponse(200)

    result = send_telegram(_cfg(), "text", opener=opener, timeout=5)
    assert result == ChannelResult("tg", True, "")
    assert calls[0][1] == 5


def test_telegram_http_4xx():
    def opener(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)

    assert send_telegram(_cfg(), "t", opener=opener).errclass == "http_4xx"


def test_telegram_http_5xx():
    def opener(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 502, "bad gateway", {}, None)

    assert send_telegram(_cfg(), "t", opener=opener).errclass == "http_5xx"


def test_telegram_timeout():
    def opener(request, timeout=None):
        raise urllib.error.URLError(TimeoutError("timed out"))

    assert send_telegram(_cfg(), "t", opener=opener).errclass == "timeout"


def test_telegram_dns():
    def opener(request, timeout=None):
        raise urllib.error.URLError(socket.gaierror(-2, "dns"))

    assert send_telegram(_cfg(), "t", opener=opener).errclass == "dns"


def test_telegram_conn_fallback():
    def opener(request, timeout=None):
        raise urllib.error.URLError("boom")

    assert send_telegram(_cfg(), "t", opener=opener).errclass == "conn"


def test_telegram_not_configured():
    assert send_telegram(_cfg(tg_chat_id=""), "t") == ChannelResult("tg", False, "config")


def test_no_secret_leak():
    """Токен не встречается ни в errclass, ни в любом сформированном тексте (R-3)."""
    def opener(request, timeout=None):
        raise urllib.error.HTTPError(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", 401, "no", {}, None
        )

    result = send_telegram(_cfg(), "t", opener=opener)
    rendered = f"{result.channel} {result.errclass} {result!r}"
    assert TG_TOKEN not in rendered
    assert SMTP_PASS not in rendered
    assert result.errclass == "http_4xx"


# ---------------------------------------------------------------------------
# send_all / backoff
# ---------------------------------------------------------------------------

def test_send_all_channels_independent():
    def broken(cfg, text):
        raise RuntimeError("tg exploded")

    def good(cfg, text):
        return ChannelResult("smtp", True, "")

    results = send_all(_cfg(), "s", "b", senders={"tg": broken, "smtp": good})
    assert [r.channel for r in results] == ["tg", "smtp"]
    assert results[0].ok is False and results[0].errclass == "conn"
    assert results[1].ok is True


def test_send_all_skips_unconfigured_channels():
    results = send_all(_cfg(tg_chat_id=""), "s", "b", senders={
        "smtp": lambda cfg, text: ChannelResult("smtp", True, ""),
    })
    assert [r.channel for r in results] == ["smtp"]


def test_send_all_real_senders_injected():
    results = send_all(
        _cfg(channels=("smtp",)),
        "s",
        "b",
        senders={"smtp": lambda cfg, text: channels.send_smtp(cfg, "s", text)},
    )
    assert results[0].ok is True


@pytest.mark.parametrize(
    "fails,expected",
    [(0, 0), (-1, 0), (1, 60), (2, 120), (3, 240), (6, 1920), (7, 3600), (20, 3600)],
)
def test_backoff_delay_sec(fails, expected):
    assert backoff_delay_sec(fails) == expected
