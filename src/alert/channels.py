"""Доставка уведомлений на stdlib (SPEC-20261117-alert-watch §3.3, §5).

Только `smtplib` / `urllib` / `ssl` / `socket` — без `requests` и новых
зависимостей (NFR stdlib).

**Инвариант секретов:** `HTTPError`/`URLError` содержат URL с токеном бота в
`str(exc)`, поэтому `str(exc)` здесь не печатается и не логируется вообще.
Наружу идёт только `errclass` из фиксированного набора. Это проверяется
тестом `test_no_secret_leak`.
"""
from __future__ import annotations

import smtplib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Callable, Optional

from src.alert.env import (
    AlertConfig,
    active_channels,
    smtp_configured,
    tg_configured,
)

# Классификаторы ошибок (без секретов и без URL).
ERRCLASS_CONFIG = "config"
ERRCLASS_TIMEOUT = "timeout"
ERRCLASS_DNS = "dns"
ERRCLASS_CONN = "conn"
ERRCLASS_AUTH = "auth"
ERRCLASS_HTTP_4XX = "http_4xx"
ERRCLASS_HTTP_5XX = "http_5xx"
ERRCLASS_TLS = "tls"


@dataclass(frozen=True)
class ChannelResult:
    channel: str  # "tg" | "smtp"
    ok: bool
    errclass: str  # "" при успехе


def _classify_os_error(exc: Exception) -> str:
    """OSError-семейство → errclass. Порядок важен: подклассы проверяются первыми."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ERRCLASS_TIMEOUT
    if isinstance(exc, socket.gaierror):
        return ERRCLASS_DNS
    if isinstance(exc, ssl.SSLError):
        return ERRCLASS_TLS
    return ERRCLASS_CONN


def _classify_smtp_exc(exc: Exception) -> str:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return ERRCLASS_AUTH
    if isinstance(exc, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected,
                        smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused)):
        return ERRCLASS_CONN
    return _classify_os_error(exc)


def _open_smtp(
    cfg: AlertConfig,
    timeout: float,
    smtp_factory: Optional[Callable[..., object]],
):
    """Создать соединение: `SMTP_SSL` по умолчанию, `SMTP` при SMTP_STARTTLS=1."""
    if smtp_factory is not None:
        return smtp_factory(cfg.smtp_host, cfg.smtp_port, timeout)
    if cfg.smtp_starttls:
        return smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
    return smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=timeout)


def send_smtp(
    cfg: AlertConfig,
    subject: str,
    text: str,
    *,
    smtp_factory: Optional[Callable[..., object]] = None,
    timeout: float = 15.0,
) -> ChannelResult:
    """Отправить письмо. `smtp_factory` инжектируется в тестах (сеть не нужна)."""
    if not smtp_configured(cfg):
        return ChannelResult("smtp", False, ERRCLASS_CONFIG)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg.smtp_from
    message["To"] = ", ".join(cfg.smtp_to)
    message.set_content(text)

    try:
        client = _open_smtp(cfg, timeout, smtp_factory)
    except Exception as exc:  # ошибка доставки классифицируется, не пробрасывается
        return ChannelResult("smtp", False, _classify_smtp_exc(exc))

    try:
        if cfg.smtp_starttls:
            try:
                client.starttls()
            except Exception as exc:  # errclass вместо исключения
                return ChannelResult("smtp", False, _classify_smtp_exc(exc))
        if cfg.smtp_user:
            try:
                client.login(cfg.smtp_user, cfg.smtp_pass)
            except Exception as exc:  # errclass вместо исключения
                return ChannelResult("smtp", False, _classify_smtp_exc(exc))
        try:
            client.send_message(message)
        except Exception as exc:  # errclass вместо исключения
            return ChannelResult("smtp", False, _classify_smtp_exc(exc))
        return ChannelResult("smtp", True, "")
    finally:
        _close_quietly(client)


def _close_quietly(client: object) -> None:
    """Закрыть SMTP-соединение; ошибка закрытия не влияет на результат отправки."""
    for name in ("quit", "close"):
        method = getattr(client, name, None)
        if callable(method):
            try:
                method()
                return
            except Exception:  # закрытие best-effort
                continue


def send_telegram(
    cfg: AlertConfig,
    text: str,
    *,
    opener: Optional[Callable[..., object]] = None,
    timeout: float = 10.0,
) -> ChannelResult:
    """POST в Bot API. `opener` инжектируется в тестах (сеть не нужна)."""
    if not tg_configured(cfg):
        return ChannelResult("tg", False, ERRCLASS_CONFIG)

    url = f"https://api.telegram.org/bot{cfg.tg_token}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": cfg.tg_chat_id,
            "text": text,
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    open_call = opener or urllib.request.urlopen

    try:
        response = open_call(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # str(exc) содержит URL с токеном — не трогаем его.
        code = getattr(exc, "code", 0) or 0
        errclass = ERRCLASS_HTTP_4XX if 400 <= code < 500 else ERRCLASS_HTTP_5XX
        return ChannelResult("tg", False, errclass)
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, Exception):
            return ChannelResult("tg", False, _classify_os_error(reason))
        return ChannelResult("tg", False, ERRCLASS_CONN)
    except Exception as exc:  # ошибка доставки классифицируется, не пробрасывается
        return ChannelResult("tg", False, _classify_os_error(exc))

    status = getattr(response, "status", None) or getattr(response, "code", None)
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # без влияния на результат
            pass
    if isinstance(status, int) and status >= 400:
        errclass = ERRCLASS_HTTP_4XX if status < 500 else ERRCLASS_HTTP_5XX
        return ChannelResult("tg", False, errclass)
    return ChannelResult("tg", True, "")


def send_all(
    cfg: AlertConfig,
    subject: str,
    text: str,
    *,
    senders: Optional[dict[str, Callable[..., ChannelResult]]] = None,
) -> list[ChannelResult]:
    """Отправить по всем активным каналам; каналы независимы.

    Исключение одного отправителя не мешает остальным: оно превращается в
    `ChannelResult(ok=False, errclass="conn")`.
    """
    registry: dict[str, Callable[..., ChannelResult]] = {
        "tg": lambda c, t: send_telegram(c, t),
        "smtp": lambda c, t: send_smtp(c, subject, t),
    }
    if senders:
        for name, fn in senders.items():
            registry[name] = fn

    results: list[ChannelResult] = []
    for channel in active_channels(cfg):
        sender = registry.get(channel)
        if sender is None:
            results.append(ChannelResult(channel, False, ERRCLASS_CONFIG))
            continue
        try:
            result = sender(cfg, text)
        except Exception:  # канал не должен валить тик
            result = ChannelResult(channel, False, ERRCLASS_CONN)
        if not isinstance(result, ChannelResult):
            result = ChannelResult(channel, False, ERRCLASS_CONN)
        results.append(result)
    return results


def backoff_delay_sec(fail_count: int) -> int:
    """Экспоненциальный backoff: `min(60·2^(n−1), 3600)`; n<=0 → 0."""
    if fail_count <= 0:
        return 0
    return min(60 * 2 ** (fail_count - 1), 3600)
