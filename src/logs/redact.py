"""Redaction-санитайзер log-forensics (SPEC §5.3, ADR-012 privacy-контракт).

Три режима, границы которых — часть контракта:

- `redact_text` — контекстные маркеры секретов (privateKey/PrivateKey =/
  PreSharedKey/shortIds/password/auth=) → `<redacted>`, UUID → `<uuid>`,
  share-ссылки (vless://|hysteria2://|vpn://) → `<link>`. Применяется ко
  ВСЕМ текстовым источникам при сборе.
- `redact_raw_text` — super-set redact_text + жадный hex/base64 ≥32 →
  `<blob>`. Применяется ТОЛЬКО к сырому тексту журналов (raw/*.log) —
  НИКОГДА к JSON-полям: sha256/checksums/rules_hash/ja3/ja4 — легальный
  hex, иначе пост-сканер аварийно удаляет собственный бандл из-за
  манифеста (SPEC §5.3, ревью G2).
- `redact_ip` — HMAC-SHA256(key, ip)[:12] с префиксом `ip:` (opt-in
  `--redact-ips`); ключ /etc/vds-forensics/hmac.key (0600, генерируется
  `logs install --apply`), детерминирован (одинаковый IP → одинаковый
  хэш в бандле и отчёте).

Каждая замена считается; итоговые счётчики попадают в coverage.redactions.
Содержимое секретов не логируется (AGENTS §6).
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import re
from typing import Optional

REDACTED = "<redacted>"
BLOB = "<blob>"
UUID_PLACEHOLDER = "<uuid>"
LINK_PLACEHOLDER = "<link>"

# Share-ссылки транспортов: до маркеров секретов (внутри — UUID/пароли).
_LINK_RE = re.compile(
    r"\b(?:vless|hysteria2|trojan|ss|vpn)://[^\s\"']+", re.IGNORECASE
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)

# Контекстные маркеры: имя маркера + значение до конца значения (до кавычки/
# пробела/конца строки). Регистронезависимо (YAML/JSON-обязательства).
_VALUE = r"[^\s\"',;}\]]+"
_CONTEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"(?i)\bprivateKey\s*[=:]\s*{_VALUE}"),
    re.compile(rf"(?i)\bPrivateKey\s*=\s*{_VALUE}"),
    re.compile(rf"(?i)\bPreSharedKey\s*[=:]\s*{_VALUE}"),
    re.compile(rf"(?i)\bshortIds?\s*[=:]\s*{_VALUE}"),
    re.compile(rf"(?i)\bpassword\s*[=:]\s*{_VALUE}"),
    re.compile(rf"(?i)\bauth\s*[=:]\s*{_VALUE}"),
    re.compile(rf"(?i)\bpsk\s*[=:]\s*{_VALUE}"),
]

# Жадные блобы — только для raw-текста (см. докстринг модуля).
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")

# Пост-сканер: паттерны секретов, которые НЕ должны остаться в бандле/отчёте.
_SECRET_SCAN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)privateKey\s*[=:]\s*\S+"),
    re.compile(r"(?i)preSharedKey\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bpassword\s*[=:]\s*\S+"),
    re.compile(r"\b(?:vless|hysteria2|vpn)://\S+", re.IGNORECASE),
]


def redact_text(text: str) -> tuple[str, int]:
    """Контекстная редакция: ссылки → UUID → маркеры секретов.

    Возвращает (текст, число замен). Hex/base64 НЕ трогает (см.
    redact_raw_text — этот режим только для raw).
    """
    count = 0
    out, n = _LINK_RE.subn(LINK_PLACEHOLDER, text)
    count += n
    out, n = _UUID_RE.subn(UUID_PLACEHOLDER, out)
    count += n
    for pat in _CONTEXT_PATTERNS:
        out, n = pat.subn(REDACTED, out)
        count += n
    return out, count


def redact_raw_text(text: str) -> tuple[str, int]:
    """Режим raw-журналов: redact_text + жадные hex/base64-блобы ≥32.

    Порядок: сначала контекстные маркеры (значения секретов уже заменены
    и не попадут под блоб-жадность как «чужие» данные), затем блобы.
    """
    out, count = redact_text(text)
    for pat in (_HEX32_RE, _B64_RE):
        out, n = pat.subn(BLOB, out)
        count += n
    return out, count


def redact_ip(ip: str, key: bytes) -> str:
    """HMAC-SHA256(key, ip)[:12] с префиксом `ip:` — детерминированно."""
    digest = hmac_mod.new(key, ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"ip:{digest[:12]}"


def load_hmac_key(path=None) -> Optional[bytes]:
    """Ключ HMAC-редакции IP (0600); отсутствует → None (вызывающий решает)."""
    from pathlib import Path

    from src.logs import paths as logs_paths

    p = Path(path) if path is not None else logs_paths.HMAC_KEY_FILE
    try:
        raw = p.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return raw.encode("utf-8") if raw else None


def scan_secrets(text: str) -> list[str]:
    """Пост-сканер: имена найденных паттернов секретов ([] — чисто).

    Вызывается на готовом бандле/отчёте; непустой результат = аварийное
    завершение сбора (SPEC §5.3: это баг редактора, не «особый случай»).
    """
    found: list[str] = []
    for pat in _SECRET_SCAN_PATTERNS:
        if pat.search(text):
            found.append(pat.pattern)
    return found
