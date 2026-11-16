"""Тесты redaction (SPEC §5.3): контекстные маркеры, блобы только для raw,
HMAC-IP детерминирован, sha256-поля НЕ маскируются."""
from __future__ import annotations

from src.logs.redact import (
    BLOB,
    LINK_PLACEHOLDER,
    REDACTED,
    UUID_PLACEHOLDER,
    load_hmac_key,
    redact_ip,
    redact_raw_text,
    redact_text,
    scan_secrets,
)

# RFC 5737 / fixture-маркеры — никаких «правдоподобных» секретов (AGENTS §6).
FIXTURE_KEY = "FIXTURE_PW_" + "0" * 40


class TestContextualRedaction:
    def test_private_key_masked(self):
        text = f"privateKey={FIXTURE_KEY}"
        out, count = redact_text(text)
        assert FIXTURE_KEY not in out
        assert REDACTED in out
        assert count >= 1

    def test_preshared_key_and_shortids(self):
        out, count = redact_text("PreSharedKey = FIXTURE_PW_psk; shortIds: FIXTURE_PW_sid")
        assert "FIXTURE_PW_psk" not in out
        assert "FIXTURE_PW_sid" not in out
        assert count >= 2

    def test_auth_param(self):
        out, _ = redact_text("GET /?auth=FIXTURE_PW_tok HTTP/1.1")
        assert "FIXTURE_PW_tok" not in out

    def test_uuid_and_share_link(self):
        out, count = redact_text(
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.5:443"
        )
        assert "vless://" not in out
        assert LINK_PLACEHOLDER in out
        assert count == 1

    def test_sha256_field_not_masked(self):
        """sha256/checksums/ja3/ja4 — легальный hex: redact_text НЕ трогает
        (жадный блоб только для raw)."""
        digest = "a" * 64
        out, count = redact_text(f'{{"sha256": "{digest}"}}')
        assert digest in out
        assert count == 0

    def test_raw_text_masks_greedy_blob(self):
        digest = "b" * 64
        out, count = redact_raw_text(f"kernel raw line digest={digest}")
        assert digest not in out
        assert BLOB in out
        assert count >= 1


class TestHmacIp:
    def test_deterministic(self):
        key = b"FIXTURE_HMAC_KEY_0123456789"
        a = redact_ip("203.0.113.7", key)
        b = redact_ip("203.0.113.7", key)
        c = redact_ip("198.51.100.9", key)
        assert a == b
        assert a != c
        assert a.startswith("ip:")
        assert len(a) == len("ip:") + 12
        assert "203.0.113.7" not in a

    def test_key_file_missing_returns_none(self, tmp_path):
        assert load_hmac_key(tmp_path / "no.key") is None

    def test_key_file_roundtrip(self, tmp_path):
        kf = tmp_path / "hmac.key"
        kf.write_text("FIXTURE_HMAC_KEY_ABC\n", encoding="utf-8")
        key = load_hmac_key(kf)
        assert key == b"FIXTURE_HMAC_KEY_ABC"


class TestScanSecrets:
    def test_clean_text(self):
        assert scan_secrets("обычный журнал UFW BLOCK SRC=203.0.113.7 DPT=443") == []

    def test_finds_private_key(self):
        found = scan_secrets(f"privateKey={FIXTURE_KEY}")
        assert found  # пост-сканер не дал секету пройти

    def test_finds_share_link(self):
        assert scan_secrets("hysteria2://FIXTURE_PW_x@203.0.113.5:443")
