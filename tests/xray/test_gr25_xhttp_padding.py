"""GR-25 (SPEC-20261116-xhttp-xmux-padding §2.1/§4/§5): серверные параметры
анти-ML профилирования XHTTP — `mode: auto` + `xPaddingBytes: "100-1000"`.

Покрытие:
- T-XM1: `render_config(xhttp_enabled=True)` рендерит оба поля в
  `streamSettings.xhttpSettings` (режимы fallback и port; константы
  `XHTTP_STREAM_MODE`/`XHTTP_PADDING_BYTES`).
- T-XM2: пере-рендер конфига не теряет `xhttpSettings` — `cdn._xhttp_fields`
  + `cdn._render_with_cdn` (add-cdn / клиенты CDN / пул фронтов),
  `install._render_xhttp_config` (повторный add-transport), `cdn._strip_cdn`
  (remove-cdn).
- Не-регресс: Reality-инблэнд, CDN-инблэнд (ws) и Hysteria2-конфиг не
  получают новых полей; share-link XHTTP не меняется (старые клиенты).
- T-XM3 (`xray -test` на живом Xray 26.1.23) локально не воспроизводим —
  бинаря в репозитории нет; см. отчёт WP.

Сети/shell нет; CDN-рендер чистый (сертификаты — строки путей, не читаются).
"""

import json
from pathlib import Path

import src.xray.cdn as cdn
import src.xray.install as install
from src.hysteria2.config import Hysteria2ConfigParams
from src.hysteria2.config import render_config as render_hysteria2_config
from src.xray.clients import render_xhttp_share_link
from src.xray.config import (
    XHTTP_PADDING_BYTES,
    XHTTP_STREAM_MODE,
    XrayConfigParams,
    render_config,
)

UUID = "11111111-2222-3333-4444-555555555555"  # зарезервированный fixture-UUID
XHTTP_UUID = "11111111-2222-3333-4444-888888888888"
PRIVATE_KEY = "FIXTURE_UUID_REALITYPRIVATEKEY"
SHORT_ID = "abcd1234"
SNI = "www.google.com"
DOMAIN = "example-103-45-247-172.example.invalid"
CDN_DOMAIN = "cdn.example.invalid"
CERT = "/etc/letsencrypt/live/example.invalid/fullchain.pem"
KEY = "/etc/letsencrypt/live/example.invalid/privkey.pem"
SECRET_PATH = "/aaaa1111bbbb2222cccc"  # фикстура пути-секрета (AGENTS.md §6)

EXPECTED_XHTTP_SETTINGS = {
    "path": "/xhttp",
    "mode": "auto",
    "xPaddingBytes": "100-1000",
}


def _params(**overrides) -> XrayConfigParams:
    base = dict(
        client_ids=[UUID],
        private_key=PRIVATE_KEY,
        short_ids=[SHORT_ID],
        sni=SNI,
        port=443,
    )
    base.update(overrides)
    return XrayConfigParams(**base)


def _xhttp_params(**overrides) -> XrayConfigParams:
    xhttp = dict(
        xhttp_enabled=True,
        domain=DOMAIN,
        cert_path=CERT,
        key_path=KEY,
        xhttp_client_ids=[XHTTP_UUID],
        xhttp_mode="fallback",
    )
    xhttp.update(overrides)
    return _params(**xhttp)


def _xhttp_config(path: str = SECRET_PATH, mode: str = "port") -> str:
    """Живой config.json с XHTTP-инблэндом (путь-секрет из state)."""
    return render_config(_xhttp_params(xhttp_mode=mode, xhttp_path=path))


def _xhttp_settings(config: dict) -> dict:
    inbounds = [
        ib
        for ib in config["inbounds"]
        if ib.get("streamSettings", {}).get("network") == "xhttp"
    ]
    assert len(inbounds) == 1
    return inbounds[0]["streamSettings"]["xhttpSettings"]


class TestTXM1Render:
    """T-XM1: `render_config()` с xhttp_enabled включает mode/xPaddingBytes."""

    def test_xhttp_settings_exact_fallback(self) -> None:
        stream = json.loads(render_config(_xhttp_params()))["inbounds"][1][
            "streamSettings"
        ]
        assert stream["xhttpSettings"] == EXPECTED_XHTTP_SETTINGS

    def test_xhttp_settings_exact_port_mode(self) -> None:
        stream = json.loads(
            render_config(_xhttp_params(xhttp_mode="port"))
        )["inbounds"][1]["streamSettings"]
        assert stream["xhttpSettings"] == EXPECTED_XHTTP_SETTINGS

    def test_constants_match_spec(self) -> None:
        assert XHTTP_STREAM_MODE == "auto"
        assert XHTTP_PADDING_BYTES == "100-1000"

    def test_custom_path_kept_with_new_fields(self) -> None:
        settings = _xhttp_settings(json.loads(_xhttp_config(SECRET_PATH)))
        assert settings == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }

    def test_reality_inbound_not_touched(self) -> None:
        """Reality-инблэнд (mode=port: без fallbacks) — байт-в-байт прежний."""
        without = json.loads(render_config(_params()))["inbounds"][0]
        with_xhttp = json.loads(
            render_config(_xhttp_params(xhttp_mode="port"))
        )["inbounds"][0]
        assert with_xhttp == without
        assert "xhttpSettings" not in with_xhttp["streamSettings"]
        assert "xPaddingBytes" not in json.dumps(with_xhttp)
        assert "xmux" not in json.dumps(with_xhttp)

    def test_cdn_inbound_not_touched(self) -> None:
        parsed = json.loads(
            render_config(
                _xhttp_params(
                    cdn_enabled=True,
                    cdn_domain=CDN_DOMAIN,
                    cdn_client_ids=[XHTTP_UUID],
                    cdn_cert_path=CERT,
                    cdn_key_path=KEY,
                )
            )
        )
        ws = parsed["inbounds"][2]["streamSettings"]
        assert ws["network"] == "ws"
        assert "xPaddingBytes" not in json.dumps(ws)
        assert "xmux" not in json.dumps(ws)
        assert "mode" not in ws["wsSettings"]

    def test_hysteria2_config_not_touched(self) -> None:
        """Параметры XHTTP не протекают в конфиг Hysteria2."""
        rendered = render_hysteria2_config(
            Hysteria2ConfigParams(password="FIXTURE_PW_HY2")
        )
        assert "xPaddingBytes" not in rendered
        assert "xmux" not in rendered
        assert "xhttpSettings" not in rendered

    def test_share_link_unchanged(self) -> None:
        """§4: базовый URI не меняется — новые параметры в ссылку не идут."""
        link = render_xhttp_share_link(
            domain=DOMAIN, client_uuid=UUID, name="xhttp-dev"
        )
        assert link == (
            f"vless://{UUID}@{DOMAIN}:443"
            f"?security=tls&network=xhttp&sni={DOMAIN}&fp=chrome"
            f"&path=/xhttp&type=xhttp#xhttp-dev"
        )
        assert "xPaddingBytes" not in link
        assert "xmux" not in link
        assert "mode=" not in link


class TestTXM2CrossRender:
    """T-XM2: `_xhttp_fields`/пере-рендер не теряют xhttpSettings."""

    def test_xhttp_fields_extracts_path(self) -> None:
        fields = cdn._xhttp_fields(json.loads(_xhttp_config()))
        assert fields is not None
        assert fields["path"] == SECRET_PATH

    def test_render_with_cdn_preserves_gr25_fields(self) -> None:
        current = json.loads(_xhttp_config())
        rendered = cdn._render_with_cdn(
            current, cdn.CdnParams(domain=CDN_DOMAIN), [XHTTP_UUID]
        )
        assert _xhttp_settings(json.loads(rendered)) == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }

    def test_render_xhttp_config_preserves_gr25_fields(self) -> None:
        current = json.loads(_xhttp_config())
        rendered = install._render_xhttp_config(current, DOMAIN, "port", [])
        assert _xhttp_settings(json.loads(rendered)) == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }

    def test_strip_cdn_keeps_gr25_fields(self) -> None:
        """remove-cdn вычитает только ws-инблэнд; xhttpSettings не трогается."""
        current = json.loads(
            cdn._render_with_cdn(
                json.loads(_xhttp_config()),
                cdn.CdnParams(domain=CDN_DOMAIN),
                [XHTTP_UUID],
            )
        )
        clean, actions = cdn._strip_cdn(current)
        assert actions  # ws-инблэнд снят
        assert _xhttp_settings(clean) == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }

    def test_fallback_renders_keep_fallbacks_and_fields(self) -> None:
        current = json.loads(_xhttp_config(mode="fallback"))
        rendered = json.loads(
            cdn._render_with_cdn(
                current, cdn.CdnParams(domain=CDN_DOMAIN), [XHTTP_UUID]
            )
        )
        assert rendered["inbounds"][0]["streamSettings"]["fallbacks"] == [
            {"alpn": ["http/1.1", "h2"], "dest": "127.0.0.1:8443"}
        ]
        assert _xhttp_settings(rendered) == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }

    def test_default_cdn_params_path_unchanged(self) -> None:
        """CDN-рендер не подмешивает xhttp-параметры в CDN-инблэнд."""
        rendered = json.loads(
            cdn._render_with_cdn(
                json.loads(_xhttp_config()),
                cdn.CdnParams(domain=CDN_DOMAIN),
                [XHTTP_UUID],
            )
        )
        ws_inbounds = [
            ib
            for ib in rendered["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        ]
        assert len(ws_inbounds) == 1
        assert "xPaddingBytes" not in json.dumps(ws_inbounds[0])


class TestTXM3Migration:
    """Мини-WP миграции asv1: ранний `already_enabled` только если GR-25
    поля уже есть; пере-рендер не теряет живой CDN-инблэнд (ws/2053)."""

    @staticmethod
    def _old_config() -> dict:
        current = json.loads(_xhttp_config())
        for inbound in current["inbounds"]:
            stream = inbound.get("streamSettings", {})
            if stream.get("network") == "xhttp":
                stream["xhttpSettings"].pop("mode", None)
                stream["xhttpSettings"].pop("xPaddingBytes", None)
        return current

    def test_has_gr25_settings_detects_old_and_new(self) -> None:
        assert install._xhttp_has_gr25_settings(self._old_config()) is False
        assert install._xhttp_has_gr25_settings(json.loads(_xhttp_config())) is True

    def test_old_config_is_not_already_enabled(
        self, monkeypatch
    ) -> None:
        from src.gateway.store import GatewayState

        old = self._old_config()
        monkeypatch.setattr(
            install, "_xhttp_precheck",
            lambda domain, mode, path, skip_domain_check=False: (old, Path("/tmp/bak-pre-xhttp")),
        )
        monkeypatch.setattr(install, "load_state", lambda state_path=None: GatewayState())
        result = install.add_transport_xhttp(DOMAIN, mode="port", apply=False)
        assert not result.get("already_enabled")
        assert result["path"] == SECRET_PATH  # путь-секрет не меняется

    def test_new_config_is_already_enabled(self, monkeypatch) -> None:
        from src.gateway.store import GatewayState

        current = json.loads(_xhttp_config())
        monkeypatch.setattr(
            install, "_xhttp_precheck",
            lambda domain, mode, path, skip_domain_check=False: (current, Path("/tmp/bak-pre-xhttp")),
        )
        monkeypatch.setattr(install, "load_state", lambda state_path=None: GatewayState())
        result = install.add_transport_xhttp(DOMAIN, mode="port", apply=False)
        assert result.get("already_enabled") is True

    def test_render_preserves_live_cdn_inbound(self) -> None:
        """asv1: XHTTP+CDN на одном узле — ws/2053 не должен исчезнуть."""
        current = json.loads(_xhttp_config())
        cdn_inbound = {
            "port": 2053,
            "protocol": "vless",
            "settings": {"clients": [{"id": XHTTP_UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": "/cdnws-fixture"},
                "tlsSettings": {"certificates": [{"certificateFile": CERT,
                                                  "keyFile": KEY}]},
            },
        }
        current["inbounds"].append(cdn_inbound)
        rendered = json.loads(
            install._render_xhttp_config(current, DOMAIN, "port", [XHTTP_UUID])
        )
        ws = [
            ib for ib in rendered["inbounds"]
            if ib.get("streamSettings", {}).get("network") == "ws"
        ]
        assert ws == [cdn_inbound]
        assert _xhttp_settings(rendered) == {
            "path": SECRET_PATH,
            "mode": "auto",
            "xPaddingBytes": "100-1000",
        }
