"""CLI-поверхность `vds gateway init` (SPEC-20261114 WP-2).

dry-run по умолчанию, exit-коды, help, отсутствие секретов в выводе.
run_init мокается — реальных вызовов shell/сети нет.
"""

from typing import Any

import pytest
from typer.testing import CliRunner

from src.main import app

runner = CliRunner()

DOMAIN = "vpn.example.ru"
EMAIL = "admin@example.ru"


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def _run(**kwargs: Any) -> int:
        calls.append(kwargs)
        return 0

    import src.gateway.init as init_mod

    monkeypatch.setattr(init_mod, "run_init", _run)
    return calls


class TestGatewayInitCLI:
    def test_dry_run_by_default(self, recorded: list[dict[str, Any]]) -> None:
        result = runner.invoke(app, ["gateway", "init"])
        assert result.exit_code == 0
        assert len(recorded) == 1
        assert recorded[0]["apply"] is False
        assert recorded[0]["protocols"] == "reality,hysteria2"

    def test_apply_flag_passed(self, recorded: list[dict[str, Any]]) -> None:
        result = runner.invoke(app, ["gateway", "init", "--apply"])
        assert result.exit_code == 0
        assert recorded[0]["apply"] is True

    def test_full_flags_roundtrip(self, recorded: list[dict[str, Any]]) -> None:
        result = runner.invoke(
            app,
            [
                "gateway", "init", "--apply",
                "--protocols", "reality,hysteria2,obfs,hop,xhttp,cdn,awg",
                "--domain", DOMAIN,
                "--email", EMAIL,
                "--sni", "www.cloudflare.com",
                "--hop-range", "20000-20500",
                "--cdn-domain", "cdn.example.ru",
                "--demo-clients",
            ],
        )
        assert result.exit_code == 0
        kwargs = recorded[0]
        assert kwargs["protocols"] == "reality,hysteria2,obfs,hop,xhttp,cdn,awg"
        assert kwargs["domain"] == DOMAIN
        assert kwargs["email"] == EMAIL
        assert kwargs["sni"] == "www.cloudflare.com"
        assert kwargs["hop_range"] == "20000-20500"
        assert kwargs["cdn_domain"] == "cdn.example.ru"
        assert kwargs["demo_clients"] is True
        assert kwargs["apply"] is True

    def test_run_init_error_propagates_exit_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.gateway.init as init_mod

        monkeypatch.setattr(init_mod, "run_init", lambda **kw: 1)
        result = runner.invoke(app, ["gateway", "init", "--apply"])
        assert result.exit_code == 1

    def test_help_lists_flags(self) -> None:
        result = runner.invoke(app, ["gateway", "init", "--help"])
        assert result.exit_code == 0
        for flag in (
            "--protocols", "--domain", "--email", "--sni", "--hop-range",
            "--cdn-domain", "--apply", "--demo-clients", "--require-domain",
        ):
            assert flag in result.output

    def test_no_secrets_in_dry_run_output(self) -> None:
        # dry-run без мока run_init: parse_protocols валидирует до чего-либо
        # секретного; в выводе нет traceback/секретов.
        result = runner.invoke(app, ["gateway", "init", "--protocols", "reality"])
        assert result.exception is None or isinstance(result.exception, SystemExit)
        out = result.output
        assert "password" not in out.lower()
        assert "uuid" not in out.lower()
        assert "Traceback" not in out
