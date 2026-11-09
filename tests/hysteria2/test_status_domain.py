"""WP-2: cert-info в hysteria2 status (тип сертификата, срок, рассинхрон E10)."""

import src.hysteria2.status as status_mod
from src.core.shell import ShellResult
from src.gateway.store import GatewayState, save_state

DOMAIN = "vpn.example.com"


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:
        self.lines.append(" ".join(str(a) for a in args))


def _env(tmp_path, monkeypatch, openssl_stdout: str, acme_domain: str = "") -> str:
    bin_path = tmp_path / "bin" / "hysteria"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("fake", encoding="utf-8")
    cert_path = tmp_path / "etc" / "hysteria" / "cert.pem"
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_text("CERT", encoding="utf-8")
    state_path = str(tmp_path / "state.json")
    state = GatewayState()
    state.protocols["hysteria2"] = {"installed": True, "port": 443}
    if acme_domain:
        state.protocols["acme"] = {"installed": True, "domain": acme_domain}
    save_state(state, state_path)

    monkeypatch.setattr(status_mod, "HYSTERIA2_BIN_PATH", bin_path)
    monkeypatch.setattr(status_mod, "HYSTERIA2_CERT_PATH", cert_path)
    monkeypatch.setattr(status_mod, "HYSTERIA2_CONFIG_PATH", tmp_path / "missing.yaml")
    monkeypatch.setattr(status_mod, "is_service_active", lambda: True)
    monkeypatch.setattr(status_mod, "port_free", lambda port, proto="udp": False)
    monkeypatch.setattr(status_mod, "port_owner", lambda port, proto="udp": "hysteria")

    def _run_list(args: list[str], timeout: int = 10) -> ShellResult:
        if args[:2] == ["openssl", "x509"]:
            return ShellResult(stdout=openssl_stdout, stderr="", returncode=0)
        if args[:1] == ["journalctl"]:
            return ShellResult(stdout="", stderr="", returncode=0)
        return ShellResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(status_mod, "run_list", _run_list)

    def _load(path=None):
        from src.gateway.store import load_state as _ls

        return _ls(state_path)

    monkeypatch.setattr(status_mod, "load_state", _load)
    return state_path


class TestCertInfo:
    def test_le_issuer_detected(self, tmp_path, monkeypatch) -> None:
        _env(
            tmp_path, monkeypatch,
            "issuer=C=US, O=Let's Encrypt, CN=E5\nnotAfter=Jan  1 00:00:00 2099 GMT\n",
            acme_domain=DOMAIN,
        )
        info = status_mod._cert_info()
        assert info["cert_type"] == "le"
        assert info["days_left"] is not None and info["days_left"] > 20000

    def test_self_signed_issuer_detected(self, tmp_path, monkeypatch) -> None:
        _env(
            tmp_path, monkeypatch,
            "issuer=CN=203.0.113.10\nnotAfter=Jan  1 00:00:00 2099 GMT\n",
        )
        info = status_mod._cert_info()
        assert info["cert_type"] == "self-signed"

    def test_unreadable_cert_returns_none(self, tmp_path, monkeypatch) -> None:
        _env(tmp_path, monkeypatch, "garbage output", )
        info = status_mod._cert_info()
        assert info["cert_type"] is None
        assert info["days_left"] is None


class TestDomainMismatchE10:
    def test_domain_but_self_signed_flagged(self, tmp_path, monkeypatch) -> None:
        """E10: домен выдан, у Hysteria2 ещё self-signed — рассинхрон виден."""
        _env(
            tmp_path, monkeypatch,
            "issuer=CN=203.0.113.10\nnotAfter=Jan  1 00:00:00 2099 GMT\n",
            acme_domain=DOMAIN,
        )
        recorder = _ConsoleRecorder()
        monkeypatch.setattr(status_mod, "console", recorder)
        info = status_mod.collect_status()
        assert info["domain_mismatch"] is True
        assert info["acme_domain"] == DOMAIN
        assert status_mod.run_status() == 0
        assert any("E10" in line and "apply-cert" in line for line in recorder.lines)

    def test_domain_and_le_no_mismatch(self, tmp_path, monkeypatch) -> None:
        _env(
            tmp_path, monkeypatch,
            "issuer=C=US, O=Let's Encrypt, CN=E5\nnotAfter=Jan  1 00:00:00 2099 GMT\n",
            acme_domain=DOMAIN,
        )
        recorder = _ConsoleRecorder()
        monkeypatch.setattr(status_mod, "console", recorder)
        info = status_mod.collect_status()
        assert info["domain_mismatch"] is False
        assert status_mod.run_status() == 0
        assert not any("E10" in line for line in recorder.lines)
        assert any("LE (Let's Encrypt)" in line for line in recorder.lines)
