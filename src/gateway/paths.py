"""Единая точка путей и имён gateway (ADR-002).

Все пути и имена systemd-юнитов фиксируются здесь и только здесь; смена —
только через новый ADR. Пути, зависящие от окружения, строятся от INSTALL_DIR.
"""
import os
from pathlib import Path

# Корень установки (AGENTS.md §5.9): /opt/my-vds или /opt/ztnet из окружения.
INSTALL_DIR = Path(os.environ.get("INSTALL_DIR", "/opt/my-vds"))

# Хранилище состояния gateway: $INSTALL_DIR/gateway/state.json (0600, root).
GATEWAY_DIR = INSTALL_DIR / "gateway"
STATE_PATH = GATEWAY_DIR / "state.json"

# systemd-юниты (шаблоны в systemd/*.service.tpl).
XRAY_UNIT = "vds-xray.service"
HYSTERIA2_UNIT = "vds-hysteria2.service"

# Xray: апстрим-конвенция Xray (ADR-002).
XRAY_CONFIG_PATH = Path("/usr/local/etc/xray/config.json")
XRAY_BIN_PATH = Path("/usr/local/bin/xray")
XRAY_GEODATA_DIR = Path("/usr/local/share/xray")

# Hysteria2: апстрим-конвенция hysteria (ADR-002).
HYSTERIA2_CONFIG_PATH = Path("/etc/hysteria/config.yaml")
HYSTERIA2_CERT_PATH = Path("/etc/hysteria/cert.pem")
HYSTERIA2_KEY_PATH = Path("/etc/hysteria/key.pem")

# AmneziaWG (SPEC-20261110, ADR-005): обфусцированный WireGuard, UDP 51825,
# kernel-модуль из PPA ppa:amnezia/ppa; подсеть 10.9.0.0/24 (RFC1918, вне
# используемых подсетей zerotier/wireguard/xray).
AWG_UNIT = "vds-amneziawg.service"
AWG_CONFIG_PATH = Path("/etc/amnezia/awg0.conf")
AWG_CLIENTS_DIR = GATEWAY_DIR / "clients" / "amneziawg"
AWG_PORT_DEFAULT = 51825
AWG_IFACE = "awg0"
AWG_ADDRESS_SUBNET = "10.9.0.0/24"

# sysctl-тюнинг (не откатывается при remove — ADR-002).
SYSCTL_CONF_PATH = Path("/etc/sysctl.d/99-vds-gateway.conf")

# ACME / Let's Encrypt (SPEC-20261109-domain-xhttp-acme, ADR-004).
# certbot.timer — пакетный, своих юнитов не добавляем (SPEC §3 «systemd: без изменений»).
ACME_HOOKS_DEPLOY_DIR = Path("/etc/letsencrypt/renewal-hooks/deploy")
ACME_HYSTERIA2_HOOK_NAME = "vds-hysteria2-cert.sh"

# XHTTP: внутренний инблэнд Xray за SNI-фолбэком Reality (ADR-003); внешних
# портов не добавляет — слушает только на loopback.
XHTTP_INTERNAL_PORT = 8443
XRAY_HTTP_BIND = "127.0.0.1"


def ACME_LETSENCRYPT_LIVE(domain: str) -> Path:
    """Каталог live-сертификата LE для домена (ADR-004, пути локализованы в acme)."""
    return Path("/etc/letsencrypt/live") / domain
