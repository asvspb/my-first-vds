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
# NAT-юнит: персистентность MASQUERADE независимо от ufw (инцидент 2026-11-13).
AWG_NAT_UNIT = "vds-amneziawg-nat.service"
AWG_CONFIG_PATH = Path("/etc/amnezia/awg0.conf")
AWG_CLIENTS_DIR = GATEWAY_DIR / "clients" / "amneziawg"
AWG_PORT_DEFAULT = 51825
AWG_IFACE = "awg0"
AWG_ADDRESS_SUBNET = "10.9.0.0/24"

# P15 (TECHDEBT, найдено на asv1): маршрутзация клиентского трафика —
# ip_forward + MASQUERADE для awg0-подсети.
AWG_SYSCTL_FORWARD_CONF = Path("/etc/sysctl.d/99-vds-awg-forward.conf")
AWG_UFW_BEFORE_RULES = Path("/etc/ufw/before.rules")

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

# CDN-транспорт (SPEC-20261110, ADR-006): VLESS+WS+TLS за Cloudflare proxy.
# Отдельный proxied-DNS-элемент cdn.<домен> (orange cloud), origin-инблэнд
# vless+ws+tls на TCP 2053 — первый свободный из CF HTTPS-портов
# (443 Reality, 8443 XHTTP-direct). LE live-путь параметризован доменом —
# см. ACME_LETSENCRYPT_LIVE(domain).
CDN_ORIGIN_PORT_DEFAULT = 2053
CDN_WS_PATH = "/cdnws"
CDN_DOMAIN_HINT = "cdn."  # имя поддомена приходит флагом; константа — подсказка для сообщений


def ACME_LETSENCRYPT_LIVE(domain: str) -> Path:
    """Каталог live-сертификата LE для домена (ADR-004, пути локализованы в acme)."""
    return Path("/etc/letsencrypt/live") / domain


# Hysteria2 port hopping (SPEC-20261112 WP-1, ADR-008): именованная цепочка
# nat/PREROUTING с REDIRECT диапазона на слушающий udp/443 + идемпотентный
# apply-скрипт и oneshot-юнит для переживания ребута. Смена имён — новый ADR.
HYSTERIA2_HOP_CHAIN = "VDS_HY2_HOP"
HYSTERIA2_HOP_SCRIPT = Path("/usr/local/sbin/vds-hy2-hop-apply.sh")
HYSTERIA2_HOP_UNIT = "vds-hysteria2-hop.service"

# Hysteria2 obfs salamander (SPEC-20261112 WP-1): параллельный инстанс на
# отдельном UDP-порту (по умолчанию 51826 — вне занятых 443/8443/2053/51825),
# собственный конфиг (0600) и юнит из шаблона.
HYSTERIA2_OBFS_CONFIG_PATH = Path("/etc/hysteria/obfs.yaml")
HYSTERIA2_OBFS_UNIT = "vds-hysteria2-obfs.service"
HYSTERIA2_OBFS_PORT_DEFAULT = 51826
