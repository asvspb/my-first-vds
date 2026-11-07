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

# sysctl-тюнинг (не откатывается при remove — ADR-002).
SYSCTL_CONF_PATH = Path("/etc/sysctl.d/99-vds-gateway.conf")
