"""Пути и константы RU-relay (ADR-007, SPEC-20261114-ru-relay §3).

Отдельный от src/gateway/paths.py модуль: у релея свои подсеть/порты/имена
юнитов (10.9.0.0/24 и 51825 на релее заняты awg1-ногой до asv1). Пути,
зависящие от окружения, строятся от INSTALL_DIR — не хардкодить.
"""
import os
from pathlib import Path

# Корень установки (AGENTS.md §5.9): /opt/my-vds или /opt/ztnet из окружения.
INSTALL_DIR = Path(os.environ.get("INSTALL_DIR", "/opt/my-vds"))

# Gateway store релея: тот же формат state.json (ADR-002), но на машине релея.
GATEWAY_DIR = INSTALL_DIR / "gateway"
STATE_PATH = GATEWAY_DIR / "state.json"

# --- AWG-сервер (вход клиентов, whitelist-порт ADR-007 R1a) ---
RELAY_UNIT = "vds-relay-awg.service"  # рендерится из systemd/vds-amneziawg.service.tpl
RELAY_CONFIG_PATH = Path("/etc/amnezia/awg0.conf")  # awg-quick ищет iface по конфигу
RELAY_IFACE = "awg0"
RELAY_SUBNET = "10.10.0.0/24"  # НЕ 10.9.0.0/24 — та занята asv1-ногой (ADR-007 девиации)
RELAY_PORT = 443  # UDP, whitelist-порт (R1a: «HTTP/3 к RU-ресурсу»)
RELAY_MTU = 1280  # двойная инкапсуляция client→relay→asv1 (SPEC §1.4)
RELAY_CLIENTS_DIR = GATEWAY_DIR / "clients" / "relay"

# --- AWG-клиентская нога relay→asv1 (awg1, v4-only) ---
RELAY_EXIT_UNIT = "vds-relay-exit.service"
RELAY_EXIT_CONFIG_PATH = Path("/etc/amnezia/awg1.conf")
RELAY_EXIT_IFACE = "awg1"
RELAY_EXIT_PORT = 51825  # UDP-порт AWG-сервера asv1
RELAY_EXIT_MTU = 1420  # одинарная инкапсуляция на этой ноге
# Таблица маршрутизации для exit-ноги и метка nft-политики (SPEC §1.3).
RELAY_MARK = "0x1"
RELAY_TABLE = "100"

# --- systemd-юниты релея (шаблоны в systemd/) ---
RELAY_NAT_UNIT = "vds-relay-nat.service"
RELAY_POLICY_UNIT = "vds-relay-policy.service"
RELAY_CIDR_UNIT = "vds-relay-cidr.service"
RELAY_CIDR_TIMER = "vds-relay-cidr.timer"

# --- nftables / CIDR ---
RELAY_DIR = Path("/etc/vds-relay")
RELAY_NFT_TABLE = "vds_relay"
RELAY_NFT_POLICY_FILE = RELAY_DIR / "nft-policy.conf"
RELAY_CIDR_LIST = RELAY_DIR / "ru-cidrs.txt"
RELAY_CIDR_SOURCE = "https://www.ipdeny.com/ipblocks/data/countries/ru.zone"

# --- UFW / sysctl ---
RELAY_SYSCTL_FORWARD_CONF = Path("/etc/sysctl.d/99-vds-relay-forward.conf")
RELAY_UFW_BEFORE_RULES = Path("/etc/ufw/before.rules")

# --- Выделенная нога relay→exit на exit-узле (ADR-015, TECHDEBT P24) ---
# Отдельный от клиентского awg0 интерфейс: порт ноги изолирован по IP релея.
# exit-сторона разворачивается командой `vds relay exit-leg install` на самом
# exit; релей лишь меняет свой локальный endpoint (WP-M3).
EXIT_LEG_IFACE = "awg2"
EXIT_LEG_CONFIG_PATH = Path("/etc/amnezia/awg2.conf")
EXIT_LEG_SUBNET = "10.11.0.0/30"
EXIT_LEG_IP = "10.11.0.1"  # адрес exit внутри ноги
EXIT_LEG_PEER_IP = "10.11.0.2"  # адрес релея внутри ноги (единственный пир)
EXIT_LEG_BASE_PORT = 51900  # P_base — слушает awg2
EXIT_LEG_POOL = "51900-51911"  # 12 портов, REDIRECT с saddr релея → P_base
EXIT_LEG_MTU = 1420  # одинарная инкапсуляция на этой ноге
EXIT_LEG_UNIT = "vds-awg-relay.service"
EXIT_LEG_POOL_UNIT = "vds-awg-relay-pool.service"
EXIT_LEG_NFT_TABLE = "vds_relay_leg"
EXIT_LEG_NFT_FILE = Path("/etc/vds/relay-leg.nft")
EXIT_LEG_POOL_SCRIPT = Path("/usr/local/sbin/vds-relay-leg-pool-apply.sh")
EXIT_LEG_LOCK_FILE = "/var/run/vds-relay-exit-leg.lock"

# Блокировка мутаций (конвенция AGENTS.md §5.3).
LOCK_FILE = "/var/run/vds-relay.lock"
