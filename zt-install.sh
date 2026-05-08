#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Auto Installer with Internet Gateway
#  Version: 1.0
#  Tested on: Ubuntu 20.04/22.04/24.04, Debian 11/12, OpenVZ 7
#
#  Функционал:
#    1. Анализ сетевой архитектуры сервера (включая OpenVZ)
#    2. Установка ZeroTier (Docker) + ZTNET Panel
#    3. Настройка IP forwarding + NAT для раздачи интернета всем ZT-клиентам
# =============================================================================

export DEBIAN_FRONTEND=noninteractive
set -euo pipefail

exec > >(tee /var/log/zt-install.log) 2>&1

# ── Цвета ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[->]${NC} $*"; }
sep()  { echo -e "${CYAN}------------------------------------------------------${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Запустите скрипт от root: sudo bash $0"

sep
echo -e "${BOLD}   ZeroTier + ZTNET Panel Installer (Internet Gateway)${NC}"
sep

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  АНАЛИЗ СЕТЕВОЙ АРХИТЕКТУРЫ СЕРВЕРА
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Анализ сетевой архитектуры сервера..."

IS_OPENVZ=false
if systemd-detect-virt &>/dev/null && systemd-detect-virt | grep -qi "openvz\|lxc"; then
    IS_OPENVZ=true
    warn "Обнаружена виртуализация: $(systemd-detect-virt)"
    warn "OpenVZ/LXC: будет использован SNAT вместо MASQUERADE"
fi

MAIN_IFACE=$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1)
[[ -z "${MAIN_IFACE}" ]] && MAIN_IFACE=$(ip -4 route show default | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
[[ -z "${MAIN_IFACE}" ]] && err "Не удалось определить основной сетевой интерфейс (нет default route)"

MAIN_IP=$(ip -4 addr show "${MAIN_IFACE}" | grep -oP 'inet \K[\d.]+' | head -1) || true
GATEWAY=$(ip -4 route show default | grep -oP 'via \K\S+' | head -1) || true
PUBLIC_IP=$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "${MAIN_IP}")
DNS_SERVERS=$(grep -oP 'nameserver \K[\d.]+' /etc/resolv.conf 2>/dev/null | sort -u | tr '\n' ' ') || true

ALL_IFACES=$(ip -o link show | grep -oP '^\d+: \K[^:]+' | sort)

echo ""
echo -e "${BOLD}  Сетевая архитектура:${NC}"
echo -e "  Основной интерфейс  : ${GREEN}${MAIN_IFACE}${NC}"
echo -e "  Локальный IP        : ${GREEN}${MAIN_IP}${NC}"
echo -e "  Шлюз                : ${GREEN}${GATEWAY}${NC}"
echo -e "  Публичный IP        : ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  DNS                 : ${GREEN}${DNS_SERVERS}${NC}"
echo -e "  OpenVZ/LXC          : ${GREEN}${IS_OPENVZ}${NC}"
echo ""
echo -e "  Все интерфейсы:"
for iface in ${ALL_IFACES}; do
    [[ -z "${iface}" ]] && continue
    iface_ip=$(ip -4 addr show "${iface}" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "-")
    iface_state=$(ip -o link show "${iface}" 2>/dev/null | grep -oP 'state \K\w+' || echo "UNKNOWN")
    printf "    %-20s %-18s %s\n" "${iface}" "${iface_ip:-?}" "${iface_state}"
done
echo ""

SERVER_IP="${PUBLIC_IP}"

# ── Параметры ZTNET ───────────────────────────────────────────────────────────
ZTNET_PORT="${ZTNET_PORT:-3000}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"

# При повторном запуске сохраняем существующие пароли
if [[ -f "${INSTALL_DIR}/.env.info" ]]; then
    POSTGRES_PASSWORD=$(grep -oP '^POSTGRES_PASSWORD=\K.*' "${INSTALL_DIR}/.env.info" 2>/dev/null || echo "$POSTGRES_PASSWORD")
    NEXTAUTH_SECRET=$(grep -oP '^NEXTAUTH_SECRET=\K.*' "${INSTALL_DIR}/.env.info" 2>/dev/null || echo "$NEXTAUTH_SECRET")
    warn "Обнаружен существующий .env.info — используем сохранённые пароли"
fi

POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -hex 16)}"
NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-$(openssl rand -hex 32)}"

if [[ "${SERVER_IP}" == *":"* ]]; then
    SERVER_IP_URL="[${SERVER_IP}]"
else
    SERVER_IP_URL="${SERVER_IP}"
fi
NEXTAUTH_URL="http://${SERVER_IP_URL}:${ZTNET_PORT}"

echo ""
warn "Параметры установки:"
echo "  Директория     : ${INSTALL_DIR}"
echo "  ZTNET URL      : ${NEXTAUTH_URL}"
echo "  ZTNET порт     : ${ZTNET_PORT}"
echo ""

# ── /dev/net/tun pre-check ───────────────────────────────────────────────────
if [[ ! -c /dev/net/tun ]]; then
    info "Создаём /dev/net/tun..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    modprobe tun 2>/dev/null || true
    if [[ ! -c /dev/net/tun ]]; then
        err "/dev/net/tun недоступен - ZeroTier не запустится"
    fi
fi
log "/dev/net/tun доступен"

# ── Pre-seed iptables-persistent ───────────────────────────────────────────
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 1/7 — Обновление системы
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 1/7 - Обновление системы"

rm -rf /var/lib/apt/lists/* || true
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg lsb-release openssl iptables-persistent
log "Система обновлена, iptables-persistent установлен"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 2/7 — Установка ZeroTier (на хосте для network_mode=host)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 2/7 - Установка ZeroTier"

if command -v zerotier-one &>/dev/null; then
    warn "ZeroTier уже установлен: $(zerotier-one -v 2>/dev/null || echo 'unknown version')"
else
    curl -s https://install.zerotier.com | bash
    systemctl enable zerotier-one
    systemctl start zerotier-one
    log "ZeroTier установлен и запущен"
fi

ZT_ADDR=$(zerotier-cli info 2>/dev/null | awk '{print $3}') || true
log "ZeroTier node address: ${BOLD}${ZT_ADDR:-неизвестен}${NC}"

if ss -tuln | grep -q ':9993 '; then
    warn "Порт 9993/udp занят (системный zerotier-one)"
    if systemctl is-active --quiet zerotier-one 2>/dev/null; then
        info "Останавливаем системный zerotier-one..."
        systemctl stop zerotier-one
        systemctl disable zerotier-one
        log "Системный zerotier-one остановлен"
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 3/7 — Установка Docker
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 3/7 - Установка Docker"

if command -v docker &>/dev/null; then
    warn "Docker уже установлен: $(docker --version)"
else
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
    systemctl enable docker
    systemctl start docker
    log "Docker установлен"
fi

if docker compose version &>/dev/null; then
    log "Docker Compose: $(docker compose version)"
elif command -v docker-compose &>/dev/null; then
    log "docker-compose: $(docker-compose --version)"
    ln -sf "$(command -v docker-compose)" /usr/local/bin/docker-compose 2>/dev/null || true
else
    info "Устанавливаем Docker Compose plugin..."
    apt-get install -y -qq docker-compose-plugin
    log "Docker Compose plugin установлен"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 4/7 — Настройка IP Forwarding + Sysctl
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 4/7 - Настройка IP Forwarding"

FORWARD_CONF="/etc/sysctl.d/99-zt-forward.conf"
cat > "${FORWARD_CONF}" <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

sysctl --system > /dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1 || true

CURRENT_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
if [[ "${CURRENT_FORWARD}" == "1" ]]; then
    log "IP forwarding включён (постоянно через ${FORWARD_CONF})"
else
    err "Не удалось включить IP forwarding"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 5/7 — Создание docker-compose.yml + NAT iptables
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 5/7 - Настройка ZTNET + NAT/iptables"

mkdir -p "${INSTALL_DIR}"

DOCKER_BRIDGE_SUBNET="172.31.255.0/29"
DOCKER_BRIDGE_GW="172.31.255.1"

# Проверка: если compose уже существует и контейнеры запущены — пропускаем перезапись
SKIP_COMPOSE=false
if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
    ALL_RUNNING=true
    for svc in postgres zerotier ztnet; do
        if ! docker compose -f "${INSTALL_DIR}/docker-compose.yml" ps --services --filter "status=running" 2>/dev/null | grep -q "^${svc}$"; then
            ALL_RUNNING=false
            break
        fi
    done
    if $ALL_RUNNING; then
        warn "Контейнеры уже работают — docker-compose.yml не будет перезаписан"
        SKIP_COMPOSE=true
    fi
fi

if ! $SKIP_COMPOSE; then
    log "Создаём docker-compose.yml..."
    cat > "${INSTALL_DIR}/docker-compose.yml" <<COMPEOF
services:
  postgres:
    image: postgres:15.2-alpine
    container_name: ztnet_postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ztnet
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d ztnet"]
      interval: 5s
      timeout: 5s
      retries: 12

  zerotier:
    image: zyclonite/zerotier:1.14.2
    hostname: zerotier
    container_name: ztnet_zerotier
    restart: unless-stopped
    volumes:
      - zerotier:/var/lib/zerotier-one
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun:/dev/net/tun
    # Всегда используем network_mode: host для:
    # 1. Прямого UDP-соединения ZeroTier (без TUNNELED режима)
    # 2. Автоматического доступа к ZT-интерфейсу на хосте
    # 3. Явного управления iptables через хостовые правила
    network_mode: host
    environment:
      - ZT_OVERRIDE_LOCAL_CONF=true
      - ZT_ALLOW_MANAGEMENT_FROM=127.0.0.1,${DOCKER_BRIDGE_SUBNET}
    healthcheck:
      test: ["CMD", "zerotier-cli", "info"]
      interval: 10s
      timeout: 5s
      retries: 12

  ztnet:
    image: sinamics/ztnet:latest
    container_name: ztnet
    working_dir: /app
    volumes:
      - zerotier:/var/lib/zerotier-one
    restart: unless-stopped
    ports:
      - "${ZTNET_PORT}:3000"
    environment:
      POSTGRES_HOST: postgres
      POSTGRES_PORT: 5432
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ztnet
      NEXTAUTH_URL: "${NEXTAUTH_URL}"
      NEXTAUTH_SECRET: "${NEXTAUTH_SECRET}"
      NEXTAUTH_URL_INTERNAL: "http://ztnet:3000"
    extra_hosts:
      - "zerotier:${DOCKER_BRIDGE_GW}"
    networks:
      - app-network
    links:
      - postgres
    depends_on:
      postgres:
        condition: service_healthy
      zerotier:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -s -o /dev/null -w \"%{http_code}\" http://ztnet:3000 | grep -qE \"^(200|30[128])$\" || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 12

volumes:
  zerotier:
  postgres-data:

networks:
  app-network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: ${DOCKER_BRIDGE_SUBNET}
COMPEOF

    log "docker-compose.yml создан в ${INSTALL_DIR}"
fi

# ── Настройка UFW ────────────────────────────────────────────────────────────
ZT_SUBNET="10.121.15.0/24"
if command -v ufw &>/dev/null; then
    UFW_ACTIVE=$(ufw status 2>/dev/null | grep -c "active" || echo "0")
    if [[ "${UFW_ACTIVE}" -gt 0 ]]; then
        warn "UFW активен - настраиваем для форвардинга ZT-трафика"

        ufw allow 9993/udp >/dev/null 2>&1
        ufw allow 9993/tcp >/dev/null 2>&1
        ufw allow "${ZTNET_PORT}/tcp" >/dev/null 2>&1

        ufw default allow routed >/dev/null 2>&1 || true

        log "UFW: порты 9993/udp, 9993/tcp, ${ZTNET_PORT}/tcp открыты, форвардинг разрешён"
    else
        info "UFW не активен - пропускаем настройку"
    fi
else
    info "UFW не установлен - пропускаем настройку"
fi

# ── iptables: NAT для ZT-трафика ────────────────────────────────────────────
info "Настройка iptables NAT..."

if [[ "${IS_OPENVZ}" == "true" ]]; then
    warn "OpenVZ: используем SNAT вместо MASQUERADE (venet0 совместимость)"
    iptables -t nat -C POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}" 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}"
    log "SNAT: ${ZT_SUBNET} -> ${MAIN_IFACE} (src=${SERVER_IP})"
else
    iptables -t nat -C POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE
    log "MASQUERADE: ${ZT_SUBNET} -> ${MAIN_IFACE}"
fi

iptables -t nat -C POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE

iptables -C FORWARD -s "${ZT_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s "${ZT_SUBNET}" -j ACCEPT

iptables -C FORWARD -d "${ZT_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 2 -d "${ZT_SUBNET}" -j ACCEPT

iptables -C FORWARD -s "${DOCKER_BRIDGE_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 3 -s "${DOCKER_BRIDGE_SUBNET}" -j ACCEPT

iptables -C FORWARD -d "${DOCKER_BRIDGE_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 4 -d "${DOCKER_BRIDGE_SUBNET}" -j ACCEPT

# Persist
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "iptables правила сохранены (переживут перезагрузку)"

# ── Сохраняем секреты ─────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/.env.info" <<EOF
# ZTNET Installation info - $(date)
SERVER_IP=${SERVER_IP}
MAIN_IFACE=${MAIN_IFACE}
MAIN_IP=${MAIN_IP}
PUBLIC_IP=${PUBLIC_IP}
IS_OPENVZ=${IS_OPENVZ}
ZTNET_URL=${NEXTAUTH_URL}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NEXTAUTH_SECRET=${NEXTAUTH_SECRET}
INSTALL_DIR=${INSTALL_DIR}
DOCKER_BRIDGE_SUBNET=${DOCKER_BRIDGE_SUBNET}
DOCKER_BRIDGE_GW=${DOCKER_BRIDGE_GW}
ZT_SUBNET=${ZT_SUBNET}
EOF
chmod 600 "${INSTALL_DIR}/.env.info"
log "Секреты сохранены в ${INSTALL_DIR}/.env.info"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 6/7 — Запуск ZTNET
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 6/7 - Запуск ZTNET (docker compose pull + up)"

cd "${INSTALL_DIR}"

ALL_RUNNING=true
for svc in postgres zerotier ztnet; do
    if ! docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^${svc}$"; then
        ALL_RUNNING=false
        break
    fi
done

if $ALL_RUNNING; then
    log "Контейнеры уже запущены — пропускаем docker compose up"
else
    docker compose pull -q

    set +e
    docker compose up -d --wait 2>/dev/null
    COMPOSE_EXIT=$?
    set -e

    if [ $COMPOSE_EXIT -ne 0 ]; then
        warn "docker compose up --wait завершился с кодом $COMPOSE_EXIT, пробуем retry-цикл..."
        FAILED=1
        for i in $(seq 1 6); do
            info "Ожидание запуска контейнеров (попытка $i/6)..."
            sleep 10
            ALL_UP=true
            for svc in postgres zerotier ztnet; do
                if ! docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^${svc}$"; then
                    ALL_UP=false
                    warn "  $svc - ещё не запущен"
                fi
            done
            if $ALL_UP; then
                FAILED=0
                break
            fi
        done
        if [ $FAILED -ne 0 ]; then
            docker compose ps
            err "Не все контейнеры запустились. Логи: docker compose -f ${INSTALL_DIR}/docker-compose.yml logs"
        fi
    fi
fi

log "Проверяем статус каждого контейнера..."
for svc in postgres zerotier ztnet; do
    if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^${svc}$"; then
        log "  $svc - работает"
    else
        docker compose logs --tail=20 "$svc" 2>/dev/null
        err "  $svc - НЕ запущен (см. логи выше)"
    fi
done

log "Проверка ZeroTier..."
ZT_INFO=$(docker exec ztnet_zerotier zerotier-cli info 2>/dev/null || true)
if [[ -n "${ZT_INFO}" ]]; then
    log "  ${ZT_INFO}"
else
    err "  ZeroTier не отвечает в контейнере"
fi

# Определяем ZT-IP сервера для Managed Route
SERVER_ZT_IP=$(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+$' | head -1 || true)
if [[ -n "${SERVER_ZT_IP}" ]]; then
    log "ZT-IP сервера: ${SERVER_ZT_IP}"
else
    warn "ZT-IP сервера не определён (создайте сеть в ZTNET и проверьте заново)"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 7/7 — Настройка NAT (хостовые iptables, без nsenter)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 7/7 - Настройка NAT для ZT-клиентов"

# При network_mode=host ZeroTier использует хостовый стек iptables,
# поэтому правила FORWARD уже работают через хостовые правила.
# Дополнительно настраиваем FORWARD для ZT-интерфейса на хосте.
if [[ "${IS_OPENVZ}" == "true" ]]; then
    info "OpenVZ: FORWARD правила уже настроены через iptables (шаг выше)"
else
    # Для обычных VPS — ZT-интерфейс будет виден на хосте (network_mode=host)
    log "Проверяем наличие ZT-интерфейса на хосте..."
    ZT_IFACE=$(ip -o link show | grep -oP 'zt[a-z0-9]+' | head -1 || true)
    if [[ -n "${ZT_IFACE}" ]]; then
        log "ZT-интерфейс на хосте: ${ZT_IFACE}"
        iptables -C FORWARD -i "${ZT_IFACE}" -o "${MAIN_IFACE}" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "${ZT_IFACE}" -o "${MAIN_IFACE}" -j ACCEPT
        iptables -C FORWARD -i "${MAIN_IFACE}" -o "${ZT_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "${MAIN_IFACE}" -o "${ZT_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
        log "FORWARD правила для ${ZT_IFACE} настроены на хосте"
    else
        warn "ZT-интерфейс пока не создан (будет после авторизации в сети)"
    fi
fi

# ── Скрипт авто-настройки NAT ────────────────────────────────────────────────
cat > "${INSTALL_DIR}/zt-nat-setup.sh" <<'NATEOF'
#!/bin/bash
set -euo pipefail
echo "[zt-nat-setup] Настройка NAT для ZeroTier..."

source /opt/ztnet/.env.info 2>/dev/null || true
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1)}"
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
[ -z "$MAIN_IFACE" ] && MAIN_IFACE="venet0"

SERVER_IP="${PUBLIC_IP:-$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
DOCKER_BRIDGE_SUBNET="${DOCKER_BRIDGE_SUBNET:-172.31.255.0/29}"
ZT_SUBNET="${ZT_SUBNET:-10.121.15.0/24}"
IS_OPENVZ="${IS_OPENVZ:-false}"

echo "  Main iface  : $MAIN_IFACE"
echo "  Server IP   : $SERVER_IP"
echo "  OpenVZ      : $IS_OPENVZ"
echo "  ZT subnet   : $ZT_SUBNET"

# Хостовые правила FORWARD (ZT -> внешняя сеть)
iptables -C FORWARD -s "${ZT_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s "${ZT_SUBNET}" -j ACCEPT
iptables -C FORWARD -d "${ZT_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 2 -d "${ZT_SUBNET}" -j ACCEPT

# FORWARD для ZT-интерфейса на хосте (при network_mode=host)
ZT_IFACE=$(ip -o link show | grep -oP 'zt[a-z0-9]+' | head -1 || true)
if [ -n "$ZT_IFACE" ]; then
    echo "  ZT interface: $ZT_IFACE"
    iptables -C FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT
    iptables -C FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# NAT (SNAT/MASQUERADE)
if [[ "${IS_OPENVZ}" == "true" ]]; then
    iptables -t nat -C POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}" 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}"
    echo "[zt-nat-setup] SNAT: ${ZT_SUBNET} -> ${MAIN_IFACE} (src=${SERVER_IP})"
else
    iptables -t nat -C POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${ZT_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE
    echo "[zt-nat-setup] MASQUERADE: ${ZT_SUBNET} -> ${MAIN_IFACE}"
fi

iptables -t nat -C POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE

netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "[zt-nat-setup] Правила сохранены"
NATEOF
chmod +x "${INSTALL_DIR}/zt-nat-setup.sh"
log "Скрипт авто-NAT сохранён: ${INSTALL_DIR}/zt-nat-setup.sh"

# ── systemd сервис для авто-NAT ──────────────────────────────────────────────
cat > /etc/systemd/system/zt-nat-setup.service <<SVCEOF
[Unit]
Description=ZeroTier NAT setup
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 15
ExecStart=${INSTALL_DIR}/zt-nat-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable zt-nat-setup.service
log "systemd сервис zt-nat-setup.service создан и включён"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 8/8 — Ожидание создания сети в ZTNET
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 8/8 - Ожидание создания сети в ZTNET"

echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ:${NC}"
echo ""
echo -e "  1. Откройте в браузере: ${CYAN}${NEXTAUTH_URL}${NC}"
echo -e "  2. Зарегистрируйтесь (первый пользователь = администратор)"
echo -e "  3. Создайте сеть в ZTNET Panel"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Вставьте Network ID созданной сети и нажмите Enter:${NC} "
read -r NETWORK_ID
NETWORK_ID="${NETWORK_ID// /}"
echo ""

if [[ -z "${NETWORK_ID}" ]]; then
    warn "Network ID не введён. Пропускаем подключение к сети."
    SERVER_ZT_IP="<ZT-IP сервера>"
else
    log "Подключаемся к сети ${NETWORK_ID}..."
    docker exec ztnet_zerotier zerotier-cli join "${NETWORK_ID}" || true

    echo ""
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ:${NC}"
    echo ""
    echo -e "  Авторизуйте ноду ${CYAN}${ZT_ADDR:-сервера}${NC} в панели ZTNET:"
    echo -e "    ${CYAN}${NEXTAUTH_URL}${NC} → Сеть → Members → ${BOLD}Auth${NC}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    SERVER_ZT_IP=""
    for i in $(seq 1 30); do
        echo -ne "\r  Ожидание авторизации... ($i/30)"
        SERVER_ZT_IP=$(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null \
            | grep -oP '\d+\.\d+\.\d+\.\d+/\d+$' | head -1 || true)
        if [[ -n "${SERVER_ZT_IP}" ]]; then
            echo ""
            log "Нода авторизована!"
            break
        fi
        sleep 5
    done

    if [[ -z "${SERVER_ZT_IP}" ]]; then
        echo ""
        warn "ZT-IP не получен за отведённое время."
        warn "Проверьте позже: docker exec ztnet_zerotier zerotier-cli listnetworks"
        SERVER_ZT_IP="<ZT-IP сервера>"
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ИТОГ
# ╚══════════════════════════════════════════════════════════════════════════════
sep
echo ""
echo -e "${BOLD}${GREEN}  Установка завершена!${NC}"
echo ""
echo -e "  ${BOLD}Сеть:${NC}"
echo -e "    Основной интерфейс  : ${CYAN}${MAIN_IFACE}${NC}"
echo -e "    Публичный IP        : ${CYAN}${PUBLIC_IP}${NC}"
echo -e "    ZT-IP сервера       : ${CYAN}${SERVER_ZT_IP}${NC}"
echo -e "    Виртуализация       : ${CYAN}$(systemd-detect-virt 2>/dev/null || echo 'N/A')${NC}"
echo ""
echo -e "  ${BOLD}ZTNET:${NC}"
echo -e "    Веб-панель          : ${BOLD}${NEXTAUTH_URL}${NC}"
echo -e "    Директория          : ${BOLD}${INSTALL_DIR}${NC}"
echo -e "    Секреты             : ${BOLD}${INSTALL_DIR}/.env.info${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}ОЧИСТИТЕ БРАУЗЕР ПЕРЕД ВХОДОМ В ПАНЕЛЬ${NC}"
echo -e "  Старая сессия зашифрована предыдущим NEXTAUTH_SECRET."
echo -e "  Без очистки кук будет ошибка JWEDecryptionFailed."
echo ""
echo -e "  ${GREEN}В браузере:${NC}"
echo -e "    ${BOLD}Настройки → Приватность → Очистить данные сайтов${NC}"
echo -e "    Или F12 → Application → Clear site data"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Для раздачи интернета через ZT:${NC}"
echo ""
echo -e "  1. Создайте сеть в ZTNET Panel"
echo -e "  2. Добавьте Managed Routes:"
echo -e "     ${CYAN}Destination: 0.0.0.0/0${NC}"
echo -e "     ${CYAN}Via: ${SERVER_ZT_IP:-<ZT-IP сервера>}${NC}"
echo -e "  3. На КАЖДОМ клиенте (включая мобильные):"
echo -e "     ${CYAN}zerotier-cli set <NETWORK_ID> allowDefault=1${NC}"
echo -e "     ${CYAN}или в настройках ZeroTier включите Allow Default Route${NC}"
echo ""
echo -e "  ${YELLOW}Узнать ZT-IP сервера:${NC}"
ZT_IP_CMD="docker exec ztnet_zerotier zerotier-cli listnetworks | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+\$'"
echo -e "    ${CYAN}${ZT_IP_CMD}${NC}"
echo ""
echo -e "  ${BOLD}Если NAT не работает после перезапуска:${NC}"
echo -e "    ${CYAN}${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "    Статус       : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml ps${NC}"
echo -e "    ZT сети      : ${CYAN}docker exec ztnet_zerotier zerotier-cli listnetworks${NC}"
echo -e "    ZT пиров     : ${CYAN}docker exec ztnet_zerotier zerotier-cli listpeers${NC}"
echo -e "    NAT настройки: ${CYAN}${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo ""
sep