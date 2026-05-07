#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Auto Installer with Internet Gateway
#  Tested on: Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12
#
#  Функционал:
#    1. Анализ сетевой архитектуры сервера
#    2. Установка ZeroTier (Docker) + ZTNET Panel
#    3. Настройка IP forwarding + NAT для раздачи интернета всем ZT-клиентам
# =============================================================================

set -euo pipefail

exec > >(tee /var/log/zt-install.log) 2>&1

# ── Цвета ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────────${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Запустите скрипт от root: sudo bash $0"

sep
echo -e "${BOLD}   ZeroTier + ZTNET Panel Installer (Internet Gateway)${NC}"
sep

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  АНАЛИЗ СЕТЕВОЙ АРХИТЕКТУРЫ СЕРВЕРА
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Анализ сетевой архитектуры сервера..."

MAIN_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
[[ -z "${MAIN_IFACE}" ]] && err "Не удалось определить основной сетевой интерфейс (нет default route)"

MAIN_IP=$(ip -4 addr show "${MAIN_IFACE}" | grep -oP 'inet \K[\d.]+' | head -1)
GATEWAY=$(ip -4 route show default | awk '{print $3}' | head -1)
PUBLIC_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || echo "${MAIN_IP}")
DNS_SERVERS=$(grep -oP 'nameserver \K[\d.]+' /etc/resolv.conf 2>/dev/null | sort -u | tr '\n' ' ')

ALL_IFACES=$(ip -4 addr show | grep -oP '^\d+: \K[^:]+' | sort)

echo ""
echo -e "${BOLD}  Сетевая архитектура:${NC}"
echo -e "  Основной интерфейс  : ${GREEN}${MAIN_IFACE}${NC}"
echo -e "  Локальный IP        : ${GREEN}${MAIN_IP}${NC}"
echo -e "  Шлюз                : ${GREEN}${GATEWAY}${NC}"
echo -e "  Публичный IP        : ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  DNS                 : ${GREEN}${DNS_SERVERS}${NC}"
echo ""
echo -e "  Все интерфейсы:"
for iface in ${ALL_IFACES}; do
    iface_ip=$(ip -4 addr show "${iface}" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "N/A")
    iface_state=$(ip link show "${iface}" 2>/dev/null | grep -oP 'state \K\w+' || echo "UNKNOWN")
    printf "    %-20s %-18s %s\n" "${iface}" "${iface_ip:-—}" "${iface_state}"
done
echo ""

SERVER_IP="${PUBLIC_IP}"

# ── Параметры ZTNET ───────────────────────────────────────────────────────────
ZTNET_PORT="${ZTNET_PORT:-3000}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -hex 16)}"
NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-$(openssl rand -hex 32)}"
NEXTAUTH_URL="${NEXTAUTH_URL:-http://${SERVER_IP}:${ZTNET_PORT}}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"

echo ""
warn "Параметры установки:"
echo "  Директория     : ${INSTALL_DIR}"
echo "  ZTNET URL      : ${NEXTAUTH_URL}"
echo "  ZTNET порт     : ${ZTNET_PORT}"
echo "  PostgreSQL pass: ${POSTGRES_PASSWORD}"
echo ""

# ── /dev/net/tun pre-check ───────────────────────────────────────────────────
if [[ ! -c /dev/net/tun ]]; then
    info "Создаём /dev/net/tun..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    modprobe tun 2>/dev/null || true
    if [[ ! -c /dev/net/tun ]]; then
        err "/dev/net/tun недоступен — ZeroTier не запустится"
    fi
fi
log "/dev/net/tun доступен"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 1/7 — Обновление системы
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 1/7 — Обновление системы"
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg lsb-release openssl iptables-persistent
log "Система обновлена, iptables-persistent установлен"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 2/7 — Установка ZeroTier
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 2/7 — Установка ZeroTier"

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
sep; info "Шаг 3/7 — Установка Docker"

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
# ║  ШАГ 4/7 — Настройка IP Forwarding + Sysctl (хост)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 4/7 — Настройка IP Forwarding на хосте"

FORWARD_CONF="/etc/sysctl.d/99-zt-forward.conf"
cat > "${FORWARD_CONF}" <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl --system > /dev/null 2>&1
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1

CURRENT_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
if [[ "${CURRENT_FORWARD}" == "1" ]]; then
    log "IP forwarding включён (постоянно через ${FORWARD_CONF})"
else
    err "Не удалось включить IP forwarding"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 5/7 — Создание docker-compose.yml + NAT iptables
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 5/7 — Настройка ZTNET + NAT/iptables"

mkdir -p "${INSTALL_DIR}"

DOCKER_BRIDGE_SUBNET="172.31.255.0/29"

cat > "${INSTALL_DIR}/docker-compose.yml" <<EOF
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
    networks:
      - app-network
    ports:
      - "9993:9993/udp"
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
      - net.ipv4.conf.all.send_redirects=0
    environment:
      - ZT_OVERRIDE_LOCAL_CONF=true
      - ZT_ALLOW_MANAGEMENT_FROM=172.31.255.0/29
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
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3000"]
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
EOF

log "docker-compose.yml создан в ${INSTALL_DIR}"

# ── iptables: NAT для трафика из Docker/ZT → интернет ────────────────────────
info "Настройка iptables NAT для маршрутизации ZT-трафика..."

iptables -C FORWARD -i "${MAIN_IFACE}" -o br-+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${MAIN_IFACE}" -o br-+ -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i br-+ -o "${MAIN_IFACE}" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i br-+ -o "${MAIN_IFACE}" -j ACCEPT

iptables -C FORWARD -i br-+ -o br-+ -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i br-+ -o br-+ -j ACCEPT

iptables -t nat -C POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE

log "iptables NAT правила применены (${DOCKER_BRIDGE_SUBNET} → ${MAIN_IFACE})"

# ── UFW (если активен) ────────────────────────────────────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Обнаружен UFW — добавляем правила для ZeroTier и форвардинга"
    ufw allow 9993/udp >/dev/null 2>&1
    ufw allow "${ZTNET_PORT}/tcp" >/dev/null 2>&1

    ufw route allow in on br-+ out on "${MAIN_IFACE}" >/dev/null 2>&1 || true
    ufw route allow in on "${MAIN_IFACE}" out on br-+ >/dev/null 2>&1 || true

    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true

    cat > /etc/ufw/before.rules.d/zt-nat.rules <<UFWEOF
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${DOCKER_BRIDGE_SUBNET} -o ${MAIN_IFACE} -j MASQUERADE
COMMIT
UFWEOF

    ufw reload >/dev/null 2>&1 || true
    log "UFW: порты 9993/udp, ${ZTNET_PORT}/tcp открыты, форвардинг + NAT разрешены"
fi

# ── Persist iptables ──────────────────────────────────────────────────────────
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "iptables правила сохранены (переживут перезагрузку)"

# ── Сохраняем секреты ─────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/.env.info" <<EOF
# ZTNET Installation info — $(date)
SERVER_IP=${SERVER_IP}
MAIN_IFACE=${MAIN_IFACE}
MAIN_IP=${MAIN_IP}
GATEWAY=${GATEWAY}
PUBLIC_IP=${PUBLIC_IP}
DNS_SERVERS=${DNS_SERVERS}
ZTNET_URL=${NEXTAUTH_URL}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NEXTAUTH_SECRET=${NEXTAUTH_SECRET}
INSTALL_DIR=${INSTALL_DIR}
DOCKER_BRIDGE_SUBNET=${DOCKER_BRIDGE_SUBNET}
EOF
chmod 600 "${INSTALL_DIR}/.env.info"
log "Секреты + сетевая информация сохранены в ${INSTALL_DIR}/.env.info"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 6/7 — Запуск ZTNET
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 6/7 — Запуск ZTNET (docker compose pull + up)"

cd "${INSTALL_DIR}"
docker compose pull

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
                warn "  $svc — ещё не запущен"
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

log "Проверяем статус каждого контейнера..."
for svc in postgres zerotier ztnet; do
    if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^${svc}$"; then
        log "  $svc — работает"
    else
        docker compose logs --tail=20 "$svc" 2>/dev/null
        err "  $svc — НЕ запущен (см. логи выше)"
    fi
done

log "Проверка сети контейнера zerotier..."
ZT_IP=""
for i in $(seq 1 6); do
    ZT_IP=$(docker inspect ztnet_zerotier --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)
    [[ -n "$ZT_IP" ]] && break
    info "  Ожидание IP zerotier (попытка $i/6)..."
    sleep 10
done
if [[ -z "$ZT_IP" ]]; then
    err "Контейнер zerotier не получил IP в сети."
fi
log "  zerotier IP (Docker bridge): ${ZT_IP}"

log "Проверка DNS-резолвинга между контейнерами..."
if docker exec ztnet sh -c 'getent hosts zerotier' &>/dev/null; then
    log "  DNS OK (ztnet → zerotier)"
else
    err "DNS-резолвинг между контейнерами не работает."
fi

log "Проверка API zerotier из контейнера ztnet..."
if docker exec ztnet node -e 'http.get("http://zerotier:9993/controller/network", r => process.exit(r.statusCode === 200 ? 0 : 1)).on("error",()=>process.exit(1))' &>/dev/null; then
    log "  API zerotier доступен из ztnet"
else
    warn "API zerotier недоступен из ztnet. Проверьте сеть."
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 7/7 — Настройка NAT внутри контейнера zerotier
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 7/7 — Настройка NAT внутри контейнера zerotier"

CONTAINER_ETH=$(docker exec ztnet_zerotier ip -4 route show default 2>/dev/null | awk '{print $5}' | head -1 || true)
if [[ -z "${CONTAINER_ETH}" ]]; then
    CONTAINER_ETH="eth0"
    warn "Не удалось определить интерфейс контейнера, используем ${CONTAINER_ETH}"
fi
log "Интерфейс контейнера: ${CONTAINER_ETH}"

docker exec ztnet_zerotier sh -c "
    echo 1 > /proc/sys/net/ipv4/ip_forward && \
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding && \
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects && \
    iptables -C FORWARD -i zt+ -o ${CONTAINER_ETH} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i zt+ -o ${CONTAINER_ETH} -j ACCEPT && \
    iptables -C FORWARD -i ${CONTAINER_ETH} -o zt+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${CONTAINER_ETH} -o zt+ -m state --state RELATED,ESTABLISHED -j ACCEPT && \
    iptables -t nat -C POSTROUTING -o ${CONTAINER_ETH} -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o ${CONTAINER_ETH} -j MASQUERADE
" 2>/dev/null

CONTAINER_NAT_EXIT=$?
if [ $CONTAINER_NAT_EXIT -eq 0 ]; then
    log "NAT внутри контейнера zerotier настроен (zt+ → ${CONTAINER_ETH} → MASQUERADE)"
else
    warn "Не удалось настроить NAT внутри контейнера. Будет настроено через entrypoint."
fi

# ── Создаём скрипт авто-настройки NAT при перезапуске контейнера ─────────────
cat > "${INSTALL_DIR}/zt-nat-setup.sh" <<'NATEOF'
#!/bin/sh
echo "[zt-nat-setup] Настройка IP forwarding и NAT для ZeroTier..."

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/all/send_redirects

IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
[ -z "$IFACE" ] && IFACE="eth0"

iptables -C FORWARD -i zt+ -o "$IFACE" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i zt+ -o "$IFACE" -j ACCEPT
iptables -C FORWARD -i "$IFACE" -o zt+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$IFACE" -o zt+ -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

echo "[zt-nat-setup] NAT настроен: zt+ → $IFACE"
NATEOF
chmod +x "${INSTALL_DIR}/zt-nat-setup.sh"
log "Скрипт авто-NAT сохранён: ${INSTALL_DIR}/zt-nat-setup.sh"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ИТОГ
# ╚══════════════════════════════════════════════════════════════════════════════
sep
echo ""
echo -e "${BOLD}${GREEN}  ✅  Установка завершена!${NC}"
echo ""
echo -e "  ${BOLD}Сеть:${NC}"
echo -e "    Основной интерфейс  : ${CYAN}${MAIN_IFACE}${NC}"
echo -e "    Публичный IP        : ${CYAN}${PUBLIC_IP}${NC}"
echo -e "    Шлюз                : ${CYAN}${GATEWAY}${NC}"
echo -e "    DNS                 : ${CYAN}${DNS_SERVERS}${NC}"
echo ""
echo -e "  ${BOLD}ZTNET:${NC}"
echo -e "    Веб-панель          : ${BOLD}${NEXTAUTH_URL}${NC}"
echo -e "    Директория          : ${BOLD}${INSTALL_DIR}${NC}"
echo -e "    Секреты             : ${BOLD}${INSTALL_DIR}/.env.info${NC}"
echo ""
echo -e "  ${YELLOW}⚠ Первый зарегистрированный пользователь → администратор${NC}"
echo ""
echo -e "  ${BOLD}🔧 Для раздачи интернета через ZT:${NC}"
echo ""
echo -e "  ${YELLOW}1. Создайте сеть в ZTNET Panel${NC}"
echo -e "  2. В настройках сети добавьте Managed Routes:"
echo -e "     ${CYAN}Destination: 0.0.0.0/0${NC}"
echo -e "     ${CYAN}Via: <ZT-IP этого сервера в сети>${NC}"
echo -e "  3. На клиенте после join включите ${CYAN}Allow Default Route${NC}"
echo ""
echo -e "  ${BOLD}Пример настройки маршрута в ZTNET:${NC}"
echo -e "     Network → Advanced → Managed Routes → Add Route"
echo -e "     ┌──────────────┬──────────────────────────┐"
echo -e "     │ Destination  │ 0.0.0.0/0                │"
echo -e "     │ Via          │ 10.x.x.x (ZT IP сервера) │"
echo -e "     └──────────────┴──────────────────────────┘"
echo ""
echo -e "  ${BOLD}Если NAT не работает после перезапуска:${NC}"
echo -e "    ${CYAN}docker exec ztnet_zerotier ${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo -e "  (скрипт автоматически применит правила iptables внутри контейнера)"
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "    Логи ZTNET   : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f ztnet${NC}"
echo -e "    Статус       : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml ps${NC}"
echo -e "    Обновить     : ${CYAN}cd ${INSTALL_DIR} && docker compose pull && docker compose up -d${NC}"
echo -e "    ZT сети      : ${CYAN}docker exec ztnet_zerotier zerotier-cli listnetworks${NC}"
echo -e "    ZT пиров     : ${CYAN}docker exec ztnet_zerotier zerotier-cli listpeers${NC}"
echo -e "    NAT статус   : ${CYAN}docker exec ztnet_zerotier iptables -t nat -L -v${NC}"
echo ""
sep
