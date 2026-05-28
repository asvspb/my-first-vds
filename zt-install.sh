#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Auto Installer with Internet Gateway
#  Version: 1.1
#  Tested on: Ubuntu 20.04/22.04/24.04, Debian 11/12, OpenVZ 7
#
#  Функционал:
#    1. Анализ сетевой архитектуры сервера (включая OpenVZ)
#    2. Установка ZeroTier (Docker) + ZTNET Panel
#    3. Настройка IP forwarding + NAT для раздачи интернета всем ZT-клиентам
# =============================================================================

export DEBIAN_FRONTEND=noninteractive
set -euo pipefail

LOCK_FILE="/var/run/ztnet-install.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    echo "Другой экземпляр установки уже запущен. Выход."
    exit 1
fi

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
# ║  ШАГ 1/8 — Обновление системы
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 1/8 - Обновление системы"

rm -rf /var/lib/apt/lists/* || true
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg lsb-release openssl iptables-persistent
apt-get install -y -qq ufw 2>/dev/null || warn "UFW не установлен: конфликт с iptables-persistent (пропускаем)"
log "Система обновлена, iptables-persistent установлен"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 2/8 — Установка ZeroTier (на хосте для network_mode=host)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 2/8 - Установка ZeroTier"

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

if ss -tuln | grep -q ':9993 ' || systemctl is-active --quiet zerotier-one 2>/dev/null || pgrep -x zerotier-one &>/dev/null; then
    warn "Порт 9993 занят или системный zerotier-one активен — освобождаем"
    systemctl stop zerotier-one 2>/dev/null || true
    systemctl disable zerotier-one 2>/dev/null || true
    pkill -9 -x zerotier-one 2>/dev/null || true
    sleep 2
    if ss -tuln | grep -q ':9993 '; then
        fuser -k 9993/tcp 9993/udp 2>/dev/null || true
        sleep 2
    fi
    systemctl mask zerotier-one 2>/dev/null || true
    log "Системный zerotier-one остановлен, отключён и замаскирован (не займёт порт 9993)"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 3/8 — Установка Docker
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 3/8 - Установка Docker"

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
# ║  ШАГ 4/8 — Настройка IP Forwarding + Sysctl
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 4/8 - Настройка IP Forwarding"

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
# ║  ШАГ 5/8 — Создание docker-compose.yml + NAT iptables
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 5/8 - Настройка ZTNET + NAT/iptables"

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
    set +e
    UFW_ACTIVE=$(ufw status 2>/dev/null | grep -c "active" || true)
    if [[ "${UFW_ACTIVE}" == "0" || -z "${UFW_ACTIVE}" ]]; then
        warn "UFW установлен, но не активен — активируем с базовыми правилами"
        ufw allow 22/tcp >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1 || true
        log "UFW активирован (SSH:22/tcp открыт)"
    fi

    ufw allow 9993/udp >/dev/null 2>&1 || true
    ufw allow 9993/tcp >/dev/null 2>&1 || true
    ufw allow "${ZTNET_PORT}/tcp" >/dev/null 2>&1 || true
    ufw default allow routed >/dev/null 2>&1 || true
    set -e

    log "UFW: порты 9993/udp, 9993/tcp, ${ZTNET_PORT}/tcp открыты, форвардинг разрешён"
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
# ║  ШАГ 6/8 — Запуск ZTNET
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 6/8 - Запуск ZTNET (docker compose pull + up)"

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

info "Ожидание ONLINE статуса контроллера..."
for i in $(seq 1 12); do
    ZT_STATUS=$(docker exec ztnet_zerotier zerotier-cli info 2>/dev/null | awk '{for(j=1;j<=NF;j++) if($j~/^(ONLINE|OFFLINE|TUNNELED)$/) print $j}')
    if [[ "${ZT_STATUS}" == "ONLINE" || "${ZT_STATUS}" == "TUNNELED" ]]; then
        log "Контроллер ${ZT_STATUS} — готов к подключению клиентов"
        break
    fi
    if [[ "$i" -eq 12 ]]; then
        warn "Контроллер не перешёл в ONLINE за 60 сек (статус: ${ZT_STATUS:-?})"
        warn "Клиенты могут не получить конфиг сети — запустите диагностику позже"
    fi
    sleep 5
done

ZT_AUTHTOKEN=$(docker exec ztnet_zerotier cat /var/lib/zerotier-one/authtoken.secret 2>/dev/null | tr -d '[:space:]' || true)
if [[ -n "${ZT_AUTHTOKEN}" ]]; then
    log "ZT authtoken.secret получен (для Controller API)"
else
    warn "Не удалось получить authtoken.secret — авто-авторизация будет недоступна"
fi

ZT_ADDR=$(docker exec ztnet_zerotier zerotier-cli info 2>/dev/null | awk '{print $3}' || true)
log "ZeroTier node address: ${BOLD}${ZT_ADDR:-неизвестен}${NC}"

# Определяем ZT-IP сервера для Managed Route
SERVER_ZT_IP=$(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+$' | head -1 || true)
if [[ -n "${SERVER_ZT_IP}" ]]; then
    log "ZT-IP сервера: ${SERVER_ZT_IP}"
else
    warn "ZT-IP сервера не определён (создайте сеть в ZTNET и проверьте заново)"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 7/8 — Настройка NAT (хостовые iptables, без nsenter)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 7/8 - Настройка NAT для ZT-клиентов"

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
echo "[zt-nat-setup] Настройка NAT для всех ZeroTier сетей..."

INSTALL_DIR="/opt/ztnet"
source "${INSTALL_DIR}/.env.info" 2>/dev/null || true
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1)}"
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
[ -z "$MAIN_IFACE" ] && MAIN_IFACE="venet0"

SERVER_IP="${PUBLIC_IP:-$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
DOCKER_BRIDGE_SUBNET="${DOCKER_BRIDGE_SUBNET:-172.31.255.0/29}"
IS_OPENVZ="${IS_OPENVZ:-false}"

echo "  Main iface  : $MAIN_IFACE"
echo "  Server IP   : $SERVER_IP"
echo "  OpenVZ      : $IS_OPENVZ"

IFS=',' read -ra SUBNETS <<< "${ZT_SUBNETS:-${ZT_SUBNET:-10.121.15.0/24}}"
for SUB in "${SUBNETS[@]}"; do
    echo "  ZT subnet   : $SUB"

    iptables -C FORWARD -s "$SUB" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -s "$SUB" -j ACCEPT
    iptables -C FORWARD -d "$SUB" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 2 -d "$SUB" -j ACCEPT

    if [[ "${IS_OPENVZ}" == "true" ]]; then
        iptables -t nat -C POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j SNAT --to-source "$SERVER_IP" 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j SNAT --to-source "$SERVER_IP"
        echo "  SNAT: $SUB -> $MAIN_IFACE"
    else
        iptables -t nat -C POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j MASQUERADE
        echo "  MASQUERADE: $SUB -> $MAIN_IFACE"
    fi
done

while IFS= read -r ZT_IFACE; do
    [ -z "$ZT_IFACE" ] && continue
    echo "  ZT interface: $ZT_IFACE"
    iptables -C FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT
    iptables -C FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
done < <(ip -o link show | grep -oP 'zt[a-z0-9]+' || true)

iptables -t nat -C POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "$MAIN_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "$MAIN_IFACE" -j MASQUERADE

netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "[zt-nat-setup] Правила сохранены для ${#SUBNETS[@]} сетей"
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

# ── Watchdog — автоконтроль и восстановление ZT ──────────────────────────────
cat > "${INSTALL_DIR}/zt-watchdog.sh" <<'WDEOF'
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/ztnet"
LOG_FILE="${INSTALL_DIR}/zt-watchdog.log"
MAX_LOG_SIZE=$((512 * 1024))
CONTAINER="ztnet_zerotier"
CHECK_WINDOW="5m"
MAX_RESTARTS_PER_HOUR=3
STATE_FILE="/tmp/zt-watchdog-restarts"
ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_w() { echo "[$(ts)] [WATCHDOG] $*" | tee -a "${LOG_FILE}"; }
rotate_log() { [[ -f "${LOG_FILE}" ]] && [[ $(stat -c%s "${LOG_FILE}" 2>/dev/null || echo 0) -gt ${MAX_LOG_SIZE} ]] && tail -200 "${LOG_FILE}" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "${LOG_FILE}"; }
count_recent_restarts() {
    [[ ! -f "${STATE_FILE}" ]] && echo 0 && return
    local cutoff=$(date -d '1 hour ago' '+%s' 2>/dev/null || date -v-1H '+%s' 2>/dev/null || echo 0)
    local count=0
    while IFS= read -r line; do
        local e=$(date -d "${line}" '+%s' 2>/dev/null || echo 0)
        [[ "${e}" -ge "${cutoff}" ]] && count=$((count + 1))
    done < "${STATE_FILE}"
    echo "${count}"
}
record_restart() {
    echo "$(ts)" >> "${STATE_FILE}"
    local cutoff=$(date -d '1 hour ago' '+%s' 2>/dev/null || date -v-1H '+%s' 2>/dev/null || echo 0)
    local tmp=$(mktemp)
    while IFS= read -r line; do
        local e=$(date -d "${line}" '+%s' 2>/dev/null || echo 0)
        [[ "${e}" -ge "${cutoff}" ]] && echo "${line}" >> "${tmp}"
    done < "${STATE_FILE}"
    mv "${tmp}" "${STATE_FILE}"
}
restart_container() {
    local recent=$(count_recent_restarts)
    if [[ "${recent}" -ge "${MAX_RESTARTS_PER_HOUR}" ]]; then
        log_w "STOP: ${recent} рестартов за час (лимит ${MAX_RESTARTS_PER_HOUR})"
        return 1
    fi
    log_w "Рестарт #$((recent+1))/${MAX_RESTARTS_PER_HOUR}"
    record_restart
    docker restart "${CONTAINER}" 2>&1 | while read -r line; do log_w "  docker: ${line}"; done
    log_w "Ожидаем ONLINE..."
    for i in $(seq 1 12); do
        sleep 5
        local info=$(docker exec "${CONTAINER}" zerotier-cli info 2>/dev/null || true)
        if echo "${info}" | grep -qE 'ONLINE|TUNNELED'; then log_w "OK: ${info}"; return 0; fi
        log_w "  ($((i*5))с): ${info:-нет ответа}"
    done
    log_w "ERROR: не ONLINE за 60с"
    return 1
}
rotate_log
BIND_ERRORS=$(docker logs "${CONTAINER}" --since "${CHECK_WINDOW}" 2>&1 | grep -cE "Could not bind|fatal error.*9993" 2>/dev/null || true)
BIND_ERRORS="${BIND_ERRORS:-0}"
ZT_INFO=$(docker exec "${CONTAINER}" zerotier-cli info 2>/dev/null || true)
ZT_STATUS=$(echo "${ZT_INFO}" | awk '{for(i=1;i<=NF;i++) if($i~/^(ONLINE|OFFLINE|TUNNELED|DEGRADED)$/) print $i}' | head -1)
CONTAINER_RUNNING=$(docker inspect --format '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || echo "false")
PROBLEM=false
[[ "${CONTAINER_RUNNING}" != "true" ]] && log_w "PROBLEM: контейнер не запущен" && PROBLEM=true
[[ "${BIND_ERRORS}" -gt 3 ]] && log_w "PROBLEM: ${BIND_ERRORS} ошибок биндинга за ${CHECK_WINDOW}" && PROBLEM=true
[[ "${ZT_STATUS}" == "OFFLINE" || -z "${ZT_STATUS}" ]] && log_w "PROBLEM: ZT статус=${ZT_STATUS:-NO_RESPONSE}" && PROBLEM=true
if ! docker exec "${CONTAINER}" pgrep -x zerotier-one >/dev/null 2>&1; then
    log_w "PROBLEM: процесс zerotier-one не найден"; PROBLEM=true
fi
if $PROBLEM; then
    log_w "Восстановление..."
    systemctl is-active --quiet zerotier-one 2>/dev/null && systemctl stop zerotier-one 2>/dev/null || true
    systemctl mask zerotier-one 2>/dev/null || true
    pkill -9 -x zerotier-one 2>/dev/null || true
    sleep 2
    for pid in $(ss -tlnup 2>/dev/null | grep ':9993 ' | grep -oP 'pid=\K\d+' || true); do
        local cpid=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER}" 2>/dev/null || echo "")
        [[ "${pid}" == "${cpid}" ]] && continue
        log_w "Убиваем конфликт PID ${pid}"
        kill -9 "${pid}" 2>/dev/null || true
    done
    sleep 2
    restart_container && log_w "Восстановлено" || log_w "Восстановление с ошибками"
else
    [[ "${BIND_ERRORS}" -gt 0 ]] && log_w "OK (${BIND_ERRORS} ошибок, но ZT ${ZT_STATUS})"
fi
WDEOF
chmod +x "${INSTALL_DIR}/zt-watchdog.sh"

cat > /etc/systemd/system/zt-watchdog.service <<WDSVEOF
[Unit]
Description=ZeroTier Watchdog
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/zt-watchdog.sh
IOSchedulingClass=idle
CPUWeight=1
WDSVEOF

cat > /etc/systemd/system/zt-watchdog.timer <<WDTEOF
[Unit]
Description=ZeroTier Watchdog Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=30s

[Install]
WantedBy=timers.target
WDTEOF

systemctl daemon-reload
systemctl enable zt-watchdog.timer
systemctl start zt-watchdog.timer
log "Watchdog zt-watchdog.timer включён (проверка каждые 2 мин)"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ШАГ 8/8 — Ожидание создания сети + авто-подключение
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Шаг 8/8 - Ожидание создания сети + авто-подключение"

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

    # ── Само-авторизация через Controller API ──────────────────────────────────
    if [[ -n "${ZT_AUTHTOKEN}" && -n "${ZT_ADDR}" ]]; then
        log "Само-авторизация ноды ${ZT_ADDR} через Controller API..."
        AUTH_RESPONSE=$(curl -s -X POST \
            -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
            -H "Content-Type: application/json" \
            -d '{"authorized": true}' \
            "http://localhost:9993/controller/network/${NETWORK_ID}/member/${ZT_ADDR}" 2>/dev/null || true)

        if echo "${AUTH_RESPONSE}" | grep -q '"authorized"'; then
            log "Нода ${ZT_ADDR} авторизована через Controller API"
        else
            warn "Авто-авторизация не удалась. Ответ: ${AUTH_RESPONSE:-пусто}"
            warn "Авторизуйте вручную в ZTNET Panel"

            echo ""
            echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ:${NC}"
            echo ""
            echo -e "  Авторизуйте ноду ${CYAN}${ZT_ADDR}${NC} в панели ZTNET:"
            echo -e "    ${CYAN}${NEXTAUTH_URL}${NC} → Сеть → Members → ${BOLD}Auth${NC}"
            echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
        fi
    else
        warn "authtoken.secret или ZT_ADDR недоступны — ручная авторизация"

        echo ""
        echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ:${NC}"
        echo ""
        echo -e "  Авторизуйте ноду ${CYAN}${ZT_ADDR:-сервера}${NC} в панели ZTNET:"
        echo -e "    ${CYAN}${NEXTAUTH_URL}${NC} → Сеть → Members → ${BOLD}Auth${NC}"
        echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi

    # ── Ожидание ZT-IP ────────────────────────────────────────────────────────
    SERVER_ZT_IP=""
    for i in $(seq 1 30); do
        echo -ne "\r  Ожидание назначения ZT-IP... ($i/30)"
        SERVER_ZT_IP=$(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null \
            | grep -oP '\d+\.\d+\.\d+\.\d+/\d+$' | head -1 || true)
        if [[ -n "${SERVER_ZT_IP}" ]]; then
            echo ""
            log "ZT-IP получен: ${SERVER_ZT_IP}"
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

    # ── Верификация доставки конфига (vRev > 0) ───────────────────────────────
    if [[ -n "${ZT_AUTHTOKEN}" && -n "${ZT_ADDR}" ]]; then
        VREV=$(curl -s -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
            "http://localhost:9993/controller/network/${NETWORK_ID}/member/${ZT_ADDR}" 2>/dev/null \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('vRev',-1))" 2>/dev/null || echo "-1")
        if [[ "${VREV}" -le 0 ]]; then
            warn "vRev=${VREV} — конфиг сети пока не доставлен (косметический статус)"
            info "Клиент работает нормально при vRev=0. Конфиг обновится при следующем запросе клиента."
        fi
    fi

    # ── Динамическое определение ZT_SUBNET ────────────────────────────────────
    ACTUAL_SUBNET=""
    if [[ -n "${ZT_AUTHTOKEN}" ]]; then
        NETWORK_CONFIG=$(curl -s \
            -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
            "http://localhost:9993/controller/network/${NETWORK_ID}" 2>/dev/null || true)

        if [[ -n "${NETWORK_CONFIG}" ]]; then
            ACTUAL_SUBNET=$(echo "${NETWORK_CONFIG}" | grep -oP '"ipRangeStart"\s*:\s*"\K[\d.]+' | head -1 \
                | sed -E 's/\.[0-9]+$/\.0\/24/' || true)

            if [[ -z "${ACTUAL_SUBNET}" ]]; then
                ACTUAL_SUBNET=$(echo "${NETWORK_CONFIG}" | grep -oP '"target"\s*:\s*"\K[\d./]+' | grep -v '0\.0\.0\.0' | head -1 || true)
            fi
        fi

        if [[ -z "${ACTUAL_SUBNET}" && "${SERVER_ZT_IP}" != "<ZT-IP сервера>" ]]; then
            ACTUAL_SUBNET=$(echo "${SERVER_ZT_IP}" | sed -E 's/\.[0-9]+\/([0-9]+)$/.0\/\1/')
        fi

        if [[ -n "${ACTUAL_SUBNET}" && "${ACTUAL_SUBNET}" != "${ZT_SUBNET}" ]]; then
            OLD_SUBNET="${ZT_SUBNET}"
            warn "Реальный ZT subnet (${ACTUAL_SUBNET}) отличается от дефолтного (${OLD_SUBNET})"
            info "Обновляем iptables правила..."

            if [[ "${IS_OPENVZ}" == "true" ]]; then
                iptables -t nat -D POSTROUTING -s "${OLD_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}" 2>/dev/null || true
                iptables -t nat -A POSTROUTING -s "${ACTUAL_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}"
                log "SNAT обновлён: ${OLD_SUBNET} → ${ACTUAL_SUBNET}"
            else
                iptables -t nat -D POSTROUTING -s "${OLD_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || true
                iptables -t nat -A POSTROUTING -s "${ACTUAL_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE
                log "MASQUERADE обновлён: ${OLD_SUBNET} → ${ACTUAL_SUBNET}"
            fi

            iptables -D FORWARD -s "${OLD_SUBNET}" -j ACCEPT 2>/dev/null || true
            iptables -I FORWARD 1 -s "${ACTUAL_SUBNET}" -j ACCEPT

            iptables -D FORWARD -d "${OLD_SUBNET}" -j ACCEPT 2>/dev/null || true
            iptables -I FORWARD 2 -d "${ACTUAL_SUBNET}" -j ACCEPT

            ZT_SUBNET="${ACTUAL_SUBNET}"

            netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            log "iptables правила обновлены и сохранены"
        elif [[ -n "${ACTUAL_SUBNET}" ]]; then
            log "ZT subnet совпадает с дефолтным: ${ACTUAL_SUBNET}"
        else
            warn "Не удалось определить реальный ZT subnet автоматически"
        fi
    fi

    # ── Обновление .env.info ──────────────────────────────────────────────────
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
NETWORK_ID=${NETWORK_ID}
EOF
    chmod 600 "${INSTALL_DIR}/.env.info"
    log ".env.info обновлён (ZT_SUBNET=${ZT_SUBNET})"

    # ── Регенерация zt-nat-setup.sh ───────────────────────────────────────────
    cat > "${INSTALL_DIR}/zt-nat-setup.sh" <<'NATEOF2'
#!/bin/bash
set -euo pipefail
echo "[zt-nat-setup] Настройка NAT для всех ZeroTier сетей..."

INSTALL_DIR="/opt/ztnet"
source "${INSTALL_DIR}/.env.info" 2>/dev/null || true
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1)}"
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
[ -z "$MAIN_IFACE" ] && MAIN_IFACE="venet0"

SERVER_IP="${PUBLIC_IP:-$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
DOCKER_BRIDGE_SUBNET="${DOCKER_BRIDGE_SUBNET:-172.31.255.0/29}"
IS_OPENVZ="${IS_OPENVZ:-false}"

echo "  Main iface  : $MAIN_IFACE"
echo "  Server IP   : $SERVER_IP"
echo "  OpenVZ      : $IS_OPENVZ"

IFS=',' read -ra SUBNETS <<< "${ZT_SUBNETS:-${ZT_SUBNET:-10.121.15.0/24}}"
for SUB in "${SUBNETS[@]}"; do
    echo "  ZT subnet   : $SUB"

    iptables -C FORWARD -s "$SUB" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -s "$SUB" -j ACCEPT
    iptables -C FORWARD -d "$SUB" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 2 -d "$SUB" -j ACCEPT

    if [[ "${IS_OPENVZ}" == "true" ]]; then
        iptables -t nat -C POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j SNAT --to-source "$SERVER_IP" 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j SNAT --to-source "$SERVER_IP"
        echo "  SNAT: $SUB -> $MAIN_IFACE"
    else
        iptables -t nat -C POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$SUB" -o "$MAIN_IFACE" -j MASQUERADE
        echo "  MASQUERADE: $SUB -> $MAIN_IFACE"
    fi
done

while IFS= read -r ZT_IFACE; do
    [ -z "$ZT_IFACE" ] && continue
    echo "  ZT interface: $ZT_IFACE"
    iptables -C FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$ZT_IFACE" -o "$MAIN_IFACE" -j ACCEPT
    iptables -C FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$MAIN_IFACE" -o "$ZT_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
done < <(ip -o link show | grep -oP 'zt[a-z0-9]+' || true)

iptables -t nat -C POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "$MAIN_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${DOCKER_BRIDGE_SUBNET}" -o "$MAIN_IFACE" -j MASQUERADE

netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "[zt-nat-setup] Правила сохранены для ${#SUBNETS[@]} сетей"
NATEOF2
    chmod +x "${INSTALL_DIR}/zt-nat-setup.sh"
    log "zt-nat-setup.sh перегенерирован (ZT_SUBNET=${ZT_SUBNET})"

    # ── Managed Route: инструкция для ZTNET Panel ─────────────────────────────
    if [[ "${SERVER_ZT_IP}" != "<ZT-IP сервера>" ]]; then
        ZT_IP_ONLY=$(echo "${SERVER_ZT_IP}" | grep -oP '^\d+\.\d+\.\d+\.\d+' || true)
        if [[ -n "${ZT_IP_ONLY}" ]]; then
            echo ""
            echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ (Managed Route):${NC}"
            echo ""
            echo -e "  Добавьте маршрут в ZTNET Panel для раздачи интернета:"
            echo ""
            echo -e "    ${CYAN}${NEXTAUTH_URL}${NC} → Сеть → Managed Routes → Add"
            echo -e "    ${BOLD}Destination:${NC} 0.0.0.0/0"
            echo -e "    ${BOLD}Via:${NC} ${ZT_IP_ONLY}"
            echo ""
            echo -e "  ${YELLOW}ВНИМАНИЕ: Via должен быть IP этой ноды в ДАННОЙ сети${NC}"
            echo -e "  (${ZT_IP_ONLY}), а НЕ IP из другой сети — иначе трафик не пойдёт."
            echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
        fi
    fi

    # ── Проверка маршрутов сети ─────────────────────────────────────────────
    if [[ -n "${ZT_AUTHTOKEN}" ]]; then
        ROUTES_RAW=$(curl -s -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
            "http://localhost:9993/controller/network/${NETWORK_ID}" 2>/dev/null || true)
        if [[ -n "${ROUTES_RAW}" ]]; then
            BAD_ROUTES=$(echo "${ROUTES_RAW}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    zt_ip = '${ZT_IP_ONLY:-}'
    for r in d.get('routes', []):
        via = r.get('via')
        target = r.get('target', '')
        if via and via != zt_ip:
            print(f'WARN: route {target} via {via} — gateway IP not in this network')
        if target == '0.0.0.0/0' and not via:
            print('WARN: default route with via=null will not forward traffic')
except: pass
" 2>/dev/null || true)
            if [[ -n "${BAD_ROUTES}" ]]; then
                warn "Обнаружены потенциально проблемные маршруты:"
                echo "${BAD_ROUTES}" | while read -r line; do warn "  $line"; done
            fi
        fi
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ВЕРИФИКАЦИЯ ПЕРСИСТЕНТНОСТИ
# ╚══════════════════════════════════════════════════════════════════════════════
echo ""
info "Проверка персистентности настроек..."

PERSIST_OK=true

if [[ -f /etc/iptables/rules.v4 ]]; then
    NAT_IN_SAVED=$(grep -c "POSTROUTING.*${ZT_SUBNET}" /etc/iptables/rules.v4 2>/dev/null || echo "0")
    FWD_IN_SAVED=$(grep -c "FORWARD.*${ZT_SUBNET}" /etc/iptables/rules.v4 2>/dev/null || echo "0")
    if [[ "${NAT_IN_SAVED}" -gt 0 && "${FWD_IN_SAVED}" -gt 0 ]]; then
        log "iptables: NAT и FORWARD для ${ZT_SUBNET} сохранены в /etc/iptables/rules.v4"
    else
        warn "iptables: правила для ${ZT_SUBNET} отсутствуют в rules.v4 — пересохраняем..."
        netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        PERSIST_OK=false
    fi
else
    warn "Файл /etc/iptables/rules.v4 не найден — сохраняем..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    PERSIST_OK=false
fi

if systemctl is-enabled zt-nat-setup.service >/dev/null 2>&1; then
    log "systemd: zt-nat-setup.service включён (правила восстановятся при загрузке)"
else
    warn "systemd: zt-nat-setup.service НЕ включён — NAT может не восстановиться"
    PERSIST_OK=false
fi

if [[ -f /etc/sysctl.d/99-zt-forward.conf ]]; then
    log "sysctl: ip_forward сохранён в /etc/sysctl.d/99-zt-forward.conf"
else
    warn "sysctl: /etc/sysctl.d/99-zt-forward.conf не найден"
    PERSIST_OK=false
fi

if readlink /etc/systemd/system/zerotier-one.service 2>/dev/null | grep -q '/dev/null'; then
    log "zerotier-one: замаскирован (не конфликтует с Docker)"
else
    warn "zerotier-one: НЕ замаскирован — может перехватить порт 9993"
    PERSIST_OK=false
fi

for SVC in ztnet ztnet_postgres ztnet_zerotier; do
    RP=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "${SVC}" 2>/dev/null || echo "?")
    if [[ "${RP}" == "unless-stopped" || "${RP}" == "always" ]]; then
        log "Docker: ${SVC} restart policy = ${RP}"
    else
        warn "Docker: ${SVC} restart policy = ${RP} (рекомендуется unless-stopped)"
        PERSIST_OK=false
    fi
done

if $PERSIST_OK; then
    log "Персистентность: ВСЕ настройки переживут перезагрузку"
else
    warn "Персистентность: некоторые настройки могут не пережить перезагрузку"
    tip "Запустите диагностику: sudo bash ${INSTALL_DIR}/zt-diagnose.sh"
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
echo -e "    ZT Subnet           : ${CYAN}${ZT_SUBNET}${NC}"
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
if [[ "${SERVER_ZT_IP}" != "<ZT-IP сервера>" ]]; then
    echo -e "  ${BOLD}${GREEN}Авто-настройка выполнена:${NC}"
    echo -e "    ${GREEN}✓${NC} Нода подключена к сети и авторизована"
    echo -e "    ${GREEN}✓${NC} ZT subnet: ${ZT_SUBNET}"
    echo -e "    ${GREEN}✓${NC} iptables NAT обновлён"
    echo ""
    echo -e "  ${YELLOW}Осталось добавить вручную в ZTNET Panel:${NC}"
    echo -e "    Managed Routes → Add → Destination: ${CYAN}0.0.0.0/0${NC}, Via: ${CYAN}$(echo "${SERVER_ZT_IP}" | grep -oP '^\d+\.\d+\.\d+\.\d+')${NC}"
    echo ""
fi
echo -e "  ${BOLD}На клиентах для доступа в интернет:${NC}"
echo -e "     ${CYAN}zerotier-cli set <NETWORK_ID> allowDefault=1${NC}"
echo -e "     ${CYAN}или в настройках ZeroTier включите Allow Default Route${NC}"
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "    Статус       : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml ps${NC}"
echo -e "    ZT сети      : ${CYAN}docker exec ztnet_zerotier zerotier-cli listnetworks${NC}"
echo -e "    ZT пиров     : ${CYAN}docker exec ztnet_zerotier zerotier-cli listpeers${NC}"
echo -e "    NAT настройки: ${CYAN}${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo ""
sep