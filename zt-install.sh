#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Auto Installer
#  Tested on: Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12
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

# ── /dev/net/tun pre-check ───────────────────────────────────────────────────
if [[ ! -c /dev/net/tun ]]; then
    info "Создаём /dev/net/tun (требуется для ZeroTier в Docker)..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    modprobe tun 2>/dev/null || true
    if [[ ! -c /dev/net/tun ]]; then
        err "/dev/net/tun недоступен — ZeroTier не запустится в Docker"
    fi
fi
log "/dev/net/tun доступен"

sep
echo -e "${BOLD}   ZeroTier + ZTNET Panel Installer${NC}"
sep

# ── Определяем IP сервера ─────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
info "Обнаружен IP сервера: ${BOLD}${SERVER_IP}${NC}"

# ── Параметры ZTNET (можно переопределить через env до запуска скрипта) ───────
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

# ── 1. Обновление пакетов ─────────────────────────────────────────────────────
sep; info "Шаг 1/5 — Обновление системы"
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg lsb-release openssl
log "Система обновлена"

# ── 2. ZeroTier ───────────────────────────────────────────────────────────────
sep; info "Шаг 2/5 — Установка ZeroTier"

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
    warn "Порт 9993/udp занят (возможно, системный zerotier-one)"
    if systemctl is-active --quiet zerotier-one 2>/dev/null; then
        info "Останавливаем системный zerotier-one..."
        systemctl stop zerotier-one
        systemctl disable zerotier-one
        log "Системный zerotier-one остановлен"
    fi
fi

# ── 3. Docker ─────────────────────────────────────────────────────────────────
sep; info "Шаг 3/5 — Установка Docker"

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

# Проверка docker compose (plugin)
if docker compose version &>/dev/null; then
    log "Docker Compose: $(docker compose version)"
elif command -v docker-compose &>/dev/null; then
    log "docker-compose: $(docker-compose --version)"
    # Создадим алиас для единообразия
    ln -sf "$(command -v docker-compose)" /usr/local/bin/docker-compose 2>/dev/null || true
else
    info "Устанавливаем Docker Compose plugin..."
    apt-get install -y -qq docker-compose-plugin
    log "Docker Compose plugin установлен"
fi

# ── 4. Создание docker-compose.yml для ZTNET ──────────────────────────────────
sep; info "Шаг 4/5 — Настройка ZTNET"

mkdir -p "${INSTALL_DIR}"

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
    devices:
      - /dev/net/tun:/dev/net/tun
    networks:
      - app-network
    ports:
      - "9993:9993/udp"
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
        - subnet: 172.31.255.0/29
EOF

log "docker-compose.yml создан в ${INSTALL_DIR}"

# Сохраняем секреты в отдельный файл
cat > "${INSTALL_DIR}/.env.info" <<EOF
# ZTNET Installation info — $(date)
SERVER_IP=${SERVER_IP}
ZTNET_URL=${NEXTAUTH_URL}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NEXTAUTH_SECRET=${NEXTAUTH_SECRET}
INSTALL_DIR=${INSTALL_DIR}
EOF
chmod 600 "${INSTALL_DIR}/.env.info"
log "Секреты сохранены в ${INSTALL_DIR}/.env.info"

# ── 5. Запуск ZTNET ───────────────────────────────────────────────────────────
sep; info "Шаг 5/5 — Запуск ZTNET (docker compose pull + up)"

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
    err "Контейнер zerotier не получил IP в сети. Возможно, конфликт портов."
fi
log "  zerotier IP: ${ZT_IP}"

log "Проверка DNS-резолвинга между контейнерами..."
if docker exec ztnet sh -c 'getent hosts zerotier' &>/dev/null; then
    log "  DNS OK (ztnet → zerotier)"
else
    err "DNS-резолвинг между контейнерами не работает. Проверьте network."
fi

log "Проверка API zerotier из контейнера ztnet..."
if docker exec ztnet node -e 'http.get("http://zerotier:9993/controller/network", r => process.exit(r.statusCode === 200 ? 0 : 1)).on("error",()=>process.exit(1))' &>/dev/null; then
    log "  API zerotier доступен из ztnet"
else
    warn "API zerotier недоступен из ztnet. Проверьте сеть."
fi

# ── Итог ──────────────────────────────────────────────────────────────────────
sep
echo ""
echo -e "${BOLD}${GREEN}  ✅  Установка завершена!${NC}"
echo ""
echo -e "  🌐 Веб-панель ZTNET   : ${BOLD}${NEXTAUTH_URL}${NC}"
echo -e "  📂 Директория         : ${BOLD}${INSTALL_DIR}${NC}"
echo -e "  🔐 Секреты            : ${BOLD}${INSTALL_DIR}/.env.info${NC}"
echo ""
echo -e "  ${YELLOW}⚠ Первый зарегистрированный пользователь получит права администратора${NC}"
echo ""
echo -e "  Полезные команды:"
echo -e "    Логи ZTNET   : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f ztnet${NC}"
echo -e "    Статус       : ${CYAN}docker compose -f ${INSTALL_DIR}/docker-compose.yml ps${NC}"
echo -e "    Обновить     : ${CYAN}cd ${INSTALL_DIR} && docker compose pull && docker compose up -d${NC}"
echo -e "    ZeroTier CLI : ${CYAN}zerotier-cli info${NC}"
echo ""
sep