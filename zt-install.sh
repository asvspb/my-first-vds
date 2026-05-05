#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Auto Installer
#  Tested on: Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12
# =============================================================================

set -euo pipefail

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
      - postgres
      - zerotier

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
docker compose up -d

# Ждём готовности
info "Ожидаем запуск контейнеров (30 сек)..."
sleep 30

# Проверка статуса
if docker compose ps | grep -q "ztnet.*running\|ztnet.*Up"; then
    log "ZTNET успешно запущен"
else
    warn "Контейнеры могут ещё запускаться. Проверьте: docker compose -f ${INSTALL_DIR}/docker-compose.yml ps"
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