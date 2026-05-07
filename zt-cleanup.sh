#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET Panel — Full Cleanup
#  Полная очистка: контейнеры, volumes, образы, компоуз, identity
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
sep()  { echo -e "${CYAN}------------------------------------------------------${NC}"; }

[[ $EUID -ne 0 ]] && err "Запустите от root: sudo bash $0"

sep
echo -e "${BOLD}   ZeroTier + ZTNET — Полная очистка${NC}"
sep

INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"

echo ""
warn "Будут удалены:"
echo "  - Все Docker контейнеры ZTNET"
echo "  - Все Docker volumes (identity, БД, конфиги)"
echo "  - ZeroTier systemd сервис (если установлен)"
echo "  - iptables правила NAT для ZT"
echo "  - Директория ${INSTALL_DIR}"
echo "  - systemd zt-nat-setup.service"
echo "  - /etc/sysctl.d/99-zt-forward.conf"
echo ""

# ── Подтверждение ──────────────────────────────────────────────────────────
echo -n "Продолжить? (y/N): "
read -r CONFIRM
[[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]] && echo "Отменено" && exit 0

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  1. Docker Compose down with volumes
# ╚══════════════════════════════════════════════════════════════════════════════
sep; echo ""

if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
    log "Останавливаем и удаляем контейнеры с volumes..."
    docker compose -f "${INSTALL_DIR}/docker-compose.yml" down --volumes --remove-orphans 2>&1 || true
    log "Контейнеры и volumes удалены"
else
    warn "docker-compose.yml не найден — удаляем контейнеры вручную"
    for c in ztnet ztnet_postgres ztnet_zerotier; do
        docker rm -f "$c" 2>/dev/null || true
    done
    for v in ztnet_postgres-data ztnet_zerotier; do
        docker volume rm -f "$v" 2>/dev/null || true
    done
    log "Контейнеры и volumes удалены вручную"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  2. Удаление образов
# ╚══════════════════════════════════════════════════════════════════════════════
sep; echo ""
log "Удаляем Docker образы..."
for img in sinamics/ztnet:latest zyclonite/zerotier:1.14.2 postgres:15.2-alpine; do
    docker rmi -f "$img" 2>/dev/null && log "  $img удалён" || true
done

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  3. ZeroTier systemd сервис (хостовой)
# ╚══════════════════════════════════════════════════════════════════════════════
sep; echo ""
if systemctl is-active --quiet zerotier-one 2>/dev/null; then
    log "Останавливаем хостовой zerotier-one..."
    systemctl stop zerotier-one
    systemctl disable zerotier-one 2>/dev/null || true
    log "  zerotier-one остановлен"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  4. iptables NAT правила для ZT
# ╚══════════════════════════════════════════════════════════════════════════════
sep; echo ""
log "Удаляем iptables правила ZT..."
RULES=$(iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep -E '10\.121\.15\.|172\.31\.255\.' | sort -rn | awk '{print $1}' || true)
for n in $RULES; do
    iptables -t nat -D POSTROUTING "$n" 2>/dev/null || true
done
for chain in FORWARD DOCKER-USER; do
    RULES=$(iptables -L "$chain" -n --line-numbers 2>/dev/null | grep -E '10\.121\.15\.|172\.31\.255\.' | sort -rn | awk '{print $1}' || true)
    for n in $RULES; do
        iptables -D "$chain" "$n" 2>/dev/null || true
    done
done
iptables -D FORWARD -s 10.121.15.0/24 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d 10.121.15.0/24 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -s 172.31.255.0/29 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d 172.31.255.0/29 -j ACCEPT 2>/dev/null || true

# UFW before.rules
rm -f /etc/ufw/before.rules.d/zt-forward.rules 2>/dev/null || true
rm -f /etc/ufw/before.rules.d/zt-nat.rules 2>/dev/null || true
if command -v ufw &>/dev/null; then
    ufw reload 2>/dev/null || true
fi

netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "iptables правила очищены и сохранены"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  5. Удаление файлов и systemd сервисов
# ╚══════════════════════════════════════════════════════════════════════════════
sep; echo ""
log "Удаляем файлы конфигурации..."

rm -f /etc/systemd/system/zt-nat-setup.service 2>/dev/null || true
rm -f /etc/sysctl.d/99-zt-forward.conf 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

if [[ -d "${INSTALL_DIR}" ]]; then
    rm -rf "${INSTALL_DIR}" 2>/dev/null && log "  ${INSTALL_DIR} удалён"
fi

log "Файлы конфигурации удалены"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  6. ИТОГ + напоминание
# ╚══════════════════════════════════════════════════════════════════════════════
sep
echo ""
echo -e "${BOLD}${GREEN}  Очистка завершена!${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}ВАЖНО: ОЧИСТИТЕ БРАУЗЕР${NC}"
echo ""
echo -e "  Сессия ZTNET зашифрована старым NEXTAUTH_SECRET."
echo -e "  После новой установки панель не сможет расшифровать"
echo -e "  старую сессию и будет выдавать ошибки JWT."
echo ""
echo -e "  ${GREEN}Сделайте в браузере:${NC}"
echo -e "    ${BOLD}Настройки → Конфиденциальность → Очистить данные сайтов${NC}"
echo -e "    Или: ${BOLD}F12 → Application → Clear site data${NC}"
echo -e "    Или: ${BOLD}Стереть куки для домена сервера${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}После очистки браузера запустите установку заново:${NC}"
echo -e "    sudo bash zt-install.sh"
echo ""
sep

[[ $? -eq 0 ]] || true
