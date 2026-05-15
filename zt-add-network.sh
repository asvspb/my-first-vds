#!/usr/bin/env bash
# =============================================================================
#  ZeroTier — Добавление новой сети к существующей установке ZTNET
#  Предусловие: zt-install.sh уже выполнен, контейнеры работают
#
#  Функционал:
#    1. Проверка состояния контейнеров и .env.info
#    2. Join новой сети через zerotier-cli
#    3. Само-авторизация через Controller API
#    4. Ожидание назначения ZT-IP
#    5. Определение реального subnet новой сети
#    6. Настройка iptables NAT/FORWARD для нового subnet
#    7. Обновление .env.info и zt-nat-setup.sh (все сети)
#    8. Инструкция по Managed Route
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[->]${NC} $*"; }
sep()  { echo -e "${CYAN}------------------------------------------------------${NC}"; }

[[ $EUID -ne 0 ]] && err "Запустите скрипт от root: sudo bash $0"

sep
echo -e "${BOLD}   ZeroTier — Добавление новой сети${NC}"
sep

INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"
ENV_FILE="${INSTALL_DIR}/.env.info"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ПРОВЕРКА ПРЕДПОСЫЛОК
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Проверка предпосылок..."

if ! docker ps --format '{{.Names}}' | grep -q 'ztnet_zerotier'; then
    err "Контейнер ztnet_zerotier не запущен. Сначала выполните zt-install.sh"
fi

if [[ ! -f "${ENV_FILE}" ]]; then
    err "Файл ${ENV_FILE} не найден. Сначала выполните zt-install.sh"
fi

source "${ENV_FILE}"

MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1)}"
MAIN_IFACE="${MAIN_IFACE:-$(ip -4 route show default | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
[[ -z "${MAIN_IFACE}" ]] && err "Не удалось определить основной сетевой интерфейс"

ZT_AUTHTOKEN=$(docker exec ztnet_zerotier cat /var/lib/zerotier-one/authtoken.secret 2>/dev/null | tr -d '[:space:]' || true)
ZT_ADDR=$(docker exec ztnet_zerotier zerotier-cli info 2>/dev/null | awk '{print $3}' || true)

[[ -z "${ZT_AUTHTOKEN}" ]] && err "Не удалось получить authtoken.secret из контейнера"
[[ -z "${ZT_ADDR}" ]] && err "Не удалось получить ZeroTier node address"

log "Контейнер ztnet_zerotier работает"
log "ZeroTier node: ${ZT_ADDR}"
log "Основной интерфейс: ${MAIN_IFACE}"

# ── Показать существующие сети ────────────────────────────────────────────────
echo ""
info "Текущие сети ZeroTier:"
docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null || true
echo ""

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ВВОД NETWORK ID
# ╚══════════════════════════════════════════════════════════════════════════════
sep
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Вставьте Network ID новой сети и нажмите Enter:${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -r NETWORK_ID
NETWORK_ID="${NETWORK_ID// /}"

[[ -z "${NETWORK_ID}" ]] && err "Network ID не введён"
[[ "${#NETWORK_ID}" -ne 16 ]] && warn "Network ID обычно 16 символов. Продолжаем..."

# Проверка: уже подключены?
if docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null | grep -q "${NETWORK_ID}"; then
    warn "Нода уже подключена к сети ${NETWORK_ID}"
    echo -n "Продолжить настройку NAT? (y/N): "
    read -r CONFIRM
    [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]] && echo "Отменено" && exit 0
else
    # ╔══════════════════════════════════════════════════════════════════════════
    # ║  ПОДКЛЮЧЕНИЕ К СЕТИ
    # ╚══════════════════════════════════════════════════════════════════════════
    sep; info "Подключение к сети ${NETWORK_ID}..."

    docker exec ztnet_zerotier zerotier-cli join "${NETWORK_ID}" || err "Не удалось подключиться к сети ${NETWORK_ID}"
    log "Команда join выполнена"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  САМО-АВТОРИЗАЦИЯ ЧЕРЕЗ CONTROLLER API
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Само-авторизация ноды ${ZT_ADDR}..."

AUTH_RESPONSE=$(curl -s -X POST \
    -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"authorized": true}' \
    "http://localhost:9993/controller/network/${NETWORK_ID}/member/${ZT_ADDR}" 2>/dev/null || true)

if echo "${AUTH_RESPONSE}" | grep -q '"authorized"'; then
    log "Нода ${ZT_ADDR} авторизована в сети ${NETWORK_ID}"
else
    warn "Авто-авторизация не удалась: ${AUTH_RESPONSE:-пусто}"
    warn "Авторизуйте вручную в ZTNET Panel → Сеть → Members → Auth"

    echo ""
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ:${NC}"
    echo -e "  Авторизуйте ноду ${CYAN}${ZT_ADDR}${NC} в панели:"
    echo -e "    ${CYAN}${ZTNET_URL}${NC} → Сеть → Members → ${BOLD}Auth${NC}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -n "Нажмите Enter после авторизации..."
    read -r
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ОЖИДАНИЕ ZT-IP
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Ожидание назначения ZT-IP..."

NEW_ZT_IP=""
for i in $(seq 1 30); do
    echo -ne "\r  Ожидание ZT-IP... ($i/30)"
    NEW_ZT_IP=$(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null \
        | grep "${NETWORK_ID}" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+$' | head -1 || true)
    if [[ -n "${NEW_ZT_IP}" ]]; then
        echo ""
        log "ZT-IP получен: ${NEW_ZT_IP}"
        break
    fi
    sleep 5
done

if [[ -z "${NEW_ZT_IP}" ]]; then
    echo ""
    warn "ZT-IP не получен за 150 сек"
    warn "Проверьте позже: docker exec ztnet_zerotier zerotier-cli listnetworks"
    echo ""
    echo -n "Введите ZT-IP вручную (напр. 10.121.16.1/24) или Enter для выхода: "
    read -r MANUAL_IP
    [[ -z "${MANUAL_IP}" ]] && exit 1
    NEW_ZT_IP="${MANUAL_IP}"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ОПРЕДЕЛЕНИЕ SUBNET НОВОЙ СЕТИ
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Определение subnet новой сети..."

NEW_SUBNET=""
if [[ -n "${ZT_AUTHTOKEN}" ]]; then
    NETWORK_CONFIG=$(curl -s \
        -H "X-ZT1-Auth: ${ZT_AUTHTOKEN}" \
        "http://localhost:9993/controller/network/${NETWORK_ID}" 2>/dev/null || true)

    if [[ -n "${NETWORK_CONFIG}" ]]; then
        NEW_SUBNET=$(echo "${NETWORK_CONFIG}" | grep -oP '"ipRangeStart"\s*:\s*"\K[\d.]+' | head -1 \
            | sed -E 's/\.[0-9]+$/\.0\/24/' || true)

        if [[ -z "${NEW_SUBNET}" ]]; then
            NEW_SUBNET=$(echo "${NETWORK_CONFIG}" | grep -oP '"target"\s*:\s*"\K[\d./]+' | grep -v '0\.0\.0\.0' | head -1 || true)
        fi
    fi
fi

if [[ -z "${NEW_SUBNET}" ]]; then
    NEW_SUBNET=$(echo "${NEW_ZT_IP}" | sed -E 's/\.[0-9]+\/([0-9]+)$/.0\/\1/')
fi

log "Subnet новой сети: ${NEW_SUBNET}"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  НАСТРОЙКА IPTABLES ДЛЯ НОВОГО SUBNET
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Настройка iptables NAT/FORWARD для ${NEW_SUBNET}..."

SERVER_IP="${PUBLIC_IP:-$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
DOCKER_BRIDGE_SUBNET="${DOCKER_BRIDGE_SUBNET:-172.31.255.0/29}"

# NAT
if [[ "${IS_OPENVZ}" == "true" ]]; then
    iptables -t nat -C POSTROUTING -s "${NEW_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}" 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${NEW_SUBNET}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}"
    log "SNAT: ${NEW_SUBNET} -> ${MAIN_IFACE} (src=${SERVER_IP})"
else
    iptables -t nat -C POSTROUTING -s "${NEW_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${NEW_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE
    log "MASQUERADE: ${NEW_SUBNET} -> ${MAIN_IFACE}"
fi

# FORWARD
iptables -C FORWARD -s "${NEW_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s "${NEW_SUBNET}" -j ACCEPT
iptables -C FORWARD -d "${NEW_SUBNET}" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 2 -d "${NEW_SUBNET}" -j ACCEPT

# Все ZT-интерфейсы
while IFS= read -r ZT_IFACE; do
    [[ -z "${ZT_IFACE}" ]] && continue
    iptables -C FORWARD -i "${ZT_IFACE}" -o "${MAIN_IFACE}" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "${ZT_IFACE}" -o "${MAIN_IFACE}" -j ACCEPT
    iptables -C FORWARD -i "${MAIN_IFACE}" -o "${ZT_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "${MAIN_IFACE}" -o "${ZT_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
    log "FORWARD для ${ZT_IFACE} настроен"
done < <(ip -o link show | grep -oP 'zt[a-z0-9]+' || true)

# Persist
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "iptables правила сохранены"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ОБНОВЛЕНИЕ .env.info — СПИСОК ВСЕХ СЕТЕЙ
# ╚══════════════════════════════════════════════════════════════════════════════
sep; info "Обновление конфигурации..."

# Собираем все subnet'ы из текущих iptables правил
ALL_SUBNETS=()
while IFS= read -r line; do
    SUB=$(echo "${line}" | grep -oP 'source \K[\d./]+' || true)
    [[ -n "${SUB}" && "${SUB}" != "${DOCKER_BRIDGE_SUBNET}" ]] && ALL_SUBNETS+=("${SUB}")
done < <(iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E '(MASQUERADE|SNAT)')

# Убираем дубликаты
UNIQ_SUBNETS=()
for s in "${ALL_SUBNETS[@]}"; do
    FOUND=false
    for u in "${UNIQ_SUBNETS[@]}"; do
        [[ "${s}" == "${u}" ]] && FOUND=true && break
    done
    ${FOUND} || UNIQ_SUBNETS+=("${s}")
done

SUBNET_LIST=$(IFS=','; echo "${UNIQ_SUBNETS[*]}")

# Собираем все Network ID
NETWORK_IDS=()
while IFS= read -r line; do
    NID=$(echo "${line}" | awk '{print $3}' || true)
    [[ -n "${NID}" && "${#NID}" -eq 16 ]] && NETWORK_IDS+=("${NID}")
done < <(docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null | tail -n +2)

NETWORK_ID_LIST=$(IFS=','; echo "${NETWORK_IDS[*]}")

cat > "${ENV_FILE}" <<EOF
# ZTNET Installation info - $(date)
SERVER_IP=${SERVER_IP}
MAIN_IFACE=${MAIN_IFACE}
MAIN_IP=${MAIN_IP}
PUBLIC_IP=${PUBLIC_IP:-${SERVER_IP}}
IS_OPENVZ=${IS_OPENVZ:-false}
ZTNET_URL=${ZTNET_URL}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NEXTAUTH_SECRET=${NEXTAUTH_SECRET}
INSTALL_DIR=${INSTALL_DIR}
DOCKER_BRIDGE_SUBNET=${DOCKER_BRIDGE_SUBNET}
DOCKER_BRIDGE_GW=${DOCKER_BRIDGE_GW:-172.31.255.1}
ZT_SUBNET=${ZT_SUBNET:-${NEW_SUBNET}}
ZT_SUBNETS=${SUBNET_LIST}
NETWORK_ID=${NETWORK_IDS[0]:-}
NETWORK_IDS=${NETWORK_ID_LIST}
EOF
chmod 600 "${ENV_FILE}"
log ".env.info обновлён (сетей: ${#NETWORK_IDS[@]})"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  РЕГЕНЕРАЦИЯ zt-nat-setup.sh (ВСЕ СЕТИ)
# ╚══════════════════════════════════════════════════════════════════════════════

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
log "zt-nat-setup.sh перегенерирован (${#UNIQ_SUBNETS[@]} subnet'ов)"

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ИТОГ
# ╚══════════════════════════════════════════════════════════════════════════════
sep
echo ""
echo -e "${BOLD}${GREEN}  Сеть ${NETWORK_ID} добавлена!${NC}"
echo ""
echo -e "  ${BOLD}Параметры новой сети:${NC}"
echo -e "    Network ID   : ${CYAN}${NETWORK_ID}${NC}"
echo -e "    ZT-IP        : ${CYAN}${NEW_ZT_IP}${NC}"
echo -e "    Subnet       : ${CYAN}${NEW_SUBNET}${NC}"
echo ""
echo -e "  ${BOLD}Всего сетей подключено: ${CYAN}${#NETWORK_IDS[@]}${NC}"
docker exec ztnet_zerotier zerotier-cli listnetworks 2>/dev/null || true
echo ""

# Managed Route
ZT_IP_ONLY=$(echo "${NEW_ZT_IP}" | grep -oP '^\d+\.\d+\.\d+\.\d+' || true)
if [[ -n "${ZT_IP_ONLY}" ]]; then
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ (Managed Route):${NC}"
    echo ""
    echo -e "  Для раздачи интернета добавьте маршрут в ZTNET Panel:"
    echo ""
    echo -e "    ${CYAN}${ZTNET_URL}${NC} → Сеть ${NETWORK_ID} → Managed Routes → Add"
    echo -e "    ${BOLD}Destination:${NC} 0.0.0.0/0"
    echo -e "    ${BOLD}Via:${NC} ${ZT_IP_ONLY}"
    echo ""
    echo -e "  ${BOLD}На клиентах:${NC}"
    echo -e "    ${CYAN}zerotier-cli set ${NETWORK_ID} allowDefault=1${NC}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "    Все сети     : ${CYAN}docker exec ztnet_zerotier zerotier-cli listnetworks${NC}"
echo -e "    NAT обновить : ${CYAN}${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo -e "    Добавить ещё : ${CYAN}sudo bash $0${NC}"
echo ""
sep
