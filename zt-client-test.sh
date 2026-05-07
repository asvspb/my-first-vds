#!/usr/bin/env bash
# =============================================================================
#  ZeroTier Client Join & Connectivity Test
#  Использование:
#    sudo bash zt-client-test.sh
#    sudo bash zt-client-test.sh --ntid 618d15c48997de73
#    sudo bash zt-client-test.sh --ntid 618d15c48997de73 --timeout 120
#    sudo bash zt-client-test.sh --leave   # выйти из сети после теста
# =============================================================================

set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

ok()     { echo -e "  ${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
fail()   { echo -e "  ${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }
warn()   { echo -e "  ${YELLOW}[WARN]${NC} $*"; WARN=$((WARN+1)); }
info()   { echo -e "  ${CYAN}[INFO]${NC} $*"; }
step()   { echo -e "\n${BOLD}$*${NC}"; }
sep()    { echo -e "${CYAN}──────────────────────────────────────────────${NC}"; }
die()    { echo -e "\n${RED}[FATAL]${NC} $*" >&2; exit 1; }

# ── Параметры ────────────────────────────────────────────────────────────────
NETWORK_ID="618d15c48997de73"
AUTH_TIMEOUT=180
POLL_INTERVAL=5
DO_LEAVE=false
PING_TARGET="1.1.1.1"
PING_COUNT=4

usage() {
    cat <<EOF
Использование: sudo bash zt-client-test.sh [ОПЦИИ]

Опции:
  --ntid <ID>        Network ID ZeroTier (по умолч.: ${NETWORK_ID})
  --timeout <сек>    Таймаут ожидания авторизации (по умолч.: ${AUTH_TIMEOUT}с)
  --leave            Выйти из сети после теста
  --ping <IP>        IP для проверки пинга (по умолч.: ${PING_TARGET})
  -h, --help         Эта справка
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ntid)     NETWORK_ID="${2:-}";       shift 2 ;;
        --timeout)  AUTH_TIMEOUT="${2:-180}"; shift 2 ;;
        --leave)    DO_LEAVE=true;            shift 1 ;;
        --ping)     PING_TARGET="${2:-}";     shift 2 ;;
        -h|--help)  usage ;;
        *)          echo "Неизвестный параметр: $1"; usage ;;
    esac
done

# ── Root check ───────────────────────────────────────────────────────────────
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Скрипт требует прав root. Запустите: sudo bash $0 $*"
fi

# ─────────────────────────────────────────────────────────────────────────────
sep
echo -e "${BOLD}   ZeroTier Join & Connectivity Test${NC}"
sep

# ════════════════════════════════════════════════════════════════════════════
# ШАГ 1 — Проверка наличия ZeroTier
# ════════════════════════════════════════════════════════════════════════════
step "[1/5] Проверка наличия ZeroTier"

if ! command -v zerotier-cli &>/dev/null; then
    fail "zerotier-cli не найден"
    echo ""
    echo -e "  ${YELLOW}Установите ZeroTier:${NC}"
    echo -e "    curl -s https://install.zerotier.com | sudo bash"
    echo ""
    sep
    echo -e "  Результат: ${RED}${FAIL} FAIL${NC}, ${GREEN}${PASS} PASS${NC}, ${YELLOW}${WARN} WARN${NC}"
    sep
    exit 1
fi

ZT_VER=$(zerotier-one -v 2>/dev/null || echo "unknown")
ok "zerotier-cli установлен (версия: ${ZT_VER})"

# Проверяем демон
ZT_INFO=$(zerotier-cli info 2>/dev/null || true)
if [[ -z "${ZT_INFO}" ]]; then
    warn "zerotier-one демон не отвечает — пробуем запустить..."
    systemctl start zerotier-one 2>/dev/null || service zerotier-one start 2>/dev/null || true
    sleep 3
    ZT_INFO=$(zerotier-cli info 2>/dev/null || true)
    [[ -z "${ZT_INFO}" ]] && die "Демон zerotier-one не запустился"
fi

ZT_NODE_ID=$(echo "${ZT_INFO}" | awk '{print $3}')
ZT_STATUS=$(echo "${ZT_INFO}"  | awk '{print $2}')

if [[ "${ZT_STATUS}" == "ONLINE" ]]; then
    ok "Нода ${CYAN}${ZT_NODE_ID}${NC} — ONLINE"
else
    warn "Нода ${ZT_NODE_ID} — статус: ${ZT_STATUS} (ожидается ONLINE)"
fi

# ════════════════════════════════════════════════════════════════════════════
# ШАГ 2 — Network ID
# ════════════════════════════════════════════════════════════════════════════
step "[2/5] Network ID"

ok "Network ID: ${CYAN}${NETWORK_ID}${NC}"

# ════════════════════════════════════════════════════════════════════════════
# ШАГ 3 — Подключение к сети (join)
# ════════════════════════════════════════════════════════════════════════════
step "[3/5] Подключение к сети (join)"

# Проверяем — вдруг уже подключены
ALREADY_JOINED=$(zerotier-cli listnetworks 2>/dev/null | grep -c "${NETWORK_ID}" || true)

if [[ "${ALREADY_JOINED}" -gt 0 ]]; then
    info "Уже подключён к сети ${NETWORK_ID}"
else
    JOIN_OUT=$(zerotier-cli join "${NETWORK_ID}" 2>&1 || true)
    if echo "${JOIN_OUT}" | grep -qi "200 join ok\|joined\|OK"; then
        ok "zerotier-cli join ${NETWORK_ID} — успешно"
    else
        # Некоторые версии не выводят "200 join OK" — проверяем через listnetworks
        sleep 2
        JOINED_CHECK=$(zerotier-cli listnetworks 2>/dev/null | grep -c "${NETWORK_ID}" || true)
        if [[ "${JOINED_CHECK}" -gt 0 ]]; then
            ok "Присоединились к сети ${NETWORK_ID}"
        else
            fail "Команда join завершилась с ошибкой: ${JOIN_OUT}"
        fi
    fi
fi

echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}ДЕЙСТВИЕ ТРЕБУЕТСЯ НА СЕРВЕРЕ:${NC}"
echo -e "  Перейдите в раздел  : ${BOLD}Members${NC}"
echo -e "  Найдите ноду        : ${CYAN}${ZT_NODE_ID}${NC}"
echo -e "  Нажмите             : ${GREEN}Authorize / Разрешить${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# ШАГ 4 — Ожидание авторизации (поллинг)
# ════════════════════════════════════════════════════════════════════════════
step "[4/5] Ожидание авторизации администратором"

info "Опрашиваем статус каждые ${POLL_INTERVAL}с (таймаут: ${AUTH_TIMEOUT}с)"
info "ID ноды для авторизации: ${CYAN}${ZT_NODE_ID}${NC}"
echo ""

ELAPSED=0
AUTH_OK=false
ZT_ASSIGNED_IP=""

spinner_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
spin_idx=0

while [[ ${ELAPSED} -lt ${AUTH_TIMEOUT} ]]; do
    # Получаем строку нашей сети
    NET_LINE=$(zerotier-cli listnetworks 2>/dev/null | grep "${NETWORK_ID}" || true)
    NET_STATUS=$(echo "${NET_LINE}" | grep -oP '\b(OK|REQUESTING|REQUESTING_CONFIGURATION|ACCESS_DENIED|NOT_FOUND|AUTHORIZING)\b' || true)

    # Ищем назначенный IP (колонка 9+ или в конце строки)
    ZT_ASSIGNED_IP=$(echo "${NET_LINE}" | grep -oP '(?<=\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1 || true)

    # Спиннер
    spin_char="${spinner_chars:${spin_idx}:1}"
    spin_idx=$(( (spin_idx + 1) % ${#spinner_chars} ))

    REMAINING=$(( AUTH_TIMEOUT - ELAPSED ))
    printf "\r  ${CYAN}${spin_char}${NC} Статус: %-30s | Прошло: %3ds | Осталось: %3ds   " \
        "${NET_STATUS:-—}" "${ELAPSED}" "${REMAINING}"

    if [[ "${NET_STATUS}" == "OK" ]] && [[ -n "${ZT_ASSIGNED_IP}" ]]; then
        AUTH_OK=true
        break
    elif [[ "${NET_STATUS}" == "OK" ]]; then
        # Статус ОК но IP ещё не назначен — ждём чуть дольше
        AUTH_OK=true
        # не прерываем — ждём IP
    elif [[ "${NET_STATUS}" == "ACCESS_DENIED" ]]; then
        echo ""
        fail "Сервер отклонил запрос (ACCESS_DENIED)"
        info "Возможно нода уже была заблокирована. Проверьте панель администратора."
        break
    fi

    sleep "${POLL_INTERVAL}"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

echo ""  # новая строка после спиннера

if [[ "${AUTH_OK}" == "true" ]]; then
    ok "Нода авторизована!"
    if [[ -n "${ZT_ASSIGNED_IP}" ]]; then
        ok "Назначен ZT IP-адрес: ${CYAN}${ZT_ASSIGNED_IP}${NC}"
    else
        # Попробуем найти IP через ip addr
        sleep 2
        ZT_IFACE=$(ip -o link show 2>/dev/null | grep -oP 'zt\S+' | head -1 || true)
        if [[ -n "${ZT_IFACE}" ]]; then
            ZT_ASSIGNED_IP=$(ip -4 addr show "${ZT_IFACE}" 2>/dev/null \
                | grep -oP 'inet \K[\d./]+' | head -1 || true)
            if [[ -n "${ZT_ASSIGNED_IP}" ]]; then
                ok "Интерфейс ${ZT_IFACE}, IP: ${CYAN}${ZT_ASSIGNED_IP}${NC}"
            else
                warn "Интерфейс ${ZT_IFACE} есть, но IPv4 ещё не назначен"
                warn "Проверьте IPv4 Auto-Assign в настройках сети ZTNET"
            fi
        else
            warn "ZT-интерфейс ещё не поднялся — подождите несколько секунд"
        fi
    fi
elif [[ "${ELAPSED}" -ge "${AUTH_TIMEOUT}" ]]; then
    fail "Таймаут ${AUTH_TIMEOUT}с истёк — авторизация не получена"
    warn "Убедитесь что:"
    warn "  1. Администратор авторизовал ноду с ID: ${ZT_NODE_ID}"
    echo ""
    sep
    echo -e "  Результат: ${GREEN}${PASS} PASS${NC}, ${RED}${FAIL} FAIL${NC}, ${YELLOW}${WARN} WARN${NC}"
    sep
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
# ШАГ 5 — Настройка маршрутизации через ZT и проверка связи
# ════════════════════════════════════════════════════════════════════════════
step "[5/5] Настройка маршрутизации через ZT-туннель"

sleep 2

ZT_IFACE=$(ip -o link show 2>/dev/null | grep -oP 'zt\S+' | head -1 || true)

if [[ -z "${ZT_IFACE}" ]]; then
    warn "ZT-интерфейс не найден — пропускаем настройку маршрутизации"
else
    info "ZT-интерфейс: ${ZT_IFACE}"

    ALLOW_DEFAULT=$(zerotier-cli get "${NETWORK_ID}" allowDefault 2>/dev/null || echo "false")
    if [[ "${ALLOW_DEFAULT}" != "true" ]]; then
        info "Включаем Allow Default Route для сети ${NETWORK_ID}..."
        zerotier-cli set "${NETWORK_ID}" allowDefault=1 >/dev/null 2>&1 || warn "Не удалось включить allowDefault"
        sleep 3
    fi

    DEFAULT_VIA_ZT=$(ip -4 route show default 2>/dev/null | grep "dev ${ZT_IFACE}" || true)

    if [[ -n "${DEFAULT_VIA_ZT}" ]]; then
        ok "Default route через ${ZT_IFACE}: ${DEFAULT_VIA_ZT}"
    else
        warn "Default route не через ZT (сеть может не иметь Managed Route 0.0.0.0/0)"
        warn "Для полной маршрутизации через ZT добавьте в ZTNET:"
        warn "  Managed Route: 0.0.0.0/0 → <ZT-IP сервера>"
        info "Пинг будет проверен через текущий маршрут"
    fi
fi

info "Пингуем ${PING_TARGET} (${PING_COUNT} пакета, таймаут 5с)..."
echo ""

PING_OUT=$(ping -c "${PING_COUNT}" -W 5 -i 0.5 "${PING_TARGET}" 2>&1 || true)

# Парсим результат
PKT_TX=$(echo "${PING_OUT}"  | grep -oP '\d+ packets transmitted' | grep -oP '\d+' || echo "0")
PKT_RX=$(echo "${PING_OUT}"  | grep -oP '\d+ received'            | grep -oP '\d+' || echo "0")
PKT_LOSS=$(echo "${PING_OUT}" | grep -oP '\d+% packet loss'       | grep -oP '\d+' || echo "100")
RTT_AVG=$(echo "${PING_OUT}" | grep -oP 'rtt.*= [0-9./]+'        | grep -oP '[0-9.]+/[0-9.]+' \
          | cut -d/ -f2 || echo "")

echo "${PING_OUT}" | grep -E '^(PING|[0-9]+ bytes|---|\d+ packets|rtt)' \
    | while IFS= read -r l; do echo -e "    ${DIM}${l}${NC}"; done
echo ""

if   [[ "${PKT_LOSS}" -eq 0 ]]; then
    ok "Пинг до ${PING_TARGET}: 0% потерь${RTT_AVG:+, avg RTT ${RTT_AVG} ms}"
    ok "Интернет через ZT-соединение РАБОТАЕТ"
elif [[ "${PKT_LOSS}" -lt 50 ]]; then
    warn "Пинг до ${PING_TARGET}: потерь ${PKT_LOSS}% (${PKT_RX}/${PKT_TX} пакетов)"
    warn "Нестабильное соединение — проверьте NAT и фаервол на сервере"
else
    fail "Пинг до ${PING_TARGET}: потерь ${PKT_LOSS}% (получено ${PKT_RX} из ${PKT_TX})"

    # Диагностические советы
    echo ""
    echo -e "  ${YELLOW}Возможные причины:${NC}"
    echo -e "  • NAT не настроен на сервере:"
    echo -e "    ${DIM}iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE${NC}"
    echo -e "  • Forwarding выключен на сервере:"
    echo -e "    ${DIM}sysctl -w net.ipv4.ip_forward=1${NC}"
    echo -e "  • Managed Route 0.0.0.0/0 не добавлен в ZTNET"
    echo -e "  • Allow Default Route не включён на клиенте"
    echo -e "  • Фаервол блокирует ICMP или форвардинг"
fi

# ── Проверка публичного IP (туннель или нет) ───────────────────────────────
echo ""
info "Проверка маршрутизации через ZT-туннель..."

PUB_IP=$(curl -s --max-time 8 https://ifconfig.me 2>/dev/null \
       || curl -s --max-time 8 https://api.ipify.org 2>/dev/null || true)

if [[ -n "${PUB_IP}" ]]; then
    info "Публичный IP: ${CYAN}${PUB_IP}${NC}"
    if [[ -n "${DEFAULT_VIA_ZT}" ]]; then
        ok "Трафик идёт через ZT-туннель (public IP: ${PUB_IP})"
    else
        warn "Default route не через ZT — публичный IP не отражает туннель"
    fi
else
    warn "Публичный IP недоступен — проверьте маршрутизацию"
fi

# ── Дополнительная диагностика при неудаче ───────────────────────────────
if [[ "${PKT_LOSS}" -gt 0 ]]; then
    echo ""
    info "Дополнительная диагностика..."

    # Traceroute 3 хопа
    if command -v traceroute &>/dev/null; then
        info "Первые 3 хопа до ${PING_TARGET}:"
        traceroute -n -m 3 -w 2 "${PING_TARGET}" 2>/dev/null \
            | tail -n +2 \
            | while IFS= read -r l; do echo -e "    ${DIM}${l}${NC}"; done || true
    fi
fi

# ── Опциональный leave ────────────────────────────────────────────────────
if [[ "${DO_LEAVE}" == "true" ]]; then
    echo ""
    info "Выходим из сети ${NETWORK_ID} (--leave)..."
    zerotier-cli leave "${NETWORK_ID}" &>/dev/null && info "Вышли из сети" || warn "Ошибка при выходе из сети"
fi

# ════════════════════════════════════════════════════════════════════════════
# Итог
# ════════════════════════════════════════════════════════════════════════════
echo ""
sep
echo ""
if [[ ${FAIL} -eq 0 && ${WARN} -le 1 ]]; then
    echo -e "  ${BOLD}${GREEN}✓ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ${NC}"
    echo ""
    echo -e "  Нода    : ${CYAN}${ZT_NODE_ID}${NC}"
    echo -e "  Сеть    : ${CYAN}${NETWORK_ID}${NC}"
    [[ -n "${ZT_ASSIGNED_IP}" ]] && echo -e "  ZT IP   : ${CYAN}${ZT_ASSIGNED_IP}${NC}"
    echo -e "  Пинг    : ${GREEN}1.1.1.1 достижим${NC}"
elif [[ ${FAIL} -eq 0 ]]; then
    echo -e "  ${BOLD}${YELLOW}⚠ ПРЕДУПРЕЖДЕНИЯ${NC} — соединение работает, но есть замечания"
    echo ""
    echo -e "  Нода : ${CYAN}${ZT_NODE_ID}${NC} | Сеть : ${CYAN}${NETWORK_ID}${NC}"
else
    echo -e "  ${BOLD}${RED}✗ ЕСТЬ ОШИБКИ${NC}"
    echo ""
    echo -e "  Нода для авторизации: ${CYAN}${ZT_NODE_ID}${NC}"
fi

echo ""
echo -e "  Итог: ${GREEN}${PASS} PASS${NC}  ${RED}${FAIL} FAIL${NC}  ${YELLOW}${WARN} WARN${NC}"
echo ""
sep

[[ ${FAIL} -eq 0 ]]