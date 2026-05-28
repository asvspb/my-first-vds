#!/usr/bin/env bash
# =============================================================================
#  ZeroTier + ZTNET — Диагностика и устранение проблем
#  Version: 1.0
#
#  Функционал:
#    1. Полная проверка всех компонентов ZeroTier + ZTNET
#    2. Автоматическое выявление проблем с цветовой индикацией
#    3. Предложения по устранению с готовыми командами
#    4. Интерактивный режим исправления (--fix)
#
#  Использование:
#    sudo bash zt-diagnose.sh              # только диагностика
#    sudo bash zt-diagnose.sh --fix        # диагностика + интерактивное исправление
#    sudo bash zt-diagnose.sh --fix --yes  # диагностика + автоисправление без подтверждения
# =============================================================================

set -euo pipefail

LOCK_FILE="/var/run/ztnet-diagnose.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    echo "Другой экземпляр диагностики уже запущен (PID $(cat /proc/$(fuser "${LOCK_FILE}" 2>/dev/null | awk '{print $1}')/stat 2>/dev/null | awk '{print $1}' 2>/dev/null || echo '?')). Выход."
    exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

log()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $*"; }
fail()  { echo -e "${RED}[XX]${NC} $*"; CRITICAL=$((CRITICAL+1)); }
info()  { echo -e "${CYAN}[>>]${NC} $*"; }
tip()   { echo -e "${MAGENTA}[fix]${NC} $*"; }
sep()   { echo -e "${CYAN}──────────────────────────────────────────────────────${NC}"; }
header() { echo -e "\n${BOLD}${CYAN}[$1]${NC} ${BOLD}$2${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Запустите от root: sudo bash $0"; exit 1; }

FIX_MODE=false
AUTO_YES=false
for arg in "$@"; do
    [[ "${arg}" == "--fix" ]] && FIX_MODE=true
    [[ "${arg}" == "--yes" || "${arg}" == "-y" ]] && AUTO_YES=true
done

CRITICAL=0
WARNINGS=0
INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"
ENV_FILE="${INSTALL_DIR}/.env.info"

sep
echo -e "${BOLD}   ZeroTier + ZTNET — Диагностика${NC} $( $FIX_MODE && echo -e "${YELLOW}[режим исправления]${NC}" || echo "" )"
sep

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ╚══════════════════════════════════════════════════════════════════════════════

ask_fix() {
    $FIX_MODE || return 1
    if $AUTO_YES; then
        echo "  ${YELLOW}Применить исправление? [y/N]: ${NC}y (auto)"
        return 0
    fi
    echo -en "  ${YELLOW}Применить исправление? [y/N]: ${NC}"
    read -r ANSWER
    [[ "${ANSWER}" == "y" || "${ANSWER}" == "Y" ]]
}

inc_warn() { WARNINGS=$((WARNINGS+1)); }

zt_exec() {
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'ztnet_zerotier'; then
        docker exec ztnet_zerotier "$@" 2>/dev/null
    else
        sudo zerotier-cli "$@" 2>/dev/null
    fi
}

zt_is_docker() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'ztnet_zerotier'
}

get_authtoken() {
    if zt_is_docker; then
        docker exec ztnet_zerotier cat /var/lib/zerotier-one/authtoken.secret 2>/dev/null | tr -d '[:space:]'
    else
        tr -d '[:space:]' < /var/lib/zerotier-one/authtoken.secret 2>/dev/null
    fi
}

get_zt_addr() {
    zt_exec zerotier-cli info 2>/dev/null | awk '{print $3}'
}

controller_api() {
    local method="${1:-GET}"
    local path="$2"
    local data="${3:-}"
    local token
    token=$(get_authtoken)
    [[ -z "${token}" ]] && return 1
    if [[ -n "${data}" ]]; then
        curl -s -X "${method}" -H "X-ZT1-Auth: ${token}" -H "Content-Type: application/json" -d "${data}" "http://localhost:9993${path}" 2>/dev/null
    else
        curl -s -H "X-ZT1-Auth: ${token}" "http://localhost:9993${path}" 2>/dev/null
    fi
}

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  1. КОНФЛИКТ ПОРТА 9993
# ╚══════════════════════════════════════════════════════════════════════════════
header "1/11" "Конфликт порта 9993 (системный vs Docker)"

PORT_HOLDERS=$(ss -tlnup 2>/dev/null | grep ':9993 ' || true)
SYS_ZT_ACTIVE=false
systemctl is-active --quiet zerotier-one 2>/dev/null && SYS_ZT_ACTIVE=true
SYS_ZT_MASKED=false
readlink /etc/systemd/system/zerotier-one.service 2>/dev/null | grep -q '/dev/null' && SYS_ZT_MASKED=true

if $SYS_ZT_ACTIVE; then
    fail "Системный zerotier-one АКТИВЕН — займёт порт 9993 и заблокирует Docker-контейнер"
    tip "systemctl stop zerotier-one"
    tip "systemctl disable zerotier-one"
    tip "systemctl mask zerotier-one"
    tip "pkill -9 -x zerotier-one"
    if ask_fix; then
        systemctl stop zerotier-one 2>/dev/null || true
        systemctl disable zerotier-one 2>/dev/null || true
        pkill -9 -x zerotier-one 2>/dev/null || true
        sleep 2
        systemctl mask zerotier-one 2>/dev/null || true
        log "Системный zerotier-one остановлен и замаскирован"
    fi
elif $SYS_ZT_MASKED; then
    log "Системный zerotier-one замаскирован (не запустится)"
elif command -v zerotier-one &>/dev/null; then
    warn "Системный zerotier-one установлен, но не замаскирован — может активироваться"
    tip "systemctl mask zerotier-one"
    inc_warn
    if ask_fix; then
        systemctl mask zerotier-one 2>/dev/null || true
        log "zerotier-one замаскирован"
    fi
else
    log "Системный zerotier-one не установлен — конфликт исключён"
fi

if [[ -n "${PORT_HOLDERS}" ]]; then
    PORT_PID=$(echo "${PORT_HOLDERS}" | grep -oP 'pid=\K\d+' | head -1 || true)
    PORT_COMM=$(cat /proc/"${PORT_PID}"/comm 2>/dev/null || echo "")
    if [[ -z "${PORT_PID}" ]]; then
        PORT_PID=$(echo "${PORT_HOLDERS}" | awk '{for(i=1;i<=NF;i++) if($i~/pid=/) print $i}' | head -1 | cut -d= -f2 || true)
    fi
    if [[ -n "${PORT_PID}" ]]; then
        DOCKER_ZT_PID=$(docker inspect --format '{{.State.Pid}}' ztnet_zerotier 2>/dev/null || echo "")
        if [[ "${PORT_PID}" == "${DOCKER_ZT_PID}" ]] || [[ "${PORT_COMM}" == "zerotier-one" && -n "${DOCKER_ZT_PID}" ]]; then
            log "Порт 9993 занят zerotier-one из контейнера ztnet_zerotier (PID ${PORT_PID}) — корректно"
        else
            fail "Порт 9993 занят процессом ${PORT_COMM} (PID ${PORT_PID}), но это НЕ ztnet_zerotier"
            tip "kill -9 ${PORT_PID}"
            tip "fuser -k 9993/tcp 9993/udp"
            if ask_fix; then
                kill -9 "${PORT_PID}" 2>/dev/null || true
                fuser -k 9993/tcp 9993/udp 2>/dev/null || true
                sleep 2
                log "Процесс завершён, порт освобождён"
            fi
        fi
    fi
else
    if zt_is_docker; then
        warn "Порт 9993 свободен, но контейнер ztnet_zerotier работает — возможно, ещё не привязался"
        tip "Подождите или перезапустите: docker restart ztnet_zerotier"
        inc_warn
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  2. DOCKER КОНТЕЙНЕРЫ
# ╚══════════════════════════════════════════════════════════════════════════════
header "2/11" "Docker-контейнеры ZTNET"

for SVC in ztnet ztnet_postgres ztnet_zerotier; do
    STATUS=$(docker inspect --format '{{.State.Status}}' "${SVC}" 2>/dev/null || echo "missing")
    HEALTH=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "${SVC}" 2>/dev/null || echo "n/a")
    RESTARTS=$(docker inspect --format '{{.RestartCount}}' "${SVC}" 2>/dev/null || echo "?")

    case "${STATUS}" in
        running)
            if [[ "${HEALTH}" == "healthy" ]]; then
                log "${SVC}: running (healthy, restarts: ${RESTARTS})"
            elif [[ "${HEALTH}" == "starting" ]]; then
                warn "${SVC}: running (health: starting...)"
                inc_warn
            else
                warn "${SVC}: running (health: ${HEALTH})"
                inc_warn
            fi
            ;;
        missing)
            fail "${SVC}: КОНТЕЙНЕР НЕ НАЙДЕН"
            tip "docker compose -f ${INSTALL_DIR}/docker-compose.yml up -d"
            ;;
        *)
            fail "${SVC}: ${STATUS} (health: ${HEALTH})"
            tip "docker logs ${SVC} --tail 30"
            tip "docker restart ${SVC}"
            if ask_fix; then
                docker restart "${SVC}" 2>/dev/null || true
                log "${SVC} перезапущен"
            fi
            ;;
    esac

    if [[ "${RESTARTS}" -gt 10 ]] 2>/dev/null; then
        warn "${SVC}: ${RESTARTS} рестартов — возможен crash loop"
        tip "docker logs ${SVC} --tail 50"
        inc_warn
    fi
done

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  3. ZEROTIER DAEMON
# ╚══════════════════════════════════════════════════════════════════════════════
header "3/11" "ZeroTier демон"

ZT_INFO=$(zt_exec zerotier-cli info 2>/dev/null || true)
if [[ -z "${ZT_INFO}" ]]; then
    fail "ZeroTier демон не отвечает"
    tip "docker restart ztnet_zerotier"
    tip "docker logs ztnet_zerotier --tail 30"
    if ask_fix; then
        docker restart ztnet_zerotier 2>/dev/null || true
        sleep 10
        ZT_INFO=$(zt_exec zerotier-cli info 2>/dev/null || true)
        if [[ -n "${ZT_INFO}" ]]; then
            log "ZeroTier запущен: ${ZT_INFO}"
        else
            fail "ZeroTier не запустился после перезапуска"
        fi
    fi
else
    ZT_STATUS=$(echo "${ZT_INFO}" | awk '{for(i=1;i<=NF;i++) if($i~/^(ONLINE|OFFLINE|TUNNELED|DEGRADED)$/) print $i}')
    ZT_ADDR=$(echo "${ZT_INFO}" | awk '{print $3}')
    ZT_VERSION=$(echo "${ZT_INFO}" | awk '{print $4}')
    case "${ZT_STATUS}" in
        ONLINE)
            log "Статус: ONLINE, версия ${ZT_VERSION}, адрес ${ZT_ADDR}"
            ;;
        TUNNELED)
            warn "Статус: TUNNELED — UDP заблокирован, используется TCP-туннель (высокая задержка)"
            tip "UDP порт 9993 заблокирован провайдером или хост-нодой (OpenVZ)"
            tip "Это ограничение контейнера — пинг будет ~100-200мс вместо ~20-50мс"
            inc_warn
            ;;
        OFFLINE)
            warn "Статус: OFFLINE — демон запускается..."
            tip "Подождите 30-60 секунд или перезапустите: docker restart ztnet_zerotier"
            inc_warn
            ;;
        *)
            warn "Статус: ${ZT_STATUS}"
            inc_warn
            ;;
    esac
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  4. TUN/TAP УСТРОЙСТВО
# ╚══════════════════════════════════════════════════════════════════════════════
header "4/11" "TUN/TAP устройство"

if zt_is_docker; then
    TUN_CHECK=$(docker exec ztnet_zerotier ls -la /dev/net/tun 2>/dev/null || true)
    if [[ -n "${TUN_CHECK}" ]]; then
        log "/dev/net/tun доступен в контейнере"
    else
        fail "/dev/net/tun НЕ доступен в контейнере"
        tip "Проверьте devices: /dev/net/tun:/dev/net/tun в docker-compose.yml"
    fi
fi

if [[ -c /dev/net/tun ]]; then
    log "/dev/net/tun существует на хосте"
else
    warn "/dev/net/tun не найден на хосте"
    tip "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun"
    inc_warn
    if ask_fix; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 2>/dev/null || true
        chmod 666 /dev/net/tun 2>/dev/null || true
        log "/dev/net/tun создан"
    fi
fi

ZT_IFACES=$(ip -o link show 2>/dev/null | grep -oP 'zt[a-z0-9]+' || true)
if [[ -n "${ZT_IFACES}" ]]; then
    echo "  ZT-интерфейсы:"
    for IFACE in ${ZT_IFACES}; do
        IFACE_IP=$(ip -4 addr show "${IFACE}" 2>/dev/null | grep -oP 'inet \K[\d./]+' || echo "no IP")
        IFACE_STATE=$(ip -o link show "${IFACE}" 2>/dev/null | grep -oP 'state \K\w+' || echo "?")
        printf "    %-16s %-20s %s\n" "${IFACE}" "${IFACE_IP}" "${IFACE_STATE}"
    done
else
    warn "ZT-интерфейсы не созданы (возможно, нет подключённых сетей)"
    inc_warn
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  5. СЕТИ И МАРШРУТЫ
# ╚══════════════════════════════════════════════════════════════════════════════
header "5/11" "Сети и маршруты"

ZT_ADDR=$(get_zt_addr)
AUTHTOKEN=$(get_authtoken)

NETWORKS_JSON=$(zt_exec zerotier-cli -j listnetworks 2>/dev/null || echo "[]")
NETWORK_COUNT=$(echo "${NETWORKS_JSON}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null | tr -d '\n' || echo "0")

if [[ "${NETWORK_COUNT}" -eq 0 ]]; then
    warn "Нет подключённых сетей"
    tip "docker exec ztnet_zerotier zerotier-cli join <NETWORK_ID>"
    inc_warn
else
    echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
nets = json.load(sys.stdin)
for n in nets:
    status = n.get('status', '?')
    nwid = n.get('id', '?')
    name = n.get('name', '?')
    ips = ', '.join(n.get('assignedAddresses', [])) or 'no IP'
    dev = n.get('portDeviceName', '?')
    routes = n.get('routes', [])
    default_via = next((r.get('via') for r in routes if r.get('target') == '0.0.0.0/0'), None)

    if status == 'OK':
        prefix = '\033[0;32m[OK] '
    elif status == 'NOT_FOUND':
        prefix = '\033[0;31m[XX] '
    else:
        prefix = '\033[1;33m[!!] '

    print(f'{prefix}{nwid} ({name}): {status} dev={dev} ip={ips}\033[0m')
    if default_via:
        print(f'     default route via {default_via}')
    for r in routes:
        t = r.get('target','')
        v = r.get('via','')
        if t != '0.0.0.0/0':
            print(f'     route: {t} via {v}')
" 2>/dev/null || warn "Не удалось распарсить список сетей"

    DEFAULT_ROUTE_VIAS=$(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
nets = json.load(sys.stdin)
for n in nets:
    if n.get('status') != 'OK':
        continue
    for r in n.get('routes', []):
        if r.get('target') == '0.0.0.0/0' and r.get('via'):
            print(f\"{n['id']} ({n.get('name','?')}) via {r['via']}\")
" 2>/dev/null || true)
    DEFAULT_ROUTE_COUNT=$(echo "${DEFAULT_ROUTE_VIAS}" | grep -c 'via' 2>/dev/null) || DEFAULT_ROUTE_COUNT=0

    if [[ "${DEFAULT_ROUTE_COUNT}" -gt 1 ]]; then
        fail "КОНФЛИКТ: ${DEFAULT_ROUTE_COUNT} сети имеют маршрут 0.0.0.0/0!"
        echo "${DEFAULT_ROUTE_VIAS}" | while read -r line; do fail "  $line"; done
        tip "Оставьте 0.0.0.0/0 только в ОДНОЙ сети (Exit-node)"
        tip "Остальные сети используйте как Transport/Mesh (без default route)"
        tip "Удалите маршрут 0.0.0.0/0 через ZTNET Panel или Controller API"
    elif [[ "${DEFAULT_ROUTE_COUNT}" -eq 1 ]]; then
        log "Default route (0.0.0.0/0): ровно 1 сеть — корректно"
        echo "${DEFAULT_ROUTE_VIAS}" | while read -r line; do info "  $line"; done
    fi

    if [[ -n "${AUTHTOKEN}" && -n "${ZT_ADDR}" ]]; then
        echo ""
        info "Проверка маршрутов (Controller API)..."
        for NWID in $(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n.get('status') == 'OK':
        print(n['id'])
" 2>/dev/null); do
            ROUTES_CHECK=$(controller_api GET "/controller/network/${NWID}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    pool = d.get('ipAssignmentPools', [{}])
    pool_start = pool[0].get('ipRangeStart', '') if pool else ''
    prefix = '.'.join(pool_start.split('.')[:3]) + '.'
    routes = d.get('routes', [])
    for r in routes:
        via = r.get('via')
        target = r.get('target', '')
        if via and not via.startswith(prefix):
            print(f'BAD_ROUTE|{target}|{via}|{prefix}0/24')
        if target == '0.0.0.0/0' and not via:
            print('NO_DEFAULT_GW')
        if target == '0.0.0.0/0' and via and via.startswith(prefix):
            print(f'OK_DEFAULT|{via}')
except: pass
" 2>/dev/null || true)
            if [[ -n "${ROUTES_CHECK}" ]]; then
                while IFS= read -r line; do
                    case "${line}" in
                        BAD_ROUTE\|*)
                            IFS='|' read -r _ TARGET VIA CORRECT_PREFIX <<< "${line}"
                            fail "Сеть ${NWID}: маршрут ${TARGET} via ${VIA} — шлюз НЕ в подсети этой сети (${CORRECT_PREFIX})"
                            tip "Исправьте в ZTNET Panel → Managed Routes → Via: <IP этой ноды в ${NWID}>"
                            tip "Или через API:"
                            tip "  curl -s -X POST -H 'X-ZT1-Auth: TOKEN' -H 'Content-Type: application/json' \\"
                            tip "    -d '{\"routes\":[{\"target\":\"${TARGET}\",\"via\":null}]}' \\"
                            tip "    http://localhost:9993/controller/network/${NWID}"
                            ;;
                        NO_DEFAULT_GW)
                            warn "Сеть ${NWID}: default route без via — клиенты не получат интернет"
                            tip "Добавьте маршрут 0.0.0.0/0 via <ZT-IP сервера в этой сети>"
                            inc_warn
                            ;;
                        OK_DEFAULT\|*)
                            VIA_IP="${line#OK_DEFAULT|}"
                            log "Сеть ${NWID}: default route via ${VIA_IP} — корректно"
                            ;;
                    esac
                done <<< "${ROUTES_CHECK}"
            fi
        done
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  6. ЧЛЕНЫ СЕТИ (MEMBERS)
# ╚══════════════════════════════════════════════════════════════════════════════
header "6/11" "Члены сетей (Members)"

if [[ -n "${AUTHTOKEN}" && -n "${ZT_ADDR}" ]]; then
    for NWID in $(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n.get('status') == 'OK':
        print(n['id'])
" 2>/dev/null); do
        NET_NAME=$(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n['id'] == '${NWID}': print(n.get('name','?')); break
" 2>/dev/null || echo "?")
        echo ""
        info "Сеть ${NWID} (${NET_NAME}):"

        controller_api GET "/controller/network/${NWID}/member" | python3 -c "
import sys, json, urllib.request

try:
    token = '${AUTHTOKEN}'
    nwid = '${NWID}'
    zt_addr = '${ZT_ADDR}'
    raw = json.load(sys.stdin)
    member_list = raw if isinstance(raw, dict) else {}
    if not member_list:
        print('  (нет членов)')

    for addr in sorted(member_list.keys()):
        try:
            req = urllib.request.Request(
                f'http://localhost:9993/controller/network/{nwid}/member/{addr}',
                headers={'X-ZT1-Auth': token}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                m = json.loads(resp.read())
        except Exception:
            m = {}

        name = m.get('name', '') or '?'
        auth = m.get('authorized', False)
        has_id = bool(m.get('identity', ''))
        vrev = m.get('vRev', -1)
        ips = ', '.join(m.get('ipAssignments', [])) or 'no IP'
        is_controller = (addr == zt_addr)

        flags = []
        if not auth: flags.append('NOT_AUTH')
        if not has_id and not is_controller: flags.append('NO_IDENTITY')
        if vrev == -1 and auth and not is_controller: flags.append('NEVER_CONNECTED')
        if vrev == 0 and auth and has_id and not is_controller: flags.append('CONFIG_STUCK')
        if is_controller: flags.append('CONTROLLER')

        flag_str = ' '.join(flags)
        if 'NOT_AUTH' in flags or 'NO_IDENTITY' in flags or 'CONFIG_STUCK' in flags:
            color = '\033[0;31m'
        elif 'NEVER_CONNECTED' in flags:
            color = '\033[1;33m'
        else:
            color = '\033[0;32m'

        print(f'  {color}{addr} ({name}): ip={ips} vRev={vrev} {flag_str}\033[0m')
except Exception as e:
    print(f'  \033[0;31mОшибка чтения: {e}\033[0m')
" 2>/dev/null || warn "  Не удалось получить список членов"

        STUCK_MEMBERS=$(controller_api GET "/controller/network/${NWID}/member" | python3 -c "
import sys, json, urllib.request
token = '${AUTHTOKEN}'
nwid = '${NWID}'
zt_addr = '${ZT_ADDR}'
raw = json.load(sys.stdin)
for addr in raw:
    if addr == zt_addr: continue
    try:
        req = urllib.request.Request(f'http://localhost:9993/controller/network/{nwid}/member/{addr}', headers={'X-ZT1-Auth': token})
        with urllib.request.urlopen(req, timeout=3) as resp:
            m = json.loads(resp.read())
        if m.get('authorized') and m.get('identity') and m.get('vRev', -1) == 0:
            print(addr)
    except: pass
" 2>/dev/null || true)
        for STUCK_ADDR in ${STUCK_MEMBERS}; do
            warn "Член ${STUCK_ADDR}: vRev=0 — косметический статус (CONFIG_STUCK)"
            tip "Это НЕ проблема — клиент работает нормально при vRev=0"
            tip "НЕ делайте deauth/reauth — это вызовет бесконечный цикл revision inflation"
            inc_warn
        done
    done
else
    warn "Нет доступа к Controller API — пропускаю проверку членов"
    inc_warn
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  7. PIR-СОЕДИНЕНИЯ
# ╚══════════════════════════════════════════════════════════════════════════════
header "7/11" "Пир-соединения (Peers)"

PEERS_JSON=$(zt_exec zerotier-cli -j listpeers 2>/dev/null || echo "[]")
LEAF_COUNT=$(echo "${PEERS_JSON}" | python3 -c "
import sys, json
peers = json.load(sys.stdin)
leaves = [p for p in peers if p.get('role') == 'LEAF']
print(len(leaves))
" 2>/dev/null | tr -d '\n' || echo "0")

LEAF_ONLINE=$(echo "${PEERS_JSON}" | python3 -c "
import sys, json
peers = json.load(sys.stdin)
leaves = [p for p in peers if p.get('role') == 'LEAF' and p.get('latency', -1) >= 0]
print(len(leaves))
" 2>/dev/null | tr -d '\n' || echo "0")

PLANET_ONLINE=$(echo "${PEERS_JSON}" | python3 -c "
import sys, json
peers = json.load(sys.stdin)
planets = [p for p in peers if p.get('role') == 'PLANET' and p.get('latency', -1) >= 0]
print(len(planets))
" 2>/dev/null | tr -d '\n' || echo "0")

PLANET_TUNNELED=$(echo "${PEERS_JSON}" | python3 -c "
import sys, json
peers = json.load(sys.stdin)
tunneled = [p for p in peers if p.get('role') == 'PLANET' and p.get('tunneled', False)]
print(len(tunneled))
" 2>/dev/null | tr -d '\n' || echo "0")

echo "${PEERS_JSON}" | python3 -c "
import sys, json
peers = json.load(sys.stdin)
for p in peers:
    role = p.get('role', '?')
    addr = p.get('address', '?')
    lat = p.get('latency', -1)
    paths = p.get('paths', [])
    tunneled = p.get('tunneled', False)
    ver = p.get('version', '?')

    path_str = paths[0].get('address', '?') if paths else 'no path'
    if lat >= 0:
        color = '\033[0;32m'
    elif tunneled:
        color = '\033[1;33m'
    else:
        color = '\033[0;31m'

    tunnel_mark = ' [TUNNELED]' if tunneled else ''
    print(f'  {color}{addr}: {role} latency={lat}ms ver={ver} path={path_str}{tunnel_mark}\033[0m')
" 2>/dev/null || warn "Не удалось распарсить пиры"

echo ""
if [[ "${PLANET_TUNNELED:-0}" -gt 0 && "${PLANET_ONLINE:-0}" -eq 0 ]]; then
    warn "Все PLANET-пиры в TUNNELED режиме — UDP заблокирован"
    tip "Это нормально для OpenVZ — соединение через TCP (порт 443)"
    tip "Ожидайте повышенную задержку (~100-200мс вместо ~20-50мс)"
    inc_warn
elif [[ "${PLANET_ONLINE:-0}" -gt 0 ]]; then
    log "PLANET-пиры подключены напрямую (UDP)"
fi

if [[ "${LEAF_COUNT:-0}" -gt 0 ]]; then
    log "LEAF-пиров: ${LEAF_COUNT} (онлайн: ${LEAF_ONLINE})"
else
    info "LEAF-пиров нет (клиенты не подключены или ещё не найдены)"
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  8. NAT / IP FORWARDING / FIREWALL
# ╚══════════════════════════════════════════════════════════════════════════════
header "8/11" "NAT / IP Forwarding / Firewall"

IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [[ "${IP_FWD}" == "1" ]]; then
    log "IP forwarding: включён"
else
    fail "IP forwarding: ВЫКЛЮЧЕН — интернет через ZT работать не будет"
    tip "sysctl -w net.ipv4.ip_forward=1"
    tip "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf && sysctl --system"
    if ask_fix; then
        sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
        echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf 2>/dev/null || true
        echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-zt-forward.conf 2>/dev/null || true
        sysctl --system > /dev/null 2>&1 || true
        log "IP forwarding включён"
    fi
fi

MAIN_IFACE=$(ip -4 route show default | grep -oP 'dev \K\S+' | head -1 || echo "")
if [[ -z "${MAIN_IFACE}" ]]; then
    warn "Не удалось определить основной интерфейс"
    inc_warn
fi

if [[ -f "${ENV_FILE}" ]]; then
    source "${ENV_FILE}" 2>/dev/null || true
fi

ALL_SUBNETS="${ZT_SUBNETS:-${ZT_SUBNET:-10.121.15.0/24}}"
IFS=',' read -ra SUBNET_ARRAY <<< "${ALL_SUBNETS}"

NAT_MISSING=()
for SUB in "${SUBNET_ARRAY[@]}"; do
    [[ -z "${SUB}" ]] && continue
    NAT_CHECK=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep "${SUB}" || true)
    if [[ -n "${NAT_CHECK}" ]]; then
        log "NAT для ${SUB}: настроен"
    else
        fail "NAT для ${SUB}: ОТСУТСТВУЕТ — клиенты этой сети не получат интернет"
        NAT_MISSING+=("${SUB}")
    fi
done

if [[ ${#NAT_MISSING[@]} -gt 0 ]]; then
    if [[ "${IS_OPENVZ:-false}" == "true" ]]; then
        tip "iptables -t nat -A POSTROUTING -s <SUBNET> -o ${MAIN_IFACE} -j SNAT --to-source ${PUBLIC_IP:-<SERVER_IP>}"
    else
        tip "iptables -t nat -A POSTROUTING -s <SUBNET> -o ${MAIN_IFACE} -j MASQUERADE"
    fi
    tip "Или запустите: ${INSTALL_DIR}/zt-nat-setup.sh"
    if ask_fix; then
        SERVER_IP="${PUBLIC_IP:-$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")}"
        for SUB in "${NAT_MISSING[@]}"; do
            iptables -C FORWARD -s "${SUB}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "${SUB}" -j ACCEPT
            iptables -C FORWARD -d "${SUB}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -d "${SUB}" -j ACCEPT
            if [[ "${IS_OPENVZ:-false}" == "true" && -n "${SERVER_IP}" ]]; then
                iptables -t nat -A POSTROUTING -s "${SUB}" -o "${MAIN_IFACE}" -j SNAT --to-source "${SERVER_IP}" 2>/dev/null || true
            else
                iptables -t nat -A POSTROUTING -s "${SUB}" -o "${MAIN_IFACE}" -j MASQUERADE 2>/dev/null || true
            fi
            log "NAT добавлен для ${SUB}"
        done
        netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
fi

FORWARD_CHECK=$(iptables -L FORWARD -n 2>/dev/null | grep -c "ACCEPT" | head -1 || echo "0")
if [[ "${FORWARD_CHECK:-0}" -eq 0 ]]; then
    fail "Нет ACCEPT правил в FORWARD — трафик ZT заблокирован"
    tip "iptables -I FORWARD 1 -s ${ZT_SUBNET:-10.0.0.0/8} -j ACCEPT"
else
    log "FORWARD правила: ${FORWARD_CHECK} ACCEPT правил"
fi

if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
    UFW_9993=$(ufw status 2>/dev/null | grep -c '9993' | head -1 || echo "0")
    if [[ "${UFW_9993:-0}" -gt 0 ]]; then
        log "UFW: порт 9993 открыт"
    else
        fail "UFW активен, но порт 9993 НЕ открыт — ZeroTier не сможет принимать соединения"
        tip "ufw allow 9993/udp && ufw allow 9993/tcp"
        if ask_fix; then
            ufw allow 9993/udp >/dev/null 2>&1 || true
            ufw allow 9993/tcp >/dev/null 2>&1 || true
            log "Порт 9993 открыт в UFW"
        fi
    fi
    UFW_ROUTE=$(ufw status verbose 2>/dev/null | grep -cE '(allow.*routed|routed.*allow)' 2>/dev/null || echo "0")
    UFW_ROUTE=$(echo "${UFW_ROUTE}" | tr -d '[:space:]' | head -1)
    UFW_ROUTE="${UFW_ROUTE:-0}"
    if [[ "${UFW_ROUTE:-0}" -gt 0 ]]; then
        log "UFW: routed traffic разрешён"
    else
        warn "UFW: routed traffic запрещён — ZT-клиенты без интернета"
        tip "ufw default allow routed"
        inc_warn
        if ask_fix; then
            ufw default allow routed >/dev/null 2>&1 || true
            log "Routed traffic разрешён в UFW"
        fi
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  9. КОНФИГУРАЦИЯ .env.info
# ╚══════════════════════════════════════════════════════════════════════════════
header "9/11" "Конфигурация .env.info"

if [[ -f "${ENV_FILE}" ]]; then
    log "Файл найден: ${ENV_FILE}"
    ENV_ZT_SUBNETS=$(grep -oP '^ZT_SUBNETS=\K.*' "${ENV_FILE}" 2>/dev/null || true)

    ACTUAL_SUBNETS=$(zt_exec zerotier-cli -j listnetworks 2>/dev/null | python3 -c "
import sys, json, ipaddress
nets = json.load(sys.stdin)
subs = set()
for n in nets:
    if n.get('status') == 'OK':
        for addr in n.get('assignedAddresses', []):
            parts = addr.split('/')
            if len(parts) == 2:
                net = ipaddress.ip_network(f'{parts[0]}/{parts[1]}', strict=False)
                subs.add(str(net))
print(','.join(sorted(subs)))
" 2>/dev/null || true)

    if [[ -n "${ACTUAL_SUBNETS}" && -n "${ENV_ZT_SUBNETS}" ]]; then
        MISSING_IN_ENV=()
        IFS=',' read -ra ACTUAL <<< "${ACTUAL_SUBNETS}"
        for SUB in "${ACTUAL[@]}"; do
            [[ -z "${SUB}" ]] && continue
            if ! echo "${ENV_ZT_SUBNETS}" | grep -q "${SUB}"; then
                MISSING_IN_ENV+=("${SUB}")
            fi
        done
        if [[ ${#MISSING_IN_ENV[@]} -gt 0 ]]; then
            warn "В .env.info отсутствуют подсети: ${MISSING_IN_ENV[*]}"
            tip "Запустите zt-add-network.sh для добавления сети или обновите вручную"
            tip "Или выполните: ${INSTALL_DIR}/zt-nat-setup.sh"
            inc_warn
        fi
    fi
else
    warn "Файл ${ENV_FILE} не найден — сначала выполните zt-install.sh"
    inc_warn
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  10. ТЕСТ СВЯЗНОСТИ
# ╚══════════════════════════════════════════════════════════════════════════════
header "10/11" "Тест связности"

for NWID in $(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n.get('status') == 'OK':
        print(n['id'])
" 2>/dev/null); do
    NET_NAME=$(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n['id'] == '${NWID}': print(n.get('name','?')); break
" 2>/dev/null || echo "?")

    SELF_IP=$(echo "${NETWORKS_JSON}" | python3 -c "
import sys, json
for n in json.load(sys.stdin):
    if n['id'] == '${NWID}':
        for a in n.get('assignedAddresses', []):
            print(a.split('/')[0])
            break
" 2>/dev/null || true)

    PEERS_IN_NET=$(controller_api GET "/controller/network/${NWID}/member" | python3 -c "
import sys, json, urllib.request

token = '${AUTHTOKEN}'
nwid = '${NWID}'
zt_addr = '${ZT_ADDR}'
raw = json.load(sys.stdin)
member_addrs = raw if isinstance(raw, dict) else {}
for addr in member_addrs:
    if addr == zt_addr:
        continue
    try:
        req = urllib.request.Request(
            f'http://localhost:9993/controller/network/{nwid}/member/{addr}',
            headers={'X-ZT1-Auth': token}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            m = json.loads(resp.read())
        if m.get('authorized'):
            for ip in m.get('ipAssignments', []):
                print(ip)
    except Exception:
        pass
" 2>/dev/null || true)

    echo ""
    info "Сеть ${NWID} (${NET_NAME}): self-ping ${SELF_IP}..."
    if [[ -n "${SELF_IP}" ]]; then
        if ping -c 1 -W 3 "${SELF_IP}" >/dev/null 2>&1; then
            log "Self-ping ${SELF_IP}: OK"
        else
            fail "Self-ping ${SELF_IP}: НЕУДАЧА — интерфейс не работает"
        fi
    fi

    for PEER_IP in ${PEERS_IN_NET}; do
        if ping -c 2 -W 3 "${PEER_IP}" >/dev/null 2>&1; then
            LATENCY=$(ping -c 2 -W 3 "${PEER_IP}" 2>/dev/null | tail -1 | grep -oP '= \K[\d./]+' | awk -F/ '{print $2}' || echo "?")
            log "Ping ${PEER_IP}: OK (${LATENCY}ms)"
        else
            warn "Ping ${PEER_IP}: НЕУДАЧА — пир недоступен в этой сети"
            tip "На устройстве ${PEER_IP} выполните: zerotier-cli join ${NWID}"
            tip "Убедитесь, что клиент авторизован в ZTNET Panel"
            inc_warn
        fi
    done
done

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  11. ПЕРСИСТЕНТНОСТЬ (переживут ли настройки перезагрузку?)
# ╚══════════════════════════════════════════════════════════════════════════════
header "11/11" "Персистентность настроек"

PERSIST_ISSUES=0

RUNTIME_NATS=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | awk '/SNAT|MASQUERADE/{for(i=1;i<=NF;i++) if($i~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/){print $i;break}}' | sort -u || true)
SAVED_NATS=$(grep -oP 'POSTROUTING.*-s\s+\K\d+\.\d+\.\d+\.\d+/\d+' /etc/iptables/rules.v4 2>/dev/null | sort -u || true)

if [[ -f /etc/iptables/rules.v4 ]]; then
    log "Файл /etc/iptables/rules.v4 существует"

    for SUB in ${RUNTIME_NATS}; do
        if echo "${SAVED_NATS}" | grep -q "${SUB}"; then
            log "NAT ${SUB}: runtime и saved совпадают"
        else
            fail "NAT ${SUB}: есть в runtime, но ОТСУТСТВУЕТ в rules.v4 — пропадёт после перезагрузки"
            tip "iptables-save > /etc/iptables/rules.v4"
            PERSIST_ISSUES=$((PERSIST_ISSUES+1))
        fi
    done
else
    fail "Файл /etc/iptables/rules.v4 НЕ найден — iptables правила НЕ переживут перезагрузку"
    tip "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4"
    PERSIST_ISSUES=$((PERSIST_ISSUES+1))
fi

if [[ -f /etc/sysctl.d/99-zt-forward.conf ]] && grep -q 'net.ipv4.ip_forward.*=.*1' /etc/sysctl.d/99-zt-forward.conf 2>/dev/null; then
    log "sysctl ip_forward: сохранён в /etc/sysctl.d/99-zt-forward.conf"
else
    fail "sysctl ip_forward: НЕ сохранён — после перезагрузки IP forwarding будет отключён"
    tip "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf && sysctl --system"
    PERSIST_ISSUES=$((PERSIST_ISSUES+1))
fi

if readlink /etc/systemd/system/zerotier-one.service 2>/dev/null | grep -q '/dev/null'; then
    log "zerotier-one: замаскирован (не конфликтует при загрузке)"
else
    if command -v zerotier-one &>/dev/null; then
        fail "zerotier-one: НЕ замаскирован — при загрузке перехватит порт 9993 у Docker"
        tip "systemctl mask zerotier-one"
        PERSIST_ISSUES=$((PERSIST_ISSUES+1))
    fi
fi

if systemctl is-enabled zt-nat-setup.service >/dev/null 2>&1; then
    log "systemd: zt-nat-setup.service включён (NAT восстановится при загрузке)"
else
    if [[ -f /etc/systemd/system/zt-nat-setup.service ]]; then
        fail "systemd: zt-nat-setup.service есть, но НЕ включён — NAT не восстановится"
        tip "systemctl enable zt-nat-setup.service"
    else
        warn "systemd: zt-nat-setup.service не найден (установлен через другой механизм?)"
        inc_warn
    fi
    PERSIST_ISSUES=$((PERSIST_ISSUES+1))
fi

if [[ -f "${INSTALL_DIR}/zt-nat-setup.sh" ]]; then
    if [[ -x "${INSTALL_DIR}/zt-nat-setup.sh" ]]; then
        log "Скрипт ${INSTALL_DIR}/zt-nat-setup.sh существует и исполняемый"
    else
        warn "Скрипт ${INSTALL_DIR}/zt-nat-setup.sh НЕ исполняемый"
        tip "chmod +x ${INSTALL_DIR}/zt-nat-setup.sh"
        inc_warn
    fi
else
    warn "Скрипт ${INSTALL_DIR}/zt-nat-setup.sh не найден"
    inc_warn
fi

for SVC in ztnet ztnet_postgres ztnet_zerotier; do
    RP=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "${SVC}" 2>/dev/null || echo "?")
    if [[ "${RP}" == "unless-stopped" || "${RP}" == "always" ]]; then
        log "Docker ${SVC}: restart=${RP}"
    else
        fail "Docker ${SVC}: restart=${RP} — контейнер НЕ запустится автоматически после перезагрузки"
        tip "docker update --restart=unless-stopped ${SVC}"
        PERSIST_ISSUES=$((PERSIST_ISSUES+1))
    fi
done

if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
    UFW_SAVED=$(ufw status numbered 2>/dev/null | grep -c '9993' || echo "0")
    if [[ "${UFW_SAVED:-0}" -gt 0 ]]; then
        log "UFW: правила 9993 сохранены (ufw persist)"
    else
        warn "UFW: правило для 9993 не найдено в сохранённых"
        inc_warn
    fi
fi

if [[ ${PERSIST_ISSUES} -eq 0 ]]; then
    log "Персистентность: ВСЕ настройки переживут перезагрузку"
else
    warn "Персистентность: ${PERSIST_ISSUES} проблем — настройки могут пропасть после перезагрузки"
    inc_warn
    if ask_fix; then
        info "Автоматическое исправление персистентности..."
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        if [[ ! -f /etc/sysctl.d/99-zt-forward.conf ]]; then
            echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf
        fi
        if ! readlink /etc/systemd/system/zerotier-one.service 2>/dev/null | grep -q '/dev/null'; then
            systemctl mask zerotier-one 2>/dev/null || true
        fi
        if [[ -f /etc/systemd/system/zt-nat-setup.service ]]; then
            systemctl enable zt-nat-setup.service 2>/dev/null || true
        fi
        for SVC in ztnet ztnet_postgres ztnet_zerotier; do
            docker update --restart=unless-stopped "${SVC}" 2>/dev/null || true
        done
        log "Персистентность исправлена"
    fi
fi

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  ИТОГ
# ╚══════════════════════════════════════════════════════════════════════════════
echo ""
sep
echo ""
if [[ ${CRITICAL} -eq 0 && ${WARNINGS} -eq 0 ]]; then
    echo -e "${BOLD}${GREEN}  Всё в порядке — проблем не обнаружено${NC}"
elif [[ ${CRITICAL} -eq 0 ]]; then
    echo -e "${BOLD}${YELLOW}  Предупреждений: ${WARNINGS} — рекомендуется устранить${NC}"
else
    echo -e "${BOLD}${RED}  Критических: ${CRITICAL}, предупреждений: ${WARNINGS}${NC}"
    echo -e "${RED}  Требуется вмешательство${NC}"
fi

echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "    Диагностика  : ${CYAN}sudo bash $0${NC}"
echo -e "    Исправление  : ${CYAN}sudo bash $0 --fix${NC}"
echo -e "    NAT обновить : ${CYAN}${INSTALL_DIR}/zt-nat-setup.sh${NC}"
echo -e "    Добавить сеть: ${CYAN}sudo bash $(dirname "$0")/zt-add-network.sh${NC}"
echo -e "    Очистка      : ${CYAN}sudo bash $(dirname "$0")/zt-cleanup.sh${NC}"
echo -e "    ZT сети      : ${CYAN}docker exec ztnet_zerotier zerotier-cli listnetworks${NC}"
echo -e "    ZT пиры      : ${CYAN}docker exec ztnet_zerotier zerotier-cli listpeers${NC}"
echo -e "    ZT логи      : ${CYAN}docker logs ztnet_zerotier --tail 30${NC}"
echo ""
sep
