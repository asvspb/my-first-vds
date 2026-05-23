#!/usr/bin/env bash
# =============================================================================
#  ZeroTier Watchdog — автоконтроль и восстановление
#
#  Проверяет:
#    1. Связку ошибок "Could not bind" в логах за последние 5 минут
#    2. Статус ZT демона (ONLINE/OFFLINE/TUNNELED)
#    3. Наличие процесса zerotier-one
#    4. Конфликт порта 9993 с системным zerotier-one
#
#  При обнаружении проблем:
#    - Убивает конфликтующий процесс
#    - Перезапускает контейнер
#    - Ждёт восстановления ONLINE
#    - Логирует все действия
# =============================================================================

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/ztnet}"
LOG_FILE="${INSTALL_DIR}/zt-watchdog.log"
MAX_LOG_SIZE=$((512 * 1024))
CONTAINER="ztnet_zerotier"
CHECK_WINDOW="5m"
MAX_RESTARTS_PER_HOUR=3
STATE_FILE="/tmp/zt-watchdog-restarts"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log_w() { echo "[$(ts)] [WATCHDOG] $*" | tee -a "${LOG_FILE}"; }

rotate_log() {
    if [[ -f "${LOG_FILE}" ]] && [[ $(stat -c%s "${LOG_FILE}" 2>/dev/null || echo 0) -gt ${MAX_LOG_SIZE} ]]; then
        tail -200 "${LOG_FILE}" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "${LOG_FILE}"
    fi
}

count_recent_restarts() {
    if [[ ! -f "${STATE_FILE}" ]]; then
        echo 0
        return
    fi
    local cutoff
    cutoff=$(date -d '1 hour ago' '+%s' 2>/dev/null || date -v-1H '+%s' 2>/dev/null || echo 0)
    local count=0
    while IFS= read -r line; do
        local ts_epoch
        ts_epoch=$(date -d "${line}" '+%s' 2>/dev/null || echo 0)
        if [[ "${ts_epoch}" -ge "${cutoff}" ]]; then
            count=$((count + 1))
        fi
    done < "${STATE_FILE}"
    echo "${count}"
}

record_restart() {
    echo "$(ts)" >> "${STATE_FILE}"
    local cutoff
    cutoff=$(date -d '1 hour ago' '+%s' 2>/dev/null || date -v-1H '+%s' 2>/dev/null || echo 0)
    local tmp
    tmp=$(mktemp)
    while IFS= read -r line; do
        local ts_epoch
        ts_epoch=$(date -d "${line}" '+%s' 2>/dev/null || echo 0)
        if [[ "${ts_epoch}" -ge "${cutoff}" ]]; then
            echo "${line}" >> "${tmp}"
        fi
    done < "${STATE_FILE}"
    mv "${tmp}" "${STATE_FILE}"
}

kill_port_thief() {
    local pids
    pids=$(ss -tlnup 2>/dev/null | grep ':9993 ' | grep -oP 'pid=\K\d+' || true)
    if [[ -z "${pids}" ]]; then
        return
    fi
    for pid in ${pids}; do
        local comm
        comm=$(cat /proc/"${pid}"/comm 2>/dev/null || echo "?")
        local container_pid
        container_pid=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER}" 2>/dev/null || echo "")
        if [[ "${pid}" == "${container_pid}" ]]; then
            continue
        fi
        log_w "Порт 9993 занят процессом ${comm} (PID ${pid}) — убиваем"
        kill -9 "${pid}" 2>/dev/null || true
        sleep 2
    done
}

kill_system_zt() {
    if systemctl is-active --quiet zerotier-one 2>/dev/null; then
        log_w "Системный zerotier-one активен — останавливаем"
        systemctl stop zerotier-one 2>/dev/null || true
        systemctl mask zerotier-one 2>/dev/null || true
    fi
    if pgrep -x zerotier-one >/dev/null 2>&1; then
        log_w "Процесс zerotier-one найден — убиваем"
        pkill -9 -x zerotier-one 2>/dev/null || true
        sleep 2
    fi
}

restart_container() {
    local recent
    recent=$(count_recent_restarts)
    if [[ "${recent}" -ge "${MAX_RESTARTS_PER_HOUR}" ]]; then
        log_w "ОСТАНОВЛЕН: уже ${recent} рестартов за час (лимит ${MAX_RESTARTS_PER_HOUR})"
        return 1
    fi
    log_w "Рестарт #\$((recent+1))/${MAX_RESTARTS_PER_HOUR} за последний час"
    record_restart
    docker restart "${CONTAINER}" 2>&1 | while read -r line; do log_w "  docker: ${line}"; done
    log_w "Контейнер перезапущен, ожидаем ONLINE..."
    for i in $(seq 1 12); do
        sleep 5
        local info
        info=$(docker exec "${CONTAINER}" zerotier-cli info 2>/dev/null || true)
        if echo "${info}" | grep -qE 'ONLINE|TUNNELED'; then
            log_w "Восстановлен: ${info}"
            return 0
        fi
        log_w "  Ожидание... ($((i*5))с): ${info:-нет ответа}"
    done
    log_w "ОШИБКА: контейнер не перешёл в ONLINE за 60с после рестарта"
    return 1
}

rotate_log

BIND_ERRORS=$(docker logs "${CONTAINER}" --since "${CHECK_WINDOW}" 2>&1 | grep -cE "Could not bind|fatal error.*9993" 2>/dev/null || true)
BIND_ERRORS="${BIND_ERRORS:-0}"
ZT_INFO=$(docker exec "${CONTAINER}" zerotier-cli info 2>/dev/null || true)
ZT_STATUS=$(echo "${ZT_INFO}" | awk '{for(i=1;i<=NF;i++) if($i~/^(ONLINE|OFFLINE|TUNNELED|DEGRADED)$/) print $i}' | head -1)
CONTAINER_RUNNING=$(docker inspect --format '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || echo "false")

PROBLEM=false

if [[ "${CONTAINER_RUNNING}" != "true" ]]; then
    log_w "ПРОБЛЕМА: контейнер ${CONTAINER} не запущен"
    PROBLEM=true
fi

if [[ "${BIND_ERRORS}" -gt 3 ]]; then
    log_w "ПРОБЛЕМА: ${BIND_ERRORS} ошибок биндинга за ${CHECK_WINDOW}"
    PROBLEM=true
fi

if [[ "${ZT_STATUS}" == "OFFLINE" || -z "${ZT_STATUS}" ]]; then
    log_w "ПРОБЛЕМА: ZT статус=${ZT_STATUS:-NO_RESPONSE}"
    PROBLEM=true
fi

if ! docker exec "${CONTAINER}" pgrep -x zerotier-one >/dev/null 2>&1; then
    log_w "ПРОБЛЕМА: процесс zerotier-one не найден в контейнере"
    PROBLEM=true
fi

if $PROBLEM; then
    log_w "Начинаем восстановление..."
    kill_system_zt
    kill_port_thief
    if restart_container; then
        log_w "Восстановление завершено успешно"
    else
        log_w "Восстановление ЗАВЕРШЕНО С ОШИБКАМИ"
        exit 1
    fi
else
    if [[ "${BIND_ERRORS}" -gt 0 ]]; then
        log_w "OK (${BIND_ERRORS} ошибок биндинга, но ZT ${ZT_STATUS})"
    fi
fi
