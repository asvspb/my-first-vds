#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

if [[ $- != *i* ]]; then
    return 2>/dev/null || exit 0
fi

if [[ -n "$SSH_TTY" ]] || [[ -n "$SSH_CONNECTION" ]]; then
    IS_SSH=1
else
    IS_SSH=0
fi

[[ -f /etc/os-release ]] && source /etc/os-release

get_uptime() {
    uptime -p 2>/dev/null | sed 's/up //'
}

get_cpu_usage() {
    local idle
    idle=$(top -bn1 | grep "Cpu(s)" | awk '{print $8}')
    if [[ -n "$idle" ]]; then
        echo "$(awk "BEGIN {printf \"%.1f\", 100 - $idle}")"
    else
        mpstat 1 1 2>/dev/null | awk '/Average/ {printf "%.1f", 100 - $NF}' || echo "N/A"
    fi
}

get_ram_info() {
    local mem_line
    mem_line=$(free -m | awk '/Mem:/ {printf "%d %d %d %d", $2, $3, $4, $6+$7}')
    read -r total used free buff_cache <<< "$mem_line"
    if [[ $total -gt 0 ]]; then
        local pct
        pct=$((used * 100 / total))
        echo "${used}MB / ${total}MB (${pct}%)"
    fi
}

get_swap_info() {
    local swap_line
    swap_line=$(free -m | awk '/Swap:/ {printf "%d %d", $2, $3}')
    read -r total used <<< "$swap_line"
    if [[ $total -gt 0 ]]; then
        local pct
        pct=$((used * 100 / total))
        echo "${used}MB / ${total}MB (${pct}%)"
    else
        echo "N/A"
    fi
}

get_disk_info() {
    df -h --type=ext4 --type=xfs --type=btrfs --type=zfs 2>/dev/null | awk 'NR>1 && $1!~/^tmpfs/ {print $1, $2, $3, $4, $5, $6}'
}

get_load() {
    cat /proc/loadavg | awk '{print $1, $2, $3}'
}

get_cpu_cores() {
    nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo
}

get_cpu_model() {
    grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs 2>/dev/null || echo "N/A"
}

get_public_ip() {
    curl -s --connect-timeout 2 --max-time 4 ifconfig.me 2>/dev/null || echo "N/A"
}

get_active_connections() {
    ss -tn state established 2>/dev/null | wc -l
}

get_failed_logins() {
    if command -v journalctl &>/dev/null; then
        journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed password" || echo "0"
    else
        grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0"
    fi
}

get_last_logins() {
    last -i -n 5 2>/dev/null | head -5
}

get_docker_status() {
    if command -v docker &>/dev/null; then
        local running stopped total
        running=$(docker ps -q 2>/dev/null | wc -l)
        total=$(docker ps -aq 2>/dev/null | wc -l)
        stopped=$((total - running))
        echo "containers: ${running} running, ${stopped} stopped (total: ${total})"
    else
        echo "not installed"
    fi
}

get_top_processes() {
    ps aux --sort=-%mem | awk 'NR<=6 {printf "%-10s %-8s %-6s %-6s %s\n", $1, $2, $3, $4, substr($0, index($0,$11))}'
}

draw_bar() {
    local pct=$1 size=30 filled
    filled=$((pct * size / 100))
    local empty=$((size - filled))
    local color
    if [[ $pct -ge 90 ]]; then color=$RED
    elif [[ $pct -ge 70 ]]; then color=$YELLOW
    else color=$GREEN
    fi

    printf "${color}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "]${NC}"
}

hostname=$(hostname 2>/dev/null || echo "N/A")
kernel=$(uname -r)
arch=$(uname -m)
uptime_str=$(get_uptime)
cpu_model=$(get_cpu_model)
cpu_cores=$(get_cpu_cores)
load=$(get_load)
cpu_usage=$(get_cpu_usage)
ram_info=$(get_ram_info)
ram_pct=$(awk '{print $2}' <<< "$ram_info" | awk -F'[()%]' '{print $1}')
swap_info=$(get_swap_info)
public_ip=$(get_public_ip)
local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
active_conns=$(get_active_connections)
docker_status=$(get_docker_status)

if [[ $IS_SSH -eq 1 ]]; then
    client_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
else
    client_ip="local"
fi

width=60
line=$(printf '─%.0s' $(seq 1 $width))

echo ""
echo -e "  ${CYAN}${BOLD}╔${line}╗${NC}"
echo -e "  ${CYAN}${BOLD}║${NC}  ${BOLD}SYSTEM STATUS${NC} — ${CYAN}${BOLD}${hostname}${NC}"
echo -e "  ${CYAN}${BOLD}╠${line}╣${NC}"
echo -e "  ${CYAN}║${NC}  ${BOLD}OS:${NC}       ${PRETTY_NAME:-N/A}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Kernel:${NC}   ${kernel} (${arch})"
echo -e "  ${CYAN}║${NC}  ${BOLD}Uptime:${NC}   ${uptime_str}"
echo -e "  ${CYAN}║${NC}  ${BOLD}CPU:${NC}      ${cpu_model} (${cpu_cores} cores)"
echo -e "  ${CYAN}║${NC}  ${BOLD}Load:${NC}     ${load}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Public IP:${NC} ${public_ip}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Local IP:${NC}  ${local_ip}"
echo -e "  ${CYAN}╠${line}╣${NC}"

if [[ "$cpu_usage" != "N/A" ]]; then
    cpu_int=${cpu_usage%.*}
    printf "  ${CYAN}║${NC}  ${BOLD}CPU Usage:${NC}  "
    draw_bar "$cpu_int"
    printf " ${cpu_usage}%%\n"
fi

if [[ -n "$ram_pct" && "$ram_pct" != "N/A" ]]; then
    printf "  ${CYAN}║${NC}  ${BOLD}RAM:${NC}       "
    draw_bar "$ram_pct"
    echo "  ${ram_info}"
else
    echo -e "  ${CYAN}║${NC}  ${BOLD}RAM:${NC}       ${ram_info}"
fi

echo -e "  ${CYAN}║${NC}  ${BOLD}Swap:${NC}      ${swap_info}"

echo -e "  ${CYAN}╠${line}╣${NC}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Disk Usage:${NC}"
while read -r fs size used avail pct mount; do
    pct_num=${pct%\%}
    printf "  ${CYAN}║${NC}    ${DIM}%-16s${NC} " "$mount"
    draw_bar "${pct_num}"
    echo " ${used}/${size} (${pct})"
done < <(get_disk_info)

echo -e "  ${CYAN}╠${line}╣${NC}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Docker:${NC}    ${docker_status}"
echo -e "  ${CYAN}║${NC}  ${BOLD}SSH from:${NC}  ${client_ip}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Active SSH:${NC} ${active_conns} connections"

failed=$(get_failed_logins)
if [[ "$failed" -gt 0 ]]; then
    echo -e "  ${CYAN}║${NC}  ${RED}${BOLD}Failed logins (24h):${NC} ${RED}${failed}${NC}"
fi

echo -e "  ${CYAN}╠${line}╣${NC}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Top Processes (by RAM):${NC}"
echo -e "  ${CYAN}║${NC}  ${DIM}USER       PID      CPU%   MEM%  COMMAND${NC}"
while read -r line_text; do
    echo -e "  ${CYAN}║${NC}  ${line_text}"
done < <(get_top_processes)

echo -e "  ${CYAN}╠${line}╣${NC}"
echo -e "  ${CYAN}║${NC}  ${BOLD}Last Logins:${NC}"
while read -r line_text; do
    echo -e "  ${CYAN}║${NC}  ${line_text}"
done < <(get_last_logins)

echo -e "  ${CYAN}╚${line}╝${NC}"
echo ""
