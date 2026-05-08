#!/bin/bash
# Version: 2.0 — Compact output for 100x30 terminal

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# Guard against sourcing directly into shell
[[ $- == *i* ]] || [[ -z "${BASH_SOURCE[0]}" || "${BASH_SOURCE[0]}" == "$0" ]] || return 2>/dev/null

[[ -f /etc/os-release ]] && source /etc/os-release

hostname=$(hostname); kernel=$(uname -r); arch=$(uname -m)
cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
cpu_cores=$(nproc)
load=$(awk '{print $1, $2, $3}' /proc/loadavg)
uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
public_ip=$(curl -s --connect-timeout 2 --max-time 4 ifconfig.me 2>/dev/null || echo "N/A")
local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

cpu_idle=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $8}')
cpu_usage=$(awk "BEGIN {printf \"%.1f\", 100 - $cpu_idle}" 2>/dev/null || echo "0")

mem=($(free -m | awk '/Mem:/ {print $2, $3}'))
ram_pct=$((mem[1] * 100 / mem[0]))
swap=($(free -m | awk '/Swap:/ {print $2, $3}'))
[[ ${#swap[@]} -gt 0 && ${swap[0]} -gt 0 ]] && swap_pct=$((swap[1] * 100 / swap[0])) || swap_pct=0

docker_running=$(docker ps -q 2>/dev/null | wc -l)
docker_total=$(docker ps -aq 2>/dev/null | wc -l)
docker_str="${docker_running}/${docker_total}"

bar() {
    local p=$1 sz=20 f=$((p * sz / 100)) e=$((sz - f))
    local c=$GREEN; [[ $p -ge 90 ]] && c=$RED; [[ $p -ge 70 && $p -lt 90 ]] && c=$YELLOW
    printf "${c}%${f}s${NC}" | tr ' ' '#'
    printf "${DIM}%${e}s${NC}" | tr ' ' '.'
}

title() { printf "${CYAN}${BOLD}%s${NC}\n" "$1"; }
line() { printf "${DIM}%s${NC}\n" "$1"; }

echo ""
title "  ════════════════════════════════════════════════════════════════════════════════════════"
printf "  ${CYAN}◆${NC} ${BOLD}%s${NC}  " "$hostname"
printf "${DIM}%s${NC} " "${PRETTY_NAME:-}"
printf "${DIM}| ${kernel} (${arch})${NC}"
echo ""

printf "  ${DIM}CPU:${NC} ${cpu_model%%)*} %scores | " "${cpu_cores}"
printf "${DIM}Load:${NC} ${load} | "
printf "${DIM}Uptime:${NC} ${uptime_str}"
echo ""

printf "  ${DIM}CPU:${NC} ${cpu_usage}%% "; bar "${cpu_usage%.*}"; echo ""
printf "  ${DIM}RAM:${NC} ${mem[1]}M/${mem[0]}M "; bar "$ram_pct"; echo ""
[[ ${#swap[@]} -gt 0 && ${swap[0]} -gt 0 ]] && { printf "  ${DIM}SWP:${NC} ${swap[1]}M/${swap[0]}M "; bar "$swap_pct"; echo ""; }

echo ""
title "  ─── Disk ────────────────────────────────────────────────────────────────────────"
df -h --type=ext4 --type=xfs --type=btrfs --type=zfs 2>/dev/null | awk 'NR>1 && $1!~/^tmpfs/ {
    printf "  %-14s %5s %5s %5s %s\n", $6, $3, $4, $5, $2
}'

echo ""
title "  ─── Network & Docker ────────────────────────────────────────────────────────────"
printf "  ${DIM}Pub IP:${NC} %-15s ${DIM}Loc IP:${NC} %s\n" "$public_ip" "$local_ip"
printf "  ${DIM}Docker:${NC} %s containers running\n" "$docker_str"


printf "${DIM}%s${NC}\n" "  ───────────────────────────────────────────────────────────────────────────────────"
echo ""