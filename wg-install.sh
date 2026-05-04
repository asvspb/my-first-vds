#!/usr/bin/env bash
#
# WireGuard Installer — Debug Edition
# Основан на https://github.com/Nyr/wireguard-install (MIT License)
# Улучшения: подробное логирование, диагностика ошибок подключений
#

# ── Строгий режим ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Режим запуска: pipe (curl|bash) или файл ──────────────────────────────────
# При curl|bash stdin занят трубой — перенаправляем интерактивный ввод на /dev/tty
if [[ ! -t 0 ]]; then
    exec < /dev/tty
fi

# ── Цвета и лог-файл ──────────────────────────────────────────────────────────
LOG_FILE="/var/log/wireguard-install-debug.log"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

# Все выводы дублируются в лог-файл
exec > >(tee -a "$LOG_FILE") 2>&1

_ts()   { date '+%Y-%m-%d %H:%M:%S'; }
log()   { echo -e "${GRAY}[$(_ts)] [INFO ]${NC}  $*"; }
ok()    { echo -e "${GREEN}[$(_ts)] [ OK  ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[$(_ts)] [WARN ]${NC}  $*"; }
err()   { echo -e "${RED}[$(_ts)] [ERROR]${NC}  $*" >&2; }
die()   { err "$*"; exit 1; }
sep()   { echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"; }
section() { sep; echo -e "${BOLD}${CYAN}  ▶ $*${NC}"; sep; }

echo ""
section "WireGuard Debug Installer — $(date)"
log "Лог-файл: $LOG_FILE"

# ── Проверка окружения ─────────────────────────────────────────────────────────
section "Проверка окружения"

if readlink /proc/$$/exe | grep -q "dash"; then
    die "Запускайте через bash, не sh"
fi
ok "Shell: bash"

[[ "$EUID" -eq 0 ]] || die "Требуется root"
ok "Запущен от root"

# Определение ОС
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
    die "Неподдерживаемый дистрибутив"
fi
ok "ОС: $os $os_version"

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    die "Требуется Ubuntu 22.04+"
fi
if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
    die "Требуется Debian 11+"
fi
if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
    die "Требуется CentOS/AlmaLinux/Rocky 9+"
fi

grep -q sbin <<< "$PATH" || die '$PATH не содержит sbin. Используйте "su -" вместо "su"'
ok "PATH содержит sbin"

# Обнаружение виртуализации / контейнера
section "Обнаружение виртуализации"
VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
log "Тип виртуализации: $VIRT"

if ! systemd-detect-virt -cq 2>/dev/null; then
    use_boringtun="0"
    ok "Не контейнер — используется kernel WireGuard"
elif grep -q '^wireguard ' /proc/modules 2>/dev/null; then
    use_boringtun="0"
    ok "Контейнер, но модуль wireguard доступен"
else
    use_boringtun="1"
    warn "Контейнер без модуля WireGuard — будет использован BoringTun (userspace)"
fi

if [[ "$use_boringtun" -eq 1 ]]; then
    log "Архитектура: $(uname -m)"
    [[ "$(uname -m)" == "x86_64" ]] || die "BoringTun поддерживает только x86_64"
    if [[ ! -e /dev/net/tun ]]; then
        die "TUN-устройство недоступно. Включите TUN в панели управления VPS"
    fi
    ( exec 7<>/dev/net/tun ) 2>/dev/null || die "TUN-устройство заблокировано"
    ok "TUN-устройство доступно"
fi

# ── Диагностика сети ──────────────────────────────────────────────────────────
section "Диагностика сети"

log "Сетевые интерфейсы:"
ip -4 addr show | grep -E 'inet |^[0-9]' | while IFS= read -r line; do
    log "  $line"
done

log "Таблица маршрутизации (IPv4):"
ip -4 route show | while IFS= read -r line; do
    log "  $line"
done

log "Проверка IP-форвардинга:"
IPV4_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
IPV6_FWD=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "н/д")
if [[ "$IPV4_FWD" -eq 1 ]]; then
    ok "IPv4 forwarding: включён"
else
    warn "IPv4 forwarding: ВЫКЛЮЧЕН (будет включён при установке)"
fi
log "IPv6 forwarding: $IPV6_FWD"

log "Проверка DNS-резолвинга:"
if host -W 3 google.com >/dev/null 2>&1 || nslookup -timeout=3 google.com >/dev/null 2>&1; then
    ok "DNS работает"
else
    warn "DNS не отвечает — могут быть проблемы с установкой пакетов"
fi

log "Проверка связи с интернетом:"
if curl -s --max-time 5 https://example.com >/dev/null 2>&1; then
    ok "Интернет доступен"
else
    warn "Интернет недоступен или заблокирован"
fi

# ── Выбор IP адреса ────────────────────────────────────────────────────────────
section "Выбор IP-адреса сервера"

# Сначала пробуем найти публичный IP (не loopback, не приватный)
public_candidate=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' |     cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' |     grep -vE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)' | head -1 || true)

all_ips=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' |     cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
ip_count=$(echo "$all_ips" | wc -l)

if [[ -n "$public_candidate" ]]; then
    ip="$public_candidate"
    ok "Автовыбран публичный IPv4: $ip"
elif [[ "$ip_count" -eq 1 ]]; then
    ip="$all_ips"
    ok "Единственный IPv4: $ip"
else
    log "Найдено $ip_count IPv4-адресов:"
    echo "$all_ips" | nl -s ') '
    read -p "IPv4 адрес [1]: " ip_number < /dev/tty
    until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$ip_count" ]]; do
        echo "$ip_number: неверный выбор."
        read -p "IPv4 адрес [1]: " ip_number < /dev/tty
    done
    [[ -z "$ip_number" ]] && ip_number="1"
    ip=$(echo "$all_ips" | sed -n "${ip_number}p")
    ok "Выбран IPv4: $ip"
fi

# Проверка — за NAT ли сервер
if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    warn "Обнаружен приватный IP ($ip) — сервер за NAT"
    log "Определяем публичный IP..."
    get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< \
        "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" 2>/dev/null \
        || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/" 2>/dev/null)" || echo "")
    if [[ -n "$get_public_ip" ]]; then
        log "Определён публичный IP: $get_public_ip"
    else
        warn "Не удалось определить публичный IP автоматически"
    fi
    read -p "Публичный IPv4 / hostname [$get_public_ip]: " public_ip < /dev/tty
    until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
        echo "Обязательное поле."
        read -p "Публичный IPv4 / hostname: " public_ip < /dev/tty
    done
    [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    ok "Публичный endpoint: $public_ip"
fi

# IPv6
if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    ok "IPv6: $ip6"
elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
    number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
    ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
    read -p "IPv6 адрес [1]: " ip6_number < /dev/tty
    until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
        echo "$ip6_number: неверный выбор."
        read -p "IPv6 адрес [1]: " ip6_number < /dev/tty
    done
    [[ -z "$ip6_number" ]] && ip6_number="1"
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "${ip6_number}p")
    ok "IPv6: $ip6"
else
    log "IPv6 не обнаружен — работаем только на IPv4"
fi

# ── Параметры WireGuard ────────────────────────────────────────────────────────
section "Параметры WireGuard"

read -p "Порт WireGuard [51820]: " port < /dev/tty
until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
    echo "$port: неверный порт."
    read -p "Порт [51820]: " port < /dev/tty
done
[[ -z "$port" ]] && port="51820"
ok "Порт: $port"

# Проверяем — не занят ли порт
if ss -ulnp | grep -q ":${port} "; then
    warn "Порт $port уже занят! Возможен конфликт."
    ss -ulnp | grep ":${port} " | while IFS= read -r line; do warn "  $line"; done
fi

read -p "Имя первого клиента [client]: " unsanitized_client < /dev/tty
client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' \
    <<< "$unsanitized_client" | cut -c-15)
[[ -z "$client" ]] && client="client"
ok "Имя клиента: $client"

# DNS
echo ""
echo "Выберите DNS для клиента:"
echo "  1) Системный"
echo "  2) Google (8.8.8.8)"
echo "  3) Cloudflare (1.1.1.1)"
echo "  4) OpenDNS"
echo "  5) Quad9"
echo "  6) AdGuard"
read -p "DNS [2]: " dns_choice < /dev/tty
case "$dns_choice" in
    1)
        if grep '^nameserver' /etc/resolv.conf | grep -qv '127.0.0.53'; then
            resolv_conf="/etc/resolv.conf"
        else
            resolv_conf="/run/systemd/resolve/resolv.conf"
        fi
        dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | \
            grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | \
            xargs | sed -e 's/ /, /g')
        ;;
    3) dns="1.1.1.1, 1.0.0.1" ;;
    4) dns="208.67.222.222, 208.67.220.220" ;;
    5) dns="9.9.9.9, 149.112.112.112" ;;
    6) dns="94.140.14.14, 94.140.15.15" ;;
    *) dns="8.8.8.8, 8.8.4.4" ;;
esac
ok "DNS: $dns"

# ── Установка WireGuard ────────────────────────────────────────────────────────
section "Установка WireGuard"

if [[ -e /etc/wireguard/wg0.conf ]]; then
    warn "WireGuard уже установлен (/etc/wireguard/wg0.conf существует)"
    warn "Переустановка не выполняется. Удалите конфиг вручную если нужно."
    exit 0
fi

# Установка пакетов
firewall=""
if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
    if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
        firewall="iptables"
    else
        firewall="firewalld"
    fi
fi

log "Установка пакетов..."
if [[ "$use_boringtun" -eq 0 ]]; then
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update -y
        apt-get install -y wireguard qrencode $firewall
    elif [[ "$os" == "centos" ]]; then
        dnf install -y epel-release
        dnf install -y wireguard-tools qrencode $firewall
    elif [[ "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode $firewall
        mkdir -p /etc/wireguard/
    fi
else
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update -y
        apt-get install -y qrencode ca-certificates $firewall
        apt-get install -y wireguard-tools --no-install-recommends
    elif [[ "$os" == "centos" ]]; then
        dnf install -y epel-release
        dnf install -y wireguard-tools qrencode ca-certificates tar $firewall
    elif [[ "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode ca-certificates tar $firewall
        mkdir -p /etc/wireguard/
    fi
    log "Загрузка BoringTun..."
    { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null \
        || curl -sL https://wg.nyr.be/1/latest/download; } \
        | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
    mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/
    echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
    ok "BoringTun установлен"
fi
ok "Пакеты установлены"

# ── Генерация конфига сервера ──────────────────────────────────────────────────
section "Генерация конфигурации сервера"

SERVER_PRIVKEY=$(wg genkey)
SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
log "Публичный ключ сервера: $SERVER_PUBKEY"

ENDPOINT="${public_ip:-$ip}"

cat > /etc/wireguard/wg0.conf << EOF
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $ENDPOINT

[Interface]
Address = 10.7.0.1/24$([[ -n "${ip6:-}" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $SERVER_PRIVKEY
ListenPort = $port

EOF
chmod 600 /etc/wireguard/wg0.conf
ok "Конфиг сервера создан: /etc/wireguard/wg0.conf"

# ── IP Forwarding ──────────────────────────────────────────────────────────────
section "Настройка IP Forwarding"

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
echo 1 > /proc/sys/net/ipv4/ip_forward
ok "IPv4 forwarding включён"

if [[ -n "${ip6:-}" ]]; then
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    ok "IPv6 forwarding включён"
fi

# ── Настройка файрвола ─────────────────────────────────────────────────────────
section "Настройка файрвола / NAT"

if systemctl is-active --quiet firewalld.service; then
    log "Используется firewalld"
    firewall-cmd --add-port="${port}"/udp
    firewall-cmd --zone=trusted --add-source=10.7.0.0/24
    firewall-cmd --permanent --add-port="${port}"/udp
    firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 \
        -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 \
        -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
    ok "firewalld настроен"
else
    log "Используется iptables"
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)

    if [[ $(systemd-detect-virt) == "openvz" ]] && \
        readlink -f "$(command -v iptables)" | grep -q "nft" && \
        hash iptables-legacy 2>/dev/null; then
        iptables_path=$(command -v iptables-legacy)
        ip6tables_path=$(command -v ip6tables-legacy)
        warn "OpenVZ: используется iptables-legacy"
    fi

    cat > /etc/systemd/system/wg-iptables.service << EOF
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF

    if [[ -n "${ip6:-}" ]]; then
        cat >> /etc/systemd/system/wg-iptables.service << EOF
ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
    fi

    echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service

    systemctl enable --now wg-iptables.service
    ok "wg-iptables.service запущен"
fi

# ── Создание клиентского конфига ───────────────────────────────────────────────
section "Создание клиентского конфига: $client"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

octet=2
while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | \
    cut -d "/" -f 1 | grep -q "^${octet}$"; do
    (( octet++ ))
done
[[ "$octet" -eq 255 ]] && die "Подсеть WireGuard заполнена (253 клиента)"

CLIENT_KEY=$(wg genkey)
CLIENT_PSK=$(wg genpsk)
CLIENT_PUBKEY=$(echo "$CLIENT_KEY" | wg pubkey)
CLIENT_IP="10.7.0.$octet"

log "IP клиента: $CLIENT_IP"
log "Публичный ключ клиента: $CLIENT_PUBKEY"

# Добавляем пира в серверный конфиг
cat >> /etc/wireguard/wg0.conf << EOF
# BEGIN_PEER $client
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = $CLIENT_IP/32$([[ -n "${ip6:-}" ]] && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF

# Клиентский конфиг
CLIENT_CONF="$script_dir/$client.conf"
cat > "$CLIENT_CONF" << EOF
[Interface]
Address = $CLIENT_IP/24$([[ -n "${ip6:-}" ]] && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $CLIENT_KEY

[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $ENDPOINT:$port
PersistentKeepalive = 25
EOF
ok "Конфиг клиента: $CLIENT_CONF"

# ── Запуск WireGuard ───────────────────────────────────────────────────────────
section "Запуск WireGuard"

systemctl enable --now wg-quick@wg0.service
sleep 2

if systemctl is-active --quiet wg-quick@wg0.service; then
    ok "wg-quick@wg0 запущен"
else
    err "wg-quick@wg0 НЕ запустился!"
    err "Журнал systemd:"
    journalctl -u wg-quick@wg0 --no-pager -n 30 | while IFS= read -r line; do
        err "  $line"
    done
    die "Установка завершилась с ошибкой"
fi

# ── Постустановочная диагностика ───────────────────────────────────────────────
section "Постустановочная диагностика"

log "Статус интерфейса wg0:"
wg show wg0 2>&1 | while IFS= read -r line; do log "  $line"; done

log "IP адрес wg0:"
ip -4 addr show wg0 2>/dev/null | while IFS= read -r line; do log "  $line"; done

log "Маршруты через wg0:"
ip route show dev wg0 2>/dev/null | while IFS= read -r line; do log "  $line"; done

log "Проверка UDP-порта $port:"
if ss -ulnp | grep -q ":${port}"; then
    ok "UDP $port слушается"
else
    warn "UDP $port не найден в ss — возможно проблема с файрволом"
fi

log "Текущие правила iptables (NAT):"
iptables -t nat -L POSTROUTING -v --line-numbers 2>/dev/null | \
    while IFS= read -r line; do log "  $line"; done

log "Проверка forwarding после запуска:"
ok "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# ── QR-код ─────────────────────────────────────────────────────────────────────
section "QR-код для клиента $client"

if command -v qrencode &>/dev/null; then
    TERM_LINES=$(tput lines 2>/dev/null || echo 40)
    AVAIL=$((TERM_LINES - 10))
    QR_RAW=$(qrencode -t ansiutf8 -m 1 < "$CLIENT_CONF")
    QR_LINES=$(echo "$QR_RAW" | wc -l)
    if [[ "$QR_LINES" -gt "$AVAIL" && "$AVAIL" -gt 0 ]]; then
        STEP=$(( (QR_LINES + AVAIL - 1) / AVAIL ))
        echo "$QR_RAW" | awk -v step="$STEP" 'NR % step == 1'
    else
        echo "$QR_RAW"
    fi
else
    warn "qrencode не установлен — QR-код недоступен"
fi

# ── Итог ───────────────────────────────────────────────────────────────────────
section "Установка завершена"
ok "Конфиг сервера:  /etc/wireguard/wg0.conf"
ok "Конфиг клиента: $CLIENT_CONF"
ok "Лог установки:  $LOG_FILE"
echo ""
log "Полезные команды для отладки подключений:"
echo "  wg show                          — текущие пиры и трафик"
echo "  wg show wg0 latest-handshakes    — время последнего хендшейка"
echo "  journalctl -u wg-quick@wg0 -f   — лог сервиса в реальном времени"
echo "  tcpdump -i any udp port $port    — захват UDP-трафика WireGuard"
echo "  iptables -t nat -L -v            — правила NAT"
echo "  cat $LOG_FILE                    — полный лог установки"
echo ""