#!/usr/bin/env bash
#
# WireGuard Installer — Debug & Manage Edition
# Улучшения: защита от усечения (wrap в main), меню управления, umask, точный NAT
#

# Оборачиваем весь скрипт в функцию для защиты от частичного скачивания (curl | bash)
main() {
    # ── Строгий режим ─────────────────────────────────────────────────────────────
    set -euo pipefail

    # Устанавливаем строгие права по умолчанию для всех создаваемых файлов (ключи, конфиги)
    umask 077

    # Открываем fd 3 на /dev/tty для интерактивного ввода независимо от stdin
    exec 3</dev/tty

    # ── Цвета и лог-файл ──────────────────────────────────────────────────────────
    LOG_FILE="/var/log/wireguard-install-debug.log"
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

    # Настраиваем логирование: вывод в консоль и дублирование в файл
    exec > >(tee -a "$LOG_FILE") 2>&1

    _ts()   { date '+%Y-%m-%d %H:%M:%S'; }
    log()   { echo -e "${GRAY}[$(_ts)] [INFO ]${NC}  $*"; }
    ok()    { echo -e "${GREEN}[$(_ts)] [ OK  ]${NC}  $*"; }
    warn()  { echo -e "${YELLOW}[$(_ts)] [WARN ]${NC}  $*"; }
    err()   { echo -e "${RED}[$(_ts)] [ERROR]${NC}  $*" >&2; }
    die()   { err "$*"; exit 1; }
    sep()   { echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"; }
    section() { echo ""; sep; echo -e "${BOLD}${CYAN}  ▶ $*${NC}"; sep; }

    echo ""
    echo -e "${BOLD}${GREEN}WireGuard VPN — Advanced Installer${NC}"
    log "Лог-файл: $LOG_FILE"

    # ── Проверка окружения ────────────────────────────────────────────────────────
    if readlink /proc/$$/exe | grep -q "dash"; then
        die "Запускайте через bash, а не sh (curl ... | bash)"
    fi

    [[ "$EUID" -eq 0 ]] || die "Требуются права root (sudo)"

    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        [[ "$os_version" -lt 2004 ]] && die "Требуется Ubuntu 20.04+"
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1 || true)
        [[ "$os_version" -lt 11 ]] && die "Требуется Debian 11+"
    elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1 || true)
        [[ "$os_version" -lt 9 ]] && die "Требуется CentOS/AlmaLinux/Rocky 9+"
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
    else
        die "Неподдерживаемый дистрибутив"
    fi

    # ── Если WireGuard уже установлен (Управление) ────────────────────────────────
    if [[ -e /etc/wireguard/wg0.conf ]]; then
        section "WireGuard уже установлен"
        echo "Выберите действие:"
        echo "   1) Добавить нового клиента"
        echo "   2) Удалить WireGuard"
        echo "   3) Выход"
        read -p "Действие [1]: " option <&3 || true
        until [[ -z "$option" || "$option" =~ ^[123]$ ]]; do
            echo "Неверный выбор."
            read -p "Действие [1]: " option <&3 || true
        done
        [[ -z "$option" ]] && option="1"

        case "$option" in
            1)
                # Добавление клиента
                section "Добавление нового клиента"
                unsanitized_client=""
                read -p "Имя клиента [client]: " unsanitized_client <&3 || true
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                [[ -z "$client" ]] && client="client"

                while grep -q "# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
                    echo "Клиент с именем $client уже существует!"
                    read -p "Новое имя клиента: " unsanitized_client <&3 || true
                    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                    [[ -z "$client" ]] && client="client2"
                done

                # Поиск свободного IP (10.7.0.2 - 10.7.0.253)
                octet=2
                while grep -q "10\.7\.0\.$octet/32" /etc/wireguard/wg0.conf; do
                    (( octet++ ))
                    [[ "$octet" -eq 254 ]] && die "Подсеть заполнена (достигнут лимит в 253 клиента)"
                done

                CLIENT_IP="10.7.0.$octet"
                CLIENT_KEY=$(wg genkey)
                CLIENT_PSK=$(wg genpsk)
                CLIENT_PUBKEY=$(echo "$CLIENT_KEY" | wg pubkey)

                # Получение данных сервера
                ENDPOINT=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | awk '{print $3}')
                SERVER_PUBKEY=$(wg show wg0 public-key)
                PORT=$(grep '^ListenPort' /etc/wireguard/wg0.conf | awk '{print $3}')
                ip6=$(grep -oE 'fddd:2c4:2c4:2c4::[0-9a-f:]+/64' /etc/wireguard/wg0.conf | head -1 | cut -d/ -f1 || true)
                
                # Добавляем в конфиг сервера
                cat >> /etc/wireguard/wg0.conf << EOF
# BEGIN_PEER $client
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = $CLIENT_IP/32$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
                wg set wg0 peer "$CLIENT_PUBKEY" preshared-key <(echo "$CLIENT_PSK") allowed-ips "$CLIENT_IP/32$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::$octet/128")"
                
                # Создаем конфиг клиента
                CLIENT_CONF="$HOME/$client.conf"
                cat > "$CLIENT_CONF" << EOF
[Interface]
Address = $CLIENT_IP/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = 8.8.8.8, 1.1.1.1
PrivateKey = $CLIENT_KEY

[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $ENDPOINT:$PORT
PersistentKeepalive = 25
EOF
                ok "Клиент добавлен!"
                ok "Конфиг: $CLIENT_CONF"
                if command -v qrencode &>/dev/null; then
                    qrencode -t ansiutf8 -m 1 < "$CLIENT_CONF"
                fi
                exit 0
                ;;
            2)
                # Удаление WireGuard
                section "Удаление WireGuard"
                read -p "Вы уверены, что хотите удалить WireGuard? [y/N]: " remove <&3 || true
                if [[ "$remove" =~ ^[yY]$ ]]; then
                    systemctl disable --now wg-quick@wg0.service || true
                    systemctl disable --now wg-iptables.service || true
                    rm -f /etc/systemd/system/wg-iptables.service
                    rm -f /etc/sysctl.d/99-wireguard-forward.conf
                    rm -rf /etc/wireguard/
                    systemctl daemon-reload || true
                    
                    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
                        apt-get remove -y wireguard wireguard-tools qrencode || true
                    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                        dnf remove -y wireguard-tools qrencode || true
                    fi
                    ok "WireGuard успешно удален!"
                else
                    log "Удаление отменено."
                fi
                exit 0
                ;;
            3)
                log "Выход..."
                exit 0
                ;;
        esac
    fi

    # ── Первоначальная установка ──────────────────────────────────────────────────
    section "Обнаружение виртуализации и сети"

    # Определение основного сетевого интерфейса (через который ходит интернет)
    PUB_NIC="$(ip -4 route ls 2>/dev/null | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)"
    if [[ -z "$PUB_NIC" ]]; then
        PUB_NIC="$(ip -4 route ls 2>/dev/null | grep default | awk '{print $5}' | head -1 || true)"
    fi
    log "Основной сетевой интерфейс: ${PUB_NIC:-не определен}"

    VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
    log "Тип виртуализации: $VIRT"

    use_boringtun="0"
    if ! systemd-detect-virt -cq 2>/dev/null; then
        ok "Не контейнер — kernel WireGuard"
    elif grep -q '^wireguard ' /proc/modules 2>/dev/null; then
        ok "Контейнер, но модуль ядра доступен"
    else
        use_boringtun="1"
        warn "Контейнер без модуля — будет установлен BoringTun"
        ARCH=$(uname -m)
        [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]] || die "BoringTun поддерживает только x86_64 и aarch64"
        if [[ ! -e /dev/net/tun ]]; then
            die "TUN-устройство недоступно. Включите TUN в панели VPS"
        fi
        ( exec 7<>/dev/net/tun ) 2>/dev/null || die "TUN-устройство заблокировано"
    fi

    # ── Выбор IP ──────────────────────────────────────────────────────────────────
    section "Конфигурация сети сервера"
    
    # Пытаемся найти публичный IP автоматически
    public_candidate=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | grep -vE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)' | head -1 || true)
    all_ips=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true)
    ip_count=$(echo "$all_ips" | wc -l)

    if [[ -n "$public_candidate" ]]; then
        ip="$public_candidate"
        ok "Автовыбран публичный IPv4: $ip"
    elif [[ "$ip_count" -eq 1 ]]; then
        ip="$all_ips"
        ok "Единственный IPv4: $ip"
    else
        echo "$all_ips" | nl -s ') '
        read -p "Выберите IPv4 адрес [1]: " ip_number <&3 || true
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$ip_count" ]]; do
            echo "Неверный выбор."
            read -p "Выберите IPv4 адрес [1]: " ip_number <&3 || true
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(echo "$all_ips" | sed -n "${ip_number}p")
        ok "Выбран IPv4: $ip"
    fi

    # Проверка на NAT (серый IP)
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        warn "Сервер находится за NAT (приватный IP)."
        get_public_ip=$(wget -T 5 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 5 -4Ls "http://ip1.dynupdate.no-ip.com/" || echo "")
        read -p "Укажите публичный IP или домен[$get_public_ip]: " public_ip <&3 || true
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
        until [[ -n "$public_ip" ]]; do
            read -p "Обязательное поле. Публичный IP: " public_ip <&3 || true
        done
    else
        public_ip="$ip"
    fi

    # Настройки клиента
    port=""
    read -p "Порт WireGuard [51820]: " port <&3 || true
    [[ -z "$port" ]] && port="51820"

    unsanitized_client=""
    read -p "Имя первого клиента[client]: " unsanitized_client <&3 || true
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
    [[ -z "$client" ]] && client="client"

    echo "  1) Google (8.8.8.8)"
    echo "  2) Cloudflare (1.1.1.1)"
    echo "  3) AdGuard (94.140.14.14 - блокировка рекламы)"
    read -p "DNS сервер для клиента [1]: " dns_choice <&3 || true
    case "${dns_choice:-1}" in
        2) dns="1.1.1.1, 1.0.0.1" ;;
        3) dns="94.140.14.14, 94.140.15.15" ;;
        *) dns="8.8.8.8, 8.8.4.4" ;;
    esac

    # ── Установка пакетов ─────────────────────────────────────────────────────────
    section "Установка пакетов"
    firewall="iptables"
    if systemctl is-active --quiet firewalld.service; then
        firewall="firewalld"
    fi

    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y qrencode iproute2 iptables $firewall
        if [[ "$use_boringtun" -eq 0 ]]; then
            apt-get install -y wireguard
        else
            apt-get install -y wireguard-tools ca-certificates wget tar --no-install-recommends
        fi
    else
        # RHEL / Fedora
        if [[ "$os" == "centos" ]]; then
            dnf install -y epel-release
        fi
        dnf install -y wireguard-tools qrencode iproute iptables $firewall tar wget
        mkdir -p /etc/wireguard/
    fi

    # Установка BoringTun, если нужно
    if [[ "$use_boringtun" -eq 1 ]]; then
        log "Скачивание BoringTun ($ARCH)..."
        BORING_URL="https://wg.nyr.be/1/latest/download"
        wget -qO- "$BORING_URL" | tar xz -C /usr/local/sbin/ --wildcards "boringtun-*/boringtun" --strip-components 1
        mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/
        echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
        ok "BoringTun установлен"
    fi

    # ── Генерация конфигов ────────────────────────────────────────────────────────
    section "Генерация конфигурации"
    
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    
    CLIENT_KEY=$(wg genkey)
    CLIENT_PSK=$(wg genpsk)
    CLIENT_PUBKEY=$(echo "$CLIENT_KEY" | wg pubkey)
    
    cat > /etc/wireguard/wg0.conf << EOF
# ENDPOINT $public_ip

[Interface]
Address = 10.7.0.1/24
PrivateKey = $SERVER_PRIVKEY
ListenPort = $port

# BEGIN_PEER $client
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.7.0.2/32
# END_PEER $client
EOF

    CLIENT_CONF="$HOME/$client.conf"
    cat > "$CLIENT_CONF" << EOF
[Interface]
Address = 10.7.0.2/24
DNS = $dns
PrivateKey = $CLIENT_KEY

[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $public_ip:$port
PersistentKeepalive = 25
EOF

    ok "Конфиг сервера: /etc/wireguard/wg0.conf"
    ok "Конфиг клиента: $CLIENT_CONF"

    # ── Сеть и Файрвол ────────────────────────────────────────────────────────────
    section "Настройка сети и Firewall"

    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
    sysctl -p /etc/sysctl.d/99-wireguard-forward.conf >/dev/null 2>&1 || true
    ok "IP Forwarding включен"

    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        log "Обнаружен активный UFW — добавляем правило для порта $port/udp"
        ufw allow "${port}/udp" >/dev/null 2>&1
        ufw route allow in on wg0 out on "${PUB_NIC:-eth0}" >/dev/null 2>&1
        ok "UFW: правила для WireGuard добавлены"
    fi

    # Если мы нашли интерфейс — привязываем NAT жестко к нему для безопасности
    NIC_OPT=""
    [[ -n "$PUB_NIC" ]] && NIC_OPT="-o $PUB_NIC"

    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --permanent --add-port="${port}/udp"
        firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
        firewall-cmd --reload
        ok "Firewalld настроен"
    else
        iptables_path=$(command -v iptables)
        # Обработка OpenVZ / nftables legacy
        if [[ $(systemd-detect-virt 2>/dev/null) == "openvz" ]] && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
        fi

        cat > /etc/systemd/system/wg-iptables.service << EOF
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 $NIC_OPT -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 $NIC_OPT -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable --now wg-iptables.service
        ok "iptables настроен (wg-iptables.service)"
    fi

    # ── Запуск ────────────────────────────────────────────────────────────────────
    systemctl enable --now wg-quick@wg0.service
    sleep 2

    if systemctl is-active --quiet wg-quick@wg0.service; then
        ok "WireGuard сервис успешно запущен"
    else
        err "Сервис не запустился! Проверьте логи: journalctl -u wg-quick@wg0"
        die "Установка завершена с ошибкой."
    fi

    # ── Вывод ─────────────────────────────────────────────────────────────────────
    section "QR-код конфигурации $client"
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 -m 1 < "$CLIENT_CONF"
    else
        warn "Утилита qrencode не найдена."
    fi

    echo ""
    log "Установка полностью завершена."
    log "Конфиг лежит тут: ${GREEN}$CLIENT_CONF${NC}"
    log "Если хотите добавить еще клиентов, просто запустите этот скрипт заново."
}

# Запуск главной функции (защита от неполного скачивания пайпом)
main "$@"