#!/usr/bin/env bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (Бронебойная версия)
set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✔${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✘  Ошибка: $*${NC}" >&2; exit 1; }

TOTAL=9
step() { echo -e "\n${CYAN}[$1/$TOTAL]${NC} $2"; }

echo "======================================================="
echo "   🚀 Инициализация базовой настройки Ubuntu 24.04     "
echo "======================================================="

[ "$EUID" -eq 0 ] || die "Запустите скрипт от имени root"

export DEBIAN_FRONTEND=noninteractive

# =======================================================================
# [0] САМОЛЕЧЕНИЕ — чиним зависшие пакеты после прошлых сбоев
# =======================================================================
step "0" "🩺 Очистка системы от зависших пакетов..."
set +e
dpkg --configure -a                          >/dev/null 2>&1
apt-get --fix-broken install -y             >/dev/null 2>&1
apt-get remove -y --purge npm nodejs libnode* >/dev/null 2>&1
apt-get autoremove -y                        >/dev/null 2>&1
apt-get clean
set -e
ok "Система очищена"

# =======================================================================
# [1] ОБНОВЛЕНИЕ СИСТЕМЫ
# =======================================================================
step "1" "📦 Обновление списка пакетов и системы..."
apt-get update -y
apt-get upgrade -y
apt-get install -y \
    git python3 python3-pip python3-venv \
    nginx curl wget ca-certificates \
    build-essential qrencode \
    iptables iproute2 ufw
ok "Базовые пакеты установлены"

# =======================================================================
# [2] SSH — только ключи
# =======================================================================
step "2" "🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "Не удалось перезапустить SSH — проверьте вручную"
ok "SSH-пароли отключены"

# =======================================================================
# [3] SWAP
# =======================================================================
step "3" "💾 Создание файла подкачки (Swap) на 2 GB..."
if grep -q "swapfile" /etc/fstab 2>/dev/null; then
    warn "Swap уже настроен — пропускаем"
else
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    ok "Swap создан и активирован"
fi

# =======================================================================
# [4] АВТООБНОВЛЕНИЯ БЕЗОПАСНОСТИ
# =======================================================================
step "4" "🛡️  Включение автообновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" \
    | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
ok "Автообновления включены"

# =======================================================================
# [5] БАЗОВЫЙ ФАЙРВОЛ (ufw)
# =======================================================================
step "5" "🔥 Настройка файрвола (ufw)..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp   # WireGuard
ufw --force enable
ok "Файрвол настроен"

# =======================================================================
# [6] DOCKER
# =======================================================================
step "6" "🐳 Установка Docker..."
if command -v docker &>/dev/null; then
    warn "Docker уже установлен ($(docker --version)) — пропускаем"
else
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
    systemctl enable --now docker
    ok "Docker установлен и запущен"
fi

# =======================================================================
# [7] NODE.JS LTS
# =======================================================================
step "7" "🟢 Установка Node.js (LTS)..."
if command -v node &>/dev/null; then
    warn "Node.js уже установлен ($(node --version)) — пропускаем"
else
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y nodejs
    ok "Node.js $(node --version) установлен"
fi

# =======================================================================
# [8] AI CLI УТИЛИТЫ
# =======================================================================
step "8" "🤖 Установка AI CLI утилит..."
NPM_PKGS=("@google/gemini-cli" "opencode-ai" "@kilocode/cli" "cline")
for pkg in "${NPM_PKGS[@]}"; do
    if npm list -g "$pkg" &>/dev/null; then
        warn "$pkg уже установлен — пропускаем"
    else
        npm install -g "$pkg" && ok "$pkg установлен"
    fi
done

# =======================================================================
# [9] WIREGUARD
# =======================================================================
step "9" "🌐 Установка WireGuard..."
if [ -f "/etc/wireguard/wg0.conf" ]; then
    warn "WireGuard уже настроен — пропускаем базовую установку"
else
    curl -fsSL https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh \
        -o /tmp/wireguard-install.sh
    chmod +x /tmp/wireguard-install.sh

    # Скрипт Angristan НЕ читает переменные окружения — он всегда вызывает
    # интерактивный read. Передаём ответы через stdin в нужном порядке:
    #   1. IPv4 адрес сервера       → авто-определяется, просто Enter
    #   2. Публичный интерфейс      → авто-определяется, просто Enter
    #   3. Имя WG-интерфейса        → wg0
    #   4. IPv4 подсеть WG          → 10.66.66.1
    #   5. IPv6 подсеть WG          → fd42:42:42::1
    #   6. Порт                     → 51820
    #   7. DNS 1                    → 8.8.8.8
    #   8. DNS 2                    → 8.8.4.4
    #   9. AllowedIPs               → 0.0.0.0/0,::/0
    #  10. "Press any key..."       → Enter
    #  11. Имя первого клиента      → wg-mobile
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    SERVER_NIC=$(ip -4 route ls | grep default | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)

    printf '%s\n%s\nwg0\n10.66.66.1\nfd42:42:42::1\n51820\n8.8.8.8\n8.8.4.4\n0.0.0.0/0,::/0\n\nwg-mobile\n' \
        "${SERVER_PUB_IP}" "${SERVER_NIC}" \
        | /tmp/wireguard-install.sh

    rm -f /tmp/wireguard-install.sh
    ok "WireGuard установлен"
fi

# =======================================================================
# ФИНАЛЬНЫЙ ВЫВОД
# =======================================================================
echo ""
echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена!                  "
echo "======================================================="

# Ищем конфиг клиента (имя файла может отличаться)
WG_CLIENT_CONF=$(find /root -maxdepth 1 -name "*.conf" -not -name "wg0.conf" 2>/dev/null | head -n1)

if [ -n "$WG_CLIENT_CONF" ]; then
    ok "Конфиг клиента WireGuard: $WG_CLIENT_CONF"
    echo "======================================================="
    echo "📱 ОТСКАНИРУЙТЕ QR-КОД ДЛЯ ПОДКЛЮЧЕНИЯ VPN:"
    echo "======================================================="
    qrencode -t ansiutf8 < "$WG_CLIENT_CONF"
    echo ""
else
    echo "✅ Все сервисы работают в штатном режиме."
    warn "Конфиг клиента WireGuard не найден в /root — проверьте вручную."
fi