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
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
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
# ФИНАЛЬНЫЙ ВЫВОД
# =======================================================================
echo ""
echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена!                  "
echo "======================================================="