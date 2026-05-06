#!/usr/bin/env bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (Бронебойная версия)
set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✔${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✘  Ошибка: $*${NC}" >&2; exit 1; }

TOTAL=10
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
# [1] ИСПРАВЛЕНИЕ TZDATA (ЧАСОВЫЕ ПОЯСА)
# =======================================================================
step "1" "⏱️  Превентивное исправление часовых поясов (tzdata)..."
# В контейнерах Ubuntu 24.04 часто отсутствуют эти файлы, что ломает 'apt upgrade'
rm -f /etc/localtime /etc/timezone
echo "Etc/UTC" > /etc/timezone
ln -sf /usr/share/zoneinfo/Etc/UTC /etc/localtime
set +e
dpkg-reconfigure -f noninteractive tzdata >/dev/null 2>&1
set -e
ok "Часовой пояс (UTC) установлен, ошибка tzdata предотвращена"

# =======================================================================
# [2] ОБНОВЛЕНИЕ СИСТЕМЫ
# =======================================================================
step "2" "📦 Обновление списка пакетов и системы..."
apt-get update -y
apt-get upgrade -y
apt-get install -y \
    git python3 python3-pip python3-venv \
    nginx curl wget ca-certificates \
    build-essential qrencode \
    iptables iproute2 ufw
ok "Базовые пакеты установлены"

# =======================================================================
# [3] SSH — только ключи
# =======================================================================
step "3" "🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "Не удалось перезапустить SSH — проверьте вручную"
ok "SSH-пароли отключены"

# =======================================================================
# [4] SWAP
# =======================================================================
step "4" "💾 Настройка файла подкачки (Swap) на 2 GB..."
if grep -q "swapfile" /etc/fstab 2>/dev/null; then
    warn "Swap уже настроен — пропускаем"
else
    # Безопасное выделение места
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    
    # Проверка, разрешает ли виртуализация (Virtuozzo/LXC) включить swap
    set +e
    swapon /swapfile 2>/dev/null
    SWAP_EXIT=$?
    set -e
    
    if [ $SWAP_EXIT -eq 0 ]; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        ok "Swap успешно создан и активирован"
    else
        warn "Контейнерная виртуализация не поддерживает Swap. Удаляем файл (2GB сохранены)..."
        rm -f /swapfile
    fi
fi

# =======================================================================
# [5] АВТООБНОВЛЕНИЯ БЕЗОПАСНОСТИ
# =======================================================================
step "5" "🛡️  Включение автообновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" \
    | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
ok "Автообновления включены"

# =======================================================================
# [6] БАЗОВЫЙ ФАЙРВОЛ (ufw)
# =======================================================================
step "6" "🔥 Настройка файрвола (ufw)..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp   # WireGuard
ufw --force enable >/dev/null 2>&1 || warn "UFW запущен с предупреждениями (нормально для контейнера)"
ok "Файрвол настроен"

# =======================================================================
# [7] DOCKER
# =======================================================================
step "7" "🐳 Установка Docker..."
if command -v docker &>/dev/null; then
    warn "Docker уже установлен ($(docker --version)) — пропускаем"
else
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh >/dev/null 2>&1
    rm -f /tmp/get-docker.sh
    systemctl enable --now docker 2>/dev/null || true
    ok "Docker установлен и запущен"
fi

# =======================================================================
# [8] NODE.JS LTS
# =======================================================================
step "8" "🟢 Установка Node.js (LTS)..."
if command -v node &>/dev/null; then
    warn "Node.js уже установлен ($(node --version)) — пропускаем"
else
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1
    apt-get install -y nodejs >/dev/null 2>&1
    ok "Node.js $(node --version) установлен"
fi

# =======================================================================
# [9] AI CLI УТИЛИТЫ
# =======================================================================
step "9" "🤖 Установка AI CLI утилит..."
NPM_PKGS=("@google/gemini-cli" "opencode-ai" "@kilocode/cli" "cline")
for pkg in "${NPM_PKGS[@]}"; do
    if npm list -g "$pkg" &>/dev/null; then
        warn "$pkg уже установлен — пропускаем"
    else
        npm install -g "$pkg" >/dev/null 2>&1 && ok "$pkg установлен" || warn "Ошибка при установке $pkg"
    fi
done

# =======================================================================
# ФИНАЛЬНЫЙ ВЫВОД
# =======================================================================
echo ""
echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена!                  "
echo "======================================================="
echo ""
echo "🔹 Установленные пакеты:"
echo "  - Docker"
echo "  - Node.js LTS"
echo "  - AI CLI утилиты: @google/gemini-cli, opencode-ai, @kilocode/cli, cline"
echo ""
echo "🔹 Настроенные сервисы:"
echo "  - Файрвол (UFW)"
echo "  - WireGuard (порт 51820/udp)"
echo ""
echo "🔹 Рекомендуемые действия:"
echo "  - Настройте WireGuard для доступа к VDS"
echo "  - Установите необходимые приложения для работы"
echo ""
echo "🔹 Для проверки работы AI CLI утилит попробуйте:"
echo "  gemini-cli --help"
echo "  opencode-ai --help"
echo "  kilo --help"
echo "  cline --help"
echo ""