#!/usr/bin/env bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (Бронебойная версия)
set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✔${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✘  Ошибка: $*${NC}" >&2; exit 1; }

TOTAL=13
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
# [3] СОЗДАНИЕ ОБЫЧНОГО ПОЛЬЗОВАТЕЛЯ (интерактивный ввод данных)
# =======================================================================
step "3" "👤 Создание обычного пользователя (ввод данных)..."

# ──────────────────────────────────────────────────────────────────────
# Функция безопасного чтения пароля с подтверждением
# ──────────────────────────────────────────────────────────────────────
read_password() {
    local prompt="$1" pass1 pass2
    while true; do
        read -rsp "$prompt: " pass1
        echo >&2
        read -rsp "Подтвердите пароль: " pass2
        echo >&2
        if [ "$pass1" != "$pass2" ]; then
            warn "Пароли не совпадают. Повторите попытку."
            continue
        fi
        if [ ${#pass1} -lt 6 ]; then
            warn "Пароль слишком короткий (минимум 6 символов)."
            continue
        fi
        break
    done
    echo "$pass1"
}

# ──────────────────────────────────────────────────────────────────────
# 3a. Запрос имени пользователя
# ──────────────────────────────────────────────────────────────────────
while true; do
    echo -e "${CYAN}   Введите имя нового пользователя (латиница, без пробелов):${NC}"
    read -rp "   Имя пользователя: " NEW_USER
    if [ -z "$NEW_USER" ]; then
        warn "Имя не может быть пустым."
        continue
    fi
    if ! echo "$NEW_USER" | grep -qE '^[a-z_][a-z0-9_-]*$'; then
        warn "Имя должно начинаться с латинской буквы или '_', содержать только a-z, 0-9, -, _."
        continue
    fi
    break
done

# ──────────────────────────────────────────────────────────────────────
# 3b. Проверка существования пользователя
# ──────────────────────────────────────────────────────────────────────
if id "$NEW_USER" &>/dev/null; then
    warn "Пользователь $NEW_USER уже существует — выбираем другое имя."
    while true; do
        read -rp "   Введите другое имя пользователя: " NEW_USER
        if [ -z "$NEW_USER" ]; then
            warn "Имя не может быть пустым."
            continue
        fi
        if ! echo "$NEW_USER" | grep -qE '^[a-z_][a-z0-9_-]*$'; then
            warn "Некорректное имя (только a-z, 0-9, -, _)."
            continue
        fi
        if ! id "$NEW_USER" &>/dev/null; then
            break
        fi
        warn "Пользователь $NEW_USER тоже существует. Попробуйте ещё раз."
    done
fi

# ──────────────────────────────────────────────────────────────────────
# 3c. Запрос пароля (с подтверждением)
# ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}   Задайте пароль для пользователя ${NEW_USER}:${NC}"
PASSWORD=$(read_password "   Введите пароль")

# ──────────────────────────────────────────────────────────────────────
# 3d. Запрос групп (предложить sudo, docker по умолчанию)
# ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}   Дополнительные группы (через запятую, без пробелов).${NC}"
echo -e "${CYAN}   По умолчанию: sudo,docker${NC}"
read -rp "   Группы: " USER_GROUPS
USER_GROUPS="${USER_GROUPS:-sudo,docker}"

# ──────────────────────────────────────────────────────────────────────
# 3e. Запрос про SSH-ключи
# ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}   Копировать SSH-ключи от root? (Y/n)${NC}"
read -rp "   [Y/n]: " COPY_SSH
COPY_SSH="${COPY_SSH:-y}"

# ──────────────────────────────────────────────────────────────────────
# 3f. Создание пользователя
# ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}   ⚙️  Создаю пользователя ${NEW_USER}...${NC}"

useradd -m -s /bin/bash "$NEW_USER"

# Устанавливаем пароль через chpasswd (безопаснее passwd в скриптах)
echo "$NEW_USER:$PASSWORD" | chpasswd
ok "Пароль установлен"

# Добавляем в группы (перебираем по запятой)
IFS=',' read -ra GROUP_ARRAY <<< "$USER_GROUPS"
for grp in "${GROUP_ARRAY[@]}"; do
    grp="$(echo "$grp" | xargs)"  # обрезаем лишние пробелы
    if [ -n "$grp" ]; then
        usermod -aG "$grp" "$NEW_USER" 2>/dev/null || warn "Группа '$grp' не найдена — пропускаем"
    fi
done
ok "Пользователь добавлен в группы: $USER_GROUPS"

# Настройка SSH
mkdir -p /home/"$NEW_USER"/.ssh
touch /home/"$NEW_USER"/.ssh/authorized_keys

if [[ "$COPY_SSH" =~ ^[YyДд]$ ]] && [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
    cat /root/.ssh/authorized_keys >> /home/"$NEW_USER"/.ssh/authorized_keys
    ok "SSH-ключи скопированы от root"
fi

# ──────────────────────────────────────────────────────────────────────
# 3g. Предложение скопировать ключ с локальной машины
# ──────────────────────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
KEY_COUNT=$(wc -l < /home/"$NEW_USER"/.ssh/authorized_keys)

if [ "$KEY_COUNT" -eq 0 ]; then
    echo ""
    echo -e "${YELLOW}   ⚠️  SSH-ключи не найдены. Подключитесь по паролю и добавьте ключ вручную.${NC}"
    echo -e "${CYAN}   Выполните на своей локальной машине:${NC}"
    echo -e "   ${YELLOW}ssh-copy-id -i ~/.ssh/id_rsa.pub ${NEW_USER}@${SERVER_IP}${NC}"
    echo ""
    echo -e "${CYAN}   После этого скрипт скопирует ключ.${NC}"
    echo -e "${CYAN}   Готово? Нажмите Enter для продолжения (или введите 's' чтобы пропустить):${NC}"
    read -rp "   [Enter/s]: " WAIT_KEY
    if [ "$WAIT_KEY" != "s" ] && [ "$WAIT_KEY" != "S" ]; then
        # Повторно проверяем authorized_keys — мог появиться через ssh-copy-id
        if [ -f /home/"$NEW_USER"/.ssh/authorized_keys ]; then
            cat /root/.ssh/authorized_keys 2>/dev/null >> /home/"$NEW_USER"/.ssh/authorized_keys
        fi
        KEY_COUNT=$(wc -l < /home/"$NEW_USER"/.ssh/authorized_keys)
    fi
fi

# Права
chown -R "$NEW_USER:$NEW_USER" /home/"$NEW_USER"/.ssh
chmod 700 /home/"$NEW_USER"/.ssh
chmod 600 /home/"$NEW_USER"/.ssh/authorized_keys

ok "Пользователь $NEW_USER создан (группы: $USER_GROUPS; ключей: $KEY_COUNT)"

# ──────────────────────────────────────────────────────────────────────
# 3h. Проверка — можно ли отключить пароль для sudo (если есть SSH-ключи)
# ──────────────────────────────────────────────────────────────────────
if [ "$KEY_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${CYAN}   Отключить запрос пароля для sudo у ${NEW_USER}? (y/N)${NC}"
    read -rp "   [y/N]: " NOPASSWD
    if [[ "${NOPASSWD:-n}" =~ ^[YyДд]$ ]]; then
        echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$NEW_USER"
        chmod 440 /etc/sudoers.d/"$NEW_USER"
        ok "sudo без пароля включён для $NEW_USER"
    fi
fi

# =======================================================================
# [4] SSH — только ключи
# =======================================================================
step "4" "🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "Не удалось перезапустить SSH — проверьте вручную"
ok "SSH-пароли отключены"

# =======================================================================
# [5] SWAP
# =======================================================================
step "5" "💾 Настройка файла подкачки (Swap) на 2 GB..."
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
# [6] АВТООБНОВЛЕНИЯ БЕЗОПАСНОСТИ
# =======================================================================
step "6" "🛡️  Включение автообновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" \
    | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
ok "Автообновления включены"

# =======================================================================
# [7] БАЗОВЫЙ ФАЙРВОЛ (ufw)
# =======================================================================
step "7" "🔥 Настройка файрвола (ufw)..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp      # Nginx HTTP
ufw allow 443/tcp     # Nginx HTTPS
ufw allow 51820/udp   # WireGuard
ufw allow 9993/udp    # ZeroTier
ufw --force enable >/dev/null 2>&1 || warn "UFW запущен с предупреждениями (нормально для контейнера)"
ok "Файрвол настроен"

# =======================================================================
# [8] DOCKER
# =======================================================================
step "8" "🐳 Установка Docker..."
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
# [9] NODE.JS LTS
# =======================================================================
step "9" "🟢 Установка Node.js (LTS)..."
if command -v node &>/dev/null; then
    warn "Node.js уже установлен ($(node --version)) — пропускаем"
else
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1
    apt-get install -y nodejs >/dev/null 2>&1
    ok "Node.js $(node --version) установлен"
fi

# =======================================================================
# [10] AI CLI УТИЛИТЫ
# =======================================================================
step "10" "🤖 Установка AI CLI утилит..."
NPM_PKGS=("@google/gemini-cli" "opencode-ai" "@kilocode/cli" "cline")
for pkg in "${NPM_PKGS[@]}"; do
    if npm list -g "$pkg" &>/dev/null; then
        warn "$pkg уже установлен — пропускаем"
    else
        npm install -g "$pkg" >/dev/null 2>&1 && ok "$pkg установлен" || warn "Ошибка при установке $pkg"
    fi
done

# =======================================================================
# [11] СИСТЕМНЫЙ МОНИТОРИНГ (sysinfo.sh)
# =======================================================================
step "11" "📊 Установка системного монитора sysinfo..."

SYSINFO_SRC="$(dirname "$(readlink -f "$0")")/sysinfo.sh"

if [[ -f "$SYSINFO_SRC" ]]; then
    cp "$SYSINFO_SRC" /etc/profile.d/sysinfo.sh
    chmod +x /etc/profile.d/sysinfo.sh
    ok "sysinfo.sh установлен в /etc/profile.d/ (вывод при каждом SSH-подключении)"
else
    warn "sysinfo.sh не найден рядом с index.sh — устанавливаем через curl..."
    curl -fsSL --connect-timeout 5 \
        "https://raw.githubusercontent.com/$(git -C "$(dirname "$(readlink -f "$0")")" remote get-url origin 2>/dev/null | sed 's/\.git$//' | sed 's|git@github.com:|https://github.com/|')/main/sysinfo.sh" \
        -o /etc/profile.d/sysinfo.sh 2>/dev/null

    if [[ -s /etc/profile.d/sysinfo.sh ]]; then
        chmod +x /etc/profile.d/sysinfo.sh
        ok "sysinfo.sh скачан и установлен в /etc/profile.d/"
    else
        warn "Не удалось скачать sysinfo.sh — пропускаем. Установите вручную:"
        warn "  scp sysinfo.sh root@<server>:/etc/profile.d/sysinfo.sh"
    fi
fi

# =======================================================================
# ФИНАЛЬНЫЙ ВЫВОД
# =======================================================================
echo ""
echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена!                  "
echo "======================================================="
echo ""