#!/bin/bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (c установщиком Nyr)
set -e

echo "======================================================="
echo "   🚀 Инициализация базовой настройки Ubuntu 24.04     "
echo "======================================================="

# Проверка запуска от имени root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Ошибка: Запустите скрипт от имени root"
  exit 1
fi

# 1. Обновление системы
echo -e "\n[1/8] 📦 Обновление списка пакетов и системы..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# 2. Настройка SSH (отключение входа по паролю)
echo -e "\n[2/8] 🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<EOF
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh

# 3. Настройка файла подкачки (Swap)
echo -e "\n[3/8] 💾 Создание файла подкачки (Swap) на 2GB..."
if ! grep -q "swapfile" /etc/fstab; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 4. Автообновления безопасности
echo -e "\n[4/8] 🛡️ Включение автообновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades

# 5. Установка базового ПО и Docker
echo -e "\n[5/8] 🐳 Установка базовых утилит и Docker..."
apt-get install -y git python3 python3-pip python3-venv nginx curl wget ca-certificates
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
fi

# 6. Установка Node.js (LTS)
echo -e "\n[6/8] 🟢 Установка Node.js (LTS)..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - > /dev/null 2>&1
    apt-get install -y nodejs
fi

# 7. Установка AI CLI агентов
echo -e "\n[7/8] 🤖 Установка AI CLI утилит (Gemini, OpenCode, KiloCode, Cline)..."
npm install -g @google/gemini-cli opencode-ai @kilocode/cli cline > /dev/null 2>&1

# 8. WireGuard (через скрипт Nyr)
echo -e "\n[8/8] 🌐 Установка WireGuard..."
echo "Применяем AUTO_INSTALL=y для тихой автоматической установки..."
export AUTO_INSTALL=y
# Если вы запустите скрипт повторно, эта переменная выберет пункт "Добавить клиента"
export MENU_OPTION=1 

wget https://git.io/wireguard -O wireguard-install.sh
bash wireguard-install.sh

echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена! "
echo "======================================================="
echo "✔️  Ваш конфиг клиента WireGuard сохранен в файл: /root/client.conf"
echo "✔️  Скачать его можно через SFTP или скопировав текст командой:"
echo "    cat /root/client.conf"
echo "======================================================="