#!/bin/bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS
set -e

echo "======================================================="
echo "   🚀 Инициализация базовой настройки Ubuntu 24.04     "
echo "======================================================="

# Проверка запуска от имени root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Ошибка: Запустите скрипт от имени root"
  exit 1
fi

echo -e "\n[1/8] 📦 Обновление списка пакетов и системы..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y git python3 python3-pip python3-venv nginx curl wget ca-certificates build-essential qrencode

echo -e "\n[2/8] 🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<EOF
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh

echo -e "\n[3/8] 💾 Создание файла подкачки (Swap) на 2GB..."
if ! grep -q "swapfile" /etc/fstab; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo -e "\n[4/8] 🛡️ Включение автообновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades

echo -e "\n[5/8] 🐳 Установка Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
fi

echo -e "\n[6/8] 🟢 Установка Node.js (LTS)..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    # ИСПРАВЛЕНИЕ: Убрали npm, так как он уже встроен в nodejs
    apt-get install -y nodejs
fi

echo -e "\n[7/8] 🤖 Установка AI CLI утилит..."
npm install -g @google/gemini-cli opencode-ai @kilocode/cli cline

echo -e "\n[8/8] 🌐 Установка WireGuard (через скрипт Angristan)..."
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh

# Задаем жесткие параметры для полностью автоматической (тихой) установки
export AUTO_INSTALL=y
export CLIENT_NAME="wg-mobile"
export WG_PORT=51820
export DNS_1=8.8.8.8
export DNS_2=77.88.8.8

./wireguard-install.sh

echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена! "
echo "======================================================="
echo "✔️  Ваш конфиг клиента WireGuard сохранен в: /root/wg-mobile.conf"
echo "======================================================="
echo "📱 ОТСКАНУЙТЕ QR-КОД ДЛЯ ПОДКЛЮЧЕНИЯ VPN:"
echo "======================================================="
qrencode -t ansiutf8 < /root/wg-mobile.conf
echo ""