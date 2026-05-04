#!/bin/bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (Бронебойная версия)

echo "======================================================="
echo "   🚀 Инициализация базовой настройки Ubuntu 24.04     "
echo "======================================================="

if [ "$EUID" -ne 0 ]; then
  echo "❌ Ошибка: Запустите скрипт от имени root"
  exit 1
fi

# =======================================================================
# БЛОК САМОЛЕЧЕНИЯ: Автоматически чиним систему после прошлых сбоев
# =======================================================================
echo -e "\n[0/8] 🩺 Очистка системы от зависших пакетов и прошлых ошибок..."
set +e  # Временно отключаем остановку при ошибках, чтобы скрипт не прервался
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a >/dev/null 2>&1
apt-get --fix-broken install -y >/dev/null 2>&1
apt-get remove -y --purge npm nodejs libnode* >/dev/null 2>&1
apt-get autoremove -y >/dev/null 2>&1
apt-get clean
set -e  # Включаем строгий контроль обратно
# =======================================================================

echo -e "\n[1/8] 📦 Обновление списка пакетов и системы..."
apt-get update -y
apt-get upgrade -y
apt-get install -y git python3 python3-pip python3-venv nginx curl wget ca-certificates build-essential qrencode iptables iproute2

echo -e "\n[2/8] 🔐 Отключение входа по паролю (только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<EOF
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh || true

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
    rm -f get-docker.sh
fi

echo -e "\n[6/8] 🟢 Установка Node.js (LTS)..."
# Благодаря шагу [0/8] система чиста, конфликта больше не будет
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs

echo -e "\n[7/8] 🤖 Установка AI CLI утилит..."
npm install -g @google/gemini-cli opencode-ai @kilocode/cli cline

echo -e "\n[8/8] 🌐 Установка WireGuard (с защитой от повторного запуска)..."
if [ ! -f "/etc/wireguard/wg0.conf" ]; then
    curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
    chmod +x wireguard-install.sh
    
    export AUTO_INSTALL=y
    export CLIENT_NAME="wg-mobile"
    export WG_PORT=51820
    export DNS_1=8.8.8.8
    export DNS_2=77.88.8.8
    
    ./wireguard-install.sh
else
    echo "⚠️ WireGuard уже установлен. Пропускаем базовую настройку."
fi

echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена! "
echo "======================================================="
if[ -f "/root/wg-mobile.conf" ]; then
    echo "✔️  Ваш конфиг клиента WireGuard сохранен в: /root/wg-mobile.conf"
    echo "======================================================="
    echo "📱 ОТСКАНУЙТЕ QR-КОД ДЛЯ ПОДКЛЮЧЕНИЯ VPN:"
    echo "======================================================="
    qrencode -t ansiutf8 < /root/wg-mobile.conf
    echo ""
else
    echo "✅ Все сервисы работают в штатном режиме."
fi