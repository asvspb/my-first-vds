#!/bin/bash
# Автоматическая настройка VDS на Ubuntu 24.04 LTS (С автонастройкой WireGuard)
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
echo -e "\n[1/10] 📦 Обновление списка пакетов и системы..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# 2. Настройка SSH (отключение входа по паролю)
echo -e "\n[2/10] 🔐 Отключение входа по паролю (оставляем только SSH-ключи)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-disable-passwords.conf <<EOF
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh
echo "✅ Доступ по паролю отключен."

# 3. Настройка файла подкачки (Swap) на 2GB
echo -e "\n[3/10] 💾 Создание файла подкачки (Swap) на 2GB..."
if ! grep -q "swapfile" /etc/fstab; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "✅ Swap на 2GB успешно создан."
else
    echo "⚠️ Swap-файл уже существует, пропускаем."
fi

# 4. Автоматическая установка обновлений безопасности
echo -e "\n[4/10] 🛡️ Включение автоматических обновлений безопасности..."
apt-get install -y unattended-upgrades update-notifier-common
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
echo "✅ Автообновления безопасности активированы."

# 5. Установка базового ПО (включая утилиты для WireGuard и QR)
echo -e "\n[5/10] 🛠 Установка Git, Python3, Nginx, WireGuard и зависимостей..."
apt-get install -y git python3 python3-pip python3-venv nginx wireguard wireguard-tools qrencode iptables iproute2 curl wget ca-certificates software-properties-common

# 6. Полная автонастройка WireGuard
echo -e "\n[6/10] 🌐 Настройка WireGuard VPN..."
# Включаем IP Forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -p /etc/sysctl.d/99-wireguard-forward.conf > /dev/null

# Получаем публичный IP и название основного сетевого интерфейса
SERVER_PUB_IP=$(curl -sSf ifconfig.me || curl -sSf api.ipify.org)
SERVER_PUB_NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# Генерация ключей
cd /etc/wireguard
umask 077
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# Создание конфига сервера
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.66.66.2/32
EOF

# Создание конфига клиента
cat > /root/wg0-client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = 10.66.66.2/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PSK
Endpoint = $SERVER_PUB_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Запуск и тестирование WireGuard
systemctl enable wg-quick@wg0.service > /dev/null 2>&1
systemctl start wg-quick@wg0.service

# Тестируем запуск
if systemctl is-active --quiet wg-quick@wg0.service && ip a show wg0 > /dev/null 2>&1; then
    WG_TEST_RESULT="✅ WireGuard УСПЕШНО запущен и интерфейс wg0 поднят!"
else
    WG_TEST_RESULT="❌ Ошибка при запуске WireGuard!"
fi
echo "$WG_TEST_RESULT"

# 7. Установка Docker
echo -e "\n[7/10] 🐳 Установка Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
    echo "✅ Docker успешно установлен."
else
    echo "⚠️ Docker уже установлен."
fi

# 8. Установка Node.js (LTS)
echo -e "\n[8/10] 🟢 Установка Node.js (LTS)..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - > /dev/null 2>&1
    apt-get install -y nodejs
    echo "✅ Node.js установлен: $(node -v)"
else
    echo "⚠️ Node.js уже установлен: $(node -v)"
fi

# 9. Установка AI CLI агентов
echo -e "\n[9/10] 🤖 Установка AI CLI утилит..."
npm install -g @google/gemini-cli opencode-ai @kilocode/cli cline > /dev/null 2>&1
echo "✅ AI инструменты (Gemini, OpenCode, KiloCode, Cline) успешно установлены."

# 10. Очистка кэша
echo -e "\n[10/10] 🧹 Очистка системы..."
apt-get autoremove -y > /dev/null 2>&1
apt-get clean

echo "======================================================="
echo " 🎉 Настройка VDS успешно завершена! "
echo "======================================================="
echo "✔️  ПО: Nginx, Git, Python3, Docker, Node.js"
echo "✔️  AI CLI: gemini, opencode, kilo, cline"
echo "✔️  SSH: Доступ по паролю ЗАКРЫТ. Только ключи!"
echo "$WG_TEST_RESULT"
echo "======================================================="
echo "📱 ДАННЫЕ ВАШЕГО WIREGUARD КЛИЕНТА:"
echo "======================================================="
cat /root/wg0-client.conf
echo "======================================================="
echo "Отсканируйте QR-код ниже в приложении WireGuard на телефоне:"
echo ""
# Вывод QR-кода в терминале
qrencode -t ansiutf8 < /root/wg0-client.conf
echo ""
echo "Конфиг-файл также сохранен на сервере по пути: /root/wg0-client.conf"
echo "Рекомендуется перезагрузить сервер (reboot) для применения всех системных патчей."