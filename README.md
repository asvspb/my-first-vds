# Настройка Ubuntu 24.04 для разработки

Набор скриптов для быстрой инициализации и управления VDS на Ubuntu 24.04.

## Скрипты

### `preinstall.sh` — Предварительная настройка

Быстрая подготовка свежего сервера перед основной настройкой (6 шагов):

1. **Чиним прерванные установки** — `dpkg --configure -a`, `apt --fix-broken install`
2. **Часовой пояс UTC** — `timedatectl set-timezone UTC`
3. **Обновление списка пакетов** — `apt update`
4. **Обновление системы** — неинтерактивный `apt upgrade`
5. **Установка утилит** — `git`, `curl`, `wget`, `mc` (Midnight Commander)
6. **Проверка** — вывод версии Git

```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/preinstall.sh | sudo bash
```

### `index.sh` — Основная настройка сервера

Полная автоматизация начальной настройки VDS (12 шагов):

| Шаг | Описание |
|-----|----------|
| 0 | 🩺 Очистка системы от зависших пакетов (лечит последствия прерванных установок) |
| 1 | ⏱️ Исправление tzdata (часовой пояс UTC) |
| 2 | 📦 Обновление системы и установка базовых пакетов (git, python3, nginx, curl, ufw и др.) |
| 3 | 👤 Создание обычного пользователя с SSH-ключами |
| 4 | 🔐 SSH — только ключи (пароли отключены) |
| 5 | 💾 Swap 2 GB |
| 6 | 🛡️ Автообновления безопасности (unattended-upgrades) |
| 7 | 🔥 Файрвол (UFW): SSH, HTTP/HTTPS, WireGuard, ZeroTier |
| 8 | 🐳 Docker |
| 9 | 🟢 Node.js LTS |
| 10 | 🤖 AI CLI утилиты (Gemini CLI, OpenCode, KiloCode, Cline) |
| 11 | 📊 Системный монитор sysinfo (вывод при SSH-подключении) |

### `sysinfo.sh` — Системный монитор

Выводит сводку о состоянии сервера при каждом SSH-подключении:

- OS, ядро, аптайм, модель CPU, load average
- Публичный и локальный IP
- CPU / RAM / Swap с цветовыми прогресс-барами
- Использование дисков
- Статус Docker-контейнеров
- IP источника SSH, активные соединения
- Неудачные попытки входа за 24ч
- Топ процессов по памяти
- Последние логины

### `wg-install.sh` — WireGuard VPN

Установка и настройка WireGuard VPN-сервера. Быстрое создание защищённого туннеля для доступа к серверу:

- Генерация ключей сервера и клиента
- Конфигурация интерфейса wg0
- Вывод QR-кода для подключения с мобильного устройства
- Открытие порта 51820/udp в UFW

### `zt-install.sh` — ZeroTier VPN

Установка ZeroTier — программно-определяемой сети (SDN) для объединения устройств:

- Установка ZeroTier через официальный скрипт
- Запуск и добавление в автозагрузку
- Открытие порта 9993/udp в UFW

## Установка

**Предварительная настройка** (перед основной):
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/preinstall.sh | sudo bash
```

**Основная настройка сервера** (всё включено):
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/index.sh | sudo bash
```

**Только системный монитор** (без полной настройки):
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/sysinfo.sh | sudo tee /etc/profile.d/sysinfo.sh > /dev/null && sudo chmod +x /etc/profile.d/sysinfo.sh
```

**WireGuard:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/wg-install.sh | sudo bash
```

**ZeroTier:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-install.sh | sudo bash
```

## Требования

- Ubuntu 24.04 (LTS)
- Доступ к интернету
- Права суперпользователя (sudo)

## Лицензия

MIT