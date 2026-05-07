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

### `zt-install.sh` — ZeroTier VPN + ZTNET Panel + Internet Gateway

Полная установка ZeroTier с веб-панелью ZTNET и настройкой сервера как шлюза для раздачи интернета всем участникам ZT-сети (8 шагов):

| Шаг | Описание |
|-----|----------|
| — | 🌐 Анализ сетевой архитектуры: основной интерфейс, IP, шлюз, DNS, все интерфейсы |
| 1 | 📦 Обновление системы, установка `iptables-persistent` |
| 2 | 📡 Установка ZeroTier (официальный скрипт) |
| 3 | 🐳 Установка Docker + Compose |
| 4 | ⚡ IP Forwarding (`sysctl`, постоянный через `/etc/sysctl.d/99-zt-forward.conf`) |
| 5 | 🐘 Docker Compose: PostgreSQL + ZeroTier (контейнер) + ZTNET Panel |
| 5 | 🔥 NAT/iptables: хост (`MASQUERADE` Docker→интернет) + UFW правила |
| 6 | 🚀 Запуск контейнеров, проверка DNS и API |
| 7 | 🔀 NAT внутри контейнера zerotier (`zt+ → eth0 → MASQUERADE`) |
| 8 | 🖧 Интерактивное подключение к ZT-сети: запрос Network ID → `zerotier-cli join` → ожидание авторизации → получение ZT-IP |

**Интерактивный шаг 8:**
1. Создайте сеть в браузере (`http://<IP>:3000`)
2. Скрипт запросит **Network ID** — вставьте его
3. Скрипт выполнит `zerotier-cli join <NETWORK_ID>`
4. Скрипт попросит авторизовать ноду в панели (Members → Auth)
5. Скрипт ждёт до 150 секунд (30 попыток по 5 сек), polling ZT-IP
6. После авторизации ZT-IP выводится в итоговой сводке

**Ключевые возможности:**
- Автоопределение сетевой архитектуры сервера (интерфейс, шлюз, публичный IP, DNS)
- Двухуровневый NAT: хост + контейнер zerotier
- IP forwarding включён постоянно (переживает перезагрузку)
- iptables правила сохраняются через `netfilter-persistent`
- UFW: автоматически добавляются route rules + NAT
- Скрипт `zt-nat-setup.sh` для восстановления NAT после перезапуска контейнера
- Интерактивное подключение к сети с ожиданием авторизации
- Постановочные инструкции по настройке маршрута `0.0.0.0/0` в ZTNET Panel

**Для раздачи интернета клиентам** — после установки:
1. В ZTNET Panel добавьте Managed Route: `0.0.0.0/0` → ZT-IP сервера
2. На клиенте включите `Allow Default Route`

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