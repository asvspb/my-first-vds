# Настройка Ubuntu 24.04 для разработки

Версия: **1.2**

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

Установка и настройка WireGuard VPN-сервера с менеджментом клиентов. Быстрое создание защищённого туннеля для доступа к серверу:

- **Первоначальная установка**: генерация ключей сервера и клиента, настройка интерфейса wg0, конфигурация NAT/iptables, вывод QR-кода
- **Добавление клиентов** при повторном запуске: автоматический поиск свободного IP, генерация конфига и QR-кода
- **Удаление WireGuard** при повторном запуске
- **BoringTun** для контейнеров без модуля ядра (OpenVZ, LXC)
- Поддержка UFW и firewalld
- Открытие порта 51820/udp

### `zt-install.sh` — ZeroTier VPN + ZTNET Panel + Internet Gateway

Полная установка ZeroTier с веб-панелью ZTNET и настройкой сервера как шлюза для раздачи интернета всем участникам ZT-сети (8 шагов):

| Шаг | Описание |
|-----|----------|
| — | 🌐 Анализ сетевой архитектуры: основной интерфейс, IP, шлюз, DNS, все интерфейсы |
| 1 | 📦 Обновление системы, установка `iptables-persistent` |
| 2 | 📡 Установка ZeroTier (официальный скрипт) |
| 3 | 🐳 Установка Docker + Compose |
| 4 | ⚡ IP Forwarding (`sysctl`, постоянный через `/etc/sysctl.d/99-zt-forward.conf`) |
| 5 | 🐘 Docker Compose: PostgreSQL + ZeroTier (контейнер) + ZTNET Panel + NAT/iptables |
| 6 | 🚀 Запуск контейнеров, проверка DNS и API |
| 7 | 🔀 Настройка NAT: FORWARD правила для ZT-интерфейса + скрипт + systemd сервис |
| 8 | 🖧 Авто-подключение к ZT-сети: join → само-авторизация → получение ZT-IP → обновление NAT |

**Автоматический шаг 8:**
1. Создайте сеть в браузере (`http://<IP>:3000`)
2. Скрипт запросит **Network ID** — вставьте его
3. `zerotier-cli join <NETWORK_ID>`
4. **Само-авторизация** через Controller API (POST `/controller/network/{ID}/member/{ADDR}`) — **ручная авторизация не требуется**
5. Ожидание ZT-IP (до 150 сек, 30 попыток)
6. **Динамическое определение реального ZT subnet** из Controller API
7. **Автоматическое обновление iptables** при несовпадении подсети с дефолтной
8. **Регенерация** `.env.info` и `zt-nat-setup.sh` с актуальным ZT subnet
9. Инструкция по добавлению Managed Route `0.0.0.0/0` для раздачи интернета

**Ключевые возможности:**
- Автоопределение сетевой архитектуры сервера (интерфейс, шлюз, публичный IP, DNS)
- Self-authorization через Controller API (не требует ручной авторизации в панели)
- Динамическое определение реального ZT subnet — автоматическая корректировка iptables
- Двухуровневый NAT: хост + контейнер zerotier
- IP forwarding включён постоянно (переживает перезагрузку)
- iptables правила сохраняются через `netfilter-persistent`
- UFW: автоматически добавляются route rules + NAT
- Скрипт `zt-nat-setup.sh` для восстановления NAT после перезапуска контейнера
- systemd сервис `zt-nat-setup.service` для авто-восстановления при загрузке
- Поддержка OpenVZ/LXC (SNAT вместо MASQUERADE)

**Для раздачи интернета клиентам** — после установки:
1. В ZTNET Panel добавьте Managed Route: `0.0.0.0/0` → ZT-IP сервера
2. На клиенте включите `Allow Default Route`

### `zt-cleanup.sh` — ZeroTier + ZTNET — Полная очистка

Полное удаление ZeroTier, ZTNET Panel и всех связанных компонентов:

- Остановка и удаление Docker контейнеров (ztnet, postgres, zerotier)
- Удаление Docker volumes (identity, БД)
- Удаление Docker образов
- Остановка хостового zerotier-one (systemd)
- Удаление всех iptables правил NAT/FORWARD для ZT
- Удаление UFW правил для ZT
- Удаление `/opt/ztnet`, systemd сервиса `zt-nat-setup.service`, `/etc/sysctl.d/99-zt-forward.conf`
- Напоминание об очистке браузера перед повторной установкой

### `zt-add-network.sh` — Добавление новой ZeroTier сети

Добавление дополнительной сети к существующей установке ZTNET без переустановки:

1. **Проверка** — контейнеры работают, `.env.info` на месте
2. **Join сети** — `zerotier-cli join <NETWORK_ID>`
3. **Само-авторизация** — через Controller API (ручная авторизация не нужна)
4. **Ожидание ZT-IP** — до 150 сек
5. **Определение subnet** — из Controller API
6. **Настройка NAT** — iptables FORWARD + POSTROUTING для нового subnet
7. **Обновление конфигурации** — `.env.info` и `zt-nat-setup.sh` для всех сетей
8. **Проверка маршрутов** — валидация Managed Routes, предупреждение о проблемах

**Поддержка нескольких сетей**: все сети хранятся в `ZT_SUBNETS` и `NETWORK_IDS` через запятую.

### `zt-watchdog.sh` — Автоматический мониторинг и восстановление ZeroTier

Автоматический watchdog для поддержания работоспособности ZeroTier:

| Проверка | Действие |
|----------|----------|
| Контейнер не запущен | Запуск контейнера |
| Ошибки "Could not bind" >3 за 5 мин | Рестарт контейнера |
| ZT статус OFFLINE | Рестарт контейнера |
| Нет процесса zerotier-one | Рестарт контейнера |
| Порт 9993 занят чужим процессом | Убить процесс |
| Системный zerotier-one активен | Остановить и замаскировать |
| Отсутствуют NAT правила | Восстановить iptables |

**Защита от частых рестартов**: лимит 3 рестарта в час.

**Защита от параллельного выполнения**: `flock` mutex на всех скриптах.

**Запрещено (watchdog не делает)**: DELETE member, deauth/reauth, запись в controller.d/, изменение маршрутов.

### `zt-reconcile.py` — Декларативный Control Plane (Desired State)

Python-скрипт для управления состоянием ZeroTier через desired-state модель:

```bash
python3 zt-reconcile.py --init       # Сгенерировать topology.json из текущего состояния
python3 zt-reconcile.py --validate   # Проверить корректность topology.json
python3 zt-reconcile.py              # Dry-run: показать расхождения (desired vs actual)
python3 zt-reconcile.py --apply      # Применить изменения
```

**Возможности:**
- Генерация `topology.json` — единый источник истины (desired state)
- Валидация: детектит >1 exit-node, отсутствующие подсети, неавторизованных членов
- Reconcile: авторизация членов, назначение IP — только безопасные операции
- **Никогда не удаляет** member-записи и не делает deauth

**Топология сетей (role):**
- `exit-node` — сеть с NAT и маршрутом 0.0.0.0/0 (раздаёт интернет). Только ОДНА на контроллере.
- `mesh` — транспортная сеть (только внутренняя маршрутизация, без default route)

### `zt-diagnose.sh` — Диагностика и устранение проблем

Интерактивная диагностика всех компонентов ZeroTier + ZTNET с автоматическим выявлением проблем и предложением исправлений:

| Проверка | Что ищет |
|----------|----------|
| Порт 9993 | Конфликт системного zerotier-one с Docker-контейнером |
| Контейнеры | Статус, health, crash loop (ztnet, postgres, zerotier) |
| ZT демон | ONLINE / TUNNELED / OFFLINE, версия |
| TUN/TAP | Доступность `/dev/net/tun` на хосте и в контейнере |
| Сети/маршруты | NOT_FOUND сети, сломанные Managed Routes (via не в своей подсети) |
| Члены сетей | NOT_AUTH, NO_IDENTITY, NEVER_CONNECTED |
| Пир-соединения | LEAF/PLANET пири, TUNNELED режим |
| NAT/Firewall | IP forwarding, SNAT/MASQUERADE для всех подсетей, UFW |
| Конфиг .env.info | Расхождение реальных подсетей с сохранёнными |
| Связность | Self-ping, ping до авторизованных членов |

```bash
# Только диагностика
sudo bash zt-diagnose.sh

# Диагностика + интерактивное исправление (спрашивает подтверждение)
sudo bash zt-diagnose.sh --fix
```

### `clean-sys.sh` — Системная очистка Ubuntu-сервера

Мощный скрипт для высвобождения дискового пространства на сервере. Аналог desktop-версии, адаптированный для серверного окружения. Все параметры настраиваются через переменные окружения.

**Основные модули (включены по умолчанию):**

| Модуль | Описание |
|--------|----------|
| apt | `clean`, `autoclean`, `autoremove --purge`, deborphan |
| Ядра | Удаление старых неиспользуемых ядер (кроме текущего) |
| journalctl | `--vacuum-size=200M` |
| Логи | Старые `.gz` (>7d), `.log` (>30d), ротированные логи в `/var/log` |
| Fail2ban | Очистка persistent bans старше 30 дней |
| /tmp, /var/tmp | Файлы старше 7 дней |
| Docker | Щадящий safe prune (контейнеры >48h, образы >7d), buildx prune |
| pip | `cache purge` |
| /var/cache | `.deb` пакеты в apt archives |
| /var/crash | Очистка краш-репортов |
| /var/mail | Очистка пользовательской почты |

**Опционально (отключено по умолчанию):**
- npm, yarn, uv, poetry, cargo cache
- Snap/Flatpak
- Nginx/Apache логи
- MySQL/PostgreSQL логи
- Docker orphan volumes, deep prune
- Корзина (включена)

**Режим сухого прогона:** `DRY_RUN=1 bash clean-sys.sh`

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

**ZeroTier Diagnose:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-diagnose.sh | sudo bash
```

**ZeroTier Cleanup:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-cleanup.sh | sudo bash
```

**ZeroTier Добавить сеть:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-add-network.sh | sudo bash
```

**ZeroTier Watchdog (автозапуск):**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-watchdog.sh | sudo tee /etc/cron.hourly/zt-watchdog > /dev/null && sudo chmod +x /etc/cron.hourly/zt-watchdog
```

**Системная очистка:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/clean-sys.sh | sudo bash
```

## Требования

- Ubuntu 24.04 (LTS)
- Доступ к интернету
- Права суперпользователя (sudo)

## Документация

- [docs/zt-auto-join-plan.md](docs/zt-auto-join-plan.md) — технические детали реализации Auto-Join

## Лицензия

MIT