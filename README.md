# Настройка Ubuntu 24.04 для разработки

Версия: **2.0**

Python-оркестратор для быстрой инициализации и управления VDS на Ubuntu 24.04.

## Архитектура v2.0

Проект мигрировал с коллекции bash-скриптов на **Python-оркестратор** с изолированным виртуальным окружением.

**Ключевые изменения:**
- Единая CLI-команда `vds` вместо множества bash-скриптов
- Python 3 + venv (обход блокировки системного pip в Ubuntu 24.04)
- Модульная структура: `core/`, `zerotier/`, `wireguard/`, `sysinfo/`, `system/`
- Библиотеки: `typer` (CLI), `requests` (API), `pydantic` (валидация), `rich` (вывод), `psutil` (метрики)
- Systemd-таймеры для watchdog и reconcile
- Старые bash-скрипты сохранены для обратной совместимости (Strangler Fig Pattern)

## Быстрый старт

```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/install.sh | sudo bash
```

После установки доступна команда `vds`:

```bash
vds --help                    # Справка
vds sysinfo                   # Статус сервера (CPU, RAM, Docker, Disk)
vds cleanup                   # Системная очистка
vds zerotier install          # Установить ZeroTier + ZTNET Panel
vds zerotier status           # Диагностика ZeroTier
vds wireguard install         # Установить WireGuard VPN
```

## Структура проекта

```
my-first-vds/
├── install.sh                  # Bootstrap (venv + deps + symlink vds)
├── requirements.txt            # Python-зависимости
├── src/
│   ├── main.py                 # CLI entry point (typer)
│   ├── core/
│   │   ├── logger.py           # Rich-based логирование
│   │   ├── shell.py            # Обёртки subprocess
│   │   └── lock.py             # fcntl мьютексы
│   ├── zerotier/
│   │   ├── api.py              # ZeroTierAPI класс (requests)
│   │   ├── reconcile.py        # Desired-state reconciler (pydantic)
│   │   ├── nat.py              # iptables NAT/FORWARD
│   │   ├── watchdog.py         # Авто-восстановление
│   │   ├── diagnose.py         # Диагностика 8 проверок
│   │   ├── install.py          # Установка ZTNET
│   │   └── cleanup.py          # Полное удаление
│   ├── sysinfo/
│   │   └── dashboard.py        # Rich dashboard (psutil)
│   ├── wireguard/
│   │   └── install.py          # WireGuard + клиенты
│   └── system/
│       └── cleanup.py          # Системная очистка
└── systemd/
    ├── vds-watchdog.service
    ├── vds-watchdog.timer
    ├── vds-reconcile.service
    └── vds-reconcile.timer
```

## CLI команды

### Общие

```bash
vds sysinfo                    # Статус сервера (CPU, RAM, Swap, Disk, Docker)
vds cleanup [--dry-run]        # Очистка системы (apt, Docker, логи, /tmp)
vds cleanup --aggressive       # Агрессивная очистка Docker
```

### ZeroTier

```bash
vds zerotier install [--port 3000]     # Установить ZeroTier + ZTNET Panel
vds zerotier status                    # Диагностика (8 проверок)
vds zerotier diagnose --fix            # Диагностика + интерактивное исправление
vds zerotier diagnose --fix --yes      # Автоисправление без подтверждения
vds zerotier reconcile                 # Dry-run: показать расхождения
vds zerotier reconcile --apply         # Применить изменения из topology.json
vds zerotier reconcile --init          # Сгенерировать topology.json
vds zerotier reconcile --validate      # Проверить topology.json
vds zerotier watchdog                  # Фоновый мониторинг и восстановление
vds zerotier nat                       # Восстановить NAT правила
vds zerotier cleanup                   # Полное удаление ZeroTier + ZTNET
```

### WireGuard

```bash
vds wireguard install [--port 51820] [--client name] [--dns "8.8.8.8"]
vds wireguard add-client [--name client2]
vds wireguard remove
```

## Systemd-сервисы

После установки ZeroTier автоматически настраиваются таймеры:

| Сервис | Описание | Интервал |
|--------|----------|----------|
| `vds-watchdog.timer` | Мониторинг и авто-восстановление ZeroTier | каждые 2 мин |
| `vds-reconcile.timer` | Синхронизация состояния с topology.json | каждые 5 мин |

**Установка таймеров:**
```bash
sudo cp systemd/vds-*.service systemd/vds-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vds-watchdog.timer vds-reconcile.timer
```

---

## Legacy bash-скрипты

Старые bash-скрипты сохранены для обратной совместимости и постепенной миграции.

### Скрипты

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

### Новая архитектура (v2.0) — рекомендуется

**Bootstrap + Python-оркестратор:**
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/install.sh | sudo bash
```

Скрипт `install.sh`:
1. Устанавливает системные зависимости (python3, python3-venv, git, curl)
2. Создаёт директорию `/opt/my-vds/`
3. Создаёт виртуальное окружение `/opt/my-vds/venv/`
4. Устанавливает Python-библиотеки из `requirements.txt`
5. Создаёт симлинк `/usr/local/bin/vds`
6. Проверяет работу CLI

### Legacy bash-скрипты (v1.x)

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
- Python 3.10+ (устанавливается автоматически)
- Доступ к интернету
- Права суперпользователя (sudo)

## Разработка

**Локальная разработка:**
```bash
git clone https://github.com/asvspb/my-first-vds.git
cd my-first-vds
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python src/main.py --help
```

**Добавление новых команд:**
1. Создайте модуль в `src/<category>/<module>.py`
2. Добавьте функцию с логикой
3. Зарегистрируйте команду в `src/main.py` через `@app.command()` или `@<category>_app.command()`

## Документация

- [docs/zt-auto-join-plan.md](docs/zt-auto-join-plan.md) — технические детали реализации Auto-Join

## Миграция с v1.x на v2.0

Проект использует **Strangler Fig Pattern** — постепенная замена bash-скриптов Python-модулями:

1. **Неделя 1**: Установка новой структуры, `install.sh` создаёт venv
2. **Неделя 2**: Перенос ZeroTier reconcile + watchdog на Python
3. **Неделя 3**: Перенос sysinfo dashboard на Python + Rich
4. **Неделя 4**: Перенос WireGuard и cleanup на Python
5. **Финал**: Удаление старых `*.sh` (кроме `install.sh`)

Старые bash-скрипты продолжают работать параллельно с новой Python-архитектурой.

## Лицензия

MIT