# VDS Orchestrator

> Универсальный Python CLI для управления VDS/VPS на Ubuntu 24.04

Версия: **3.0**

## Обзор

VDS Orchestrator — единый инструмент инициализации и управления выделенным сервером. Входит в состав [ubuntuInstaller](../) как модуль `vds/`.

**Возможности:**
- Интерактивное TUI-меню (на базе `questionary`)
- **Gateway-протоколы против блокировок** (основной сценарий): Xray VLESS
  Reality (TCP 443), VLESS XHTTP (TCP 8443, TLS) и Hysteria2 (QUIC, UDP 443),
  общее хранилище клиентов (`vds gateway`), опционально ACME-сертификаты
  для домена
- ZeroTier + ZTNET Panel, WireGuard, Coturn — **архив/опционально**:
  модули рабочие, но не входят в основной сценарий (см. [docs/DEPLOY.md](docs/DEPLOY.md))
- Системный dashboard: CPU, RAM, диск, Docker
- Первичная настройка сервера: пользователь, SSH, UFW, Docker, Swap

## Структура

```
vds/
├── install.sh          # Bootstrap-установщик (запускать на сервере)
├── preinstall.sh       # Базовая подготовка сервера
├── local-init.sh       # Устарел — используй scripts/8_vds-server.sh
├── upload-ssh-cert.sh  # Загрузка SSH-ключа на сервер (пароль root → authorized_keys)
├── requirements.txt    # Python-зависимости
├── requirements-dev.txt # Dev-зависимости (pytest; ставятся install.sh при наличии)
├── pyproject.toml      # Метаданные пакета
├── systemd/            # Systemd unit-файлы
│   ├── vds-watchdog.service/.timer
│   ├── vds-reconcile.service/.timer
│   ├── vds-xray.service.tpl
│   ├── vds-hysteria2.service.tpl
│   └── sysctl/99-vds-gateway.conf.tpl
├── AGENTS.md           # Контекст проекта для ИИ-агентов
├── TECHDEBT.md         # Бэклог техдолга
├── .zcode/agents/      # Определения ролей ИИ-команды (8 агентов)
├── docs/
│   ├── TEAM.md              # Ролевая модель и процесс (гейты G0–G6)
│   ├── VPN-PROTOCOLS.md     # Обзор протоколов (VLESS Reality, Hysteria2, XHTTP) и план модулей
│   └── CENSORSHIP-ROADMAP.md # Roadmap внедрения практик обхода блокировок
└── src/
    ├── main.py         # Точка входа CLI (typer + questionary)
    ├── core/           # Ядро: логгер, shell-утилиты, блокировки
    ├── zerotier/       # ZeroTier: установка, watchdog, reconcile, NAT, диагностика
    ├── wireguard/      # WireGuard VPN
    ├── coturn/         # TURN-сервер для WebRTC
    ├── xray/           # Xray VLESS Reality (TCP 443)
    ├── hysteria2/      # Hysteria2 QUIC (UDP 443)
    ├── gateway/        # Общее состояние клиентов gateway (state.json)
    ├── sysinfo/        # Dashboard метрик сервера
    └── system/         # Базовая настройка, cleanup
```

Тесты: `tests/` (unit, без root/сети — `pytest -q`).

## Быстрый деплой на новый сервер

Деплой VDS (Xray Reality + Hysteria2, опционально домен + ACME + XHTTP) одной командой
с локальной машины, без ИИ и ручных швов:

```bash
bash ~/Dev/ubuntuInstaller/scripts/11_vds-deploy.sh
```

Скрипт: SSH-ключ → rsync репо на сервер → install.sh → протоколы →
авто-детект GitHub (при блокировке — зеркало) → демо-клиенты → печать share-links.
Полная инструкция (включая ручной вариант и чеклист проверки) — [docs/DEPLOY.md](docs/DEPLOY.md).

## Быстрый старт

### С локальной машины (через ubuntuInstaller)

```bash
bash ~/Dev/ubuntuInstaller/scripts/8_vds-server.sh
```

Скрипт: запросит IP → скопирует SSH-ключ → загрузит исходники → установит → откроет меню `vds`.

### Напрямую на сервере

```bash
# Предварительная подготовка (опционально)
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/main/preinstall.sh | sudo bash

# Установка
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/main/install.sh | sudo bash
```

## Команды CLI

```bash
vds                          # Интерактивное TUI-меню
vds --help                   # Справка по всем командам
vds sysinfo                  # Dashboard: CPU, RAM, диск, Docker
vds zerotier install         # Установить ZeroTier + ZTNET Panel
vds zerotier watchdog        # Проверить/восстановить туннели
vds zerotier reconcile       # Синхронизировать топологию
vds zerotier reconcile --init    # Инициализировать topology.json
vds zerotier reconcile --apply   # Применить изменения
vds zerotier diagnose        # Диагностика сети
vds zerotier add-network     # Добавить сеть в topology.json
vds wireguard install        # Установить WireGuard VPN
vds server-setup             # Мастер первичной настройки
vds cleanup                  # Очистка системы (логи, кэши, Docker)
```

### Gateway: Xray / Hysteria2 (MVP, фазы 0–2)

Два транспорта против блокировок + общее хранилище клиентов. Не конфликтуют
между собой: Xray — TCP 443, Hysteria2 — UDP 443. Все команды требуют root;
`remove` без `--apply` показывает только план (dry-run).

```bash
vds gateway status                  # Состояние gateway: state.json, клиенты, протоколы
vds gateway links                   # Share-links всех клиентов (фильтр: --protocol xray|hysteria2)

vds xray install                    # Установить Xray VLESS Reality (TCP 443)
vds xray install --sni www.cloudflare.com   # Сайт-маска (по умолчанию www.google.com)
vds xray add-client phone           # Клиент + share-link vless://... (в stdout)
vds xray status                     # Юнит, валидность конфига, порт, journal
vds xray remove                     # План удаления (dry-run)
vds xray remove --apply             # Удалить (юнит, конфиг, бинарь, клиенты из store)

vds hysteria2 install               # Установить Hysteria2 (QUIC, UDP 443)
vds hysteria2 add-client mob        # Клиент + share-link hysteria2://...
vds hysteria2 status                # Юнит, UDP-порт, сертификат, journal
vds hysteria2 remove --apply        # Удалить (sysctl-тюнинг НЕ откатывается)
```

Ссылки импортируются в v2rayNG / NekoRay / Hiddify / sing-box. Состояние
клиентов — `$INSTALL_DIR/gateway/state.json` (0600); приватные ключи — только
в конфигах сервера, никогда в share-link и логах. Порты TCP/UDP 443 должны
быть открыты в UFW. Обзор протоколов — [docs/VPN-PROTOCOLS.md](docs/VPN-PROTOCOLS.md),
план развития — [docs/CENSORSHIP-ROADMAP.md](docs/CENSORSHIP-ROADMAP.md),
паттерны обхода с живыми доказательствами — [docs/CENSORSHIP-PATTERNS.md](docs/CENSORSHIP-PATTERNS.md).

> **Hysteria2 в MVP — тестовый режим:** self-signed сертификат + `insecure=1`
> в клиентской ссылке. ACME-сертификат (Let's Encrypt по домену) — фаза 6
> roadmap.

> **Дисклеймер:** VPN-функциональность — исключительно для легального
> использования в соответствии с местальным законодательством (подробнее —
> [docs/VPN-PROTOCOLS.md](docs/VPN-PROTOCOLS.md), раздел «Важно»).

## Роли ИИ-команды

Проект ведётся восемью агентами (`.zcode/agents/`); процесс с гейтами — [docs/TEAM.md](docs/TEAM.md), контекст — [AGENTS.md](AGENTS.md).

| Роль | Агент | Ответственность |
|---|---|---|
| Владелец | `vds-owner` | Идеи, ценность, приоритет, границы |
| Аналитик | `vds-analyst` | Идея → требования (REQ) и критерии приёмки |
| Архитектор | `vds-architect` | ТЗ/SPEC, архитектура, ADR, work packages |
| Кодер | `vds-coder` | Реализация WP по ТЗ с доказательствами |
| Дебагер | `vds-debugger` | Воспроизведение, root cause, регрессионный тест |
| Тестировщик | `vds-tester` | Независимая верификация по AC |
| Документатор | `vds-docs` | README/docs/CHANGELOG в синхроне с кодом |
| Оркестратор | `vds-orchestrator` | Поток, гейты G0–G6, трассируемость |

Типовой поток: `owner → analyst → architect → coders → tester → [debugger] → docs → close`.
Модели: архитектор и тестировщик — `glm-5.3`, дебагер — `deepseek-flash`, остальные — `glm-5.3-flash`.

## Systemd-таймеры (только для ZeroTier, архив)

Активируются **только** при явной установке `vds zerotier install` (опциональный
сценарий; основной VPN-путь — gateway-протоколы, таймеры им не нужны):

| Таймер | Описание | Интервал |
|--------|----------|----------|
| `vds-watchdog.timer` | Мониторинг и авто-восстановление ZeroTier-туннелей | каждые 2 мин |
| `vds-reconcile.timer` | Декларативная синхронизация с `topology.json` | каждые 5 мин |

```bash
# Проверка статуса
systemctl list-timers vds-*
journalctl -u vds-watchdog -n 20
```

## topology.json

Файл `/opt/ztnet/topology.json` описывает желаемое состояние ZeroTier-сетей. Reconciler сравнивает его с реальным и устраняет расхождения.

```json
{
  "networks": {
    "<network_id>": {
      "name": "название сети",
      "members": {
        "<node_id>": {
          "name": "имя узла",
          "authorized": true
        }
      }
    }
  }
}
```

## Установочные пути

| Путь | Содержимое |
|------|-----------|
| `/opt/my-vds/` | Исходники и venv |
| `/opt/my-vds/venv/` | Python виртуальное окружение |
| `/opt/ztnet/topology.json` | Конфиг топологии ZeroTier |
| `/opt/my-vds/gateway/state.json` | Состояние gateway: клиенты Xray/Hysteria2 (0600) |
| `/usr/local/etc/xray/config.json` | Конфиг Xray (0600) |
| `/etc/hysteria/config.yaml` | Конфиг Hysteria2 (0600) |
| `/usr/local/bin/vds` | Симлинк команды `vds` |
| `/etc/systemd/system/vds-*.service` | Systemd-сервисы |

## Зависимости

| Библиотека | Назначение |
|------------|------------|
| `typer` | CLI-фреймворк |
| `questionary` | Интерактивное TUI-меню |
| `rich` | Красивый вывод в терминале |
| `psutil` | Системные метрики |
| `pydantic` | Валидация конфигураций |
| `requests` | HTTP API к ZTNET |

## Разработка

Для добавления новых команд:
1. Создать модуль в `src/<category>/<module>.py`
2. Зарегистрировать в `src/main.py` через `@app.command()` или `@<category>_app.command()`
3. При необходимости добавить пункт в `main_menu()`

Для запуска тестов: `pip install -r requirements-dev.txt` (или `pip install -e '.[dev]'`), затем `pytest -q`.

## Требования

- Ubuntu 24.04 LTS
- Root-доступ
- Python 3.10+ (устанавливается автоматически)
- Docker (для ZeroTier/ZTNET)

## Лицензия

MIT