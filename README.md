# VDS Orchestrator

> Универсальный Python CLI для управления VDS/VPS на Ubuntu 24.04

Версия: **3.0** (`vds-cli` 3.0.0)

## Обзор

VDS Orchestrator — единый инструмент инициализации и управления выделенным сервером.
Живёт в отдельном репозитории [my-first-vds](https://github.com/asvspb/my-first-vds);
UbuntuInstaller (ноутбук) деплоит его скриптами `scripts/11_vds-deploy.sh` /
`scripts/8_vds-server.sh` (источник — рабочий checkout, `VDS_REPO`) и забирает
share-линки через `vpn profile pull`. Копии репозитория внутри ubuntuInstaller нет.

**Возможности:**
- Интерактивное TUI-меню (на базе `questionary`)
- **Gateway-протоколы против блокировок** (основной сценарий): Xray VLESS
  Reality (TCP 443), VLESS XHTTP (инблэнд 8443 за SNI-фолбэком Reality),
  VLESS+WS за CDN/Cloudflare (origin 2053), Hysteria2 (QUIC, UDP 443) с port
  hopping (`vds-hysteria2-hop`) и obfs salamander (`vds-hysteria2-obfs`),
  AmneziaWG (обфусцированный WireGuard, UDP 51825); общее хранилище клиентов
  (`vds gateway`), ACME/Let's Encrypt по домену
- ZeroTier + ZTNET Panel, WireGuard, Coturn — **архив/опционально**:
  модули рабочие, но не входят в основной сценарий (см. [docs/DEPLOY.md](docs/DEPLOY.md))
- Системный dashboard: CPU, RAM, диск, Docker
- Первичная настройка сервера: пользователь, SSH, UFW, Docker, Swap

## Структура

```
vds/
├── install.sh          # Bootstrap-установщик (запускать на сервере)
├── preinstall.sh       # Базовая подготовка сервера
├── local-init.sh       # Устарел — используй scripts/8_vds-server.sh из ubuntuInstaller
├── upload-ssh-cert.sh  # Загрузка SSH-ключа на сервер (пароль root → authorized_keys)
├── requirements.txt    # Python-зависимости
├── requirements-dev.txt # Dev-зависимости (pytest; ставятся install.sh при наличии)
├── pyproject.toml      # Метаданные пакета
├── systemd/            # Systemd unit-файлы
│   ├── vds-watchdog.service/.timer
│   ├── vds-reconcile.service/.timer
│   ├── vds-xray.service.tpl
│   ├── vds-hysteria2.service.tpl
│   ├── vds-hysteria2-hop.service.tpl    # port hopping (ADR-008)
│   ├── vds-hysteria2-obfs.service.tpl   # obfs salamander (SPEC-20261112)
│   ├── vds-amneziawg.service.tpl
│   └── sysctl/99-vds-gateway.conf.tpl
├── AGENTS.md           # Контекст проекта для ИИ-агентов
├── TECHDEBT.md         # Бэклог техдолга
├── .zcode/agents/      # Определения ролей ИИ-команды (8 агентов)
├── docs/
│   ├── TEAM.md              # Ролевая модель и процесс (гейты G0–G6)
│   ├── DEPLOY.md            # Деплой и чеклист проверки
│   ├── VPN-PROTOCOLS.md     # Протоколы: Reality, XHTTP, Hysteria2 (hop/obfs), AWG, CDN
│   ├── CDN-FRONTS.md        # Пул фронтов CDN (SPEC WP-2)
│   ├── CENSORSHIP-ROADMAP.md
│   ├── CENSORSHIP-PATTERNS.md
│   ├── MIGRATE-VDS.md       # Перенос на другой сервер
│   ├── adr/                 # ADR-001…ADR-008
│   └── team/
└── src/
    ├── main.py         # Точка входа CLI (typer + questionary)
    ├── core/           # Ядро: logger, shell, lock, protocol, netcheck, secrets, units
    ├── zerotier/       # ZeroTier: install, api, watchdog, reconcile, nat, diagnose, add_network, cleanup
    ├── wireguard/      # WireGuard VPN
    ├── coturn/         # TURN-сервер для WebRTC
    ├── xray/           # Reality (443), XHTTP (8443), CDN (2053): adapter, install, clients, config, status, remove
    ├── hysteria2/      # Hysteria2 QUIC (443): adapter, install, clients, config, status, hop, obfs, sysctl, remove
    ├── amneziawg/      # AmneziaWG (UDP 51825): install, clients, status, remove
    ├── acme/           # ACME/Let's Encrypt (certbot HTTP-01 + deploy-hook)
    ├── gateway/        # paths, store (state.json 0600), links, blockcheck
    ├── sysinfo/        # Dashboard метрик сервера
    └── system/         # Базовая настройка, cleanup
```

Тесты: `tests/` (unit, без root/сети — `pytest -q`).

## Быстрый деплой на новый сервер

Деплой VDS (Xray Reality + Hysteria2, опционально XHTTP/CDN и ACME по домену;
AmneziaWG — отдельной командой) одной командой с локальной машины, без ИИ и
ручных швов:

```bash
bash ~/Dev/ubuntuInstaller/scripts/11_vds-deploy.sh
```

Скрипт: SSH-ключ → rsync репо на сервер (`VDS_REPO`, по умолчанию
`~/Dev/my-coding/vds`) → install.sh → протоколы →
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

### Gateway: Xray / Hysteria2 / AmneziaWG / ACME

Транспорты против блокировок + общее хранилище клиентов. Не конфликтуют
между собой по портам: Reality — TCP 443, XHTTP-инблэнд — TCP 8443 (loopback),
CDN-origin — TCP 2053, Hysteria2 — UDP 443 (hop-диапазон редиректится на него),
AmneziaWG — UDP 51825. Все команды требуют root; `remove` без `--apply`
показывает только план (dry-run).

```bash
vds gateway status                  # Состояние gateway: state.json, клиенты, протоколы
vds gateway links                   # Share-links клиентов (--protocol xray|hysteria2|amneziawg)
vds gateway links --include-obfs    # + obfs-ссылки hysteria2 (`<name>@obfs`)
vds gateway blockcheck              # «Блок IP» vs «деградация» vs «локальная проблема»
vds gateway healthcheck             # Юниты/порты/сертификат (<14 дн. warning, <7 error)
vds gateway healthcheck --install-timer  # Таймер vds-gateway-health (каждые 5 мин)

vds xray install                    # Установить Xray VLESS Reality (TCP 443)
vds xray install --sni www.cloudflare.com   # Сайт-маска (по умолчанию www.google.com)
vds xray add-client phone           # Клиент + share-link vless://...
vds xray add-transport              # XHTTP-инблэнд за SNI-фолбэком Reality (ADR-003)
vds xray remove-transport           # Снять XHTTP (инблэнд + XHTTP-клиенты)
vds xray use-domain --domain vpn.example.ru   # Reality-ссылки по домену (state.domain)
vds xray add-cdn --domain cdn.example.ru      # CDN-транспорт VLESS+WS+TLS (ADR-006)
vds xray add-cdn-client <name>      # CDN-клиент + ссылка (--front — фронт пула)
vds xray add-cdn-front <domain>     # Фронт в пул CDN (сертификат в инблэнде)
vds xray status                     # Юнит, валидность конфига, порт, journal
vds xray remove --apply             # Удалить (юнит, конфиг, бинарь, клиенты из store)

vds hysteria2 install               # Установить Hysteria2 (QUIC, UDP 443)
vds hysteria2 add-client mob        # Клиент + share-link hysteria2://...
vds hysteria2 add-hop-ports 20000-20500   # Port hopping: REDIRECT → udp/443 (ADR-008)
vds hysteria2 add-obfs              # obfs salamander: параллельный инстанс (--port 51826)
vds hysteria2 rotate-obfs           # Ротация obfs-пароля (клиентам — ре-импорт ссылки)
vds hysteria2 apply-cert --apply    # Подменить self-signed на LE (без флага — dry-run)
vds hysteria2 status                # Юнит, UDP-порт, сертификат, journal
vds hysteria2 remove --apply        # Удалить (sysctl-тюнинг НЕ откатывается)

vds amneziawg install               # AmneziaWG: PPA ppa:amnezia/ppa, UDP 51825
vds amneziawg add-client laptop     # Клиент: .conf (0600) для импорта в AmneziaVPN
vds amneziawg status                # Юнит, DKMS-версия, UDP-порт, peers (секреты скрыты)
vds amneziawg remove-client <name>  # Удалить клиента (dry-run; --apply применяет)
vds amneziawg remove --apply        # Удалить сервис (пакеты PPA — вручную)

vds acme issue --domain vpn.example.ru --email admin@example.ru   # LE (HTTP-01) + deploy-hook
```

Ссылки импортируются в v2rayNG / NekoRay / Hiddify / sing-box; AmneziaWG-конфиг —
в AmneziaVPN. Клиентская сторона: `vpn profile pull` (импорт ссылок) и
`vpn speed` (живой замер скорости всех каналов, несколько эндпоинтов).
Состояние
клиентов — `$INSTALL_DIR/gateway/state.json` (0600); приватные ключи — только
в конфигах сервера, никогда в share-link и логах. Порты TCP/UDP 443 должны
быть открыты в UFW. Обзор протоколов — [docs/VPN-PROTOCOLS.md](docs/VPN-PROTOCOLS.md),
план развития — [docs/CENSORSHIP-ROADMAP.md](docs/CENSORSHIP-ROADMAP.md),
паттерны обхода с живыми доказательствами — [docs/CENSORSHIP-PATTERNS.md](docs/CENSORSHIP-PATTERNS.md),
точки роста схем/протоколов (для техлида) — [docs/GROWTH-POINTS.md](docs/GROWTH-POINTS.md).

> **Hysteria2 TLS/ACME:** без домена — self-signed сертификат и `insecure=1`
> в клиентской ссылке. С доменом: `vds acme issue <domain>` (HTTP-01,
> deploy-hook `vds-hysteria2-cert.sh`) → `vds hysteria2 apply-cert`; новые
> клиентские ссылки рендерятся без `insecure=1`, `sni=<домен>`.
> Port hopping и obfs salamander добавляются поверх любого TLS-режима и
> попадают в ссылку параметрами `mport=` и `obfs=salamander&obfs-password=`.
> Детали — [docs/VPN-PROTOCOLS.md](docs/VPN-PROTOCOLS.md) §2.3.1–2.3.3,
> [docs/DEPLOY.md](docs/DEPLOY.md).

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

## Systemd: gateway-сервисы и таймеры ZeroTier

Gateway-протоколы — статические сервисы, без таймеров:
`vds-xray.service`, `vds-hysteria2.service`, `vds-hysteria2-hop.service`
(oneshot, восстанавливает nat-цепочку после ребута), `vds-hysteria2-obfs.service`,
`vds-amneziawg.service`. Юниты ставятся из шаблонов `systemd/*.tpl`.

Таймер `vds-gateway-health.timer` (W1 GR-18) — healthcheck gateway-юнитов,
портов и срока сертификата; ставится вручную:
`vds gateway healthcheck --install-timer` (каждые 5 мин, rate-limited рестарт
упавших юнитов).

Таймеры — только для ZeroTier (архив):

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
| `/opt/my-vds/gateway/state.json` | Состояние gateway: клиенты и протоколы (0600) |
| `/opt/my-vds/gateway/clients/` | Клиентские артефакты (AmneziaWG `.conf`, 0600) |
| `/usr/local/etc/xray/config.json` | Конфиг Xray (0600) |
| `/etc/hysteria/config.yaml` | Конфиг Hysteria2 (0600) |
| `/etc/hysteria/obfs.yaml` | Конфиг obfs-инстанса salamander (0600) |
| `/usr/local/sbin/vds-hy2-hop-apply.sh` | Идемпотентный скрипт hop-цепочки `VDS_HY2_HOP` |
| `/etc/amnezia/awg0.conf` | Конфиг AmneziaWG (0600) |
| `/etc/letsencrypt/live/<domain>/` | LE-сертификаты (ACME, HTTP-01) |
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