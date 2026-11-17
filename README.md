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
  Reality (TCP 443), VLESS XHTTP (инблэнд 8443 за SNI-фолбэком Reality;
  сервер — `mode: auto` + `xPaddingBytes: 100-1000`, GR-25),
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
│   ├── vds-watchdog.service / vds-watchdog.timer        # ZeroTier (архив)
│   ├── vds-reconcile.service / vds-reconcile.timer      # ZeroTier (архив)
│   ├── vds-xray.service.tpl
│   ├── vds-hysteria2.service.tpl
│   ├── vds-hysteria2-hop.service.tpl    # port hopping (ADR-008)
│   ├── vds-hysteria2-obfs.service.tpl   # obfs salamander (SPEC-20261112)
│   ├── vds-amneziawg.service.tpl
│   ├── vds-amneziawg-nat.service.tpl    # NAT/forwarding AWG (oneshot при загрузке)
│   ├── vds-gateway-health.service.tpl   # healthcheck gateway (W1 GR-18)
│   ├── vds-gateway-health.timer.tpl
│   ├── vds-probe-watch.service.tpl      # монитор зондирования tcp/{443,8443,2053} (И33+W1-1)
│   ├── vds-probe-watch.timer.tpl
│   ├── vds-probe-rucidr.service.tpl     # обновление RU-CIDR-агрегата
│   ├── vds-probe-rucidr.timer.tpl
│   ├── vds-relay-exit.service.tpl       # RU-relay (ADR-007): exit-policy
│   ├── vds-relay-nat.service.tpl        # RU-relay: NAT ноги
│   ├── vds-relay-policy.service.tpl     # RU-relay: policy-routing до exit-ноды
│   ├── vds-relay-cidr.service.tpl       # RU-relay: RU-CIDR (ipdeny)
│   ├── vds-relay-cidr.timer.tpl         #   еженедельное обновление
│   └── sysctl/99-vds-gateway.conf.tpl
├── AGENTS.md           # Контекст проекта для ИИ-агентов
├── TECHDEBT.md         # Бэклог техдолга
├── .zcode/agents/      # Определения ролей ИИ-команды (10 агентов, см. docs/TEAM.md)
├── docs/
│   ├── TEAM.md              # Ролевая модель и процесс (гейты G0–G6)
│   ├── DEPLOY.md            # Деплой и чеклист проверки
│   ├── VPN-PROTOCOLS.md     # Протоколы: Reality, XHTTP, Hysteria2 (hop/obfs), AWG, CDN
│   ├── CDN-FRONTS.md        # Пул фронтов CDN (SPEC WP-2)
│   ├── CENSORSHIP-ROADMAP.md
│   ├── CENSORSHIP-PATTERNS.md
│   ├── MIGRATE-VDS.md       # Перенос на другой сервер
│   ├── adr/                 # ADR-001…ADR-014
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
    ├── gateway/        # paths, store (state.json 0600), links, blockcheck, probing (probe-watch
    │                   #  + threat-level машина), probing_rucidr (RU-CIDR без релея)
    ├── sysinfo/        # Dashboard метрик сервера
    └── system/         # Базовая настройка, cleanup, ufw (harden/ssh-port/lock-443)
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
vds server-setup             # Мастер первичной настройки (легаси — для файрвола используйте ufw harden)
vds cleanup                  # Очистка системы (логи, кэши, Docker)
vds system ufw harden --profile gateway       # UFW hardening (dry-run; --apply применить; hop 20000-20500 → 20000:20500)
vds system ufw ssh-port --to 49222 --apply    # двухфазный перенос SSH (22 закрывает --finalize; при сбое Фазы A демон поднимается авто)
vds system ufw status                         # сводка UFW + pending-перенос
vds system ufw lock-443 --reason "RU-PROBE-SUSPECT" --apply   # изоляция 443 (TTL 48h; AWG/CDN/ssh живы)
vds system ufw lock-443 --allow-from 203.0.113.10 --ttl 24h --apply  # 443 только для своих
vds system ufw lock-443 --status              # состояние лока + TTL (read-only)
vds system ufw lock-443 --unlock --apply      # досрочное снятие (ровно снимок из журнала)
```

### Gateway: Xray / Hysteria2 / AmneziaWG / ACME

Транспорты против блокировок + общее хранилище клиентов. Не конфликтуют
между собой по портам: Reality — TCP 443, XHTTP-инблэнд — TCP 8443 (loopback),
CDN-origin — TCP 2053, Hysteria2 — UDP 443 (hop-диапазон редиректится на него),
AmneziaWG — UDP 51825. Все команды требуют root; `remove` без `--apply`
показывает только план (dry-run).

```bash
vds gateway init                     # Идемпотентное развёртывание с нуля (dry-run: план+проверки)
vds gateway init --apply             # Установить reality + hysteria2 + healthcheck-таймер
vds gateway init --apply --protocols reality,hysteria2,obfs,hop,xhttp,cdn,awg \
    --domain vpn.example.ru --email admin@example.ru --demo-clients  # всё сразу

vds gateway status                  # Состояние gateway: state.json, клиенты, протоколы
vds gateway links                   # Share-links клиентов (--protocol xray|hysteria2|amneziawg)
vds gateway links --include-obfs    # + obfs-ссылки hysteria2 (`<name>@obfs`)
vds gateway blockcheck              # «Блок IP» vs «деградация» vs «локальная проблема»
vds gateway healthcheck             # Юниты/порты/сертификат (<14 дн. warning, <7 error)
vds gateway healthcheck --install-timer  # Таймер vds-gateway-health (каждые 5 мин)
vds gateway probe-watch install --apply  # Монитор зондирования tcp/{443,8443,2053} (nft + таймер, dry-run по умолчанию)
vds gateway probe-watch watch            # Дельта счётчиков + вердикт + threat-level (read-only)
vds gateway probe-watch watch --json     # + контракт: threat_level/threat_reason/lockdown/ru_syn_new (+ аддитивно syn_*_extra, extra_ports)
# RU-PROBE-SUSPECT гейтится суммой syn_valid + syn_valid_extra (443/8443/2053);
# PROBE-BURST по-прежнему калибруется только по 443
vds gateway probe-watch explain          # Карта покрытия: что меряется, что слепо (access-log/UDP-порты/IPv6)
vds gateway probe-watch ru-cidr install --apply  # RU-CIDR без релея: включает RU-PROBE-SUSPECT (+таймер)
vds gateway probe-watch ru-cidr update --apply   # Разово обновить RU-CIDR из ipdeny (root; иначе — таймер)
vds gateway probe-watch config           # конфиг auto-lockdown (default off; on = авто-лок 443 при threat high)
vds gateway probe-watch remove --apply   # Демонтаж nft-таблицы vds_probe + юнитов (dry-run по умолчанию)
# probe-watch исключает своих из probers4 и без AWG: verified_session_ips
# (ss/conntrack, двусторонний трафик, кэш 24 ч); `--auto-lockdown on`
# требует непустого allow-списка (allow-ips.txt / --lockdown-allow), иначе exit 1
# Быстрый контур (W1-1): 5-мин сэмплер vds-logs-sample считает дельту probers4,
# при >= 10 уникальных probers/5 мин — тег FAST-CONTOUR в journal (телеметрия,
# без авто-действий); verified-IP — в сайдкар-кэше /var/lib/vds/probe-fast-cache.json

vds logs status                     # Состояние конвейера логов (ADR-012)
vds logs install --apply            # Таймеры vds-logs-sample/daily (dry-run по умолчанию)
vds logs sample --apply             # Сэмпл journald/счётчиков (телеметрия; dry-run по умолчанию)
vds logs analyze --live --since 24h # Разбор сэмплов/вердиктов probe-watch
vds logs report --apply             # Ежедневный отчёт (reports/, 0600); --last — последний
vds logs capture start              # Ручной capture-бандл (pcap опционально)
vds logs capture status             # Статус активного capture
vds logs capture stop               # Остановить capture, собрать бандл
vds logs remove --apply             # Демонтаж таймеров/данных лог-конвейера (dry-run)

vds xray install                    # Установить Xray VLESS Reality (TCP 443)
vds xray install --sni www.cloudflare.com   # Сайт-маска (по умолчанию www.google.com)
vds xray add-client phone           # Клиент + share-link vless://...
vds xray add-transport              # XHTTP-инблэнд за SNI-фолбэком Reality (ADR-003); путь — случайный
                                     # секрет (state 0600; миграция не ломает ссылки; ротация — --regenerate-path,
                                     # после apply сразу `vpn profile pull` на клиентах). Инблэнд рендерится
                                     # с mode=auto + xPaddingBytes=100-1000 (GR-25; Xray >= 26.1.23, ADR-010).
                                     # смена IP: --skip-domain-check (E1 DNS ещё старый; cert/SNI не меняются)
vds xray remove-transport           # Снять XHTTP (инблэнд + XHTTP-клиенты)
vds xray use-domain --domain vpn.example.ru   # Reality-ссылки по домену (state.domain)
vds xray add-cdn --domain cdn.example.ru      # CDN-транспорт VLESS+WS+TLS (ADR-006); ws-path — случайный
                                     # секрет; 2053/tcp открыт только для CIDR Cloudflare (ips-v4)
vds xray add-cdn-client <name>      # CDN-клиент + ссылка (--front — фронт пула)
vds xray add-cdn-front <domain>     # Фронт в пул CDN (сертификат в инблэнде)
vds xray remove-cdn-front <domain>  # Снять фронт из пула (LE-cert остаётся; dry-run)
vds xray list-cdn-fronts            # Фронты пула: LE-файлы, срок, DNS-чек
vds xray remove-cdn-client <name>   # Удалить CDN-клиента (uuid + state; dry-run)
vds xray remove-cdn --apply         # Снять CDN-транспорт (инблэнд ws, клиенты, UFW; Reality/XHTTP живы)
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
vds amneziawg add-client laptop --keepalive 113   # И44: keepalive по умолчанию НЕ пишется
                                    # (радиомолчание в простое; 113 — только для NAT-дырки)
vds amneziawg status                # Юнит, DKMS-версия, UDP-порт, peers (секреты скрыты)
vds amneziawg remove-client <name>  # Удалить клиента (dry-run; --apply применяет)
vds amneziawg remove --apply        # Удалить сервис (пакеты PPA — вручную)

vds acme issue --domain vpn.example.ru --email admin@example.ru   # LE (HTTP-01) + deploy-hook

vds relay init --exit <exit-ip> --domain relay.asvpersonal.ru --sni <RU_SNI>
                                    # RU-relay (ADR-007): dry-run план; --apply развёртывает
                                    # AWG udp/443 + Reality tcp/443 + policy-routing (DEPLOY-RU-RELAY.md)
                                    # Целевая ОС — Ubuntu 24.04 (LandVPS, проверено 2026-11-17):
                                    # iptables/ufw из коробки, ssh.socket, Python 3.12
vds relay status                    # Юниты, awg0/awg1, живость ноги до exit, nft, CIDR
vds relay add-client phone          # Пир awg0: .conf (0600), endpoint relay-домен:443
                                     # (--keepalive 113 — И44: по умолчанию keepalive не пишется)
                                     # (--endpoint HOST[:PORT] — явный endpoint;
                                     #  имя самой машины пропускается, нерезолв →
                                     #  warning + IP сервера)
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
серверная реакция на зондирование (threat-level → lock-443) —
[docs/team/specs/SPEC-20261116-probe-response.md](docs/team/specs/SPEC-20261116-probe-response.md)
и [docs/SERVER-BASELINE.md](docs/SERVER-BASELINE.md) §5.12,
точки роста схем/протоколов (для техлида) — [docs/GROWTH-POINTS.md](docs/GROWTH-POINTS.md),
системный split и его аналоги — [docs/SPLIT-TRANSPORTS.md](docs/SPLIT-TRANSPORTS.md),
настройки ОС/сервера и чеклист восстановления — [docs/SERVER-BASELINE.md](docs/SERVER-BASELINE.md).

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

Проект ведёт ИИ-команда из десяти агентов (`.zcode/agents/`); процесс с гейтами — [docs/TEAM.md](docs/TEAM.md), контекст — [AGENTS.md](AGENTS.md).

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
| Метагент | `vds-agent-smith` | Проектирует и создаёт новых `vds-*` агентов |
| Скаут | `vds-youtube-scout` | YouTube-дайджесты по обходу блокировок (вход G0) |

Типовой поток: `owner → analyst → architect → coders → tester → [debugger] → docs → close`.
Модели: архитектор и тестировщик — `glm-5.3`, дебагер — `deepseek-flash`, остальные — `glm-5.3-flash`.

## Systemd: gateway-сервисы и таймеры ZeroTier

Gateway-протоколы — статические сервисы, без таймеров:
`vds-xray.service`, `vds-hysteria2.service`, `vds-hysteria2-hop.service`
(oneshot, восстанавливает nat-цепочку после ребута), `vds-hysteria2-obfs.service`,
`vds-amneziawg.service`. Юниты ставятся из шаблонов `systemd/*.tpl`.

Gateway-таймеры (ставятся по явной команде, не при установке протокола):

| Таймер | Назначение | Откуда |
|--------|-----------|--------|
| `vds-gateway-health.timer` | healthcheck юнитов/портов/сертификата, rate-limited рестарт упавших (W1 GR-18) | `vds gateway healthcheck --install-timer`, каждые 5 мин |
| `vds-probe-watch.timer` | дельта счётчиков зондирования tcp/{443,8443,2053} + threat-level | `vds gateway probe-watch install --apply` |
| `vds-probe-rucidr.timer` | обновление RU-CIDR-агрегата из ipdeny | `vds gateway probe-watch ru-cidr install --apply` |
| `vds-relay-cidr.timer` | RU-CIDR на релее (еженедельно) | `vds relay init --apply` (ADR-007) |
| `vds-logs-sample.timer` (`vds-logs-sample.service.tpl`/`vds-logs-sample.timer.tpl`) | 5-минутный сэмпл телеметрии (journald/счётчики, ADR-012); `ReadWritePaths=/var/lib/vds /var/run` (runtime-lock) | `vds logs install --apply` |
| `vds-logs-daily.timer` (`vds-logs-daily.service.tpl`/`vds-logs-daily.timer.tpl`) | ежедневный отчёт/ротация лог-конвейера (ADR-012); `ReadWritePaths=/var/lib/vds /var/run` (runtime-lock) | `vds logs install --apply` |

Таймеры ZeroTier (архив) активируются **только** при явной установке
`vds zerotier install` (опциональный сценарий):

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

### Синхронизация документации (docsync)

Документация — часть изменения: коммит, меняющий наблюдаемую поверхность
(CLI/порты/systemd/state/роли/версию), обязан содержать правки mapped живых
доков (SPEC-20261116-doc-sync). На свежем клоне установите git-хуки:

```bash
bash tools/install-hooks.sh   # commit-msg + pre-push; откат: git config --unset core.hooksPath
```

Команды инструмента (stdlib-only, без сети/root):

```bash
python3 tools/docsync.py check --staged          # что проверит commit-msg (индекс)
python3 tools/docsync.py audit [--strict]        # reverse-инварианты, ссылки, свежесть
python3 tools/docsync.py explain <path>          # какие доки требует изменение
python3 tools/docsync.py debt                    # коммиты с обходом «Docs: none»
```

Режимы: поле `"mode"` в `docs/doc-sync.json` — `warn` (нарушения печатаются,
хуки не блокируют; внедренческий период) или `block` (честный exit 1). Переход
в block — правкой реестра (коммит), не env-переменной. `audit --strict`
(гейты G4/G6) блокирует всегда, независимо от mode. Обход — трейлер
`Docs: none — <причина> (TECHDEBT Pxx)` в сообщении коммита; `--no-verify`
ловит pre-push.

## Требования

- Ubuntu 24.04 LTS
- Root-доступ
- Python 3.10+ (устанавливается автоматически)
- Docker (для ZeroTier/ZTNET)

## Лицензия

MIT