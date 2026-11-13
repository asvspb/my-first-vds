# AGENTS.md — контекст проекта VDS Orchestrator для ИИ-агентов

> **Прочитай этот файл целиком перед началом работы.** Здесь — что за проект, как устроен,
> какие команды запускать и какие правила соблюдать. Ролевая модель и процесс — в
> [docs/TEAM.md](docs/TEAM.md). Техдолг — в [TECHDEBT.md](TECHDEBT.md).

## 1. О проекте

**VDS Orchestrator** — Python CLI для управления выделенным сервером (Ubuntu 24.04):
gateway-протоколы против блокировок (Xray VLESS Reality/XHTTP/CDN, Hysteria2 с port
hopping и obfs salamander, AmneziaWG), ACME/Let's Encrypt, общее хранилище клиентов
(`vds gateway links`), плюс ZeroTier + ZTNET Panel (Docker), WireGuard, Coturn
(архив/опционально), системный dashboard, первичная настройка и очистка.
Версия 3.0. Почти все операции требуют root.

Репозиторий отдельный (`my-first-vds`); UbuntuInstaller деплоит его скриптами
`11_vds-deploy.sh` / `8_vds-server.sh` (источник — `VDS_REPO`) и забирает ссылки
через `vpn profile pull`. Копии репозитория в ubuntuInstaller нет.

## 2. Стек

| Слой | Технология |
|---|---|
| Язык | Python 3.10+ |
| CLI | typer, questionary (TUI), rich (вывод) |
| Конфиги/модели | pydantic 2.x |
| HTTP | requests |
| Метрики | psutil |
| Тесты | pytest (`tests/`: core, gateway, xray, hysteria2, amneziawg, acme) |
| Инфраструктура | Docker (ZTNET), systemd, iptables/nftables, UFW, certbot |
| ОС | Ubuntu 24.04 LTS |

## 3. Структура

```
src/
├── main.py              # typer-app, все команды; импорты модулей — ЛЕНИВО внутри команд
├── core/                # logger, shell, lock + protocol (ProtocolAdapter), netcheck, secrets, units
├── zerotier/            # install, api, watchdog, reconcile, nat, diagnose, add_network, cleanup
├── wireguard/           # install, add-client, remove
├── coturn/              # TURN-сервер
├── xray/                # Reality (443), XHTTP (8443), CDN (2053): adapter, install, clients, config, status, remove
├── hysteria2/           # QUIC (443): adapter, install, clients, config, hop, obfs, status, sysctl, remove
├── amneziawg/           # AmneziaWG (UDP 51825): install, clients, status, remove
├── acme/                # ACME/LE: issue (HTTP-01) + deploy-hook для Hysteria2
├── gateway/             # paths, store (state.json 0600), links, blockcheck
├── sysinfo/             # dashboard
└── system/              # setup, cleanup
systemd/                 # таймеры/сервисы; vds-xray/vds-hysteria2(-hop/-obfs)/vds-amneziawg .service.tpl; sysctl/99-vds-gateway.conf.tpl
tests/                   # unit-тесты (pytest, без root/сети): core/, gateway/, xray/, hysteria2/, amneziawg/, acme/
docs/                    # TEAM.md, DEPLOY.md, VPN-PROTOCOLS.md, CDN-FRONTS.md,
                         # CENSORSHIP-ROADMAP.md, CENSORSHIP-PATTERNS.md, MIGRATE-VDS.md, adr/, team/
install.sh, preinstall.sh, local-init.sh, myhelp.sh
```

## 4. Команды

| Команда | Что делает |
|---|---|
| `python -m src.main --help` | Справка CLI |
| `python -m src.main` | TUI-меню |
| `python -m src.main sysinfo` | Dashboard |
| `python -m compileall -q src` | Синтаксическая проверка |
| `pytest -q` | Юнит-тесты (`tests/`, без root/сети/docker) |
| `bash install.sh` | Установка (root, на сервере) |

## 5. Конвенции кода

1. **Модули**: `src/<category>/<module>.py`; регистрация команды в `src/main.py` с
   **ленивым импортом** внутри функции (запуск CLI не должен тянуть тяжёлые модули).
2. **Shell**: только через `src/core/shell.py`. В новом коде — `run_list([...])`,
   `shell=True` не использовать. `docker_exec` принимает список аргументов.
3. **Блокировки**: `core.lock.FileLock` для любой мутирующей операции.
4. **Секреты и конфиги**: атомарная запись, права 0600, значения не попадают в лог,
   share-link и git.
5. **Вывод**: `core.logger.console`, теги `[info] [success] [warning] [error] [change]`.
6. **Типы**: аннотации обязательны; без `except:` и пустых обработчиков; ошибки
   возвращаются через `ShellResult`.
7. **Идемпотентность**: повторный запуск не должен ломать состояние.
8. **Деструктивные операции**: dry-run по умолчанию + явное подтверждение / `--apply`.
9. **Пути**: `INSTALL_DIR` из env (`/opt/ztnet`, `/opt/my-vds`); не хардкодить.

## 6. Инварианты безопасности (не нарушать)

- Не убивать процессы по порту/имени без белого списка (см. TECHDEBT P4).
- В тестах не трогать production-состояние: только моки, temp-каталоги, Docker.
- Не логировать и не выводить UUID, пароли, приватные ключи.
- Перед установкой сервиса проверять занятость порта (`ss -tlnp`).
- systemd-юниты — только из шаблонов `systemd/`, не править на сервере руками.
- **Фикстуры секретов** (тесты, примеры в доке) — только со значимыми префиксами
  `FIXTURE_PW_` / `FIXTURE_UUID_` и зарезервированными IP/UUID (203.0.113.0/24 RFC 5737,
  11111111-2222-…). Никаких «правдоподобных» паролей (`SharedPass123`, `s3cretpass`) —
  детекторы секретов (GitGuardian) триггерятся на них и дают ложные инциденты.

## 7. Тестовая стратегия

- **Unit** (без root/сети/docker): генераторы конфигов, `reconcile`, `store`,
  `netcheck`, `secrets`, `units`, rate-limit watchdog (см. `tests/`).
- **E2E** (Docker): сервер↔клиент через loopback (Xray/sing-box).
- **Приёмка протоколов** — на живом VDS по чеклисту (локально не воспроизвести).

## 8. Документация

`README.md` — обзор и команды; `docs/TEAM.md` — роли и процесс;
`docs/DEPLOY.md` — деплой и чеклист; `docs/VPN-PROTOCOLS.md` — протоколы
(Reality, XHTTP, Hysteria2 hop/obfs, AWG, CDN); `docs/CDN-FRONTS.md` — пул
фронтов CDN; `docs/CENSORSHIP-ROADMAP.md` — roadmap (статус фаз + волны W1–W6);
`docs/CENSORSHIP-PATTERNS.md` — паттерны обхода (с живыми доказательствами);
`docs/GROWTH-POINTS.md` — точки роста схем/протоколов (вход для intake);
`docs/SPLIT-TRANSPORTS.md` — системный split: AWG и аналоги (Reality/Hy2/XHTTP/CDN);
`docs/MIGRATE-VDS.md` — перенос сервера; `docs/adr/` — ADR-001…009;
`TECHDEBT.md` — бэклог. При изменении поведения обновлять соответствующий документ
(новый протокол/транспорт — ADR + VPN-PROTOCOLS + README + AGENTS).

## 9. Роли

`vds-owner` · `vds-analyst` · `vds-architect` · `vds-coder` · `vds-debugger` ·
`vds-tester` · `vds-docs` · `vds-orchestrator`. Определения — `.zcode/agents/`,
процесс и гейты — `docs/TEAM.md`.
