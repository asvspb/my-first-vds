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
Версия 3.0 (pyproject `3.0.0`). Почти все операции требуют root.

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
| Тесты | pytest (`tests/`: core, gateway, xray, hysteria2, amneziawg, acme, relay, docs) |
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
├── xray/                # Reality (443), XHTTP (8443, path — случайный секрет), CDN (2053, только CF-CIDR): adapter, install, clients, config, status, remove
├── hysteria2/           # QUIC (443): adapter, install, clients, config, hop, obfs, status, sysctl, remove
├── amneziawg/           # AmneziaWG (UDP 51825): install, clients, status, remove
├── relay/               # RU-relay (ADR-007): init, status, clients, cidr (AWG udp/443 + Reality tcp/443 + policy-routing до exit-ноды)
├── acme/                # ACME/LE: issue (HTTP-01) + deploy-hook для Hysteria2
├── gateway/             # paths, store (state.json 0600), links, blockcheck, init (идемпотентное развёртывание), probing (probe-watch: телеметрия+threat-level+auto-lockdown+verified_session_ips anti Self-DoS, SPEC probe-response; probers4 на tcp/{443,8443,2053} + быстрый контур fast_contour_check в 5-мин сэмплере vds-logs-sample, SPEC probe-coverage W1-1; RU-PROBE-SUSPECT = syn_valid + syn_valid_extra, PROBE-BURST — только 443), probing_rucidr (RU-CIDR)
├── sysinfo/             # dashboard
├── logs/                # log-forensics (ADR-012): install, collect (sample), report/analyze, capture
└── system/              # setup, cleanup, ufw (harden/ssh-port — SPEC-20261116; CDN-порт — CF-CIDR-набор)
systemd/                 # таймеры/сервисы; vds-xray/vds-hysteria2(-hop/-obfs)/vds-amneziawg(-nat)/
                         # vds-relay-{exit,nat,policy,cidr}.service.tpl; vds-gateway-health / vds-probe-watch /
                         # vds-probe-rucidr / vds-logs-sample / vds-logs-daily .service+.timer.tpl
                         # (vds-logs-sample/daily: ReadWritePaths /var/lib/vds + /var/run для FileLock);
                         # sysctl/99-vds-gateway.conf.tpl
tests/                   # unit-тесты (pytest, без root/сети): core/, gateway/, xray/, hysteria2/, amneziawg/, acme/, relay/
docs/                    # TEAM.md, DEPLOY.md, DEPLOY-RU-RELAY.md, VPN-PROTOCOLS.md, CDN-FRONTS.md,
                         # CENSORSHIP-ROADMAP.md, CENSORSHIP-PATTERNS.md, MIGRATE-VDS.md, adr/, team/
install.sh, preinstall.sh, local-init.sh, myhelp.sh
```

## 4. Команды

| Команда | Что делает |
|---|---|
| `python -m src.main --help` | Справка CLI |
| `python -m src.main` | TUI-меню |
| `python -m src.main sysinfo` | Dashboard |
| `vds system ufw harden --profile gateway/relay/exit-cascade` | Идемпотентный UFW hardening (SPEC-20261116; dry-run по умолчанию, `--apply`, `--undo`; hop-диапазон из state нормализуется `-`→`:`) |
| `vds system ufw ssh-port --to 49222 [--finalize]` | Двухфазный перенос SSH-порта (22 закрывается только `--finalize`; откат Фазы A сам перезапускает ssh.socket/ssh, drop-in 0644) |
| `python -m compileall -q src` | Синтаксическая проверка |
| `pytest -q` | Юнит-тесты (`tests/`, без root/сети/docker) |
| `bash install.sh` | Установка (root, на сервере) |

> Миграция XHTTP после смены IP узла (DNS ещё на старом адресе):
> `vds xray add-transport xhttp --domain <домен> --mode port --skip-domain-check --apply --yes`
> — E1 отключается только для этого случая, сертификат/SNI не меняются;
> CDN-инбаунд (ws/2053) сохраняется, `path` не ротируется.

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
`docs/SERVER-BASELINE.md` — настройки ОС/сервера: авто vs вручную, чеклист восстановления;
`docs/SPLIT-TRANSPORTS.md` — системный split: AWG и аналоги (Reality/Hy2/XHTTP/CDN);
`docs/MIGRATE-VDS.md` — перенос сервера; `docs/adr/` — ADR-001…014;
`TECHDEBT.md` — бэклог. При изменении поведения обновлять соответствующий документ
(новый протокол/транспорт — ADR + VPN-PROTOCOLS + README + AGENTS).

## 9. Документация — часть изменения

Код и его документация живут в одном коммите (SPEC-20261116-doc-sync, инструмент
`tools/docsync.py`, реестр `docs/doc-sync.json`):

1. **Коммит = код + тесты + mapped-доки.** Изменение наблюдаемой поверхности
   (CLI, поведение, порты, systemd, state, роли, версия) тянет правки всех живых
   доков по правилам реестра. Какие доки требует путь:
   `python3 tools/docsync.py explain <path>`.
2. **Единственный обход** — трейлер в сообщении коммита:
   `Docs: none — <причина> (TECHDEBT Pxx)`; Pxx обязан существовать в
   `TECHDEBT.md` (фиктивный — fail). Список долгов:
   `python3 tools/docsync.py debt`.
3. **`git commit --no-verify`** — аварийный выход; его ловит `pre-push`
   (`docsync audit --range origin/main..HEAD`) и G4/G6 (`audit --strict`).
4. **Хуки ставятся на каждом клоне**: `bash tools/install-hooks.sh`
   (commit-msg + pre-push; откат: `git config --unset core.hooksPath`).
5. **Режим warn/block** — поле `mode` в `docs/doc-sync.json`: `warn` — нарушения
   печатаются, но не блокируют; `block` — честный exit 1. Переход в block —
   только правкой реестра (коммит), не env-переменной. `audit --strict`
   (G4/G6) блокирует всегда.
6. **Docsync debt** — `Docs: none`-коммиты видны в `docsync debt`; G6 не
   закрывается с непогашенным долгом (закрытие — правка доков или строка в
   TECHDEBT).

## 10. Роли

`vds-owner` · `vds-analyst` · `vds-architect` · `vds-coder` · `vds-debugger` ·
`vds-tester` · `vds-docs` · `vds-orchestrator` · метагент `vds-agent-smith` · скаут
`vds-youtube-scout` (всего 10). Определения — `.zcode/agents/` (канон) и
генерируемое зеркало `.opencode/agents/` (`tools/export_opencode_agents.py`),
процесс и гейты — `docs/TEAM.md`.
