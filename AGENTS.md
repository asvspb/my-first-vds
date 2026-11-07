# AGENTS.md — контекст проекта VDS Orchestrator для ИИ-агентов

> **Прочитай этот файл целиком перед началом работы.** Здесь — что за проект, как устроен,
> какие команды запускать и какие правила соблюдать. Ролевая модель и процесс — в
> [docs/TEAM.md](docs/TEAM.md). Техдолг — в [TECHDEBT.md](TECHDEBT.md).

## 1. О проекте

**VDS Orchestrator** — Python CLI для управления выделенным сервером (Ubuntu 24.04):
ZeroTier + ZTNET Panel (Docker), WireGuard, Coturn, системный dashboard, первичная
настройка и очистка. Версия 3.0. Почти все операции требуют root.

## 2. Стек

| Слой | Технология |
|---|---|
| Язык | Python 3.10+ |
| CLI | typer, questionary (TUI), rich (вывод) |
| Конфиги/модели | pydantic 2.x |
| HTTP | requests |
| Метрики | psutil |
| Тесты | pytest (планируется, см. TECHDEBT P6) |
| Инфраструктура | Docker (ZTNET), systemd, iptables, UFW |
| ОС | Ubuntu 24.04 LTS |

## 3. Структура

```
src/
├── main.py              # typer-app, все команды; импорты модулей — ЛЕНИВО внутри команд
├── core/                # logger, shell, lock
├── zerotier/            # install, api, watchdog, reconcile, nat, diagnose, add_network, cleanup
├── wireguard/           # install, add-client, remove
├── coturn/              # TURN-сервер
├── sysinfo/             # dashboard
└── system/              # setup, cleanup
systemd/                 # unit-файлы таймеров/сервисов
docs/                    # TEAM.md, VPN-PROTOCOLS.md, CENSORSHIP-ROADMAP.md
install.sh, preinstall.sh, local-init.sh, myhelp.sh
```

## 4. Команды

| Команда | Что делает |
|---|---|
| `python -m src.main --help` | Справка CLI |
| `python -m src.main` | TUI-меню |
| `python -m src.main sysinfo` | Dashboard |
| `python -m compileall -q src` | Синтаксическая проверка |
| `pytest -q` | Тесты (когда появятся `tests/`) |
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

## 7. Тестовая стратегия

- **Unit** (без root/сети/docker): генераторы конфигов, `reconcile`, `store`,
  `netcheck`, rate-limit watchdog.
- **E2E** (Docker): сервер↔клиент через loopback (Xray/sing-box).
- **Приёмка протоколов** — на живом VDS по чеклисту (локально не воспроизвести).

## 8. Документация

`README.md` — обзор и команды; `docs/TEAM.md` — роли и процесс;
`docs/VPN-PROTOCOLS.md` — протоколы; `docs/CENSORSHIP-ROADMAP.md` — roadmap;
`TECHDEBT.md` — бэклог. При изменении поведения обновлять соответствующий документ.

## 9. Роли

`vds-owner` · `vds-analyst` · `vds-architect` · `vds-coder` · `vds-debugger` ·
`vds-tester` · `vds-docs` · `vds-orchestrator`. Определения — `.zcode/agents/`,
процесс и гейты — `docs/TEAM.md`.
