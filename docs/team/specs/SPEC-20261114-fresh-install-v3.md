# SPEC-20261114-fresh-install-v3

## Мета
- **Источник:** задача владельца 2026-11-14 «настроить сервер vds с нуля»;
  разбор показал, что `11_vds-deploy.sh` поднимает только Reality+Hy2, а
  XHTTP/CDN/AWG/obfs/hop/healthcheck требуют ручных шагов.
  Связано: [GROWTH-POINTS](../GROWTH-POINTS.md) GR-16 (`gateway init`),
  [MIGRATE-VDS](../../MIGRATE-VDS.md), [DEPLOY](../../DEPLOY.md).
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-14
- **Статус:** **G4: code accepted 2026-11-14** (unit + live dry-run + чистое
  Ubuntu 24.04 в systemd-контейнере: Reality+Hy2, AC-1/2/3/4 подмножества
  PASS); полноценная VM-приёмка AWG/obfs/hop/CDN/ACME — за владельцем; см.
  [TEST-20261114-fresh-install-v3](../reports/TEST-20261114-fresh-install-v3.md) §6
- **ADR:** не требуется (аддитивная оркестрация существующих идемпотентных
  команд; публичные контракты install/add-* не меняются)

## 1. Цель и решение

Сделать **одну идемпотентную команду** полного развёртывания на чистом
сервере: `vds gateway init` (dry-run по умолчанию, `--apply` для исполнения).
Она последовательно поднимает выбранные транспорты через уже существующие
модули (`xray install`, `hysteria2 install`, `acme issue`,
`xray add-transport`, `xray add-cdn`, `hysteria2 add-obfs`,
`hysteria2 add-hop-ports`, `amneziawg install`, `gateway healthcheck
--install-timer`), проверяет порты/DNS **до** мутаций, пропускает уже
установленное и печатает итоговую карту «что поднято / что дальше».

`11_vds-deploy.sh` перестаёт дёргать отдельные команды: он вызывает
`vds gateway init --apply` с параметрами из env. Поведение по умолчанию
(`reality,hysteria2`) сохраняется — обратная совместимость.

## 2. Архитектура

```
vds gateway init [flags]                    # dry-run: план + проверки
vds gateway init --apply                    # исполнение по шагам
   │
   ├─ preflight: root, OS, INSTALL_DIR, public_ip, DNS, порты (ss), egress
   ├─ steps (последовательно, fail-fast):
   │   1 xray install (reality)
   │   2 hysteria2 install
   │   3 acme issue + hysteria2 apply-cert      (если --domain/--email)
   │   4 xray add-transport (xhttp)              (если в --protocols)
   │   5 xray add-cdn (cdn)                      (если есть домен)
   │   6 hysteria2 add-obfs (obfs)                (если в --protocols)
   │   7 hysteria2 add-hop-ports (hop)            (если в --protocols)
   │   8 amneziawg install (awg)
   │   9 gateway healthcheck --install-timer
   └─ summary: units/ports/certs + `vds gateway links` + next steps

11_vds-deploy.sh:
   VDS_PROTOCOLS=reality,hysteria2[,xhttp,cdn,obfs,hop,awg]
   VDS_DOMAIN=… VDS_EMAIL=…  →  ssh "vds gateway init --apply …"
```

Точки отказа: занятый порт (fail до мутаций), DNS ещё не на новый IP
(ACME/CDN пропускаются с warning, остальное ставится), отсутствие root.

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/gateway/init.py` | создать | план, preflight, исполнение шагов, summary |
| `src/main.py` | изменить | команда `gateway init` (ленивый импорт) |
| `tests/gateway/test_init.py` | создать | план/скипы/порты/флаги/fail-fast/идемпотентность |
| `tests/gateway/test_init_cli.py` | создать | CLI-поверхность, dry-run по умолчанию, exit-коды |
| `docs/DEPLOY.md` | изменить | «Вариант A»: один вызов init; таблица флагов |
| `README.md` | изменить | короткий пример полного init |
| `AGENTS.md` | изменить | структура: `gateway/init.py` |
| `ubuntuInstaller/scripts/11_vds-deploy.sh` | изменить | вызов init вместо отдельных команд; env `VDS_PROTOCOLS` |
| `ubuntuInstaller/doc/vds.md` | изменить | свежий чеклист с нуля (какие протоколы, что делает init) |

**Публичные интерфейсы:**

```python
# src/gateway/init.py
@dataclass
class Step:
    name: str            # "xray", "hysteria2", "acme", ...
    title: str
    command: list[str]   # argv для run_list (не shell)
    skip_reason: str = ""

@dataclass
class InitPlan:
    steps: list[Step]
    warnings: list[str]
    errors: list[str]

def parse_protocols(value: str) -> list[str]: ...   # валидация, ValueError
def build_plan(protocols, domain, email, sni, hop_range, cdn_domain,
               state_path=None) -> InitPlan: ...
def preflight(plan, domain, state_path=None) -> list[str]: ...  # ошибки
def run_init(protocols, domain, email, sni, hop_range, cdn_domain,
             apply=False, demo_clients=False, state_path=None) -> int: ...
```

**CLI-поверхность:**

```bash
vds gateway init                                  # dry-run: план + проверки
vds gateway init --apply                          # reality + hysteria2
vds gateway init --apply \
    --protocols reality,hysteria2,obfs,hop,xhttp,cdn,awg \
    --domain vpn.example.ru --email admin@example.ru \
    --sni www.cloudflare.com --hop-range 20000-20500 \
    --cdn-domain cdn.example.ru --demo-clients
```

| Флаг | Default | Смысл |
|---|---|---|
| `--protocols` | `reality,hysteria2` | csv из `reality,hysteria2,obfs,hop,xhttp,cdn,awg` |
| `--domain` | — | домен для ACME/CDN/ссылок |
| `--email` | — | ACME (не сохраняется) |
| `--sni` | `www.google.com` | Reality dest/serverNames |
| `--hop-range` | `20000-20500` | диапазон при `hop` |
| `--cdn-domain` | = `--domain` | origin-домен CDN |
| `--demo-clients` | off | создать phone/mob/laptop и напечатать links |
| `--apply` | off | исполнить (иначе dry-run) |

**Правила зависимостей (валидация на входе):**

- `obfs`/`hop` требуют `hysteria2`;
- `xhttp` требует `reality` (инблэнд за SNI-фолбэком, ADR-003);
- `cdn` требует `--domain` (или `--cdn-domain`) и `reality`;
- `awg` независим;
- неизвестный протокол → ошибка до любых действий.

## 4. Миграция и совместимость

- Существующие установки: `init` идемпотентен — установленные транспорты
  пропускаются (`state.protocols[...]`), добавляются только недостающие.
- `11_vds-deploy.sh`: при отсутствии `VDS_PROTOCOLS` ведёт себя как раньше
  (reality+hysteria2), но через init; старые вызовы команд остаются
  доступными.
- State-схема не меняется; новых ключей нет.
- Откат: по-прежнему `vds <proto> remove --apply`; init печатает команды
  отката для каждого установленного шага.

## 5. Безопасность и отказы

- Секреты: только в state/конфигах (0600); init не логирует пароли/ключи,
  ACME-email не сохраняет (ADR-004).
- Dry-run по умолчанию; мутации только с `--apply`.
- Порты проверяются **до** мутаций: занят чужим процессом → fail с
  подсказкой (без убийства процессов).
- DNS: если домен не резолвится в публичный IP сервера — ACME/CDN
  пропускаются с warning, остальные шаги выполняются (или fail при
  `--require-domain` — OQ-1).
- Fail-fast: первая ошибка останавливает init, печатается шаг, stderr
  команды (без секретов) и команда ручного продолжения.

## 6. Тест-план

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | `parse_protocols` (валидность/зависимости); `build_plan` (порядок, скипы по state); preflight (занятый порт, DNS); fail-fast; dry-run не вызывает мутаций | `tests/gateway/test_init.py` |
| CLI | dry-run по умолчанию; `--apply`; exit-коды; help; отсутствие секретов в выводе | `tests/gateway/test_init_cli.py` |
| Integration (Docker) | нет systemd — ограниченно: проверка плана/валидации; полноценный e2e — на VM | `tests/gateway/` |
| Ручная приёмка (чистая Ubuntu 24.04 VM/VDS) | один вызов init → все юниты active, порты слушаются, `gateway links` непустой, healthcheck-таймер; повторный init — «изменений не требуется» | чеклист в `docs/DEPLOY.md` |

**Критерии приёмки:**

1. На чистой VM `vds gateway init --apply --domain … --email … --protocols
   reality,hysteria2,obfs,hop,xhttp,cdn,awg` → все требуемые юниты active,
   порты 443/8443/2053/51825/51826 (+hop-диапазон) слушаются, `gateway
   links --include-obfs` отдаёт ссылки, `vds-gateway-health.timer` активен.
2. Повторный тот же вызов — ни одной мутации, «уже установлено/изменений
   не требуется», exit 0.
3. Без `--domain`: acme/cdn пропущены с понятным warning, reality/hy2/awg
   работают.
4. Занятый порт (запустить `python -m http.server 8443`) → init падает до
   установки, сообщает порт/владельца, ничего не ломает.
5. `pytest -q` (vds) зелёный; в логах нет uuid/паролей/ключей.
6. `11_vds-deploy.sh` без `VDS_PROTOCOLS` даёт прежний результат
   (reality+hysteria2) на чистой машине.

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| **WP-1** | План/preflight/executor без CLI | `src/gateway/init.py`, `tests/gateway/test_init.py` | — | unit зелёные; dry-run не мутирует; fail-fast; скипы по state |
| **WP-2** | CLI `gateway init` + summary + `--demo-clients` | `src/main.py`, `tests/gateway/test_init_cli.py` | WP-1 | help/exit-коды; dry-run по умолчанию; секретов в выводе нет |
| **WP-3** | `11_vds-deploy.sh` → init, env `VDS_PROTOCOLS`, docs | `ubuntuInstaller/scripts/11_vds-deploy.sh`, `docs/DEPLOY.md`, `README.md`, `AGENTS.md`, `ubuntuInstaller/doc/vds.md` | WP-2 | дефолт-поведение сохранено; docs-чеклист с нуля; shellcheck/`bash -n` |

Пересечение файлов: WP-2 и WP-3 не пересекаются (разные репозитории), WP-1/2
последовательны. Каждый WP — отдельный коммит, `pytest` до/после.

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| init идемпотентен не для всех add-* (obfs при state-only) | средняя | «фантомный» юнит | WP-1 проверяет **наличие юнита/конфига**, а не только state; при расхождении — предупреждение и повторная установка |
| ACME гоняется до DNS-переключения | высокая | init падает на чистой VM без домена | DNS-проверка + skip с warning (OQ-1) |
| Провайдерский файрвол режет порты | средняя | протокол не работает | preflight egress + warning; открытие портов — шаг владельца |
| init затронет работающий сервер | низкая | простой | dry-run по умолчанию; скипы по state; отдельный флаг `--apply` |
| Расхождение с migrate/backup | средняя | путаница | init — только «с нуля/добить»; перенос — отдельный GR-20 |

## 9. Границы изменений

- **Трогаем:** `src/gateway/init.py`, `src/main.py`, тесты, `docs/DEPLOY.md`,
  `README.md`, `AGENTS.md`, `scripts/11_vds-deploy.sh`, `doc/vds.md`.
- **Не трогаем:** публичные контракты `install/add-*/remove`, схему
  state.json, секреты, systemd-шаблоны, UFW/провайдерские политики,
  `20_vds-migrate.sh` (GR-20 — отдельно), CF-туннели/Argo.
- **Вне скоупа:** split-схемы для Reality/XHTTP (SPLIT-TRANSPORTS),
  subscription/QR-export, DNS-01, деплой с Windows.

## 10. Трассируемость

| Источник | WP | Файлы | Тест |
|---|---|---|---|
| Разбор fresh install 2026-11-14 | WP-1/2 | `gateway/init.py`, `main.py` | `test_init*.py` |
| Ручные шаги в `11_vds-deploy.sh` | WP-3 | `11_vds-deploy.sh` | приёмка §6 |
| GR-16 (`gateway init`) | WP-1/2 | — | §6 п.1–2 |

## 11. Открытые вопросы

- **OQ-1:** при отсутствии DNS-соответствия init должен (а) пропускать ACME
  с warning (предлагается) или (б) падать при `--require-domain`? Решение:
  (а) по умолчанию + флаг `--require-domain` для строгого режима.
- **OQ-2:** `--demo-clients` создаёт фиксированные имена (`phone/mob/laptop`)
  или принимает csv `name:protocol`? Решение: фиксированные имена для
  совместимости с `11_vds-deploy.sh`, csv — future.
- **OQ-3:** `hop` включать по умолчанию при `--protocols all`? Решение: нет,
  только явно (риск клиентской совместимости, v2rayNG 2.3.8).

## Следующий шаг

→ `vds-coder`: WP-1 → WP-2 → WP-3, каждый — отдельный коммит `feat(init): …`;
после каждого `pytest -q` (vds) и `bash -n` для скрипта. Приёмка — на чистой
VM/VDS по §6 (тестер — `vds-tester`/архитектор).
