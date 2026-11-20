# SPEC-20261116-doc-sync — симметричная синхронизация документации с кодом в каждом коммите

## Мета
- **Источник:** аудит документации 2026-11-16 (сессия владельца; HEAD `c31462e`) +
  прямое поручение владельца «документация должна меняться в том же коммите».
  Формальный REQ не заводился — на ревью решить, нужен ли он (рекомендация:
  нет, это процесс + dev-инструмент, не пользовательская функциональность).
- **Автор:** оркестратор (черновик по поручению владельца)
- **Дата:** 2026-11-16
- **Статус:** **draft — на ревью `vds-architect` + техлид (G2)**
- **Ревьюеры:** архитектор (архитектура инструмента, границы), техлид/владелец
  (blocking-политика, коммит-конвенция, цена внедрения)
- **ADR:** не требуется: решение обратимо (хуки отключаются одной командой,
  документы остаются валидными). При желании — ADR-012 «doc-sync как процесс».
- **Скоуп:** репозиторий `vds`. Клиентский `ubuntuInstaller`/`vpnm` — отдельная
  SPEC тем же паттерном (интерфейс конфига совместим).

---

## 1. Проблема

Документация отстаёт не из-за отсутствия правил, а из-за **отсутствия
детерминированной точки проверки**: «обновить доки» существует как пожелание
в AGENTS/TEAM, но ни один гейт не падает, если доки не обновлены. Аудит
2026-11-16 показал системный дрейф:

| Факт | Доказательство |
|---|---|
| «Единый источник правды» описывает закрытый цикл | `docs/team/STATUS.md:6-56` — CDN-transport `⏳ pending`, хотя CDN работает; нет циклов relay/UFW/probe-response/И44/asv2 |
| README противоречит сам себе | `README.md:256` — healthcheck-таймер; `README.md:261-264` — «таймеры только для ZeroTier» |
| Справочник протоколов отстал на 9 дней | `docs/VPN-PROTOCOLS.md:3,258-267` — «XHTTP/ACME не реализованы» |
| Roadmap-статусы не соответствуют коду | `docs/CENSORSHIP-ROADMAP.md:63-140` — «hub/healthcheck ❌», «499 тестов» |
| Поведение изменено, доки молчат | И44: `PersistentKeepalive` больше не пишется по умолчанию (`src/amneziawg/config.py:154-156,210`), в README/DEPLOY-RU-RELAY нет `--keepalive` |
| Механические факты расходятся | ADR-011 есть — AGENTS говорит «ADR-001…010»; агентов 10 — README говорит «8»; 843 теста — GROWTH/ROADMAP говорят «499» |
| Битые ссылки | 4 относительные ссылки в `docs/team/{requirements,specs}/` |

Вывод: нужен **алгоритм**, который делает документацию частью определения
готовности коммита, а не финальной уборкой цикла. Проверка должна быть
локальной, детерминированной и не зависеть от CI (CI пока нет — GR-24).

---

## 2. Цель, требования и принципы

### 2.1. Цель

Любой коммит, меняющий наблюдаемую поверхность (CLI, поведение, порты,
systemd, state, роли, версию), **в том же коммите** содержит согласованные
изменения во всех документах, которые эту поверхность описывают. Обратно:
документ не может описывать то, чего нет в коде.

### 2.2. Требования

| ID | Требование | Как проверяется |
|---|---|---|
| R-1 | Изменение кода и его документации — в одном коммите | `docsync check --staged` в `commit-msg` |
| R-2 | Симметрия: код→доки **и** доки→код (нет фантомных команд/юнитов/ADR/ролей) | reverse-инварианты в `audit` |
| R-3 | Живые документы синхронизируются; снимки (SPEC/REPORT/research) не переписываются | классы документов в реестре |
| R-4 | Проверка локальная: без сети, root, Docker, LLM и внешних зависимостей | stdlib-only, `--staged` < 300 мс |
| R-5 | Обход правила возможен, но явен и виден аудиту | трейлер `Docs: none — причина (TECHDEBT Pxx)` + `docsync debt` |
| R-6 | Алгоритм встроен в гейты G1–G6, а не живёт отдельно | чеклисты TEAM + шаблоны REQ/SPEC/STATUS |
| R-7 | Внедрение обратимо; сначала warning, потом block | режим `warn` → `block`, откат — `core.hooksPath` |

### 2.3. Принципы

1. **Один коммит — один связный срез.** Код + тесты + доки того же среза.
2. **Проверяем факты, а не текст.** Инструмент не пишет прозу и не оценивает
   качество формулировок; он гарантирует наличие/существование.
3. **Явное лучше неявного.** Неизвестный путь → warning с подсказкой, а не
   молчаливый пропуск.
4. **Снимок неприкосновенен.** SPEC/TEST/research — исторические артефакты;
   правим только битые ссылки.
5. **Никакой «документации ради галочки».** Наличие файла в коммите проверяет
   хук; содержательность — ревьюер на G4/G5.

---

## 3. Архитектура решения

```
разработчик / ИИ-агент
        │  git commit
        ▼
.githooks/commit-msg ──► tools/docsync.py check --staged --message "$1"
        │                        │
        │                        ├─ rules: какие доки обязаны измениться
        │                        ├─ staged: что реально в индексе
        │                        ├─ трейлер "Docs: none — причина"
        │                        └─ exit 0 | 1 (+ список missing)
        ▼
   коммит создан
        │  git push
        ▼
.githooks/pre-push ──► tools/docsync.py audit --range origin/main..HEAD
        │                        ├─ reverse-инварианты
        │                        ├─ ссылки/свежесть/запрещённые счётчики
        │                        └─ exit 0 | 1
        ▼
гейты G4/G5/G6 + еженедельный аудит ──► audit --strict
```

Компоненты:

| Компонент | Роль |
|---|---|
| `docs/doc-sync.json` | **единственный** реестр: классы документов, правила «изменение → доки», reverse-инварианты, пороги свежести |
| `tools/docsync.py` | проверщик: `check`, `audit`, `explain`, `debt`; только stdlib + `git`/`ast` |
| `.githooks/commit-msg` | блокирующая проверка на коммите (основная точка R-1) |
| `.githooks/pre-push` | полный аудит диапазона (страховка от `--no-verify`) |
| `tools/install-hooks.sh` | `git config core.hooksPath .githooks` (идемпотентно) |
| Шаблоны/гейты | «Doc impact» в REQ/SPEC, критерии G1–G6 |
| `.github/workflows/docs.yml` | опционально, после GR-24: тот же `audit` в CI |

Почему **не** pre-commit framework: лишняя зависимость и сеть; хватает git-хуков
и stdlib. Почему **не** генерация прозы: высокая цена поддержки и риск
«сгенерировали не то»; v1 проверяет наличие и непротиворечивость.

---

## 4. Классы документов и правила жизненного цикла

| Класс | Примеры | Синхронизация | Свежесть |
|---|---|---|---|
| `living` | `README.md`, `AGENTS.md`, `TECHDEBT.md`, `docs/TEAM.md`, `docs/DEPLOY.md`, `docs/VPN-PROTOCOLS.md`, `docs/CENSORSHIP-ROADMAP.md`, `docs/CENSORSHIP-PATTERNS.md`, `docs/SERVER-BASELINE.md`, `docs/MIGRATE-VDS.md`, `docs/SPLIT-TRANSPORTS.md`, `docs/CDN-FRONTS.md`, `docs/DEPLOY-RU-RELAY.md` | обязательна при изменении mapped-источника | 30 дней с последнего изменения источника |
| `status` | `docs/team/STATUS.md` | обновляется на гейтах и live-ops, не на каждый коммит | 7 дней; плюс «старше последнего `feat:`-коммита» → warning |
| `adr` | `docs/adr/ADR-*.md` | append-only; статус/дата обязательны | без SLA, проверяется диапазон/существование |
| `snapshot` | `docs/team/specs/**`, `docs/team/reports/**`, `docs/team/requirements/**`, `docs/research/**`, `docs/GROWTH-POINTS.md` | не переписывается; только битые ссылки | нет |
| `template` | `docs/team/templates/**` | не синхронизируется с кодом | нет |

`GROWTH-POINTS.md` — **snapshot**: это банк идей с датой базы; актуальные
статусы живут в ROADMAP/STATUS. Иначе он превращается в второй STATUS.

Правила:
- новый `.md` в корне или `docs/` обязан попасть в реестр (иначе `audit` →
  warning: «незарегистрированный живой документ»);
- `snapshot` не требует синхронизации, но его ссылки проверяются;
- `status` не обязан меняться в каждом коммите, но G6 без обновления STATUS
  невозможен (это уже правило TEAM).

---

## 5. Реестр `docs/doc-sync.json`

Единый JSON (stdlib, без PyYAML; Python 3.10-совместимо). Схема v1:

```json
{
  "version": 1,
  "classes": {
    "living": [
      "README.md", "AGENTS.md", "TECHDEBT.md", "docs/TEAM.md",
      "docs/DEPLOY.md", "docs/VPN-PROTOCOLS.md", "docs/CENSORSHIP-ROADMAP.md",
      "docs/CENSORSHIP-PATTERNS.md", "docs/SERVER-BASELINE.md",
      "docs/MIGRATE-VDS.md", "docs/SPLIT-TRANSPORTS.md",
      "docs/CDN-FRONTS.md", "docs/DEPLOY-RU-RELAY.md"
    ],
    "status": ["docs/team/STATUS.md"],
    "adr": ["docs/adr/ADR-*.md"],
    "snapshot": [
      "docs/team/specs/**", "docs/team/reports/**",
      "docs/team/requirements/**", "docs/research/**",
      "docs/GROWTH-POINTS.md"
    ],
    "template": ["docs/team/templates/**"]
  },
  "rules": [
    {
      "id": "cli-surface",
      "match": ["src/main.py"],
      "require": ["README.md", "AGENTS.md"],
      "consider": ["docs/VPN-PROTOCOLS.md"],
      "why": "команды/флаги CLI"
    },
    {
      "id": "ufw",
      "match": ["src/system/ufw.py"],
      "require": ["README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"],
      "consider": ["docs/DEPLOY.md", "docs/MIGRATE-VDS.md"],
      "why": "порты/профили/ssh-перенос/лок 443"
    },
    {
      "id": "probing",
      "match": ["src/gateway/probing.py", "src/gateway/probing_rucidr.py"],
      "require": ["README.md", "AGENTS.md", "docs/CENSORSHIP-PATTERNS.md", "docs/SERVER-BASELINE.md"],
      "consider": ["docs/CENSORSHIP-ROADMAP.md"],
      "why": "probe-watch/threat-level/ru-cidr/lock-443"
    },
    {
      "id": "relay",
      "match": ["src/relay/**"],
      "require": ["README.md", "docs/DEPLOY-RU-RELAY.md", "AGENTS.md"],
      "consider": ["docs/MIGRATE-VDS.md", "docs/SERVER-BASELINE.md"],
      "why": "релей, ноги, policy-routing"
    },
    {
      "id": "amneziawg",
      "match": ["src/amneziawg/**"],
      "require": ["README.md", "docs/VPN-PROTOCOLS.md", "AGENTS.md"],
      "consider": ["docs/DEPLOY-RU-RELAY.md"],
      "why": "AWG-параметры, keepalive, клиенты"
    },
    {
      "id": "transports",
      "match": ["src/xray/**", "src/hysteria2/**", "src/acme/**"],
      "require": ["README.md", "docs/VPN-PROTOCOLS.md", "docs/DEPLOY.md"],
      "consider": ["docs/SERVER-BASELINE.md"],
      "why": "протоколы, порты, TLS/ACME"
    },
    {
      "id": "paths-state",
      "match": ["src/gateway/paths.py", "src/gateway/store.py"],
      "require": ["README.md", "docs/SERVER-BASELINE.md", "docs/MIGRATE-VDS.md"],
      "consider": [],
      "why": "установочные пути и схема state"
    },
    {
      "id": "systemd",
      "match": ["systemd/**"],
      "require": ["README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"],
      "consider": ["docs/DEPLOY.md"],
      "why": "юниты/таймеры"
    },
    {
      "id": "adr",
      "match": ["docs/adr/**"],
      "require": ["AGENTS.md", "README.md"],
      "consider": [],
      "why": "диапазон/список ADR"
    },
    {
      "id": "agents",
      "match": [".zcode/agents/**"],
      "require": ["docs/TEAM.md", "AGENTS.md", "README.md"],
      "consider": [],
      "why": "реестр ролей и моделей"
    },
    {
      "id": "version",
      "match": ["pyproject.toml"],
      "require": ["README.md", "AGENTS.md"],
      "consider": [],
      "why": "версия CLI"
    },
    {
      "id": "installers",
      "match": ["install.sh", "preinstall.sh", "local-init.sh"],
      "require": ["README.md", "docs/DEPLOY.md", "docs/SERVER-BASELINE.md"],
      "consider": [],
      "why": "путь установки/подготовки"
    }
  ],
  "reverse": {
    "commands_from": "src/main.py",
    "commands_docs": ["README.md", "AGENTS.md", "docs/VPN-PROTOCOLS.md"],
    "legacy_commands_allowlist": [
      "vds zerotier install", "vds zerotier status", "vds zerotier diagnose",
      "vds zerotier reconcile", "vds zerotier watchdog", "vds zerotier nat",
      "vds zerotier add-network", "vds zerotier cleanup",
      "vds wireguard install", "vds wireguard add-client", "vds wireguard remove",
      "vds coturn install", "vds coturn status", "vds coturn remove"
    ],
    "units_docs": ["README.md", "AGENTS.md", "docs/SERVER-BASELINE.md"],
    "generated_units_allowlist": ["vds-relay-awg.service"],
    "adr_docs": ["AGENTS.md", "README.md"],
    "agents_docs": ["docs/TEAM.md", "AGENTS.md", "README.md"],
    "version_docs": ["README.md", "AGENTS.md"],
    "links": true,
    "banned_test_counts": true
  },
  "freshness": {
    "status_days": 7,
    "living_days": 30,
    "source_lag": "warn"
  },
  "escape": {
    "trailer": "Docs: none",
    "require_reason": true,
    "require_debt_ref": true
  }
}
```

Семантика:
- `require` — **все** перечисленные документы должны быть в индексе коммита;
- `consider` — warning, если не тронуты (не блокирует);
- `match` — glob по путям (нормализация `/`, без регэкспов);
- правило срабатывает, если в коммите есть **хотя бы один** файл из `match`;
- несколько правил объединяются по union (require — тоже union);
- `match` для документации не создаёт правил: docs-only коммит разрешён;
- `legacy_commands_allowlist` — для архивных модулей, которые не обязаны быть в
  README построчно (ZeroTier/WireGuard/Coturn); список виден и аудируется.

---

## 6. Матрица триггеров (начальная, расширяется по мере дрейфа)

| Изменение | Обязательные документы | Комментарий |
|---|---|---|
| `src/main.py` | `README.md`, `AGENTS.md` | новые команды/флаги; reverse-check ловит недокументированные |
| `src/system/ufw.py` | `README.md`, `AGENTS.md`, `SERVER-BASELINE.md` | профили, ssh-перенос, lock-443 |
| `src/gateway/probing*.py` | `README.md`, `AGENTS.md`, `CENSORSHIP-PATTERNS.md`, `SERVER-BASELINE.md` | probe-watch/threat-level/ru-cidr |
| `src/relay/**` | `README.md`, `DEPLOY-RU-RELAY.md`, `AGENTS.md` | релей и ноги |
| `src/amneziawg/**` | `README.md`, `VPN-PROTOCOLS.md`, `AGENTS.md` | параметры/keepalive/клиенты |
| `src/xray/**`, `src/hysteria2/**`, `src/acme/**` | `README.md`, `VPN-PROTOCOLS.md`, `DEPLOY.md` | протоколы/TLS |
| `src/gateway/paths.py`, `store.py` | `README.md`, `SERVER-BASELINE.md`, `MIGRATE-VDS.md` | пути/схема state |
| `systemd/**` | `README.md`, `AGENTS.md`, `SERVER-BASELINE.md` | юниты/таймеры |
| `docs/adr/**` | `AGENTS.md`, `README.md` | диапазон ADR |
| `.zcode/agents/**` | `docs/TEAM.md`, `AGENTS.md`, `README.md` | роли/модели |
| `pyproject.toml` | `README.md`, `AGENTS.md` | версия |
| `install.sh`, `preinstall.sh` | `README.md`, `DEPLOY.md`, `SERVER-BASELINE.md` | установка |
| `src/gateway/init.py`, `links.py`, `health.py` | `README.md`; consider: `DEPLOY.md`, `SERVER-BASELINE.md`, `AGENTS.md` | gateway init/links/healthcheck-таймер (дреф №2 §1 шёл именно отсюда — правило обязательное) |
| `src/system/{setup,cleanup}.py`, `src/sysinfo/**` | consider: `DEPLOY.md`, `SERVER-BASELINE.md` | server-setup/cleanup/dashboard — не требуют, но напоминают |
| `tests/**`, `requirements*.txt` | — | синхронизация не требуется; счётчики запрещены |

Явное освобождение (решение, не умолчание): `src/zerotier|wireguard|coturn`
(архивные модули) — без правил триггеров; их команды покрыты
`legacy_commands_allowlist` выше.

Правило расширения: если аудит дважды поймал дрейф в одном и том же документе —
добавить путь в `match` соответствующего правила. Реестр — живой, но меняется
только через PR с ревью `vds-docs`.

---

## 7. Алгоритм проверки

### 7.1. Коммит (`check --staged`)

```text
changed = git diff --cached --name-only
if merge_in_progress or commit is merge:  exit 0   # merge/rebase — на audit
rules = [r for r in rules if any(match(changed, g) for g in r.match)]
required = union(r.require for r in rules)
missing  = required - changed
warnings = union(r.consider for r in rules) - changed
if missing and message has escape trailer with reason+debt:
    warn("Docs: none", missing, reason); exit 0
if missing:
    print missing + why + ближайшие примеры; exit 1
run quick_checks(changed_docs): links, banned counts
exit 0
```

Особенности:
- `Docs: none — refactor без изменения поверхности (TECHDEBT P19)` — единственный
  легальный обход; без причины/ссылки на долг — fail; ссылка на долг
  ВАЛИДИРУЕТСЯ: `Pxx` обязан существовать в `TECHDEBT.md` (фиктивный P99 —
  fail; ревью техлида G2);
- `git commit --no-verify` технически возможен; его ловит `pre-push`/CI, а
  `docsync debt` перечисляет такие коммиты (если они реально пропустили доки);
- docs-only коммит всегда проходит sync-проверку (но проходит `links`).

### 7.2. Push/CI (`audit --range A..B`)

1. **Sync-история:** для каждого коммита диапазона — те же правила; коммиты без
   доков и без `Docs: none` → error (страховка от `--no-verify`).
2. **Reverse-инварианты** (AST-алгоритм, проверен прототипом на HEAD c31462e:
   14 apps, 68 leaf (67 @command + 1 iwc-callback `vds gateway probe-watch`; правки ревью G2 + WP-1/2 факт):
   - собрать `<var> = typer.Typer(...)` из модуль-уровня `ast.Assign`;
   - префиксное дерево из `<parent>.add_typer(<child>, name=...)`
     (`name` по умолчанию = имя переменной, `_`→`-`); вложенность любая
     (gateway→probe-watch→ru-cidr);
   - leaf = `@<var>.command("name")` на `FunctionDef` (имя по умолчанию =
     def-имя, `_`→`-`);
   - callback-политика: корневой callback (TUI `main_menu`) — ИСКЛЮЧИТЬ;
     `invoke_without_command=True` у sub-app (например `probe-watch`) —
     считать leaf (реальная поверхность);
   - **zero-commands guard**: из main.py извлеклось 0 leaf-команд → exit 2
     (не молча-pass; защита от выноса команд в другие модули);
   - версию `pyproject.toml` читать регэкспом (Python 3.10, tomllib нет).
   Исходные проверки:
   - каждая leaf-команда из AST `src/main.py` встречается хотя бы раз в
     `commands_docs` (кроме allowlist);
   - каждый `systemd/*.tpl` упомянут в `units_docs` (кроме generated allowlist);
   - каждый `ADR-NNN`, упомянутый в живых доках, существует; диапазон
     `ADR-001…NNN` в AGENTS/README равен фактическому максимуму;
   - каждый файл `.zcode/agents/vds-*.md` есть в таблице TEAM;
   - версия `pyproject.toml` совпадает с README/AGENTS;
   - в живых доках нет hardcoded test-count (`\d+ (passed|тестов)`), кроме
     строк с `<!-- docsync:ignore -->`.
3. **Ссылки:** все относительные markdown-ссылки разрешаются (включая snapshot).
4. **Свежесть:**
   - `STATUS.md` старше 7 дней → warning; старше последнего `feat:`-коммита →
     warning (на G6 — error);
   - для каждого living-дока: `git log -1 --format=%ct -- <doc>` vs самый
     свежий mapped-источник; источник новее → warning (`source_lag`), на
     `--strict` — error.

### 7.3. CLI и контракт

```bash
python3 tools/docsync.py check --staged [--message FILE] [--json]
python3 tools/docsync.py check --range origin/main..HEAD [--json]
python3 tools/docsync.py audit [--strict] [--json]
python3 tools/docsync.py explain src/system/ufw.py     # какие доки требует путь
python3 tools/docsync.py debt [--since 30d]            # список Docs: none
```

Exit codes: `0` — ok; `1` — нарушения; `2` — ошибка конфига/инструмента/git.
Нет `origin/main` (fresh clone без fetch / офлайн) — warning+skip, не fail.
Force-push: диапазон может включать уже запушенные коммиты — повторный audit
безвреден, не fail. FileLock НЕ требуется: checker read-only.
`--json` отдаёт `{status, changed, required, missing, warnings, checks[]}` —
контракт для ИИ-агентов и будущего CI.

Пример вывода:

```text
[docsync] staged: src/system/ufw.py
[docsync] rule ufw -> requires: README.md, AGENTS.md, docs/SERVER-BASELINE.md
[docsync] missing: docs/SERVER-BASELINE.md
[docsync] hint: python3 tools/docsync.py explain src/system/ufw.py
[docsync] FAIL (1 required doc not staged)
```

---

## 8. Коммит-протокол

1. Коммит = код + тесты + mapped-доки. Хук `commit-msg` проверяет индекс.
2. Merge/rebase-коммиты пропускаются (их содержание проверяет `audit` диапазона).
3. Многошаговый WP: либо каждый шаг несёт свой doc-минимум, либо промежуточные
   коммиты идут с `Docs: none — intermediate WP-2, docs в WP-3 (<hash>)`;
   финальный коммит обязан закрыть долг.
4. Hotfix: допускается `Docs: none — hotfix, follow-up TECHDEBT Pxx`; долг
   виден в `docsync debt`, G6/G5 без его закрытия не проходит.
5. Запрещено: пустой `Docs: none` без причины, `DOCSYNC_SKIP`-переменные,
   отключение хуков «на время». Только `--no-verify` как аварийный выход,
   который ловит pre-push.

---

## 9. Интеграция в гейты (G1–G6)

| Гейт | Что добавляется | Кто |
|---|---|---|
| G1 Ready | REQ содержит «Doc impact»: какие живые доки затронет функция, какие снимки создать | аналитик |
| G2 Spec | SPEC содержит «Doc delta»: таблица `документ → изменение → WP`; ADR-решение, если меняется необратимый контракт | архитектор |
| G3 Build | DoD каждого WP: «`docsync audit` зелёный; mapped-доки обновлены или `Docs: none` с долгом» | кодер |
| G4 Verify | Тестировщик запускает `audit --strict` + проверяет содержательность diff'а доков (не только факт касания) | тестер |
| G5 Docs | `vds-docs` делает полный sync-pass: свежесть, cross-doc противоречия, ссылки, удаление устаревших утверждений | докуменатор |
| G6 Close | STATUS обновлён, `docsync audit --strict` зелёный, `docsync debt` пуст или заведён в TECHDEBT | оркестратор |

Шаблоны (`docs/team/templates/`):
- `REQ.md` — новый раздел **§ Doc impact** (до G1);
- `SPEC.md` — новый раздел **§ Doc delta** (до G2);
- `STATUS.md` — поле **«Doc audit»** (green/debt) в шапке цикла;
- `TEAM.md` §3/§4 — критерии гейтов и артефакт `DOC-REPORT` дополняются
  результатом `docsync audit`.

---

## 10. Изменения в коде и файлах

| Файл | Действие | Назначение |
|---|---|---|
| `tools/docsync.py` | создать | весь checker (stdlib: `json`, `ast`, `pathlib`, `re`, `subprocess`, `argparse`) |
| `tools/install-hooks.sh` | создать | `git config core.hooksPath .githooks`, проверка версии git |
| `docs/doc-sync.json` | создать | реестр/правила/инварианты (§5) |
| `.githooks/commit-msg` | создать | sync-проверка + escape-трейлер |
| `.githooks/pre-push` | создать | `audit --range origin/main..HEAD` |
| `tests/docs/test_docsync.py` | создать | unit/интеграционные тесты checker'а |
| `docs/team/templates/{REQ,SPEC,STATUS}.md` | изменить | Doc impact/delta/audit |
| `docs/TEAM.md` | изменить | критерии G1–G6, установка хуков, роль `vds-docs` |
| `AGENTS.md` | изменить | новый раздел «Документация — часть изменения»; commit-протокол |
| `README.md` | изменить | раздел «Разработка»: `tools/install-hooks.sh`, `docsync` |
| `.github/workflows/docs.yml` | создать (WP-5, после GR-24) | `check --range` + `audit --strict` |

**Публичный интерфейс инструмента:** команды из §7.3 и JSON-контракт. Это
dev-инструмент, не часть `vds` CLI; в `install.sh` не попадает (серверу не
нужен).

**Зависимости:** только Python stdlib + `git` в PATH. Никаких `pre-commit`,
`pyyaml`, `requests`.

**Безопасность:** инструмент не исполняет код проекта (AST-парсинг, не импорт),
не читает секреты/конфиги, не ходит в сеть; git-вызовы — списком аргументов,
без `shell=True` (конвенция AGENTS §5.2).

---

## 11. Миграция и baseline (обязательный WP-0)

До включения blocking-режима нужно привести текущее состояние к зелёному
аудиту. Это **не переписывание истории**, а синхронизация живых документов:

1. `STATUS.md`: архивировать закрытый CDN-transport, добавить циклы
   2026-11-14…16 (xhttp-split, relay, UFW, probe-response, И44, asv2).
2. `README.md`: таймеры (health/probe/relay), полный список юнитов/путей,
   ADR-011, 10 ролей, `--keepalive`, `add-transport xhttp`.
3. `AGENTS.md`: ADR-001…011, 10 ролей, `systemd/`, тесты `relay`, команды
   probe-watch/ru-cidr/lock-443/relay.
4. `VPN-PROTOCOLS.md`: §3 «план» → «фактическое состояние»; новый §2.5 AWG
   (включая И44); UFW через `harden`, не `server-setup`.
5. `CENSORSHIP-ROADMAP.md`: as-is с asv2/relay/probe; статусы фаз 5/7/8 и W1;
   порты 8443/49222/relay; убрать «499».
6. `SPLIT-TRANSPORTS.md`: шапка «код не начат» → «реализовано/G4 PASS».
7. `CENSORSHIP-PATTERNS.md`: дата обновления; при необходимости — И44.
8. `DEPLOY.md`: harden/ssh-port/probe-watch/ru-cidr в чеклисте; актуальная
   версия Xray в примере зеркала.
9. `MIGRATE-VDS.md`: probe/ru-cidr/relay-артефакты; полный список рестартов;
   повторный harden/ssh-port.
10. `GROWTH-POINTS.md`: перевести в `snapshot` (в реестре §5 уже так), добавить
    отметку даты базы; актуальные статусы GR-* живут в ROADMAP/STATUS. Если
    техлид решит иначе — оставить `living` и обновить GR-01/16/18 + счётчик тестов.
11. `TECHDEBT.md`: шапка (дата/HEAD).
12. 4 битые ссылки; `.zcode/agents/vds-agent-smith.md` «8 агентов».

Критерий WP-0: `docsync audit --strict` — 0 errors (warnings допускаются,
список согласован с техлидом).

**Режим внедрения:** 2 недели/один цикл `warn` (хуки печатают, но не блокируют)
→ техлид подтверждает → `block`. Откат: `git config --unset core.hooksPath`
(или `--no-verify` на конкретном коммите); документы и реестр остаются.

**Факт (DECISION Q8, 2026-11-20): режим `block` включён досрочно.** Критерий
«один цикл `warn`» выполнен по существу (за 4 дня — полные циклы alert-watch,
vpn-guard, P24/P25, 12+ коммитов). Pre-flight: `audit --strict` = 0; `docsync debt`
= 1 зарегистрированный долг (TECHDEBT P26); `core.hooksPath=.githooks` установлен;
контрольный staged-тест: правка `src/main.py` без доков → exit 1, с валидным
`Docs: none — … (TECHDEBT P26)` → exit 0.

---

## 12. Тест-план и критерии приёмки

### 12.1. Unit (без root/сети, temp git repo через `git init` в `tempfile` — не clone, без сети)

| Что | Проверка |
|---|---|
| Матчинг правил | glob, несколько правил, union require, нормализация путей |
| Staged | staged/не staged, docs-only, merge-коммит, файлы вне репо |
| Escape | `Docs: none` с причиной+долгом → pass; без причины/долга → fail |
| Reverse | AST-команды: undocumented → fail; allowlist → pass |
| Units/ADR/agents/version | отсутствие/фантом/несовпадение диапазона → fail |
| Links | относительные ссылки/анкоры; битая → fail |
| Freshness | подмена времени/git-лога: source новее → warn; `--strict` → fail |
| Banned counts | `843 passed` в living → fail; `<!-- docsync:ignore -->` → pass |
| JSON | стабильная схема и exit codes |
| Производительность | `check --staged` < 300 мс на репо; `audit` < 2 с |

### 12.2. Интеграционные сценарии

1. Коммит `src/system/ufw.py` без доков → **blocked** с точным списком.
2. Тот же коммит + 3 обязательных дока → **pass**.
3. Новый `systemd/vds-foo.tpl` без упоминания → `audit` **fail**.
4. Коммит только `README.md` → **pass**.
5. `Docs: none — refactor, no surface (TECHDEBT P19)` → pass + запись в `debt`.
6. `--no-verify` с кодом без доков → `pre-push` **fail**.
7. Новый ADR-012 без обновления диапазона → `audit` **fail**.
8. Новый агент без строки в TEAM → `audit` **fail**.
9. Версия в `pyproject.toml` ≠ README → **fail**.
10. WP-0-состояние репозитория → `audit --strict` **pass**.

### 12.3. AC

- **AC-1:** невозможно закоммитить изменение mapped-поверхности без
  соответствующего живого дока (кроме явного `Docs: none` с долгом).
- **AC-2:** невозможно оставить в живых доках фантомную команду/юнит/ADR/роль.
- **AC-3:** проверка работает офлайн, без root/Docker/CI и укладывается в 2 с.
- **AC-4:** обход виден: `docsync debt` перечисляет коммиты с `Docs: none`,
  которые **реально пропустили** обязательные доки (docs-only коммиты с трейлером
  в долг не попадают — считать их долгом значит терять сигнал в шуме).
- **AC-5:** WP-0 приводит текущий дрейф к нулю; G4/G5/G6 не проходят с красным
  аудитом.

---

## 13. Work packages

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | Ядро checker'а: конфиг, правила, `check --staged/--range`, escape, JSON, exit codes | `tools/docsync.py`, `docs/doc-sync.json`, `tests/docs/test_docsync.py` | — | unit зелёные; сценарии 1, 2, 4, 5 §12.2 на temp-репо (3 — WP-2, 6 — WP-4) |
| WP-2 | Reverse-инварианты: commands/units/ADR/agents/version, links, counts, freshness | `tools/docsync.py`, `tests/docs/` | WP-1 | сценарии 3,7,8,9 зелёные; `audit --json` стабилен |
| WP-3 | Baseline-синхронизация живых доков (§11) | перечень §11 | WP-2 | `audit --strict` → 0 errors; согласовано с техлидом |
| WP-4 | Хуки + процесс: `commit-msg`, `pre-push`, `install-hooks.sh`, AGENTS/TEAM/README, шаблоны, агентские определения | `.githooks/*`, `tools/install-hooks.sh`, `AGENTS.md`, `docs/TEAM.md`, `docs/team/templates/*`, `README.md`, `.zcode/agents/vds-{coder,tester}.md` | WP-1 | установка с нуля по AGENTS; warn-режим работает; сценарий 6 §12.2; кодер/тестер знают `docsync audit --json` как часть DoD-отчётов |
| WP-5 | Rollout: 2 недели warn → block; pre-push ужесточение; CI-workflow после GR-24; метрики | `.github/workflows/docs.yml` (опц.), STATUS/TECHDEBT | WP-3, WP-4 | 0 пропущенных дрейфов за цикл; откат проверен |

Границы: WP-1/2 не меняют ни один документ, кроме собственных; WP-3 не меняет
код; WP-4 не меняет поведение `vds`; WP-5 не трогает runtime.

---

## 14. Риски и меры

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| Слишком грубые правила → лишние касания доков | средняя | трение в разработке | `require` — только ключевые доки; остальное `consider`; расширять по фактам дрейфа |
| «Галочка»: файл тронут, смысл не обновлён | средняя | ложное спокойствие | G4/G5 проверяют diff по существу; правило «изменение поведения → абзац/таблица, а не пробел» |
| Обход через `--no-verify` | низкая | дрейф | pre-push + CI + `docsync debt` |
| Медленный аудит на большом репо | низкая | раздражение | staged-путь только по индексу; audit < 2 с; без pytest/сети |
| Python 3.10 (нет `tomllib`) | низкая | не запустится | JSON + stdlib |
| Конфликты в `doc-sync.json` | низкая | merge-шум | один владелец (`vds-docs`), правила мелкими блоками |
| Ложные срабатывания freshness | средняя | warnings-шум | `source_lag: warn`; strict только G4–G6 |
| Snapshot-доки правят «для зелёного» | низкая | порча истории | класс `snapshot` исключён из синхронизации; менять можно только ссылки |
| Хуки не установлены на новой машине | средняя | обход | AGENTS/README: `tools/install-hooks.sh` в setup; `pre-push`/CI ловят |
| Ребейз/аменд ломает проверку | низкая | ложный fail | merge/rebase skip; повторный прогон на итоговом диапазоне |

---

## 15. Границы изменений / non-goals

**Трогаем:** процесс разработки, dev-инструмент, шаблоны/гейты, живые доки
(в WP-3), git-хуки.

**Не трогаем:**
- runtime `vds` CLI и поведение сервера;
- исторические SPEC/REPORT/research (только ссылки);
- клиентский репозиторий `ubuntuInstaller` (отдельная SPEC);
- CI-инфраструктуру сверх одного workflow (GR-24 — отдельный цикл);
- генерацию прозы/LLM в хуках;
- docs-site, mkdocs и т.п.

---

## 16. Открытые вопросы (решения до кодинга)

| # | Вопрос | Рекомендация |
|---|---|---|
| OQ-1 | Блокировать сразу или после warn-периода? | **2 недели/1 цикл warn**, затем block (техлид подтверждает) |
| OQ-2 | Проверять каждый коммит или только push? | **каждый коммит** для mapped-путей; push — полный audit |
| OQ-3 | Разрешать `Docs: none`? | **да**, только с причиной и ссылкой на TECHDEBT; список виден в `debt` |
| OQ-4 | STATUS обновлять в каждом коммите? | **нет**: live-ops + G6; freshness 7 дней/последний `feat:` |
| OQ-5 | `GROWTH-POINTS` — living или snapshot? | **snapshot** с датой; актуальные статусы — ROADMAP/STATUS |
| OQ-6 | Генерировать блоки (команды/юниты) или проверять наличие? | **проверять наличие** в v1; генерацию вводить только при повторных расхождениях |
| OQ-7 | Где хранить реестр? | `docs/doc-sync.json` (рядом с доками, не в корне) |
| OQ-8 | Ставить ли хуки автоматически из `install.sh`? | **нет**: `install.sh` — серверный; dev-хуки — `tools/install-hooks.sh` по AGENTS |
| OQ-9 | Что делать с историческими счётчиками тестов в STATUS? | вынести в архивные секции/`docsync:ignore`, в живых доках — запретить |
| OQ-10 | Нужен ли формальный REQ? | **нет** (процесс/инструмент); при желании — оформить задним числом на G1 |

---

## 17. Трассируемость

| Требование | WP | Файлы | Тесты/AC |
|---|---|---|---|
| R-1 same-commit | WP-1, WP-4 | `tools/docsync.py`, `.githooks/commit-msg` | §12.2 сцены 1–2, AC-1 |
| R-2 симметрия | WP-2 | `tools/docsync.py` | сцены 3,7,8,9, AC-2 |
| R-3 классы | WP-1, WP-3 | `docs/doc-sync.json` | §12.1, AC-5 |
| R-4 локальность | WP-1 | `tools/docsync.py` | perf-тест, AC-3 |
| R-5 обход | WP-1 | escape-логика, `debt` | сцена 5, AC-4 |
| R-6 гейты | WP-4 | TEAM/AGENTS/шаблоны | чеклисты G1–G6 |
| R-7 обратимость | WP-4, WP-5 | hooks/install | откат проверен |

---

## Следующий шаг

→ **G2-ревью:** `vds-architect` — архитектура инструмента, правила §6, границы;
техлид — политика blocking/warn, escape-hatch, цена внедрения.
После APPROVED: WP-1…WP-2 (кодер) → WP-3 baseline (доки) → WP-4 хуки/процесс →
WP-5 block + CI.
