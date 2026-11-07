# Tech Debt — VDS Orchestrator

> План устранения недостатков по результатам ревизии кода.
> Дата составления: 2026-11-07. Ветка: `main` @ `bfc9362`.
> Пункты самодостаточны, можно брать по одному. Порядок работ — в конце.

---

## P1. Устранить дублирование `load_env()` — ~15 мин — ✅ ВЫПОЛНЕНО 2026-11-07

> Закрыто в MVP gateway (WP-1), см. [SPEC-20261107-gateway-mvp](docs/team/specs/SPEC-20261107-gateway-mvp.md).
> `load_env(path)` — единственная, в `src/core/shell.py`; zerotier-модули импортируют общий.

**Проблема:** идентичные функции в `src/zerotier/reconcile.py:58` и `src/zerotier/nat.py:12`. Правка в одной копии не попадает в другую.

**Действия:**
1. Вынести `load_env()` в `src/core/shell.py` (или создать `src/core/env.py`), параметризовав путь: `load_env(path: str) -> dict[str, str]`.
2. В обоих модулях оставить только `ENV_FILE` и импортировать общий `load_env`.
3. Проверить, что `watchdog.py` импортирует `load_env` из `nat.py` (`watchdog.py:11`) — перенаправить импорт на новый модуль.

**Критерий:** `grep -rn "def load_env" src/` находит одну функцию.

---

## P2. Синхронизировать версии зависимостей — ~15 мин — ✅ ВЫПОЛНЕНО 2026-11-07

> Закрыто в MVP gateway (WP-1), см. [SPEC-20261107-gateway-mvp](docs/team/specs/SPEC-20261107-gateway-mvp.md).
> За истину — `requirements.txt`; pyproject выровнен (проверено статически в
> TEST-20261107 §1; прогон в чистом venv — опционально).

**Проблема:** два источника истины. `pyproject.toml` — диапазоны (`typer>=0.9.0`), `requirements.txt` — пины (`typer>=0.12.0`, `requests==2.31.0`). История коммитов (86f0419) показывает, что typer-версия уже стреляла.

**Действия:**
1. За истину принять `requirements.txt` (его читает install.sh); в pyproject выровнять нижние границы (typer `>=0.12.0`, pydantic `>=2.5.2`, rich `>=13.7.0`).
2. Либо — пины только в `requirements.txt`, pyproject оставить только метаданные; в README указать, что install.sh ставит по requirements.txt.
3. Убрать противоречие: одно место, где задаются версии.

**Критерий:** `pip install -e .` и `pip install -r requirements.txt` дают одинаковое окружение.

---

## P3. Безопасный `docker_exec` — ~30–60 мин — ✅ ВЫПОЛНЕНО 2026-11-07

> Закрыто в MVP gateway (WP-1), см. [SPEC-20261107-gateway-mvp](docs/team/specs/SPEC-20261107-gateway-mvp.md).
> `docker_exec(container, cmd: str|list)` — строка через `shlex.split`, все вызовы в `src/` — списки.

**Проблема:** `core/shell.py:86` — `command.split()` по пробелам. Аргументы с кавычками/пробелами сломаются. Обходной путь через `run()` со shell-строкой делает код разнородным.

**Действия:**
1. Сигнатура: `docker_exec(container: str, command: str | list[str], ...)` — строку парсить через `shlex.split()`, список передавать как есть.
2. Перевести вызовы с аргументами в `zerotier/` (api.py, watchdog.py, install.py, diagnose.py) на список.
3. Smoke-тест на реальном контейнере: `docker_exec(CONTAINER, "zerotier-cli info")` и `docker_exec(CONTAINER, ["zerotier-cli", "-j", "listnetworks"])`.

**Критерий:** все вызовы `docker_exec` в `src/` передают список аргументов; shell-строки остаются только в `run()`.

---

## P4. Смягчить `kill_port_thief` — ~30 мин

**Проблема:** `zerotier/watchdog.py:71–88` — `kill -9` любому процессу на порту 9993, кроме контейнера. Может убить легитимный сервис.

**Действия:**
1. Эскалация: `kill -TERM` → пауза 5с → `kill -KILL` только если процесс ещё жив.
2. Белый список имён процессов (например, только `zerotier-one`); чужой `comm` на 9993 — логировать `[warning]`, не убивать.
3. Задокументировать поведение в README-разделе про watchdog.

**Критерий:** watchdog не способен убить процесс, чьё `comm` не входит в белый список; в логе — читаемое предупреждение.

---

## P5. Почистить репозиторий — ~10 мин

**Проблема:** в корне закоммичен `__pycache__/zt-reconcile.cpython-310.pyc`; `.kilo/`, `.v2c/` — служебные каталоги без оговорки.

**Действия:**
1. `git rm -r --cached __pycache__`; дополнить `.gitignore` (корневой `__pycache__/`, `*.pyc`).
2. `.kilo/` и `.v2c/` — либо в `.gitignore` + `git rm --cached`, либо оставить с комментарием.
3. `local-init.sh` помечен устаревшим в README — добавить в шапку файла `# DEPRECATED: используйте scripts/8_vds-server.sh` (или удалить).

**Критерий:** `git status` чистый после регенерации `__pycache__`; в репо нет бинарных артефактов.

---

## P6. Юнит-тесты на reconcile-логику — ~2–4 ч (самое ценное)

**Проблема:** логика сравнения desired/actual (`reconcile()`, `validate_topology()`) и state-механика watchdog (`count_recent_restarts`, rate-limit) — чистые функции без покрытия. Регрессия = молчаливая порча production-сетей.

**Действия:**
1. Добавить `pytest` в dev-зависимости (`pyproject.toml: [project.optional-dependencies] dev`).
2. Тесты без сети и docker (мокается `ZeroTierAPI` и `docker_exec`):
   - `validate_topology`: exit-node без 0.0.0.0/0, несколько exit-node, неавторизованные участники, пустые networks;
   - `reconcile()` dry-run: авторизация/деавторизация, расхождение IP, имена, orphan-участники (не удаляются), `zt_addr` не удаляется;
   - `load_topology`/`save_topology`: roundtrip с alias `_meta`, битый JSON, права 0600;
   - watchdog: `count_recent_restarts` / `record_restart` — ротация записей старше часа, лимит 3.
3. Структура: `tests/` рядом с `src/`, запуск `python -m pytest tests/`.
4. (Опционально, отдельно) GitHub Actions: ruff + pytest на Python 3.10/3.12.

**Критерий:** `pytest` зелёный; логика reconcile покрыта на уровне «можно менять reconcile.py без страха».

---

## Порядок работ

| Этап | Пункты | Суммарно | Почему сначала |
|------|--------|----------|----------------|
| 1 | P5, P1, P2 | ~40 мин | Мелочь, снижает шум; P1 — prerequisite для чистых импортов в P3 |
| 2 | P3, P4 | ~1.5 ч | Укрепляют runtime-поведение, затрагивают код, который потом тестируем |
| 3 | P6 | 2–4 ч | Тесты пишем на уже приведённый в порядок код |

**Сознательно не делаем:**
- CI (P6.4) — оставить на потом, пока нет `tests/`.
- Миграция на библиотеку типа `plumbum` — текущей обёртки достаточно.

**Примечания:**
- Пункты 1–5 — атомарные коммиты (`fix:`/`refactor:`), пункт 6 — отдельный `feat(tests):`.
- P3 и P4 проверять на реальной машине с ZTNET — локально эти пути не воспроизвести без контейнера.
- Тесты P6 не требуют root и запускаются локально.
