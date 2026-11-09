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

## P7. `install.sh:74` — `cp` падает при `SCRIPT_DIR == INSTALL_DIR` — ~20 мин — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09): guard на обе геометрии (realpath),
> копирование через `find` (скрытые файлы переносятся, `venv/` и `.git` исключены),
> опциональная установка `requirements-dev.txt` в install.sh. Живая приёмка трёх
> сценариев на чистой системе — за vds-owner при следующем развёртывании.
> Найдено при развёртывании на живой VDS `asv1` (2026-11-09), см.
> [ORCH-20261109-vds-deploy-install](docs/team/reports/ORCH-20261109-vds-deploy-install.md §4).
> Прогон скомпенсирован ручной доустановкой, сервер рабочий.

**Проблема:** `install.sh:74` — `cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/"` под
`set -e`. При запуске скрипта из каталога, куда файлы уже развёрнуты
(`SCRIPT_DIR == INSTALL_DIR`, наш сценарий rsync), `cp` возвращает
`cp: 'X' and 'X' are the same file` → `set -e` убивает скрипт **после** apt-шага
(частично выполненная установка). Второй сценарий падения: `INSTALL_DIR` —
подкаталог `SCRIPT_DIR` → GNU `cp -r` отказывается «copy a directory into
itself» с тем же эффектом. Побочно: glob `"${SCRIPT_DIR}/"*` не переносит
скрытые файлы (`.gitignore` и пр.) и тащит существующий `venv/`, если он есть
в `SCRIPT_DIR`.

**Действия:**
1. Guard на обе геометрии перед `cp` (реализация — за кодером):
   `[[ "$(realpath "${SCRIPT_DIR}")" == "$(realpath "${INSTALL_DIR}")" || "$(realpath "${INSTALL_DIR}")" == "$(realpath "${SCRIPT_DIR}")"/* ]]` → пропустить копирование с `log`, иначе `cp`.
2. (Опционально) исключить `venv` из копирования; скрытые файлы — осознанное решение (сейчас `.git` не копируется — оставить так).
3. Ручная приёмка на VDS по трём сценариям: (a) `SCRIPT_DIR == INSTALL_DIR` — пропуск cp, установка доходит до шага 6; (b) `INSTALL_DIR` внутри `SCRIPT_DIR` — то же; (c) обычный запуск из клона — файлы скопированы.

**Критерий:** `bash install.sh` проходит end-to-end во всех трёх сценариях на
чистой системе; повторный запуск из установленного каталога — идемпотентен.

---

## P8. `xray/install.py` — парсер `.dgst` не знал метку `SHA2-256=` — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`:
> установка Xray падала с «SHA256 не найден в .dgst-ассете release».

**Проблема:** `_sha256_from_dgst()` сравнивал метку только с `SHA256`, а апстрим
(Xray-core v25.1.1) в `.dgst`-ассетах метит SHA256 как `SHA2-256=` — парсер
никогда не работал с реальными ассетами этого формата.

**Действия:** 1) парсер принимает и `SHA256=`, и `SHA2-256=` (регистр/пробелы
нормализуются; MD5/SHA1 по-прежнему игнорируются); 2) юнит-тесты
(`tests/xray/test_install.py::TestSha256FromDgst`) — upstream-формат, legacy-формат,
отсутствие SHA256 → InstallError.

**Критерий:** `pytest tests/xray/` зелёный; вербатим-прогон на реальном
содержимом `Xray-linux-64.zip.dgst` v25.1.1 возвращает SHA256 релиза.

---

## P9. `hysteria2/install.py` — openssl pkeyopt alias `ec_param_gen_curve:prime256v1` отвергается OpenSSL 3.x — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`
> (Ubuntu 24.04.5, OpenSSL 3.0.13): установка Hysteria2 падала на генерации
> self-signed сертификата.

**Проблема:** `_ensure_certificate()` вызывала `openssl req -newkey ec -pkeyopt
ec_param_gen_curve:prime256v1`. OpenSSL 3.0.13 отвергает этот alias
(`digital envelope routines … name=ec_param_gen_curve, value=prime256v1 …
command not supported`) — установка падала с InstallError.

**Действия:** 1) pkeyopt заменён на каноничную форму
`ec_paramgen_curve:P-256` (проверена на целевом сервере, exit=0);
2) регрессионный тест в `tests/hysteria2/test_install.py::TestFullInstall` —
аргументы содержат `ec_paramgen_curve:P-256` и не содержат `ec_param_gen_curve`.

**Критерий:** `pytest tests/hysteria2/` зелёный; вербатим: список аргументов
команды генерации содержит `ec_paramgen_curve:P-256`.

---

## P10. `systemd/vds-hysteria2.service.tpl` — ExecStart без subcommand `server` — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`:
> юнит crash-loop'ился с FATAL «failed to parse client config» в client mode;
> ручной запуск `hysteria server -c /etc/hysteria/config.yaml` — «server up
> and running».

**Проблема:** `ExecStart={bin_path} -c {config_path}` — hysteria v2 без
subcommand стартует в client mode (Xray-шаблон корректен: `run -config`).

**Действия:** 1) ExecStart заменён на `{bin_path} server -c {config_path}`;
2) регрессионные тесты `tests/hysteria2/test_install.py::TestUnitTemplate` —
рендер шаблона содержит `server -c`, ctx из `_install_locked` рендерится
без KeyError.

**Критерий:** `pytest tests/hysteria2/` зелёный; вербатим: рендер содержит
`ExecStart=<bin> server -c <config>`.

---

## P11. `run_install` обоих протоколов — port-чек раньше проверки «уже установлен» — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`:
> повторный `vds xray install` при активном сервисе (сам владеет 443)
> отвечал «Порт 443/tcp занят (владелец: xray)» вместо «уже установлен».

**Проблема:** в `src/xray/install.py` и `src/hysteria2/install.py` проверка
`port_free` шла ДО `_installed()` — ломала идемпотентность (AC E4) и
блокировала восстановление state.

**Действия:** 1) в обоих `run_install` проверка `_installed()` перенесена
выше port-чека (у xray — та же единая функция `_installed()`, логика не
дублируется); 2) поведение «не установлен + порт занят» сохранено (ошибка
порта); 3) регрессионные тесты `test_already_installed_wins_over_busy_port`
в обоих test_install.py: установлен + порт занят → exit 0 и port_free/
port_owner не вызываются.

**Критерий:** `pytest tests/xray/ tests/hysteria2/` зелёный; вербатим-прогон:
при занятом порте и установленном сервисе run_install возвращает 0.

---

## P12. `xray/install.py::_installed()` — сверка версии падала на реальном формате вывода — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`:
> `_installed()` всегда False на установленном Xray — идемпотентность P11
> не срабатывала, повторный install падал на port-чеке.

**Проблема:** `_installed()` сравнивал `XRAY_VERSION in result.stdout`, где
`XRAY_VERSION = "v25.1.1"` (тег release), а реальный вывод
`/usr/local/bin/xray version` — «Xray 25.1.1 ...» без ведущего «v».
В юнит-тестах проходило, потому что мок возвращал точный пин с «v».

**Действия:** 1) сравнение без учёта ведущего «v» —
`XRAY_VERSION.lstrip("v") in result.stdout` (покрывает и «Xray 25.1.1», и
гипотетический полный пин); 2) регрессионные тесты
`tests/xray/test_install.py::TestInstalledVersionFormat` — реальный формат
вывода → True, полный пин → True, другая версия («Xray 24.9.30») → False.
Аналог в `hysteria2/install.py::_installed()` НЕ тронут: там сверка по
`_VERSIONplain = "v2.13.0"`, и живой вывод `hysteria version` содержит
«app/v2.13.0» — совпадает (подтверждено на asv1).

**Критерий:** `pytest tests/xray/` зелёный; вербатим-прогон `_installed()`
на реальном формате вывода («Xray 25.1.1 (Xray, Penetrates Everything.)
e80ca67 (go1.23.4 linux/amd64)») → True.

---

## P13. `xray/install.py::add_transport_xhttp` — state-meta без `installed: True` после remove→re-add — ✅ ВЫПОЛНЕНО 2026-11-09

> Закрыто WP-микро (vds-coder, 2026-11-09). Найдено на живой приёмке `asv1`:
> после `xray remove-transport --apply` → `xray add-transport --mode port
> --apply` живой транспорт показывался в `vds gateway status` как
> «xhttp: not installed». На сервере исправлено ops-фиксом; ниже — кодовый.

**Проблема:** `remove_transport_xhttp` вычищает весь ключ
`protocols.pop("xhttp", None)`, а `add_transport_xhttp` при записи meta
(`state.protocols["xhttp"] = {...}`) выставлял только port/mode/domain/extra —
без `"installed": True`. `main.py::gateway status` читает
`meta.get("installed", False)` → ложное «not installed» при живом транспорте.
Первый add_transport перед remove не ловил дефект, потому что… расхождение
проявилось только после re-add: любой последующий add перезаписывал ключ
без флага.

**Действия:** 1) `add_transport_xhttp` пишет `"installed": True` в meta
(вслед за `protocols["xray"]` из `_save_state_meta`); 2) регрессионный тест
`tests/xray/test_links_xhttp.py::TestRemoveTransportXHTTP::
test_re_add_after_remove_writes_installed_true` — remove → add →
`state.protocols["xhttp"]["installed"] is True`; существующий
`test_apply_writes_fallbacks_and_state` обновлён на новый точный состав meta.

**Критерий:** `pytest -q` зелёный (226 тестов); verbatim-прогон нового теста.

---

## Порядок работ

| Этап | Пункты | Суммарно | Почему сначала |
|------|--------|----------|----------------|
| ~~0~~ | ~~P7~~ ✅ | — | Выполнено 2026-11-09 (см. §P7); живая приёмка end-to-end — при следующем [VDS]-цикле |
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
