# Tech Debt — VDS Orchestrator

> План устранения недостатков по результатам ревизии кода.
> Дата составления: 2026-11-07, актуализировано 2026-11-16. Ветка: `main` @ `5ff2bef`.
> Пункты самодостаточны, можно брать по одному. Порядок работ — в конце.

> **Смежное:** продуктовые/архитектурные возможности (per-client auth, подписки,
> healthcheck, exporter, CI) — в [docs/GROWTH-POINTS.md](docs/GROWTH-POINTS.md).
> Здесь — только долг и дефекты существующего кода.

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

**Критерий:** `pytest -q` зелёный (полный suite); verbatim-прогон нового теста.

---

## P14. `systemd/vds-amneziawg.service.tpl` — ExecStop по iface ищет конфиг не там — ✅ ВЫПОЛНЕНО 2026-11-10

> Найдено на живой приёмке AWG (WP-6, asv1): после add/remove-client сервис
> vds-amneziawg в crash-loop — «awg0 already exists» на каждом start.

**Проблема:** `ExecStart=/usr/bin/awg-quick up {config_path}` (явный путь —
работает), но `ExecStop=/usr/bin/awg-quick down {iface}` — awg-quick down по
имени интерфейса ищет конфиг в ДЕФОЛТНОМ каталоге
`/etc/amnezia/amneziawg/<iface>.conf`, а наш лежит в `/etc/amnezia/awg0.conf`
(`paths.py::AWG_CONFIG_PATH`). ExecStop падает, интерфейс остаётся up,
следующий start — «awg0 already exists», crash-loop.

**Действия:** 1) шаблон: `ExecStop=/usr/bin/awg-quick down {config_path}`
(awg-quick down принимает путь к конфигу); 2) `amneziawg/install.py` перед
`systemctl enable+restart` — очистка stale-интерфейса: `ip link show <iface>`
существует → `ip link del <iface>` (idempotent, run_list); 3) регресс в
`tests/amneziawg/test_install.py`: шаблон содержит `down {config_path}` и
НЕ содержит `down {iface}`; happy-path выполняет ip-link-del-очистку перед
enable/restart; случай отсутствия интерфейса — без del.

**Критерий:** `pytest -q` зелёный (326); `compileall`; verbatim grep шаблона.

---

## P15. `amneziawg/install.py` — не настроена маршрутизация (ip_forward + MASQUERADE) — ✅ ВЫПОЛНЕНО 2026-11-10

> Найдено на живой asv1: handshake UDP проходит, клиентский трафик не
> выходит в интернет (handshake ok, данные — нет).

**Проблема:** WP-2 install.py ставит пакеты, генерирует ключи, пишет конфиг и
поднимает юнит vds-amneziawg, но не включает `net.ipv4.ip_forward` и не
добавляет MASQUERADE для awg0-подсети (10.9.0.0/24). awg0-интерфейс поднят,
handshake успешен, но forwarded-трафик клиентов отбрасывается.

**Действия:** 1) `amneziawg/install.py::_ensure_ip_forward` — `sysctl -w
net.ipv4.ip_forward=1` (до старта юнита) + persist
`/etc/sysctl.d/99-vds-awg-forward.conf` (`net.ipv4.ip_forward = 1`),
идемпотентно; 2) `_detect_wan_iface` — WAN по `ip route get 1.1.1.1`
(поле `dev`; отказ определения — отказ установки, угадывать нельзя);
3) `_ensure_nat_masquerade` — runtime `iptables -t nat -C POSTROUTING
-s 10.9.0.0/24 -o <wan> -j MASQUERADE` (нет → `-A`) + persist: NAT-секция
(`*nat` / `:POSTROUTING ACCEPT [0:0]` / правило / `COMMIT`) вставляется
перед `*filter` в `/etc/ufw/before.rules` (grep по строке правила;
`ufw reload` НЕ выполняется — runtime-правило уже активно, ufw перечитает
при рестарте); before.rules отсутствует → только runtime + warning;
4) пути в `gateway/paths.py`: `AWG_SYSCTL_FORWARD_CONF`,
`AWG_UFW_BEFORE_RULES`; 5) регресс в
`tests/amneziawg/test_install.py::TestRoutingSetup` — happy-path
последовательность sysctl → route-get → iptables -C → -A → restart,
persist-файлы (tmp), идемпотентность обоих persist, отсутствие before.rules,
уже существующее NAT-правило (без -A), извлечение wan_if.

**Критерий:** `pytest -q` зелёный (346+N); `compileall`; verbatim
happy-path последовательности (sysctl → nat → before.rules).

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

## P16 — before.rules-дубль MASQUERADE (SERVER-BASELINE §5.2, аудит 2026-11-16)
`amneziawg install` пишет MASQUERADE awg0 и в `/etc/ufw/before.rules`, и
ставит юнит `vds-amneziawg-nat` (стандарт персистентности). На asv2 живут
оба (дубль). Убрать запись в before.rules из install-пути (юнит достаточен,
before.rules при inactive ufw всё равно мёртв) + миграция живых серверов
(изъять секцию, сохранив юнит). Проверка: `iptables -t nat -S POSTROUTING`
— одна MASQUERADE-правилона подсеть.

## P17 — rename sshd-override 99→00 (SERVER-BASELINE §4, аудит 2026-11-16)
`ufw ssh-port` пишет `99-vds-port.conf` — для `Port` безопасно (аддитивная
директива), но override-класс (PasswordAuthentication и пр.) требует
префикса `00-` (first-match-wins против 50-cloud-init). Унифицировать
константы модуля на `00-`, с миграцией живого файла на asv2.

## P18 — relay-профиль: DNS-резолвер (аудит 2026-11-16)
Для RU-релея `8.8.8.8` из базового профиля может перехватываться/деградировать
в ЦОД РФ. В relay-профиль SERVER-BASELINE добавить резолвер: локальный
DC-резолвер или DoH (cloudflared), не Google-UDP напрямую.

## P19 — `CursorStore.save`: read-modify-write без `threading.Lock` (P2, 2026-11-17)

**Факт.** Два reader-потока (`journal:user`/`journal:system`) пишут
`guard/cursor.json`. После HF `78ce00c` запись атомарна (уникальный
`mkstemp` + `os.replace`), файл не бьётся и `ENOENT` исключён. Но
read→modify→replace не сериализован: при совпадении микросекунды курсор
одного источника может «откатиться» на предыдущее значение; следующий
`persist` (PERSIST_EVERY_N/`PERSIST_EVERY_S`) его восстановит, кольцо
`recent` защищает от дублей.

**Действие (v1.1, не блокер v1):** обернуть `save()` в общий
`threading.Lock` (или один writer-поток) и добавить тест на lost-update.
**Критерий:** 4 потока × 100 save → итоговый `cursor.json` содержит
последний курсор каждого источника, без потерянных обновлений.

## P20 — `vds relay remove-client` отсутствует (2026-11-17)

**Факт.** У AWG-сервера релея есть только `vds relay add-client`; удалить пир
можно лишь правкой `/etc/amnezia/awg0.conf` + `systemctl restart
vds-relay-awg` (так удалён тестовый `smoke-asv2` при раскатке LandVPS).
Для gateway-профиля аналогичная команда есть (`vds amneziawg remove-client`).

**Действие.** Добавить `vds relay remove-client NAME [--apply]` по образцу
`src/amneziawg/clients.py::remove_client`: убрать `[Peer]`-блок по
`AllowedIPs` пира, атомарная запись 0600, restart юнита, `--dry-run` по
умолчанию, запись в state-метаданные клиентов.

**Критерий.** Пиры: добавить → удалить → в конфиге и в `awg show awg0` нет
пира, остальные не тронуты; повторный `remove` идемпотентен.

## P21 — `unparsed_ratio`: стартовый баннер Xray засчитывается как app-строка (2026-11-17)

**Факт.** AC-5 меряет `unparsed / app_lines`. Старт каждого Xray-профиля
пишет 3 строки, которые не несут телеметрии:
`Xray <ver> (Xray, Penetrates Everything.)`, `A unified platform for
anti-censorship.`, `[Info] infra/conf/serial: Reading config: &{...}`.
На ноутбуке за 24 ч: `app_lines=16`, из них 12 — баннеры → `unparsed_ratio=0.75`
при полностью рабочем парсере (T0.5 в
`docs/team/reports/TEST-20261117-vpn-guard-checkpoint-t0.md`).

**Действие (v1.1).** Классифицировать баннеры как `ignored_infra`
(исключать из `app_lines`), по аналогии с awg-quick/dnsmasq-шумом.
Спека AC-5 при этом не меняется — меняется только учёт.

**Критерий.** Реплей 24-часового журнала с 12 баннерными строками даёт
`unparsed_ratio <= 0.05` без реальных непарсенных событий; тест на
`ParseStats`.

## P22 — `vds relay add-client`: endpoint из неразрешимого `state.domain` (2026-11-17) — ✅ ВЫПОЛНЕНО 2026-11-17

> Закрыто: `--endpoint HOST[:PORT]` + `choose_endpoint()` — override →
> `state.domain` (имя самой машины пропускается) → канонический домен →
> публичный src-IP сервера (`ip route get`); нет фолбэка → отказ с
> подсказкой `--endpoint`. Важно: проверка резолва идёт с сервера, а
> внутреннее имя хостера там резолвится, поэтому отсекается именно по
> совпадению с hostname/FQDN.
> Тесты: `tests/relay/test_clients.py::TestChooseEndpoint` (+2 сквозных на
> `add_client`); доки — README, AGENTS, DEPLOY-RU-RELAY §9.
> Живая проверка 2026-11-17: после фикса DNS `relay.asvpersonal.ru` клиент
> `laptop` собирается на домене.

**Факт.** Клиентский `.conf` получает `Endpoint = {state.domain}:443`
(`src/relay/clients.py`: `domain or 'relay.asvpersonal.ru'`). На LandVPS
`state.domain = 354051.landvps.online` — внутреннее имя панели, которого
нет в публичном DNS (проверено 1.1.1.1 и 8.8.8.8). `relay.asvpersonal.ru`
тоже ещё не создан. Итог живой приёмки 2026-11-17: `vpn start relay`
падает на `awg-quick: Name or service not known`, хотя сервер и ключи
исправны — чинилось ручной заменой endpoint на IP.

**Действие.** `vds relay add-client --endpoint HOST[:PORT]` (явный
override) + предупреждение, если `state.domain` не резолвится (или
резолвится в приватный адрес); в ранбуке §9 — «до создания
`relay.asvpersonal.ru` endpoint = IP релея».

**Критерий.** `add-client` без override при неразрешимом домене печатает
warning и пишет IP-фолбэк (или отказывает с подсказкой `--endpoint`);
`add-client --endpoint relay.asvpersonal.ru:443` пишет ровно заданное;
юнит-тест на выбор endpoint; `vpn start relay` с таким conf поднимается
без ручной правки.

## P23 — `vds relay add-client`: нет `DNS =` и нет выпуска QR (2026-11-17) — ✅ ВЫПОЛНЕНО 2026-11-17

> Закрыто: `DNS = 1.1.1.1, 1.0.0.1` пишется всегда (`--dns` для
> переопределения, принимаются только IP-литералы), `AllowedIPs` только
> `0.0.0.0/0` (без `::/0`), `--qr` печатает ANSIUTF8-QR через stdin
> (`qrencode`; без него — warning, без падения). Тесты —
> `tests/relay/test_clients.py` (DNS default/override/отказ, AllowedIPs, QR
> без qrencode и через stdin); доки — README, AGENTS, DEPLOY-RU-RELAY §9.

**Факт.** Клиентский conf не содержит `DNS =`, а `AllowedIPs` пишется как
`0.0.0.0/0,::/0`. На Android/Windows при полном туннеле это даёт «подключено,
но интернет мёртв» (DNS уходит на локальный роутер в туннель; резолвера на
10.10.0.1 нет) и IPv6-чёрную дыру (нога awg1 v4-only, ENETUNREACH). QR для
телефона приходится делать вручную (`vpn amneziawg qr` на ноутбуке или
`qrencode`), а для этого конфиг надо сначала перенести в `~/.awg/`.

**Действие.** В `add_client` (src/relay/clients.py): писать `DNS = 1.1.1.1`
(или `--dns X[,Y]`, `--no-dns`) и `AllowedIPs = 0.0.0.0/0` без `::/0`
(или `--ipv6` для opt-in). Дополнительно `--qr`: рендер PNG рядом с `.conf`
через `qrencode` (если установлен), в stdout — только путь; секреты не
печатать.

**Критерий.** Свежий conf содержит `DNS = 1.1.1.1` и `AllowedIPs = 0.0.0.0/0`;
`--qr` создаёт `<name>-qr.png` (0600) и печатает путь; тесты на рендер conf и
на отказ без `qrencode`; docs/DEPLOY-RU-RELAY §9 упрощается до двух команд.

## P24 — изоляция межузлового порта exit-узла (2026-11-17) — ✅ ВЫПОЛНЕНО 2026-11-20

**Факт.** На exit-узле (asv2) `51825/udp` — это **основной AWG-порт клиентов**
(mobile/win-пиры) и одновременно нога релея (`RELAY_EXIT_PORT = 51825`). Прямой
`ufw allow from <IP релея> to any port 51825 proto udp` с удалением общего правила
порвёт мобильные/Windows-пиры. Отсюда FR-8 REQ-20261117-alert-watch в цикл не
взят и вынесен (`docs/team/specs/SPEC-20261117-alert-watch.md` §9.4).

**Действие.** Собрать факт с живого asv2 (`ss -ulnp`, `ufw status numbered`,
`awg show`), затем выбрать: отдельный `awg2`/порт для ноги релея (предпочтительно),
либо nft-фильтр по src на общем порту. Новый межузловой порт — через ADR
(меняется схема relay↔exit).

**Критерий.** Клиентские пиры сохраняют handshake; нога релея жива на изолированном
порту; внешний скан с произвольного IP не получает ни ответа, ни ICMP.

**Выкат 2026-11-20 (PASS).** `awg2` на exit, пул 51900-51911 через nft REDIRECT
(`saddr` релея), MASQUERADE `10.11.0.0/30`, `ALERT_RELAY_IFACE=awg2`; внешний скан
пула молчит, клиентский `awg0` не тронут; нога проверена через `:51901`.
Приёмка: `docs/team/reports/ACCEPT-20261120-p24-exit-leg.md`. Старый пир на `awg0`
оставлен на 24 ч как страховка откатa.

**WP-M0 (2026-11-20, факты).** Exit: единственный `awg0` слушает `51825/udp` (v4+v6),
UFW `ALLOW Anywhere`, `awg2` нет — блокер подтверждён. Relay: `awg1` →
`213.108.23.119:51825`, `Table = off`, **`PersistentKeepalive` не задан**. IPv6-нога
жива: `ping -6` relay→exit 47 мс, TCP6/443 OPEN (вариант fallback без новых портов).
Отчёт: `docs/team/reports/TEST-20261120-relay-leg-diag.md`.

## P25 — автоматический манёвр порта/протокола на плече relay↔exit (2026-11-17) — ✅ ВЫПОЛНЕНО 2026-11-20

**Факт.** При блокировке UDP-потока `релей → exit:51825` канал умирает, и сейчас
восстановление ручное. `vds relay status --json` уже отдаёт `exit_handshake_age_sec`,
но порог «подозрительно» в `src/relay/status.py` — 6 ч, автоматики нет. FR-9
REQ-20261117-alert-watch в цикл не взят (риск обрыва канала; вероятно нужен ADR —
смена порта/`H1..H4`/TCP-fallback меняет межузловую схему).

**Действие.** Отдельный REQ: триггер «handshake мёртв > 3 мин при живом релее» →
смена порта ноги / `H1..H4` / fallback на TCP-Reality до exit; защита от пинг-понга
(не более одной попытки в N минут, откат по таймауту, журнал попыток); клиенты не
перенастраиваются.

**Критерий.** Имитация блокировки UDP на стенде → канал восстанавливается < 60 с;
клиентский handshake не рвётся дольше T секунд; после снятия блокировки состояние
стабилизируется.

**Выкат 2026-11-20 (PASS, M3+M4+M5).** Ядро `src/relay/maneuver.py` + opt-in
таймер `vds-relay-maneuver.{service,timer}` (auto=off, интервал 60s) на релее;
живой тест: runtime-drop `ct original proto-dst 51900` на asv2 → 3/3 + activity →
манёвр 51900→51901 за ~7 с после 3/3 (< 60 с), персист Endpoint + бэкап 0600,
rollback вернул 51900. Находки: (1) blunt drop в input режет и REDIRECT'нутые
пакеты — блок порта имитировать `ct original proto-dst`; (2) при мёртвом
handshake `awg1.tx` замерзает (data не шифруется) — gate живёт на клиентском
`awg0` (unit-тесты; live-валидация ветки awg0 — первый эпизод с клиентом).
Noise-замер: 92 Б/60 с ≪ 4096. Приёмка: `docs/team/reports/ACCEPT-20261120-p25-maneuver.md`.
Критерий P25 «<60 с» — ВЫПОЛНЕН (реакция после 3/3 ≈ 7 с). Остатки: ребут-тест в
окно ТО; `--enable-auto` — по решению владельца после первого живого эпизода.

**WP-M0 (2026-11-20): триггер P25 невалиден — PIVOT.** Handshake-возраст не равен
недоступности: наблюдался «blocked» с `latest handshake` 5 ч 11 мин, при этом
`ping -I awg1 10.9.0.1` — 2/2 и `curl --interface awg1` — HTTP 200; под трафиком
handshake обновляется каждые ~120 с, keepalive 25 с инициирует его за ~30 с.
⇒ автомат на `handshake_age` менял бы порт на работающем канале. Триггер перевести
на data-plane liveness (ICMP/TCP **внутри** туннеля + отсутствие прироста rx);
`PersistentKeepalive=25` на `awg1` — базовый кандидат-митигация. Длительности
эпизодов после cooldown-коррекции: 35 эпизодов, медиана **7 мин** (было 32 мин —
артефакт 30-мин cooldown'а alert-watch), макс 306 мин. Отчёт:
`docs/team/reports/TEST-20261120-relay-leg-diag.md`.

## P26 — внешний вид текста уведомлений alert-watch вне документации (2026-11-18, открыт)

**Факт.** `format_message` (`src/alert/watch.py`) задаёт шапку с эмодзи-статусом,
линию-разделитель фиксированной ширины и подписи полей. В SPEC-20261117-alert-watch
описан контракт `(subject, body)` и смысл полей, но не внешний вид текста; владелец
меняет оформление по вкусу (капс, ширина линии, порядок полей), поэтому держать его
в доках значило бы гонять доки за косметикой.

**Действие.** Если формат станет контрактом (шаблон для внешних получателей или
парсинг сообщений), описать его в SPEC и закрепить тест-эталон. До тех пор правки
текста идут через `Docs: none` со ссылкой на эту запись.

**Критерий.** Формат описан в SPEC либо явно признан внутренним (эта запись).

## P27 — D4: `file_parse_error` без TTL и без атрибуции к файлу (2026-11-20, открыт)

**Факт.** В клиентском guard ошибка парсинга файла подавляет правило, но не имеет
TTL и не указывает, какой именно файл её вызвал (всплыло в
TEST-20261119-vpn-guard-t33: `file_parse_error` держится в `sources`/подавлении
дольше, чем живёт причина). Один битый файл может скрывать finding неограниченно,
а фикс не адресный.

**Действие (v1.1, WP V11-4).** Добавить TTL подавления (например, 3 окна) и
поле-атрибут в `sources` и finding — **только basename/относительное имя**
(`last-speed.json`), без `/home/<user>/…` (privacy ADR-014 §7); при истечении
TTL — снимать подавление и пере-парсить. Схема `guard.status/1` не меняется —
расширение `sources`/`finding` аддитивно, lock схем обновляется по D-17.

**Критерий.** На синтетическом битом файле: finding скрыт ≤ TTL, затем правило
снова эмитит; в выводе виден путь файла; после починки файла подавление
исчезает сразу.

## P28 — hysteria2 deploy-hook без фильтра $RENEWED_DOMAINS (2026-11-20, открыт)

**Статус (2026-11-20/21):** код закрыт — фильтр в `render_deploy_hook`
(`src/acme/install.py`) + тесты пробельного матча и sh-семантики +
mapped-доки (README/VPN-PROTOCOLS/DEPLOY)
в коммите этого цикла. Осталось: регенерировать hook на exit-узле в утреннем
окне 2026-11-21 (идемпотентный путь — `vds acme issue` того же домена) вместе
с Хвостом 1 (P24), после чего запись закрывается.

**Факт.** `/etc/letsencrypt/renewal-hooks/deploy/vds-hysteria2-cert.sh`
(`src/acme/install.py`) копирует сертификат и рестартует `vds-hysteria2`
на **любое** продление. После добавления второго сертификата `ws.<domain>`
(ADR-016, WP-P2P-4) каждое его продление (~60 дней) будет лишний раз
рестартовать hysteria2 (безвредно, но неожиданно), а hook wstunnel при
продлении основного домена — нет (у него фильтр есть).

**Действие.** Однострочный фильтр в начало hysteria-hook:
`case " $RENEWED_DOMAINS " in *" $DOMAIN "*) ;; *) exit 0 ;; esac`
(домены certbot передаёт через пробел).

**Критерий.** Продление ws.<domain> не рестартует hysteria; продление
основного домена работает как раньше.
