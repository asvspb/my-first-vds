# DECISIONS-vpn-guard — зафиксированные решения архитектора

> **Тип:** реестр решений (snapshot), дополняет SPEC/ADR, не заменяет их.
> **Дата:** 2026-11-16. **Ревьюер:** главный архитектор (Gemini Argon).
> **Основание:** ревью `b0297d8` (WP-G3), `a7e7a8f` (G2-фиксы), `b097e4e` (docsync).
> **Статус:** accepted; используется как вход для WP-G4/WP-G5.
> **Связанные:** [SPEC-20261116-vpn-guard](../specs/SPEC-20261116-vpn-guard.md),
> [ADR-014](../../adr/ADR-014-vpn-guard.md), [BRIEF-20261116-vpn-guard](BRIEF-20261116-vpn-guard.md).

---

## D-01. Per-rule гистерезис

`SINGLE_EVIDENCE_RULES = {G-02…G-07}` получают `confirm_windows=1`: их порог
по SPEC сам является подтверждением (3 reset / 3 cycle / 2 idle / 3 auth_fail /
2 DNS / одиночный `network_unreachable`). Absence-правила G-01/G-08 остаются
на `confirm_windows=2`.

## D-02. G-02 уступает G-03

Обрывы, укладывающиеся в ≤5 с после успешного handshake, — это G-03
(`post_handshake_drop`), а не G-02 (`reset_storm`). В окне срабатывает ровно
один finding.

## D-03. G-01 не подавляется по `state.active`

«Команда `vpn up/switch` ≤60 с» реализуется как атрибуция `lifecycle.cause`,
а не подавление через `active=null` (иначе ослепляется главный сценарий AC-14).
Подавляются только штатный stop/exit-0 и `network_unreachable`.

## D-04. G-05 branch A — обратное окно

«Нет `auth_ok` за последние 5 минут» — это обратное окно 300 с (быстрое
срабатывание AC-3), а не ожидание 5 минут. Более поздний `auth_ok` снимает
правило.

## D-05. G-06 имена и `suspend_grace_s`

Имена DNS-запросов не персистятся (R-3): «≥2 разных имени» считается по
`endpoint.host` / `template`-хэшу. `suspend_grace_s=300` — стоп-фактор G-04,
читается из `guard.json.thresholds`.

## D-06. Единый монотонный домен для S3 и server verdict

**Проблема:** journald отдаёт `__MONOTONIC_TIMESTAMP` (µs от загрузки), а файлы
S3 (`state.json`, `activity.json`, `last-speed.json`, `server-verdict.json`)
хранят только wall-clock. Пересчёт wall→mono ломается при NTP-скачке/suspend.

**Решение:**

1. `mono_us` для **всех** S3-событий ставится в момент обнаружения изменения
   `FileWatcher` из единого `clock.now_us()` (в демоне — `window.mono_us()`).
2. Wall-clock из содержимого (`fetched_at`, `ts`) используется **только** для
   проверки свежести относительно `datetime.now(timezone.utc)` при чтении
   (`age_s <= 3900` для 65-минутной свежести verdict).
3. В `RuleEngine` передаётся уже `ServerContext(fresh: bool, age_s: int, …)`.
   `WindowStore`/`RuleEngine` живут исключительно в `clock.now_us()`; wall-clock
   и монотонные окна не смешиваются.

## D-07. AWG-поллер: `mono_s`/`mono_us` и закрытое окно один раз

`CounterSample` уже содержит `mono_s`. В WP-G4:

1. `_maybe_close_window()` возвращает дополнительные поля:
   `"mono_s": sample.mono_s`, `"mono_us": int(sample.mono_s * 1_000_000)`.
2. Появляется `pop_closed_window() -> Optional[Dict[str, object]]` (или чтение
   `_evaluated_window` с обнулением), чтобы run-петля передавала закрытое
   120-секундное окно в `engine.note_awg_window(win)` **ровно один раз**,
   а не на каждом 1-секундном тике `poll()`.

Обратная совместимость: существующие 14 тестов counters не меняются.

## D-08. Приоритет `ROOT_CAUSE_PRIORITY` — по SPEC §9.2

Выровнять `correlate.ROOT_CAUSE_PRIORITY` по §9.2:

`local_net > local_fault > config > dns > tunnel_down > censorship_suspect >
endpoint_unreachable > degraded > observability`.

Физика: упавший юнит (G-10, `local_fault`) или битый конфиг/ключ (G-05,
`config`) закономерно сыплет ошибками DNS (G-06) — первопричина локальная,
DNS — вторичный симптом. Матрица задания `G-07 > G-06 > G-10 > G-05 > G-01…G-04`
была временной; §9.2 главнее. Правка — 2 строки в `correlate.py`.

## D-09. Персист кольца G-11 в `state.json`

Кольцо ≤5 последних мини-записей (`ts`, `profile`, `proto`, `median_mbps`)
персистится в `guard/state.json` в WP-G5. Причина: `vpn speed` запускается
редко; рестарт демона/`kill -9` обнулял бы статистику, и G-11 никогда не
набрал бы 2 отчёта `< 2.0` за 24 ч.

## D-10. `unparsed_ratio` — только app-строки

Знаменатель AC-5 — только app-источники (`xray`, `hysteria2`; `unknown` для
vpnm-юнитов без hint). `awg-quick`: `[#] ip link add` → `unit_start`,
`[#] ip link delete` → `unit_stop`, остальные строки → `ignored_infra`
(событие не создаётся). dns/zapret/awg-split unmatched видны как событие, но
в знаменатель не входят. `PROBE-BURST` (сервер) по-прежнему калибруется
только по 443.

## D-11. Персистентный `redaction_hits`

Кумулятивный счётчик хранится в `guard/state.json` через
`store.write_state(accumulate_redaction_hits=True)`; при старте читается
начальное значение, новые срабатывания прибавляются. `vpn guard status/sources`
берут `max(state.json, install-state)`. `kill -9`/рестарт счётчик не обнуляет
(AC-11). *(В отчётах WP-G3 значился как D-08.)*

## D-12. Пост-сканер: голый `FIXTURE_*` — секрет

В `redact.py` добавлен `\bFIXTURE_(?:PW|UUID|SECRET)_[A-Za-z0-9_-]+`:
маскируется на записи (`<redacted>`) и детектируется пост-сканером
(`fixture_marker`); голый токен без `password=`/`vless://` блокирует
`export_gate` кодом 2 (AC-13). *(В отчётах WP-G2 значился как D-09.)*

---

## D-13. AC-13 — fail-closed на исходных артефактах

Секрет, найденный в исходных `findings.jsonl`/`coverage.json`, блокирует экспорт
кодом 2 (`input_export_hits`), а не маскируется. Причина: если секрет прошёл
входной redact и лёг в артефакт — это инцидент нарушения инварианта §3.1 п.5;
тихая маскировка скрыла бы баг санитайзера.

## D-14. `suppressed` остаётся в `counters.suppressed`

Не расширять верхний уровень `guard.status/1` новым полем: подавления видны
в `counters.suppressed`; схема не меняется.

## D-15. WP-G6 — эксплуатационный гейт владельца

Кодовый объём G0–G5 завершён. WP-G6: 7 дней `vpn-guard.service` на живом
ноутбуке (AWG/Reality/XHTTP/Hy2), 24 ч бенч AC-5 (RSS/CPU/unparsed),
AC-17 на чистом десктопе, реальный `kill -9`, `selftest` из установленного
wheel. Только после этого — v1.1 по [ARCH-эволюции](ARCH-20261116-vpn-guard-evolution.md).

## D-16. Путь схем — внутри пакета (`vpnm/guard/schemas/`)

Схемы живут в пакете, а не в `scripts/vpn-manager/schemas/guard/` (буква OQ-8):
иначе `pip install`/wheel не довезёт файлы и `schema_hash`/`selftest` падают
(AC-12). Отклонение от OQ-8 подтверждено, SPEC и ADR-014 обновлены.
**Основание:** `vpnm/guard/schema.py:SCHEMA_DIR`, список схем в wheel по BRIEF
Прил. A.

## D-17. Контракт `schema_hash` между репозиториями (DECISION Q1, 2026-11-20)

**Решение.** Источник правды — клиент (ubuntuInstaller) с детерминированным
lock-файлом `vpnm/guard/schemas/schema_hashes.json`. Сервер вендорит **только**
этот lock в `docs/contracts/guard-schema-hashes.json`; тела схем не копируются
(копии гарантируют тихий дрейф). Проверка — локальными тестами, без сети:
на клиенте правка схемы без обновления lock роняет тест; на сервере
`tests/gateway/test_guard_verdict_contract.py` валидирует lock (7 ключей,
`sha256:<64 hex>`) и контракт полей `probe-watch watch --json`; при заданном
`VPN_MANAGER_REPO` — сверка хэшей 1-в-1 с явным diff.
**Отклонено:** GitHub Actions как транспорт (в обоих репо нет `.github/`, сеть в
тестах запрещена); полные копии схем на сервере; «не фиксировать хэши вовсе».
**Состояние:** серверная часть сделана 2026-11-20 (lock + тест, source_commit
`1e54011`); клиентская (WP-Q1b) — коммит после WP-Q1a, установка pipx на
ноутбук заблокирована до 2026-11-24 15:24 MSK (окно G6).

## D-18. `guard.incident/1` дублируется в `$defs` `guard.status/1`

Дублирование допустимо: `status` валидируется без резолвера ссылок. Равенство
копий закреплено тестом, поэтому расхождение — падающий тест, а не тихий дрейф.
**Основание:** `tests/guard/test_guard_contract.py` (сравнение `$defs.incident`
с отдельным файлом схемы).

## D-19. `compat`-профиль — наблюдаемое состояние, не авария

`compat` (без `ProtectSystem`/`SystemCallFilter`/userns) — штатный fallback для
десктопов без userns. Он пишется строкой в `sources`, отдельной записи в
`STATUS`/`TECHDEBT` не требует; отдельный учёт нужен только при переходе
hardened→compat из-за сбоя (причина фиксируется в `sources`).
**Основание:** `vpnm/guard/install.py` (AC-17, `unit_profile=compat`).

## D-20. `stage` в `guard.server_verdict/1` — аддитивно, без смены major

Поле `stage` опционально (`type: ["string","null"]`): его отсутствие не блокирует
разбор, появление в WP-S1 не требует ни bump major, ни правок серверной стороны.
**Основание:** `guard.server_verdict.1.schema.json` (`stage`, «absence must not
block»), серверный тест контракта допускает отсутствие ключа.

## D-21. Порядок коммитов — сначала серверный контракт, затем клиент

Принят порядок: (1) `vds` — SPEC/ADR/STATUS/диапазон ADR; (2) клиент —
`vpnm/guard/`, `pyproject.toml`, `tests/guard/`; после коммита клиента хэши
фиксируются lock-файлом (D-17) и STATUS. Фактическая история P24/P25 это
подтвердила: серверные доки уходили первыми, клиентские правки — отдельным
коммитом со своим тестом.

## D-22. Мост v1.2: `vpn guard export` → `vds logs analyze --client-report` (DECISION Q3)

**Решение.** В v1.2 переиспользовать существующий обезличенный бандл
`guard.bundle/1` (`vpnm/guard/store.py:build_export`) как вход расширенной
команды `vds logs analyze --client-report <file>` — **только по ручной команде**,
без таймера и без сетевого push. `guard.bundle/1` становится 8-й схемой в
lock-контракте D-17; сервер читает её строго по privacy-allowlist в уже
заложенный источник `client_report` (`src/logs/detect.py:88`).

**Allowlist.** Разрешено: `manifest` (schema/created/since/keep_hosts/findings/
counts/rules_hash/config_hash/findings_sha256/coverage_sha256/schemas);
`findings[]` (id, rule, severity, confidence, category, stage_hint,
**нормализованный** proto: amneziawg|xray-reality|xray-xhttp|xray-cdn-ws|
hysteria2 — без имени профиля, window, count, expected_lockdown, cross_vantage,
enum-идентификаторы fp_checks, числовые/enum агрегаты evidence); `coverage`
(status, unparsed_ratio, dropped, blind[], redaction_hits).
**Запрещено:** IP третьих сторон (top/ru_top/new_ru_ips), реальные хосты и
домены (`endpoint.host → <host>`), SNI, ws/xhttp path, UUID, пароли/ключи/obfs,
share-ссылки, **полные пути ФС с именем пользователя** (только basename),
snippets, сырые строки логов; свободный текст `hypothesis`/`action`/`alternatives`
на сервере отбрасывается при импорте.

**Триггер.** Вручную: `vpn guard export --since 24h -o client-guard.json`
(≤ 5 МБ, `keep_hosts=false`) → `scp` во временный путь (вне git) →
`vds logs analyze --live --since 24h --client-report /tmp/…` → удалить файл.

**Куда пишется.** По умолчанию 100 % read-only (stdout/`--json`). При явном
`--apply`/`--out` — только `/var/lib/vds/forensics/reports/report-YYYYMMDD-client.json`
(0600, TTL 90 дн, ADR-012); клиентский файл в `/var/lib/vds/telemetry` и git не
сохраняется. Совпадение UTC-окна (±10 мин) → `coverage.client_report=ok` и
`client_confirmed=true` (повышает confidence; **пересчёт порогов T-01…T-23
запрещён** — детерминизм `rules_hash`), локальный G-06/G-07 в том же окне
помечает серверный `effect_only` как `client_local_fault`.

**Отклонено:** новый формат `client_report/1` (дубль `guard.bundle/1`);
таймер/авто-push при `high` (ломает 0-socket и создаёт корреляционный маяк);
авто-пересчёт весов T-* по клиентскому отчёту (отравление порогов единичным FP).

**Проверка (AC v1.2):** фикстурный `guard.bundle/1` → `client_report=ok`,
`client_confirmed=true`; `keep_hosts=true` без `--allow-hosts` / битый
`findings_sha256` / > 5 МБ → exit 2; подставленный секрет в `hypothesis` не
попадает в вывод; lock D-17 (8 схем) зелёный в обоих репо.

## D-23. Политика эшелонов в v1.1 — две независимые оси (DECISION Q7)

**Решение.** Ось A (сервер): `threat_level ∈ {quiet,elevated,high}` + `lockdown`
+ `stage`. Ось B (клиентские эшелоны): единый источник правды — уже
существующая матрица `vpnm/scout/rank.py` (`BASE_SCORES` + `pre_score`), без
дублирующей таблицы в guard:
`direct+awg 90 → direct+reality 88 → direct+hy2 85` (Эшелон 1, прямой asv2);
`relay+awg 82 → relay+reality/hy2 80` (Эшелон 2, обход прямого IP через релей);
`xhttp 75 → cdn 65` (Эшелон 3, холодный резерв — только если профиль в store).
Смешивать оси нельзя: при `threat=high` + `lockdown=on` закрыт direct:443, но
`direct+awg` и релей полностью рабочие.

**Эскалация (только рекомендации, 0 авто-действий).** Жёсткое подавление при
активных G-06/G-07/G-12 или в окне подавления S4 netlink — переключение
эшелона не рекомендуется (`action: vpn doctor`). Штрафы в окне
`RECENT_FINDINGS_S=30 мин` (офлайн `pre_score`, 0 сокетов): G-04 −60 (есть),
**G-13 −45** (уводит с AWG на Reality/relay), **G-14 −25** (уводит с
затронутого TCP на AWG/Hy2/relay), G-01/G-03 −12 (есть). Никогда не
эскалируют без свежего серверного вердикта: lock-443 (уже `LOCKDOWN_BONUS=10`,
`TSPU_RELAY_BONUS=15`) — только при `lockdown.active=true` и `fresh`
(≤ 65 мин для диагностики guard, ≤ 10 мин `VERDICT_FRESH_S` для выбора
маршрута); `cross_vantage=true` — только при свежем `threat_level ∈
{elevated,high}`.

**Формат строки `server:`** (закрывает OQ-V11-3, схема `guard.status/1` не
меняется). Нет/битый вердикт: `server: none (запустите vpn guard sync)`.
Валидный: `server: verdict=<v> threat=<t> lockdown=<on|off> age=<compact>
(<fresh|stale>) stage=<s|n/a>`, где compact = `<N>s` (<60 с), `<N>m` (<2 ч),
`<N>h` (≥2 ч); пример: `server: verdict=PROBE-BURST threat=elevated
lockdown=off age=41m (fresh) stage=n/a`. При `lockdown=on` и fresh —
доп. строка `hint: lock-443 активен — direct:443 закрыт, используйте
AWG/Hy2/relay (vpn scout)`.

**Отклонено:** статическая цепочка AWG→XHTTP→Hy2-obfs→CDN внутри
`guard/rules.py` (дублирует `scout/rank.py`, устарела: XHTTP на asv2 нет, CDN в
холодном резерве, релей не учтён); сетевой `vpn scout` из guard (нарушает
0-сокет, ADR-014 §8); отложить политику до v2.0 (лишает 30-дневной сверки).

**Проверка:** юнит-тесты `tests/guard` на 4 состояния строки `server:` при
неизменном hash `guard.status/1`; `tests/scout` на штрафы G-13/G-14 в
`pre_score` (0 сокетов) и подавление при G-06/G-07.

## D-24. v2.0 Smart Failover — критерии входа в ADR, границы, fail-safe (DECISION Q4)

**Решение.** Smart Failover остаётся строго в v2.0 под отдельным ADR-016+.
Роли разделены: `vpn-guard.service` — read-only детектор (ADR-014 §6/§8 не
меняются); актуатор — **отдельный opt-in компонент `vpn failover`**,
`auto=off` по умолчанию, `--dry-run` по умолчанию.

**Критерии входа в ADR (все 4 одновременно):** ≥ 30 календарных дней поля (из
них ≥ 14 на v1.1 с откалиброванным G-13 и протестированным S4 netlink);
≥ 5 реальных эпизодов деградации + ≥ 3 реальных роуминга, где рекомендация
`scout/rank.py` совпала с ручным выбором владельца; FP = 0 за последние 14 дней
по всем правилам-триггерам (G-01/G-03/G-04/G-13/G-14) на `confidence=high`;
работает механизм свежести вердикта ≤ 10 мин (`VERDICT_FRESH_S`), а не часовой
lock-443.

**Разрешено актуатору** (только `confidence=high` И не G-06/G-07/G-12 И не
`netlink_cooldown` И `coverage ∉ {blind,insufficient_data}`): смена
схемы/профиля **внутри уже установленных профилей** по рангу `scout/rank.py`;
синхронизация локального sysproxy; запись аудита + уведомление владельцу о
каждом действии и откате.

**Запрещено без человека:** любые действия на сервере (ssh, ufw, lock-443,
`vds relay maneuver`); правка конфигов профилей, ключей, `guard.json`,
systemd-юнитов, DoH/DNS, zapret, NetworkManager; новые sudo-действия;
переключение при G-06/G-07 или `insufficient_data`; активация
отсутствующих/холодных эшелонов (CDN/XHTTP без профиля).

**Fail-safe (по образцу P25/`vpnm/doh.py`):** до переключения атомарный снимок
`previous_scheme/previous_profile/sysproxy` в
`~/.local/share/vpn-manager/failover-state.json` (0600). Провал = ненулевой exit
подъёма, ИЛИ нет data-plane liveness за 20 с (реальный проход трафика, не
`systemctl is-active`), ИЛИ срабатывание G-01/G-03/G-04 на новом профиле в окне
верификации. Откат: профиль в `failed_profiles` на 600 с, немедленный
детерминированный возврат на `previous_scheme` (если жив) или следующий
кандидат; бюджет — cooldown 600 с после успеха, ≤ 3 попытки в час, затем
`exhausted` с уведомлением; `vpn failover disable` гасит автопилот мгновенно,
не трогая `vpn-guard.service`.

**Отклонено:** встроить авто-свитч в `vpn-guard.service` (ломает read-only
sandbox); ранний `--auto` в v1.1 (нарушает заморозку ADR-014 §5 и даст
флап-шторм при роуминге — RSK-8).

**Проверка (гейт открытия ADR-016):** в шапке ADR — ≥ 30-дневный полевой отчёт
(≥ 5 инцидентов, ≥ 3 роуминга, FP = 0 на high); sandbox `vpn-guard.service`
неизменён. Примечание: в `vpnm/doh.py` функции `_rollback` нет — откат через
`disable()` + обратимый `mv` drop-in (`DROPIN ↔ DROPIN_DISABLED`).

---

## Остаток (WP-G6)

1. `vpn guard install` на ноутбуке; 7 дней без падений; `status --json`/`findings`
   ежедневно.
2. AC-5: RSS < 80 МБ, CPU < 1%, unparsed < 5% app-строк за 24 ч.
3. AC-17: три живые проверки sandbox; fallback `compat` при `226/NAMESPACE`.
4. Реальный `kill -9` → рестарт без дублей и потери курсора/`redaction_hits`.
5. `vpn guard selftest` из установленного пакета.
6. По итогам поля — решение о v1.1 (ss/netlink, packet-size ratio, ленивый sync);
   v2.0 Smart Failover — только отдельным ADR.
