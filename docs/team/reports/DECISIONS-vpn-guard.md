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

## D-08. Персистентный `redaction_hits`

Кумулятивный счётчик хранится в `guard/state.json` через
`store.write_state(accumulate_redaction_hits=True)`; при старте читается
начальное значение, новые срабатывания прибавляются. `vpn guard status/sources`
берут `max(state.json, install-state)`. `kill -9`/рестарт счётчик не обнуляет
(AC-11).

## D-09. Пост-сканер: голый `FIXTURE_*` — секрет

В `redact.py` добавлен `\bFIXTURE_(?:PW|UUID|SECRET)_[A-Za-z0-9_-]+`:
маскируется на записи (`<redacted>`) и детектируется пост-сканером
(`fixture_marker`); голый токен без `password=`/`vless://` блокирует
`export_gate` кодом 2 (AC-13).

## D-10. `unparsed_ratio` — только app-строки

Знаменатель AC-5 — только app-источники (`xray`, `hysteria2`; `unknown` для
vpnm-юнитов без hint). `awg-quick`: `[#] ip link add` → `unit_start`,
`[#] ip link delete` → `unit_stop`, остальные строки → `ignored_infra`
(событие не создаётся). dns/zapret/awg-split unmatched видны как событие, но
в знаменатель не входят. `PROBE-BURST` (сервер) по-прежнему калибруется
только по 443.

---

## Открытые вопросы к WP-G4

1. Синтетические S3-события и verdict — штамповать `clock.now_us()` (D-06),
   не wall-clock из файла.
2. `counters.py` — `pop_closed_window()` и `mono_s/mono_us` (D-07), затем
   `engine.note_awg_window()` один раз за окно.
3. `verdict.py`/`ServerContext`: `fresh` при `age_s <= 3900`, `lockdown`,
   `threat_level`, `verdict`, `stage`.
4. G-09…G-12, `correlate.py` (инциденты/подавления), `run`-петля,
   `status --json`/`findings`/`explain`, `sync`, `export` — WP-G4/WP-G5.
