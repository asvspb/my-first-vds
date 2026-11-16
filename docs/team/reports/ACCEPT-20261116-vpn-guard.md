# ACCEPT-20261116-vpn-guard — приёмка G3/G4/G5 (клиентский `vpn guard`)

> **Тип:** ACCEPT-отчёт (snapshot), не SPEC.
> **Дата:** 2026-11-16. **Ревьюер:** главный архитектор (Gemini Argon).
> **Вердикт:** **PASS** — G3 Build, G4 Verify, G5 Docs приняты; G6 Close —
> после полевого WP-G6 (7 дней на живом ноутбуке).
> **SPEC:** [SPEC-20261116-vpn-guard](../specs/SPEC-20261116-vpn-guard.md) ·
> **ADR:** [ADR-014](../../adr/ADR-014-vpn-guard.md) ·
> **Решения:** [DECISIONS-vpn-guard](DECISIONS-vpn-guard.md) ·
> **Доклад:** [BRIEF-20261116-vpn-guard](BRIEF-20261116-vpn-guard.md).
> **Репозитории:** `ubuntuInstaller` (`origin/main` = `b10553a`),
> `my-first-vds` (`origin/main` = `20b52ff`) — оба синхронизированы с GitHub.

---

## 1. Объём

Пакеты WP-G0…WP-G5 (весь кодовый объём `vpn guard`):

| WP | Содержание | Коммит (`ubuntuInstaller`) |
|---|---|---|
| WP-G0 | контракт: `events.py`, `schema.py`, 7 JSON-схем, package-data, контрактные тесты | `4bc145e` |
| WP-G2 | parser structured-first, redaction, пост-сканер, export gate | `6ead3cc` |
| WP-G1 | readers S1/S2/S3, AWG counters без хардкода `awg0`, coverage/sources, unit `hardened`/`compat`, `hmac.key`, activity-маркеры | `757e2f2` |
| WP-G2 fix | голый `FIXTURE_*` → секрет; `unparsed_ratio` только по app-строкам | `a7e7a8f` |
| WP-G3 | окна/reorder, правила G-01…G-08, персист `redaction_hits` | `b0297d8` |
| WP-G4 | `verdict.py`/`sync`, G-09…G-12, `correlate.py`, `runner.py` | `c84560d` |
| WP-G5 | `rules`/`export`/`selftest`, `run --trace`, нотификации, TUI, доки | `b10553a` |

Серверная часть процесса в `my-first-vds`: ADR-014 `f502985`, отчёты
`c13b0a5`, реестр решений `b42d4cc`/`20b52ff`, AC-16 `69225a7`.

## 2. Доказательства (снимок 2026-11-16)

| Проверка | Результат |
|---|---|
| `ubuntuInstaller`: `pytest -q tests/guard` | 451 passed |
| `ubuntuInstaller`: `pytest -q` | 872 passed |
| `ubuntuInstaller`: `compileall vpnm`, `pyflakes vpnm/guard/*.py` | exit 0 |
| `my-first-vds`: `pytest -q` | 1028 passed |
| `my-first-vds`: `docsync audit --strict` | exit 0 (только freshness-warning STATUS) |
| `git diff --check` в обоих репо | чисто |

Каждый finding в тестах проходит `schema.validate(...) == []` и
`redact.scan_secrets(...) == []` (AC-6/AC-13). Секреты в фикстурах — только
`FIXTURE_PW_*`/`FIXTURE_UUID_*`, IP — RFC 5737.

## 3. Покрытие AC

| AC | Статус | Где |
|---|---|---|
| AC-1…AC-4, AC-6…AC-16 | ✅ код + unit/integration | см. отчёты WP-G1…G5, маппинг G-01…G-12 |
| AC-5 (24 ч live RSS/CPU/unparsed) | ⏳ WP-G6 (поле) | `--trace`, `status --json`, coverage готовы |
| AC-11 (`kill -9`) | ✅ fake-Popen + персист курсора/счётчиков; ⏳ реальный демон в WP-G6 |
| AC-17 (чистый десктоп, `hardened`/`compat`) | ✅ скриптованная проверка 226/NAMESPACE/203/218 + fallback; ⏳ живые три проверки в WP-G6 |
| AC-16 server half | ✅ `69225a7`: mtime+sha256 на `probe-watch.json` и `gateway/state.json` при `record=False` |

## 4. Утверждённые отклонения

1. `reader.py` — `follow: bool` для `run --once` (backfill без `-f`); default не изменён.
2. `test_rules.py` — assert каталога расширен с G-01…G-08 до G-01…G-12.
3. Root cause — по SPEC §9.2 (D-08), а не по временной матрице WP-G4.
4. Аддитивные поля `/1`: `guard.incident/1` (`severity`, `expected_lockdown`,
   `cross_vantage`), `guard.status/1` (`coverage`, `rules_hash`, `config_hash`).
5. G-09 `conn_refused` → категория `endpoint_unreachable` (в схеме нет
   `endpoint_down`); в тексте действия цензура не заявляется.
6. G-11 — один finding на худший канал; G-10 «обновление бинаря» — в `fp_checks`.
7. Новый `guard/notify.py` — отдельная политика доставки, `install` переиспользован.
8. `export` — fail-closed: секрет в исходных `findings.jsonl`/`coverage.json`
   блокирует бандл (exit 2), а не маскируется.
9. `rules --json` не вводит `guard.rules/1`; манифест `guard.bundle/1` — по §10.1.
10. `suppressed` остаётся в `counters.suppressed`, без нового поля верхнего уровня.

## 5. Финальные решения (D-13…D-15)

- **D-13.** AC-13 — fail-closed на `input_export_hits`; тихая маскировка запрещена
  (секрет в артефакте = инцидент нарушения инварианта §3.1 п.5).
- **D-14.** `suppressed` — только `counters.suppressed`; `guard.status/1` не
  расширять.
- **D-15.** WP-G6 — эксплуатационный гейт владельца: 7 дней `vpn-guard.service`
  на живом ноутбуке (AWG/Reality/XHTTP/Hy2), 24 ч бенч AC-5, AC-17 на чистом
  десктопе, реальный `kill -9`, `selftest` из установленного wheel.

## 6. Остаток (WP-G6)

1. `vpn guard install` на ноутбуке; 7 дней работы без падений; `status --json`
   и `findings` — раз в сутки.
2. AC-5: RSS < 80 МБ, CPU < 1%, unparsed < 5% app-строк за 24 ч.
3. AC-17: три живые проверки sandbox на чистом десктопе; fallback `compat`
   при `226/NAMESPACE`.
4. Реальный `kill -9` → рестарт без дублей и потери курсора/`redaction_hits`.
5. `vpn guard selftest` из установленного пакета (не из исходников).
6. Сбор полевых findings; по итогам — решение о v1.1 (ss/netlink, packet-size
   ratio, ленивый sync) и только затем v2.0 (Smart Failover, отдельный ADR).

## 7. Трассируемость

| IDEA / SPEC | Коммиты | Тесты | Доки |
|---|---|---|---|
| запрос владельца 2026-11-16 → SPEC-vpn-guard + ADR-014 | `4bc145e`, `6ead3cc`, `757e2f2`, `a7e7a8f`, `b0297d8`, `c84560d`, `b10553a` | `tests/guard/` (451), полный `pytest` (872) | SPEC, ADR-014, DECISIONS, `doc/vpn-manager.md`, README |
| AC-16 (стык с `vds`) | `69225a7` | `test_probing_hf1.py` | DECISIONS, STATUS |
