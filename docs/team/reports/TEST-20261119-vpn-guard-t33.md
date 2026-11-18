# TEST-20261119-vpn-guard-t33 — чекпоинт WP-G6 (T+33 ч)

> **Тип:** TEST-отчёт (read-only снимок поля + архитектурный триаж дефектов).
> **Дата снимка:** 2026-11-19 00:28 MSK. **Хост:** ноутбук `dragonMi`.
> **Код клиента:** `ubuntuInstaller` `e3abc81` (после `vpn qr`); guard-фиксы
> D1/D3 — **в рабочем дереве, на ревью, не задеплоены** (см. §5).
> **Секреты:** нет; только счётчики, состояния, хэши, имена юнитов.

## 1. Точка отсчёта 7-дневного окна (сдвиг относительно T0)

| | Значение |
|---|---|
| Старт непрерывного инстанса | **2026-11-17 15:24:17 MSK** (`ExecMainStartTimestamp`) |
| Закрытие окна | **2026-11-24 15:24 MSK** |
| Аптайм на снимке | **33 ч 04 мин** (119 058 с) |
| `NRestarts` | **0** |

Причина сдвига относительно T0 (17.11 00:00 MSK): 17.11 13:18 демон упал на
`Errno 2` (отсутствовала `guard.status.1.schema.json` в pipx-venv — гонка
переустановки, D2), после чего юнит был перезапущен; текущее непрерывное окно
отсчитывается от 15:24. T0-отчёт ([TEST-20261117-vpn-guard-checkpoint-t0](TEST-20261117-vpn-guard-checkpoint-t0.md))
остаётся валидным как исходная точка, но 7-дневный таймер сдвинут на 15 ч 24 мин.

## 2. Живой снимок AC-5

```
vpn-guard.service: active, profile=hardened, state=armed, NRestarts=0
RSS:  23 121 920 B ≈ 22.1 MiB   (лимит AC-5: < 80 MiB)      PASS
CPU:  335.2 s / 119 058 s = 0.28 %  (лимит AC-5: < 1 %)      PASS
counters: events=6025, unparsed=1, dropped=0, findings=7,
          suppressed=860, redaction_hits=0
coverage: unparsed_ratio=1.0, blind=[],
          notes=[verdict_stale, speed_ring_restored:4, file_parse_error,
                 app_signal=blind (нет app-событий за прогон)]
sources: journal:user/system, state, file, verdict, sysfs:awg(iface=laptop) — ok;
         netlink — off (v1.1, opt-in)
signals: systemd=ok, amneziawg=counters, dns/xray/hysteria2=blind
```

Разбор метрик:

- `unparsed=1` — **единственная** строка за 33 ч: Hysteria2-баннер
  `INFO\tclient mode` (см. §4/D3). `unparsed_ratio=1.0` — арифметика `1/1`
  на выборке из одной app-строки, а не деградация парсера; после фиксов
  D3+D6 реплей всего журнала даёт `parsed=6, unparsed=0` (§4/D6).
- `app_signal=blind` — **не «простой»**, а дефект D6: `proto_hints` не
  заполнялся, поэтому сигналы не могли стать `ok` даже при живом трафике
  (полевая серия §6 это подтвердила).
- `verdict_stale` — `vpn guard sync` не запускался > 65 мин (норма без sync).

## 3. Findings за 7 дней — 26 (live, `--since 7d`)

| правило | n | первое | последнее | юнит | вердикт |
|---|---|---|---|---|---|
| G-06 DNS | 13 | 16.11 18:03Z | 18.11 13:43Z | `cloudflared-proxy-dns.service` | **полевое доказательство**: совпадает с реальными провалами DNS (эксперимент с `public-dns.conf` 18.11, смена сети/сон 16–17.11); FP-проверки `distinct_names=0` корректны |
| G-07 local_net | 7 | 16.11 18:03Z | 17.11 10:18Z | тот же | корректная атрибуция локальной сети/DNS, не VPN |
| G-12 observability | 3 | 17.11 07:19Z | 17.11 21:06Z | — | **low**, evidence `source_lost: sysfs:awg` 61–62 с (не `unparsed_ratio`, см. §4/D3) |
| G-09 endpoint_unreachable | 3 | **16.11 20:39Z** | 16.11 20:39Z | тот же | **закрыто фиксом `c447171`** (G-09 на вспомогательном DNS-юните); после фикса повторов нет |

Наблюдения:

1. **G-06 отработал по факту** (AC-4 в поле): DNS-провал 18.11 пойман high-finding'ом
   с action `vpn repair`, а не только лабораторным replay.
2. **G-09-дефект реально закрыт**: все три записи — до `c447171`, ни одной после.
3. **100 % findings — на вспомогательном DNS-юните**; findings на VPN-транспорте
   (G-02/G-03/G-04/G-05/G-10/G-11) в поле пока нет → это гэп покрытия G6,
   закрывается прогонами 4 транспортов (§6).

`counters.findings=7` vs `findings --since 24h = 6` — **не баг** (D5): счётчик
в `status` монотонен с момента старта процесса (17.11 15:24), а `findings`
фильтрует `findings.jsonl` по окну 24 ч; один finding выпал из окна.

## 4. Дефекты (триаж)

### D1 — exit-код демона при штатном останове (ИСПРАВЛЕНО В КОДЕ, не задеплоено)

Симптом: журнал 17.11 15:24 — `Main process exited, code=exited,
status=2/INVALIDARGUMENT`, `Failed with result 'exit-code'`.
Причина: `vpnm/guard/cli.py` завершал любой прогон с `exit 2`, если за время
работы были high-findings (`if counters.high: raise typer.Exit(code=2)`).
Для сервиса это ложное «падение» → искажает AC-5 и может шуметь в G-11.
Фикс: `high → 2` только при `once=True`; демон на SIGTERM/SIGINT — `exit 0`.
Тесты: `tests/guard/test_guard_g6_acceptance.py` (daemon high→0, `--once` high→2,
`--once` без high→0).

### D2 — падение на отсутствующей схеме 17.11 13:18 (историческое, до окна)

`[error] guard run: [Errno 2] ... vpnm/guard/schemas/guard.status.1.schema.json`
→ `exit 3`. Класс — гонка pipx-переустановки (копия пакета без package-data на
момент старта демона), тот же класс, что D1-packaging в `vpn qr`.
Сейчас проверено: в pipx-venv лежат **10/10** `guard.*.schema.json`.
В окно непрерывности не попадает (произошло до 15:24). Предложение на WP-микро
после G6: стартовый self-check схем с внятным сообщением вместо голого `OSError`.

### D3 — Hysteria2-баннер уходил в `unparsed`, AC-5 показывал 1.0 (ИСПРАВЛЕНО В КОДЕ)

Root cause (реплей 67 681 строки user-журнала с 17.11 15:24): единственная
`unparsed`-строка — `2026-11-18T13:32:29+03:00\t\x1b[34mINFO\x1b[0m\tclient mode`
от `vpnm-asv2-hy2.service`. Это **стартовый баннер** Hysteria2 2.x, который не
содержит имени протокола, поэтому регэксп `app_banner_ok` его не ловил →
1) строка в `unparsed`, 2) **`app_banner_ok` не выставлялся**, то есть G-01 терял
доказательство покрытия для Hy2.

Фикс:
1. `parse.py`: в семейство `app_banner_ok` добавлен вариант
   `(?:^|[\t: ])client mode(?:[,;]|\s*$)` — строго с `,`/`;`/концом строки,
   чтобы «client mode disabled» баннером не считался (есть негативный тест).
2. `runner.py`: `unparsed_ratio` не отдаётся как метрика AC-5 при
   `app_lines < 20` (`MIN_APP_LINES_FOR_RATIO`), вместо этого в `notes`
   добавляется `app_lines_low:<n>` — число не прячется, но и не краснит AC-5.

Проверка реплеем после фикса: `ParseStats(lines=67 681, app_lines=1, parsed=1,
unparsed=0)` — 0 unparsed, баннер распознан.

**Поправка к гипотезе о G-12:** G-12 на `unparsed_ratio` не срабатывал и не мог —
порог `self_unparsed_min_lines=200` (и ratio > 0.3) отсекает выборку из 1–16 строк
(есть тест `test_g12_unparsed_ratio_needs_volume`). Все три полевых G-12 —
`source_lost: sysfs:awg` (61–62 с) в момент переключений AWG/сна; это
low-severity и отдельный сюжет (кандидат в тюнинг G6: окно/гистерезис для
sysfs-источника при смене iface).

### D4 — `file_parse_error` «залипает» при `sources.file=ok` (P-долг)

`coverage.notes` содержит `file_parse_error`, при этом источник `file` — `ok`.
Проверено: все три наблюдаемых JSON (`activity.json`, `last-speed.json`,
`server-verdict.json`) сейчас валидны и являются объектами. Значит note —
транзиент (гонка чтения во время перезаписи), но живёт в `notes` без TTL и без
атрибуции к файлу, что противоречит §6.6 (degraded-статус при error-note).
Правка затрагивает больше 15 строк (reader + coverage-сборка) → **в P-долг**,
не в этот срез.

### D5 — несоответствие счётчика и персиста (не баг, зафиксировано)

См. §3: `counters.findings` — монотонный счётчик процесса; `findings` — окно по
`window.last` из `findings.jsonl`. Разные семантики, обе корректны.

### D6 — `signals.xray`/`signals.hysteria2` не могли стать `ok` (ИСПРАВЛЕНО В КОДЕ)

Найдено полевой серией (§7): при живом трафике Reality и Hy2 сигналы оставались
`blind`, `notes` держал `app_signal=blind`.

**Root cause.** `JournalParser.proto_hints` в боевом `build_runner` **не
заполнялся вообще** (единственное заполнение — в `cli.py` у `selftest`). Для
юнитов `vpnm-*` протокол брался только из hints (`parse.py:_proto_for`), иначе
`"unknown"`; а `_app_proto[proto]="ok"` пишется только для
`xray|hysteria2|amneziawg` (`runner.py`). Итог: в проде все события профилей
получали `unknown` → `signals.xray/hysteria2` навсегда `blind`, и AC-5
«покрытие доказано» было недоказуемо даже при живом трафике.

**Фикс (три уровня, контракт не меняется):**

1. **Primary** — `build_runner` собирает hints из клиентского profile-store
   (`runner.profile_proto_hints()`): `xray-*|vless*|vmess*|trojan* → xray`,
   `hysteria2|hy2 → hysteria2`, `amneziawg|awg → amneziawg`.
2. **Fallback #1 (контент)** — в `parse.py`, если hint'а нет: однозначные
   маркеры строки (`Xray <ver>`, `infra/conf/serial`, `core: Xray` →
   `xray`; `client mode`, `SOCKS5 server listening`, `update available
   {"version":"v2.` → `hysteria2`) резолвят протокол и **кэшируются** в
   `proto_hints` (самовосстановление для профилей, добавленных после старта
   демона, и при недоступном store).
3. **Fallback #2 (имя юнита)** — `vpnm-*-hy2|*hysteria*` → `hysteria2`,
   `vpnm-*-reality|-xhttp|-xray|-ws|-cdn` → `xray`.

**Заодно закрыт `unparsed` пролога** (те же 4 строки из полевой серии):
`Xray <ver> (…)` теперь `app_banner_ok`; `A unified platform for
anti-censorship`, `infra/conf/serial: Reading config`,
`update available {"version":…}` и `received signal, shutting down gracefully` →
`ignored_infra` (авторитетный lifecycle-сигнал даёт systemd `unit_stop`).

**Evidence (реплей user-журнала с 17.11 15:24, 68 657 строк):**

| прогон | app_lines | parsed | unparsed | ignored_infra |
|---|---|---|---|---|
| до фикса | 7 | 6 | **1** | 3 |
| после фикса | 6 | 6 | **0** | 4 |

Runner-реплей 10 записей `vpnm-*` через реальный `build_runner`:
`signals = {systemd: ok, xray: ok, hysteria2: ok, amneziawg: counters, dns: blind}`,
`unparsed_ratio=0.0`, `notes` без `app_signal=blind` (остаётся `app_lines_low:6`).

## 5. Состояние кода и стоп-кран на аптайм

| Что | Где | Статус |
|---|---|---|
| D1 фикс + 3 теста | `vpnm/guard/cli.py`, `tests/guard/test_guard_g6_acceptance.py` | **закоммичено** `612a64b`, не задеплоено |
| D3 фикс + 5 тестов | `vpnm/guard/parse.py`, `vpnm/guard/runner.py`, там же | **закоммичено** `612a64b`, не задеплоено |
| D6 фикс + 6 тестов | `vpnm/guard/{parse,runner}.py`, там же | в рабочем дереве, **не закоммичено/не задеплоено** |
| Полный прогон | `scripts/vpn-manager` | **1181 passed** |
| Живой демон | `vpn-guard.service` | **не тронут**: `MainPID=2100090`, `NRestarts=0`, окно непрерывности идёт |

Деплой D1/D3/D6 (`pipx install --force -e .` + рестарт юнита) и AC-11 (`kill -9`)
— **строго после 2026-11-24 15:24 MSK**, чтобы не обнулить 7-дневное окно.

## 6. Полевая серия транспортов (2026-11-19, живой прогон)

Проведена по решению владельца. Демон **не перезапускался**: `MainPID=2100090`,
`NRestarts=0`, `active` до, между и после всех переключений (`pipx install` не
выполнялся — живёт ещё не обновлённый инстанс).

| Транспорт | Доказательство трафика | Δevents / Δunparsed | findings 1h | signals |
|---|---|---|---|---|
| **AWG** (`laptop`, mode DIRECT) | 3× HTTPS 200; iface `laptop`: tx **+59 008 B**, rx **+1 045 504 B** | +0 / +0 | 0 | `amneziawg=counters` (канал kernel-level: журнал не растёт, sysfs-счётчики — да) |
| **Reality** (`asv2-reality`, socks 2080) | `generate_204` 204, 0.48 s | +5 / +3 | 0 | до фикса — `blind`; после D6-фикса в реплее — `ok` |
| **Hy2** (`asv2-hy2`, socks 2083) | `generate_204` 204, 0.42 s | +4 / +2 | 0 | до фикса — `blind`; после D6-фикса в реплее — `ok` |
| **XHTTP** | — | — | — | **N/A**: на asv2 транспорта нет (Reality 443/tcp + Hy2 443/udp + AWG), asv1 с XHTTP выведен 2026-11-16. Движок Xray в поле доказан через Reality; ветка XHTTP покрыта корпусными/контрактными тестами |

Возврат в штатный режим выполнен: `mode: DIRECT (awg laptop)`, split жив; итог
`events 6025 → 6034`, `unparsed 1 → 6`, `dropped 0`, `findings 7 → 7` (новых
нет), `redaction_hits 0`.

**Разбор +5 unparsed** (источник правок D3/D6): Reality — 3 строки пролога
Xray (`Xray 26.x (…)`, tagline, `Reading config`); Hy2 — баннер `client mode`
(не распознан старым инстансом) и `update available {"version":…}`. После
фиксов реплей даёт `unparsed = 0` (§4/D6).

**G-12 `source_lost: sysfs:awg` в серии не срабатывал:** socks-профили не
трогают AWG-интерфейс, `sysfs:awg` оставался `ok`; ранее зафиксированные
61–62 с относятся к реальным сменам AWG-iface и остаются кандидатом в
калибровку порогов на T+7.

## 7. Остаток до G6 close

Осталось: завершение 7-дневного окна (24.11 15:24 MSK), деплой D1/D3/D6,
AC-11 (`kill -9`), тюнинг порогов по кандидатам (Xray/Hy2-пролог → `ignored_infra`
уже закрыт; `source_lost: sysfs:awg`; D4-note TTL) и финальный G6-отчёт.

## Трассируемость

| Что | Ссылка |
|---|---|
| T0/T0.5 (исходная точка) | [TEST-20261117-vpn-guard-checkpoint-t0](TEST-20261117-vpn-guard-checkpoint-t0.md) |
| Спека и AC-1…AC-17 | [SPEC-20261116-vpn-guard](../specs/SPEC-20261116-vpn-guard.md) §14.2, §15 |
| Полевые фиксы правил (G-09 и др.) | `ubuntuInstaller c447171` (T0.5, §«Пост-фикс») |
| D1/D3 (этот чекпоинт) | `ubuntuInstaller 612a64b` (запушен 2026-11-19) |
| D6 (полевая серия) | `ubuntuInstaller` (рабочее дерево, ревью) |
| Дефект D4 | TECHDEBT (P-долг, кандидат P22+) |
