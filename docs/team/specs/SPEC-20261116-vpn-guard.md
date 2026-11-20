# SPEC-20261116-vpn-guard — real-time анализ клиентских логов (`vpn guard`)

## Мета
- **Источник:** запрос владельца 2026-11-16 («продумай спеку для архитектора и
  техлида для команды `vpn guard`, чтобы анализировались логи в живом
  времени»); [SPEC-20261116-log-forensics](SPEC-20261116-log-forensics.md)
  §3 (карта слепоты сервера) и §15 (клиентская телеметрия — отдельная SPEC);
  [SPEC-20261116-survivability](SPEC-20261116-survivability.md) (стадии,
  T-18…T-23); [ADR-012](../../adr/ADR-012-log-forensics.md).
- **Автор:** оркестратор (черновик для `vds-architect` + техлида)
- **Дата:** 2026-11-16
- **Статус:** **G5 PASS 2026-11-16** — G0…G5 приняты архитектором
  ([ACCEPT-20261116-vpn-guard](../reports/ACCEPT-20261116-vpn-guard.md));
  осталось **WP-G6** — 7 дней поля на живом ноутбуке, бенч AC-5 и AC-17.
  Спека остаётся контрактом; реализация — `ubuntuInstaller/scripts/vpn-manager`.
- **Репозиторий реализации:** `ubuntuMastering/ubuntuInstaller`,
  `scripts/vpn-manager/vpnm/` (клиентская команда `vpn`). Спека и процесс — в
  `vds`: здесь живут роли, гейты и реестр спек; клиентский репозиторий своего
  process-контура не имеет.
- **ADR:** **ADR-014 «client observability: контракт
  guard.event/guard.finding, демон vpn-guard.service, приватность и retention
  клиентских артефактов»** — утверждён на G2 (решение §20.2 п.8). Это
  необратимые решения (новый демон, постоянные артефакты, кросс-репо схема) — по
  прецеденту ADR-012. Создаётся в WP-G0.
- **Скоуп v1:** клиент, user-space, **read-only**. Серверный разбор логов —
  `vds logs` (SPEC-20261116-log-forensics), серверная реакция — probe-response.
  `vpn guard` не дублирует ни то, ни другое.

---

## 1. Проблема

Серверный `vds logs` видит **эффекты** на NIC и активные пробы. Целый класс
отказов виден только с клиента (log-forensics §3): SNI-drop, DNS-подмена,
whitelist-режим, «handshake прошёл — данные умерли» на конкретном пути
оператора. Сейчас клиент отвечает на «VPN не работает» тремя инструментами,
и все они — **точечные снимки**:

| Инструмент | Что даёт | Чего не даёт |
|---|---|---|
| `vpn monitor` | матрица 7 каналов, активные пробы | не видит историю: «упало 40 секунд назад» |
| `vpn doctor` | окружение, порты, DNS, бинари | не видит поток ошибок и их порядок |
| `vpn repair` | снимок в лог + починка DNS | запускается руками, уже после инцидента |
| `journalctl --user -u vpnm-*` | сырой текст | нет правил, корреляции, уверенности, дедупа |

Последствия:

1. **Инцидент живёт минуты, а разбор — часы.** Окно ТСПУ часто 2–15 минут;
   пользователь замечает «VPN умер», когда лог уже прокручен.
2. **Симптом принимают за причину.** Рестарт юнита при data-phase freeze
   сбрасывает состояние и уничтожает улики (тот же вывод, что в §5.9/§5.11
   SERVER-BASELINE).
3. **Локальная поломка выглядит как цензура.** Нет route/DNS/unit-flap —
   а пользователь уже меняет профиль и «прячет» сервер.
4. **Нет доказательств для серверной стороны.** Клиентский факт («RST через
   1–2 с после handshake, 4 раза за 2 минуты») не передаётся и не
   сопоставляется с серверным вердиктом.

`vpn guard` закрывает именно эту дыру: **непрерывный потоковый анализ
клиентских логов**, который за секунды отвечает «что сломалось, на каком
слое, насколько уверены и что делать», не трогая сервисы.

---

## 2. Цель, требования, принципы

### 2.1. Цель

Дать пользователю и агенту детерминированный **real-time** конвейер
`tail → parse → normalize → window → rules → correlate → finding → notify`,
который:

- работает на живом журнале (`journalctl -f`), а не по расписанию;
- объясняет отказ в терминах слоя (локальная сеть / DNS / конфиг / сервер /
  цензура) и стадии (`pre_handshake`, `data_phase`, `udp_response`, …);
- хранит только обезличенные счётчики и хэши шаблонов;
- не требует root, сети и LLM;
- не выполняет никаких действий, кроме записи собственных артефактов.

### 2.2. Требования

| ID | Требование | Как проверяется |
|---|---|---|
| R-1 | **Потоковость:** один долгоживущий reader на источник, обработка по строке; задержка «строка журнала → finding» p95 ≤ 2 с, медиана ≤ 300 мс | бенч-тест на синтетическом потоке, метрики в `status --json` |
| R-2 | **Детерминизм:** одинаковый корпус событий + конфиг → побайтно одинаковый `findings.jsonl` | golden-тест, виртуальные часы, стабильные ID |
| R-3 | **Приватность:** ни UUID, ни паролей/ключей/obfs/shortId, ни share-ссылок, ни payload; текст строки не сохраняется | сканер артефактов + тест-корпус с `FIXTURE_*` |
| R-4 | **Без root, сети и LLM:** демон не открывает сетевых сокетов; системный журнал — best-effort | тест с monkeypatch `socket.socket`; `sources` показывает `denied` |
| R-5 | **Доказательства:** finding = окно, счётчики сигналов, хэши шаблонов, выполненные FP-проверки | схема `guard.finding/1` + `explain` |
| R-6 | **Ресурсы:** RSS ≤ 80 МБ, CPU ≤ 1% одного ядра в покое, диск ≤ 20 МБ, очереди ограничены | 24-часовой прогон, `MemoryMax`/`CPUQuota` |
| R-7 | **Read-only v1:** никаких restart/repair/switch/ufw/правок конфигов | grep по коду + ревью; в finding только `action` (текст) |
| R-8 | **Совместимость:** `vpn monitor --json`, `state.json`, юниты `vpnm-*`, `vpn doctor/repair` не меняются; единственное добавление — маркер `activity.json` без влияния на вывод | регрессионные тесты существующего контракта |
| R-9 | **Честная слепота:** coverage по источникам и сигналам; доля `unparsed`; правило self-health | `vpn guard sources`, G-12 |
| R-10 | **Кросс-vantage:** серверный вердикт читается из файла (без сети в демоне), свежесть `fetched_at` ≤ 65 мин (часовой серверный тик + допуск), при активном lock-443 клиентские отказы помечаются ожидаемыми | тест merge + `server.lockdown` в finding |
| R-11 | **Покрытие AmneziaWG:** активный kernel-туннель не приводит к `idle`; tx↑/rx≈0 детектируется как UDP-блэкаут | AC-15 (sysfs-поллер, replay счётчиков) |

### 2.3. Принципы

1. **Структура важнее текста.** Сначала структурированные поля journald и
   JSON-файлы состояния; regex — только для app-логов Xray/Hysteria2 (они
   англоязычные и стабильнее локализованных сообщений systemd).
2. **Один сигнал — не вывод.** High-confidence требует ≥ 2 независимых
   сигналов или свежего серверного вердикта.
3. **Не подменять `monitor`.** Guard не делает сетевых проб; активная проверка
   остаётся за `vpn monitor`/`vpn probe`.
4. **Не трогать сервисы.** Анализ не рестартит, не переключает, не «лечит».
5. **Меньше хранить.** Счётчики, окна и хэши шаблонов; сырой текст — только в
   памяти и только на время классификации.
6. **Деградировать явно.** Нет источника — `coverage.status=denied`, а не
   «всё хорошо».
7. **Демон не сетевой.** Сеть — только у явной команды `vpn guard sync`
   (одноразовый ssh), никогда у `run`.

---

## 3. Границы (scope / non-goals)

**Трогаем (клиент):**
- новый подпакет `vpnm/guard/` (WP-G0: `events.py`, `schema.py`,
  `schemas/*.schema.json`) и регистрацию `vpn guard` в `vpnm/cli.py`;
- `vpnm/guard/install.py` — user-юнит `vpn-guard.service`;
- `scripts/vpn-manager/pyproject.toml` — включить подпакет в `packages`;
- тесты `tests/guard/`, фикстуры-корпус;
- `doc/vpn-manager.md`, `README.md` клиента (живые доки клиента).

**Трогаем (сервер, минимально):**
- эта спека + запись в `docs/team/STATUS.md`;
- при принятии — `docs/adr/ADR-014-*.md`;
- опционально (после полевых данных) — §1.12 `CENSORSHIP-PATTERNS.md` с
  де-идентифицированными клиентскими наблюдениями.

**Не трогаем:**
- `vds logs`, `src/logs/**`, правила T-01…T-23 и серверные таймеры;
- `probe-watch`/`probe-response`, lock-443 и UFW;
- runtime xray/hysteria2/amneziawg, их конфиги и loglevel (см. §4.3);
- `vpn monitor`, `vpn doctor`, `vpn repair`, `vpn speed`, `vpn probe` —
  поведение и JSON-контракты;
- packets/pcap/eBPF (нужен root; серверный log-forensics уже владеет темой);
- LLM/ML, отправку логов и телеметрии куда-либо;
- автоматические действия (авто-рестарт/авто-переключение) — отдельный ADR
  после ≥ 30 дней полевых данных;
- Windows/macOS, system-wide multi-user режим.

**Транспортный охват v1.** Guard наблюдает **все три** боевых клиентских
канала: user-space профили `vpnm-<profile>.service` (Xray, Hysteria2) и
kernel-туннель **AmneziaWG** (`vpn-awg-split@<name>.service` / `awg-quick@*`,
сплит-DNS — `dnsmasq`). Последний не пишет app-логов вообще, поэтому
наблюдается двумя источниками: lifecycle/state системного журнала (S2) и
world-readable счётчиками
`/sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes}` (S3, poll 1 с).
Если активен только AWG, guard **не** уходит в `idle` (§8.1).

---

## 4. Модель наблюдаемости клиента

### 4.1. Что клиент видит, а что нет

| Отказ / поведение ТСПУ | Что видно клиенту | Источник | Правило |
|---|---|---|---|
| RST-инъекция после handshake | reset/EOF, часто сразу после успешного handshake | app-log | G-02, G-03 |
| Data-phase freeze (TCP) | handshake ok → нет данных → read timeout / reconnect loop | app-log + systemd | G-03, G-11 |
| Silent ClientHello drop | TCP connect ok → TLS/QUIC stall → timeout | app-log | G-09 (`tls_stall`) |
| UDP response drop (Hy2) | QUIC handshake ok → idle timeout → повторный handshake | app-log | G-04 |
| UDP-блэкаут на AWG | tx растёт (клиент шлёт), rx почти не растёт; app-логов нет by design | sysfs counters | G-04 (ветка `awg_tx_no_rx`) |
| L3-ACL по IP | dial timeout на IP:port; иногда ICMP проходит | app-log | G-09 |
| DNS-подмена/отравление | SERVFAIL/NXDOMAIN на заведомо живом имени | app-log + system | G-06 |
| Whitelist-режим | все не-RU эндпоинты молчат; прямой канал жив | косвенно | G-09 + coverage `blind` |
| Локальная сеть | `network unreachable`, нет default route, Wi-Fi down | app-log + netlink | G-07 |
| Локальный сбой клиента | unit exit/flap, OOM, нет бинаря | systemd | G-10 |
| Ошибка конфига/кредов | `auth_fail`, cert error | app-log | G-05, G-08 |
| Серверный lock-443 | клиент видит те же reset/timeout, но это **ожидаемо** | server-verdict | merge (§9.3) |
| Собственные пробы (`monitor`/`speed`) | короткие соединения/обрывы | командные маркеры | FP-guard |

### 4.2. Стадии: клиентский `stage_hint` ↔ серверные T-правила

Единый словарь нужен, чтобы клиентское и серверное наблюдение склеивались
без перевода. `stage_hint` — **гипотеза клиента**, не вердикт.

| `stage_hint` | Клиентское наблюдение | Серверный аналог |
|---|---|---|
| `pre_handshake` | dial timeout / connect refused, handshake не начинался | T-19 (client SYN без ClientHello), T-23 (L3) |
| `tls_stall` | TCP connect ok, TLS/QUIC молчит, timeout | T-19 (silent ClientHello drop) |
| `post_handshake` | handshake ok, соединение закрылось без данных | T-18 (RST injection) |
| `data_phase` | handshake ok, данные идут/должны идти, затем freeze/reset | T-01 (data-phase blackhole), T-22 (sendq) — серверная сторона |
| `udp_response` | QUIC handshake ok, ответы не приходят, idle timeout | T-21 (UDP response blackhole) |
| `l3_silence` | молчит весь IP, включая соседние порты (если видны) | T-23 (L3 ACL) |
| `local` | route/DNS/unit/конфиг | T-09/T-10 (локальный сбой, но на сервере) |

Чего у клиента **нет** by design: T-20 (sweep соседних портов) и T-22
(sendq freeze) — это серверные наблюдения. Guard не изобретает их из логов.

### 4.3. Слепота app-логов (честно)

При default loglevel Xray/Hysteria2 не логируют каждое соединение и тем более
payload. Поэтому:

- системные сигналы (`unit_start/stop/exit/restart`) доступны **всегда**;
- app-сигналы (`handshake_ok`, `conn_reset`, `idle_timeout`) доступны
  **настолько, насколько их печатает текущий loglevel**;
- если unit active, трафик ожидается, но за 10 минут нет ни одного
  app-сигнала — coverage получает `app_signal=blind`, G-12 пишет
  `observability` (не «всё хорошо»);
- менять loglevel — **не задача guard** (не трогаем конфиги). В `sources`
  печатается подсказка, решение — за пользователем.

Это прямое продолжение принципа log-forensics: «отсутствующий источник — это
`missing`, а не норма».

**AmneziaWG — отдельная честность.** `awg-quick`/`vpn-awg-split@` не печатают
ни handshake, ни per-connection событий; `awg show` требует root, поэтому guard
его не вызывает. Единственный сигнал — счётчики интерфейса (world-readable).
Отсюда: `coverage.signals.amneziawg = counters` (не `blind`, но и не `ok`), а
`app_signal=blind` для AWG **не** блокирует G-04-ветку `awg_tx_no_rx` —
отсутствие app-логов там by design, а не слепота.

---

## 5. Архитектура

### 5.1. Схема

```text
 ~/.config/systemd/user/vpnm-<profile>.service   (xray | hysteria2)
        │ stdout/stderr
        ▼
   journald (user) ──journalctl --user -f -o json─────┐
   journald (system, best-effort) ────────────────────┤
     awg-quick@*, vpn-awg-split@*, dnsmasq ───────────┤
   ~/.local/share/vpn-manager/logs/repair-*.log ──────┤
   state.json / last-speed.json / verdict.json ───────┤
   /sys/class/net/<iface>/statistics/{rx,tx}_bytes ───┤
   ip -o monitor route (opt-in) ──────────────────────┘
                                                      │ bounded queue (10k)
                                                      ▼
                                          ┌───────────────────┐
                                          │ normalize + redact│
                                          │ structured-first  │
                                          └─────────┬─────────┘
                                                    ▼
                                          ┌───────────────────┐
                                          │ windows / state   │  ring buffers,
                                          │ per unit+endpoint │  monotonic time
                                          └─────────┬─────────┘
                                                    ▼
                                          ┌───────────────────┐
                                          │ rules G-01…G-12   │  fixed order,
                                          │ + FP guards       │  5 s ticker
                                          └─────────┬─────────┘
                                                    ▼
                                          ┌───────────────────┐
                                          │ correlate/score   │  incidents,
                                          │ + server verdict  │  confidence merge
                                          └─────────┬─────────┘
                                                    ▼
                        ┌───────────────────────────┴────────────────────┐
                        ▼                                                ▼
              findings.jsonl (0600, rotate)                 journal stdout + notify-send
                                                             (desktop — opt-in)
```

### 5.2. Почему streaming, а не polling

| Подход | Задержка | Пропуски/дубли | CPU | Решение |
|---|---|---|---|---|
| `journalctl -n 200` каждые 10 с | 0–10 с | дубли, окна теряются | низкий | отклонено |
| `journalctl --since` по cron | минуты | зависит от расписания | низкий | отклонено (это batch) |
| `journalctl -f -o json` | миллисекунды | нет (курсор) | низкий | **выбрано** |
| tail файлов приложения | 1 с | ротация/inode | низкий | только как вторичный источник |
| inotify на `/var/log` | мс | не покрывает journald | — | неприменимо |

### 5.3. Процессная модель

- **main** — оркестрация, 5-секундный тикер для absence-правил, graceful
  shutdown по SIGTERM/SIGINT (закрыть readers, сбросить state, exit 0).
- **reader threads** — по одному на источник; читают stdout `journalctl`
  или файл, кладут `RawLine` в `queue.Queue(maxsize=10000)`.
- **counter poller** — один общий поток на 1 с читает
  `state.json`/`last-speed.json`/`verdict.json`/`sysfs`-счётчики AWG по
  `mtime+size` (или прямым `read_text` для sysfs); эмитит синтетические
  `RawLine` с `source=state|sysfs`.
- **analyzer thread** — единственный потребитель; порядок событий
  `(mono_us, source_seq)`; reorder-буфер 100 мс для склейки источников.
- **sink** — буферизованная запись findings/state, flush раз в 1 с и на
  shutdown; ротация по размеру.
- Никакого asyncio: блокирующее чтение pipe в отдельных потоках проще и
  детерминированнее; GIL не мешает (I/O-bound).

### 5.4

> Ревью G2: `events.py` — ЕДИНЫЙ файл (реестр констант И dataclasses);
> ниже в таблице упоминается один раз с обеими ролями.. Раскладка кода (клиент)

```text
scripts/vpn-manager/
├── vpnm/guard/
│   ├── __init__.py
│   ├── events.py     # реестр констант: сигналы, правила, enum'ы (frozen v1)
│   ├── schema.py     # загрузка схем, canonical JSON, schema_hash, валидатор
│   ├── schemas/      # канонические guard.*/1 JSON-схемы (package-data)
│   ├── cli.py        # typer: guard run|status|findings|explain|rules|sources|sync|install|export|selftest
│   ├── reader.py     # journalctl/file/netlink readers, cursor, backoff
│   ├── counters.py   # sysfs-поллер AWG (rx/tx bytes), iface discovery
│   ├── parse.py      # journal JSON, structured-first, сигналы, шаблоны
│   ├── redact.py     # маскирование до записи, пост-сканер
│   ├── events.py     # dataclasses + валидация guard.event/1
│   ├── window.py     # окна, sequence/absence/count, GC
│   ├── rules.py      # G-01…G-12, фиксированный порядок
│   ├── correlate.py  # инциденты, suppression, confidence merge
│   ├── store.py      # findings.jsonl, state.json, coverage, retention
│   ├── report.py     # human/JSON, explain
│   ├── verdict.py    # чтение server-verdict.json (без сети)
│   └── install.py    # vpn-guard.service, install/uninstall, undo-журнал
└── tests/guard/      # фикстуры-корпус, golden, property
```

`pyproject.toml`: `packages = ["vpnm", "vpnm.guard", "vpnm.guard.schemas"]` +
`[tool.setuptools.package-data] "vpnm.guard.schemas" = ["*.json"]` — иначе
`vpn guard` работает из исходников и падает после `pip install` (нет схем →
нет `schema_hash`/`selftest`). Это отдельный AC (AC-12).

---

## 6. Источники и чтение

### 6.1. S1 — пользовательский журнал (основной)

```text
journalctl --user -f -o json --since -2m \
  --output-fields=MESSAGE,PRIORITY,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP,\
__CURSOR,_SYSTEMD_USER_UNIT,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID,_COMM,\
UNIT,JOB_TYPE,JOB_RESULT,EXIT_CODE,EXIT_STATUS,MESSAGE_ID,\
_SYSTEMD_INVOCATION_ID,INVOCATION_ID
```

- читается **весь** user-journal, фильтрация в процессе:
  `unit = _SYSTEMD_USER_UNIT or UNIT`, `unit.startswith("vpnm-")` (юнит
  профиля) — так новые профили подхватываются без перезапуска reader'а;
- `vpn-guard.service` исключён по имени (нет самопоедания);
- `--output-fields` уменьшает объём и поверхность приватности;
- `--since -2m` только на старте: контекст для absence-правил;
- `__CURSOR` сохраняется после обработки — рестарт продолжает без дублей;
- юниты `vpnm-*` не задают `StandardOutput`, поэтому stdout/stderr Xray и
  Hysteria2 по умолчанию попадают именно в user-journal — отдельный файл
  приложения не нужен;
- если `journalctl` не понимает `--output-fields` (старый systemd), reader
  повторяет запуск без флага и фиксирует `coverage.note`; поля фильтруются
  уже в Python.

### 6.2. S2 — системный журнал (best-effort)

```text
journalctl -f -o json \
  -u cloudflared-proxy-dns -u zapret -u dnsmasq -u systemd-resolved \
  -u NetworkManager -u 'awg-quick@*' -u 'vpn-awg-split@*' \
  --output-fields=...
```

- `dnsmasq` — резолвер сплита AmneziaWG (`/etc/dnsmasq.d/awg-split.conf`,
  `127.0.0.1` → `cloudflared #5053`); без него G-06 на AWG-профиле слепнет;
- `awg-quick@*` / `vpn-awg-split@*` — kernel-туннель AmneziaWG: lifecycle,
  `unit_start/stop/exit`, ошибки `awg-quick up` (занятый iface, битый конфиг).
  Юниты системные, поэтому извлекаются по `UNIT`/`_SYSTEMD_UNIT`, не по
  `_SYSTEMD_USER_UNIT`; `-u` принимает glob, отдельные `-u` на каждый инстанс
  не нужны;
- без членства в `systemd-journal`/`adm` чтение может быть запрещено:
  `coverage.status=denied`, guard продолжает работу, `sources` печатает
  точную причину и **не** предлагает sudo-действие от имени guard;
- включается флагом `sources.system_journal=true` (по умолчанию `false`:
  минимум привилегий, user-журнала достаточно для Xray/Hy2). **Исключение —
  AWG:** если `counters.py` обнаружил активный `awg-quick@*`/
  `vpn-awg-split@*`, а системный журнал запрещён, `coverage.note` явно
  сообщает `awg_lifecycle_unobservable`, но счётчики (S3) работают всегда;
- `vpn guard install` проверяет членство в группе `systemd-journal` и, если
  оно есть, предлагает включить `system_journal=true` (не включает молча).

### 6.3. S3 — файлы состояния и отчётов (structured)

| Файл | Что читаем | Зачем |
|---|---|---|
| `~/.config/vpn-manager/state.json` | `active`, `sysproxy` | ключ группировки, FP-guard «команда пользователя» |
| `~/.local/share/vpn-manager/last-speed.json` | `channels[].speed_mbps`, `finished` | G-11 (деградация) |
| `~/.local/share/vpn-manager/logs/repair-*.log` | только строки `DNS:`/итог действия | контекст `last_repair_at`, не источник findings |
| `~/.local/share/vpn-manager/server-verdict.json` | allowlist полей (§13) | кросс-vantage merge |
| `~/.local/share/vpn-manager/guard/activity.json` | `{cmd, started, until}` | маркер активной пробы (`monitor`/`probe`/`speed`) — FP-guard |
| `/sys/class/net/<iface>/statistics/rx_bytes`, `tx_bytes` | монотонные счётчики AWG | G-04 ветка `awg_tx_no_rx`; `iface` = инстанс `vpn-awg-split@<name>`, не хардкод `awg0` |

Все файлы пишутся атомарно существующим кодом; guard читает только при
изменении `mtime+size`, ошибка разбора → `coverage.note`, без падения.

**Обнаружение AWG-интерфейса (без `systemctl` и без root).** Приоритет
источников, все read-only:

1. имя инстанса из lifecycle-события S2 (`vpn-awg-split@<name>` →
   `iface=<name>`, `awg-quick@<name>` → `iface=<name>`);
2. скан `/sys/class/net/*/type` и отбор `ARPHRD_NONE` (65534) — так выглядят
   wireguard-подобные туннели; `lo` и интерфейсы, уже занятые профилем,
   исключаются;
3. если найдено > 1 кандидата — `coverage.note=awg_iface_ambiguous` и
   выбирается тот, у которого растёт `tx_bytes`; при полном отсутствии
   кандидатов G-04-ветка выключена, `coverage.signals.amneziawg=missing`.

`awg show` и любой `sudo` **не используются** (R-4): всё, что нужно, — два
64-битных счётчика.

### 6.4. S4 — netlink (opt-in, v1.1)

`ip -o monitor route` (без root) даёт `route_change_ts` для FP-guard G-07/
G-04. По умолчанию выключен: источник полезен только на ноутбуках с
переключением Wi-Fi/ethernet. Если включён — юниту нужен
`RestrictAddressFamilies=AF_UNIX AF_NETLINK`.

### 6.5. Курсоры, backfill, рестарт

- после каждого обработанного батча сохраняется `last_cursor` (по источнику);
- рестарт: `journalctl --after-cursor=<cursor>`; невалидный/протухший курсор
  → fallback `--since -2m` + дедуп по `__CURSOR`;
- state пишется атомарно (`tmp` + `os.replace`, 0600) не чаще раза в 5 с;
- backfill ограничен: `--since` максимум 24 ч (иначе отказ с подсказкой),
  память окон не зависит от длины backfill (ring buffers).

### 6.6. Health источников

```json
{
  "schema": "guard.coverage/1",
  "sources": [
    {"name": "journal:user", "status": "ok", "last_event_ts": "...", "lag_ms": 120},
    {"name": "journal:system", "status": "denied", "note": "нет прав на системный журнал"},
    {"name": "state", "status": "ok"},
    {"name": "sysfs:awg", "status": "ok", "note": "iface=laptop"},
    {"name": "netlink", "status": "off"}
  ],
  "signals": {"xray": "ok", "hysteria2": "blind", "amneziawg": "counters",
              "systemd": "ok", "dns": "ok"},
  "unparsed_ratio": 0.02,
  "dropped": 0,
  "blind": ["whitelist_mode_unobservable"]
}
```

`status` источника: `ok | degraded | denied | off | lost`. `lost` — процесс
reader'а умер и backoff ещё не восстановил; G-12.

---

## 7. Нормализация

### 7.1. Канонический Event (v1)

```json
{
  "schema": "guard.event/1",
  "ts": "2026-11-16T12:00:03.412Z",
  "mono_us": 812345678,
  "source": "journal:user",
  "unit": "vpnm-asv2.service",
  "profile": "asv2",
  "proto": "hysteria2",
  "level": "warn",
  "signal": "quic_idle_timeout",
  "template": "3f9a1c02be77",
  "endpoint": {"host": "asv2.example.net", "port": 443},
  "fields": {"timeout_s": 10},
  "count": 1
}
```

Правила:

- `ts` — UTC RFC3339 с миллисекундами; окна считаются по `mono_us`
  (`__MONOTONIC_TIMESTAMP`), чтобы скачок часов не рвал окна; при отсутствии
  mono — fallback на realtime с флагом `clock_fallback=true`;
- для источников `file`/`state`/`verdict` `mono_us` синтезируется из
  wall-clock в момент чтения (точность окон — секунды, для этих сигналов
  достаточно);
- `source` — `journal:user | journal:system | file | state | sysfs | verdict`;
- `unit`/`profile` — из `_SYSTEMD_USER_UNIT` или `UNIT`; имя профиля — срез
  `vpnm-<name>.service`;
- `proto` — `xray|hysteria2|amneziawg|systemd|dns|zapret|unknown` (по
  unit/identifier/источнику: `amneziawg` — только для событий
  `awg-quick@*`/`vpn-awg-split@*` и `source=sysfs`);
- `endpoint` — только `host`/`port` из allowlist-полей сигнала; сырые строки
  с URL/путями/креды сюда не попадают;
- `template` — `sha1(нормализованная строка)[:12]`; сам текст не хранится;
- дедуп: одинаковые `(source, cursor)` отбрасываются; события одного
  `(unit, signal, endpoint)` в пределах 100 мс схлопываются с `count>1`;
- лимит: ≤ 10 000 событий в очередях и ≤ 256 событий на окно правила;
  превышение — drop-oldest + счётчик `dropped` (сначала `info`, потом `warn`).

### 7.2. Каталог сигналов

Сигналы — **стабильные имена**, а не тексты. Маппинг «regex/поле → сигнал»
живёт в корпусе и версионируется.

| Группа | Сигналы |
|---|---|
| lifecycle | `unit_start`, `unit_stop`, `unit_exit`, `unit_restart_scheduled`, `job_failed` |
| app-boot | `app_banner_ok` (стартовый баннер Xray/Hysteria2; доказывает «приложение живо», но не трафик — §8.3) |
| TCP | `dial_start`, `tcp_connected`, `tls_handshake_ok`, `handshake_ok`, `conn_established`, `conn_closed`, `conn_reset`, `conn_eof`, `dial_timeout`, `conn_refused`, `address_in_use`, `network_unreachable`, `no_route` |
| QUIC | `quic_handshake_ok`, `quic_handshake_fail`, `quic_idle_timeout`, `quic_no_recent_activity` |
| auth | `auth_ok`, `auth_fail` |
| DNS | `dns_lookup_fail`, `dns_timeout`, `dns_servfail`, `dns_nxdomain` |
| TLS | `tls_cert_error`, `tls_alert`, `tls_stall` |
| perf | `read_timeout`, `write_timeout`, `slow_consumer` |
| counters (AWG) | `awg_tx_growth`, `awg_rx_flat`, `awg_iface_gone` |
| self | `unparsed`, `source_lost`, `clock_skew`, `no_signal_window` |

Порядок разбора:

1. **structured-first**: `UNIT`+`JOB_TYPE`/`JOB_RESULT` для systemd
   (не зависит от локали), `EXIT_CODE/EXIT_STATUS` для `unit_exit`;
2. **app-regex**: Xray/Hysteria2 (англоязычные, C-locale) — упорядоченный
   список семейств, first match wins;
3. **fallback**: `unknown` → инкремент `unparsed`, хэш шаблона; не finding,
   кроме G-12 (всплеск).

Derived-сигналы — их не печатает ни один демон:

- `tls_stall` — был `tcp_connected`, но за `tls_stall_s` (default 10 с) нет
  `tls_handshake_ok` (классический клиентский след silent ClientHello drop);
- `no_signal_window` — unit active и ожидается трафик, но за 10 мин нет
  ни одного app-сигнала → `coverage.app_signal=blind` + G-12, без выдумывания
  findings;
- `awg_tx_growth` — за `awg_window_s` (default 120 с) `tx_bytes` вырос
  ≥ `awg_tx_min_bytes` (default 262144, т.е. ~2 КБ/с);
- `awg_rx_flat` — за то же окно `rx_bytes` вырос < `awg_rx_ratio`
  (default 0.05) от прироста `tx_bytes`, при `awg_tx_growth`;
- `awg_iface_gone` — интерфейс, который был активен, исчез из
  `/sys/class/net` (down/удалён) — G-10/G-07, не G-04.

Пример семейства (не контракт, а иллюстрация подхода):

```python
# vpnm/guard/parse.py (фрагмент каталога)
("quic_idle_timeout", re.compile(r"\b(?:no recent network activity|"
                                 r"idle timeout|timeout: no recent)\b", re.I)),
("conn_reset",        re.compile(r"\b(?:connection reset|ECONNRESET|"
                                 r"reset by peer)\b", re.I)),
("dial_timeout",      re.compile(r"\b(?:i/o timeout|dial timeout|"
                                 r"context deadline exceeded)\b", re.I)),
```

Точные шаблоны фиксируются golden-корпусом под версии Xray/Hysteria2;
несовпадение версии → `unparsed`, а не «тихо всё хорошо».

### 7.3. Redaction (до записи)

Область применения: **свободный текст** (`MESSAGE`, app-строки) и строковые
значения в `fields`, **кроме** структурного allowlist (см. ниже). Ключи и
значения самого контракта (`schema`, `schema_hash`, `rules_hash`,
`config_hash`, `raw_sha256`, `template`, `id`, `evidence_hash`) — не текст
и не редактируются.

| Что | Замена | Когда |
|---|---|---|
| UUID | `<uuid>` | всегда (текст) |
| hex ≥ 32, base64 ≥ 24 | `<blob>` | всегда (текст) |
| `password`, `obfs-password`, `auth`, `privateKey`, `publicKey`, `shortId`, `shortIds` | `<redacted>` | всегда |
| `vless://`, `hysteria2://`, `ss://`, `trojan://` | `<link>` | всегда |
| URL с userinfo, query-токены | `<url>` | всегда |
| email | `<email>` | всегда |
| домен/IP эндпоинта | остаётся локально; в `export` → `<host>` | `export` по умолчанию |
| текст строки | не сохраняется | всегда |

**Пост-сканер секретов (перед записью finding и перед `export`).**
Сериализованный JSON обходится по ключам и значениям, и проверка устроена так,
чтобы **не срабатывать на собственный контракт**:

- значения под ключами `*_hash`, `*_sha256`, `template`, `id`,
  `evidence_hash`, `schema`, `rule`, `signal`, `category`, `stage_hint`,
  `incident_id` исключены из проверки;
- строка вида `sha256:[0-9a-f]{64}` или ровно `[0-9a-f]{64}` в
  allowlist-ключе — **не** секрет;
- проверяются только: `evidence[].snippet` (если сниппеты включены),
  свободные строки `fields`, `hypothesis`/`action`/`alternatives`,
  `coverage.note`;
- при совпадении: finding пишется **без сниппета** (`snippet` отброшен,
  `redaction_hits` инкрементится) + `[warning]`; `export` блокируется с
  кодом 2 и списком полей (не значений);
- для `export` дополнительно: `--keep-hosts=false` заменяет хосты на
  `<host>`, а `manifest.json` не содержит ни одного значения из
  проверяемых полей.

Тот же сканер прогоняется в тесте AC-6 по корпусу `FIXTURE_*`; эталонный
finding с `schema_hash`/`rules_hash` обязан пройти без единого хита
(AC-13).

### 7.4. Шаблоны и unparsed

- нормализация строки: `UUID→<uuid>`, `IPv4/IPv6→<ip>`, `числа→<n>`,
  `hex≥16→<hex>`, `/path/…→<path>`, `"…"→<str>`, `email→<email>`,
  `домен→<domain>`;
- `sha1(template)[:12]` — единственное, что хранится от текста;
- `unparsed_ratio` = unparsed / все app-строки за 5 мин;
  > 30% при ≥ 200 строках → G-12 `observability` (low), подсказка обновить
  каталог сигналов/проверить версию клиента.

---

## 8. Правила G-01…G-12

### 8.1. Общая модель

- ключ состояния: `(unit, endpoint, profile)`; одновременно могут работать
  несколько юнитов (активный профиль + CDN/резерв) — это норма, а не конфликт;
- `idle` наступает только если **нет ни одного канала**: ни `vpnm-*`, ни
  AWG-интерфейса в `/sys/class/net`, ни активного lifecycle
  `vpn-awg-split@*`/`awg-quick@*`. Если AWG-интерфейс есть, но трафика нет —
  это `armed` (не `idle`): счётчики продолжают читаться, G-04-ветка ждёт
  `awg_tx_growth`, `status` показывает `amneziawg=quiet`. Живой AWG в
  `idle` — это баг: основной канал ноутбука именно AWG (R-11);
- окна: `count` (N за T), `sequence` (A→B за ≤ Δ), `absence` (нет B за T),
  `ratio` (доля сигнала);
- окна на монотонном времени; тикер 5 с добивает absence-правила;
- гистерезис: fire после `confirm_windows` (default 2) подряд; resolve после
  `quiet_windows` (default 3) без повторов;
- dedup: ключ `rule|unit|endpoint|cause`; повтор в пределах `cooldown_s`
  (300 с) увеличивает `count`/`last_ts`, но не создаёт новый finding и не
  уведомляет;
- глобальный cap: 12 уведомлений/час; превышение — `suppressed` счётчик;
- severity (`info|low|medium|high`) и confidence (`low|medium|high`) —
  независимы; finding с `severity=high` и `confidence=low` не уведомляется;
- порядок правил фиксирован по ID; findings сортируются
  `(window_start, rule, evidence_hash)`;
- ID finding: `sha256(rule|unit|endpoint|window_start)[:12]`.

Пороговые значения по умолчанию (все — в `guard.json`, без произвольных
regex):

| Параметр | Default | Смысл |
|---|---|---|
| `handshake_timeout_s` | 25 | absence после старта unit |
| `startup_banner_s` | 15 | окно для `app_banner_ok` (G-01) |
| `reset_storm_count` | 3 / 60 с | G-02 |
| `post_handshake_drop_count` | 3 / 120 с, drop ≤ 5 с | G-03 |
| `udp_blackhole_count` | 2 / 10 мин | G-04 |
| `auth_fail_count` | 1 (и нет `auth_ok` 5 мин) | G-05 |
| `dns_fail_count` | 2 / 60 с | G-06 |
| `endpoint_silent_count` | 5 / 10 мин | G-09 |
| `unit_flap_count` | 3 / 10 мин | G-10 |
| `degraded_mbps` | 2.0 | G-11 (как в `probe.DEGRADED_MBPS`) |
| `awg_window_s` | 120 | окно счётчиков AWG (G-04 ветка) |
| `awg_tx_min_bytes` | 262144 | порог «клиент реально шлёт» (~2 КБ/с) |
| `awg_rx_ratio` | 0.05 | rx/tx ниже этого = ответы не приходят |
| `cooldown_s` | 300 | dedup/notify |
| `confirm_windows` / `quiet_windows` | 2 / 3 | гистерезис |

**Командные маркеры (FP-guard верхнего уровня).** Guard отличает действие
пользователя от аварии по паре «lifecycle + state.json», без вызова
systemctl:

- `unit_stop`/`unit_exit` с кодом 0 **и** `state.json.active=null` (±5 с) →
  `cause=vpn_down` (штатно, high-правила подавлены);
- `unit_start` **и** смена `active` (±60 с) → `cause=vpn_up`/`vpn_switch`;
- `unit_exit` с ненулевым кодом **или** `unit_restart_scheduled` при
  неизменном `active` → авария (G-10);
- backfill без lifecycle-событий не считается «только что запущен» — G-01
  не стреляет по пустоте.

`status --json` отдаёт `last_lifecycle = {signal, ts, cause}`, чтобы
AC-1 можно было проверить без чтения журнала.

### 8.2. Каталог

| ID | Правило | Триггер | Sev | Категория / stage | FP-guard |
|---|---|---|---|---|---|
| G-01 | `no_handshake_after_start` | `unit_start`; покрытие доказано (`app_banner_ok` ≤ 15 с **или** `dial_start/dial_timeout/conn_refused` ≤ 25 с), но за 25 с нет `handshake_ok/conn_established/quic_handshake_ok` | high (только при доказанном покрытии) | `tunnel_down` / `pre_handshake` | команда `vpn up/switch` ≤ 60 с; `network_unreachable`; штатный stop; **нет ни banner, ни dial → `insufficient_data`, не finding** |
| G-02 | `reset_storm` | ≥ 3 `conn_reset/conn_eof` за 60 с на одном endpoint, при наличии `handshake_ok` за 10 мин | high | `censorship_suspect` / `post_handshake` | свои пробы; `vpn down/switch`; `auth_fail`; unit flap |
| G-03 | `post_handshake_drop` | ≥ 3 циклов `handshake_ok → reset/eof/idle` за 120 с, разрыв ≤ 5 с после handshake | high | `censorship_suspect` / `data_phase` | свои пробы; рестарт сервера/клиента; `slow_consumer`; lock-443 → `expected_lockdown`/info |
| G-04 | `udp_response_blackhole` | Hy2: `quic_handshake_ok`, затем ≥ 2 `quic_idle_timeout/no_recent_activity` за 10 мин, handshake повторно успешен. AWG-ветка `awg_tx_no_rx`: `awg_tx_growth` + `awg_rx_flat` в 2 окнах подряд | high | `censorship_suspect` / `udp_response` | нет трафика (idle), suspend/roaming, route change ± 90 с, `auth_fail`, `awg_iface_gone` |
| G-05 | `auth_failure` | `auth_fail` и нет `auth_ok` 5 мин, или ≥ 3 `auth_fail` за 5 мин | high | `config` / `pre_handshake` | серверный lock-443 (не auth); неверный профиль после pull — всё равно config |
| G-06 | `dns_broken` | ≥ 2 `dns_lookup_fail/dns_timeout/dns_servfail` за 60 с, или SERVFAIL на ≥ 2 разных именах | high | `dns` / `local` | `network_unreachable`/нет route → понижение до G-07; DoH выключен штатно — всё равно finding |
| G-07 | `local_network_down` | `network_unreachable/no_route`, удаление default route, Wi-Fi disconnect | high | `local_net` / `local` | VPN выключен (`active=null`), плановое переключение сети |
| G-08 | `tls_cert_error` | `tls_cert_error` и нет успешного TLS 5 мин | high | `config` / `tls_stall` | Reality (сертификат назначения), собственные пробы, системное время |
| G-09 | `endpoint_silent` | ≥ 5 `dial_timeout/tls_stall/conn_refused/conn_reset` (до handshake) на один host:port за 10 мин, 0 `handshake_ok` | medium (timeout) / high (refused) | `endpoint_unreachable` / `pre_handshake` | нет dial-попыток; альтернативный канал жив; `conn_refused` → `endpoint_down`, не цензура |
| G-10 | `unit_flap` | ≥ 3 `unit_exit` (non-zero) или `unit_start` за 10 мин на один unit | high | `local_fault` / `local` | штатный `vpn down` (exit 0/stop), `vpn switch`, обновление бинаря |
| G-11 | `degraded_throughput` | `last-speed.json`: ≥ 2 подряд наблюдённых отчёта `speed_mbps < 2.0` за 24 ч, или 1 отчёт + ≥ 3 `read/write_timeout` за 5 мин | medium | `degraded` / `data_phase` | замер во время инцидента (сам speed добавил нагрузку); CDN-профиль исключён (CF не даёт bulk) |
| G-12 | `guard_selfdegraded` | источник `lost` > 60 с; unparsed > 30%; queue drops; skew > 2 с | low | `observability` / `local` | никогда не эскалируется и не уведомляется по умолчанию |

### 8.3. Ключевые правила подробнее

**G-02 `reset_storm`.** Клиент не отличает RST от локального close по
тексту; поэтому решение принимается по **паттерну**: успешный handshake был,
затем серия reset/EOF в узком окне, без `auth_fail`, без unit-flap, без
команд пользователя. Если разрывы приходятся на первые 5 с после handshake —
это усиливает G-03 (data-phase), а не просто «сеть шумит». Если RST идут
**до** handshake — это G-09 (`pre_handshake`), не G-02.

**G-03 `post_handshake_drop`.** Главный клиентский fingerprint
data-phase-воздействия: handshake проходит, следом тишина/сброс. Требования
к доказательствам:

- ≥ 3 полных цикла в 120 с (не единичный обрыв);
- каждый разрыв ≤ 5 с после успешного handshake;
- нет `unit_exit`/`unit_restart_scheduled` в окне;
- нет `auth_fail`/`tls_cert_error`;
- нет активного lock-443 в свежем server-verdict.

Confidence: `medium` по умолчанию; `high`, если свежий серверный
`threat_level=high`/`stage=data_phase`, либо паттерн повторился в ≥ 2 окнах
подряд. В `alternatives` всегда перечисляются «рестарт сервера» и «локальный
краш клиента», даже при high.

**G-04 `udp_response_blackhole`.** Hy2-специфично: QUIC handshake — это
несколько RTT, и он может проходить, пока ответные данные дропаются. Правило
не срабатывает на «клиент просто молчал»: нужен признак ожидания трафика
(повторный `dial_start`/`quic_handshake_ok` после idle timeout) либо запись
`slow_consumer`/`read_timeout`. Роуминг и suspend — стоп-факторы.

**G-04, ветка AWG (`awg_tx_no_rx`).** У AmneziaWG app-логов нет вообще,
поэтому доказательство строится только на счётчиках (§6.3), а «слепота
app-логов» здесь by design и не блокирует правило. Условия:

- `awg_tx_growth` в **двух** окнах подряд (`awg_window_s` = 120 с), т.е.
  клиент устойчиво шлёт (≥ `awg_tx_min_bytes` за окно);
- `awg_rx_flat` — прирост `rx_bytes` < `awg_rx_ratio` от прироста `tx_bytes`
  в тех же окнах (ответов нет, хотя запросы идут);
- интерфейс существовал всё окно (`awg_iface_gone` не было), не было
  suspend/roaming и route change ± 90 с;
- `state.json.active != null` и lifecycle не `vpn_down` — иначе это штатная
  остановка или G-10.

Confidence `medium`; `high` — только с серверным подтверждением
(T-21/`threat=high`, §9.3). `alternatives` обязательно содержат «сервер
не отвечает/лежит» и «битый конфиг AWG»: по счётчикам они неотличимы от
UDP-блэкаута. Action — не рестартить; `vpn probe` по AWG; проверить
резервный канал.

**G-09 `endpoint_silent`.** Не утверждает цензуру. Если нет сравнения с
другим каналом, категория `endpoint_unreachable`, confidence ≤ medium.
Только совокупность «эндпоинт молчит + прямой/резервный канал жив + сервер
видит probing» повышает уверенность (через merge §9.3).

Внутри G-09 две ветки:

- `conn_refused` — IP достижим, но порт закрыт (сервис не запущен/упал):
  `cause=endpoint_down`, severity `high`, confidence `high`; action —
  проверить unit/порт на сервере, профиль не менять; цензура не заявляется;
- `dial_timeout`/`tls_stall` без refused — `cause=endpoint_unreachable` или
  `tls_stall` (кандидат на silent ClientHello drop), confidence ≤ medium до
  подтверждения вторым vantage;
- серия `conn_reset` **до** handshake (нет `handshake_ok` в окне) — ранний
  RST/отбой ClientHello, stage `pre_handshake`; confidence ≤ medium, пока
  серверный vantage не подтвердит probing.

**G-01 и слепота логов.** G-01 — absence-правило, поэтому без проверки
покрытия оно опасно: при default loglevel приложение может вообще не печатать
успешный handshake. Но требование «за 10 минут до старта был app-сигнал»
делает правило мёртвым при первом запуске профиля (до `unit_start` сигналов
физически нет). Поэтому условие — **наличие banner/dial после старта**:

1. `app_banner_ok` — стартовый баннер в течение `startup_banner_s`
   (default 15 с): `Xray ... started`, `Hysteria2 client mode`, строки
   версии/`listen`/`server listening`. Это отдельный сигнал (§7.2): его
   печатают обе программы независимо от loglevel, потому что это сообщение
   о запуске, а не о соединении;
2. либо `dial_start` / `dial_timeout` / `conn_refused` в течение
   `handshake_timeout_s` (25 с) после `unit_start` — приложение пытается
   соединяться, значит, оно живо и говорит.

Срабатывание — три исхода, и только один из них finding:

- **(1) или (2) есть, handshake нет** → **G-01 `tunnel_down`**, severity
  `high`, confidence `medium` (свежий серверный вердикт может поднять до
  `high`): клиент жив и говорит, соединение не устанавливается;
- **handshake есть** → правила нет (норма), `last_lifecycle.cause=vpn_up`;
- **ни (1), ни (2), ни handshake** → `coverage.signals[proto]=blind` +
  G-12 `observability`, `insufficient_data` с причиной `no_app_banner`;
  finding **не** создаётся. Это не «всё хорошо», но и не ложный
  `tunnel_down`: приложение молчит так, что доказать отказ невозможно.
  `sources` предлагает поднять loglevel (решение — за пользователем).

Проверка идёт внутри **того же инстанса** юнита (`INVOCATION_ID`) и не
оглядывается на историю до старта. Backfill без lifecycle-события по-прежнему
не считается «только что запущен» (§8.1). Важно: `app_banner_ok` доказывает
только «приложение живо», но **не** трафик — для `no_signal_window`/G-12 он
не считается app-активностью, иначе баннер маскировал бы полную слепоту.

**G-11 и история замеров.** `last-speed.json` хранит только последний отчёт,
поэтому guard держит в `state.json` кольцо из 5 последних **наблюдённых**
отчётов (`ts`, `channel`, `speed_mbps`; без URL и профильных секретов).
«2 подряд» проверяется по этому кольцу; при первом запуске истории нет →
правило ждёт второй отчёт (`insufficient_data`).

### 8.4. Взаимодействие правил (suppression)

| Активно | Эффект |
|---|---|
| G-07 `local_network_down` | все туннельные правила → `confidence=low`, `explained_by=G-07`; уведомляется только G-07 |
| G-10 `unit_flap` | G-01/G-02/G-03 для этого unit подавлены (рестарты — причина, не следствие) |
| G-05 `auth_failure` | G-02/G-03 подавлены (reset-loop из-за неверных кредов — не цензура) |
| G-08 `tls_cert_error` | G-09 не эскалируется |
| `awg_iface_gone` | G-04-ветка `awg_tx_no_rx` подавлена; событие идёт в G-10/G-07 |
| G-12 `guard_selfdegraded` | никогда не повышает confidence других правил |
| server `lockdown.active=true` | G-02/G-03/G-09 получают `expected_lockdown=true`, severity ≤ `info`, уведомление выключено |
| `activity.json` (проба идёт) | G-02/G-03/G-09 не эскалируются в пределах `±30 с`; `fp_checks+=active_probe` |

**Маркеры активности команд.** `vpn monitor`, `vpn probe` и `vpn speed` —
короткоживущие CLI, которые создают реальные соединения и могут выглядеть
как reset storm. Чтобы не гадать по `/proc`, они пишут атомарный маркер
`~/.local/share/vpn-manager/guard/activity.json`
(`{cmd, started, until}`) на время работы; guard читает его как контекст и
не эскалирует G-02/G-03/G-09. Это единственное изменение существующих
команд: без новых флагов, без изменения `--json` и вывода; запись
best-effort (ошибка/нет каталога — молча пропускается, команда работает
как раньше).

---

## 9. Корреляция, уверенность, инциденты

### 9.0.0 Контракт `schema_hash` между репозиториями (D-17, DECISION Q1)

Источник правды — клиент: `scripts/vpn-manager/vpnm/guard/schemas/schema_hashes.json`
(`schema_id → sha256:<64 hex>` + `source_commit`), обновляется только вместе с
правкой схемы. Сервер не копирует тела схем, а вендорит lock в
`docs/contracts/guard-schema-hashes.json` и проверяет:

- `tests/gateway/test_guard_verdict_contract.py` — 7 ключей, формат хэшей,
  покрытие полей `vds gateway probe-watch watch --json` (включая опциональный
  `stage`), и при заданном `VPN_MANAGER_REPO` — сверка с живым клиентом 1-в-1
  (офлайн, без сети);
- на клиенте — тест, падающий при правке схемы без обновления lock.

Транспорт через `.github/workflows` сознательно не используется: в обоих репо
каталога нет, а сеть в тестах запрещена (AGENTS §6). Когда CI появится, те же
два pytest-теста подключаются без переделки контракта.

### 9.0 Возраст серверного вердикта (ревью G2)

`finding.server` обязан нести `data_age_s` (или `window`): `fresh` по
`fetched_at` не отражает, что вердикт описывает окно возрастом до ~1 ч
(серверный тик часовой). При boost до `high` потребитель видит возраст
данных, а не только время доставки.

## 9.1. Finding (v1)

```json
{
  "schema": "guard.finding/1",
  "id": "7c1d2f0a9b3e",
  "rule": "G-03",
  "severity": "high",
  "confidence": "high",
  "category": "censorship_suspect",
  "stage_hint": "data_phase",
  "unit": "vpnm-asv2.service",
  "profile": "asv2",
  "endpoint": {"host": "asv2.example.net", "port": 443},
  "window": {"first": "2026-11-16T12:00:03.412Z",
             "last": "2026-11-16T12:01:58.901Z"},
  "count": 4,
  "evidence": [
    {"kind": "signal_count", "signal": "handshake_ok", "value": 4},
    {"kind": "signal_count", "signal": "conn_reset", "value": 4},
    {"kind": "cycle", "metric": "handshake_to_drop_s", "median": 1.2}
  ],
  "fp_checks": ["no unit_exit", "no netlink route change",
                "no auth_fail", "server verdict fresh"],
  "hypothesis": "data-phase воздействие на пути (handshake ok, данные/rst)",
  "alternatives": ["рестарт сервера", "локальный краш клиента"],
  "action": "не рестартить; vpn probe; свежие ссылки; резервный канал",
  "server": {"threat_level": "high", "stage": "data_phase",
             "age_s": 120, "fresh": true, "lockdown": false},
  "cross_vantage": true,
  "incident_id": "i-2f81c0",
  "schema_hash": "sha256:…"
}
```

`evidence` не содержит текста строк; `fp_checks` — явные выполненные
проверки (отсутствие проверки = не «прошла», а `unknown`).

### 9.2. Инцидент и корневая причина

- findings в пределах 180 с на одном unit группируются в инцидент;
- приоритет корневой причины:
  `local_net > local_fault > config > dns > endpoint_unreachable >
  censorship_suspect > degraded > observability`;
- инцидент хранит ссылки на findings, `headline`, `server`, `first/last`;
- инцидент закрывается после 10 мин без повторов (`resolved_at`), но
  остаётся в истории до TTL;
- `vpn guard status` показывает открытые инциденты, `findings` — историю.

### 9.3. Merge с сервером

| Клиент | Сервер (свежий) | Итог |
|---|---|---|
| G-03 reset storm | `threat=high`, `stage=data_phase` | confidence `high`, `cross_vantage=true` |
| G-03 reset storm | `quiet` / файл отсутствует | остаётся `medium`; note «сервер эффекта не видит — возможен SNI/DNS/локальный путь» |
| G-02/G-03/G-09 | `high` + `lockdown.active` | `expected_lockdown=true`, severity `info`, action «снять лок или подождать TTL» |
| G-07 local net | любой | `local_net` high; серверный high **не** повышает и не переклассифицирует |
| только G-09 | `quiet` | `endpoint_unreachable`, не «цензура» |
| нет клиентских findings | `high` | guard ничего не создаёт (не выдумывает наблюдения) |

Свежесть: `fetched_at` ≤ **65 мин** (серверный `vds-probe-watch.timer` тикает
раз в час, поэтому «≤ 15 мин» гарантировало бы ложный `stale` в половине
случаев); иначе `fresh=false`, boost запрещён, `coverage.note`. Реальный
охват данных виден по полю `window` вердикта — клиент не притворяется, что
знает больше сервера. Поля `top`/`ru_top` (IP третьих сторон) в клиентский
файл **не попадают** — sync фильтрует allowlist.

---

## 10. CLI, контракты, эксплуатация

### 10.1. Команды

| Команда | Что делает | Exit |
|---|---|---|
| `vpn guard run [--foreground] [--since 2m] [--once] [--json] [--quiet] [--trace]` | потоковый анализ; `--once` — обработать backfill и выйти | 0 нет high; 2 есть high; 3 ошибка конфига/источника |
| `vpn guard status [--json]` | running, uptime, источники, счётчики, открытые инциденты | 0 ok; 1 degraded; 2 high open |
| `vpn guard findings [--since 24h] [--limit 50] [--json] [--follow]` | история findings; `--follow` — хвост JSONL | 0 |
| `vpn guard explain <id или rule>` | почему сработало: окно, сигналы, FP-проверки, что делать | 0 |
| `vpn guard rules [--json] [--verbose]` | каталог правил и порогов (rules_hash) | 0 |
| `vpn guard sources [--json] [--recheck]` | coverage: права, лаг, unparsed, слепые зоны | 0 ok; 1 degraded |
| `vpn guard sync [--host root@asv2] [--timeout 10]` | **сеть:** один ssh `vds gateway probe-watch watch --json` → `server-verdict.json` | 0/2 |
| `vpn guard install [--linger] [--sync-timer]` / `uninstall [--purge]` | user-юнит + enable; opt-in таймер sync; undo-журнал | 0/2 |
| `vpn guard export [--since 7d] [-o FILE] [--keep-hosts]` | обезличенный bundle findings+coverage, ≤ 5 МБ | 0/2 |
| `vpn guard selftest` | проверка корпуса сигналов/схем без живых логов | 0/1 |

`vpn` без аргументов (TUI) получает пункт «Guard» — опционально, WP-G5.

`export` — это `manifest.json` (`guard.bundle/1`, `rules_hash`, `sha256`),
`findings.ndjson` и `coverage.json`; сырых логов и событий в бандле нет.

`--once` обрабатывает только доступное окно (`--since`, default 2 мин) и
выходит; absence-правила, которым нужно будущее время (G-01/G-09/G-11),
в этом режиме могут вернуть `insufficient_data`, а не ложный finding.
`run` всегда foreground (демонизация — только systemd); `--foreground`
оставлен для явности.

Пример живого вывода (без секретов; `--quiet` это подавляет):

```text
[guard] 12:00:03 G-03 high/medium  vpnm-asv2  handshake→drop ×4/120s
        evidence: handshake_ok=4, conn_reset=4, median drop 1.2s
        fp: no unit_exit, no auth_fail, server fresh (high/data_phase)
        action: не рестартить; vpn probe; свежие ссылки; резервный канал
[guard] 12:00:04 incident i-2f81c0 root_cause=censorship_suspect (medium)
```

### 10.2. JSON-контракты

- `guard.event/1` — NDJSON в trace-файле (`--trace`), не в stdout;
- `guard.finding/1` — NDJSON (`run --json`, `findings --json --follow`);
- `guard.incident/1` — внутри `status --json`;
- `guard.coverage/1` — `sources --json`;
- `guard.status/1` — `status --json`;
- `guard.server_verdict/1` — файл обмена (§13);
- `guard.config/1` — файл конфига (§10.3).

Канонические файлы схем — `scripts/vpn-manager/vpnm/guard/schemas/`
(7 файлов, package-data), реестр enum'ов — `vpnm/guard/events.py`,
`schema_hash` считает `vpnm/guard/schema.py` (canonical JSON: sorted keys,
compact separators, UTF-8).

Версионирование: поле `schema`; в пределах major — только аддитивные поля;
потребитель обязан игнорировать неизвестные ключи. `schema_hash` — sha256
канонического JSON-схемного файла, печатается в `rules --json` и finding.

Пример `guard.status/1`:

```json
{
  "schema": "guard.status/1",
  "running": true,
  "pid": 4242,
  "since": "2026-11-16T10:00:00Z",
  "rules_hash": "…",
  "config_hash": "…",
  "sources_ref": "coverage.json",
  "last_event_ts": "2026-11-16T12:01:58.901Z",
  "last_lifecycle": {"signal": "unit_stop", "ts": "2026-11-16T12:02:00Z",
                     "cause": "vpn_down"},
  "counters": {"events": 1234, "unparsed": 2, "dropped": 0, "findings": 3},
  "open_incidents": []
}
```

### 10.3. Пути, конфиг, retention

| Артефакт | Путь | Права | TTL/лимит |
|---|---|---|---|
| findings | `~/.local/share/vpn-manager/guard/findings.jsonl` | 0600 | 14 дней, 5 × 4 МБ |
| state | `~/.local/share/vpn-manager/guard/state.json` | 0600 | ≤ 64 КБ |
| coverage | `~/.local/share/vpn-manager/guard/coverage.json` | 0600 | перезапись |
| install undo | `~/.local/share/vpn-manager/guard/install-state.json` | 0600 | до uninstall |
| конфиг | `~/.config/vpn-manager/guard.json` | 0600 | — |
| юнит | `~/.config/systemd/user/vpn-guard.service` | 0644 | — |
| trace (opt-in) | `~/.local/share/vpn-manager/guard/trace.ndjson` | 0600 | 1 час, ≤ 10 МБ |

Конфиг — только пороги/флаги, **без пользовательских regex** (детерминизм и
безопасность):

```json
{
  "schema": "guard.config/1",
  "sources": {"user_journal": true, "system_journal": false,
              "files": true, "awg_counters": true,
              "netlink": false, "server_verdict": true},
  "notify": {"desktop": false, "min_severity": "high"},
  "redact": {"hosts_in_export": true, "snippets": false},
  "thresholds": {"handshake_timeout_s": 25, "startup_banner_s": 15,
                 "reset_storm_count": 3,
                 "post_handshake_drop_count": 3, "udp_blackhole_count": 2,
                 "awg_window_s": 120, "awg_tx_min_bytes": 262144,
                 "awg_rx_ratio": 0.05,
                 "cooldown_s": 300},
  "retention_days": 14
}
```

### 10.4. systemd user unit

Имя — **`vpn-guard.service`**, не `vpnm-guard.service`: `runners.enabled_vpnm_units()`
трактует любой `vpnm-*.service` как профиль, и `vpn autostart off` / `vpn down`
могли бы отключить сам guard (реальный конфликт имён, найден при анализе
кода). Суффикс `vpn-` такой коллизии не даёт.

```ini
[Unit]
Description=VPN guard — real-time client log analysis

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m vpnm guard run --foreground --quiet
Restart=on-failure
RestartSec=10
Nice=10
MemoryMax=128M
CPUQuota=10%
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=%h/.local/share/vpn-manager/guard
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vpn-guard

[Install]
WantedBy=default.target
```

`ExecStart` рендерится из `sys.executable -m vpnm guard run` при установке
(в примере — `/usr/bin/python3`; фактический интерпретатор подставляется,
чтобы не зависеть от PATH/venv). `--linger` — opt-in, как у профилей
(политика чистого старта: по умолчанию guard **не** ставится и **не**
включается).

**Sandbox — проверяемая гипотеза, а не догма (WP-G1).** `ProtectSystem=strict`
в `systemd --user` работает через user-namespace; на Ubuntu 24.04 с
ограниченным unprivileged-userns (`kernel.apparmor_restrict_unprivileged_userns=1`)
комбинация `ProtectSystem=strict` + `NoNewPrivileges=yes` +
`SystemCallFilter=@system-service` может дать `status=226/NAMESPACE` —
юнит не стартует вообще. Поэтому в WP-G1 обязательны три проверки на **чистом
десктопе**, а не только на dev-машине:

1. `systemctl --user start vpn-guard` → `active (running)` и `journalctl
   --user -u vpn-guard` без `226/NAMESPACE`, `203/EXEC`, `218/CAPABILITIES`;
2. чтение user-журнала из sandbox: `journalctl --user -f` не получает
   `EPERM`/`EACCES` (при отказе — `sources` пишет `degraded`, но это не
   повод снимать `NoNewPrivileges`);
3. `notify-send` при `notify.desktop=true`: D-Bus session bus — это
   `AF_UNIX` (`$XDG_RUNTIME_DIR/bus`), поэтому `RestrictAddressFamilies=AF_UNIX`
   его пропускает; проверяется фактическая доставка уведомления (а не только
   `rc=0`). Если `notify-send` недоступен/заблокирован — уведомления
   деградируют в journal-строку, finding не теряется.

**Fallback-профиль.** Installer пишет `vpn-guard.service` из двух профилей:

| Профиль | Содержимое | Когда |
|---|---|---|
| `hardened` (default) | всё из блока выше | старт прошёл, все три проверки зелёные |
| `compat` | без `ProtectSystem`, `SystemCallFilter`, `SystemCallArchitectures`; остаются `NoNewPrivileges`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX`, `MemoryMax`, `CPUQuota`, `UMask` | `hardened` дал `226/NAMESPACE` на живом юните |

Выбор профиля — **только по факту проверки**, с записью
`install-state.json.profile` и строкой в `sources`
(`unit_profile=compat`, причина). Молчаливого «ослабим на всякий случай»
нет: `compat` — наблюдаемое состояние, а не дефолт. `AF_NETLINK` добавляется
в `RestrictAddressFamilies` только при `netlink=true`.

---

## 11. Приватность, безопасность, retention

1. **Нет секретов в артефактах.** UUID/ключи/пароли/obfs/shortId/share-ссылки
   маскируются до записи; сырой текст не персистится; `evidence` — счётчики и
   хэши. Сниппеты — только `redact.snippets=true` и ≤ 120 символов после
   маскирования.
2. **Нет сети в демоне.** Тест: `socket.socket`/`socket.create_connection`
   monkeypatch → любой вызов = fail. `sync` — отдельная команда, не демон.
3. **Нет root.** Guard не вызывает `sudo`; системный журнал — best-effort.
4. **Права.** Каталог 0700, файлы 0600; юнит 0644; state пишется атомарно.
5. **Retention.** findings 14 дней/20 МБ; trace 1 час; `export` ≤ 5 МБ;
   `uninstall --purge` удаляет каталог; обычный `uninstall` — сохраняет
   историю.
6. **Экспорт.** По умолчанию хосты заменяются на `<host>`; `--keep-hosts` —
   осознанный opt-in. Пост-сканер секретов блокирует экспорт при совпадении,
   но не проверяет allowlist-поля (`*_hash`, `*_sha256`, `template`, `id`) и
   значения вида `sha256:<64 hex>` — иначе собственный `schema_hash` делал бы
   экспорт нерабочим (AC-13).
7. **Никакой связи с git.** Артефакты в XDG-каталогах; фикстуры в тестах —
   только `FIXTURE_*` и зарезервированные IP/UUID (AGENTS §6).
8. **Чужой шум.** В findings не попадают IP третьих сторон, `ru_top`,
   `top`, payload, SNI, URL. Домен эндпоинта — только локально.
9. **AWG без привилегий.** Счётчики читаются из
   `/sys/class/net/<iface>/statistics/*` (world-readable); `awg show`,
   `sudo`, netlink-дампы конфигурации не используются.

---

## 11.1 Бюджет латентности по классам (ревью G2)

p95 ≤ 2 с — для **event-triggered** правил (G-02/G-03/G-05); absence-правила
(G-01, G-09-таймауты) по конструкции привязаны к 5-с тикеру + таймауту (25 с)
— бенч AC-5 мерит классы РАЗДЕЛЬНО, усреднение запрещено.

## 12. Производительность и надёжность

| Метрика | Бюджет | Как проверяем |
|---|---|---|
| задержка line→finding | p95 ≤ 2 с, медиана ≤ 300 мс | synthetic replay с метками |
| CPU (idle, 1 профиль) | ≤ 1% ядра | `/proc/self/stat` за 24 ч |
| RSS | ≤ 80 МБ (unit cap 128 МБ) | 24-часовой прогон |
| диск | ≤ 20 МБ findings, ≤ 10 МБ trace | ротация + `du` |
| burst | 2000 строк/с без OOM | генератор + drop-политика |
| старт | ≤ 1.5 с до первого события | замер |
| sysfs-поллер AWG | 2 чтения/с, 0 сокетов, ≤ 0.05% ядра | strace + `/proc/self/stat` |
| рестарт | без дублей findings (cursor+cooldown) | kill -9 + повторный старт |

| Отказ | Поведение |
|---|---|
| `journalctl` отсутствует | source `unavailable`, файлы/state работают, `status` degraded |
| нет прав на системный журнал | `denied` + note, без повторов и sudo |
| reader упал | backoff 1→2→4→…→30 с; через 60 с G-12 `source_lost` (low) |
| битая JSON-строка | `unparsed++`, шаблон-хэш, без падения |
| диск заполнен | findings не пишутся, поток продолжается, однократный warning, `coverage.disk_full` |
| скачок часов | окна по mono; skew > 2 с → G-12 |
| unit удалён | состояние GC через 1 ч |
| `/sys/class/net/<iface>` исчез | `awg_iface_gone` (G-10/G-07), G-04-ветка выключена до появления iface, без спама |
| нет доступа к sysfs-счётчикам | `sysfs:awg=denied`, `coverage.signals.amneziawg=missing`, Xray/Hy2 работают штатно |
| секрет в evidence | сниппет отброшен, finding остаётся со счётчиками, warning |
| guard перезапущен | state восстановлен, открытые инциденты не дублируются |

---

## 13. Интеграция с сервером (read-only)

### 13.1. Producer: `vpn guard sync`

```bash
vpn guard sync --host root@asv2
# внутри: ssh <host> "vds gateway probe-watch watch --json"
```

- **только чтение, зафиксировано:** серверная команда `watch` без `--record`
  не вызывает `save_snapshot()`, не обновляет `threat`-поля снапшота и не
  запускает `run_auto_reactions()` (`src/gateway/probing.py: cmd_watch` —
  любая запись только под `if record:`).
  Это расхождение с поправкой M1 в `SPEC-20261116-log-forensics` §5.1
  снимается **явно**, а не на словах: в WP-G4 в `vds` добавляется
  серверный regression-тест, который считает `mtime`+`sha256`
  `/var/lib/vds/probe-watch.json` и gateway `state.json` (lockdown-поля)
  до и после `cmd_watch(record=False)` и требует их неизменности. Единственный
  побочный эффект — touch файла блокировки `/var/run/vds-probe-watch.lock`;
  это не состояние и в проверку не входит. Если тест когда-либо покраснеет —
  sync переводится на отдельный read-only endpoint (или `--json`-подкоманду),
  а не «как-нибудь работает»;
- host по умолчанию берётся из `~/.config/vpn-manager/settings.json` (как у
  `vpn profile pull`); `--host` переопределяет;
- ssh — список аргументов, без `shell=True`, timeout 10 с;
- ошибка/таймаут → старый файл сохраняется, `coverage.note=verdict_stale`;
- периодический sync — **opt-in** timer `vpn-guard-sync.timer`, интервал
  **60 мин** (`OnUnitActiveSec=1h`, `RandomizedDelaySec=5min`): 15-минутный
  интервал давал бы 96 SSH-сессий/сутки на боевой порт `49222` без выигрыша
  (серверный снапшот всё равно обновляется раз в час). Ставится только явно
  (`vpn guard install --sync-timer`); по умолчанию пользователь сам решает,
  когда обновлять;
- `sync` **не мутирует** клиентские артефакты кроме `server-verdict.json`
  (атомарная замена + `fetched_at`); findings/state/coverage только читаются
  следующим тиком демона.

### 13.2. Формат `guard.server_verdict/1`

```json
{
  "schema": "guard.server_verdict/1",
  "fetched_at": "2026-11-16T12:00:00Z",
  "host": "root@asv2",
  "source": "vds gateway probe-watch watch --json",
  "verdict": "RU-PROBE-SUSPECT",
  "threat_level": "high",
  "threat_reason": "2 окна RU-PROBE-SUSPECT",
  "window": "2026-11-16T11:00:00 .. 2026-11-16T12:00:00",
  "stage": "data_phase",
  "reasons": ["..."],
  "lockdown": {"active": false, "ttl_until": ""},
  "raw_sha256": "…"
}
```

`stage` — опциональное поле (появится с survivability WP-S1); guard терпит
его отсутствие (`null`), не требуя серверных изменений в v1. Свежесть
определяется по `fetched_at` (≤ 65 мин, §9.3), а `window` честно показывает,
за какой серверный интервал данные. `top`/`ru_top`/IP-списки **вырезаются**
при записи.

### 13.3. Границы

- клиент → сервер: **non-goal v1**. Импорт клиентских findings в `vds logs`
  (`--client-report FILE` уже есть в схеме) — отдельный цикл после полевых
  данных и privacy-ревью;
- сервер → клиент: только вердикт, только файл, только allowlist;
- общих Python-зависимостей нет: контракт — JSON-схемы + корпус фикстур,
  версия сверяется `schema_hash` в CI обоих репозиториев.

---

## 14. Тестовая стратегия и приёмка

### 14.1. Уровни

| Уровень | Что | Без root/сети |
|---|---|---|
| unit | parser/redact/window/rules/correlate/store на фикстурах | да |
| golden | корпус → `findings.jsonl`, побайтовое сравнение | да |
| property | fuzz строк (битые UTF-8, гигантские строки, секреты) — нет падений, память ограничена | да |
| integration | фейковый journal-producer (pipe) + реальный `run --once` | да |
| regression | `vpn monitor --json` и `vpn profile` контракты не изменились | да |
| field | 7 дней на ноутбуке с Reality + Hy2 + **AWG (основной канал)** | живой VDS |

Корпус: `tests/guard/fixtures/<proto>/<version>/*.jsonl`, только
синтетические записи; секреты — `FIXTURE_UUID_11111111-2222-…`, IP —
203.0.113.0/24 (RFC 5737). Реальные логи в git не попадают.

### 14.2. Приёмочные критерии

| ID | Критерий |
|---|---|
| AC-1 | Остановка профиля (`vpn down`) → ≤ 5 с `last_lifecycle.cause=vpn_down`, high-finding нет |
| AC-2 | Reset-storm (replay) → ровно один G-02/G-03 с `count`, без дублей в cooldown |
| AC-3 | Auth-fail (replay) → G-05 `config`, категория цензуры не появляется |
| AC-4 | Потеря DNS (остановить резолвер) → G-06 ≤ 60 с, action `vpn repair` |
| AC-5 | 24 ч live: RSS < 80 МБ, CPU < 1%, unparsed < 5% app-строк, 0 падений |
| AC-6 | Сканер секретов на findings/state/export — 0 совпадений |
| AC-7 | Демон не делает сетевых вызовов (тест с monkeypatch socket) |
| AC-8 | `status --json`/`findings --json` валидны по схемам; `monitor --json` не изменился |
| AC-9 | Детерминизм: два прогона корпуса → идентичный JSONL |
| AC-10 | Merge: stale verdict игнорируется; fresh high повышает confidence; `lockdown=true` даёт `expected_lockdown` |
| AC-11 | Kill -9 guard → рестарт без дублей и потери курсора |
| AC-12 | `pip install` пакета → `vpn guard selftest` работает (подпакет включён) |
| AC-13 | Эталонный finding с `schema_hash`/`rules_hash`/`config_hash`/`raw_sha256` проходит пост-сканер и `export` **без хитов**; реальный `FIXTURE_PW_*` в сниппете — экспорт блокируется с кодом 2 |
| AC-14 | Первый запуск профиля: `unit_start` + `app_banner_ok` (без handshake) → G-01 `tunnel_down`, покрытие доказано (не `blind`); `unit_start` без banner и без dial-сигналов → `insufficient_data` с `no_app_banner` + G-12, G-01 не срабатывает |
| AC-15 | AWG replay счётчиков: активный `vpn-awg-split@laptop` не даёт `idle`; `tx↑` при `rx≈0` в 2 окнах → G-04 `awg_tx_no_rx` (medium); `awg_iface_gone` → ветка подавлена, G-10/G-07; `iface` не хардкожен как `awg0` |
| AC-16 | (серверный, `vds`) `cmd_watch(record=False)` не меняет `mtime`+`sha256` `/var/lib/vds/probe-watch.json` и gateway `state.json` (lockdown); допустим только touch `/var/run/vds-probe-watch.lock`. `vpn guard sync` меняет только `server-verdict.json` |
| AC-17 | Юнит стартует в профиле `hardened` на чистом десктопе (нет `226/NAMESPACE`); при искусственном отказе installer выбирает `compat`, пишет `install-state.json.profile` и `sources.unit_profile=compat` |

### 14.3. Полевая приёмка (7 дней)

Дневник: каждое реальное «VPN не работает» фиксируется вручную (время,
симптом, что сделал). Сравнение с findings:

- recall ≥ 80% реальных инцидентов;
- ≤ 1 ложный high в сутки (после недели тюнинга — ≤ 1 за 3 суток);
- 0 секретов в артефактах;
- guard не влияет на `vpn speed`/`probe` (нет проб, только CPU);
- **AWG:** при активном `vpn-awg-split@*` guard ни разу не в `idle`;
  ≥ 1 подтверждённый `awg_tx_no_rx`-инцидент (или 0 FP на этом правиле за
  неделю) — иначе ветка уходит в v1.1 с пометкой `not_validated`;
- отчёт `TEST-20261116-vpn-guard` с таблицей инцидентов и FP-разбором.

---

## 15. Работы и гейты

| WP | Объём | DoD |
|---|---|---|
| WP-G0 | контракт `guard.event/1`, `guard.finding/1`, `guard.coverage/1`, `guard.status/1`, `guard.incident/1`, `guard.server_verdict/1`, `guard.config/1`; реестр `vpnm/guard/events.py` (+`app_banner_ok`, AWG-counter сигналы); `schema.py` + `schema_hash`; `schemas/` как package-data; `pyproject.toml`; **ADR-014** | G2 approved; ADR-014 закоммичен, схемы закоммичены в клиенте, `pytest tests/guard` зелёный, спека обновлена |
| WP-G1 | readers (user journal, files, state, **sysfs AWG counters**), iface discovery, cursors, backoff, coverage, `status`/`sources`, `install` юнита (**профили `hardened`/`compat`**, AC-17), маркеры `activity.json` в `monitor`/`probe`/`speed`, регрессия `enabled_vpnm_units()` | AC-5/AC-7/AC-11/AC-17; unit поднимается и переживает рестарт |
| WP-G2 | парсер structured-first + app-regex, `app_banner_ok`, redaction, шаблоны, unparsed, **пост-сканер с allowlist `*_hash`** | AC-6/AC-13, property-fuzz, golden парсера |
| WP-G3 | окна/гистерезис, G-01…G-08 (**включая G-01 banner/dial и G-04 AWG-ветку**), findings, cooldown, `explain` | AC-1…AC-4, AC-9, AC-14, AC-15 |
| WP-G4 | корреляция/инциденты/suppression, G-09…G-12, `verdict.py`, merge, **серверный regression-тест `watch` без `--record`** | AC-10, AC-16; тест stale/lockdown/quiet |
| WP-G5 | `export`, `selftest`, notifications, TUI-пункт, доки клиента, `rules` | AC-8/AC-12; `doc/vpn-manager.md` + README клиента |
| WP-G6 | 7-дневная полевая приёмка, тюнинг порогов, отчёт | recall/FP бюджеты; G6 close |

Порядок: G2 → WP-G0 → (WP-G1 ∥ WP-G2) → WP-G3 → WP-G4 → WP-G5 → WP-G6.
Оценка: ~10 dev-days + 7 дней наблюдения. Реализация — `vds-coder` в
клиентском репозитории; ревью — `vds-architect` (контракт/правила) и техлид
(эксплуатация/приватность).

---

## 16. Риски

| # | Риск | Митигация |
|---|---|---|
| RSK-1 | Дрейф форматов Xray/Hysteria2 → unparsed | golden-корпус по версиям, `unparsed_ratio`, G-12, версия клиента в coverage |
| RSK-2 | Локализованные сообщения systemd | structured-first (`UNIT`/`JOB_TYPE`/`EXIT_CODE`), regex только для app-логов |
| RSK-3 | Ложные срабатывания на своих пробах/командах | командные маркеры, grace-окна, FP-проверки, cooldown, полевая калибровка |
| RSK-4 | Шумный user-journal (другие юниты) | фильтр по префиксу, bounded queue, drop info, CPU-бюджет |
| RSK-5 | Дублирование с `monitor`/`doctor` | чёткое разделение: guard не делает проб; action ссылается на monitor |
| RSK-6 | Утечка секретов через evidence | маскирование до записи, сниппеты off, пост-сканер, экспорт-блокировка |
| RSK-7 | Кросс-репо дрейф схем | **закрыт контрактом D-17 (DECISION Q1)**: источник правды — клиентский lock `vpnm/guard/schemas/schema_hashes.json`; сервер вендорит его в `docs/contracts/guard-schema-hashes.json` и проверяет локальными тестами (без сети) — структура lock, поля `probe-watch watch --json`, при `VPN_MANAGER_REPO` сверка хэшей 1-в-1; `.github/` не нужен |
| RSK-8 | Guard усиливает флап (нагрузка/рестарты) | read-only, Nice/CPUQuota, G-10 suppression, никаких systemctl из правил |
| RSK-9 | Скачок часов/сон ноутбука | mono-время, skew-детект, G-12; suspend-пауза окон |
| RSK-10 | Пользователь ждёт «само починится» | явно: v1 только диагностика; авто-действия — отдельный ADR |
| RSK-11 | `vpnm-guard.service` ломает `vpn autostart off` | имя `vpn-guard.service` + тест на коллизию |
| RSK-12 | Логи не содержат per-connection событий | честный `app_signal=blind`, подсказка в `sources`, не выдумывать findings |
| RSK-13 | Основной канал (AWG) не виден: guard уходит в `idle` и «молчит» | R-11/AC-15: sysfs-счётчики всегда, `idle` требует отсутствия и AWG-активности, G-04-ветка `awg_tx_no_rx` |
| RSK-14 | `ProtectSystem=strict` в user-инстансе даёт `226/NAMESPACE` и guard не стартует | AC-17: три проверки на чистом десктопе, профили `hardened`/`compat`, выбор только по факту |
| RSK-15 | Пост-сканер блокирует собственные `*_hash` и ломает экспорт | AC-13: allowlist ключей + `sha256:<64 hex>` не считается секретом |
| RSK-16 | `sync` воспринимается как «read-only», но мутирует серверный снапшот | AC-16: серверный regression-тест на `mtime`+`sha256` при `record=False`; клиент пишет только `server-verdict.json` |

---

## 17. Открытые вопросы — **закрыты на G2 (2026-11-16)**

Все вопросы ниже закрыты решениями §20.2; колонка «Решение» — обязательна к
исполнению, переоткрытие только новым гейтом.

| # | Вопрос | Решение (G2, 2026-11-16) |
|---|---|---|
| OQ-1 | Где живёт команда: клиент `vpn` или сервер `vds`? | **клиент** (`vpnm`): серверная слепота к SNI/DNS/whitelist; сервер остаётся `vds logs` |
| OQ-2 | Имя: `vpn guard` vs `vpn watch`/`vpn logs`? | **`vpn guard`** (запрос владельца); коллизия с режимом `vpn doh guard on` безвредна (разные уровни) |
| OQ-3 | Автодействия в v1? | **нет**, read-only; авто-DNS/авто-переключение — после 30 дней данных и ADR |
| OQ-4 | Системный журнал по умолчанию? | **нет** (минимум привилегий), но `install` проверяет группу `systemd-journal` и *предлагает* включить; в S2 обязательны `dnsmasq`, `awg-quick@*`, `vpn-awg-split@*` |
| OQ-5 | Desktop-уведомления по умолчанию? | **нет**; opt-in `notify.desktop=true`, min_severity=high; доставка проверяется в WP-G1 (D-Bus = AF_UNIX) |
| OQ-6 | Retention findings | **14 дней / 20 МБ** (5 × 4 МБ), trace 1 час |
| OQ-7 | Периодический sync с сервером | **ручной** по умолчанию; opt-in `vpn-guard-sync.timer` — **60 мин** (не 15: серверный тик часовой); свежесть `fetched_at` ≤ 65 мин |
| OQ-8 | Владелец JSON-схем | **клиент**: `scripts/vpn-manager/vpnm/guard/schemas/` (внутри пакета → package-data, иначе `pip install` не довезёт схемы); `vds` ссылается на SPEC и `schema_hash` |
| OQ-9 | Сниппеты строк в evidence | **нет** по умолчанию; opt-in, ≤ 120 символов после маскирования |
| OQ-10 | Ставить guard при `vpn install`? | **нет** (чистый старт); только `vpn guard install` |
| OQ-11 | Источник `state.json` — это «лог»? | да, как structured context; read-only, poll 1 с |
| OQ-12 | Backfill на старте | 2 мин по умолчанию, максимум 24 ч; память не зависит от глубины |
| OQ-13 | Пользовательские regex в конфиге | **запрещены**; только пороги/флаги (детерминизм, безопасность) |
| OQ-14 | Baseline скорости | v1 — абсолютный порог 2.0 Мбит/с; персональный baseline — v2 |
| OQ-15 | Нужен ли ADR-014? | **да** (демон + постоянные артефакты + кросс-репо контракт); создаётся в WP-G0 |
| OQ-16 | Импорт клиентских findings на сервер | **non-goal v1**; отдельный цикл после privacy-ревью |
| OQ-17 | Наблюдать ли AmneziaWG (основной канал ноутбука)? | **да**: sysfs-счётчики + lifecycle S2, `proto=amneziawg`, G-04-ветка `awg_tx_no_rx`; `awg show`/`sudo` не используются |
| OQ-18 | Что делать, если sandbox не стартует в user-инстансе? | **профиль `compat`** с явной записью в `install-state.json`/`sources`; молчаливого ослабления нет |
| OQ-19 | Как G-01 переживает первый запуск профиля? | **`app_banner_ok`** (≤ 15 с) или `dial_start`/`dial_timeout` (≤ 25 с) внутри того же `INVOCATION_ID`; без них — `insufficient_data` |
| OQ-20 | Как пост-сканер не ломает собственные хэши? | allowlist ключей `*_hash`/`*_sha256`/`template`/`id`; `sha256:<64 hex>` — не секрет |

---

## 18. Альтернативы

| Вариант | Плюсы | Минусы | Решение |
|---|---|---|---|
| **Потоковый reader + правила (выбран)** | секунды, без root/сети, детерминизм | свой код, дрейф форматов | да |
| Батч `journalctl --since` по cron | просто | минуты, пропуски, не «живое время» | нет |
| `journalctl -n` polling | просто | дубли/пропуски, задержка | нет |
| Только tail файлов Xray/Hy2 | без journald | systemd владеет stdout, ротация | только вторичный |
| pcap/eBPF | точные пакеты | root, тяжело, дублирует серверный forensics | нет |
| SIEM/log-shipping | централизация | сеть, приватность, инфраструктура | нет |
| LLM-триаж | «умно» | недетерминизм, утечка логов | нет |
| Только серверный анализ | нет нового демона | SNI/DNS/whitelist невидимы | нет |
| Встроить в xray/hysteria | раньше сигнал | не наш код, форк | нет |

---

## 19. Трассируемость

| Требование | WP | Файлы | Тесты/AC |
|---|---|---|---|
| R-1 потоковость | WP-G1 | `reader.py`, `window.py` | latency bench, AC-5 |
| R-2 детерминизм | WP-G0/3 | `events.py`, `rules.py`, `store.py` | AC-9 |
| R-3 приватность | WP-G2 | `redact.py`, `store.py` | AC-6 |
| R-4 без root/сети | WP-G1 | `reader.py`, `install.py` | AC-7 |
| R-5 доказательства | WP-G3 | `rules.py`, `report.py` | AC-2/AC-3, golden |
| R-6 ресурсы | WP-G1 | `reader.py`, unit | AC-5 |
| R-7 read-only | WP-G3/4 | `rules.py`, `correlate.py` | grep + ревью |
| R-8 совместимость | WP-G5 | `cli.py`, тесты | AC-8 |
| R-9 честная слепота | WP-G2/4 | `parse.py`, G-12 | coverage-тесты |
| R-10 кросс-vantage | WP-G4 | `verdict.py` | AC-10 |
| R-11 покрытие AWG | WP-G1/3 | `counters.py`, `rules.py` (G-04) | AC-15 |

---

## 20. Doc delta и решение G2

### 20.1. Документация

| Репозиторий | Документ | Изменение | WP |
|---|---|---|---|
| `vds` | эта SPEC | новый snapshot | G2 |
| `vds` | `docs/team/STATUS.md` | запись о G2 APPROVED | G2 |
| `vds` | `docs/adr/ADR-014-vpn-guard.md` | новый ADR (утверждён на G2) | WP-G0 |
| `ubuntuInstaller` | `doc/vpn-manager.md` | раздел `vpn guard`: команды, правила, пути, приватность, unit, JSON | WP-G5 |
| `ubuntuInstaller` | `README.md` | строка в списке команд | WP-G5 |
| `ubuntuInstaller` | `scripts/vpn-manager/vpnm/guard/{events,schema}.py` + `schemas/` | реестр констант и 7 JSON-схем (package-data) | WP-G0 |
| `ubuntuInstaller` | `scripts/vpn-manager/pyproject.toml` | `packages` + package-data | WP-G0 |
| `ubuntuInstaller` | `tests/guard/` | корпус + golden | WP-G2/3 |

`vds` doc-sync не видит клиентский репозиторий; в DoD WP-G5 — ручной
чеклист «код + тесты + `doc/vpn-manager.md` + README в одном коммите
клиента». Серверные живые доки не меняются: `vds logs` и probe-response не
затронуты.

### 20.2. Решения G2 — **утверждены 2026-11-16**

| # | Решение | Итог |
|---|---|---|
| 1 | **Скоуп:** клиентский read-only демон, сервер — только `vds logs` | ✅ да |
| 2 | **Контракт:** `guard.event/1` + `guard.finding/1`, владелец — клиент, `schema_hash` в CI | ✅ да |
| 3 | **Источники:** user-journal обязателен; system — opt-in (с `dnsmasq`, `awg-quick@*`, `vpn-awg-split@*`); netlink — v1.1; **AWG sysfs-счётчики — обязательны** | ✅ да |
| 4 | **Правила:** каталог G-01…G-12 и пороги §8.1 заморожены для v1 — **с поправками**: G-01 через `app_banner_ok`/`dial_*`, G-04 получает ветку `awg_tx_no_rx` | ✅ да |
| 5 | **Приватность:** без сниппетов, экспорт с `<host>`, retention 14 дней/20 МБ; пост-сканер с allowlist `*_hash` | ✅ да |
| 6 | **Реакция:** v1 только рекомендации; авто-действия — отдельный ADR после ≥ 30 дней данных | ✅ да |
| 7 | **Имя юнита:** `vpn-guard.service` + регрессия `enabled_vpnm_units()` | ✅ да |
| 8 | **ADR-014:** нужен, создаётся в WP-G0 | ✅ да |
| 9 | **Survivability:** `stage` — опциональное поле (`str`/`None`), отсутствие не блокирует | ✅ да |
| 10 | **Выход G2:** пять правок внесены (см. ниже) | ✅ G2 APPROVED |

**Внесённые правки (условие выхода G2):**

1. **sync/read-only** — §13.1: `watch` без `--record` зафиксирован как
   read-only, добавлен серверный regression-тест на `mtime`+`sha256`
   (`probe-watch.json`, gateway `state.json`) — AC-16; таймер 60 мин,
   свежесть `fetched_at` ≤ 65 мин (§9.3, R-10).
2. **AmneziaWG** — §3, §4.1, §5.1, §6.2, §6.3, §7.1, §7.2, §8.1, §8.2/§8.3,
   §6.6: `proto=amneziawg`, `dnsmasq` и AWG-юниты в S2, sysfs-поллер,
   запрет `idle` при живом AWG, ветка G-04 `awg_tx_no_rx`, AC-15.
3. **sandbox** — §10.4: три проверки на чистом десктопе, профили
   `hardened`/`compat`, D-Bus-проверка `notify-send`, AC-17.
4. **пост-сканер** — §7.3/§11.6: allowlist `*_hash`/`*_sha256`/`template`/`id`,
   `sha256:<64 hex>` не секрет, AC-13.
5. **G-01** — §7.2/§8.2/§8.3: `app_banner_ok` (≤ 15 с) или
   `dial_start`/`dial_timeout` (≤ 25 с) внутри `INVOCATION_ID`; иначе
   `insufficient_data`, AC-14.

Реализация начинается с WP-G0 (ADR-014 + схемы), не с кода демона.

---

## 21. Связь с существующими решениями

- **SPEC-20261116-log-forensics** — серверный конвейер; §15 прямо выносит
  клиентскую телеметрию в отдельную SPEC, а §3 объясняет, почему сервер не
  видит SNI/DNS/whitelist. `vpn guard` — недостающий vantage, не дубль.
- **SPEC-20261116-survivability** — стадии 0–3 и T-18…T-23; guard
  использует `stage_hint` и серверный `stage`, не пересчитывает серверные
  пороги.
- **SPEC-20261116-probe-response** — lock-443; клиент помечает отказы при
  активном локе как `expected_lockdown`, чтобы не принять защиту за цензуру.
- **ADR-012** — границы приватности/retention и «анализатор не реагирует»;
  guard повторяет те же принципы на клиенте (свои пути, свой TTL).
- **`vpn monitor`/`doctor`/`repair`** — активные снимки; guard их не
  заменяет и не вызывает, только ссылается в `action`.


## 21. Резолюция G2 (техлид/оркестратор, 2026-11-16)

Скоуп клиентский read-only — подтверждён; схемы — владеет клиент, vds
вендорит schema_hash; ADR-014 обязателен до WP-G1; системный журнал —
opt-in; уведомлений в v1 нет (findings-файл), retention 14д/20МБ, sync
по требованию + периодика 15 мин; автодействия — никогда в v1 (30 дней
данных + отдельный ADR); `stage` — опционально. compat-профиль = аварийное
диагностируемое состояние (не норма). `vpn-guard.service` — подтверждено
кодом runners.py. sync: `watch --json` СТРОГО без `--record` (AC-16
страховка). Спека: G2 APPROVED-with-notes — правки §5.4/11.1/9.0/14.3/WP-G0
внесены, к WP-G1 без повторного ревью.
