# SPEC-20261116-log-forensics — систематический разбор дампов серверных логов и мониторинг ТСПУ

## Мета
- **Источник:** поручение владельца 2026-11-16; аудит документации 2026-11-16;
  правила [SERVER-BASELINE](../../SERVER-BASELINE.md) §5.9/§5.11/§5.12/§5.13;
  идеи И40/И41 ([youtube-ideas](../../research/youtube-ideas-2026-11.md));
  соседняя [SPEC-20261116-probe-response](SPEC-20261116-probe-response.md).
- **Автор:** оркестратор (черновик по поручению владельца)
- **Дата:** 2026-11-16
- **Статус:** **G2 APPROVED-with-notes 2026-11-16** (архитектор: M1 `watch`-мутация
  → collect читает снапшот+nft с in-process дельтой; M2 ADR-012 → WP-1; baseline
  hour_of_day-дефолт; T-02 absolute-floor; pcap-кламп; redaction shortId/PKey/PSK;
  RandomizedDelaySec/MemoryMax — все внесены. Техлид: OQ-1..15 закрыты)
- **Ревьюеры:** архитектор (границы модуля, схема данных, правила и корреляция);
  техлид/владелец (ценность, стоимость эксплуатации, приватность, retention,
  политика захвата пакетов).
- **ADR:** требуется **ADR-012 «log-forensics: локальная телеметрия, дампы и
  захват пакетов»** — вводятся новые постоянные артефакты (`/var/lib/vds/
  telemetry`, `/var/lib/vds/forensics`), правила приватности и bounded-pcap.
  ADR-012 в этом документе не пересекается с doc-sync: SPEC-20261116-doc-sync
  ADR не требует.
- **Скоуп:** репозиторий `vds`, серверная сторона. Клиентская телеметрия
  (`vpn`/`ubuntuInstaller`) — отдельная SPEC; здесь только формат импорта
  (non-goal v1, §15).

---

## 1. Проблема

`probe-watch` уже даёт **L3/L4-вердикты** (RU-PROBE-SUSPECT / PROBE-BURST) и
threat-level, а `probe-response` — серверную реакцию (lock-443). Но между
«вердикт» и «понять, что произошло» остаётся разрыв:

| Пробел | Следствие |
|---|---|
| Логи живут в journald и никуда не собираются | инцидент разбирается вручную, набор источников зависит от того, что вспомнил оператор |
| §5.13 описывает `tcpdump` руками | забытый захват, `/var/tmp`, нет ротации/лимитов, нет привязки к вердикту |
| Нет временных рядов | нельзя отличить «TCP-443 душат данные» от «клиент сломался»: `ss` — мгновенный снимок, app-логи слепы (§5.11) |
| Нет базовой линии | каждый всплеск выглядит аномалией; ложные тревоги и привыкание |
| Нет правил и корреляции | вывод зависит от экспертизы; «единичный счётчик» выдаётся за атаку |
| Нет единого отчёта с доказательствами | нельзя передать архитектору/техлиду воспроизводимый разбор |
| Нет границ приватности/retention | дампы с IP клиентов и pcap могут утечь в git/чат |
| Нет карты слепоты | сервер не видит SNI-блок/DNS-подмену; об этом забывают и «чинят» исправный сервер |

Показательный кейс уже есть: asv2, 2026-11-15 — первые ~30 минут ТСПУ душит
TCP-443 TLS-payload при живом UDP-443 (§5.9). Без временных рядов это
выглядит как «Reality сломан», и типичная реакция (рестарт юнита) только
сбрасывает профиль. Нужен **воспроизводимый алгоритм**: собрать → нормализовать
→ обогатить → применить правила → коррелировать → оценить уверенность →
отчитаться → сохранить/удалить по политике.

---

## 2. Цель, требования, принципы

### 2.1. Цель

Дать оператору/агенту детерминированный путь от «есть подозрение на ТСПУ или
сбой» до **отчёта с доказательствами и ограничениями наблюдаемости** — за
один проход, офлайн, без LLM, с явными границами приватности и ресурсов.

### 2.2. Требования

| ID | Требование | Как проверяется |
|---|---|---|
| R-1 | Единый конвейер: `collect → normalize → enrich → detect → correlate → score → report → retain` | один код-путь для `--live` и для готового bundle |
| R-2 | Каждый вывод ссылается на доказательство (источник + окно + счётчик/строки) | `findings[].evidence[]`, отчёт без «голых» утверждений |
| R-3 | Детерминизм: одинаковый вход + правила + baseline → побайтно одинаковый JSON | golden-тест + стабильные ID |
| R-4 | Честная карта покрытия: что видно, что слепо, чего не хватает | `coverage{}` в отчёте, `vds logs explain` |
| R-5 | Приватность и секреты: ни UUID/ключей/паролей, ни payload; IP — с возможностью редактирования | тест-сканер бандла/отчёта; redaction-режим |
| R-6 | Ресурсы ограничены: объём бандла, строки, время, pcap-кольцо | лимиты в коде + отказ при превышении |
| R-7 | Анализ офлайн и без root; root — только сбор/захват | прогон analyze от непривилегированного пользователя на bundle |
| R-8 | Никакой дублирующей логики вердиктов: источник — probe-watch (снапшот последнего тика + дельта in-process через compute_delta, БЕЗ мутации — M1) | анализатор потребляет вердикт, а не пересчитывает nft-пороги и не конкурирует с таймером |
| R-9 | Реакция не здесь: анализатор только советует, исполняет — `probe-response`/оператор | в коде нет вызовов `ufw lock-443` и рестартов |

### 2.3. Принципы

1. **Сначала факты, потом гипотезы.** Отчёт разделяет «наблюдено» и
   «интерпретация»; гипотеза всегда с уверенностью и альтернативами.
2. **Один счётчик — не вывод.** High-confidence требует ≥2 независимых
   источников, из них ≥1 прямой (nft, kernel-counters, pcap).
3. **Слепоту признаём явно.** Отсутствующий источник — это `coverage.status =
   missing`, а не «всё хорошо».
4. **Не трогать сервисы под обстрелом.** Анализ read-only; рекомендации
   учитывают правило §5.9/§5.11.
5. **Снимки не переписываем.** Исторические SPEC/REPORT — только чтение.
6. **Никакой сети и ML.** stdlib + системные утилиты; без API, без моделей.
7. **Удаляем раньше, чем забываем.** У каждого артефакта есть TTL и команда
   удаления; pcap по умолчанию удаляется после разбора.

---

## 3. Модель наблюдаемости ТСПУ (с какого vantage что видно)

Сервер видит только то, что дошло до его NIC/ядра. Это ограничение —
центральное для отчёта.

| Поведение ТСПУ | Механизм | Видно с сервера? | Источник сигнала | Максимум вывода |
|---|---|---|---|---|
| Пассивный DPI-анализ | зеркало/эвристики на пути | ❌ принципиально | — | только последствия |
| Активное зондирование TCP/443 | 8-пробная J3-серия (И40) | ✅ | nft `syn_valid/probers4`, pcap ClientHello | `probing` |
| Активное зондирование UDP/443 | QUIC-Initial/мусор | ⚠️ частично | `udp_443` объём (pcap v1 — только TCP/443) | `probing_udp?` (низкая уверенность) |
| Data-phase blackhole TCP/443 | SYN проходит, данные дропаются | ✅ | nft+`ss`+nstat+interface | `effect_tcp` |
| Троттлинг/дроп UDP | шейпер/blackhole | ✅ при трафике | `udp_443`, interface counters | `effect_udp` |
| Блок IP (L3) | null-route/ACL | ⚠️ косвенно | трафик исчезает; нужен внешний vantage | `effect_ip?` |
| SNI-based drop | разрыв по ClientHello | ❌ | только клиент/внешняя точка РФ | `client_side` |
| DNS-подмена | in-path DNS | ❌ | только клиент | `client_side` |
| Whitelist-режим | разрешены только RU-сервисы | ❌ | только клиент | `client_side` |

Следствия для дизайна:
- **Мониторинг ТСПУ на сервере — это мониторинг эффектов и активных проб**, а
  не «детект ТСПУ» как такового. Формулировки отчёта это фиксируют
  (`effect_only`, `probing_only`, `probing_plus_effect`).
- Клиентские отчёты (`vpn` JSON) могут повысить уверенность, но их импорт —
  отдельный цикл (§15). В v1 поле `client_report` существует в схеме, но
  заполняется только вручную (`--client-report FILE`).
- §5.11 остаётся в силе: app-логи Xray при default loglevel не видят
  plain-TLS-пробы. Анализатор **не** пытается их «найти» и помечает источник
  как `blind`.

---

## 4. Архитектура

```
                    ┌──────────────────────────────┐
                    │ vds logs (typer, lazy import)│
                    └───────┬──────────────┬───────┘
        root only           │              │  read-only / no root
   ┌────────────────────────▼───┐   ┌──────▼─────────────────────┐
   │ collect / capture / sample │   │ analyze / report / explain │
   └───────┬───────────┬────────┘   └──────┬─────────────────────┘
           │           │                   │
   journald/nft/ss/    │ pcap (bounded)    │ bundle dir or --live
   nstat/ip/systemctl  │                    │
           │           ▼                    ▼
           │     ┌───────────┐      ┌──────────────┐
           │     │ pcap.py   │      │ normalize.py │
           │     │ parse/FP  │─────▶│ Event[]      │
           │     └───────────┘      └──────┬───────┘
           ▼                                ▼
   ┌──────────────┐                 ┌──────────────┐
   │ bundle/      │                 │ enrich.py    │
   │ manifest     │                 │ RU/own/ASN?  │
   │ raw (opt)    │                 └──────┬───────┘
   │ checksums    │                        ▼
   └──────┬───────┘                 ┌──────────────┐   ┌────────────┐
          │                         │ rules.py     │◀──│ baseline.py│
          └────────────────────────▶│ T-01..T-17   │   │ median/MAD │
                                    └──────┬───────┘   └────────────┘
                                           ▼
                                    ┌──────────────┐
                                    │ correlate.py │
                                    │ incidents    │
                                    └──────┬───────┘
                                           ▼
                                    ┌──────────────┐
                                    │ report.py    │
                                    │ JSON + MD    │
                                    └──────────────┘
```

| Компонент | Роль |
|---|---|
| `src/logs/paths.py` | все пути/имена (по образцу `gateway/paths.py`) |
| `src/logs/collect.py` | сбор bundle: источники, лимиты, redaction, manifest, checksums |
| `src/logs/sample.py` | компактный сэмпл телеметрии (таймер 5 мин) |
| `src/logs/normalize.py` | journal/UFW/nft/ss/nstat/pcap → канонический `Event` |
| `src/logs/enrich.py` | RU-CIDR, свои IP (AWG-endpoints/whitelist/сервер), шаблоны |
| `src/logs/rules.py` | каталог правил, пороги, severity |
| `src/logs/baseline.py` | построение/загрузка baseline (median/MAD, hour-of-day; hour-of-week opt-in ≥4 нед) |
| `src/logs/correlate.py` | группировка findings → incidents, confidence |
| `src/logs/report.py` | JSON-схема, MD-отчёт, санитайзер |
| `src/logs/pcap.py` | bounded capture, stdlib-парсер, опционально tshark |
| `src/logs/retention.py` | TTL/ротация/prune, disk-cap |
| `src/logs/explain.py` | карта покрытия/слепоты |

Почему отдельный модуль, а не расширение `gateway/probing.py`:
`probing` — L3/L4-телеметрия и вердикты (часовой тик, nft); `logs` — сбор,
хранение, разбор и корреляция (минуты/дни, диск, pcap). Разные жизненные
циклы и права. Общие функции (`load_ru_cidrs`, `classify_ip`, `load_own_ips`,
`read_awg_endpoints`) импортируются из `src.gateway.probing` без дублирования.

---

## 5. Сбор данных: bundle

### 5.1. Формат bundle

```
<out>/                                  # 0700 root
├── manifest.json                       # версия, host, окно, команды, лимиты, хэши
├── probe-watch.json                    # вердикт последнего тика + независимо
│                                       # посчитанная дельта (см. M1: watch
│                                       # МУТИРУЕТ снапшот/threat — НЕ вызывать)
├── telemetry/                          # копия сэмплов за окно (если есть)
├── raw/                                # опционально: matched|full
│   ├── journal-<unit>.log.gz
│   ├── kernel.log.gz
│   └── ...
├── pcap/                               # опционально, только при --include-pcap
└── checksums.sha256                    # всё, кроме самого файла
```

Свойства:
- `manifest.json` фиксирует: `bundle_version`, `created_at` (UTC), `host`,
  `role` (`exit|relay|lab`), `window{since,until}`, `tool_version`, `python`,
  `kernel`, `cmd[]` (argv списком, без shell), `limits`, `coverage`,
  `rules_hash`, `checksums`. Bundle — **одного хоста**; слияние exit+relay —
  non-goal v1 (разные часы/точки наблюдения, §15).
- bundle — **неизменяемое доказательство**: сырьё + снимки. Нормализованные
  `Event` — производные, живут в памяти анализатора (и в отчёте как
  агрегаты), в bundle не пишутся.
- `raw/` — по умолчанию `matched` (строки уровня error/warn/fatal, сигнатуры
  `REALITY|auth|BLOCK|DROP|OOM|failed|timeout|restart` +2 строки контекста,
  максимум 20 000 строк на источник), `--raw full` — полный journal за окно
  (gzip), `--raw none` — без сырья.
- `checksums.sha256` покрывает все файлы bundle; отчёт фиксирует хэш этого
  файла — целостность доказательств проверяется без доверия к каталогу.
- bundle **никогда** не содержит `/opt/my-vds/gateway/state.json` целиком:
  только `clients_count`, `protocols` (имена/порты/домены), без UUID/ключей.

### 5.2. Источники

| Источник | Как читаем | Что берём | Лимит |
|---|---|---|---|
| journal: `vds-xray`, `vds-hysteria2`, `-obfs`, `-hop`, `vds-amneziawg`, `vds-probe-watch`, `vds-probe-rucidr`, `vds-relay-*`, `vds-gateway-health` | `journalctl -u <unit> --since … --until … -o short-iso-precise` | ошибки/старты/падения/шаблоны | ≤200k строк/источник |
| journal: kernel (`-k`) | `journalctl -k` | UFW BLOCK/IN=, OOM, conntrack, link | ≤200k |
| journal: `sshd` | `journalctl -u ssh` | failed/invalid (шум для контекста) | ≤50k |
| nft | `nft -j list table inet vds_probe` | счётчики/сеты | один JSON |
| nft ruleset | `nft -j list ruleset` | счётчики правил UFW/relay/nat | один JSON |
| probe-watch | **НЕ вызывать `watch`** (ревью M1: он мутирует снапшот+threat и съедает дельту окна таймера → может сорвать RU-SUSPECT-гистерезис). Collect читает `/var/lib/vds/probe-watch.json` + `nft -j list table inet vds_probe` и считает дельту in-process чистым `compute_delta(current, snapshot)` БЕЗ save_snapshot/update_threat; в bundle: вердикт последнего тика + поле `computed_by: logs-collect (read-only)` | один JSON |
| snapshot | `/var/lib/vds/probe-watch.json` | история baseline/threat | один JSON |
| ss | `ss -Htn state established '( sport = :443 )'`, `ss -s` | ESTAB/SYN-RECV/очереди | мгновенно |
| nstat | `nstat -asz` (обязательно `-s`/`--no-update`: без него nstat СБРАСЫВАЕТ базовую линию в /tmp/.nstat.u0 и sample/collect обнуляют дельты друг друга; альтернатива — читать /proc/net/snmp+/proc/net/netstat напрямую) | TcpExt/Udp/Ip кумулятивные счётчики с бута | один дамп |
| interface | `ip -s -j link` | rx/tx bytes/packets/drops/errors | один JSON |
| systemd | `systemctl show -p …` по списку юнитов | ActiveState/NRestarts/Result | ≤20 юнитов |
| resources | `df -P`, `/proc/loadavg`, `free -b`, `conntrack -C` (если есть) | диск/память/таблица | один снимок |
| certs | `openssl x509 -enddate -noout -in <cert>` | days_left (без приватных ключей) | ≤10 сертификатов |
| config hashes | `sha256` файлов конфигов | дрейф без содержимого | ≤20 файлов |
| pcap | `vds logs parse-pcap` | ClientHello/метаданные | §8 |

Команды выполняются только через `run_list([...])` (AGENTS §5.2), без
`shell=True`; каждая команда имеет timeout и учитывается в `coverage`.

### 5.3. Redaction (обязательно)

- **Запрещено** попадание в bundle/отчёт: UUID клиентов, приватных ключей,
  `privateKey`, `shortIds`, паролей/auth, `state.json` целиком, share-ссылок,
  TLS-ключей, содержимого `/etc/letsencrypt/archive`.
- Конфиги — только `sha256` и whitelisted-поля (порт, домен, SNI, путь).
- Строки журнала проходят санитайзер: `uuid4` → `<uuid>`, `password=…`/
  `auth=…` → `<redacted>`, share-ссылки; контекстные маркеры ключей
  (`privateKey`, `PrivateKey =`, `PreSharedKey =`, `shortIds`, `password`) → <blob>;
  жадный `hex/base64 ≥32 → <blob>` — ТОЛЬКО к сырому тексту raw/*.log, НЕ к
  JSON-полям (sha256/checksums/rules_hash/ja3/ja4 — легальный hex; иначе
  пост-сканер аварийно удаляет собственный бандл из-за манифеста!)
  (`vless://`, `hysteria2://`, `vpn://`) → `<link>`.
- Санитайзер работает **всегда**; каждая замена считается и попадает в
  `coverage.redactions` + `[warning]`. Если после санитайзера пост-сканер
  находит секрет — сбор аварийно завершается, bundle удаляется (это баг
  редактора, а не «особый случай»).
- `--redact-ips` — IP заменяются на `HMAC-SHA256(key, ip)[:12]` с префиксом
  `ip:`. Ключ — `/etc/vds-forensics/redact.key` (0600, генерируется при
  `logs install --apply`), **не** попадает в bundle. Без установленного ключа
  `--redact-ips` завершается ошибкой с подсказкой `logs install`. Нужен для
  передачи разбора наружу без раскрытия клиентских адресов.
- Тест-сканер (unit) проверяет bundle и отчёт на паттерны секретов; при
  находке — `error`, запись не создаётся.

### 5.4. Лимиты и отказы

| Параметр | Default | Поведение при превышении |
|---|---|---|
| окно анализа | 24h | `--since` ≤ 168h, иначе fail |
| размер bundle | 200 MB | остановка, `[error]` с предложением сузить окно/`--raw none` |
| строк на источник | 200k | обрезка + `coverage.partial=true`, предупреждение |
| время сбора | 120 s | таймаут источника → `missing`, сбор продолжается |
| pcap | 5×10 MB, ≤1h | авто-стоп, см. §8 |
| disk free | ≥2 GB | отказ от сбора/захвата |

Сбор **не блокирует** сервисы: только read-only команды; `journalctl` без
`-f`; никаких рестартов/локов (кроме FileLock на запись артефактов). Сам
сбор в сеть не ходит; единственное исключение — вызов существующего
чтения `/var/lib/vds/probe-watch.json` + `nft -j` с in-process compute_delta (M1; вызов мутирующего `watch` ЗАПРЕЩЁН). Анализатор сеть не использует вообще.

Отдельно фиксируется **активный lock-443**: UFW роняет SYN после nft-hook
−140, поэтому `syn_valid=0` — это не «проб нет», а «момент ослепления».
`coverage` получает `lockdown.active=true` и note; отсутствие T-01/T-03 в
таком окне не трактуется как «чисто».

---

## 6. Телеметрия: сэмплер и временные ряды

### 6.1. Sample (NDJSON, одна строка = 5 мин)

```json
{
  "v": 1,
  "ts": "2026-11-16T12:05:00Z",
  "host": "asv2",
  "window_s": 300,
  "nft": {"syn_bare": 812, "syn_valid": 37, "udp_443": 10422,
          "probers": 19, "probers_ru": 2, "per_element": true},
  "ss": {"estab_443": 4, "synrecv_443": 0}, "awg": {"peers_fresh_lt180s": 1}  # estab_51825 НЕ СУЩЕСТВУЕТ: 51825=UDP, у WG-сокета состояние UNCONN; активность AWG = свежесть latest-handshakes (<180с)
  "net": {"eth0": {"rx_b": 81234567, "tx_b": 90123456,
                    "rx_d": 0, "tx_d": 0, "rx_e": 0, "tx_e": 0}},
  "nstat": {"TcpRetransSegs": 12, "TcpOutSegs": 98000,
             "TcpExtTCPTimeouts": 1, "TcpExtListenOverflows": 0,
             "TcpExtListenDrops": 0, "UdpInErrors": 0, "IpInDiscards": 0},
  "units": {"vds-xray": {"state": "active", "restarts": 0},
             "vds-hysteria2": {"state": "active", "restarts": 0}},
  "res": {"conntrack": 412, "conntrack_max": 65536, "disk_pct": 41,
           "load1": 0.11, "mem_avail_b": 812345678},
  "lockdown": {"active": false},
  "threat": "quiet"
}
```

Счётчики nft — **кумулятивные** значения; анализатор считает дельты между
соседними сэмплами (как `compute_delta` в `probing`), отрицательная дельта
трактуется как reset (переустановка таблицы/ребут) и помечается `reset=true`.

### 6.2. Каденция

| Что | Период | Кто |
|---|---|---|
| sample | 5 мин | `vds-logs-sample.timer` |
| probe-watch (вердикт) | 1 час | существующий `vds-probe-watch.timer` |
| daily analyze + prune | 04:15 | `vds-logs-daily.timer` |
| baseline rebuild | ежедневно в daily, окно 14 дней | `logs baseline build` |
| incident bundle | по запросу/после `high` | оператор |

Юниты — oneshot, `Nice=10`, `IOSchedulingClass=idle`, `RandomizedDelaySec=30` (sampler — не синхронизироваться с gateway-health), `MemoryMax=64M` sampler / `MemoryMax=192M` daily-analyze (ревью G2), `TimeoutStartSec=120`,
`ProtectSystem=strict` + `ReadWritePaths=/var/lib/vds`, `NoNewPrivileges=yes`.

### 6.3. Хранение и ротация

- `/var/lib/vds/telemetry/YYYY-MM-DD.ndjson` (0700/0600), 7 дней по умолчанию.
- `/var/lib/vds/forensics/baseline.json`, `reports/`, `bundles/`, `captures/`.
- `vds logs prune` удаляет по TTL (см. §11); `--apply` обязателен, dry-run
  печатает план и объём.
- Ротация — по дате, не по размеру; при превышении disk-cap —
  `[warning]` и отказ писать новые сэмплы (не забивать диск).

### 6.4. Оценка объёма

Сэмпл ≈ 2–5 KB → 288/сутки ≈ 0.6–1.4 MB/сутки; 7 дней ≈ 4–10 MB.
Baseline ≈ 0.5–2 MB. Bundle 24h (matched raw, gzip) ≈ 2–20 MB.
Дефолты заведомо ниже лимитов слабого VDS (10 GB).

---

## 7. Алгоритм анализа

### 7.1. Канонический Event

```json
{
  "ts": "2026-11-16T11:59:58.123Z",
  "source": "kernel|journal:xray|journal:hysteria2|nft|ss|nstat|net|probe|pcap|systemd|resource",
  "signal": "ufw_block|syn_bare|syn_valid|udp_443|estab|auth_fail|unit_restart|...",
  "proto": "tcp|udp|icmp|null",
  "src_ip": "203.0.113.7",
  "src_port": 43121,
  "dst_port": 443,
  "bytes": 40,
  "count": 1,
  "outcome": "ok|fail|drop|timeout|reset|unknown",
  "template": "a1b2c3d4e5f6",
  "fingerprint": {"ja3": "...", "ja4": "...", "ch_len": 517, "sni": "..."},
  "tags": ["RU", "own", "scanner", "probe_series"],
  "raw_ref": "raw/kernel.log.gz#L1203"
}
```

Правила нормализации:
- все времена — UTC RFC3339 с миллисекундами; источник с иным TZ
  конвертируется и помечается `tz_assumed=true`;
- `src_ip` валидируется `ipaddress`; невалидный — `src_ip=null`,
  `tags+=["invalid_ip"]`;
- IPv6 не отбрасывается, но в правила v1 участвует только как контекст
  (probe-watch v1 IPv4-only — §5.11);
- дубликаты (один и тот же `source+ts+signal+src_ip+count`) схлопываются;
- объём: потоковый парсер, память ≤150 MB на 24h.

### 7.2. Конвейер (псевдокод)

```text
analyze(input, window, opts):
    bundle   = input or collect_live(window)          # read-only
    coverage = Coverage.from(bundle)
    baseline = load_baseline() or ColdStart()
    events   = []
    for src in bundle.sources:                        # streaming, bounded
        events += normalize(src)
    events   = dedup(filter_own(enrich(events)))      # RU/own/ASN?/template
    findings = []
    for rule in RULES:                                # фиксированный порядок
        findings += rule.evaluate(events, baseline, coverage)
    findings = score(findings, coverage, baseline.quality)
    incidents = correlate(findings)
    report    = render(incidents, findings, coverage, bundle.manifest)
    assert redaction(report) and deterministic(report)
    return report
```

Инварианты:
- порядок правил фиксирован (ID), findings сортируются `(window_start, rule,
  evidence_hash)`; ID = `sha256(rule|window|evidence_key)[:12]`;
- `--live` не создаёт файлов (кроме временного каталога в `/tmp`, удаляется);
- при `coverage.critical_missing` (нет nft + нет probe + нет kernel) отчёт
  выдаётся как `inconclusive`, high-confidence запрещён.

### 7.3. Обогащение

| Поле | Источник | Fallback |
|---|---|---|
| `RU` | `/etc/vds-relay/ru-cidrs.txt` (`load_ru_cidrs`) | `unknown` + `geo_source` |
| `own` | серверный IP, AWG-endpoints, `/etc/vds-probe-watch/allow-ips.txt` | только серверный IP |
| `scanner` | bare-SYN 40 б / известные шаблоны | — |
| `template` | нормализация строки (см. §7.4) | — |
| `novel` | отсутствие template-hash в baseline | `true` при cold start |
| `client_report` | `--client-report FILE` (JSON от `vpn`) | отсутствует |

### 7.4. Шаблонизация журнала (без ML)

Детерминированная нормализация строки:
`UUID→<uuid>`, `IPv4/IPv6→<ip>`, `числа→<n>`, `hex≥16→<hex>`,
`/path/…→<path>`, `"…"→<str>`, `email→<email>`, `домен→<domain>`.
Хэш `sha1(template)[:12]`. Baseline хранит **только хэши** и счётчики (не
текст) — это и приватно, и достаточно для «новая ошибка появилась».

### 7.5. Каталог правил (v1)

Severity — если finding подтверждён; итоговая уверенность считается отдельно
(§7.6).

| ID | Правило | Триггер (static) | Baseline-режим | Sev | Смысл |
|---|---|---|---|---|---|
| T-01 | `tcp443_data_blackhole` | `syn_validΔ>0` И (доля `:443`-сокетов с retrans/Send-Q>0/`timer:(on,)` ≥60%) 3 сэмпла подряд (15 мин), `TcpExtTCPTimeouts`/`TcpRetransSegs`↑; `bytes_acked≈0` у новых (ревью G2-2: при data-phase blackhole сокеты ВИСЯТ ESTABLISHED-зомби, а не исчезают — estab=0 физически недостижим сразу после ClientHello) | baseline estab/retrans | high | SYN проходит, данные душатся (§5.9) |
| T-02 | `udp443_collapse` | `udp_443Δ < 20%` медианы 3 из 4 сэмплов (20 мин) при active hy2 И **медиана ≥ absolute-floor** (при median≈0 правило неприменимо — static-skip, ревью G2) | устойчивое падение | medium | UDP-путь деградировал/заблокирован |
| T-03 | `ru_active_probe` | вердикт `RU-PROBE-SUSPECT` из probe-watch | — | high | активное зондирование из РФ |
| T-04 | `mass_scan` | вердикт `PROBE-BURST` | — | info | масс-сканеры, не ТСПУ |
| T-05 | `hy2_auth_bruteforce` | ≥20 `auth_fail`/10 мин с одного src | z>4 | medium | перебор пароля/скан |
| T-06 | `ufw_block_flood` | ≥50 BLOCK/10 мин один src+DPT | z>4 | low | сканер/шум |
| T-07 | `pcap_probe_series` | ≥6 ClientHello/10 с с одного src на 443 **или** 8-пробная серия (443) | — | high | профиль активного зондирования (И40) |
| T-08 | `pcap_garbage_probe` | первый PSH-байт `!= 0x16` (не-TLS мусор) ИЛИ CH len `< 180` (примитивный сканер) ≥3 | — | medium | артефакт проб (И41; ВАЖНО: нормальный ClientHello 517–1300Б — <209/>214 давало 100% FP на браузерах с PQ-Kyber) |
| T-09 | `unit_instability` | `NRestarts↑`, `failed`, OOM | — | high | локальный сбой, не цензор |
| T-10 | `resource_pressure` | conntrack>80%, disk>90%, fd>80% | — | high | локальный риск |
| T-11 | `cert_expiry` | days_left <7 | — | medium | сломается сам |
| T-12 | `relay_leg_down` | relay активен, awg1 handshake >300 с | — | high | нога релея мертва |
| T-13 | `clock_skew` | скачок >2 с (`chronyc`/journal) | — | low | окна недостоверны |
| T-14 | `prober_mix_anomaly` | доля новых /24 > baseline + 3×MAD | только baseline | medium | новая кампания/сеть |
| T-15 | `config_drift` | sha конфига изменился без deploy-события в журнале | — | info | ручная правка/дрейф |
| T-16 | `novel_log_template` | новый template ≥3 раза за окно | только baseline `high` | low | новая ошибка/версия |
| T-17 | `panic_or_crash_loop` | `panic`/`fatal`/`segfault` ≥2 или Restart loop | — | high | локальная авария |

**Guard от ложных срабатываний на простое:** T-01/T-02 применяются только при
подтверждённой клиентской активности (estab/transfer в предыдущем окне,
AWG-handshake <5 мин или `--client-report`). Пустой сервер без клиентов —
не «blackhole»; такие findings понижаются до `info`/`inconclusive`.
T-16 при cold-start baseline не срабатывает (все шаблоны «новые»).

Пороги — константы `src/logs/rules.py`; override —
`/etc/vds-forensics/rules.json` (JSON, валидируется схемой, `rules_hash`
печатается в отчёте). Менять пороги «на ходу» без версии нельзя.

### 7.6. Корреляция, уверенность, вердикт

**Источники доказательств** (независимые): `nft`, `kernel`, `ss`, `app-log`,
`pcap`, `probe`, `resource`, `client_report`.

- `confidence=low` — 1 источник или baseline отсутствует;
- `medium` — 2 независимых источника;
- `high` — ≥3 источника, из них ≥1 прямой (`nft`/`kernel`/`pcap`);
- понижение на 1 шаг, если: clock_skew (T-13), окно <30 мин,
  `coverage.partial`, baseline cold-start.

**Типы инцидентов** (не «ТСПУ подтверждён»!):

| Тип | Условие | Рекомендация |
|---|---|---|
| `probing_only` | T-03/T-07 без эффекта | наблюдать; конфиги не менять; проверить резервный транспорт |
| `effect_only` | T-01/T-02 без проб | вероятнее путь/апстрим; внешняя проверка, не рестарт |
| `probing_plus_effect` | T-03/T-07 **и** T-01/T-02 в ±2 окнах | готовить переключение клиента (Hy2/asv1/relay); лок 443 — по `probe-response` |
| `mass_scan` | T-04 | игнор, не эскалировать |
| `local_fault` | T-09/T-10/T-11/T-12/T-17 | чинить локально |
| `inconclusive` | coverage критичен/противоречия | сузить окно, добрать источник |

Правило: **один finding никогда не даёт `probing_plus_effect`**; и
`probing_plus_effect` не исполняет действий — только рекомендация.

### 7.7. Дерево триажа (15 минут)

```
1. Интерфейс получает пакеты? (net.rx, ip -s)
   нет ─▶ блок IP/апстрим/провайдер. Нужен внешний vantage. Сервер не различает.
   да ─▶ 2
2. SYN на 443 приходят? (nft syn_bare/syn_valid)
   нет, но клиенты жалуются ─▶ SNI/DNS/путь на стороне клиента. Сервер слеп.
   да ─▶ 3
3. ESTABLISHED на 443 есть? (ss-сэмплы)
   нет + timeouts/retrans↑ ─▶ T-01 data-phase blackhole: НЕ рестартить, ждать/переключить.
   да ─▶ 4
4. UDP-443 объём в норме? (udp_443Δ vs baseline)
   нет ─▶ T-02: проверить hy2/hop/obfs, переключить клиента.
   да ─▶ 5
5. Всплеск проб? (probe verdict, pcap)
   да, без деградации ─▶ probing_only: наблюдать.
   да + деградация ─▶ probing_plus_effect: готовить манёвр.
   нет ─▶ 6
6. Локальные ошибки/ресурсы? (T-09/T-10/T-11/T-12/T-17)
   да ─▶ local_fault: чинить.
   нет ─▶ inconclusive: добрать источники/расширить окно.
```

### 7.8. Baseline (медиана/MAD, без ML)

- Ключ: `metric` × `hour_of_day` (24 бакета; ревью G2: 14 дней × 12 точек/час → ~168 точек/бакет, MAD устойчив; `hour_of_week` (=2×12=24 точки, MAD-ошибка ~30%) — opt-in после накопления ≥4 недель).
- Baseline строится на logs-телеметрии (5-мин сэмплы), НЕ на probe-watch-снапшотах.
- Non-scorable: MAD=0 или медиана ниже absolute-floor метрики → бакет static-режим (правило по абсолютному порогу, z не считается).
- Минимум: 7 дней и ≥20 сэмплов на бакет; иначе глобальная медиана, качество
  `low`.
- Аномалия: `z = 0.6745·(x − median)/MAD`; `|z| ≥ 3.5` → medium, `≥5` → high,
  но **всегда** с абсолютным минимумом (например, `syn_validΔ ≥ 20`), чтобы
  шум на нулевой медиане не давал тревог.
- `reset`-дельты (переустановка nft/ребут) помечаются и не участвуют в
  baseline.
- Baseline хранит: `version`, `built_at`, `window_days`, `rules_hash`,
  `metrics{median,mad,p10,p90,count}`, `templates[unit]={hash:count}`.

### 7.9. Схема отчёта

```json
{
  "schema_version": 1,
  "bundle": {"created_at": "...", "window": {"since": "...", "until": "..."}},
  "tool": {"version": "...", "rules_hash": "...", "python": "3.12"},
  "coverage": {
    "nft": {"status": "ok", "note": ""},
    "pcap": {"status": "missing", "note": "tshark не установлен"},
    "geo": {"status": "ok", "source": "ru-cidrs"}
  },
  "baseline": {"quality": "high|low|none", "built_at": "..."},
  "findings": [
    {"id": "…", "rule": "T-01", "severity": "high", "confidence": "medium",
     "window": ["...", "..."],
     "evidence": [{"source": "nft", "metric": "syn_valid", "value": 240},
                   {"source": "ss", "metric": "estab443_zombie_pct", "value": 80}],
     "hypothesis": "TCP-443 data-phase blackhole",
     "alternatives": ["upstream"], "action": "не рестартить; проверить Hy2"}
  ],
  "incidents": [],
  "summary": {"verdict": "effect_only", "confidence": "medium", "headline": "..."}
}
```

Пример человеческого отчёта:

```text
# Инцидент 2026-11-16 12:15 · bundle incident-20261116 (24h)

## Наблюдали
- 11:58–12:08 syn_valid Δ=240, доля зомби-сокетов :443 (retrans/Send-Q>0) = 80% (3 сэмпла), TCPTimeouts +7
- probe-watch: RU-PROBE-SUSPECT (12:00), threat=elevated
- ресурсы/юниты: без изменений

## Гипотеза
- probing_plus_effect (medium): активное зондирование + data-phase blackhole TCP/443
- альтернатива: апстрим/провайдер — с сервера не различается

## Чего не видим
- JA3/JA4: tshark отсутствует; SNI/DNS-блок — только со стороны клиента

## Что делать
- не рестартить xray; проверить Hy2; при ухудшении — манёвр клиента (relay/asv1)
- лок 443 — только по процедуре probe-response, не этим отчётом
```

MD-отчёт (`REPORT.md`) — тот же контент по-русски: «Что наблюдали», «Что это
может быть», «Чего мы не видим», «Что делать», «Доказательства».

### 7.10. Операционный цикл (SOP)

| Шаг | Когда | Действие | Выход |
|---|---|---|---|
| 0. Мониторинг | постоянно | sample 5 мин + probe-watch 1 ч | временные ряды/вердикты |
| 1. Сигнал | `threat≥elevated`, жалоба клиента, аномалия daily | `vds logs collect --since 2h --apply` | bundle с фиксированным окном |
| 2. Разбор | сразу | `vds logs analyze <bundle>` | findings + coverage |
| 3. Триаж | ≤15 мин | дерево §7.7 | тип инцидента + уверенность |
| 4. Уточнение | если `inconclusive`/нужны пробы | `vds logs capture start --duration 1h` → `parse-pcap` | pcap-метаданные, T-07/T-08 |
| 5. Действие | по типу | `probing_only` — наблюдать; `effect_only` — внешняя проверка; `probing_plus_effect` — манёвр клиента; `local_fault` — чинить | решение + запись в STATUS |
| 6. Закрытие | после стабилизации | `vds logs report --last`, де-идентифицированный вывод — в CENSORSHIP-PATTERNS (ревью) | отчёт/урок |
| 7. Гигиена | ежедневно 04:15 / еженедельно | daily analyze + prune; baseline 14d; проверка `logs explain` | диск в норме, baseline свежий |

Правила цикла:
- окно фиксируется **до** действий и не расширяется задним числом (иначе
  evidence «плывёт»);
- шаг 5 не выполняется по `inconclusive`; вместо этого добирается источник;
- после инцидента baseline **не** перестраивается в том же окне (риск
  «отравить» норму); перестройка — на следующий день;
- любое действие (лок/переключение) фиксируется в STATUS с ссылкой на bundle.

---

## 8. Захват и разбор pcap (опционально)

### 8.1. Политика

- **Только по явной команде** (v1). Авто-захват по `threat=high` — OQ-4.
- Захват ограничен: `--duration` (default 1h, max 4h), `--max-mb` (default
  50, **клампится к 50 при кольце -C 10 -W 5; >50 → пересчёт C = max_mb//5**, ревью G2), `-G` (авто-стоп). Легитимные Reality-клиенты попадают в фильтр — осознанно, metadata-only/TTL.
- Фильтр: только 443/tcp, SYN + TLS-handshake-записи; исключить серверный IP,
  whitelist и private ranges:
  `tcp port 443 and (tcp[tcpflags] & tcp-syn != 0 or tcp[((tcp[12] & 0xf0) >> 2):2] = 0x1603) and not host <own>`
- `-s 1600` (полный MTU: PQ-TLS ClientHello Chrome 130+ ~1100–1300Б, `-s 1024` резал его).
- BPF обязан начинаться с `ip and` (IPv4-only v1): classic BPF `tcp[n]` в libpcap НЕ РАБОТАЕТ для IPv6 (protochain not supported) — на asv2 (/48) tcpdump упадёт.
- Несколько собственных IP → `and not (host A or host B or …)`, не цепочка `not host`.
- Путь — `/var/lib/vds/forensics/captures/` (не `/var/tmp`), 0700/0600.
- `--metadata-only` (default): после разбора pcap удаляется, остаются
  `pcap-summary.json` и хэши.
- `stop` убивает только PID из pidfile после проверки `comm == tcpdump`
  (не «по порту/имени», AGENTS §6/TECHDEBT P4).
- Без `tcpdump` — `[error]` и инструкция; без `tshark` — degraded-режим.

### 8.2. Разбор

| Уровень | Инструмент | Что даёт |
|---|---|---|
| L3/L4 | stdlib (`struct`) | времена, src/dst, длины, SYN/ACK/RST, inter-arrival |
| TLS ClientHello | stdlib-парсер (record 0x16 0x03) | `ch_len`, SNI, ALPN, cipher count |
| JA3/JA4 | `tshark -T fields -e tls.handshake.ja3 -e tls.handshake.ja4` | отпечаток (если установлен; поля зависят от версии Wireshark) |
| Серия | правила T-07/T-08 | 8-пробная серия/мусорные длины |

Деградация честная: без `tshark` отчёт пишет
`pcap.fingerprint = "unavailable (tshark missing)"`, а не «проб нет».

### 8.3. Приватность pcap

pcap содержит IP/порты/SNI. Поэтому: не в git (`.gitignore`), не в bundle
по умолчанию, TTL 7 дней, `--delete-after-parse` по умолчанию, в отчёт
попадают только агрегаты/хэши (при `--redact-ips` — и IP хэшируются).

---

## 9. CLI

```bash
# сбор (root; dry-run по умолчанию — конвенция AGENTS §5.8)
sudo vds logs collect --since 24h --out /root/incident-20261116 --apply
sudo vds logs collect --since 24h --raw none --redact-ips --apply
sudo vds logs collect --since 2h --include-pcap --apply

# анализ (read-only; root не нужен)
vds logs analyze /root/incident-20261116
vds logs analyze --live --since 24h --json
vds logs analyze /root/incident-20261116 --client-report client.json --out report.md

# телеметрия и baseline (root)
sudo vds logs sample --apply
sudo vds logs baseline build --days 14 --apply
vds logs baseline show

# pcap (root)
sudo vds logs capture start --duration 1h --max-mb 50 --apply
sudo vds logs capture status
sudo vds logs capture stop --apply
vds logs parse-pcap <file.pcap> --delete-after-parse

# отчёты/обслуживание
vds logs report --last
vds logs report --last --json
sudo vds logs prune --apply
sudo vds logs install --apply      # каталоги, redact.key, sample/daily timers
sudo vds logs remove --apply
vds logs explain                   # карта покрытия/слепоты (без root)
```

| Команда | Root | Мутация | Exit codes |
|---|---|---|---|
| `collect` | да | создаёт bundle (с `--apply`) | 0/1/2 |
| `analyze` | нет | нет | 0 — ok, 1 — findings ≥ medium, 2 — ошибка |
| `sample` | да | пишет сэмпл | 0/1/2 |
| `baseline build` | да | пишет baseline | 0/1/2 |
| `capture *` | да | pcap/pidfile | 0/1/2 |
| `parse-pcap` | нет | может удалить pcap | 0/1/2 |
| `prune` | да | удаляет | 0/1/2 |
| `install/remove` | да | юниты/каталоги | 0/1/2 |
| `explain` | нет | нет | 0 |

`--json` — стабильный контракт для агентов/будущего CI: `schema_version`,
`summary`, `findings`, `coverage`, `exit_code`.

Ограничение `--live` без root: привилегированные источники (`nft`, `journal`
вне группы `systemd-journal`, `ss` чужих процессов) дают
`coverage.status=denied`; полноценный анализ — по bundle, собранному root'ом.

Пример вывода:

```text
[logs] bundle: /root/incident-20261116 (24h, 12.4 MB)
[logs] coverage: nft ok · kernel ok · ss ok · pcap missing (no tshark) · geo ok
[logs] baseline: high (14d)
[logs] T-01 tcp443_data_blackhole  high/medium   11:58–12:08
[logs]   evidence: nft syn_valid Δ=240; ss :443 zombie-sockets (retrans/Send-Q>0) = 80% (3 samples); nstat timeouts +7
[logs] verdict: effect_only (medium) — вероятнее data-phase DPI/апстрим
[logs] action: не рестартить xray; проверить Hy2; повторить через 30 мин
```

---

## 10. Интеграция

| Куда | Что |
|---|---|
| `probe-watch` | source of truth для вердиктов; collect читает снапшот+nft с in-process дельтой (M1), анализатор не пересчитывает пороги |
| `probe-response` | анализатор **не** вызывает lock-443; рекомендация в отчёте, исполнение — оператор/авто-лок |
| `ufw` | `coverage` фиксирует активный лок (он ослепляет `syn_valid` — §9.A probe-response) |
| `gateway healthcheck` | пересечение по T-09/T-10: healthcheck чинит, logs объясняет |
| `docs/LOG-FORENSICS.md` (новый, living) | операторский ранбук: триаж §7.7, правила, retention, приватность |
| `SERVER-BASELINE` §5.13 | ручной `tcpdump` → `vds logs capture`; старый рецепт остаётся fallback |
| `SERVER-BASELINE` §5.8 | sample/daily timers в reboot-гейт |
| `CENSORSHIP-PATTERNS` §1.12 | де-идентифицированные выводы (после ревью), не сырые дампы |
| `CENSORSHIP-ROADMAP` | W1/W4 — закрыть «нет наблюдаемости» по факту |
| `doc-sync` (если принят) | правило `src/logs/** → README/AGENTS/LOG-FORENSICS/SERVER-BASELINE`; класс `living` |
| Гейты G4/G5 | в DoD: `vds logs explain` без сюрпризов, отчёт по инциденту приложен |
| `.gitignore` | `*.pcap`, `*.ndjson`, `bundles/`, `captures/`, `telemetry/` |

ADR-012 фиксирует: новые пути, формат артефактов, privacy-контракт,
bounded-capture, «анализатор не реагирует». Структура ADR: контекст (слепота
сервера, §5.11), решение (наблюдаемость эффектов + bounded pcap), последствия
(диск/TTL/приватность), альтернативы (SIEM, log-shipping, только probe-watch),
откат (`logs remove --apply`, удаление каталогов).

**RU-релей:** тот же модуль ставится на relay-хост (`role=relay`), источники —
`vds-relay-*`, `awg1`; bundle/отчёты — раздельные по хостам. Слияние
exit+relay в один отчёт — non-goal v1: разные vantage и часы.

### 10.1. Doc delta (для G2)

| Документ | Изменение | WP |
|---|---|---|
| `docs/LOG-FORENSICS.md` | **новый** living: триаж §7.7, правила, privacy/retention, SOP | WP-5 |
| `docs/adr/ADR-012-log-forensics.md` | **новый** ADR — **WP-1** (M2: пути/redaction-контракт/.gitignore — необратимые решения, ADR до реализации; WP-5 лишь дополняет) | WP-1 |
| `README.md` | раздел `vds logs`, пути, таймеры, «дампы не в git» | WP-5 |
| `AGENTS.md` | `src/logs/`, команды, тесты `tests/logs/`, структура | WP-5 |
| `SERVER-BASELINE.md` | §5.13 — tool вместо ручного tcpdump (старый рецепт fallback); §5.8 — timers; §5.14 — риск | WP-5 |
| `DEPLOY.md` | post-deploy `vds logs install --apply` (opt-in, OQ-2) | WP-5 |
| `MIGRATE-VDS.md` | каталоги telemetry/forensics, `redact.key`, переустановка timers | WP-5 |
| `CENSORSHIP-PATTERNS.md` | §1.12 «наблюдаемость эффектов» + де-идентифицированные выводы | WP-5 |
| `CENSORSHIP-ROADMAP.md` | закрыть «нет наблюдаемости» в W1/W4 по факту | WP-5 |
| `.gitignore` | `*.pcap`, `*.ndjson`, `bundles/`, `captures/`, `telemetry/` | WP-1 |
| `docs/doc-sync.json` | класс `living` для `LOG-FORENSICS.md` + правило `src/logs/** → README/AGENTS/LOG-FORENSICS/SERVER-BASELINE` (если doc-sync принят) | WP-5 |

---

## 11. Хранение, приватность, retention

| Артефакт | Путь | TTL default | Права | В git |
|---|---|---|---|---|
| samples | `/var/lib/vds/telemetry/*.ndjson` | 7 дней | 0700/0600 | нет |
| baseline | `/var/lib/vds/forensics/baseline.json` | пересоздаётся | 0600 | нет |
| bundles | `/var/lib/vds/forensics/bundles/` | 30 дней | 0700 | нет |
| reports | `/var/lib/vds/forensics/reports/` | 90 дней | 0600 | нет |
| captures | `/var/lib/vds/forensics/captures/` | 7 дней / после parse | 0700 | нет |
| redact.key | `/etc/vds-forensics/redact.key` | бессрочно | 0600 | нет |
| rules override | `/etc/vds-forensics/rules.json` | бессрочно | 0600 | нет |

Правила:
- всё локально; сетевой экспорт — только вручную оператором;
- `prune` — единственный путь удаления; dry-run печатает объём;
- при `disk_pct > 90` сэмплер не пишет, daily-отчёт помечает T-10;
- IP клиентов — персональные данные: не публиковать; для обмена использовать
  `--redact-ips`;
- pcap — самый чувствительный артефакт: default `--metadata-only`.

---

## 12. Тест-план и критерии приёмки

### 12.1. Unit (без root/сети, temp-каталоги)

| Что | Проверка |
|---|---|
| Нормализация journal | фикстуры xray/hy2/kernel/sshd → Event, TZ, невалидный IP |
| UFW/kernel | извлечение `SRC/DPT`, агрегация, шаблоны |
| nft JSON | кумулятивные счётчики, reset, per-element/fallback |
| ss/nstat/ip | парсинг реальных форматов (фикстуры), отсутствие поля → partial |
| Шаблонизация | UUID/IP/hex/path → стабильный hash; одинаковые строки → один template |
| Redaction | UUID, ключи, share-link, password → `<redacted>`; скан bundle/отчёта |
| Правила | каждый T-01…T-17: positive/negative/edge; порядок и стабильные ID |
| Корреляция | 1 источник → low; 3 → high; coverage missing понижает |
| Baseline | MAD на синтетике, cold start, reset-дельты исключены |
| Pcap stdlib | синтетический pcap (struct): CH len/SNI/серия; битый файл |
| Retention | TTL/prune/disk-cap; ничего лишнего не удалено |
| Безопасность | нет shell=True, нет сети, нет импорта проекта в AST-режиме |
| Детерминизм | два прогона → идентичный JSON (кроме `created_at` bundle) |

### 12.2. Integration (temp repo/каталог, моки `run_list`)

1. `collect` на мок-источниках → bundle с manifest/checksums; размер ≤ лимита.
2. `analyze` bundle → JSON по схеме; exit 0/1 по severity.
3. `--live` + отсутствие nft → `coverage.missing`, verdict `inconclusive`,
   без high-confidence.
4. Секрет в фикстурной строке → санитайзер заменяет и пишет `warning`; если
   после санитайзера пост-сканер нашёл секрет → сбор **падает**, bundle
   удаляется.
5. `--redact-ips` → в bundle/отчёте нет исходных IP, хэши стабильны.
6. Синтетика «клиент активен, SYN есть, estab=0, timeouts↑» → T-01 +
   `effect_only`.
7. Синтетика «пробы + эффект при активном клиенте» → `probing_plus_effect`,
   рекомендация без вызова lock-443.
8. pcap-серия 8 ClientHello → T-07; мусорные длины → T-08.
9. `prune --apply` на дереве с TTL → удалено ровно по политике.
10. `install --apply` → юниты/каталоги/key; повторный запуск идемпотентен.

### 12.3. Ручная приёмка (живой VDS, asv2)

- Сбор 24h на asv2 ≤ 60 с, bundle ≤ 50 MB (matched raw).
- `analyze` на asv2 при `quiet` → нет medium+ findings (ложных).
- Инсценировка: `tcpdump`-фикстура серии проб → T-07/T-08.
- Инсценировка: остановить xray на 2 мин → T-09/T-17, но **не** T-01.
- Проверка слепоты: plain-TLS-проба к 443 при default loglevel → отчёт
  честно пишет `app-log blind`, вердикт не выдумывается.
- `capture start/status/stop` — авто-стоп по времени/объёму; pcap удалён
  после parse.
- Ребут → sample/daily timers `active (waiting)`, каталоги на месте.

### 12.4. AC

- **AC-1:** 24h-инцидент разбирается одной командой; отчёт содержит
  доказательства и `coverage`.
- **AC-2:** ни один артефакт не содержит секретов/UUID/ключей/payload;
  тест-сканер зелёный.
- **AC-3:** анализ офлайн/без root; pcap не обязателен для базового вывода.
- **AC-4:** `probing_plus_effect` невозможен по одному источнику; слепота
  сервера отражена в каждом отчёте.
- **AC-5:** bundle/телеметрия/pcap ограничены и удаляются по TTL.
- **AC-6:** анализатор не меняет состояние сервера (read-only, ни одного
  `--apply` внутри `analyze`).

---

## 13. Work packages

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | Каркас: `paths`, CLI, `collect` (источники/лимиты/redaction/manifest/checksums), `explain`, `.gitignore` | `src/logs/paths.py`, `collect.py`, `explain.py`, `src/main.py`, `.gitignore`, `tests/logs/` | — | bundle собирается на моках; redaction-тест; повторный `collect --apply` не перезаписывает старый bundle |
| WP-2 | Сэмплер и телеметрия: парсеры nft/ss/nstat/ip/systemctl, store/rotation, юниты | `sample.py`, `paths.py`, `systemd/vds-logs-*`, `tests/logs/` | WP-1 | sample 5 мин, ротация 7 дней, reboot-гейт; дельты/reset |
| WP-3 | Анализ: normalize/templates, enrich, rules T-01…T-17, baseline, correlate, report JSON/MD | `normalize.py`, `enrich.py`, `rules.py`, `baseline.py`, `correlate.py`, `report.py`, `tests/logs/` | WP-1, WP-2 | golden-тест детерминизма; все правила positive/negative; AC-1/AC-4 |
| WP-4 | Pcap: bounded capture, stdlib-парсер, tshark-адаптер, T-07/T-08 | `pcap.py`, `systemd/` (если нужно), `tests/logs/` | WP-2 | авто-стоп, pidfile-guard, синтетический pcap, metadata-only |
| WP-2+ | расширяет paths.py/tests/logs, НЕ меняя контракта WP-1 (ревью G2) |
| WP-5 | Документация/интеграция: `docs/LOG-FORENSICS.md`, ADR-012, правки SERVER-BASELINE §5.13/§5.8, DEPLOY/MIGRATE, README/AGENTS, CENSORSHIP-PATTERNS, doc-sync-правило | docs | WP-1…WP-4 | приёмка на asv2 §12.3; `docsync audit` (если принят) зелёный |

Границы: WP-1/2 не меняют анализ; WP-3 не трогает сбор; WP-4 изолирован;
WP-5 не меняет код runtime.

---

## 14. Риски и меры

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| Ложные тревоги на шумном скане | высокая | недоверие к отчёту | T-04 = info; high только ≥3 источников; абсолютные минимумы |
| «Единичный счётчик» выдан за ТСПУ | средняя | неверные решения | корреляция + `alternatives` + `coverage` |
| Диск забит телеметрией | средняя | падение сервера | 5-мин сэмпл ~1 MB/сутки, 7 дней, disk-cap, T-10 |
| Pcap с payload/приватностью | низкая | утечка | `-s 1600`, IPv4-фильтр handshake, metadata-only, TTL 7d, не в git |
| Захват влияет на сервис | низкая | CPU/диск | Nice/ionice, лимиты, авто-стоп, только по команде |
| tshark отсутствует | высокая | нет JA3/JA4 | degraded-режим честно; stdlib L3/L4 + CH len |
| Парсер отстаёт от формата journal/nstat | средняя | пропуски | фикстуры по версиям, `partial` в coverage |
| Baseline «отравлен» инцидентом | средняя | слепота | reset-дельты, robust MAD, окно 14d, перестройка после инцидента |
| Дрейф правил без ревью | низкая | непредсказуемость | `rules_hash`, override только через файл + тест |
| Анализатор начнут «лечить» сервер | средняя | рестарты под обстрелом | R-9, запрет apply внутри analyze, явные рекомендации |
| Слепоту примут за «всё хорошо» | средняя | пропуск блока | `coverage` в каждом отчёте, `inconclusive` при критичных пропусках |

---

## 15. Границы изменений / non-goals

**Трогаем:** новый модуль `src/logs/`, CLI `vds logs`, timers, артефакты в
`/var/lib/vds`, документацию/ADR, `.gitignore`.

**Не трогаем:**
- runtime-поведение xray/hysteria2/amneziawg/relay и их конфиги;
- `probe-watch`-вердикты и пороги (только потребляем);
- автоматическую реакцию (lock-443 остаётся за `probe-response`);
- клиентскую телеметрию `vpn`/`ubuntuInstaller` (отдельная SPEC);
- внешние vantage (`check-host`, RU-зонды), сетевые API;
- слияние bundle'ов exit+relay в один отчёт (v1 — по хостам);
- активный self-test сервера из РФ (ByeByeVPN, И40) — отдельный цикл;
- LLM/ML-анализ, генерацию выводов;
- SIEM/экспорт логов за пределы сервера, log-shipping;
- повышение loglevel xray «чтобы видеть пробы» (§5.11 — не помогает);
- непрерывный фоновый pcap;
- расшифровку трафика.

---

## 16. Открытые вопросы (решения до кодинга)

| # | Вопрос | Рекомендация |
|---|---|---|
| OQ-1 | Имя CLI/модуля: `vds logs` vs `vds diag`/`vds telemetry`? | **`vds logs`** (`src/logs/`): совпадает с языком оператора |
| OQ-2 | Включать sample-таймер в `gateway init` по умолчанию? | **нет** в v1: `vds logs install --apply` отдельно (осознанная стоимость диска) |
| OQ-3 | Retention: 7/30/90 дней и disk-cap? | 7 (samples/pcap), 30 (bundles), 90 (reports); cap 2 GB |
| OQ-4 | Авто-захват pcap при `threat=high`? | **v1 — только вручную**; авто — отдельный OQ после полевых данных |
| OQ-5 | `tshark` — обязательная зависимость? | **нет**, опционально; stdlib-парсер обязателен |
| OQ-6 | IP в отчёте по умолчанию: сырые или хэш? | локально сырые; `--redact-ips` для передачи |
| OQ-7 | Может ли анализатор инициировать лок/рестарт? | **нет** (R-9); только рекомендация |
| OQ-8 | Импорт клиентских отчётов `vpn` в v1? | **схема есть, автозагрузки нет**; отдельная SPEC с vpnm |
| OQ-9 | Где правила: код или `/etc/vds-forensics/rules.json`? | defaults в коде + override-файл с `rules_hash` |
| OQ-10 | Нужен ли baseline с первого дня? | cold start честно `low`; baseline через 7 дней |
| OQ-11 | Хранить ли matched-raw в bundle по умолчанию? | **да** (иначе разбор невоспроизводим), лимит 20k строк |
| OQ-12 | Отдавать ли findings в `probe-watch --json` (v2)? | v1 — отдельный отчёт; интеграция — по факту пользы |
| OQ-13 | Активный self-test с RU-vantage (ByeByeVPN, И40) в этом цикле? | **нет**; после покупки RU-релея — отдельная SPEC (источник проб из РФ) |
| OQ-14 | Хранить ли в baseline список /24 (T-14)? | да, только агрегаты (hash/сеть), без IP клиентов |
| OQ-15 | Авто-сбор bundle при `threat≥elevated` (hook из probe-watch)? | **v1 — нет** (ручной/SOP); авто — после стабилизации правил, opt-in |

---

## 17. Трассируемость

| Требование | WP | Файлы | Тесты/AC |
|---|---|---|---|
| R-1 единый конвейер | WP-1, WP-3 | `collect.py`, `normalize.py`, `correlate.py` | §12.2 сцены 1–3, AC-1 |
| R-2 доказательства | WP-3 | `report.py`, `findings[].evidence` | golden-отчёт, AC-1 |
| R-3 детерминизм | WP-3 | `rules.py`, `report.py` | §12.1 «Детерминизм», AC-3 |
| R-4 покрытие/слепота | WP-1, WP-3 | `explain.py`, `coverage` | §12.3 «слепота», AC-4 |
| R-5 приватность | WP-1, WP-4 | redaction, `pcap.py` | §12.2 сцены 4–5, AC-2 |
| R-6 ресурсы | WP-1, WP-2, WP-4 | лимиты/retention | §12.1 Retention, AC-5 |
| R-7 офлайн/без root | WP-3 | `analyze` | §12.2 сцена 2, AC-3 |
| R-8 без дублей вердиктов | WP-3 | `probe`-адаптер | §12.2 сцена 3, AC-4 |
| R-9 без реакции | WP-3, WP-5 | `report.py`, docs | AC-6 |

---

## Следующий шаг

→ **G2-ревью:** `vds-architect` — границы `src/logs` vs `gateway/probing`,
схема Event/report, каталог правил, корреляция/уверенность, pcap-политика;
техлид — ценность/стоимость, retention, приватность, OQ-2/OQ-4/OQ-6.

**Решения техлида (G2, 2026-11-16):** OQ-1 `vds logs`; OQ-2 opt-in
(install --apply); OQ-3 7 дней/cap 2 ГБ (30/90 — при реальной потребности);
OQ-4 pcap только вручную (asv1 1 ГБ — авто-риск); OQ-5 tshark опция,
stdlib-парсер обязателен; OQ-6 локально сырые IP, --redact-ips для наружу;
OQ-9 пороги rules.json/логика в коде; OQ-13/15 отдельные циклы. Все OQ
закрыты, блокеров нет.
После APPROVED: WP-1 (каркас/сбор) → WP-2 (телеметрия) → WP-3 (анализ) →
WP-4 (pcap) → WP-5 (доки/приёмка на asv2).
