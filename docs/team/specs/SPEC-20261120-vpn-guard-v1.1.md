# SPEC — vpn guard v1.1 (draft)

- **Статус:** 🟡 **draft** — каркас под DECISION Q2 (2026-11-20). G2 и любой код
  v1.1 — **только после** закрытия окна WP-G6 (2026-11-24 15:24 MSK) и деплоя
  фиксов D1/D3/D6. Пороги G-13/G-14 калибруются по 7-дневному полевому дампу G6
  и в этой ревизии стоят плейсхолдерами.
- **Связанные:** [ADR-014](SPEC-20261116-vpn-guard.md) ·
  [SPEC-20261116-vpn-guard](SPEC-20261116-vpn-guard.md) · D-16…D-21 в
  [DECISIONS-vpn-guard](../reports/DECISIONS-vpn-guard.md) ·
  [ARCH-эволюция](../reports/ARCH-20261116-vpn-guard-evolution.md) §2 ·
  контракт схем — D-17 (lock `schema_hashes.json`, сервер вендорит).
- **Код:** клиент `ubuntuInstaller/scripts/vpn-manager/vpnm/guard/`; сервер в v1.1
  не меняется (кроме полей, если появятся в `guard.server_verdict/1`, — аддитивно).

---

## 1. Инварианты (не нарушать)

| # | Инвариант |
|---|---|
| I-1 | **100 % read-only.** Ноль авто-действий: guard не вызывает `systemctl`, `ip`, `awg set`, `ufw`, `nft`, не пишет конфиги VPN. |
| I-2 | **Ноль сетевых сокетов в демоне.** Ни одного `AF_INET`/`AF_INET6` сокета. `NETLINK_SOCK_DIAG` (G-14) — локальная интроспекция ядра, не сеть; разрешён только при `ss_tcp=true`. |
| I-3 | **Ноль `sudo`.** Всё читается из user-journal, sysfs, `/proc` своих процессов. |
| I-4 | **Ноль секретов** в состоянии, логах, findings и `status --json`. |
| I-5 | **Схемы аддитивны.** `guard.*/1` не меняют существующих полей/enum'ов; новое — только новые ключи с дефолтами (`guard.config/1`: `netlink`, `ss_tcp`, пороги G-13/G-14). Обновление `schema_hashes.json` — по протоколу D-17. |
| I-6 | **Правила v1.0 не трогаются.** G-01…G-12, их пороги и приоритеты заморожены (ADR-014 §5). G-13/G-14 — новые правила со своими порогами. |
| I-7 | **Privacy.** G-14 фильтрует сокеты строго по PID/имени собственных процессов `vpnm-xray@*`; чужие IP, процессы и порты не читаются и не попадают в evidence. |

## 2. Состав v1.1

### S4. Netlink-детект смены маршрута — `netlink=false` по умолчанию

**Проблема.** Роуминг Wi-Fi/смена маршрута даёт ложные G-01/G-02/G-04: старые
счётчики/курсоры относятся к прежнему пути.

**Что уже есть (каркас):** `cli.py --netlink`, `install.py`
`RestrictAddressFamilies=AF_UNIX + AF_NETLINK`, `guard.config/1.schema.json`
`netlink: {type: boolean, default: false}`, `rules.note_route_change()`
(подавление окна).

**Что доделать:** тонкий листенер `ip -o monitor route` (или netlink-route
напрямую) → `note_route_change()` в state; источник `sources[]` получает
`netlink: on/off`; тест: смена маршрута подавляет G-01/G-02/G-04 на 1 окно и
пишется в `sources`, не в findings.

**AC:** при `netlink=false` поведение на корпусе v1.0 идентично; при `true` —
FP после смены маршрута не эмитятся, событие видно в `sources`.

### G-13. AWG packet-size ratio (MTU/DPI-срез payload) — включено по умолчанию

**Проблема.** ТСПУ режет крупные фреймы, мелкие keepalive/DNS проходят: канал
«жив» по handshake и пингам, но bulk = 0. Действующая G-04 видит только полный
глухой дроп UDP.

**Данные без новых привилегий:** `counters.py` уже читает sysfs
`tx_bytes/rx_bytes/tx_packets/rx_packets` для AWG.

**Правило:** за окно, при `Δtx_bytes ≥ tx_min` и `Δtx_packets ≫ Δrx_packets`,
средний размер принятого пакета `avg_rx_pkt = Δrx_bytes / Δrx_packets < 120 B`
→ finding G-13 «payload-срез / MTU-blackhole» (severity medium), с `action` на
`vpn monitor`/`vpn doctor`, без авто-действий.

**Пороги (плейсхолдер, калибровка по G6):** `tx_min = 64 KiB/окно`,
`avg_rx_pkt_max = 120 B`, `tx_packets_ratio_min = 8`, окно 60 с.
**Тесты:** мелкий keepalive/DNS при росте tx → finding; обычный bulk-трафик
(avg ≥ 120 B) → нет finding; отсутствие счётчиков → `insufficient_data`.

**AC:** G-13 не эмитится на нормальном AWG-трафике 7-дневного дампа G6
(0 FP на эталонной выборке), ловит синтетический MTU-срез.

### G-14. Read-only `ss -tnip` по своим сокетам xray — `ss_tcp=false` по умолчанию

**Проблема.** Тихий шейпинг ТСПУ по TCP (рост retrans/RTT при живом соединении)
не виден ни логам, ни sysfs.

**Источник:** `ss -tnip` (NETLINK_SOCK_DIAG), строго сокеты процессов
`vpnm-xray@*` (свои PID), поля `retrans`, `rtt`, `bytes_acked`. Требует
`AF_NETLINK` в юните (как S4).

**Правило:** в окне 60 с `Δretrans ≥ r_min` **и** рост `rtt` относительно
baseline → G-14 «TCP-шейпинг» (severity low/medium), evidence строго по своим
сокетам: без чужих IP, без адресов третьих сторон.

**Пороги (плейсхолдер):** `r_min = 3` ретрансмита/мин, `rtt_growth = +30 %`
к 10-мин baseline, окно 60 с.

**AC:** opt-in=false — ноль обращений к `ss`; при true — finding на
синтетическом росте retrans/rtt; чужой процесс/IP в evidence не попадает
(тест на подставленный сокет другого PID).

### Гигиена из поля G6

- **`server:` в человекочитаемом `vpn guard status`:** строка
  `server: verdict=… threat=…` (возраст вердикта — `age_s`), **без** изменения
  схемы `guard.status/1` (ARCH §6 п. 2).
- **D4 (P27):** `file_parse_error` получает TTL и атрибуцию к конкретному файлу,
  всплывшему в TEST-t33; TTL — чтобы «вечный» битый файл не держал подавление
  бесконечно, атрибуция — чтобы фикс был адресным.

## 3. Схемы и контракт

- `guard.config/1` (аддитивно): `netlink` (есть), `ss_tcp: bool=false`,
  `thresholds: {g13: {...}, g14: {...}}` — новые ключи, старые дефолты
  не меняются.
- `guard.finding/1`: правило `G-13`/`G-14` — расширение enum `rule`
  (аддитивно; клиентский валидатор принимает новые значения).
- После любой правки схемы — обновить `schema_hashes.json` **и** серверный
  `docs/contracts/guard-schema-hashes.json` по протоколу D-17 (иначе тесты
  падают с явным diff).

## 4. Сознательно вне v1.1

| Что | Почему / когда |
|---|---|
| Ленивый sync из `vpn guard explain` / `vpn doctor` (ARCH §2.3) | ждёт серверный 5-мин сэмплер W1-1: при часовом `vds-probe-watch.timer` лишний SSH даёт лишь часовой снимок + риск RST-бана |
| Мост `vpn guard export` → `vds logs analyze --client-report` | v1.2 (DECISION Q3): нужен privacy-allowlist и потребитель на сервере |
| Smart Failover / любые авто-действия | v2.0 (DECISION Q4): отдельный ADR после ≥ 30 дней поля |

## 5. Риски

| Риск | Митигация |
|---|---|
| G-13 FP на мобильном (мелкие пакеты в простое) | порог `tx_min` 64 KiB/окно + требование перекоса `tx_packets ≫ rx_packets`; калибровка по G6 |
| G-14 раздувает CPU на ноутбуке | opt-in=false по умолчанию, окно 60 с, только свои PID, бюджет p95 < 50 мс/тик |
| `AF_NETLINK` ломает hardened-профиль | уже включён в шаблон при `netlink=true`; при `ss_tcp=true` включается той же веткой; fallback `compat` записывается в `sources` |
| Дрейф схем между репо | D-17: lock + два теста (клиент/сервер), сверка 1-в-1 офлайн |

## 6. План работ (после G6)

| WP | Объём | AC |
|---|---|---|
| V11-1 | G-13 + пороги из G6-дампа + тесты | 0 FP на эталонной выборке, ловит синтетику |
| V11-2 | S4 netlink end-to-end (листенер → `note_route_change`) | FP роуминга исчезают, opt-in=false нейтрален |
| V11-3 | G-14 opt-in + privacy-тест | чужой PID/IP не в evidence |
| V11-4 | `server:` строка + D4 (P27) + TTL | TTL и имя файла в finding/статусе |
| V11-5 | Обновление схем/lock, прогон `tests/guard`, G2-ревью | `audit --strict` OK, lock синхронен |

## 7. Открытые вопросы (OQ)

| # | Вопрос | Статус |
|---|---|---|
| OQ-V11-1 | Точные пороги G-13 по G6-дампу | ждёт 7-дневный дамп (до 2026-11-24) |
| OQ-V11-2 | Нужен ли G-14 в v1.1, если baseline шейпинга не наберётся | решается по дампу; при отсутствии сигнала — перенос в v1.2 |
| OQ-V11-3 | Формат `server:` строки (subject к Q7-политике эшелонов) | после DECISION Q7 |
