# SPEC — p2p link: носители `awg` + `wstunnel-wg`, селектор на RU-релее

- **Статус:** 🟡 draft (входной гейт G2 спеки; ревизия после ревью `d886602`).
  Контракт — [ADR-016](../../adr/ADR-016-p2p-link-multi-carrier.md) (принят G2 2026-11-20).
- **Связано:** ADR-015 (нога `awg2` + P25), ADR-007 (RU-relay), ADR-004 (ACME
  HTTP-01), AGENTS §6, SPEC-20261120-relay-maneuver, SPEC-20261117-alert-watch.
- **Код до G2 этой спеки не пишется.**

## 1. Факты с живых узлов (read-only, 2026-11-20)

| Проверка | exit (NL) | RU-релей |
|---|---|---|
| `443/tcp` | занят `xray` (Reality) | занят `xray` (Reality) |
| `8443/tcp` | **занят `xray` — XHTTP-инбаунд жив** | свободен |
| `9443/tcp` | **свободен** (`ss -tlnp`) | свободен |
| `2053/tcp` | свободен (резерв CDN, Q6 — не трогаем) | свободен |
| `awg` (AmneziaWG tools) | **есть** (`/usr/bin/awg`) | есть |
| `wg` (vanilla wireguard-tools) | **нет** | нет |
| `wstunnel` | нет, в apt пакета нет | нет |
| LE-сертификаты | `<exit-domain>` (один) | нет |

**Следствия:**

1. **Порт — `9443/tcp`** (8443 занят XHTTP, 2053 — резерв CDN). Проверено на обоих.
2. **Стек — `awg` (AmneziaWG), не vanilla `wg`.** `awg` уже стоит на обоих узлах,
   на нём же весь контур (awg0/awg1/awg2) и `alert-watch` (`awg show … dump`).
   Обфускация внутри WSS **выключена** (`Jc=0, Jmin=0, Jmax=0, S1=S2=0`,
   `H1..H4` — случайные различные): junk внутри TLS только жжёт MTU и TCP-окно.
3. **`wstunnel` вендорится** (не из apt): пиннинг версии + SHA256 (OQ-1 → §9).
4. **Нужен второй LE-домен** `ws.<domain>` (DNS — владелец, OQ-2 → §9).

## 2. Носители

### 2.1 `awg` (приоритет 1) — без изменений

Существующая нога: `awg1` 10.11.0.0/30, пул 51900–51911, манёвр P25. Спека его
не меняет; селектор **читает** состояние и вызывает пробы.

### 2.2 `wstunnel-wg` (приоритет 2)

**Exit (NL):**

- **AWG `wg-ws0`:** адрес **10.12.0.1/30**, пир релея `10.12.0.2/32`,
  `ListenPort = <WG_WS_PORT>`, обфускация выключена (§1 п.2),
  `PersistentKeepalive = 25`.
- **Kernel AWG/WG не умеет bind на loopback** — `ListenPort` всегда слушает
  `0.0.0.0`/`[::]`. Защита вместо bind — nft:
  ```
  chain input { type filter hook input priority filter - 1; policy accept;
      iifname != "lo" udp dport <WG_WS_PORT> drop
  }
  ```
  `inet`-таблица покрывает IPv4 и IPv6 одним правилом.
- **wstunnel server:** `wss` на `<WS_PORT>` = 9443, TLS — LE на `ws.<domain>`;
  апгрейд-путь ограничен секретным префиксом
  (`--restrict-http-upgrade-path-prefix <prefix>` / `--http-upgrade-path-prefix
  <prefix>` — точный флаг по `--help` релиза, OQ-1); форвард **только** на
  `127.0.0.1:<WG_WS_PORT>` (`--restrict-to`).
- **nft `table inet vds_relay_wstun`:** `postrouting`
  `ip saddr 10.12.0.0/30 oifname "<wan>" masquerade`; `input` —
  `ip saddr != <relay-ip> tcp dport <WS_PORT> drop` +
  `meta nfproto ipv6 tcp dport <WS_PORT> drop` (defense-in-depth к UFW);
  `forward` — allow `iifname wg-ws0 oifname <wan>`.
- UFW: `allow from <relay-ip> to any port <WS_PORT> proto tcp` — и всё.

**Релей (RU):**

- **AWG `wg-ws0`:** адрес **10.12.0.2/30**, `Table = off`, MTU §4,
  **`Endpoint = 127.0.0.1:<LOCAL_UDP_PORT>`** (локальный порт wstunnel-клиента),
  **`PersistentKeepalive = 25`** — релей инициатор WSS-потока, keepalive держит
  сессию против idle-timeout на NAT/промежуточных устройствах.
  Юнит `wg-ws0`: `Wants=`/`After=vds-wstunnel-client.service`.
- **wstunnel client:** подключение к **`wss://ws.<domain>:<WS_PORT>`** — по
  hostname, чтобы (а) прошла валидация LE, (б) ушёл настоящий SNI (ради него и
  заводится домен). Форвард UDP:
  ```
  wstunnel client \
    --http-upgrade-path-prefix <prefix> \
    -L "udp://127.0.0.1:<LOCAL_UDP_PORT>:127.0.0.1:<WG_WS_PORT>?timeout_sec=0" \
    wss://ws.<domain>:<WS_PORT>
  ```
  Псевдосхема `wg://` **не используется** — в `erebe/wstunnel` её нет; WG внутри
  это UDP-форвард на локальный порт AWG. Точные имена флагов
  (`--http-upgrade-path-prefix`, у сервера `--tls-private-key`) сверяются по
  `--help` пиннингованного релиза до WP-P2P-1 (OQ-1).
- Соединение идёт через **main table** (eth0), вне `fwmark 0x1`.

**Секрет-префикс:** `/etc/vds/wstunnel-{client,server}.env` (0600), подстановка
`${WS_PREFIX}` через `EnvironmentFile=`. Ограничение: systemd раскрывает
переменную до `exec` → префикс виден в `argv`. Митигация: узлы
однопользовательские (только root), `ProtectProc=invisible`, `ProcSubset=pid`;
если релиз поддерживает конфиг-файл — использовать его (проверка в OQ-1).

## 3. Per-carrier NAT и переключение

| Носитель | Релей | Exit | NAT релея | NAT exit |
|---|---|---|---|---|
| awg | `awg1` 10.11.0.2/30 | `awg2` 10.11.0.1/30 | `oifname awg1` | `saddr 10.11.0.0/30 oifname wan` |
| wstunnel-wg | `wg-ws0` 10.12.0.2/30 | `wg-ws0` 10.12.0.1/30 | `oifname wg-ws0` | `saddr 10.12.0.0/30 oifname wan` |

**MASQUERADE `wg-ws0` на релее — одно место:** `vds-relay-nat.service`
(iptables; там же awg1 и eth0, `src/relay/init.py`), **не** nft-таблица
`vds_relay`. Причина: nft-файл `vds_relay` перегенерируется еженедельным
`vds-relay-cidr.timer` — правило, положенное туда, будет молча потеряно.

Переключение (атомарно, общий `FileLock`):

```
ip route replace default dev <awg1|wg-ws0> table 100
```

Состояние: `/var/lib/vds/p2p-carriers.json` (0600):
`{active, since, switched_at[], failed[], attempts[]}`.

**Инвариант старта:** `vds-relay-policy.service` (и ребут) не должен молча
вернуть `awg1` — после `nft -f` селектор применяет `table 100` из state.

## 4. MTU / MSS

- `awg0` на релее — **1280** (не меняется).
- `wg-ws0` — **1240** (1500 − 20 IP − 20 TCP − ~40 TLS+WS − 60 WG, с запасом под
  PPPoE/провайдерские туннели); значение конфигурируемое.
- nft `chain forward` (`vds_relay`): `tcp flags syn tcp option maxseg size set
  rt mtu` — иначе PMTUD-blackhole.
- Обфускация выключена (§1 п.2): junk/S-паддинг не съедает MTU.

## 5. Селектор: контракт

**Состояния:** `primary` → `fallback` → `recovering` → `primary`, плюс
терминальное `exhausted`.

| Переход | Условие |
|---|---|
| `primary → fallback` | P25 вернул `rollback`, **И** pre-check `ping -I wg-ws0 10.12.0.1` успешен |
| `primary → exhausted` | P25 `rollback`, **И** pre-check `wg-ws0` провален (оба носителя мертвы) → alert |
| `fallback → recovering` | редкая проба `awg1` (`ping -I awg1 10.11.0.1`) успешна |
| `recovering → primary` | **3** успешных пробы подряд **И** прошло **600 с** |
| `recovering → fallback` | проба упала — серия сброшена |
| `fallback → exhausted` | **3 отказа подряд** liveness `wg-ws0` (как у awg1; одиночный потерянный ping — не повод) → alert |
| `exhausted → primary`/`fallback` | **автовыход** при стабильном liveness любого носителя (по образцу `maneuver.py`, где `exhausted` снимается оживлением) |

**Две дыры закрыты явно:**

1. **Переключение вслепую запрещено.** Перед `ip route replace` обязательна
   проба целевого носителя; если `wg-ws0` мёртв — не переключаемся, а уходим в
   `exhausted` с уведомлением (иначе трафик уедет в мёртвый носитель и
   `exhausted` не наступит никогда).
2. **P25 в `fallback` не крутит порты.** Контракт: `maneuver` читает
   `p2p-carriers.json`; при `active == "wstunnel"` тик делает **только**
   liveness-пробу `awg1` (для `prefer_primary`) и **не** начинает манёвр:
   не инкрементирует `attempts`/лимит «3/час», не делает `awg set … endpoint`,
   повторный `rollback` — no-op. Иначе на здоровом `wg-ws0` три ложных rollback
   за 30 минут свалят селектор в `exhausted`.

**CLI:** `vds relay carrier status [--json]`, `vds relay carrier switch --to
awg|wstunnel [--apply]`, `vds relay carrier install --apply`, `remove --apply`.

## 6. alert-watch: список интерфейсов ноги

`ALERT_RELAY_IFACE` — **список через запятую** (`awg2,wg-ws0`), одно значение
работает как раньше. Пульс `ok`, если на **любом** интерфейсе найден пир релея и
есть трафик; `blocked` — только если мертвы все. Схема `alert.status` не
меняется. Вариант «селектор переключает env» отклонён (ADR-016 §9, I-5).

**Реализовано (`src/alert/env.py::relay_ifaces`, `checks.read_relay_signal`):**
один интерфейс — прямой вызов `_probe_one_iface` (поведение прежнее); несколько —
проба каждого, `ok` при любом живом, иначе худший живой вердикт;
`peer_rx` = сумма по носителям (гейт активности между тиками).

## 7. Критерии приёмки (сводная таблица SPEC)

К AC-1…AC-8 ADR-016 добавляются спеко-специфичные:

| # | Критерий |
|---|---|
| AC-S1 | Внешний скан `9443/tcp` с чужих IP — тишина; `<WG_WS_PORT>/udp` с `iifname != lo` — дроп (kernel-bind невозможен, проверяем nft) |
| AC-S2 | `wss://ws.<domain>:9443` проходит валидацию LE и отправляет SNI `ws.<domain>` (`openssl s_client -servername`) |
| AC-S3 | Секрет-префикс не встречается в git, логах и `status --json`; env-файлы 0600 |
| AC-S4 | `ip route … table 100` не теряется при рестарте `vds-relay-policy` и при обновлении `ru_cidr` (cidr-таймер) |
| AC-S5 | Переключение при мёртвом `wg-ws0` **не происходит** — сразу `exhausted` + уведомление (pre-check) |
| AC-S6 | В `fallback` тик P25 не инкрементирует `attempts` и не меняет endpoint (no-op), лимит 3/час не расходуется |
| AC-S7 | `ping -I wg-ws0 10.12.0.1` восстанавливается сам после 15-с `nft drop` на `9443/tcp` без рестарта юнита (Restart=always + keepalive 25) |
| AC-S8 | HTTPS-поток > 1 МБ через `awg0 → wg-ws0` при MTU 1240 без зависаний (MSS clamp) |
| **AC-S9** | При переходе на `wg-ws0` alert-watch **не шлёт ложный** `relay_blocked` (список интерфейсов) |

## 8. План работ

| WP | Объём | AC |
|---|---|---|
| WP-P2P-1 | `src/relay/wstunnel.py`: вендоринг (версия+SHA256, проверка до распаковки, атомарная установка 0755), рендер server/client env, юниты `vds-wstunnel-{server,client}` (`Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=0`), секрет-префикс 0600 | AC-S3, AC-1 ADR |
| WP-P2P-2 | AWG `wg-ws0` (10.12/30, `Jc=0`, `Table=off`, MTU 1240, keepalive 25 обе стороны); nft exit (`vds_relay_wstun`) и релей (`iifname wg-ws0 return` + `chain forward` MSS); MASQUERADE в `vds-relay-nat.service` | AC-3, AC-4, AC-5 ADR, AC-S1, AC-S8 |
| WP-P2P-3 | селектор: state, pre-check целевого, `ip route`, хук на `rollback`, `prefer_primary` (3 пробы + 600 с), fallback-режим P25 (no-op), лимит 3/час | AC-2, AC-6, AC-7 ADR, AC-S5, AC-S6 |
| WP-P2P-4 | второй LE: `ws.<domain>` (ADR-004: `--standalone` 80/tcp), домен в `protocols["p2p_wstunnel"]["domain"]` (аддитивно, скалярный `acme.domain` не ломаем), deploy-hook с фильтром `$RENEWED_DOMAINS` | AC-S2; продление не рестартит чужие сервисы |
| WP-P2P-5 | alert-watch: `ALERT_RELAY_IFACE` как список | AC-S9 |
| WP-P2P-6 | живая приёмка релей↔exit: блок пула → fallback ≤ 240 с; скан 9443 — тишина; reconnect после drop; возврат на awg | AC-1…AC-8 ADR + AC-S1…S9 |

## 9. Решения по OQ

| # | Решение |
|---|---|
| OQ-1 | **Вендоринг:** официальный GitHub Release `erebe/wstunnel`, статический `linux_amd64`; версия пиннится константами `WSTUNNEL_VERSION` + `WSTUNNEL_SHA256` в `src/relay/wstunnel.py`; никаких `latest` и `curl \| sh`. Скачать → сверить sha256 **до** распаковки → атомарно в `/usr/local/bin/wstunnel` (0755). Точные флаги — по `--help` этого релиза до WP-P2P-1 |
| OQ-2 | **DNS+LE:** `ws.<domain>` A → IP exit, DNS-only (без CF-прокси) — делает **владелец**. Домен хранится в `protocols["p2p_wstunnel"]["domain"]` (аддитивно); `protocols["acme"]["domain"]` не трогаем |
| OQ-3 | **Порт `9443/tcp`** — APPROVED (свободен на обоих узлах, проверено). 8443 (XHTTP) и 2053 (резерв CDN) не трогаем |
| OQ-4 | **Reconnect:** `Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=0` на обоих юнитах + `PersistentKeepalive=25` на релее; AC-S7 (drop 15 с → оживает без рестарта) |
| OQ-5 | **XHTTP на 8443 не гасим** — другой контур, порту 9443 не мешает |
