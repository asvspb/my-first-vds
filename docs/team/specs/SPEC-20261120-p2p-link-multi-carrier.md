# SPEC — p2p link: носители `awg` + `wstunnel-wg`, селектор на RU-реелее

- **Статус:** 🟡 **draft** (входной гейт G2 спеки). Контракт закреплён в
  [ADR-016](../../adr/ADR-016-p2p-link-multi-carrier.md) (принят G2 2026-11-20).
- **Связано:** ADR-015 (нога `awg2` + П25), ADR-007 (RU-relay), AGENTS §6,
  SPEC-20261120-relay-maneuver (P25), SPEC-20261117-alert-watch.
- **Код до G2 этой спеки не пишется.** WP ниже — план, не разрешение.

## 1. Факты с живых узлов (read-only, 2026-11-20)

| Проверка | asv2 (exit, NL) | RU-релей |
|---|---|---|
| `ss -tlnp` 443 | `xray` (Reality) | `xray` (Reality) |
| `ss -tlnp` 8443 | **`xray` — XHTTP-инбаунд ЖИВ** | свободен |
| 2053 / 9443 / 2096 | 2053 свободен | 2053, 9443, 2096 свободны |
| `wstunnel` бинарник | **нет** | **нет** |
| `apt-cache policy wstunnel` | пакета в репозиториях нет | — |
| LE-сертификаты | `asv2.asvpersonal.ru` (до 2027-02-13) | нет |

**Следствия (обязательны для реализации):**

1. **`8443/tcp` на asv2 занят XHTTP** — кандидат из ADR отпадает. Берём
   **`9443/tcp`** (свободен на обоих узлах). 2053 не берём: это порт CDN-резерва
   (Q6), чтобы не плодить конфликт при его реактивации.
2. **`wstunnel` ставится не из apt** — нужен вендоринг бинарника: фиксированная
   версия + SHA256 из релиза, проверка перед установкой (AGENTS §6: без
   `curl | sh`). Открытый вопрос OQ-1 ниже.
3. **Нужен второй LE-домен** (например `ws.asvpersonal.ru`): DNS-запись делает
   владелец; `state.protocols["acme"]` хранит **один** скалярный `domain` —
   механика второго сертификата в WP-4.

## 2. Носители

### 2.1 `awg` (приоритет 1) — без изменений

Существующая нога: `awg1` 10.11.0.0/30, пул 51900–51911, манёвр P25,
автопилот 60 с. Спека его не меняет; селектор только **читает** его состояние
(`state`, `exhausted`, `rollback`).

### 2.2 `wstunnel-wg` (приоритет 2)

**Exit (asv2):**

- `wstunnel server wss://0.0.0.0:<WS_PORT>` с:
  `--restrict-to 127.0.0.1:<WG_WS_PORT>`, `--tls-certificate`/`--tls-key` (LE),
  случайный `ws_path` (секрет 0600, `gen_secret_path()`).
- WG-сервер на `127.0.0.1:<WG_WS_PORT>`: адрес **10.12.0.1/30**, пир релея
  `10.12.0.2/32`, `PersistentKeepalive = 25`, обфускация как у ноги (тот же
  генератор, что `exit_leg`).
- nft `table inet vds_relay_wstun`: `postrouting ip saddr 10.12.0.0/30 oifname "<wan>"
  masquerade`; `input` — `ip saddr != <relay-ip> tcp dport <WS_PORT> drop` +
  `meta nfproto ipv6 tcp dport <WS_PORT> drop`; `forward` — allow
  `iifname wg-ws0 oifname <wan>`.
- UFW: `allow from <relay-ip> to any port <WS_PORT> proto tcp` (и всё).
- **WG-порт слушает только loopback** — прийти на него мимо wstunnel нельзя.

**Релей (RU):**

- клиент `wstunnel client -L "wg://127.0.0.1:<WG_WS_PORT>?remote=127.0.0.1:<WG_WS_PORT>" wss://<exit-ip>:<WS_PORT>/<ws_path>`
  — подключение через **main table** (eth0), вне `fwmark 0x1`.
- `wg-ws0`: адрес **10.12.0.2/30**, `Table = off`, MTU — см. §4.
- MASQUERADE на `wg-ws0` (per-carrier, §3).

## 3. Per-carrier NAT и переключение

| Носитель | Релей | Exit | NAT релея | NAT exit |
|---|---|---|---|---|
| awg | `awg1` 10.11.0.2/30 | `awg2` 10.11.0.1/30 | `oifname awg1` | `saddr 10.11.0.0/30 oifname wan` |
| wstunnel-wg | `wg-ws0` 10.12.0.2/30 | WG 10.12.0.1/30 (listen 127.0.0.1) | `oifname wg-ws0` | `saddr 10.12.0.0/30 oifname wan` |

Переключение (атомарно, под общим `FileLock`):

```
ip route replace default dev <awg1|wg-ws0> table 100
```

Плюс синхронизация состояния в `/var/lib/vds/p2p-carriers.json` (0600):
`{active: "awg"|"wstunnel", since, switched_at[], failed: {...}}`.

**Инвариант старта:** `vds-relay-policy.service` (и ребут) не должен молча
возвращать `awg1`: после `nft -f` селектор применяет `table 100` из state.

## 4. MTU / MSS

- `awg0` на релее: **1280** (не меняется).
- `wg-ws0`: MTU = `min(внешний путь, 1500) − TLS/WS-заголовки − WG-оверхед`.
  Расчёт: 1500 − 20(IP) − 20(TCP) − ~40(TLS+WS) − 60(WG, IPv4) ≈ **1360**;
  безопасный практический старт — **1240** (запас на PPPoE/туннели провайдера).
  Значение — конфигурируемое, дефолт 1240.
- `nft chain forward` (таблица `vds_relay`): `tcp flags syn tcp option maxseg
  size set rt mtu` — обязательно, иначе PMTUD-blackhole на клиентских HTTPS.

## 5. Селектор: контракт

**Триггер Уровня 2** — первый `rollback` манёвра P25 (см. ADR §4 I-2):
хук внутри apply-пути манёвра, под тем же `FileLock`.

**Состояния:** `primary` → `fallback` → `recovering` → `primary`.

| Переход | Условие |
|---|---|
| `primary → fallback` | P25 вернул `rollback` (порт не сменился на живой) |
| `fallback → recovering` | редкая проба `awg1` (`ping -I awg1 10.11.0.1`) успешна |
| `recovering → primary` | **3** успешных пробы подряд **и** прошло **600 с** |
| `recovering → fallback` | проба упала — сброс серии |

**Ограничители:** не более 3 переключений в час; при исчерпании —
`exhausted` (терминальное, уведомление владельцу, авто-переключений нет).

**CLI (черновик):**
`vds relay carrier status [--json]`, `vds relay carrier switch --to awg|wstunnel [--apply]`,
`vds relay carrier install --apply` (юниты + конфиг + wg-ws0), `remove --apply`.

## 6. alert-watch: список интерфейсов ноги

`ALERT_RELAY_IFACE` принимает **список** через запятую (`awg2,wg-ws0`), обратная
совместимость — одно значение как раньше. Пульс `ok`, если на **любом**
интерфейсе найден пир релея и трафик жив; `blocked` — только если мертвы все.
Схема `alert.status` не меняется. Вариант «селектор переключает env» отклонён
(ADR-016 §9, инвариант I-5).

## 7. План работ

| WP | Объём | AC |
|---|---|---|
| WP-P2P-1 | `src/relay/wstunnel.py`: вендоринг бинарника (версия+SHA256), рендер server/client конфигов, юниты exit/reлей, `--restrict-to`, случайный `ws_path` 0600 | dry-run по умолчанию; секретов в логах нет; юнит с `StateDirectory` |
| WP-P2P-2 | per-carrier NAT + nft (exit `vds_relay_wstun`, релей `wg-ws0` return + forward MSS) + `wg-ws0` 10.12.0.0/30, `Table = off`, MTU 1240 | AC-3, AC-4, AC-5 ADR |
| WP-P2P-3 | селектор: state, `ip route replace`, хук на `rollback` P25, `prefer_primary` (3 пробы + 600 с), лимит 3/час | AC-2, AC-6, AC-7 |
| WP-P2P-4 | второй LE-домен: DNS (владелец) + `acme.wstunnel_domain` или отдельный сертификат без поломки существующего | сертификат валиден, `certbot.timer` продлевает оба |
| WP-P2P-5 | alert-watch: список интерфейсов | AC-9 (нет ложных `relay_blocked` при fallback) |
| WP-P2P-6 | живая приёмка на релей↔asv2: блок пула → fallback ≤240 с; внешний скан `9443` — тишина; возврат на awg | AC-1…AC-8 ADR |

## 8. Открытые вопросы

| # | Вопрос | Блокирует |
|---|---|---|
| OQ-1 | **Вендоринг wstunnel**: версия, источник (GitHub release), SHA256, отсутствие `curl \| sh` | WP-P2P-1 |
| OQ-2 | DNS-запись `ws.<домен>` → asv2 (делает владелец, у меня нет доступа к зоне) | WP-P2P-4 |
| OQ-3 | Порт: **9443** выбран (8443 занят XHTTP, 2053 — резерв CDN). Подтвердить | WP-P2P-1 |
| OQ-4 | Поведение wstunnel при обрыве TCP: переустанавливает ли сессию сам, нужен ли watchdog-юнит | WP-P2P-3 |
| OQ-5 | Нужно ли гасить XHTTP на 8443, чтобы освободить порт под что-то ещё | — (не блокирует) |
