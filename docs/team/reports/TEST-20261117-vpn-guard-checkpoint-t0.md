# TEST-20261117-vpn-guard-checkpoint-t0 — точка покоя WP-G6 (T0)

> **Тип:** TEST-отчёт (снимок T0, старт 7-дневного WP-G6).
> **Дата:** 2026-11-17 00:0x MSK. **Хост:** ноутбук `dragonMi`.
> **Код клиента:** `ubuntuInstaller` `78ce00c` (guard live-fix); сервер
> `my-first-vds` `0798218`. **Секреты:** нет; только счётчики/состояния.

## Сервис

```
vpn-guard.service: active/running, enabled, profile=hardened
с 2026-11-17 00:00:28 MSK
RSS: 16 068 608 B (~15.3 MiB) при MemoryMax=128M
```

Юнит: `ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX`,
`NoNewPrivileges=yes`, `Nice=10`, `CPUQuota=10%`.

## Источники и вердикт

```
[ok] journal:user
[ok] journal:system
[ok] state
[ok] file
[ok] verdict
[ok] sysfs:awg — iface=laptop
[off] netlink — v1.1, opt-in
signals: amneziawg=counters, dns=blind, hysteria2=blind, systemd=ok, xray=blind
```

`vpn guard sync --host root@asv2`: `verdict=quiet`, `threat=quiet`,
`fresh=true`, `lockdown=false`, `age_s=0`.

## Счётчики на T0

```
state=armed
counters: events=0, unparsed=0, dropped=0, findings=0,
          suppressed=0, redaction_hits=0
coverage: unparsed_ratio=0, notes=[speed_ring_restored:4,
          app_signal=blind (нет app-событий за прогон)]
findings.jsonl: 11 исторических (до restart)
```

`app_signal=blind` ожидаем в простое: app-события Xray/Hy2 пишутся при
старте/соединениях, окно пустое.

## Профили (после декомиссии asv1)

```
asv2-hy2      hysteria2    socks:2083
asv2-reality  xray-reality socks:2080
```

Активный — `asv2-reality` (egress 213.108.23.119); AWG-split `laptop` жив.
Мёртвые asv1-профили (`mob`, `phone`, `xhttp-web`, `cdn-home`) удалены.

## План контроля

- **T+24–48 ч:** `vpn guard status --json`, `vpn guard sync --host root@asv2`,
  `vpn guard findings`, `unparsed_ratio`, RSS/CPU.
- **T+7 дней:** AC-5 (RSS<80 МБ, CPU<1%, unparsed<5%), AC-17 живые проверки,
  реальный `kill -9`, `vpn guard selftest` из установленного wheel.
- Замечание архитектора P2 (не блокер): `CursorStore.save` — read-modify-write
  без `threading.Lock`; атомарная замена исключает битый файл, редкий потерянный
  тик курсора лечится следующим persist. Заведено в TECHDEBT P19.

## Трассируемость

| Что | Коммит |
|---|---|
| guard live-fix (stderr/cursor) | `ubuntuInstaller 78ce00c` |
| HF-SSH (UFW phase A) | `my-first-vds 14999ec` |
| T0/пост-мортем docs | `0798218` |

## T0.5 — контрольная точка T+12 ч (2026-11-17, после раскатки RU-relay)

```
vpn-guard.service: running, hardened, state=armed, iface=laptop
counters: events=77, unparsed=6, dropped=0, findings=3,
          suppressed=43, redaction_hits=0
coverage: unparsed_ratio=0.75, blind=[], speed_ring_restored:4
findings.jsonl: 3 записи за интервал
```

### Диагноз `unparsed_ratio=0.75` — артефакт метрики, не деградация парсера

Реплей 24-часового user-журнала через `JournalParser`:

```
ParseStats(lines=34485, app_lines=16, parsed=4, unparsed=12,
           ignored_infra=0, errors=0)
```

Все 12 «непарсенных» — **стартовый баннер Xray**, а не телеметрия:

```
Xray 26.1.23 (Xray, Penetrates Everything.) 0a42dba (go1.25.6 linux/amd64)
A unified platform for anti-censorship.
2026/11/17 08:18:40 [Info] infra/conf/serial: Reading config: &{Name:...}
```

Причина: знаменатель AC-5 — `app_lines` (16 за сутки, реального трафика в
окне почти не было), а каждая смена профиля добавляет 3 строки баннера.
На боевом трафике доля баннеров падает до ~0. Заведено в TECHDEBT P21:
в v1.1 классифицировать баннеры как `ignored_infra` (вне `app_lines`).

### Findings: G-06/G-07 по `cloudflared-proxy-dns.service`

Записи 18:03–18:41 UTC (21:03–21:41 MSK, 16.11) — `network_unreachable=8`
и `dns_timeout`. Это локальная сеть/DNS ноутбука, не VPN: FP-логика верно
отмечает `no network_unreachable/no_route in 60s`, `0 distinct names`.
Связаны со сменой сети/сна ноутбука вечером 16.11 (до начала раскатки
релея 17.11). Подавления (43) — штатная гистерезисная работа правил.

### Пост-фикс по итогам T0.5 (2026-11-17)

Полевые данные `vpn guard findings` вскрыли 4 дефекта правил и корреляции;
закрыты в ubuntuInstaller коммитом `c447171` (ветка
`fix/guard-g6-field-checkpoint`, полный прогон зелёный, +17 тестов в
`tests/guard/test_guard_field_fixes.py`):

1. **G-09 на вспомогательном DNS-юните.** `_g09` не различал тип юнита, и
   `conn_reset=5` от `cloudflared-proxy-dns.service` давал
   `endpoint_silent` с советом «свежие ссылки / резервный канал».
   Введён `is_vpn_transport_unit()` (только `vpnm-*`, `vpn-xray-split@*`,
   `vpn-awg-split@*`, `awg-quick@*`, `vpn-relay-*`; неизвестный юнит —
   не транспорт, fail-closed).
2. **Дубли findings в одном батче.** Ключ дедупа
   `rule|unit|endpoint|cause` строился по endpoint события-триггера, а
   правило выбирает хост из окна; при нескольких upstream-IP это давало
   новые ключи. Добавлен `_Verdict.dedup_endpoint` (G-02/G-03/G-08/G-09) —
   один физический сбой = один finding.
3. **Немонотонный порядок `vpn guard findings`.** `FindingsStore.read()`
   отдавал файловый порядок. Теперь strict chronology по `window.last|ts`
   с детерминированным tie-break по вставке; `--json`/`--follow` — тот же
   путь.
4. **G-06 не подавлялся парным G-07.** Окно-подавление было, добавлен
   batch-scoped приоритет (`_batch_local_net`): drain, в котором есть
   `no_route`/`network_unreachable`, не может обвинить DNS; reason
   `local_net_down`. При `distinct_names=0` fp-строка теперь честная —
   «distinct names not extracted», а не «0 names broken».
5. **G-12 `source_lost: sysfs:awg` при выключенном AWG.** Runner читает
   `mode.json` (`note_awg_expected`), плюс детектор suspend/resume по
   расхождению realtime↔monotonic (`SUSPEND_DRIFT_S=5`) — `note_clock_skew`
   наконец вызывается из рантайма.

Отдельно (не Guard, системное): шум `cloudflared-proxy-dns` объясняется
`strict-order` в `/etc/dnsmasq.d/awg-split.conf` — dnsmasq сначала ждёт
мёртвый в РФ DoH (1.1.1.1:443) и только потом идёт в 77.88.8.8. Правка —
в генераторе `15_domain-split.sh` (ubuntuInstaller), решение владельца.

### A+B: IPv6-ENETUNREACH и IPv4-only cloudflared (2026-11-17, `904212f`)

Полевой остаток: на ноутбуке без v6 dual-stack cloudflared ходил в
`[2606:4700:4700::1111]` и получал `network is unreachable` каждые ~5 с —
16 строк / 10 мин, G-07 high по G-07-логике и риск маскировки настоящего
G-06 через batch-приоритет. Закрыто с двух сторон одним коммитом:

- **Guard:** парсер не эмитит `network_unreachable`/`no_route`, если в
  сообщении IPv6-адресат (учёт в `ignored_infra`, AC-5 не раздувается);
  IPv4-случай по-прежнему даёт сигнал.
- **Система:** cloudflared получает только IPv4-литералы
  (`--upstream 1.1.1.1/1.0.0.1`, bootstrap `162.159.36.1/46.1`);
  `15_domain-split.sh` идемпотентно переписывает ExecStart уже
  установленного юнита и перезапускает сервис.

Живая проверка после применения: `network is unreachable` — 0 за 3 мин,
ошибок cloudflared — 0, `vpn guard findings --since 20m` — пусто,
DNS отвечает (youtube/ipinfo — единицы миллисекунд).
