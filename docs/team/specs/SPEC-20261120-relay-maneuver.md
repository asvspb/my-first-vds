# SPEC-20261120 — Изоляция порта exit (P24) и манёвр ноги relay↔exit (P25)

- **Статус:** G2 (на ревью), 2026-11-20
- **ADR:** [ADR-015](../adr/ADR-015-relay-exit-isolation-maneuver.md)
- **Данные:** [`TEST-20261120-relay-leg-diag.md`](../reports/TEST-20261120-relay-leg-diag.md) (WP-M0)
- **Долги:** TECHDEBT P24, P25

## 1. Цель и границы

1. Изолировать межузловой порт exit от клиентских пиров (P24).
2. Дать релею локальный актуатор манёвра порта ноги; авто-таймер — opt-in (P25).
3. Не менять клиентские конфиги (`mobile`/`win`/`laptop`) и не давать релею
   прав на exit (AGENTS §6, ADR-015 «граница доверия»).

## 2. Жёсткие инварианты (нарушение = P0 на ревью)

1. Ноль SSH/API-вызовов с RU-релея на exit; на релее нет ключей/токенов exit.
2. Клиентский `awg0` (51825/udp) на exit не трогается; пиры 10.9.0.2–10.9.0.4
   не перенастраиваются и не теряют handshake.
3. `awg1` и `table 100` не рвутся: только runtime `awg set`, затем запись
   `Endpoint` в `/etc/amnezia/awg1.conf` после подтверждённого liveness.
   `awg-quick down/up` в горячем пути запрещён.
4. Dry-run по умолчанию + `--apply` + `FileLock` для мутирующих команд.
5. Activity gate: простой без трафика не триггерит манёвр.
6. Откат по таймауту: нет восстановления liveness за `probe_timeout_s` (20 с) →
   вернуть предыдущий endpoint, записать событие.
7. `run_list([...])`, stdlib-only, 0600 для state/конфигов, 0 секретов в логах.

## 3. Контракты

### 3.1 Интерфейсы и адресация

| объект | значение |
|---|---|
| `awg2` (exit) | подсеть `10.11.0.0/30`: exit `10.11.0.1`, релей `10.11.0.2` |
| базовый порт `P_base` | `51900/udp` (слушает `awg2`) |
| пул портов | `51900–51911` (12), все слушаются 24/7, `nft` REDIRECT `saddr <relay-ip>` → `P_base` |
| `awg1` (relay) | endpoint `exit-ip:<pool_port>`, `Table = off`, `PersistentKeepalive = 25` |
| `awg2` peer (exit) | `PersistentKeepalive = 25`, единственный разрешённый адрес — `<relay-ip>` |

### 3.2 UFW / nft (exit)

```
ufw allow from <relay-ip> to any port 51900 proto udp   # только P_base
nft: table inet vds_relay_leg {
  chain prerouting  { type nat hook prerouting priority dstnat; }
  #   ip saddr <relay-ip> udp dport 51901-51911 redirect to :51900
  #   (сам 51900 не матчится — петли нет)
  chain postrouting { type nat hook postrouting priority srcnat; }
  #   ip saddr 10.11.0.0/30 oifname "<wan>" masquerade
  chain input { type filter hook input priority filter - 1; policy accept; }
  #   ip saddr != <relay-ip> udp dport 51900-51911 drop
  #   meta nfproto ipv6 udp dport 51900-51911 drop
}
```
`net.ipv4.ip_forward = 1` обязателен (install проверяет и отказывает иначе).
Правила — oneshot-юнит (переживают reboot); перед apply — `nft -c -f`.

### 3.3 State (exit)

`state["protocols"]["relay_leg"]`:

```json
{"iface": "awg2", "subnet": "10.11.0.0/30", "exit_ip": "10.11.0.1",
 "peer_ip": "10.11.0.2", "base_port": 51900, "pool": "51900-51911",
 "relay_ip": "185.80.91.135", "public_key": "<pub релея>",
 "exit_public_key": "<pub awg2 — для клиентского шаблона>",
 "obfuscation": {"Jc": 0, "Jmin": 0, "Jmax": 0, "S1": 0, "S2": 0,
                 "H1": 0, "H2": 0, "H3": 0, "H4": 0},
 "exit_public_ip": "213.108.23.119", "wan_iface": "enp0s3", "installed": true}
```

### 3.4 State и история манёвра (релей)

`/var/lib/vds/relay-maneuver.json` (0600):

```json
{"version": 1, "current_port": 51900, "previous_port": 51900,
 "attempts": [{"ts": "...", "from": 51900, "to": 51901, "result": "ok|rollback",
               "liveness_ms": 47}], "cooldown_until": "...", "exhausted": false}
```

Состояния: `idle` → `healthy` → `suspect` → `maneuvering` → `cooldown` → `exhausted`.

### 3.5 Триггер (data-plane, НЕ handshake)

`suspect`, если одновременно:

1. liveness-проба внутри туннеля падает N≥3 раза подряд
   (`ping -I awg1 10.11.0.1` и/или TCP до exit через туннель);
2. есть активный трафик: прирост `tx` пиров `awg0` за окно или растущий счётчик
   `awg1.tx` при нулевом `rx`-приросте;
3. `handshake_age` **не используется** как триггер (только для отчёта).

Anti-ping-pong: ≤1 попытка в `cooldown_s` (600), ≤3 в час, детерминированный
обход пула без возврата на только что отказавший порт.

### 3.6 CLI

```
vds relay maneuver status [--json]
vds relay maneuver history [--limit N]
vds relay maneuver step [--dry-run|--apply]
vds relay maneuver rollback [--apply]
vds relay maneuver tick [--apply]              # ExecStart таймера; всегда exit 0
vds relay maneuver install [--apply] [--enable-auto] [--interval 60s]
vds relay maneuver remove [--apply]
sudo vds relay exit-leg install  [--apply]   # exit: awg2 + пул + UFW/nft
sudo vds relay exit-leg remove   [--apply]
```

Exit-часть — только на самом exit (роль владельца); на релее `exit-leg`
отказывает с явным сообщением.

### 3.7 Новые параметры alert-watch

`ALERT_RELAY_IFACE` (default `awg0`) — с какого интерфейса читать пир релея;
`read_relay_signal` ищет peer по `relay_peer` public key, а не по имени iface.

## 4. Work Packages

| WP | Содержание | Файлы | Зависимости | AC |
|---|---|---|---|---|
| M0 | Факты и валидация гипотезы | report | — | ✅ 2026-11-20 |
| M1 | ADR-015 + этот SPEC | docs | M0 | ✅ 2026-11-20 |
| M2 (P24) | exit: `awg2` + юнит + UFW/nft пул + `ALERT_RELAY_IFACE` | `src/relay/exit_leg.py`, `src/gateway/paths.py`, `src/system/ufw.py`, `src/alert/checks.py`, `src/alert/env.py`, `systemd/vds-awg-relay.service.tpl`, `systemd/vds-awg-relay-pool.service.tpl`, tests | M1 | клиенты не задеты; скан пула с чужого IP молчит; reboot-устойчивость; идемпотентность |
| M3 (P25 core) | relay: state-machine, liveness, актуатор `awg set`, anti-ping-pong, CLI | `src/relay/maneuver.py`, `src/relay/paths.py`, `src/main.py`, tests | M1 | dry-run/apply; rollback по 20 с; нет рестарта `vds-relay-exit`; секретов нет |
| M4 | opt-in таймер (60 с) + journal-теги | `systemd/vds-relay-maneuver.{service,timer}.tpl`, `src/relay/maneuver.py`, `src/core/units.py`, `src/main.py`, tests | M2, M3 | auto=off по умолчанию; exit-код тика всегда 0 |
| M5 | G4–G6: unit + живое окно + docsync | доки, TECHDEBT, STATUS, report | M2, M4 | nft drop порта → <60 с; `docsync audit --strict` = 0 |

**M4 — уточнение тайминга и `--interval` (2026-11-20).** `install` принимает
аддитивный `--interval` (дефолт `60s`, минимум `15s`, парсер — как у
`alert install`). Таймер: `OnUnitActiveSec=<interval>` + `Unit=vds-relay-maneuver.service`,
`[Install] WantedBy=timers.target`; у `.service` секции `[Install]` нет
(включается только таймером). При `OnUnitActiveSec=60s` и пороге `N=3`
детекция в авторежиме — **≈180 с (3 тика)** до `suspect` + 5–20 с сам манёвр.
Критерий M5 «<60 с» относится к **времени реакции актуатора после достижения
suspect (3/3)**, а не к интервалу от первого пропавшего пакета. Для стенда
допустим `--interval 15s`. `tick` — отдельная команда (`ExecStart` юнита),
**всегда exit 0**: `ManeuverError`/`StoreError`/`OSError`/отказ guard/занятый
`FileLock` перехватываются, печатается одна структурированная строка
`[relay-maneuver] state=… port=… liveness=<ok|fail> ms=<…|-> activity=<0|1>
fails=<n>/3 acted=<0|1> result=<ok|rollback|none>`; секретов нет. `step`
остаётся ручным (dry-run по умолчанию).

## 5. Тесты (unit, без root/сети)

- state-machine: `idle/healthy/suspect/maneuvering/cooldown/exhausted` — таблица переходов;
- activity gate: idle + stale handshake → **нет** манёвра (регресс на WP-M0);
- rollback: проба не восстановилась за 20 с → endpoint возвращён, событие записано;
- anti-ping-pong: 2-я попытка в течение 600 с отклоняется;
- pool walk: не возвращается на только что отказавший порт;
- `exit_leg`: рендер `awg2.conf`, nft-правил, UFW-строк; идемпотентность; `remove` откатывает;
- секреты: нет PSK/ключей в `status --json` и journal.

## 6. Риски

| риск | митигация |
|---|---|
| Смена UDP-порта не помогает (режется весь UDP до IP) | IPv6-нога (WP-M0: 47 мс, TCP6 OPEN) или TCP-Reality — отдельный WP |
| Ложный манёвр при живом канале | триггер = liveness внутри туннеля, а не handshake; activity gate; cooldown |
| Обрыв `table 100` при манёвре | только runtime `awg set`; откат по таймауту |
| Ослабление границы доверия | пул статичен на exit, reley без прав на exit |

## 7. Открытые вопросы

- OQ-1: IPv6-нога как первый fallback — нужна проверка стабильности 24 ч (WP-M5).
- OQ-2: причина 5-часового stale-handshake при идущем трафике (dkms 1.0.0) —
  отдельный эксперимент; до ответа `handshake_age` не используется в триггере.
- OQ-3: нужен ли pool > 12 портов (зависит от поведения ТСПУ в живом окне).
