# ACCEPT — WP-M3/M4/M5: манёвр ноги relay↔exit (P25, ADR-015/SPEC-20261120)

- **Код:** `008b346` (M3) → `ee2b50f` (P1-фикс, APPROVE) → `add24c7` (M4) →
  `b7036c4`+`dd0b289` (StateDirectory, APPROVE) → `9335580` (P2: to= в теге)
- **Полигон:** RU-релей `185.80.91.135` (deploy: полный rsync `src/` + `systemd/`,
  md5 сверен; auto=off, интервал штатный 60s), exit asv2 (тестовые правила —
  только runtime)
- **Вердикт:** ✅ PASS — автомат отработал живой блок ноги: детект 3/3 → манёвр
  51900→51901 → liveness 32 мс → персист Endpoint → откат командой на базовый порт.

## 1. Развёртывание M3+M4 на релее

- rsync полного `src/` + `systemd/` (по ревью: maneuver тянет `exit_leg.parse_pool`,
  `alert.env.parse_duration`, `core.units(enable=False)` — точечный список дал бы
  ModuleNotFoundError/TypeError); `__pycache__` очищен, md5 7 ключевых файлов = local.
- `vds relay maneuver status`: `idle`, порт 51900, пул 51900–51911, таймер `disabled`/`inactive`.
- `step` (dry-run): `state=healthy — манёвр не нужен`.
- `install --apply` (без `--enable-auto`): оба юнита `enable=False`;
  `is-enabled timer=disabled`, `is-active=inactive`, `.service=static`.
- Одиночный `systemctl start vds-relay-maneuver.service`: **exit 0**, journal — одна
  строка `[relay-maneuver] state=healthy port=51900 liveness=ok ms=31 activity=0
  fails=0/3 acted=0 result=none`, `is-failed` → inactive (нет 226/NAMESPACE).

## 2. Замер шума gate (P2 из ревью M3)

`Δawg1.tx` за 60 с простоя (PersistentKeepalive=25 + 1 ping): **92 байта**
≪ `ACTIVITY_NOISE_BYTES=4096` и < прогноза 500 Б. Keepalive/junk не пробивают gate.

## 3. Живой тест блока (ключевой)

Методика: на asv2 runtime-правило `ct original proto-dst 51900 drop` (имитация
ТСПУ-блока именно 5-tuple порта 51900 — **не** дергает REDIRECT'нутые 51901+).
Важно: тупой `udp dport 51900 drop` в `input` режет и перенаправленные пакеты
(после REDIRECT dport=51900) — первая попытка теста корректно закончилась
rollback'ом 51901 (это заодно проверило ветку отката по 20 с). Для «блока порта»
правило MUST матчить original dst (conntrack).

Трафик: релей сам шлёт `ping -I awg1 -s 1200 -c 10` в цикле (окно сессии < 180 с —
`awg1.tx` считается; `awg1.rx`=0).

| тик | state | liveness | activity | fails | acted |
|---|---|---|---|---|---|
| 1–3 (до дропа) | healthy | ok 31 мс | 1/0/0 | 0/3 | 0 |
| 4 | suspect | fail | **1** | 1/3 | 0 |
| 5 | suspect | fail | **1** | 2/3 | 0 |
| 6 | maneuvering | fail→ok | **1** | 3/3 | **1 → result=ok** |

- Манёвр: `awg set awg1 listen-port 0 peer … endpoint …:51901` → liveness
  восстановился, **реакция после 3/3 ≈ 7 с** (< 60 с AC), `Endpoint` персистнут,
  `.bak-pre-maneuver` 0600, `table 100` цел, ping 31 мс на 51901.
- Первая попытка (шумный дроп-рул) валидировала откат: 20 с → runtime-возврат,
  конфиг не тронут, `failed_ports=[51901]`, `result=rollback`.

Находка (важно для эксплуатации): при мёртвом handshake (>180 с) WireGuard
**не шифрует** data-пакеты — `awg1.tx` замерзает, и ветка gate `Δawg1.tx ≥ 4096
при Δawg1.rx == 0` не срабатывает на «пингах через мёртвую ногу». В проде
триггер закрывается **первой** веткой — клиентским `awg0` (клиенты шлют в релей
независимо от состояния ноги), что покрыто unit-тестами; live-валидация ветки 1
случится на первом реальном эпизоде с клиентом за релеем.

## 3.1 Живая валидация ветки gate по `awg0` (2026-11-20, Tail 3)

Закрыт единственный непроверенный пункт §3: ветка gate «клиентский трафик в
`awg0` при мёртвой ноге» — раньше только unit-тесты.

**Условия.** За релеем живой клиент `10.10.0.4` (endpoint `178.155.115.222:1119`);
на клиенте запущен реальный трафик: **Δawg0 = 39.5 МБ за 60 с** (порог 4096 Б).
На exit — runtime-правило `ct original proto-dst 51900 drop` (имитация блока
именно текущего порта ноги; `51901+` и клиентский `awg0` не задеты) + страховка
`systemd-run --on-active=240` с автоснятием.

| тик (интервал 15 с) | state | liveness | activity | fails | acted |
|---|---|---|---|---|---|
| 1 | suspect | fail | **0** (первый тик — нет базовой выборки) | 1/3 | 0 |
| 2 | suspect | fail | **1** (клиентский `awg0`) | 2/3 | 0 |
| 3 | maneuvering | fail→ok | **1** | 3/3 | **1 → result=ok, to=51901** |
| 4–10 | healthy | ok 31 мс | 1 | 0/3 | 0 |

- Переезд `51900 → 51901` — **~7 с после 3/3**, детекция ≈ 45 с при ручном
  интервале 15 с (в проде при 60 с — ≈180 с, как в SPEC §4).
- Клиент не заметил переезда: handshake 43 с, `transfer` вырос до
  **2.95 MiB rx / 146.05 MiB sent** (идёт загрузка через релей).
- Важно: первый тик всегда даёт `activity=0` — одиночная выборка без
  предыдущей не считается активностью (защита от ложного триггера).

**Уборка.** Тестовое правило снято рестартом `vds-awg-relay-pool.service`
(`ct original` правил в цепочке — 0), dead-man таймер отменён (юнитов
`legtest-*` нет), `rollback --apply` вернул базу `51901 → 51900` (liveness 31 мс,
`Endpoint` персистнут), 4 клиентских пира `awg0` не тронуты.

## 4. Откат и восстановление

- asv2: `systemctl restart vds-awg-relay-pool.service` — таблица `vds_relay_leg`
  восстановлена штатно (тестовое ct-правило ушло), `awg2` жив.
- Релей: `vds relay maneuver rollback --apply` → 51901→51900, liveness 32 мс,
  Endpoint персистнут, `consecutive_failures` сброшен (фикс ee2b50f в бою).
- Финал: нога на **51900**, state `cooldown` (истекает сам), таймер auto=off,
  интервал 60s (стендовых 15s на проде не было).

## 5. Остатки

- Soak: старый пир релея на `awg0` asv2 — держать ≥24 ч (P24), затем удалить
  (окно открывается 2026-11-21 ~05:30 UTC).
- ~~Ребут-тест релея/exit~~ — **ПРОЙДЕН 2026-11-20** (§6): юниты enabled,
  нога поднялась сама на 51900 из персистнутого `Endpoint`, `table 100` и
  fwmark-правило целы, `maneuver.timer` остался `disabled`.
- ~~Первый реальный эпизод блока с клиентом за релеем~~ — **ветка gate по `awg0`
  валидирована вживую 2026-11-20 (§3.1)**. Осталось решение владельца по
  `--enable-auto` (критерий: AC-1 + AC-2 + ветка подтверждена + 0 ложных
  подозрений) — включается `vds relay maneuver install --apply --enable-auto`.
- `vpn-guard.service` не трогался (окно G6 до 2026-11-24 15:24 MSK).

## 6. Ребут-протокол (2026-11-20, AC-2)

По одному узлу: exit asv2 → релей. Полная таблица проверок exit — в
[ACCEPT P24](ACCEPT-20261120-p24-exit-leg.md) §5. Для манёвра существенны три факта:

| Проверка | Результат |
|---|---|
| `Endpoint` в `/etc/amnezia/awg1.conf` после ребута | `213.108.23.119:51900` — персист `persist_endpoint` пережил ребут |
| `awg show awg1` через ~2 мин после ребута | handshake 1 м 12 с — **нога восстановилась без `maneuver` и без ручных действий** |
| `maneuver status --json` | `state=cooldown`, `endpoint_port=51900`, пул 51900–51911, таймер `disabled`/`inactive` |
| `md5sum /opt/my-vds/src/relay/maneuver.py` | `90b2ae2de358dacd575371b72c85e904` = HEAD `9335580`; `to={target}` присутствует (стр. 1360) — **досинхронизация перед `--enable-auto` не требуется** |

Вывод: ребут не требует ни `step`, ни `rollback` — состояние порта живёт в
конфиге, а `state=cooldown` истекает сам (артефакт приёмки, не блокер).

