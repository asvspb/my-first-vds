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

## 4. Откат и восстановление

- asv2: `systemctl restart vds-awg-relay-pool.service` — таблица `vds_relay_leg`
  восстановлена штатно (тестовое ct-правило ушло), `awg2` жив.
- Релей: `vds relay maneuver rollback --apply` → 51901→51900, liveness 32 мс,
  Endpoint персистнут, `consecutive_failures` сброшен (фикс ee2b50f в бою).
- Финал: нога на **51900**, state `cooldown` (истекает сам), таймер auto=off,
  интервал 60s (стендовых 15s на проде не было).

## 5. Остатки

- Soak: старый пир релея на `awg0` asv2 — держать ≥24 ч (P24), затем удалить.
- Ребут-тест релея/exit — в окно ТО (юниты enabled).
- Первый реальный эпизод блока с клиентом за релеем — валидация ветки gate по
  `awg0` (см. §3); авто-таймер (`--enable-auto`) включается решением владельца
  после этого эпизода.
- `vpn-guard.service` не трогался (окно G6 до 2026-11-24 15:24 MSK).
