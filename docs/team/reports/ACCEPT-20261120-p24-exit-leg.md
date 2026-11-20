# ACCEPT — P24: изолированная нога relay↔exit на `awg2` (2026-11-20)

- **Код:** `d171295` (P24), `bf0ead9` (фикс P0/P1), `924552d` (доки)
- **Контракт:** [ADR-015](../../adr/ADR-015-relay-exit-isolation-maneuver.md),
  [SPEC-20261120](../specs/SPEC-20261120-relay-maneuver.md)
- **Полигон:** exit asv2 `213.108.23.119`, RU-релей `185.80.91.135`
- **Вердикт:** ✅ PASS (клиентские пиры не затронуты; нога живёт на изолированном
  порту; внешний скан пула молчит). P25 (манёвр) — не входил в этот выкат.

## 1. Выкат на exit

```
vds relay exit-leg install --relay-ip 185.80.91.135 \
  --public-key xoqTx1f5nSSjPoz+brJtte++vlp60dqT1lJKe3efXnw= --apply   → exit 0
```

Факты после применения:

| Проверка | Результат |
|---|---|
| `awg show awg2` | listen **51900**, пир `xoqTx1f5…` (релей), `allowed ips 10.11.0.2/32`, `persistent keepalive: 25`, обфускация сгенерирована (Jc/Jmin/Jmax/S1/S2/H1..H4) |
| `awg show awg0` | **не изменён**: relay-пир (10.9.0.5) + клиентские 10.9.0.2/.3/.4 на месте |
| `nft list table inet vds_relay_leg` | 3 цепочки: `prerouting` (redirect 51901–51911 → :51900, `saddr` релея), `postrouting` (`masquerade 10.11.0.0/30` на `enp0s3`), `input` (`drop` пула для не-релея + ipv6) |
| `ufw status` | `51900/udp ALLOW 185.80.91.135` (только P_base, только релей) |
| `ss -ulnp` | `0.0.0.0:51900`, `[::]:51900` |
| `vds system ufw harden --profile gateway` (dry-run) | правило `from 185.80.91.135 to any port 51900 proto udp [уже есть]`; предупреждений о неизвестном слушателе нет |
| Внешний UDP-скан с ноутбука: 51900 / 51901 / 51911 | **тишина** (ни ответа, ни ICMP unreachable) |

## 2. Cutover релея

Шаблон `relay-exit-leg.conf` (0600, без приватного ключа) перенесён exit → ноутбук →
релей; `PrivateKey` подставлен на релее из его собственного `awg1` (ключ релея не
покидал релей). Бэкап: `/etc/amnezia/awg1.conf.bak-pre-leg`.

```
systemctl restart vds-relay-exit   → active
systemctl restart vds-relay-policy → active
```

| Проверка | Результат |
|---|---|
| `awg show awg1` | endpoint **213.108.23.119:51900**, peer = pub awg2, `allowed ips 0.0.0.0/0`, `latest handshake` 5 с, `persistent keepalive 25` |
| `ping -I awg1 -c3 10.11.0.1` | 3/3, 0 % потерь, 32 мс |
| `curl --interface awg1 https://ifconfig.me` | **213.108.23.119** |
| `ip route show table 100` | `default dev awg1` (policy-routing цел) |
| Пул: временный `endpoint …:51901` → ping → возврат `:51900` | 51901: 2/2, 31 мс; 51900: 2/2, 31 мс — **nft REDIRECT + conntrack работают** |

## 3. Сторож

`/etc/vds/alert.env` (0600): добавлен `ALERT_RELAY_IFACE=awg2`.

```
vds alert status --json → relay_pulse: {checked: true, classification: "ok",
                                        peer_found: true, handshake_age_sec: 30}
```

## 4. Страховка и остатки

- Старый пир релея на клиентском `awg0` (10.9.0.5) **не удалён** — минимум 24 ч
  стабильной работы `awg2`; откат = вернуть `awg1.conf.bak-pre-leg` + рестарт
  `vds-relay-exit`/`vds-relay-policy` (без правок на exit).
- Откат exit-стороны: `vds relay exit-leg remove --apply`.
- Бэкап `/etc/amnezia/awg1.conf.bak-pre-leg` **удалён 2026-11-20** после зелёного
  ребут-протокола обоих узлов (§5); откат теперь только через exit-сторону или
  пересборку ноги.
- Не проверено: сквозной клиентский трафик через релей на живом устройстве (нет
  активного клиента в момент приёмки), поведение при реальном ТСПУ-блоке
  (WP-M3/M4).

## 5. Ребут-протокол (2026-11-20, AC-2)

Узлы перезагружались **строго по одному**: сначала exit asv2, затем релей.
Проверка релея выполнялась без ручных действий на стороне exit.

### Exit asv2

| Проверка после ребута | Результат |
|---|---|
| `systemctl is-active vds-awg-relay.service vds-awg-relay-pool.service vds-alert-watch.timer …` | 6/6 `active` |
| `awg show awg2` | listen **51900**, `allowed ips 10.11.0.2/32`, `persistent keepalive: 25` |
| `nft list table inet vds_relay_leg` | 3 цепочки на месте (пересозданы `vds-awg-relay-pool`) |
| `ip_forward` | `1` |
| `ufw status` | `51900/udp ALLOW 185.80.91.135` |
| `/var/lib/vds/probe-watch.json` | присутствует (сторож жив) |
| Внешний UDP-скан с ноутбука 51900 / 51901 / 51911 | **тишина** (3 с timeout по каждому) |

### Релей (после зелёного exit)

| Проверка после ребута | Результат |
|---|---|
| `is-active` vds-relay-awg / exit / nat / policy / cidr.timer | 5/5 `active` |
| `is-enabled` / `is-active` `vds-relay-maneuver.timer` | `disabled` / `inactive` (auto=off) |
| `ip route show table 100` | `default dev awg1 scope link` |
| `ip rule show` | `32765: from all fwmark 0x1 lookup 100` |
| `awg show awg1` | `endpoint 213.108.23.119:51900`, handshake 1 м 12 с (**нога поднялась сама**), keepalive 25 |
| `ping -I awg1 -c3 10.11.0.1` | 3/3, **0 %** потерь, 31 мс |
| `curl --interface awg1 https://ifconfig.me` | **213.108.23.119** |
| `vds relay maneuver status --json` | state `cooldown`, `endpoint_port` **51900**, пул 51900–51911 |
| `Endpoint` в `/etc/amnezia/awg1.conf` | `213.108.23.119:51900` (персист манёвра пережил ребут) |
- `vpn-guard.service` на ноутбуке не трогался (окно G6 до 2026-11-24 15:24 MSK).
