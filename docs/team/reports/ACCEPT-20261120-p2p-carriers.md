# ACCEPT — носитель №2 (wstunnel/WG) + селектор: живая приёмка (WP-P2P-6)

- **Коммиты:** WP-P2P-1 `4ba2d11`, WP-P2P-2 `309353f`+`2429d19`+`9a2cb7b`+`39d14e0`,
  WP-P2P-3 `769a7eb`+`5513b68`+`dfe7f2c`, WP-P2P-4 `333d3e4`+`8145ac3`,
  P2-фикс `3a7609a`
- **Контракт:** [ADR-016](../../adr/ADR-016-p2p-link-multi-carrier.md),
  [SPEC p2p link](../specs/SPEC-20261120-p2p-link-multi-carrier.md)
- **Полигон:** RU-релей `<relay-ip>` ↔ exit (NL); клиент за релеем — активный
- **Вердикт:** ✅ PASS — полный цикл **primary → fallback → primary** в бою

## 1. Вендоринг и установка

| Шаг | Результат |
|---|---|
| Архив v11.1.0 на ноутбуке | sha256 `512edf4e…aa23` = пиннинг ✅ |
| `wstunnel install --archive --apply` (оба узла) | `wstunnel-cli 11.1.0`, `status --json`: pinned = installed |
| rsync src/ + systemd/ | md5 carriers/wstunnel/main идентичны на обоих узлах |
| **P0 приёмки:** `write_env` без mkdir | на релее нет `/etc/vds` → env молча не записался; фикс: mkdir + raise при сбое; тест `test_write_env_creates_parent_dir` |

## 2. Трёхшаговая установка

1. **релей `init`:** ключи `wg-ws0.priv` 0600 + prefix env 0600; публичный ключ
   `<relay-pub>` (в stdout секретов нет);
2. **exit `server`:** conf `wg-ws0` 10.12.0.1/30 (plain, пир релея /32, keepalive 25),
   nft `vds_relay_wstun`, UFW «9443/tcp только с IP релея», юниты
   (`vds-wstunnel-nft`/`vds-awg-wg-ws0`/`vds-wstunnel-server`), deploy-hook LE;
   печатает публичный ключ exit `<exit-pub>`;
3. **релей `client`:** conf `wg-ws0` (`Table=off`, MTU 1240, Endpoint
   `127.0.0.1:51822`), `Wants/After=wstunnel-client`, NAT-ветка, перерендер
   policy; **table 100 не тронут** — `default dev awg1`.

Сразу после установки: `ping -I wg-ws0 10.12.0.1` 3/3 **0 %**, 31.7 мс;
handshake 3 с; все 4 юнита active.

## 3. AC-таблица

| AC | Критерий | Результат |
|---|---|---|
| AC-1/AC-S1 | внешний скан 9443 — тишина | ✅ connect с ноутбука: timeout (nft drop чужих) |
| AC-S2 | LE + SNI `ws.<domain>` | ✅ `openssl s_client` с релея: `CN=ws.<domain>`, issuer LE |
| AC-3/AC-4 | обратный маршрут без правок на exit | ✅ ping 10.12.0.1 0 %; table 100 = awg1 до переключения |
| **AC-2** | блок пула 51900–51911 → fallback | ✅ полный живой цикл, см. §4 |
| AC-6 | prefer_primary | ✅ возврат на awg1: ≥600 с + 3 пробы (13 мин фактических) |
| AC-S4 | policy берёт носитель из state | ✅ `carrier-default-iface.sh` 0755 установлен; перерендер policy |
| AC-S7 | drop 9443 15 с → reconnect сам | ✅ NRestarts=0; handshake восстановился (22 с); ping с релея 31.9 мс |
| AC-S8 | bulk через awg0→wg-ws0 | ✅ ~1.4 МБ клиентского трафика за 13 мин fallback |
| AC-S9 | нет ложных relay_blocked | ✅ 0 `ALERT-SENT relay_blocked` в окно цикла (`ALERT_RELAY_IFACE=awg2,wg-ws0`) |
| AC-5 | MTU/MSS | ✅ bulk без зависаний при MTU 1240 (косвенно, через AC-S8) |
| AC-7 | единый FileLock | ✅ интеграционные тесты + бою (rollback → хук без re-lock) |

## 4. Живой цикл (боевое подтверждение, 2026-11-20 UTC)

| Время (UTC) | Событие |
|---|---|
| 17:44 | вставлен runtime drop `ct original proto-dst 51900-51911` (dead-man 600 с) |
| 17:46–17:48 | тики: fails 1/3 → 3/3, **activity=1** (клиентский трафик) → maneuvering |
| 17:48:19 | манёвр 51900→51901 → liveness fail → **rollback** |
| **17:48:43** | хук → pre-check wg-ws0 ok → **switched to wstunnel** (fallback, 24 с после rollback) |
| 17:48–18:01 | 13 мин клиентского трафика через носитель №2 (~1.4 МБ на exit wg-ws0) |
| ~17:53 | dead-man снял drop — awg1 ожил |
| **18:01:19** | prefer_primary (3 пробы awg1 + ≥600 с) → **switched to primary** |
| после | P25-серия сброшена (healthy, exhausted=False, failed_ports=[]) — ложного манёвра нет |

## 5. Проверено в бою (не только тестами)

- **P0-4 фикс (reset_p25_state/last_sample):** после возврата на primary —
  healthy, fails=0, ложного манёвра не было;
- **P0-3 фикс (свой state-path):** p2p-carriers.json и relay-maneuver.json
  не перезаписали друг друга;
- **AC-S9 дизайн (список интерфейсов):** alert-watch молчал всё время fallback.

## 6. Остатки

- Хвост 1 (P24): снять legacy-пир релея с `awg0` (окно с 2026-11-21 ~05:30 UTC);
- G6 close + деплой клиента — после 2026-11-24 15:24 MSK;
- P28 (TECHDEBT): hysteria-hook без фильтра `$RENEWED_DOMAINS`;
- скрипт `carrier-default-iface.sh` рендерится при `wstunnel client --apply`;
  для узлов, у которых шапка policy-юнита уже перерендерена с ExecStartPost,
  отсутствие скрипта до установки носителя безопасно (ведущий дефис).
