# ACCEPT-20261113 — живая приёмка P0 + W1 на asv1

- **Дата:** 2026-11-13 · **Сервер:** asv1 / 103.45.247.172
- **Коммиты:** P0 `4d1edd1`, W1 `1e0b679`, research `3a54569`, chore `f352f73`
- **Вердикт: PASS** (все `[VDS]`-пункты AC закрыты; 2 инцидента в процессе, оба устранены)

## Снапшот отката (до работ)

`/root/acceptance-20261113/`: iptables.bak-pre, ip6tables.bak-pre,
config.json.bak-pre, config.yaml.bak-pre, awg0.conf (+ `awg0.conf.bak-pre-mobile`).

## P0-чеклист (SPEC §3.5/§4.4/§5.4)

| AC | Результат |
|---|---|
| add-hop-ports dry-run → план без мутаций | ✅ план корректный, ноль изменений |
| add-hop-ports --apply → цепочка+jump+UFW+юнит+state | ✅ `VDS_HY2_HOP` (-A REDIRECT 20000:20500→443), jump в PREROUTING, state hop_ports, юнит enabled |
| UFW | ⚠️ UFW на asv1 **inactive** (файрвол = чистый iptables) — правило добавлено, no-op; работа через iptables-цепочку |
| Живой 443/udp не прерывался | ✅ |
| **REDIRECT-функционал** (внешняя проба) | ✅ 3 UDP-пакета с ноутбука в диапазон → счётчик правила ровно 1→3 (REDIRECT подтверждён в бою) |
| Идемпотентность apply×2 | ✅ дублей -A нет (2 строки в цепочке) |
| add-obfs (был уже применён деплоером ранее) | ✅ юнит active, 51826 слушается, yaml 0600 |
| obfs-клиент подключается | ✅ сверх AC: journal содержит **реальный клиентский трафик** через obfs (ноут владельца, 2026-11-12 17:43) |
| journal без obfs-пароля | ✅ grep -cF пароля = 0 за 7 дней |
| blockcheck живой → ok, rc 0 | ✅ evidences полные |
| blockcheck DROP 443/tcp → local_problem | ✅ local False + внешний ок, рекомендация корректная; снятие → ok |
| CDN-пул | ⏳ серверная часть здорова (fronts в state нет — не применялась); DNS-часть (CF-панель) — отдельный шаг владельца по docs/CDN-FRONTS.md |

## W1-чеклист (§5 W1)

| AC | Результат |
|---|---|
| Deploy W1 на asv1 | ✅ scp 5 файлов, compileall OK, ручной healthcheck зелёный |
| hook рестартует все 3 юнита | ✅ hook перегенерирован (install_deploy_hook), grep показывает безусловный restart hy2 + цикл try-restart xray/obfs с cat-guard; ручной прогон → 6 systemd-событий, все active |
| certbot renew --dry-run | ✅ «all simulated renewals succeeded» (⚠️ hook при --dry-run не вызывается — см. дефекты №4) |
| `gateway healthcheck` ручной | ✅ все юниты/порты, cert 88 дн. |
| `--install-timer` | ✅ таймер установлен и уже сработал (OnUnitActiveSec=5min); unit-режим rc 0 |

## Reboot-гейт (Фаза 3)

- hop: юнит отработал при загрузке (active (exited)), **цепочка восстановлена** ✅
- xray/hy2/obfs: active, все 5 портов, Reality-gate (dest google по SNI — probe resistance жив) ✅
- ⚠️ **Инцидент 1**: vds-amneziawg failed после ребута — root cause: вчерашний мобильный
  пир вписан в `awg0.conf` командой `cut -d= -f2`, которая **обрезала base64** по
  `=`-паддингу (битые PubKey/PSK). До ребута маскировалось runtime-ом.
  **Фикс:** восстановление из `.bak-pre-mobile` + корректное чтение meta
  (`sed -n 's/^PUB=//p'`), рестарт → peer-ы на месте, handshake ноутбука «Now»
  (рабочий канал владельца восстановлен немедленно).
- **Инцидент 2** (не из приёмки): P0-код уже был на asv1 до этой приёмки (obfs
  применён 2026-11-12 16:48) — деплоер не из этого цикла; принят как данность.

## Дефекты/наблюдения (в бэклог)

1. **Ошибка оператора (мой)**: `cut -d= -f2` ломает base64 — инцидент описан выше; правило: base64-значения доставать только `sed 's/^KEY=//p'`.
2. **W2-кандидат**: `vds acme issue` отказывает при orange-апексе (DNS-прекондишн) — перегенерация hook требует прямого вызова функции. Нужна команда `vds acme hook-reinstall` (или флаг `--skip-dns-check`).
3. `certbot renew --dry-run` не вызывает deploy-hook — методика приёмки дополнить: hook проверять ручным прогоном (или `--run-deploy-hooks`).
4. `gateway healthcheck` не проверяет 51825/udp (AWG вне state.protocols — осознанная граница; noted).
5. check-host RU-узлы: 0/0 (RU-сегмент API не отвечает) — ограничение для whitelist-диагностики И18; учитывать в методике.
6. `--remove-timer` для healthcheck — TECHDEBT (симметричный откат), кандидат уже был отмечен кодером.

## Итоговое состояние asv1

4 юнита active (xray, hy2, hy2-obfs, amneziawg) · hop 20000-20500→443 переживает
ребут · obfs 51826 с реальным трафиком · healthcheck-таймер 5 мин · cert 88 дн ·
blockcheck в арсенале · все боевые каналы живы, AWG-схема владельца восстановлена
и работает.

**Гейты:** G4 (Verify) — **PASS**. Циклы P0 и W1 закрыты полностью (DoD).
