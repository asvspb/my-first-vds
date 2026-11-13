# HANDOFF-20261113 — отчёт другому ИИ-агенту: состояние asv1 после приёмки P0+W1, инциденты, откат

> Аудитория: ИИ-агент/оператор, который продолжит работу с сервером asv1 после
> этого отчёта. Читай целиком перед любым действием. Дата: 2026-11-13 ~06:00 UTC.

## 1. Что было сделано в цикле 2026-11-12/13 (контекст)

- **P0-пакет `4d1edd1`**: Hysteria2 port hopping (iptables-цепочка `VDS_HY2_HOP`,
  REDIRECT 20000:20500/udp → 443, oneshot-юнит `vds-hysteria2-hop`), obfs salamander
  (UDP 51826, параллельный инстанс `vds-hysteria2-obfs`), пул CDN-фронтов
  (`add-cdn-front`, state), `gateway blockcheck`.
- **W1 `1e0b679`**: deploy-hook ACME рестартует все 3 юнита (hy2 безусловно,
  xray/obfs через `systemctl cat`-guard), `gateway healthcheck` + таймер 5 мин
  (`vds-gateway-health.timer`), пороги cert 14/7 дн.
- **Живая приёмка на asv1: PASS** (ACCEPT-20261113-p0-w1-live.md, `b5ab053`):
  hop применён и пережил reboot, REDIRECT подтверждён внешними UDP-пробами,
  hook перегенерирован и проверен ручным прогоном (6 systemd-событий),
  healthcheck-таймер установлен и сработал.

## 2. Раскладка кода на сервере (важно: /opt/my-vds — БЕЗ .git)

- Код живёт в `/opt/my-vds` (PYTHONPATH), CLI: `/usr/local/bin/vds`
  (обёртка `python -m src.main`). **Git-клона на сервере нет** — deploy был
  scp-файлами: сегодня `src/gateway/health.py`, `src/acme/install.py`,
  `src/main.py`, `systemd/vds-gateway-health.{service,timer}.tpl`.
- P0-код уже стоял ДО этой приёмки (hop/obfs/blockcheck-команды на месте,
  obfs применён 2026-11-12 16:48) — кто деплоил, из этого цикла неизвестно.
- state: `/opt/my-vds/gateway/state.json` (version 1; `hop_ports` задан,
  `hysteria2-obfs.installed=true`, `xray-cdn.fronts` пуст).

## 3. Инцидент №1 — AWG PSK-truncation (ИСПРАВЛЕН, но проверь)

**Root cause:** при создании мобильного AWG-пира (10.9.0.3, 2026-11-12) значения
`PUB`/`PSK` доставались из `/etc/amnezia/mobile/mobile.meta` командой
`cut -d= -f2` — base64-значения **обрезались по первому `=`** (паддинг).
Битые PubKey/PSK легли в `/etc/amnezia/awg0.conf`. До reboot маскировалось
поднятым runtime-ом; **reboot 2026-11-13 05:02 проявил**: `vds-amneziawg` failed
(«Key is not the correct length or format»), iface awg0 не поднялся.

**Фикс (сделан):** `awg0.conf` восстановлен из `awg0.conf.bak-pre-mobile`,
значения перечитаны корректно (`sed -n 's/^PUB=//p'` и т.п. — длина 44),
`systemctl restart vds-amneziawg` → обе peer-записи на месте, handshake
ноутбука (peer .2) «Now» сразу после фикса.

**Что проверить наследнику:**
1. `awg show awg0` — 2 peer-а, у мобильного (10.9.0.3) ключи длиной 44 симв.
2. Телефон владельца (peer .3, конфиг `~/.config/vpn-manager/mobile-awg.conf`
   на ноутбуке + QR `mobile-awg-qr.png`) — handshake ещё ни разу не подтверждён.
3. Урок: base64 из KEY=VALUE доставать только `sed 's/^KEY=//p'`, никогда
   `cut -d=`.

## 4. Инцидент №2 — TSPU-окно в момент верификации протоколов (ОТКРЫТ)

Хронология (2026-11-13 ~05:5x UTC):
1. Сквозной `vpn probe --no-switch` с ноутбука: **cdn-home ok** (2845–3176 ms),
   **mob (hy2) / phone (reality) / xhttp-web — fail** (timeout на всех сэмплах).
2. Голые TCP-пробы с ноутбука: **443/8443/2053 FAIL**, и **SSH 22 FAIL** —
   полный блок IP asv1 от клиента в РФ. SSH работал за минуты до этого.
3. Внешняя верификация не удалась с ноутбука: check-host.net из РФ — пустой
   ответ; через socks 2081 — socks-портов в этот момент нет (probe поднимает
   их временно).
4. Проверка извне РФ через WebFetch-инструмент агента: **ETIMEDOUT и на
   103.45.247.172:443, и на check-host.net, и даже на example.com** —
   значит эгресс самого инструмента деградировал; **вывод «сервер мёртв
   глобально» из этого НЕ делать**. Инструментальную валидность верификации
   восстановить (другая точка выхода / `curl` с чистого VPS / мобильный интернет
   владельца) и проверить сервер снаружи заново.

**Гипотезы (по приоритету):**
- **H-1 (вероятная): behavioral-заморозка TSPU** — паттерн И25/И26 (PATTERNS/копилка):
  blackhole ~120 с после >3 параллельных хендшейков к одному SNI. Приёмка
  нагенерила много проб (hop-пробы, openssl, ssh). Но окно длится >4 мин —
  возможно, длинный эпизод (PATTERNS §0 знает эпизоды полного блока asv1).
- **H-2 (менее вероятная, исключить в первую очередь!): сервер упал после
  reboot/healthcheck-таймера.** До блока все 4 юнита были active, порты слушались,
  hop-счётчик чистый. healthcheck unit-режим rc 0. Признаков краха не было,
  но прямо перед блоком мы ставили `vds-gateway-health.timer` и прогоняли hook.
  Опровергается внешней пробой или консолью хостера.

**Что сделать наследнику (порядок):**
1. `ping`/TCP-проба asv1:443 из НЕ-РФ точки (чистый VPS, мобильный интернет
   владельца, панель хостера VNC). Сервер жив? → H-1, просто ждать окно.
2. Если жив — выждать 10–30 мин и повторить с ноутбука; блок обычно спадает.
3. Если мёртв глобально — консоль хостера (VNC): `systemctl is-active` всех
   4 юнитов, `journalctl -u vds-gateway-health -b`, dmesg. Откат см. §5.
4. После разблокировки НЕ повторять ошибку приёмки: пробы серийно с паузами
   (И26), не параллельно; `gateway blockcheck` — штатный инструмент различения
   «локально мёртв / IP-блок / глобальная деградация» (но и он качает probes —
   держать разнесённо).

## 5. Бэкапы и откат (полная карта)

**Снапшот перед приёмкой** (на asv1): `/root/acceptance-20261113/`
- `iptables.bak-pre`, `ip6tables.bak-pre` — полный дамп правил ДО hop
- `config.json.bak-pre` — Xray ДО каких-либо изменений этого цикла
- `config.yaml.bak-pre` — Hysteria2 основной ДО
- `awg0.conf` — снимок на момент снапшота (⚠️ уже содержит битый мобильный пир!)
- Истинно чистый AWG-конфиг: `/etc/amnezia/awg0.conf.bak-pre-mobile`

**Атомарные бэкапы кода (автоматические):**
- `config.yaml.bak-pre-le`, `cert.pem.bak-pre-le`, `key.pem.bak-pre-le`
  (Hysteria2, от ADR-004 hook-а)
- `awg0.conf.bak-pre-mutation`, `awg0.conf.bak.jcfix` — от более ранних циклов

**Откат по компонентам (все идемпотентные команды проекта):**
- hop: `vds hysteria2 remove-hop-ports --apply` (цепочка+jump+UFW-правило+юнит+state);
  руками: `iptables -t nat -F VDS_HY2_HOP; iptables -t nat -D PREROUTING -j VDS_HY2_HOP;
  iptables -t nat -X VDS_HY2_HOP; systemctl disable --now vds-hysteria2-hop`
- obfs: `vds hysteria2 remove-obfs --apply`
- healthcheck-таймер: `systemctl disable --now vds-gateway-health.timer` +
  `rm /etc/systemd/system/vds-gateway-health.{service,timer}` (команды
  `--remove-timer` в коде нет — известный пробел, TECHDEBT)
- hook: вернуть однострочный рестарт (файл
  `/etc/letsencrypt/renewal-hooks/deploy/vds-hysteria2-cert.sh` — см. git
  `1e0b679^` для старого рендера)
- health.py-код: просто удалить `/opt/my-vds/src/gateway/health.py`
  (больше ничего не импортирует)
- AWG-мобильный пир: удалить секцию peer 10.9.0.3 из `awg0.conf` + `awg set awg0 peer <pub> remove`
- Полноразмерный откат сервера: снапшоты §5 + код из git (репо:
  github.com/asvspb/my-first-vds, main @ `b5ab053`; P0=`4d1edd1`, W1=`1e0b679`)

**Что НЕ тронуто (откат не нужен):** сертификаты LE, клиентские UUID/пароли,
share-параметры, CDN-часть (fronts не применялись, DNS не менялся),
ZeroTier (выключен владельцем).

## 6. Состояние «последней здоровой точки»

2026-11-13 ~05:50 UTC (непосредственно до окна): 4 юнита active
(xray/hysteria2/hysteria2-obfs/amneziawg), порты 443tcp/443udp/8443tcp/2053tcp/
51825udp/51826udp слушались, hop-цепочка на месте, healthcheck rc 0, cert 88 дн.,
Reality-gate (openssl на 443 с чужим SNI → CN google) — probe resistance жив.
С момента последней проверки серверных юнитов **признаков деградации сервера
не наблюдалось**; обрыв наступил сетевой (все TCP-порты + 22 одновременно).

## 7. Открытые пункты (не блокируют откат)

- CDN-фронты: DNS-часть в панели CF — шаг владельца (docs/CDN-FRONTS.md)
- И18 whitelist-чекер: ждёт решений владельца (OQ-1..3)
- ADR-009 per-client auth: отложен «на подумать»
- И20: тикет хостеру о dest/SNI той же AS — не отправлен
- И26-инвариант «серийные пробы» — зафиксировать в probe после этого окна

---

## 8. Addendum (2026-11-13 05:40 UTC): инцидент №2 закрыт, найден и исправлен инцидент №3

### 8.1. Инцидент №2 (TSPU-окно): H-2 опровергнут, H-1 подтверждён с уточнением

**Проверено преемником сразу после чтения отчёта.**

Состояние сервера (SSH с ноутбука, РФ):

```
uptime: up 33 min, boot 2026-11-13 05:02 (это плановый reboot для AWG-фикса)
юниты: xray, hysteria2, hysteria2-obfs, hysteria2-hop, amneziawg, health.timer — все active
порты: 443tcp/8443tcp/2053tcp/443udp/51826udp/51825udp слушаются; hop-цепочка на месте
healthcheck: прогон 05:31:27, rc 0, сертификат 88 дн.
```

Внешняя проверка (check-host.net, 51 узел, 05:36–05:39 UTC):

| Проба | Результат |
|---|---|
| ICMP `103.45.247.172` | **51/51 OK** (0.018–0.2 с) |
| TCP 22 / 443 / 2053 | **0/51**: `Connection refused` / `timeout` с большинства узлов |
| TCP `1.1.1.1:443` (контроль) | 51/51 OK — API исправен |
| С ноутбука (РФ): 22/443/2053 | open; TLS на 443 → `CN=*.google.com` (Reality-decoy жив) |

На сервере **файрвола нет**: `ufw inactive`, `iptables -P INPUT ACCEPT`, в nft только
nat-цепочка `VDS_HY2_HOP`. Значит TCP-фильтрация по источнику — **на стороне
провайдера/апстрима** (гео/anti-DDoS), не сервера.

**Вывод:**
- **H-2 (сервер упал) — опровергнут**: сервер непрерывно работал, рестартов юнитов
  после boot нет.
- **H-1 (сетевой эпизод) — подтверждён**, но формулировка в §4 требует уточнения:
  блок был **по источнику**, а не «сервер мёртв». РФ-клиент был отрезан ~10–30 мин,
  а не-РФ источники **не проходят TCP постоянно** (ICMP при этом проходит для всех).
- Практический инвариант: «сервер недоступен» проверять тремя осями — **ICMP, TCP,
  страна/AS источника**. Отсутствие TCP с check-host ≠ смерть сервера.
- ⚠️ Таймстемпы §4/§6 сдвинуты: фактические события ~**05:2x–05:3x UTC**, а не
  «05:5x/06:00». Отчёт писался в 05:32 UTC (mtime).

### 8.2. Инцидент №3 (НОВЫЙ, исправлен 05:37): подмена сертификата Hysteria2 сломала ссылки

**Симптом:** `gateway links` отдаёт `sni=103-45-247-172.eu-cloud-xip.com`, а
`/etc/hysteria/cert.pem` после приёмки W1 стал `subject=CN=asvpersonal.ru`
(deploy-hook применяет сертификат своего домена). Проверка локальным
`hysteria client`:

```
sni=103-45-247-172.eu-cloud-xip.com -> FATAL (TLS), туннель не поднимается
sni=asvpersonal.ru                  -> curl через туннель OK
```

То есть **все hy2-ссылки (main и obfs) были нерабочими** для клиентов, пока не
поправлен сертификат. Xray не затронут: XHTTP-инбаунд использует cert xip.com
(`config.json:50`), CDN-origin — cert asvpersonal.ru (`config.json:80`).

**Фикс (сделан):**

```
cp -a /etc/hysteria/cert.pem /etc/hysteria/cert.pem.bak-asvpersonal
cp -a /etc/hysteria/key.pem  /etc/hysteria/key.pem.bak-asvpersonal
install -m 0600 /etc/letsencrypt/live/103-45-247-172.eu-cloud-xip.com/fullchain.pem /etc/hysteria/cert.pem
install -m 0600 /etc/letsencrypt/live/103-45-247-172.eu-cloud-xip.com/privkey.pem   /etc/hysteria/key.pem
systemctl restart vds-hysteria2 vds-hysteria2-obfs
```

Проверено: `subject=CN=103-45-247-172.eu-cloud-xip.com`, `notAfter=Feb 7 2027`,
оба юнита active, handshake с `sni=xip.com` проходит (curl через туннель →
`103.45.247.172`). Ссылки менять не пришлось.

**Причина и рецидив:** hook доменно-зависим (`DOMAIN="asvpersonal.ru"`), а
`state.domain = xip.com` — именно этот домен попадает в ссылки. Следующее
продление asvpersonal.ru снова подменит `/etc/hysteria/cert.pem` → hy2 опять
сломается. Нужен **GR-10**: раздельные `host`/`sni` в ссылке (host = адрес
сервера, sni = домен развёрнутого сертификата) либо единый домен для hy2; до
реализации — добавить в healthcheck проверку «subject cert.pem == sni из links».

### 8.3. §3 (AWG PSK-truncation): подтверждено на живом пире

`awg show awg0 dump`:

```
10.9.0.2/32  last handshake 05:35:15 UTC  (ноутбук)
10.9.0.3/32  last handshake 05:09:35 UTC  (мобильный пир — ПОСЛЕ reboot 05:02)
```

Мобильный пир подключался после фикса PSK — открытый вопрос из §3 закрыт.

### 8.4. Что делать дальше (приоритет)

1. **Владельцу:** проверить в панели хостера anti-DDoS/гео-фильтр TCP (ICMP
   проходит, TCP с не-РФ AS — refused). Это влияет и на CDN-цепочку CF→origin.
2. **Код:** healthcheck-инвариант «cert subject == sni в ссылках» (дешёвый детект
   инцидента №3); затем GR-10 (host/sni).
3. Зафиксировать И26 (серийные пробы с паузами) в `probe`/приёмке.
4. Поправить таймстемпы §4/§6 (см. 8.1).
