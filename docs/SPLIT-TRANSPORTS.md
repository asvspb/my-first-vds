# Системный split: AWG и его аналоги (Reality, Hysteria2, XHTTP, CDN)

> **Статус:** анализ (proposed), код не начат. Дата: 2026-11-13.
> Вход для intake (G0) и планирования волны «split-транспорты».
>
> **Вопрос, на который отвечает документ:** можно ли сделать другой транспорт
> «основным с зонным split» так же, как сейчас сделан AmneziaWG, и что для
> этого мешает.
>
> Смежное: [VPN-PROTOCOLS](VPN-PROTOCOLS.md) (§2.4 — измерения скорости),
> [CENSORSHIP-PATTERNS](CENSORSHIP-PATTERNS.md) §9 (И26),
> [GROWTH-POINTS](GROWTH-POINTS.md) (GR-16/GR-21),
> [CENSORSHIP-ROADMAP](CENSORSHIP-ROADMAP.md) (W4–W6), [ADR-007](adr/ADR-007-ru-relay.md),
> клиентская сторона — `ubuntuInstaller/doc/vpn-manager.md` (`vpn speed`,
> `vpn scheme`).

## 1. Как устроен AWG-split сегодня (эталон)

```
systemd-resolved → dnsmasq (127.0.0.1:53) → DoH (cloudflared)
                 └─ nftset: домены из /opt/awg-split/domains.txt
nft inet/awg_split: mark 0x21000 для адресов из set
ip rule fwmark 0x21000 → table 21000 → default dev awg0-split
awg-quick: Table=off, AllowedIPs 0.0.0.0/0 (маршруты ведёт nft/fwmark)
```

Свойства, которые дают «повседневность»:
- системный уровень: браузер/приложения без SOCKS и без sysproxy;
- зоны (com/org/net/io/dev/ai + youtube/telegram/google) — в туннель,
  RU/GLM — напрямую;
- DNS-цепочка с DoH лечит NXDOMAIN-перехват;
- нативный UDP (звонки/игры/QUIC);
- отдельный root-юнит `vpn-awg-split@<name>.service`, идемпотентные скрипты.

Известные ограничения эталона (учтены в выводах): захардкоженные IP
приложений требуют статических диапазонов (Telegram уже добавлен), браузерный
DoH обходит dnsmasq (лечится политиками Chrome/Firefox), при падении юнита
маршруты в мёртвый tun дают blackhole (нужен kill-switch).

## 2. Критерии сравнения

| Критерий | Почему важен |
|---|---|
| Системный интерфейс | tun/tproxy «из коробки» vs ручные маршруты |
| Механизм split | nft/dnsmasq, ACL клиента, routing внутри ядра |
| UDP/QUIC | звонки, игры, QUIC-приложения |
| DNS-зависимость | hardcoded-IP, DoH-утечки |
| Права и юниты | root, CAP_NET_ADMIN, systemd |
| Конфликты | второй tun, mark/table, default route |
| Stealth | насколько трафик похож на легитимный |
| Скорость (замер 2026-11-13) | потолок канала и одного потока |
| Стоимость | инженерные дни |

Измерения (`vpn speed`, OVH, один поток): XHTTP **106.3**, Reality **74.6**,
AWG **66.2**, Hy2 **41.4** Мбит/с; CDN — latency 2.39 с, bulk не отдался.
Один TCP-поток при RTT ~70 мс упирается в 7–20 Мбит/с (предел потока, не
шифра); `--flows 4` на AWG дал 35–42 Мбит/с агрегата.

## 3. Аналоги: разбор

### 3.1. Hysteria2 — ближайший аналог, дешевле всего

**Плюсы:** у клиента hysteria2 есть **штатный tun-режим** (сам поднимает
маршруты) и **ACL** (`direct(domain:…)` / `proxy(…)`) — зонный split можно
делать внутри клиента, без dnsmasq/nft. Нативный UDP. Уже есть obfs/hop.

**Минусы:** ACL по домену работает через sniffing (TCP — SNI/Host; для UDP и
hardcoded-IP нужны IP-правила); серверный потолок — один auth-пароль на всех
(per-user auth запланирован, ADR-009); уязвим к «зарежь UDP» и QUIC-SNI-
цензуре; скорость ниже Reality (41 vs 74) — настройки Brutal/BBR и потери.

**Что сделать:** root-юнит `vpn-hy2-split@<profile>` + конфиг с `tun` + `acl`
+ `vpn scheme hy2-split`; проверить на 2.13.0, что tun поднимает маршруты на
Ubuntu 22.04 и ACL корректно матчит домены из `domains.txt`.

**Оценка:** 0.5–1 день. **Вердикт:** лучший кандидат «основной после AWG».

### 3.2. Reality — лучший stealth, средняя цена

**Плюсы:** чужая TLS-маска (лучшая незаметность), скорость 74.6, один TCP
порт 443, уже работает на сервере.

**Минусы:** xray `tun` есть, но **auto-route нет** — маршруты, ip rule и DNS
поднимаем сами; split переиспользует AWG-конвейер (`dev xray0`, свои
mark/table); UDP идёт UDP-over-TCP (звонки/игры хуже); kill-switch обязателен.

**Что сделать:** tun inbound + генерация конфига из профиля, параметризация
`15_domain-split.sh` (`--dev/--mark/--table`), root-юнит
`vpn-xray-split@<profile>`, `vpn scheme reality [profile]`, kill-switch.

**Оценка:** 1–1.5 дня (из них 0.5 — параметризация split, она же пригодится
XHTTP). **Вердикт:** «незаметный основной» для браузинга/видео.

### 3.3. XHTTP — тот же xray, но клиенты ограничены

> **План реализации:** [SPEC-20261114-xhttp-split](team/specs/SPEC-20261114-xhttp-split.md)
> (WP-1..4, acceptance, риски). **Статус:** код принят, G4 заблокирован
> версией серверного Xray — [TEST-20261114-xhttp-split](team/reports/TEST-20261114-xhttp-split.md). **Реализовано 2026-11-14 (WP-1..3 кодером):**
> `vpn scheme xhttp-split` — tun `xray0` (xray 26.1.23+, отдельный бинарь
> `/usr/local/lib/vpn-xray-split`, socks-профили остаются на 25.1.1),
> mark 0x23000/table 23000/nft `xray_split`, kill-switch через ExecStopPost.
> OQ-1 закрыт: tun-инбаунд появился в v26.1.23 (PR #5464/#5509), схема
> проверена `xray -test` под root. Приёмка на ноутбуке — тестер.

**Плюсы:** самая высокая скорость (106), xray-core уже есть.

**Минусы:** транспорт понимают только Xray-клиенты (v2rayNG/FoXray;
sing-box/Hiddify — нет); сервер отдаёт его отдельным портом (у нас `mode=port`,
8443), т.е. это второй внешний порт, а не «замаскированный под 443»; системный
слой — ровно как у Reality.

**Оценка:** 1–1.5 дня (после Reality, переиспользуя split-параметризацию).
**Вердикт:** «скоростной» профиль для ноутбука, не универсальный основной.

### 3.4. CDN (VLESS+WS+TLS через Cloudflare) — только выживание

**Плюсы:** переживает блок IP сервера, HTTP-мимикрия, xray-core.

**Минусы:** latency 2.4–2.8 с, bulk-скорость нестабильна (OVH не отдался),
один фронт, зависимость от CF и его ToS, в белых списках CF нет; системный
слой — как у Reality, т.е. цена та же при худшем UX.

**Вердикт:** основным не делать; оставить sysproxy/выживание (текущая роль).

### 3.5. Сводка

| Протокол | Клиент | Tun «из коробки» | Split | UDP | Stealth | Скорость | Оценка |
|---|---|---|---|---|---|---|---|
| **AWG** | kernel + awg-quick | ✅ | dnsmasq→nft (готово) | ✅ | средне | 66 | — (эталон) |
| **Hysteria2** | hysteria 2.13 | ✅ tun | ✅ ACL | ✅ | средне+ | 41 | **0.5–1 д** |
| **Reality** | xray-core | ⚠️ tun без auto-route | nft/table или tproxy | ⚠️ UDP-over-TCP | высокий | 74.6 | 1–1.5 д |
| **XHTTP** | xray-core | ⚠️ как Reality | как Reality | ⚠️ | высокий | 106.3 | 1–1.5 д |
| **CDN** | xray-core | ⚠️ как Reality | как Reality | ⚠️ | высокий | — (2.4 с) | не делать |

## 4. Общие требования к любой split-схеме

1. **Одна основная схема за раз.** Два tun одновременно = конфликт default
   route/mark/table; нужен явный взаимоисключающий выбор (`vpn scheme …`).
2. **Kill-switch.** Падение юнита не должно оставлять маршруты в мёртвый tun:
   таймер снимает правила и откатывает трафик (клиентский аналог
   `gateway healthcheck`).
3. **Разведение меток/таблиц**: AWG — `0x21000`/21000; новым схемам —
   0x22000/22000 (Hy2/Reality), 0x23000/23000 (XHTTP) и т.д.
4. **DNS**: либо общий dnsmasq+DoH (как у AWG), либо DNS внутри ядра
   (xray/hysteria) — но без утечек через браузерный DoH (политики Chrome/Firefox).
5. **Статические диапазоны** для приложений с hardcoded-IP (Telegram и др.) —
   независимо от механизма split.
6. **Серийные пробы** при приёмке (И26): один SNI — один инбаунд.

## 5. Рекомендованный порядок

| Шаг | Что | Зачем | Оценка |
|---|---|---|---|
| 1 | Параметризовать `15_domain-split.sh`: `--dev/--mark/--table` | одна механика для AWG/Reality/XHTTP | 0.5 д |
| 2 | **Hy2-split** (`tun` + `acl`) | самый дешёвый новый «основной» | 0.5–1 д |
| 3 | **Reality-split** (`tun xray0` + общий split + kill-switch) | незаметный основной для браузинга | 1 д |
| 4 | **XHTTP-split** ([SPEC](team/specs/SPEC-20261114-xhttp-split.md)) — **реализовано 2026-11-14** | скоростной вариант для xray-клиентов | сделано (WP-1..3) |
| 5 | CDN | не делать; оставить выживание | — |

Критерии приёмки шага 2/3 (одинаковые): youtube/telegram через туннель, RU
напрямую, DNS/IPv6 без утечек, падение юнита → откат ≤ 1 цикла таймера,
`vpn speed` показывает ≥60 Мбит/с (OVH), `vpn reset` возвращает чистый старт.

## 6. Докеризация: почему это не решение

Короткий вывод из отдельного разбора (2026-11-13): Docker полезен для
упаковки/версий/E2E-тестов, но **не решает** задачи split-схемы:

| Проблема | Docker |
|---|---|
| Маршруты, ip rule, nft/mark | остаются на хосте (host-network) или требуют tproxy на IP контейнера |
| DNS-перехват, DoH-утечки | host-level |
| Kill-switch/blackhole | host-таймер, не `Restart=always` |
| Два tun | конфликт host-уровня |
| UDP/QUIC | путь не меняется; bridge-NAT добавляет MTU/оверхед |
| Права на tun | `/dev/net/tun` + CAP_NET_ADMIN; `docker` group ≈ root |

Правильное применение Docker — `tests/e2e/` (сервер↔клиент в CI, ловля
schema-регрессов вроде `obfs.salamander.password`); для изоляции клиентских
юнитов достаточно systemd-сэндбокса
(`CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`, `PrivateTmp`).

## 7. Открытые вопросы (для SPEC при старте шага)

- OQ-1: Hy2-split — ACL внутри клиента или общий nft-split (единообразие с AWG)?
- OQ-2: Reality-split — tun + nft-split (проще) или tproxy + domain-routing
  внутри xray (убирает DNS-зависимость, лечит hardcoded-IP)?
- OQ-3: kill-switch — общий клиентский таймер для всех схем или per-unit?
- OQ-4: нумерация mark/table — фиксированные константы в `vpnm` или
  динамический выбор свободных?
- OQ-5: как выбирается «основная» схема при старте — `vpn scheme` вручную или
  автоподбор по `vpn speed`/probe (пересечение с GR-21)?
