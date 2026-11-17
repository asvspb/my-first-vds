# STATUS — живое состояние работ

> Обновляет оркестратор после каждого гейта. Единый источник правды о текущем цикле.
> Шаблон: [templates/STATUS.md](templates/STATUS.md).
> Счётчики тестов в исторических записях — моментальные снимки (OQ-9):
> актуальный baseline — `pytest -q`, число в живых доках не хранится.

## Активный цикл: doc-sync (SPEC-20261116-doc-sync) — WP-3 baseline
- **SPEC:** [SPEC-20261116-doc-sync](specs/SPEC-20261116-doc-sync.md) (G2, WP-1/2 done:
  `tools/docsync.py` + `docs/doc-sync.json` + тесты, коммит `5ff2bef`)
- **WP-3 (в работе, vds-docs):** синхронизация живых доков по §11 — команды
  probe-watch/ru-cidr/CDN-remove, юниты health/probe/relay/amneziawg-nat, ADR-011,
  10 ролей, версия, banned-счётчики, source_lag.
- **Дальше:** WP-4 (хуки + процесс), WP-5 (warn → block).
- **Doc audit:** in progress (WP-3 = G5 этого цикла).

## Предложение на G2: survivability (SPEC-20261116-survivability)
- **SPEC:** [SPEC-20261116-survivability](specs/SPEC-20261116-survivability.md) —
  draft, ждёт `vds-architect` + техлида (G2). Не реализация.
- **Суть:** packet-level стадии 1/2/3 (freeze → probing → RST-инъекция /
  silent ClientHello drop / UDP response drop / L3-бан), новые правила
  **T-18…T-23** + поле `stage`, stage-aware ранбук, портфель мер S-01…S-15
  (P0: ранбук/keepalive/`surface audit`/XMUX; P1: failover/canary/пул фронтов;
  P2: SPA по **ADR-013**, ротация IP, anti-fingerprint).
- **Технические поправки:** `TcpInRsts` в nstat нет (есть `TcpEstabResets`/
  `TcpExtEmbryonicRsts`/`TcpOutRsts`); `syn_valid` не видит ClientHello;
  Δt<15 мс — сильная улика, абсолютным делает RTT-floor + TTL/TSopt/seq.
- **Ревью:** [ARCH-20261116-tspu-blindspots](reports/ARCH-20261116-tspu-blindspots.md) —
  8 слепых пятен глазами инженера ТСПУ (вход для intake; P0-кандидаты:
  Self-DoS в probe-watch, демаскировка 8443/2053, конфликт SNI/LE).
- **Дальше:** G2 → WP-S1/S2 (детект+stage) → WP-S3 (surface audit) →
  WP-S4 (canary); SPA (WP-S5) — только после приёмки probe-response v1.

## G2 APPROVED: vpn guard (SPEC-20261116-vpn-guard)
- **SPEC:** [SPEC-20261116-vpn-guard](specs/SPEC-20261116-vpn-guard.md) —
  **G2 APPROVED 2026-11-16** (`vds-architect` + техлид). Пять правок ревью
  внесены; открытых вопросов нет (OQ-1…OQ-20 закрыты). Не реализация.
- **Суть:** клиентский **real-time** анализатор логов (`journalctl --user -f`)
  — конвейер `tail → parse → normalize → window → rules → correlate →
  finding`; правила **G-01…G-12** (no-handshake, reset storm, post-handshake
  drop, UDP blackhole, auth/config, DNS, local-net, TLS, endpoint silent,
  unit flap, degraded, self-health), `stage_hint` ↔ T-18…T-23, merge с
  серверным `probe-watch --json` через файл (без сети в демоне).
- **Границы:** read-only v1 (никаких restart/repair/switch), user-space,
  без root/сети/LLM; findings 14 дней/20 МБ, только счётчики и хэши
  шаблонов; юнит `vpn-guard.service` (не `vpnm-*` — иначе `vpn autostart off`
  отключит guard).
- **Правки G2:** (1) `probe-watch watch` без `--record` закреплён как
  read-only + серверный regression-тест, sync 60 мин, свежесть 65 мин;
  (2) AmneziaWG (`awg-quick@*`/`vpn-awg-split@*`, `dnsmasq`, sysfs-счётчики)
  как полноценный канал — `idle` при живом AWG запрещён, ветка G-04
  `awg_tx_no_rx`; (3) sandbox-профили `hardened`/`compat` + проверка
  `226/NAMESPACE` и D-Bus; (4) пост-сканер не трогает `*_hash`/`*_sha256`;
  (5) G-01 через `app_banner_ok`/`dial_*`, иначе `insufficient_data`.
- **Реализация:** `ubuntuInstaller/scripts/vpn-manager` (`vpnm/guard/`);
  спека здесь, потому что процесс/гейты — в `vds`. **ADR-014** утверждён,
  создаётся в WP-G0.
- **Доклад для G2-аудитории:**
  [BRIEF-20261116-vpn-guard](reports/BRIEF-20261116-vpn-guard.md) — 13 слайдов,
  тезисы, риски и 6 вопросов к архитектору/техлиду. Промпт напарника
  (архитектор+техлид+ревьюер): [PROMPT-20261116-vpn-guard-arch-lead](reports/PROMPT-20261116-vpn-guard-arch-lead.md).
- **Дальше:** WP-G0…WP-G5 — ✅ PASS 2026-11-16 (G3/G4/G5 approve
  архитектора); **WP-G6** — 7 дней поля, бенч AC-5, AC-17, `kill -9`,
  `selftest` из wheel. AC-1…AC-17 — §14.2.
- **Статус цикла (2026-11-16):** ✅ **G0–G5 PASS**; приёмка —
  [ACCEPT-20261116-vpn-guard](reports/ACCEPT-20261116-vpn-guard.md).
  Коммиты: `ubuntuInstaller` — `4bc145e` (G0), `6ead3cc` (G2), `757e2f2` (G1),
  `a7e7a8f` (G2-фиксы), `b0297d8` (G3), `c84560d` (G4), `b10553a` (G5);
  `my-first-vds` — ADR-014 `f502985`, AC-16 `69225a7`, DECISIONS
  `b42d4cc`/`20b52ff`. Осталось: **WP-G6** — 7 дней `vpn-guard.service`
  на живом ноутбуке (AWG/Reality/XHTTP/Hy2), 24 ч бенч AC-5, AC-17 на чистом
  десктопе, реальный `kill -9`, `selftest` из установленного wheel.
- **Живой старт WP-G6 (2026-11-16):** pipx-wheel + `selftest` OK; unit
  `hardened` (без fallback), `state=armed`, iface `laptop`; sync с asv2 —
  `fresh=true`. AC-12/AC-15/AC-17 — PASS; 7-дневное наблюдение идёт.
  Отчёт: [TEST-20261116-vpn-guard-live-start](reports/TEST-20261116-vpn-guard-live-start.md).
- **Guard live-fix 2026-11-17 (`ubuntuInstaller 78ce00c`):** файл-подобный
  `stderr` (TextIOWrapper) и гонка `cursor.json.tmp` (два reader-потока) —
  исправлены; `journal:user/system` = ok, `cursor_write_failed` ушёл,
  `verdict` обновляется после `sync`. APPROVE 2026-11-17; HF-SSH `14999ec`
  тоже APPROVE. T0-снимок:
  [TEST-20261117-vpn-guard-checkpoint-t0](reports/TEST-20261117-vpn-guard-checkpoint-t0.md);
  следующая контрольная точка — T+24–48 ч.
- **Ревью (эволюция v1.0 → v2.0):** [ARCH-20261116-vpn-guard-evolution](reports/ARCH-20261116-vpn-guard-evolution.md) —
  стратегическая оценка + предложение v1.1 (ss/netlink, packet-size ratio,
  ленивый sync), v1.2 (`--client-report`) и v2.0 (Smart Failover, только через ADR).

## Инфраструктура (live-ops, 2026-11-14..16)
- **asv2 = основной AWG-exit** (213.108.23.119): deploy 2026-11-15 — UFW harden
  gateway-профиль (ADR-011), SSH → 49222, /48 IPv6, LE `asv2.asvpersonal.ru`
  (Hy2 secure, без insecure=1). **asv1 удалён 2026-11-16** — настройка
  пропущена, единственный боевой exit — asv2.
- **asv2: состав транспортов (2026-11-16):** оставить Reality 443/tcp +
  Hysteria2 443/udp + AmneziaWG 51825/udp; XHTTP :8443 и CDN :2053 не
  поднимать до GR-07 Self-Steal — иначе Cross_Port_Cert_Conflict на
  единственном боевом узле.
- **asv2: Wave 0 + W1-1 выкачены 2026-11-16** (`4fb1956`): HF-1 verified
  sessions, HF-2 (код; xhttp/cdn на asv2 нет), W1-1 probers4
  `{443,8443,2053}` + extra-счётчики. Юниты пере-рендерены с venv;
  `systemctl --failed` = 0, все vds-таймеры active, `logs sample` пишет
  телеметрию, `auto_lockdown=false`. Найден и закрыт EROFS-lock
  (`vds-logs-sample`: `ReadWritePaths=/var/lib/vds /var/run`).
  Отчёт: [DEPLOY-20261116-asv2-wave0-w1](reports/DEPLOY-20261116-asv2-wave0-w1.md).
  **HF-3 закрыт** (`fb3e8fe`, docs `83dc1cc`): `resolve_python()` =
  venv → `sys.executable` → PATH; проверено на asv2 install с чистым
  системным PATH — юниты рендерятся с venv, `systemctl --failed` = 0.
- **RU-relay: РАЗВЁРНУТ 2026-11-17** — LandVPS `vm354051`
  (`185.80.91.135`, AS216334, Москва), **Ubuntu 24.04.4** (переустановка
  шаблона 2026-11-17, второй прогон — без ошибок), 512 МБ + 1 ГБ swap;
  `vds-relay-{awg,exit,nat,policy,cidr}` + `vds-xray` active, UFW профиль
  relay, RU-CIDR 8664 агрегата. Живые проверки: клиент через релей →
  egress `213.108.23.119` (asv2), RU-сайты direct (ya.ru 0.13 с), фолбэк
  Reality SNI=ya.ru с ноутбука OK. Найдены и закрыты 4 дефекта раскатки
  (iptables на cloud-образе, идемпотентные порты, потеря public_key,
  потеря policy-маршрута при рестарте ноги → `PartOf=`). Отчёт:
  [DEPLOY-20261117-ru-relay-landvps](reports/DEPLOY-20261117-ru-relay-landvps.md).
  Открыто: DNS `relay.asvpersonal.ru` (A, DNS-only) — владелец; смена
  паролей панели/root; TECHDEBT P20 (remove-client). ОС закрыта: 24.04.4.
  Reboot-тест PASS (дважды — 22.04 и 24.04): 6/6 юнитов, policy-маршрут и
  NAT восстанавливаются сами. Клиенты перевыпущены (`~/.awg/relay.conf`,
  профиль `relay-reality`).
  **Клиентский старт 2026-11-17:** `vpn start relay` (ubuntuInstaller
  `bef29b1`+) — взаимоисключение с прямым контуром (`vpn start` гасит
  релей, `vpn start relay` гасит vpnm-*/AWG-split/xsplit), `vpn down` не
  трогает `vpn-guard.service`; режим в `vpnm.mode/1` (`mode.json`), guard
  читает его как подсказку, `activity.json` остаётся probe-маркером.
  Живой preflight на ноутбуке: без `sudo -n` `vpn start relay` → exit 1,
  прямой контур (`asv2-reality` + `@laptop`) не изменён.
  **Живой старт PASS 2026-11-17:** первый запуск падал на
  `vpn-awg-split@relay` — `awg-quick: Name or service not known:
  '354051.landvps.online:443'`. Причина: `vds relay add-client` берёт
  endpoint из `state.domain`, а это внутреннее имя LandVPS, не публикуемое
  в публичном DNS (`relay.asvpersonal.ru` ещё не создан). Ключи целы
  (пир `9tmMZ…` = серверный peer), сервер в порядке (`:443/udp`, UFW 443,
  pubkey совпадает). Фикс: `Endpoint = 185.80.91.135:443` в
  `~/.awg/relay.conf` (бэкап `.bak-pre-endpoint`) + серверные экспорты
  `laptop.conf` / `smoke-asv2.conf` (там же бэкапы). После фикса: юнит
  active, handshake есть, egress `213.108.23.119` (asv2), RU-сайты direct
  (`ya.ru 302 / 0.19 s`), `mode.json` = `relay`, `vpn status` печатает
  `RELAY (awg relay → 185.80.91.135)`. Постоянное решение — DNS-запись
  `relay.asvpersonal.ru` (владелец) либо `--endpoint` в `add-client`
  (TECHDEBT P22). `vpn status relay` — не подкоманда: режим показывает
  `vpn status`.
  **Ранбук обновлён 2026-11-17:** тариф LandVPS RU-1 (KVM, 1 ГБ/20 ГБ,
  1 месяц до года, swap при 0.75 ГБ), 5-мин gate §0.3 через **asv2
  (213.108.23.119:51825)**, anti-DDoS UDP-проверка; asv1-IP удалён из команд.
  **Gate PASS 2026-11-17:** LandVPS `vm354051` (185.80.91.135, AS216334,
  Москва) — AWG UDP до asv2 работает (egress 213.108.23.119, Google 200/0.34 s),
  anti-DDoS UDP не режет. Отчёт:
  [TEST-20261117-ru-relay-gate](reports/TEST-20261117-ru-relay-gate.md).
  Остаток: решение OS 24.04 vs 22.04, DNS `relay.asvpersonal.ru` (A→IP,
  DNS-only), RU_SNI, затем `vds relay init --exit 213.108.23.119`.
- **probe-watch v3** (SPEC-20261116-probe-response): threat-level quiet/elevated/high,
  ru-cidr install, lock-443 TTL/undo/hop-guard, auto-lockdown off (default).
- **И44:** AWG/relay генераторы клиентов без дефолтного `PersistentKeepalive`
  (`--keepalive N` — явный opt-in, для NAT-дырки 113).

## Циклы 2026-11-14..16 (завершены)
- **xhttp-split — G4 PASS 2026-11-14:** [SPEC-20261114-xhttp-split](specs/SPEC-20261114-xhttp-split.md),
  [TEST-20261114-xhttp-split](reports/TEST-20261114-xhttp-split.md); Xray 26.1.23
  (ADR-010); схема обобщена на Reality (`vpn start reality/xhttp`, по умолчанию AWG).
- **RU-relay WP-1..5 — код принят 2026-11-15:** [ADR-007](../adr/ADR-007-ru-relay.md),
  [DEPLOY-RU-RELAY](../DEPLOY-RU-RELAY.md); юниты vds-relay-{exit,nat,policy,cidr}.
- **UFW hardening — ADR-011 + SPEC-20261116:** `vds system ufw harden/ssh-port/lock-443`;
  asv2 развёрнут по профилю gateway (см. выше).
- **probe-response — probe-watch v3:** [SPEC-20261116-probe-response](specs/SPEC-20261116-probe-response.md)
  (коммит `c31462e`): threat-level, RU-CIDR, lock-443 c TTL/undo/hop-guard.
- **И44 keepalive:** генераторы без метронома по умолчанию (коммит `8979673`).

## Архив: CDN-transport — VLESS за Cloudflare — ЗАВЕРШЁН 2026-11-10
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-10 (пятый канал: egress через
  CF, чтобы цензор видел IP Cloudflare)
- **REQ:** [REQ-20261110-cdn-transport](requirements/REQ-20261110-cdn-transport.md) (G1 READY)
- **SPEC:** [SPEC-20261110-cdn-transport](specs/SPEC-20261110-cdn-transport.md)
  + [ADR-006](../adr/ADR-006-cdn-cloudflare-transport.md) (OQ-1..5: proxied-запись
  `cdn.eu-cloud-xip.com`, апекс/`103-45-247-172` — grey; транспорт WS v1, XHTTP
  packet-up — future; origin-порт TCP 2053 (CF HTTPS-порты: 443/2053/2083/2087/2096/8443),
  edge-порт = origin-порт — девиация от FR-4; TLS Full (strict) + отдельный LE-cert
  cdn-домена; CF — ручные шаги владельца, CF-API — future)
- **Этап:** ✅ G6 Close — сервер установлен на asv1 (PPA, UDP 51825, юнит с P14-фиксом),
  клиент laptop + e2e (handshake + youtube 204/0.28s через AWG-туннель с ноутбука),
  NAT/forwarding (P15) персистентны. Финальная верификация:
  [TEST-20261110-amneziawg-cdn](reports/TEST-20261110-amneziawg-cdn.md) (AWG PASS, CDN-блокер B-1 найден и закрыт).
  Эксплуатация: split-конфиг ноутбука (`~/awg0-split.conf`, awg-quick) — youtube/telegram через AWG,
  остальное напрямую; на стороне провайдера владельца youtube-SNI DPI-иммунен к zapret-стратегиям.

### Открытые пункты цикла (CDN)
0. **ADR-007 RU-relay (proposed, ждёт владельца):** входной AWG-релей на RU VDS — покрытие mobile-whitelist вектора + дешёвая ротация exit-ноги по v6; [ADR-007](../adr/ADR-007-ru-relay.md); шаги внедрения внутри.
0. **Новый цикл (REQ готов, ждёт владельца): transport-hardening —** Salamander для Hysteria2 + ротация параметров/порта AWG; REQ: [REQ-20261112-transport-hardening](requirements/REQ-20261112-transport-hardening.md); UDP-over-TCP отложен.
1. **Девиация FR-4 (SPEC §4.3):** share-link CDN использует порт 2053, не 443 —
   факт CF «edge-порт = origin-порт», 443 занят Reality. Аналитик правит REQ на G5.
2. **Reality-gate приёмки (блокер G4):** после переноса зоны в CF клиент `phone`
   (Reality, доменная ссылка) и `mob` (Hysteria2) обязаны работать e2e —
   апекс/`103-45-247-172` grey-cloud. Нарушение → откат toggle orange + G4 FAIL.
3. LE-продление cdn-домена через CF edge (E11) — проверка `certbot renew --dry-run`
   на приёмке; fallback — временный grey на время продления (чеклист §7.1-9).

## Цикл AmneziaWG transport (фаза 4 roadmap) — ЗАВЕРШЁН 2026-11-10
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-10 (четвёртый UDP-транспорт:
  серверный модуль `src/amneziawg/`, клиентская выдача .conf, guard-минор .zshrc)
- **REQ:** [REQ-20261110-amneziawg-transport](requirements/REQ-20261110-amneziawg-transport.md) (G1 READY)
- **SPEC:** [SPEC-20261110-amneziawg-transport](specs/SPEC-20261110-amneziawg-transport.md)
  + [ADR-005](../adr/ADR-005-amneziawg-transport-decisions.md) (OQ-1..6: UDP 51825;
  клиентский режим (b) — conf + AmneziaVPN; источник — PPA `ppa:amnezia/ppa`
  (amneziawg-tools + amneziawg-dkms, kernel-модуль), mirror-конвенция не применима —
  задокументировано; AWG 1.5-набор параметров; PSK по умолчанию)
- **Этап:** ✅ G6 Close — сервер установлен на asv1 (PPA, UDP 51825, юнит с P14-фиксом),
  клиент laptop + e2e (handshake + youtube 204/0.28s через AWG-туннель с ноутбука),
  NAT/forwarding (P15) персистентны. Финальная верификация:
  [TEST-20261110-amneziawg-cdn](reports/TEST-20261110-amneziawg-cdn.md) (AWG PASS, CDN-блокер B-1 найден и закрыт).
  Эксплуатация: split-конфиг ноутбука (`~/awg0-split.conf`, awg-quick) — youtube/telegram через AWG,
  остальное напрямую; на стороне провайдера владельца youtube-SNI DPI-иммунен к zapret-стратегиям.
- **Владелец гейта:** architect → orchestrator

### Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 Генератор+рендер обфускации | vds-coder | ✅ done (fbd23d7) | — | — |
| WP-2 Install (PPA/port/UFW/юнит) | vds-coder | ✅ done (177831b, +P15) | — | — |
| WP-3 Клиенты+store/links | vds-coder | ✅ done (c782a2a) | — | — |
| WP-4 Status+remove | vds-coder | ✅ done (da4d9ba) | — | — |
| WP-5 Guard .zshrc (awg*) | vds-coder | ✅ done (35608e0, +P14-паттерн-фикс amnezia0) | — | — |
| WP-6 Приёмка [VDS] + гейт импорта в AmneziaVPN (OQ-4) | оркестратор + тестер (G4) | ✅ PASS (установка на asv1 + e2e ноутбук; импорт .conf в AmneziaVPN подтверждён трафиком 316+ МБ) | — | — |

### Гейты
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-10 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-10 | vds-analyst |
| G2 Spec | ✅ APPROVED | 2026-11-10 | vds-architect |
| G3 Build | ⏳ | — | vds-coder (WP-1..4, сериализация; WP-5 параллельно) |
| G4 Verify | ⏳ | — | vds-tester |
| G5 Docs | ⏳ | — | vds-docs |
| G6 Close | ⏳ | — | оркестратор |

### Открытые пункты цикла
1. **Гейт OQ-4:** клиентский .conf (AWG 1.5-набор) должен импортироваться в
   AmneziaVPN владельца (WP-6); отказ → правка ADR-005 на 2.0-набор (S1–S4 ≥12,
   H-диапазоны), не «fix on the fly».
2. Mirror-конвенция (ADR-001/VDS_GITHUB_MIRROR) на AWG-путь не распространяется:
   источник — Launchpad PPA; при недоступности PPA с asv1 — E1-отказ + ручной
   перенос .deb, эскалация к архитектору.

## Архив: Domain / XHTTP / ACME (фазы 3 + частично 6) — ЗАВЕРШЁН 2026-11-09
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-09 (домен `103-45-247-172.eu-cloud-xip.com` → 103.45.247.172 проверен; три направления: XHTTP, ACME, домен для Reality)
- **REQ:** [REQ-20261109-domain-xhttp-acme](requirements/REQ-20261109-domain-xhttp-acme.md) (G1 READY)
- **SPEC:** [SPEC-20261109-domain-xhttp-acme](specs/SPEC-20261109-domain-xhttp-acme.md) + [ADR-003](../adr/ADR-003-xhttp-reality-coexistence.md) (OQ-1; уточнён фактом [VDS]: fallback не работает, основной режим `--mode port`) + [ADR-004](../adr/ADR-004-acme-http01-certbot.md) (OQ-2/OQ-4)
- **Этап:** ✅ G6 Close — [ACCEPT-20261109-domain-xhttp-acme](reports/ACCEPT-20261109-domain-xhttp-acme.md) PASS: LE на Hysteria2 (89 дн., автопродление), XHTTP e2e через домен:8443 (mode=port), Reality-домен; breaking-находка (старые hysteria2-ссылки требуют перевыпуска после LE) задокументирована; P13 закрыт; 226 passed <!-- docsync:ignore -->
- **Владелец гейта:** orchestrator / владелец

## Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 ACME-выдача (certbot) | vds-coder | ✅ done | отчёт в сессии (157 passed) | — | <!-- docsync:ignore -->
| WP-2 Hysteria2 + LE | vds-coder | ✅ done | отчёт в сессии (180 passed) | — | <!-- docsync:ignore -->
| WP-3 XHTTP | vds-coder | ✅ done (+дельта path=/xhttp) | отчёт в сессии (213 passed) | fallback → --mode port (ADR-003 поправка) | <!-- docsync:ignore -->
| WP-4 Reality-домен | vds-coder | ✅ done | отчёт в сессии (223 passed) | — | <!-- docsync:ignore -->
| WP-5 Приёмка [VDS] | оркестратор + тестер (G4) | ✅ PASS | [ACCEPT-20261109-domain-xhttp-acme](reports/ACCEPT-20261109-domain-xhttp-acme.md) | — |

## Гейты
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-09 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-09 | vds-analyst |
| G2 Spec | ✅ APPROVED | 2026-11-09 | vds-architect |
| G3 Build | ✅ | 2026-11-09 | vds-coder (WP-1..4 + follow-up D1–D3, P13) |
| G4 Verify | ✅ CONDITIONAL PASS (minor D1–D4, закрыты) | 2026-11-09 | vds-tester |
| G5 Docs | ✅ (ADR-003 поправка, ACCEPT-отчёт) | 2026-11-09 | оркестратор |
| G6 Close | ✅ | 2026-11-09 | ACCEPT PASS |

## Открытые пункты
1. **Breaking-заметка для владельца:** после `hysteria2 apply-cert` все старые
   hysteria2-ссылки (SNI=IP, insecure=1) НЕ работают (сервер отклоняет SNI≠домен) —
   перевыпустить (новые ссылки рендерятся с доменом, без insecure). Поправить
   REQ §4 и README на G5-docs follow-up.
2. OQ-5 (из REQ): пере-выдача ссылок существующим клиентам — вручную оператором,
   не автоматизирована (вне скоупа).
3. DNS-01 как запасной вариант ACME — только при появлении API-токена DNS-провайдера (будущий ADR).
4. Из прошлого цикла: TECHDEBT P4–P6; клиентская запись xhttp в state показывает
   port 443 при фактическом 8443 (косметика).

## Трассируемость
| IDEA | REQ | SPEC | Коммиты | TEST | DOC |
|---|---|---|---|---|---|
| чат 2026-11-09 | REQ-20261109-domain-xhttp-acme | SPEC-20261109-domain-xhttp-acme (+ADR-003/004) | aa01d98 (WP-1..4) + P13 | G4 CONDITIONAL PASS + ACCEPT PASS | ACCEPT-20261109-domain-xhttp-acme |

## Бэклог идей (вход для intake)

- **Точки роста схем/протоколов:** [docs/GROWTH-POINTS.md](../GROWTH-POINTS.md) —
  25 пунктов (GR-01…GR-25) с фактами, действиями и AC.
- **GR-25 (XHTTP padding/xmux) — живая приёмка 2026-11-16:** сервер
  `7af391b`, клиент `1807945`, миграция + CDN-preserve `9e43590`,
  `--skip-domain-check` `43d1ee6`. На asv1 (до его удаления) миграция
  применена (path/CDN/Reality-хэши не изменились, `xray -test` OK),
  **T-XM6 PASS**: 2–3 сокета, ротация в окне 3–5 мин, 451 МБ без разрыва.
  Отчёт: [TEST-20261116-gr25-asv1-txm6](reports/TEST-20261116-gr25-asv1-txm6.md).
  **asv1 удалён 2026-11-16** — DNS/ACME-остаток по нему снят; код GR-25
  готов для следующего XHTTP-узла (сервер + клиент).
  Долг: SHA256 `.dgst` в `vpnm/bins.py`.
- **asv1 SSH lockout — закрыт декомиссией 2026-11-16:** узел удалён
  владельцем, восстановление не требуется. Детали:
  [INCIDENT-20261116-asv1-ssh-lockout](reports/INCIDENT-20261116-asv1-ssh-lockout.md).
- **Цикл CDN-usability — G4 CLOSED 2026-11-13:**
  [SPEC-20261113-cdn-usability](specs/SPEC-20261113-cdn-usability.md),
  отчёт [TEST-20261113-cdn-mux](reports/TEST-20261113-cdn-mux.md) §9.
  Принято: TTFB p50/p95 в `vpn speed` (WP-2), CDN-baseline с контролем и
  smoke (WP-3). Откачено: mux через CF (1/5 против 5/5).
  **Проверено (2026-11-13):** XHTTP через Cloudflare **не работает** —
  [TEST-20261113-cdn-xhttp-cf](reports/TEST-20261113-cdn-xhttp-cf.md):
  CF проксирует 2083, но XHTTP (auto/packet-up/stream-up, h1/h2) — 0/2,
  таймауты; при этом XHTTP **напрямую** даёт TTFB 0.40 с (WS-CF — 2.45–2.88 с).
  Вывод: причина — маршрут CF, а не транспорт.
  **CF-эксперименты закрыты 2026-11-13 (решение владельца, результаты
  недостаточны):** mux — 1/5 против 5/5; XHTTP через CF — 0/2 (CF не
  пропускает XHTTP); [cloudflared tunnel](reports/TEST-20261113-cf-tunnel.md)
  — TTFB 2.97–4.64 с против 2.45–2.88 с, bulk 0 (HKG→AMS→NL). Инфраструктура
  откачена (туннель disabled и удалён, конфиг восстановлен).
  **CDN остаётся каналом выживания.** Возвращаться к CF-оптимизации не
  планируем; альтернатива — CDN с PoP в РФ или прямые XHTTP/Reality.
- **Цикл fresh-install-v3 — G4 code accepted 2026-11-14:**
  [SPEC-20261114-fresh-install-v3](specs/SPEC-20261114-fresh-install-v3.md),
  отчёт [TEST-20261114-fresh-install-v3](reports/TEST-20261114-fresh-install-v3.md).
  `vds gateway init` (dry-run/--apply): reality, hysteria2, acme, xhttp, cdn,
  obfs, hop, awg, healthcheck + `use-domain`; `11_vds-deploy.sh` → init
  (env `VDS_PROTOCOLS`). Закрыт GR-16 (hub). Осталось: приёмка на чистой VM
  (AC-1/3/4) — владелец.
- **xray-split (Reality/XHTTP) — G4 PASS (2026-11-14):**
  [SPEC-20261114-xhttp-split](specs/SPEC-20261114-xhttp-split.md),
  [TEST-20261114-xhttp-split](reports/TEST-20261114-xhttp-split.md).
  tun/unit/rules/kill-switch PASS; vpnm 392 теста. Серверный Xray обновлён <!-- docsync:ignore -->
  до 26.1.23 (ADR-010); Reality/XHTTP/CDN/Hy2 проверены. Ноутбук: youtube 204
  через split, example.com 200, ya.ru напрямую, `vpn monitor` ok,
  kill-switch и `vpn reset` — PASS. Схема обобщена: `vpn scheme xray-split
  [profile]` работает и для Reality (`phone`), и для XHTTP (`xhttp-web`);
  `xhttp-split` — алиас. Быстрый вход: `vpn start reality`,
  `vpn start xhttp` (`vpn start` по умолчанию — AWG). Исправлены: петля
  xray→свой tun (sockopt.mark),
  порядок DoH + ожидание готовности, один dnsmasq-конфиг,
  mkdir /etc/vpn-manager.
- **OS baseline (2026-11-14):** [SERVER-BASELINE](../SERVER-BASELINE.md) —
  инвентарь настроек ОС/сервера (авто vs вручную), UFW-матрица портов,
  чеклист восстановления агентом, дрейф asv1 (UFW off, swap 0, SSH-пароли,
  Docker нет).
- **Roadmap v2 (2026-11-13, ревизия архитектора):**
  [CENSORSHIP-ROADMAP](../CENSORSHIP-ROADMAP.md) — фазы 0–9 переведены в
  «статус + остаток», остаток разложен на волны **W1–W6**; W1 (hook+healthcheck)
  и W2 (per-user auth, [ADR-009](../adr/ADR-009-hysteria2-per-client-auth.md) —
  **proposed**) готовы к intake. Дефекты/долг — [TECHDEBT.md](../../TECHDEBT.md).

## Архитектурные решения (вне циклов)

### ZeroTier → архив/опционально (2026-11-10, решение владельца)
- **Пользовательский VPN-канал полностью заменён** gateway-стеком (Reality/XHTTP/
  Hysteria2 + AWG в работе): ZeroTier не нужен ни одному клиентскому сценарию
- Модуль `src/zerotier/` **сохраняется как опциональная утилита** (приватная
  management-сеть, ZTNET-панель); из основного пути деплоя ([DEPLOY.md](../DEPLOY.md),
  11_vds-deploy.sh) не входит и не будет входить
- Будущие баги ZT-стека (watchdog/reconcile/ZTNET) чинить по остаточному принципу,
  не поднимать их приоритет — приоритет gateway-стека выше
- Формальный признак в guard-скриптах (_check_vpn_active): ZT/WG остаются
  валидными признаками «VPN активен», но не обязательными

## Завершённые циклы

### Gateway MVP (фазы 0–2) — ЗАВЕРШЁН 2026-11-09
- **REQ:** [REQ-20261107-gateway-mvp](requirements/REQ-20261107-gateway-mvp.md) · **SPEC:** [SPEC-20261107-gateway-mvp](specs/SPEC-20261107-gateway-mvp.md) + [ADR-001](../adr/ADR-001-xray-install-mechanism.md) + [ADR-002](../adr/ADR-002-gateway-paths-units-state.md)
- Гейты G0–G6 все ✅; G6 Close — [VDS]-приёмка PASS 2026-11-09 ([ACCEPT-20261109](reports/ACCEPT-20261109-vds-asv1.md)): оба протокола на asv1, e2e подтверждён; закрыты P7–P12 + VDS_GITHUB_MIRROR (коммиты c1e7886..e5ececb).
- WP: WP-1 P1–P3+tests, WP-2 core, WP-3 gateway store+CLI, WP-4 Xray Reality, WP-5 Hysteria2 — все ✅ done.
- Наследованный бэклог: TECHDEBT P4–P6; баг install.sh:74 (`cp -r` на себя, ORCH-20261109 §4); pytest вне requirements (нужен requirements-dev.txt); глобальный фильтр маскирования логов → фаза 6; `HYSTERIA2_BIN_PATH` → `gateway/paths.py` при следующем ADR.
