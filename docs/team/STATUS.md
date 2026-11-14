# STATUS — живое состояние работ

> Обновляет оркестратор после каждого гейта. Единый источник правды о текущем цикле.
> Шаблон: [templates/STATUS.md](templates/STATUS.md).

## Активный цикл (параллельный #2): CDN-transport — VLESS за Cloudflare (фаза 3 roadmap)
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
  остальное напрямую; на стороне провайдера владельца youtube-SNI DPI-иммунен к zapret-стратегиям.; **владелец-шаги
  (перенос зоны в CF, чеклист SPEC §7.1) запускаются параллельно с кодом**
- **Владелец гейта:** architect → orchestrator
- **Пересечение с AWG-циклом:** `src/main.py` — только добавляющие команды (WP-3);
  `src/amneziawg/*` не трогаются. При merge-конфликте — сериализация WP-3.

### Work packages (CDN)
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 Рендер CDN-инблэнда (paths+config) | vds-coder | ⏳ pending | — | — |
| WP-2 src/xray/cdn.py (install/remove/clients) | vds-coder | ⏳ pending (после WP-1) | — | — |
| WP-3 CLI+status+links | vds-coder | ⏳ pending (после WP-2) | — | — |
| Владелец §7.1 (CF-панель, шаги 1–8) | владелец | ⏳ параллельно | — | шаг 2 (grey на direct-записях) — блокер инварианта |
| Приёмка [VDS] + Reality-gate | оркестратор + тестер (G4) | ⏳ pending | — | — |

### Гейты (CDN)
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-10 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-10 | vds-analyst |
| G2 Spec | ✅ APPROVED | 2026-11-10 | vds-architect |
| G3 Build | ⏳ | — | vds-coder (WP-1..3 сериализация) |
| G4 Verify | ⏳ | — | vds-tester (§7.2 + Reality-gate блокер) |
| G5 Docs | ⏳ | — | vds-docs + **аналитик: правка FR-4 REQ (порт 2053, SPEC §4.3)** |
| G6 Close | ⏳ | — | оркестратор |

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
- **Этап:** ✅ G6 Close — [ACCEPT-20261109-domain-xhttp-acme](reports/ACCEPT-20261109-domain-xhttp-acme.md) PASS: LE на Hysteria2 (89 дн., автопродление), XHTTP e2e через домен:8443 (mode=port), Reality-домен; breaking-находка (старые hysteria2-ссылки требуют перевыпуска после LE) задокументирована; P13 закрыт; 226 passed
- **Владелец гейта:** orchestrator / владелец

## Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 ACME-выдача (certbot) | vds-coder | ✅ done | отчёт в сессии (157 passed) | — |
| WP-2 Hysteria2 + LE | vds-coder | ✅ done | отчёт в сессии (180 passed) | — |
| WP-3 XHTTP | vds-coder | ✅ done (+дельта path=/xhttp) | отчёт в сессии (213 passed) | fallback → --mode port (ADR-003 поправка) |
| WP-4 Reality-домен | vds-coder | ✅ done | отчёт в сессии (223 passed) | — |
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
  24 пункта (GR-01…GR-24) с фактами, действиями и AC.
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
  tun/unit/rules/kill-switch PASS; vpnm 392 теста. Серверный Xray обновлён
  до 26.1.23 (ADR-010); Reality/XHTTP/CDN/Hy2 проверены. Ноутбук: youtube 204
  через split, example.com 200, ya.ru напрямую, `vpn monitor` ok,
  kill-switch и `vpn reset` — PASS. Схема обобщена: `vpn scheme xray-split
  [profile]` работает и для Reality (`phone`), и для XHTTP (`xhttp-web`);
  `xhttp-split` — алиас. Быстрый вход: `vpn start` = Reality-split
  (по умолчанию), `vpn start xhttp`, `vpn start awg`. Исправлены: петля
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
