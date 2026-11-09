# STATUS — живое состояние работ

> Обновляет оркестратор после каждого гейта. Единый источник правды о текущем цикле.
> Шаблон: [templates/STATUS.md](templates/STATUS.md).

## Активный цикл: Domain / XHTTP / ACME (фазы 3 + частично 6) — ЗАВЕРШЁН 2026-11-09
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

## Завершённые циклы

### Gateway MVP (фазы 0–2) — ЗАВЕРШЁН 2026-11-09
- **REQ:** [REQ-20261107-gateway-mvp](requirements/REQ-20261107-gateway-mvp.md) · **SPEC:** [SPEC-20261107-gateway-mvp](specs/SPEC-20261107-gateway-mvp.md) + [ADR-001](../adr/ADR-001-xray-install-mechanism.md) + [ADR-002](../adr/ADR-002-gateway-paths-units-state.md)
- Гейты G0–G6 все ✅; G6 Close — [VDS]-приёмка PASS 2026-11-09 ([ACCEPT-20261109](reports/ACCEPT-20261109-vds-asv1.md)): оба протокола на asv1, e2e подтверждён; закрыты P7–P12 + VDS_GITHUB_MIRROR (коммиты c1e7886..e5ececb).
- WP: WP-1 P1–P3+tests, WP-2 core, WP-3 gateway store+CLI, WP-4 Xray Reality, WP-5 Hysteria2 — все ✅ done.
- Наследованный бэклог: TECHDEBT P4–P6; баг install.sh:74 (`cp -r` на себя, ORCH-20261109 §4); pytest вне requirements (нужен requirements-dev.txt); глобальный фильтр маскирования логов → фаза 6; `HYSTERIA2_BIN_PATH` → `gateway/paths.py` при следующем ADR.
