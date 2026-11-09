# STATUS — живое состояние работ

> Обновляет оркестратор после каждого гейта. Единый источник правды о текущем цикле.
> Шаблон: [templates/STATUS.md](templates/STATUS.md).

## Активный цикл: Gateway MVP (фазы 0–2)
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-07 (MVP 0–2, без домена)
- **REQ:** [REQ-20261107-gateway-mvp](requirements/REQ-20261107-gateway-mvp.md)
- **SPEC:** [SPEC-20261107-gateway-mvp](specs/SPEC-20261107-gateway-mvp.md) + [ADR-001](../adr/ADR-001-xray-install-mechanism.md) + [ADR-002](../adr/ADR-002-gateway-paths-units-state.md)
- **Этап:** G6 Close (ждёт commit + [VDS]-приёмку)
- **Владелец гейта:** orchestrator / владелец

## Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 P1–P3 + tests bootstrap | vds-coder | ✅ done | отчёт в сессии (pre-flight verbatim) | — |
| WP-2 core-примитивы | vds-coder | ✅ done | отчёт в сессии | — |
| WP-3 gateway store + CLI | vds-coder | ✅ done | отчёт в сессии | — |
| WP-4 Xray VLESS Reality | vds-coder | ✅ done | отчёт в сессии | — |
| WP-5 Hysteria2 self-signed | vds-coder | ✅ done | отчёт в сессии | — |

## Гейты
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-07 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-07 | vds-analyst |
| G2 Spec | ✅ | 2026-11-07 | vds-architect |
| G3 Build | ✅ | 2026-11-07 | vds-coder ×4 → vds-architect |
| G4 Verify | ✅ PASS | 2026-11-07 | vds-tester |
| G5 Docs | ✅ | 2026-11-07 | vds-docs |
| G6 Close | ⏳ | — | ожидает: commit, [VDS]-приёмка |

## Открытые пункты
1. **[VDS]-приёмка** — чеклист 28 пунктов в [TEST-отчёт §8](reports/TEST-20261107-gateway-mvp.md):
   живая установка обоих протоколов, probe-resistance (FR-X.1), одновременный TCP/UDP 443
   (FR-X.2), идемпотентность, docker_exec smoke на ZTNET.
2. Minor-дефекты tester: `run_remove(yes=...)` не экспонирован в CLI; FR-0.2 проверен
   статически (чистый venv-прогон не делался).
3. Глобальный фильтр маскирования логов → фаза 6 (hardening).
4. `HYSTERIA2_BIN_PATH` вынести в `gateway/paths.py` при следующем ADR.
5. **Баг install.sh:74** — `cp -r` на самого себя при `SCRIPT_DIR == INSTALL_DIR` убивает
   скрипт под `set -e` (найдено при развёртывании на asv1, см.
   [ORCH-20261109](reports/ORCH-20261109-vds-deploy-install.md) §4).
6. pytest отсутствует в requirements — нужен requirements-dev.txt / extra (ORCH-20261109 §5.2).
7. [VDS]-приёмка готова к запуску на asv1 (103.45.247.172) — CLI установлен, порты 443
   свободны (ORCH-20261109 §5.3).

## Трассируемость
| IDEA | REQ | SPEC | Коммиты | TEST | DOC |
|---|---|---|---|---|---|
| чат 2026-11-07 | REQ-20261107-gateway-mvp | SPEC-20261107-gateway-mvp (+ADR-001/002) | pending G6 | TEST-20261107-gateway-mvp (PASS) | DOC-20261107-gateway-mvp |

## Вне цикла (бэклог)
- TECHDEBT P4–P6 остаются открытыми (P1–P3 закрыты этим циклом).
- Roadmap фазы 3–9: XHTTP (нужен домен), AmneziaWG, подписки/hub, hardening/ACME,
  watchdog/метрики, e2e, дистрибуция.
