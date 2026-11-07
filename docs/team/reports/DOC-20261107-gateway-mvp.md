# DOC-20261107-gateway-mvp

## Мета
- **SPEC:** [SPEC-20261107-gateway-mvp](../specs/SPEC-20261107-gateway-mvp.md) ·
  TEST: [TEST-20261107-gateway-mvp](TEST-20261107-gateway-mvp.md)
- **Автор:** документатор (vds-docs)
- **Дата:** 2026-11-07
- Код и тесты не правились.

## Обновлено
- **README.md**
  - «Возможности»: пункт про gateway-протоколы (Xray Reality / Hysteria2).
  - Структура: `src/xray/`, `src/hysteria2/`, `src/gateway/`, шаблоны юнитов
    и sysctl, `tests/`; строки путей `/opt/my-vds/gateway/state.json`,
    `/usr/local/etc/xray/config.json`, `/etc/hysteria/config.yaml`.
  - Новый раздел «Gateway: Xray / Hysteria2 (MVP, фазы 0–2)»: все фактические
    команды с примерами, dry-run-семантика `remove`, пометка «Hysteria2 в MVP —
    тестовый режим self-signed (insecure=1), ACME — фаза 6», краткий дисклеймер
    о легальном использовании (дубль из VPN-PROTOCOLS «Важно»).
- **docs/VPN-PROTOCOLS.md** — раздел 3: статус-блок «MVP реализовано 2026-11-07
  (фазы 0–2), команды фактические» + блок фактических команд
  (`gateway status`; `xray install [--sni]|add-client|status|remove [--apply]`;
  `hysteria2 install|add-client|status|remove [--apply]`); исходный план
  оставлен как контекст для фаз 3+; ссылки на SPEC/ADR-001/ADR-002.
- **docs/CENSORSHIP-ROADMAP.md** — шапка: «фазы 0–2 реализованы 2026-11-07
  (см. SPEC-20261107-gateway-mvp)»; XHTTP/AmneziaWG/подписки/SNI-мультиплексор —
  не реализованы; текущее состояние проекта уточнено.
- **TECHDEBT.md** — P1, P2, P3 помечены «✅ ВЫПОЛНЕНО 2026-11-07» со ссылкой
  на SPEC-20261107-gateway-mvp и кратким фактом закрытия; текст пунктов сохранён.
- **AGENTS.md** — структура: `core/` дополнена (protocol/netcheck/secrets/units),
  добавлены `xray/`, `hysteria2/`, `gateway/`, `tests/`, sysctl-шаблоны;
  стек: pytest «планируется» → фактическое; команда `pytest -q` — актуальна;
  тестовая стратегия — без «когда появятся».

## Проверено (verbatim — ключевые строки)
```
$ python -m src.main xray --help        → install/add-client/status/remove; «Xray VLESS Reality gateway (TCP 443)»; exit=0
$ python -m src.main hysteria2 --help   → install/add-client/status/remove; «Hysteria2 QUIC gateway (UDP 443)»; exit=0
$ python -m src.main gateway --help     → status; «Gateway state management»; exit=0
$ python -m pytest -q                   → 126 passed in 0.54s
```
Полный вывод `--help` — в логе цикла; команды/флаги (`--sni`, `--apply`)
существуют в CLI, ничего не документировано «по замыслу».

## Ссылки целы
- `docs/team/specs/SPEC-20261107-gateway-mvp.md` — OK
- `docs/team/reports/TEST-20261107-gateway-mvp.md` — OK
- `docs/adr/ADR-001-xray-install-mechanism.md`, `ADR-002-gateway-paths-units-state.md` — OK
- `docs/VPN-PROTOCOLS.md`, `docs/CENSORSHIP-ROADMAP.md` — OK

## Не обновлено / требует решения
- CHANGELOG.md — не создан (релиза ещё не было; создать при первом релизе).
- docs/TEAM.md — процесс не менялся, правок не требуется.
- Docstrings — сигнатуры в коде соответствуют SPEC §3; расхождений не найдено.
- Дефект №1 из TEST-отчёта (глобальный фильтр маскирования в logger.py) —
  решение за архитектором; в документации описано фактическое поведение
  (точечное маскирование в status.py).

## Гейт G5 (Docs): DONE
→ Цикл готов к закрытию (после [VDS]-приёмки по чеклисту TEST §8).
