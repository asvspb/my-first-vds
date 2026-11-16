# SPEC-20261116-probe-coverage — W1-1: probe-watch на всех боевых TCP-портах + быстрый контур детекта серий ТСПУ

> **Статус:** draft → G1/G2 (внешний архитектор Gemini Argon, через пуш).
> W1-1 реализован (2026-11-16, WP W1-1; приёмка-живое — §5.2/5.3 владельцем).
> **Источник:** [ARCH-20261116-tspu-blindspots](../reports/ARCH-20261116-tspu-blindspots.md) §3
> (слепота probe-watch ко всему кроме 443; реакция 1–2 ч против серий ТСПУ 2–15 с);
> продолжение [SPEC-20261116-surface-hardening](SPEC-20261116-surface-hardening.md)
> §6 (Wave 0 закрыт: HF-1 `df72a9f`, HF-2 `41001ce`+`4530fa2`, G4 PASS).
> **Скоуп:** только W1-1. SSH-в-туннель (W1-2, §6 ARCH) и ADR-пункты Волны 2 — вне.

## 1. Расширение nft-охвата

Сейчас (`src/gateway/probing.py`, `render_nft()`): `probers4` и счётчики
(`syn_valid`, `syn_bare`, `udp_443`) собираются только на `tcp dport 443`.
Сканер по 8443 (XHTTP) / 2053 (CDN origin) невидим → `quiet`, 0 probers.

Требования:

1. Правило probers4: `tcp dport { 443, 8443, 2053 }` (named set — один,
   порт-набор в правиле). UDP-порты (443/51826) в probers4 НЕ добавлять —
   QUIC-клиенты дадут ложные срабатывания; UDP остаётся только на счётчике.
2. Счётчики: `syn_valid`/`syn_bare` продолжают считать ТОЛЬКО 443 (база для
   PROBE-BURST ratio — история порогов не ломается); новые именованные
   `syn_valid_extra` / `syn_bare_extra` (суммарно по 8443+2053) — телеметрия
   и попадание в probers4. `udp_443` не трогать.
3. **JSON-контракт `watch --json` (критично, ADR-014/vpn guard):** поля
   `syn_bare`, `syn_valid`, `udp_443`, `threat_level`, `threat_reason`,
   `lockdown`, `ru_syn_new`, `own_ips_sources` — НЕ меняются; новые счётчики —
   аддитивно (`syn_valid_extra`, `syn_bare_extra`, `extra_ports: [8443, 2053]`).
   Guard sync старой версией клиента обязан работать без ошибок.
4. Вердикты: PROBE-BURST-пороги считать по 443 как раньше (без ломки калибровки);
   попадание сканера только в 8443/2053 видно через probers4 (а значит в
   `new_ru_ips` → RU-PROBE-SUSPECT) и в `explain`-карте покрытия.
5. `probe-watch explain` обновить: отражать, что 8443/2053 теперь покрыты,
   UDP-порты — по-прежнему слепы (per-element nft-счётчики UDP вне скоупа).

## 2. Быстрый контур детекта серий ТСПУ

Проблема: таймер probe-watch 1 ч × HIGH_STREAK 2 → реакция 1–2 ч; серия ТСПУ
длится 2–15 с, IP в блок-лист попадает до срабатывания.

Требования:

1. НОВОГО демона НЕ создавать. Быстрый контур = хук в существующем
   `vds-logs-sample` (5-мин таймер, ADR-012): при каждом сэмпле читать дельту
   probers4/named-счётчиков (лёгкое nft-чтение, уже есть в probing.py) и
   пополнять `own_ips_cache` (verified_session_ips — тот же инвариант
   HF-1) + при всплеске (≥ N новых probers за 5 мин) — тег в journal
   `[warning] [probe] FAST-CONTOUR: N probers/5min` для vds logs. АВТО-ДЕЙСТВИЙ
   НЕТ (никакого lock-443 из быстрого контура — только телеметрия; lockdown
   остаётся исключительной прерогативой часового probe-watch с его гейтами).
2. Интеграция: модульная функция `fast_contour_check()` в probing.py,
   вызывается из `src/logs/collect.py` сэмплером (ленивый импорт, отсутствие
   nft-таблицы — тихий скип). Запись в кэш — в файл кэша сэмплера, НЕ в
   snapshot probe-watch (чтобы не нарушить инвариант «watch --json без
   --record не мутирует snapshot» — сэмплер пишет в свой лог, часовой watch
   подхватит кэш через существующий own_ips_cache-механизм только на
   record-тике).
3. Порог N: `FAST_CONTOUR_PROBERS = 10` (уникальных IP за 5 мин; настраиваемый
   через конфиг probe-watch, dry-run-семантика по умолчанию — только журнал).

## 3. Затронутые файлы

| Файл | Изменение |
|---|---|
| `src/gateway/probing.py` | port-set в nft-правиле, `syn_*_extra`, `fast_contour_check()`, explain |
| `src/logs/collect.py` | вызов fast_contour_check в сэмплере |
| `tests/gateway/` | nft-рендер (port-set, счётчики), JSON-схема, fast-contour |
| `docs/team/specs/SPEC-20261116-probe-response.md` | §карта покрытия/verdiktы |
| README/AGENTS по docsync explain | при изменении наблюдаемой поверхности |

## 4. Тест-кейсы

- W1: рендер nft содержит `tcp dport { 443, 8443, 2053 }` в probers4-правиле;
  счётчики `syn_valid_extra`/`syn_bare_extra` объявлены; `syn_valid`/`syn_bare`
  по-прежнему привязаны к 443.
- W2: `watch --json`: все старые ключи на месте с прежней семантикой; новые —
  аддитивно (схема-тест: старый набор ключей ⊂ новый).
- W3: probers по 8443/2053 (эмуляция nft-вывода) попадают в new_ru_ips →
  RU-PROBE-SUSPECT; свои verified-клиенты по 8443 (HF-1-механика) не попадают.
- W4: `fast_contour_check`: ≥10 probers/5мин → warning-тег; <10 — тишина;
  nft-таблицы нет — тихий скип без исключения; snapshot probe-watch не
  мутируется (инвариант ADR-014).
- W5: PROBE-BURST пороги не меняются от extra-счётчиков (регресс калибровки).

## 5. Критерии приёмки

1. Тесты W1–W5 зелёные, полный pytest без регрессий (998 сейчас).
2. Живое: скан 8443/2053 с постороннего IP → probers4 растёт, `watch` видит
   IP в отчёте; Reality-клиент по 8443 с прокачкой трафика — не в probers4.
3. `journalctl -u vds-logs-sample` содержит FAST-CONTOUR-тег при всплеске;
   авто-lockdown НЕ срабатывает из быстрого контура.
