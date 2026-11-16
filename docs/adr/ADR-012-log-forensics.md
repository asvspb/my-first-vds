# ADR-012: log-forensics — локальная телеметрия, дампы и захват пакетов

- **Дата:** 2026-11-16
- **Статус:** accepted (G2 APPROVED-with-notes, оба раунда ревью внесены)
- **Контекст SPEC:** [SPEC-20261116-log-forensics](../team/specs/SPEC-20261116-log-forensics.md)
  (WP-1 — ADR до реализации; ревью M2: пути/redaction-контракт/.gitignore —
  необратимые решения)
- **Связанные:** ADR-002 (пути/юниты), ADR-007 (RU-relay), ADR-011 (UFW
  hardening / lock-443), SPEC-20261116-probe-response (граница «анализатор
  не реагирует»)

## Контекст

Систематической форензики нет: логи живут в journald и никуда не собираются,
§5.13 SERVER-BASELINE описывает ручной `tcpdump` (забытый захват, `/var/tmp`,
нет ротации/лимитов, нет привязки к вердикту probe-watch). Инцидент asv2
2026-11-15 (первые ~30 минут ТСПУ душит TCP-443 TLS-payload при живом
UDP-443) разбирался вручную: без временных рядов «Reality сломан» и типичная
реакция (рестарт юнита) только сбрасывает профиль.

Ограничения, определяющие дизайн:

- **TSPU-окна** приходят внезапно и живут минуты; разбирать их нужно по
  временным рядам (5-мин сэмплы), а не по мгновенным `ss`.
- **Reality слеп в логах** (§5.11): app-логи Xray при default loglevel не
  видят plain-TLS-пробы; поднимать loglevel бессмысленно. Сервер видит
  только эффекты (nft/kernel-счётчики, ss-сокеты, interface counters).
- Дампы с IP клиентов — персональные данные; pcap может утечь в git/чат.

## Рассмотренные варианты

| Вариант | Плюсы | Минусы |
|---|---|---|
| **Локальный конвейер collect→…→retain (выбран)** | офлайн, stdlib+системные утилиты, без LLM/ML; данные не покидают сервер; deterministic-отчёт с доказательствами | свой код; диск под артефакты (смягчено TTL и disk-cap) |
| SIEM / log-shipping | центральный поиск | сеть-зависимость, экспорт приватных логов за пределы сервера, новая инфраструктура — противоречит принципу «всё локально» |
| Только probe-watch (расширить) | меньше кода | разные жизненные циклы и права (минуты/дни/диск/pcap vs часовой тик/nft); разбирать бандлы офлайн не умеет; ревью G2: граница модуля `src/logs` vs `gateway/probing` сохраняется |

## Решение

1. **Конвейер:** `collect → normalize → enrich → detect → correlate → score
   → report → retain` — один код-путь для `--live` и для готового bundle
   (SPEC R-1). Модуль `src/logs/` (paths, collect, sample-хранилище,
   baseline, detect, report, capture, install).
2. **Пути (фиксируются, смена — новый ADR):**
   - `/var/lib/vds/telemetry/` — 5-мин NDJSON-сэмплы (`samples-YYYYMMDD.ndjson`,
     0700/0600), TTL 7 дней;
   - `/var/lib/vds/forensics/{captures,bundles,reports}` — pcap-кольцо,
     бандлы инцидентов (TTL 30), отчёты (TTL 90, 0600);
   - `/etc/vds-forensics/rules.json` — override порогов правил T-01…T-17
     (0600; defaults в коде; `rules_hash` в отчёте);
   - `/etc/vds-forensics/hmac.key` — ключ HMAC-редакции IP (0600,
     генерируется `logs install --apply`);
   - `/var/lib/vds/probe-watch.json` — снапшот probe-watch, read-only
     потребление (M1: collect НЕ вызывает мутирующий `watch`; дельта —
     in-process чистая `compute_delta`, `computed_by="logs-collect
     (read-only)"`).
3. **Privacy-контракт (неотъемлемая часть ADR):**
   - `state.json`/секреты (UUID клиентов, ключи, пароли, share-ссылки) в
     артефактах ЗАПРЕЩЕНЫ; пост-сканер находит секрет → сбор аварийно
     завершается, bundle удаляется;
   - redaction-паттерны: контекстные маркеры (`privateKey`, `PrivateKey =`,
     `PreSharedKey`, `shortIds`, `password`, `auth=`) → `<redacted>`;
     жадные hex/base64 ≥32 → `<blob>` ТОЛЬКО к raw-тексту журналов, НИКОГДА
     к JSON-полям (sha256/checksums/rules_hash/ja3/ja4 — легальный hex);
   - IP клиентов — только с `--redact-ips` (HMAC-SHA256(key, ip)[:12],
     детерминировано) при передаче разбора наружу; локально — сырые;
   - bounded-pcap: metadata-only по умолчанию, TTL 7 дней, `-s 1600`,
     кольцо `-C`/`-G 3600`/`-W 5`, BPF `ip and tcp port 443 and
     (tcp[tcpflags] & (tcp-syn|tcp-push) != 0) and not (host A or host B …)`
     (IPv4-only v1: classic BPF `tcp[n]` не работает для IPv6), путь
     `/var/lib/vds/forensics/captures/` (не `/var/tmp`), после parse —
     delete-after-parse по умолчанию.
4. **Анализатор не реагирует** (граница с probe-response): detect/report
   только советуют (тип инцидента `probing_only/effect_only/
   probing_plus_effect/local_fault/inconclusive`); ни одного вызова
   `ufw lock-443`/рестартов из кода анализа; исполнение — оператор или
   `probe-response`. Read-only: root нужен только collect/capture.
5. **Таймеры (opt-in):** `vds-logs-sample.timer` (5 мин,
   RandomizedDelaySec=30, Nice=10, IOSchedulingClass=idle, MemoryMax=64M,
   caps: CAP_NET_ADMIN/CAP_SYSLOG/CAP_DAC_READ_SEARCH, ProtectSystem=strict,
   ReadWritePaths=/var/lib/vds) и `vds-logs-daily.timer` (04:15,
   MemoryMax=192M) ставятся ТОЛЬКО `vds logs install --apply` (OQ-2:
   осознанная стоимость диска), remove с undo-журналом
   `install-state.json` (паттерн ufw-модуля).

## Красные флаги (git-гигиена, проверяется тест-сканером)

- `.gitignore` дополнен: `*.pcap`, `*.ndjson`, `bundles/`, `captures/`,
  `telemetry/` — дампы/телеметрия НЕ попадают в репозиторий;
- `/var/lib/vds/*` и `/etc/vds-forensics/*` — runtime-артефакты сервера, в
  репо отсутствуют (упоминание — только в доках/ADR); фиксстуры тестов —
  только `FIXTURE_PW_*`/`FIXTURE_UUID_*` и RFC 5737 IP (AGENTS §6).

## Последствия

- Положительные: воспроизводимый разбор инцидента одной командой (AC-1);
  честная карта покрытия (`coverage`, `logs explain`) — слепота признаётся
  явно (§3: SNI/DNS-блок — только со стороны клиента); детерминизм отчёта
  (R-3); диск ограничен (сэмпл ~1 MB/сутки, TTL, disk-cap 90%).
- Отрицательные: постоянный 5-мин таймер на VDS (смягчено
  RandomizedDelaySec/Nice/idle/MemoryMax=64M); без tshark нет JA3/JA4
  (degraded-режим честно `pcap.fingerprint="unavailable"`); iptables/nft
  счётчики сбрасываются ребутом (reset-дельты помечаются, в baseline не
  попадают).
- Трудно изменить позже: пути артефактов, формат NDJSON-сэмпла (v1),
  privacy-контракт — смена через новый ADR.
- Откат: `vds logs remove --apply` (демонтирует юниты/таймеры по
  undo-журналу); каталоги `/var/lib/vds/{telemetry,forensics}` удаляются
  оператором вручную (данные владельца).
