# SPEC-20261116-surface-hardening — Wave 0: probe-response v2 (anti Self-DoS) + surface hardening (XHTTP/CDN)

> **Статус:** draft → G0 (владелец утвердил порядок HF-1 → HF-2 → W1-1, 2026-11-16).
> **Источник:** [ARCH-20261116-tspu-blindspots](../reports/ARCH-20261116-tspu-blindspots.md)
> §4, §2 (+ §8.1–8.2) + техническое ревью оркестратора (подводные камни сверены по коду
> 2026-11-16: `probing.py`, `cdn.py`, `install.py`, `ufw.py`, `config.py`).
> **Скоуп:** ровно два хотфикса. W1-1 (расширение probers4 на 8443/2053) — следующий
> цикл, здесь только его неотложные совместимости (§6). ADR-уровневые пункты §1/§5
> (SNI, AWG 2.0/hop) — вне скоупа.
> **Стоп-условие (владелец):** auto-lockdown на бою не включать до приёмки HF-1.

## 1. HF-1 — anti Self-DoS в probe-watch

### 1.1 Проблема

`own_ips` собирается только из `awg show awg0 endpoints` + `allow-ips.txt`
(`src/gateway/probing.py`, `OWN_IPS_FILE`). Клиенты на Reality/XHTTP/Hy2 без
активного AWG-туннеля попадают в `probers4` как `new_ru_ips`; порог
`NEW_RU_IPS_THRESHOLD = 2` (два своих устройства) → `RU-PROBE-SUSPECT` → при
включённом auto-lockdown сервер блокирует владельцу 443.

### 1.2 Решение: verified_session_ips

Новый источник исключений — IP с **верифицированными сессиями** на серверных
TCP-портах. Инвариант против «бот ТСПУ проходит handshake» (бот устанавливает
ESTABLISHED и шлёт ClientHello — голый `state established` его пропустит):

```python
VERIFIED_BYTES_ACKED = 16384   # 16 КБ отправлено клиенту
VERIFIED_BYTES_RECEIVED = 4096 # 4 КБ получено от клиента

def read_verified_session_ips(ports: tuple[int, ...] = (443, 8443, 2053)) -> set[str]:
    """IP из `ss -tniH state established '( sport = :443 or sport = :8443 or sport = :2053 )'`,
    у которых bytes_acked >= 16384 И bytes_received >= 4096.
    Проба ТСПУ/Censys не проходит авторизацию VLESS/XHTTP и не качает
    двусторонний трафик (Reality при fallback к dest рвётся после сертификата).
    Парсер строк ss: bytes_acked:<N> и bytes_received:<N> печатаются на ВТОРОЙ
    (индентированной) строке пары «адресная строка + метрики сокета» — регулярка
    склеивает пару строк. IPv4-mapped IPv6 (::ffff:203.0.113.5:54321 — dual-stack
    listener Xray/Hy2 показывает клиента именно так) — префикс ::ffff: срезать,
    иначе IP не совяжется с IPv4-ключом probers4. Оба ключа bytes обязательны,
    сокеты без обоих полей — игнорировать fail-closed."""
```

**Аффинность между тиками** (клиент закрыл ноутбук до тика таймера; `probers4`
живёт 1h, `ss` видит только момент запуска):

- Верифицированные IP кэшируются в `snapshot["own_ips_cache"]` с TTL **24 ч**
  (список пар `(ip, first_seen_ts)`, чистка при каждом watch).
- Кэш пополняется: (а) самим `cmd_watch`, (б) опционально — сэмплером
  `vds-logs-sample` (если уже ходит чаще; отдельного таймера в этом SPEC не создаём).
- `own_ips` на входе в RU-классификацию = `awg_endpoints ∪ allow_ips ∪ own_ips_cache`.

**UDP (Hy2 443/udp, 51826/udp):** читать через `/proc/net/nf_conntrack`
(не требует пакета conntrack). Нюанс Ubuntu 24.04: `net.netfilter.nf_conntrack_acct`
по умолчанию **0** — полей `bytes=` в строках нет, есть только `[ASSURED]`.
Делаем оба: (а) включаем `nf_conntrack_acct = 1` в
`systemd/sysctl/99-vds-gateway.conf.tpl` (persist) при install; (б) graceful
fallback в парсере: если `bytes=` присутствуют — требовать
`bytes_orig + bytes_reply > 32768` **и** `[ASSURED]`; если acct=0 (полей нет) —
фолбэк на `[ASSURED]` (ядро ставит его только при двустороннем обмене пакетами,
что в QUIC/Hysteria2 и есть признак живого клиента). При отсутствии файла —
деградация без ошибки (только TCP+AWG+кэш), в watch-выводе тег источника.

### 1.3 Fail-fast в cmd_config (ужесточение)

Сейчас (`probing.py:~1758`): guard срабатывает только если
`not lockdown_allow AND not has_non_443_channel(state)`. Ужесточить:

`--auto-lockdown on` требует **непустого** `lockdown_allow` (allow-ips.txt или
`--lockdown-allow`) **всегда**; наличие 51825/2053 в state больше не является
достаточным основанием. Текст ошибки обновить. Обратная совместимость: явный
`--lockdown-allow` продолжает работать как раньше.

### 1.4 Не-цели HF-1

- НЕ трогать логику threat-level/decay/HIGH_STREAK.
- НЕ смешивать с циклом vpn guard (ADR-014): HF-1 правит только серверный
  `probing.py`; WP-G4 (AC-16, regression `cmd_watch(record=False)`) идёт после HF-1.

## 2. HF-2 — недемаскировка XHTTP/CDN

### 2.1 Рандомизация путей + фикс скрытого бага кросс-рендера

Подтверждённый баг: `_xhttp_fields` (`src/xray/cdn.py`) вытаскивает из
config.json client_ids/mode/port/bind/cert_path/key_path, но **не path**;
`_xhttp_inbound` (`src/xray/config.py`) зашивает `"path": XHTTP_PATH` без
поля в `XrayConfigParams` (комментарий в config.py прямо обещает
«смена — коммитом + state (extra.path)» — не доведено). Любая рандомизация без
фикса будет молча сброшена первым же `cdn setup` / перерендером, а ссылки в
`links.py` разойдутся с config.json.

Требования:

1. `XrayConfigParams.xhttp_path: str = XHTTP_PATH` (новое поле, frozen-dataclass).
2. `_xhttp_inbound`: `"path": params.xhttp_path`. Аналогично для CDN:
   `ws_path` уже параметризован (`params.ws_path`) — проверить и закрепить тестом.
3. `_xhttp_fields` (cdn.py) и `_render_xhttp_config` (install.py) прокидывают
   path: `xhttp["path"]` из текущего инбаунда / из
   `state.protocols["xhttp"]["extra"]["path"]`.
4. **Идемпотентность пути:** `add-transport xhttp` генерирует случайный путь
   (секрет-генератор из `core.secrets`, формат `/`+16..24 hex), только если
   `extra.path` отсутствует; существующий путь не перегенерируется никогда
   (иначе слетают выданные клиентские ссылки). Тот же принцип для `cdn_ws_path`.
   Литерал `/xhttp` остаётся только как default для существующих установок при
   миграции (первый `add-transport` на живом сервере берёт текущий путь из
   config.json, не ломая ссылки; смена на рандомный — отдельной опцией
   `--regenerate-path` с явным предупреждением). Ротация секрета на живом
   сервере — штатная операция оператора: `--regenerate-path --apply` →
   немедленный `vpn profile pull` на всех клиентах (тихая смена пути рвёт
   резервные каналы). Новые инсталляции с нуля получают рандомный путь
   автоматически. Подтверждено владельцем 2026-11-16.
5. Путь — секрет: не логировать, не в share-link вывод кроме как в самой ссылке,
   хранение в `state.json` (уже 0600).

### 2.2 Порт 2053/tcp — только Cloudflare

Сейчас `_ufw_allow(port)` в `src/xray/cdn.py` делает `ufw allow 2053/tcp`
(Anywhere); профиль gateway в `src/system/ufw.py` строит план для CDN-порта.

Требования:

1. `_ufw_allow` для CDN-порта → список `ufw allow from <cf_cidr> to any port 2053 proto tcp`
   по официальным IPv4-подсетям Cloudflare (`ips-v4`, 15 CIDR; источник —
   константа в коде с комментарием-ссылкой на https://www.cloudflare.com/ips-v4,
   обновление — правкой кода; v6 — вне скоупа, origin слушает v4-факт).
2. `UfwSnapshot`-парсер и `build_plan` (`src/system/ufw.py`) должны распознавать
   эти CIDR-правила как штатное покрытие CDN-порта: профиль gateway не должен
   (а) требовать широкое `allow 2053/tcp` и (б) ломаться на 15 CIDR-строках.
   Критерий покрытия: порт считается открытым, если покрыт CF-CIDR-набором.
3. Миграция живых установок: при повторном `cdn setup` / `ufw harden --apply`
   широкое правило `2053/tcp` заменяется на CF-набор. **Порядок обязателен**
   (живая сессия через CDN не должна мигнуть): сначала добавляем все 15
   `allow from <cf_cidr> …`, и только после успешного добавления —
   `ufw delete allow 2053/tcp`; всё в одной транзакции плана с откатом при
   неудаче добавления.
4. `_ufw_delete` — симметрично удалять CIDR-набор.

## 3. Затронутые файлы

| Файл | Изменение |
|---|---|
| `src/gateway/probing.py` | `read_verified_session_ips`, `own_ips_cache` (TTL 24h), conntrack-UDP, fail-fast cmd_config |
| `src/xray/config.py` | `xhttp_path` в `XrayConfigParams`, `_xhttp_inbound`/`_cdn_inbound` path из params |
| `src/xray/cdn.py` | `_xhttp_fields` + path; `_ufw_allow`/`_ufw_delete` CF-CIDR; идемпотентная генерация путей |
| `src/xray/install.py` | `_render_xhttp_config` прокидывает path; генерация при `add-transport` |
| `src/system/ufw.py` | CF-CIDR-набор как штатное покрытие CDN-порта (парсер + build_plan) |
| `tests/gateway/`, `tests/xray/` | новые кейсы (§4) |

## 4. Тест-кейсы (для vds-tester, без root/сети)

**HF-1:**
- T1: ss-вывод с bytes_acked≥16384+bytes_received≥4096 → IP верифицирован;
  bytes только в одну сторону / ESTABLISHED без трафика → НЕ верифицирован.
- T2: строки ss без `bytes_*` (не `-ti`, кривой вывод) → fail-closed, IP не
  верифицирован, исключение не поднято.
- T3: аффинность: IP верифицирован в окне N, сокета уже нет в окне N+1 (< 24h)
  → остаётся в own_ips; после 24h — чистится.
- T4: `--auto-lockdown on` без allow-ips и без `--lockdown-allow` → exit 1,
  даже когда в state есть 51825 (регресс ужесточения).
- T5: RU-классификация: 2 новых RU-IP, один из них верифицированный → НЕ
  RU-PROBE-SUSPECT.
- T6 (регресс): `watch --json` без `--record` не мутирует snapshot (стык с
  vpn guard, AC-16-совместимость).

**HF-2:**
- T7: `add-transport xhttp` дважды → path в state один и тот же (идемпотентность).
- T8: кросс-рендер: рандомный path в state → `cdn setup`/перерендер → path в
  config.json равен state (не `/xhttp`) — регресс скрытого бага.
- T9: `_xhttp_fields` вытаскивает path из живого config.json (миграция без
  перевыпуска ссылок).
- T10: план ufw для профиля gateway с CDN: CF-CIDR-набор признаётся покрытием,
  широкое `allow 2053/tcp` не добавляется поверх; снимок с широким правилом
  мигрирует в CIDR-набор.
- T11: путь не появляется в логах/выводе кроме share-link (fixture-префиксы по
  AGENTS §6).
- T12: ss-вывод с `::ffff:203.0.113.5` (dual-stack) → IP нормализован в
  IPv4-ключ; conntrack-строки без `bytes=` (acct=0) → фолбэк `[ASSURED]`,
  с `bytes=` → порог 32768.

## 5. Docsync-карта (коммит = код + тесты + mapped-доки)

`python3 tools/docsync.py explain` по затронутым путям; ожидаемые mapped-доки:

- `src/system/ufw.py`, `src/xray/*` → `docs/VPN-PROTOCOLS.md` (разделы XHTTP/CDN:
  пути не литеральные, 2053 CF-only), `README.md` (поведение команд), возможно
  `docs/CDN-FRONTS.md`.
- `src/gateway/probing.py` → `docs/team/specs/SPEC-20261116-probe-response.md`
  (§11 own_ips: + verified_session_ips/кэш/conntrack; fail-fast §4.2 ужесточён),
  `docs/CENSORSHIP-PATTERNS.md` не трогаем (паттерн поведения не меняется).
- `AGENTS.md`/`TECHDEBT.md` — только если появятся отложенные хвосты
  (например, отдельный быстрый таймер реактивности — W1-1, не здесь).

## 6. Совместимость с W1-1 и vpn guard

- W1-1 (расширение `probers4` на `{443, 8443, 2053}`) идёт **после** Wave 0;
  при его реализации — отдельные именованные счётчики (`syn_valid_extra`),
  JSON-схема `watch --json` (syn_bare/syn_valid/udp_443) расширяется, но не
  меняется (читает клиентский `vpn guard sync`).
- Файлы HF-1/HF-2 не пересекаются с WP-G0..G3 (ADR-014/vpnm guard);
  WP-G4 стартует после HF-1.

## 7. Критерии приёмки

1. T1–T11 зелёные; полный `pytest -q` без регрессий.
2. Живая проверка на asv2 (после G-гейтов, отдельным шагом владельца):
   подключение с двух RU-IP без AWG → `watch` не выдаёт RU-PROBE-SUSPECT;
   `nft list set inet vds_probe probers4` не содержит IP владельца;
   включить accounting вручную (шаблон подхватится только при переустановке
   sysctl-профиля): `sudo sysctl -w net.netfilter.nf_conntrack_acct=1`
   (+ `sysctl --system` после обновления 99-vds-gateway.conf) — до этого
   conntrack-источник работает на фолбэке `[ASSURED]`.
3. `vds xray cdn setup` повторно — path стабилен, `ufw status` показывает
   CF-CIDR вместо широкого 2053, `vds system ufw audit` зелёный.
4. Auto-lockdown включается только с заполненным allow-списком.
