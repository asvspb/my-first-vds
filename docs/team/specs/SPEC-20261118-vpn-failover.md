# SPEC-20261118-vpn-failover — клиентское авто-переключение каналов (WP-FAILOVER)

## Мета
- **Источник:** ТЗ реализатору `PROMPT-20261118-vpn-failover-implementer.md`
  (документ 2), ответы владельца 2026-11-18 (два решения: SPEC+ADR до кода;
  desktop — отдельным opt-in флагом), SPEC-20261116-probe-response §16,
  ADR-014 §«чего guard не делает».
- **Автор:** архитектор
- **Дата:** 2026-11-18
- **Статус:** **G2 APPROVED 2026-11-18** (arch-lead; две линзы — реализуемость и
  тест-план; §11 и уточнения по триггерам приняты в контракт без замечаний).
  Код начинается только после APPROVE — APPROVE получен.
- **ADR:** **обязателен** — [ADR-015](../../adr/ADR-015-vpn-failover.md)
  (меняется граница «демон ничего не делает»: появляется исполняющий агент).
- **Ревьюеры:** `vds-coder` (реализуемость), `vds-tester` (12 AC),
  `vds-debugger` (ложные переключения), `vds-docs` (docsync-пути).
- **Скоуп:** клиент `scripts/vpn-manager/` + узкая серверная правка
  (`src/gateway/probing.py`, `src/alert/watch.py`).

---

## 0. TL;DR для кодера

1. Новый модуль `vpnm/guard/failover.py` (движок) и расширение **существующих**
   `notify.py`, `install.py`, `cli.py`, `redact.py` — **не** создавать их заново.
2. Новый user-юнит **`vpn-failover.service`** + `vpn-failover.path`
   (префикс `vpn-`, не `vpnm-`).
3. Триггеры узкие: `G-01` (high), `G-09` (medium и выше) и **производное**
   условие `expected_lockdown` (свежий `server-verdict.json` c
   `lockdown.active=true` + активный профиль в `trigger_profiles`).
4. Лестница `relay → asv2-hy2 → asv2-awg → asv2-cdn`; на каждом кандидате
   `pre_flight` → switch → `post_flight`; неуспех — следующий, не повтор.
5. Desktop — **opt-in** `notify.failover_desktop` (по умолчанию `false`).
   Telegram — из файла токена 0600, при сбое в `pending_alerts.jsonl`.
6. Сервер: защита allow-list/релея в `auto-lockdown` + **новое** событие
   `lockdown_off` в `vds alert` (сейчас есть только `lockdown_on`).

---

## 1. Цель, принципы, non-goals

**Цель:** при отказе прямого канала вернуть связь **без участия человека**,
уложившись в окно 2–15 мин, и при этом не сломать наблюдаемость.

**Принципы:**

1. **Действие — исполнение политики, не анализ.** Решение принимается по
   перечислимым правилам; никакой «интеллектуальной» оценки.
2. **Сначала проверить, что проблема не локальная.** `local_net_check()` —
   шаг 0, до любого переключения.
3. **Не переключать «наугад».** `pre_flight` до смены профиля, `post_flight`
   после: канал либо доказан, либо отброшен.
4. **Лучше не переключить, чем переключить в пустоту.** Total blackout — это
   явный терминальный статус с backoff, а не бесконечные попытки.
5. **Никакой самовольной отмены.** Снятие серверного лока не возвращает
   человека на прямой канал — только сообщает.

**Non-goals v1:**

- серверных решений (сервер по-прежнему только уведомляет; `auto-lockdown`
  остаётся opt-in);
- переключения между серверами/новых endpoint'ов (только существующие
  профили/схемы);
- IPv6-специфичной логики и CDN-мультиплексирования;
- «лечения» DNS, MTU, sysctl (это `vpn repair`/`vpn doctor`);
- работы без активной сессии пользователя (нет linger — агент живёт в сессии).

---

## 2. Инварианты, которые НЕЛЬЗЯ нарушить

| # | Инвариант | Как проверяется |
|---|---|---|
| I-1 | `vpn guard` остаётся read-only: в `reader.py`, `parse.py`, `window.py`, `rules.py`, `correlate.py` нет `sudo`, `systemctl`, вызовов failover и сетевых сокетов | AC-F1 (AST) |
| I-1a | Явное уточнение (2026-11-18, по итогам ревью): `subprocess` **не** запрещён — `reader.py` штатно запускает `journalctl -f` (SPEC-20261116-vpn-guard §10.4). AST-тест запрещает сеть/`sudo`/`systemctl`/failover во всех пяти модулях, а `subprocess` — в четырёх (`parse`, `window`, `rules`, `correlate`); исключение для `reader.py` зафиксировано в docstring теста | AC-F1 |
| I-2 | `vpn guard sync` — единственная сетевая команда **guard-а** | ревью + существующий тест |
| I-3 | Секреты не попадают в argv, журнал, `export`, `failover_history.jsonl` | AC-F10 |
| I-4 | Артефакты 0600 / каталог 0700, bounded, через `store.py` | AC-F11 + `selftest` |
| I-5 | Юнит `vpn-*` не подпадает под `runners.enabled_vpnm_units()` | AC-F11 |
| I-6 | `config.failover.enabled` по умолчанию `false` | AC-F8 + `selftest` |
| I-7 | Desktop-уведомления opt-in (`notify.failover_desktop=false`) | §8.1 |

---

## 3. Триггеры

`should_trigger(incident, state, activity) -> TriggerDecision` — все условия
должны выполниться одновременно.

| Условие | Значение |
|---|---|
| `config.failover.enabled` | `true` (дефолт `false`) |
| активный профиль ∈ `config.failover.trigger_profiles` | дефолт `["asv2-reality"]` (route `direct`, proto `xray-reality`) |
| нет подавления локальными маркерами | нет активного `activity_scope("down"/"reset")` (§3.2) |
| правило инцидента | `G-01` (severity `high`) **или** `G-09` (severity `≥ medium` при подтверждённом локе) |
| **или** `expected_lockdown` | `server-verdict.json` свежий (≤10 мин) и `lockdown.active == true` |
| cooldown | с прошлого переключения `≥ 900 с` (монотонные часы; при ребуте — `wall_ts`) |
| rate limit | `< 3` переключений за последний час |

### 3.1 Почему набор триггеров именно такой

- `G-01 no_handshake_after_start` (25 с без handshake, **high**, `tunnel_down`)
  — прямая подпись серверного `DROP` на 443/tcp.
- `G-09 endpoint_silent` (≥5 pre-handshake сбоев на host:port за 10 мин,
  **medium**, `endpoint_unreachable`) — то, как лок часто выглядит на клиенте
  при REJECT-семантике. Поэтому «severity ≥ medium» **только для G-09**;
  общий порог `high` остаётся.
- `G-02 reset_storm` / `G-03` / `G-04` — подписи **ТСПУ**, не серверного лока.
  Переключение по ним возможно в v2, но требует отдельного решения: там
  смена канала не обязательно помогает (ТСПУ режет весь 443 независимо от
  маршрута).
- **`expected_lockdown` — производное условие, а не категория**: в каталоге
  `rules.py` нет категории `expected_lockdown` (есть `local_net`, `local_fault`,
  `config`, `dns`, `tunnel_down`, `censorship_suspect`, `endpoint_unreachable`,
  `degraded`, `observability`). Считать флагом: `server_verdict.lockdown.active`
  + профиль в `trigger_profiles`.

### 3.2 Подавление ручной остановкой

Отдельного `desired_state` в `activity.json` **нет** и заводить не нужно.
Используем существующий механизм `store.activity_scope` / `activity_active`:

- `vpn down` оборачивается в `activity_scope("down")`, `vpn reset` —
  в `activity_scope("reset")`; в `ACTIVITY_GRACE_S` добавляются
  `"down": 300`, `"reset": 300`.
- `should_trigger` отказывает, если `store.activity_active("down")` или
  `activity_active("reset")`.

Это переиспользует FP-guard-механизм вместо параллельного флага состояния.

---

## 4. Лестница кандидатов

### 4.1 Виды кандидатов

Лестница смешивает **схему** и **профили**, и это надо различать явно:

```python
Candidate = namedtuple("Candidate", "id kind argv")   # kind: "scheme" | "profile"
LADDER = [
    Candidate("relay",     "scheme",  ["vpn", "start", "relay"]),
    Candidate("asv2-hy2",  "profile", ["vpn", "switch", "asv2-hy2"]),
    Candidate("asv2-awg",  "scheme",  ["vpn", "start"]),          # AWG-split
    Candidate("asv2-cdn",  "profile", ["vpn", "switch", "asv2-cdn"]),
]
```

`relay` и `asv2-awg` — **схемы** (требуют root: `awg`/`nft`), остальные —
socks-профили. Для схем обязателен `sudo -n`; отсутствие sudo →
`Attempt(result="switch_error")`, не падение.

### 4.2 Проход

Для каждого кандидата (по порядку):

1. **Пропуск по индивидуальному cooldown** — 600 с после `dead_entry`/`dead_exit`.
   Не пропускать, если в cooldown **все** кандидаты (иначе лестница «пустая» и
   blackout наступает без попыток).
2. **`pre_flight(candidate)`, бюджет 2.0 с** — достижимость endpoint'а:
   - `profile` (TCP/TLS): TCP-handshake до `host:port` из конфига профиля;
   - `scheme:relay`: UDP-маршрутизируемость до endpoint релея (**0 байт**, тот же
     приём, что в `vpnm/scout/probes.py::_udp_local_route`);
   - `scheme:awg`: маршрут есть, `awg show` не отдаёт «Address family not
     supported» (иначе это наша ошибка прав, а не смерть канала).
   Провал → `Attempt(result="dead_entry")`, **switch не вызывается**.
2a. **Гашение tun-схемы перед socks-ступенью** (2026-11-18, по итогам приёмки).
   Если исходный канал поднят как `vpn start reality` / `vpn scheme xray-split`
   (tun `xray0`), а кандидат — **профиль** (`asv2-hy2`, `asv2-cdn`), то перед
   switch схема снимается (`xsplit.stop`): мёртвый `xray0` не должен остаться в
   таблице маршрутизации над живым резервом. Схемные ступени (`relay`,
   `asv2-awg`) снимают прямой контур сами внутри `vpn start relay` / `vpn start`
   (`_teardown_direct`). Сбой гашения → статус `teardown_failed`, переключение
   **не** выполняется (лучше не переключить, чем сложить два контура).
   Права: `sudo -n` — `vpn-failover.service` это user-юнит без TTY, пароль
   спросить некому; на ноутбуке passwordless sudo уже есть
   (`1_ubuntuStart.sh` → `/etc/sudoers.d/90-nopasswd`).
2b. **Источник активного канала.** `state.json.active` покрывает только socks;
   tun-схема определяется из юнита `vpn-xray-split@<profile>` (см. §3).
3. **switch** — `Candidate.argv` через `RunCmd` (без `shell=True`). Ненулевой код →
   `Attempt(result="switch_error")`.
4. **`post_flight(candidate)`, бюджет 4.0 с:**
   - сквозная проверка: egress/`probe` **через поднятый канал**; для AWG —
     дополнительно рост `rx_bytes` пира после handshake;
   - схемные ступени (`relay`, `asv2-awg`) пробуются **дважды** (пауза 1.5 с):
     холодный старт AWG-плеча не укладывается в один 4-секундный проб (живой
     прогон 2026-11-18: healthy relay дал ложный `egress_empty` за 6.6 с);
   - провал → `Attempt(result="dead_exit")` + **немедленно следующий кандидат**
     (релей жив, но его связь с exit оборвана);
   - `candidate_cooldown` 600 с ставится только **профильным** ступеням
     (`asv2-hy2`, `asv2-cdn`). Схемная ступень после двух проб — «недоказана»,
     а не «мертва»: вычёркивать предпочтительный резерв на 10 минут нельзя;
   - успех → `vpn guard sync` (read-only, один ssh) для подтверждения
     `expected_lockdown`; при недоступности sync — **не считать это провалом**
     канала (связь уже доказана), просто `lockdown_confirmed=false`.
5. **Успех:** pin на профиле, уведомления (§8), строка в `failover_history.jsonl`,
   выход.

### 4.3 Pin

`pin = {profile, since, reason, lockdown_active}` в `failover_state.json`.
Pin **не** запрещает человеку переключаться вручную — он только:
- подавляет повторный failover с того же профиля;
- служит основанием для §6 (снятие лока).

### 4.4 Detect-1: in-tunnel liveness (2026-11-18, по итогам приёмки)

**Проблема.** `vpn guard` записывает `xray=blind` (парсер app-сигналов — WP-G2),
а сгенерированный конфиг xray не имел `log`-секции: при обрыве 443/tcp в
журнале **не появляется ничего**. Значит `G-01`/`G-09` в середине сессии не
срабатывают, и без ручного `vpn guard sync` ноутбук остаётся на мёртвом `xray0`.

**Решение.** Периодическая проверка живости **сквозь туннель**, без парсинга
логов:

- `vpn-failover.timer` (user, `OnUnitInactiveSec=60s`) будит тот же oneshot;
- при активном профиле из `trigger_profiles`, поднятом как tun-схема
  (`source_via_xsplit`), агент делает
  `curl --interface xray0 https://<split-домен>/generate_204` — трафик идёт
  **внутрь туннеля** и выглядит как обычный запрос: никаких внешних коннектов
  к собственному 443 и никакого демаскирующего паттерна;
- счётчик `liveness_failures`: успех сбрасывает в 0, провал инкрементит;
- **обязательное условие** перед засчитыванием провала — `local_net_check()`
  (мёртвый локальный аплинк не является отказом туннеля);
- при `liveness_failures >= failover.liveness_failures` (2) → производный
  триггер `active_probe_dead` → обычная лестница §4.2 (cooldown/rate-limit/
  pin/уведомления те же).

**Конфиг:** `failover.liveness_enabled` (true), `liveness_interval_sec` (60,
30…600), `liveness_failures` (2, 2…10).

**Границы v1:** проверка выполняется только для tun-схемы (`xray0`); для
socks-профилей детекта нет (там мгновенный egress уже даёт `post_flight`).
Новое правило в каталог `G-01…G-12` **не вводится** — каталог заморожен
ADR-014; `active_probe_dead` живёт в контуре failover, не в guard.

**Диагностический слой (Detect-2) отложен:** в генератор конфига xray добавлен
`"log": {"loglevel": "warning"}`, чтобы журнал перестал быть немым, но разбор
этих строк (`G-13` и т.п.) — отдельная работа после сбора полевых логов.

---

## 5. Total blackout

Все кандидаты вернули `dead_entry` / `switch_error` / `dead_exit`:

1. Ровно **один** проход по лестнице (без повторов внутри вызова).
2. Backoff `120 → 300 → 900` с (потолок 900); счётчик сбрасывается после
   успешного переключения или ручного `vpn guard failover reset`.
3. **Гарантия провайдерского трафика** (2026-11-18, по итогам приёмки): если
   `kill_switch` **не** включён, агент обязан вернуть связь, а не просто
   «вызвать `vpn down`»:
   - user-scope `vpn down` (останов профилей и tun-схемы);
   - проверка egress по провайдерскому маршруту (`curl api.ipify.org`);
   - если маршрут всё ещё мёртв — root-`vpn reset` (снимает и релейный контур);
   - повторная проверка; результат честно пишется в уведомление и историю
     («трафик у провайдера подтверждён» / «НЕ подтверждён — проверьте вручную»).
   Оба вызова используют **абсолютный путь** CLI: в user-юните PATH не содержит
   `~/.local/bin`, и голое `vpn` молча падало (найдено в приёмке).
   `kill_switch=true` — явный fail-closed, маршрут не трогается.
4. Desktop `urgency="critical"` (если opt-in включён) + событие
   `total_blackout` в `pending_alerts.jsonl`.
5. **Восстановление (`recovered`).** В состоянии backoff агент проверяет TCP
   до сервера триггерного профиля. Если сервер снова отвечает: выполнить
   `vpn reset` (чистое состояние), обнулить `backoff`/`pin`/`liveness_failures`,
   записать событие `recovered`, уведомить «сервер снова доступен, трафик у
   провайдера; подключиться: `vpn scheme xray-split <profile>`».
   **Авто-переподключения нет** — OQ-4 (решение за человеком); смысл шага в том,
   чтобы после аварии машина осталась в известном чистом состоянии, а не с
   обломками mode/юнитов.

---

## 6. Снятие серверного лока — БЕЗ авто-возврата

Если `pin.lockdown_active == true` и свежий `server-verdict.json` принёс
`lockdown.active == false`:

- профиль **остаётся** на текущем;
- снять `pin.lockdown_active`;
- тихий Desktop-баннер (при opt-in) и Telegram:
  `ℹ️ [client] Серверный lockdown на 443/tcp снят. Вы остаётесь на профиле
  <current_profile>. Для возврата: vpn switch asv2-reality`.

Причина запрета: возврат в 443/tcp через 48 ч — это новый цикл проб; человек
должен решать сам, тем более что за 48 ч мог смениться операторский контекст.

---

## 7. Конфиг (в существующем `~/.config/vpn-manager/guard.json`)

Расширение `store.py::DEFAULT_CONFIG` и валидатора (только известные ключи,
как сейчас):

```json
{
  "failover": {
    "enabled": false,
    "trigger_profiles": ["asv2-reality"],
    "ladder": ["relay", "asv2-hy2", "asv2-awg", "asv2-cdn"],
    "cooldown_sec": 900,
    "max_switches_per_hour": 3,
    "candidate_cooldown_sec": 600,
    "backoff_sec": [120, 300, 900],
    "pre_flight_timeout_sec": 2.0,
    "post_flight_timeout_sec": 4.0,
    "confirm_lockdown_via_sync": true,
    "kill_switch": false
  },
  "notify": {
    "desktop": false,
    "min_severity": "high",
    "failover_desktop": false,
    "telegram": {
      "bot_token_file": "~/.config/vpn-manager/telegram.token",
      "chat_id": "",
      "timeout_sec": 4.0
    }
  }
}
```

Правила валидации: `enabled`/`failover_desktop`/`kill_switch` — bool;
`cooldown_sec` 60…7200; `max_switches_per_hour` 1…20;
`candidate_cooldown_sec` 60…3600; `backoff_sec` — возрастающая
последовательность ≤ 3 элементов, каждый 30…3600; таймауты 0.5…10.0;
`ladder` — подмножество известных id; `trigger_profiles` — существующие имена
профилей (несуществующие → warning, не ошибка: профиль мог не импортироваться).

---

## 8. Уведомления

### 8.1 Desktop — отдельный opt-in

- Флаг **`notify.failover_desktop`**, дефолт **`false`** (решение владельца
  2026-11-18). Не наследует `notify.desktop` и не переопределяет его.
- Отправка через существующий `vpnm/guard/notify.py` (класс `Notifier`):
  аргументный вызов `notify-send`, `shell=False`, таймаут 2.0 с, тело через
  `redact_raw`. Отсутствие бинаря/D-Bus → `status="unavailable"`, без падения.
- `urgency`: `normal` для старта/успеха, `critical` — только total blackout.

**Шаблоны:**

| Событие | Заголовок | Тело |
|---|---|---|
| старт | `⚠️ VPN Guard: прямой канал недоступен` | `Профиль <from> (443/tcp) не отвечает. Переключаю на резерв (<first_candidate>)...` |
| успех на relay | `✅ VPN переключён на relay` | `Канал <from> закрыт защитой сервера (lockdown). Связь через relay активна.` |
| успех на резерве №2+ | `🟠 VPN переключён на <to> (relay недоступен)` | `Канал <from> закрыт. Резерв relay пропущен (<reason>). Связь восстановлена через <to>.` |
| blackout | `🚨 VPN Guard: ВСЕ резервные каналы недоступны!` | `Проверены: <attempted>. Локальный интернет: ЕСТЬ. Повтор через <backoff> с.` |

### 8.2 Telegram (клиент)

- Токен — **только из файла** `notify.telegram.bot_token_file`; файл с правами
  шире `0600` → warning в статус, но чтение продолжается.
- Токен **никогда** не попадает в текст исключений: `URLError` содержит URL —
  перехват и очистка до логирования (`redact` + `str.replace` по токену).
- `POST https://api.telegram.org/bot<TOKEN>/sendMessage`, поля `chat_id`,
  `text`, `disable_web_page_preview=true`, `timeout=4.0`.
- Сбой → `enqueue_pending_alert()` в `pending_alerts.jsonl`
  (0600, ≤50 записей, ≤1 МБ, FIFO), статус `queued`.

**Отчёт клиента** (после успешного подъёма):

```text
🔄 [client: <hostname>] Авто-переключение VPN
• Было: <from> (причина: <trigger_rule> / <lockdown_status>)
• Стало: <to> — ONLINE (<latency_ms> ms)
• Цепочка попыток: <attempts_summary>
• Примечание: <"штатный переход на relay" | "⚠️ ВНИМАНИЕ: узел relay недоступен (dead_entry/dead_exit), проверьте релей!">
```

### 8.3 Досылка очереди

`flush_pending_alerts()` вызывается: после успешного `post_flight`; в
`vpn guard sync`; при `vpn guard failover status`. Отправляет с префиксом
`[Отложенное уведомление от <ts_utc>]`, при успехе атомарно переписывает файл.

---

## 9. Артефакты, приватность, redact

| Файл | Права | Лимит | Назначение |
|---|---|---|---|
| `guard/failover_state.json` | 0600 | ≤16 КБ | pin, cooldown-метки, backoff-счётчик, `lockdown_active` |
| `guard/failover_history.jsonl` | 0600 | 5 × 4 МБ, 14 дней (как `findings.jsonl`) | `Attempt`-строки, итоги переключений |
| `guard/pending_alerts.jsonl` | 0600 | ≤50 записей / ≤1 МБ | очередь Telegram |

Все три — через `store.py` (атомарная запись 0600, каталог 0700) и **со
схемами** в `vpnm/guard/schemas/`, чтобы `schema_hashes()` и
`vpn guard selftest` оставались осмысленными (новые имена аддитивны:
`guard.failover_state/1`, `guard.failover_history/1`, `guard.pending_alerts/1`).

`redact.py`: добавить паттерн `\b\d{8,10}:[A-Za-z0-9_-]{35}\b` →
`<redacted:tg_token>`; он же попадает в пост-сканер секретов `export`
(`vpn guard export` обязан ловить утёкший токен, AC-F10).

---

## 10. Серверная часть (`vds`)

### 10.1 Защита allow-list и релея в `auto-lockdown`

- Ключа `relay_ips` **не существует** — используем существующий контракт:
  `lockdown_allow` (`probing.py::2298`) + `load_own_ips()`.
- Требование: если релей настроен в gateway `state.json` (пир/endpoint релея)
  и его IP **не** покрыт `lockdown_allow` **и** не входит в `own_ips` — при
  `--auto-lockdown on` печатать предупреждение с адресом для добавления
  (`relay` ходит в exit по AWG/udp, но правило должно быть явным, а не
  подразумеваемым).
- `build_lockdown_plan` уже ставит `allow from <ip> to any port 443 proto tcp`
  **перед** изъятием широкого allow (`ufw.py::1495+`) — инвариант сохранить и
  покрыть тестом AC-F12.

### 10.2 Событие снятия лока — реальный пробел

`src/alert/watch.py` сегодня отправляет `lockdown_on` и `lockdown_still`
(строки ~504-527) и **не отправляет ничего при снятии**: блок исполняется
только под `if active:`. Требуется:

1. Добавить `lockdown_off` в `TITLES` и `ROUTING_KINDS`.
2. В переходе `prev_active and not active` — отправить `lockdown_off` с
   причиной снятия (`ttl-expired` / ручной `--unlock`) и `since`.
3. Событие `lockdown_on` **уже** содержит `lockdown_reason`, `ttl_until`,
   `allow_from_count` и маршрутную подсказку (`routing_advice`) — **не
   дублировать**, только дополнить перечнем живых транспортов, если его там
   нет.

---

## 11. Поправки к ТЗ (обязательны к применению кодером)

| ТЗ говорит | Реальность / как делать |
|---|---|
| «новый `vpnm/guard/notify.py`, класс `GuardNotifier`» | `notify.py` **существует**, класс `Notifier` (desktop, opt-in, rate-limit). Расширять его; `GuardNotifier` не вводить |
| «новый `install.py`, `cli.py`» | оба существуют — юниты и подкоманды добавляются в них |
| `severity in ("high","critical")` | `critical` в словаре severity **нет** (`SEVERITIES = info/low/medium/high`); `critical` — только urgency `notify-send` |
| категория `expected_lockdown` | такой категории нет — это **производное** условие из `server-verdict.json` (§3.1) |
| `config.relay_ips` | нет; есть `lockdown_allow` + `load_own_ips()` |
| `activity.json.desired_state` | нет; `store.activity_scope("down"/"reset")` + `ACTIVITY_GRACE_S` (§3.2) |
| `pending_alerts.jsonl` «просто файл» | через `store.py` + схему, иначе `selftest`/`schema_hashes` разъедутся |
| desktop безусловно | opt-in `notify.failover_desktop=false` (§8.1) |
| сервер: алерт при входе в лок | **уже реализовано** (`lockdown_on`); новое — только `lockdown_off` (§10.2) |

---

## 12. WP-план

| WP | Содержание | Файлы |
|---|---|---|
| WP-F1 | Конфиг + валидатор + схемы артефактов | `store.py`, `schemas/` |
| WP-F2 | `failover.py`: триггеры, `local_net_check`, `pre/post_flight`, лестница, pin, blackout, backoff | `guard/failover.py` |
| WP-F3 | Уведомления: desktop-флаг, Telegram, очередь, flush | `guard/notify.py` |
| WP-F4 | `redact`-паттерн токена + пост-сканер export | `guard/redact.py` |
| WP-F5 | Юниты `vpn-failover.service`/`.path` + `install/uninstall` | `guard/install.py` |
| WP-F6 | CLI: `failover status\|run --once\|reset\|enable\|disable\|test-notify` | `guard/cli.py` |
| WP-F7 | Маркеры `down`/`reset` в `vpn down`/`vpn reset` | `cli.py`, `store.py` |
| WP-F8 | Сервер: предупреждение allow-list/релея + `lockdown_off` | `vds`: `probing.py`, `alert/watch.py` |
| WP-F9 | Тесты 12 AC + документы (docsync) | `tests/`, `doc/*.md`, `docs/*.md` |

---

## 13. AC (критерии приёмки)

| AC | Проверяемое | Тест |
|---|---|---|
| AC-F1 | guard-ядро read-only: нет `subprocess`/`sudo`/`systemctl`/failover-импортов в `reader/parse/window/rules/correlate` | AST-тест |
| AC-F2 | happy path: reality↓ → pre(relay) ok → switch ok → post ok → sync подтверждает → desktop+tg | моки |
| AC-F3 | `pre_flight(relay)=False` → switch(relay) **не вызван** → switch(asv2-hy2) → TG предупреждает о `dead_entry` | моки |
| AC-F4 | `dead_exit` релея → немедленно hy2; в отчёте `relay: dead_exit` | моки |
| AC-F5 | blackout: ровно один проход, backoff 120 с, critical-баннер, tg в очередь | моки часов |
| AC-F6 | очередь досылается на следующем успехе/`sync` и очищается | моки |
| AC-F7 | `local_net_check=False` → ни одного switch, `suppressed_local_net_down` | моки |
| AC-F8 | `enabled=false` (дефолт) и активный `activity_scope("down")` → не срабатывает | моки |
| AC-F9 | cooldown 900 с: повтор через 60 с игнорируется; `lockdown.active=false` → без авто-отката, только инфо | моки часов |
| AC-F10 | токен не утекает: `URLError` с URL бота → ни в логах, ни в истории, ни в `export`; пост-сканер ловит фикстуру | фикстура `FIXTURE_TG_TOKEN` |
| AC-F11 | юниты `vpn-failover.*` создаются; `runners.enabled_vpnm_units()` их игнорирует; `selftest` зелёный | `install.py` + `runners.py` |
| AC-F12 | (vds) при авто-локе правило allow для relay-IP **выше** блокирующего 443/tcp; при пустом allow — предупреждение | `tests/` vds |

**Фикстуры секретов** — только значимые префиксы (`FIXTURE_TG_TOKEN_...`),
никаких «правдоподобных» токенов (AGENTS.md §6).

---

## 14. Тест-план

- Все часы (`mono_ns`, `wall_ts`), сеть (`pre/post_flight`, `local_net_check`,
  HTTP к Telegram) и `switch` — **инъектируемые** зависимости. Никаких `sleep`
  и реальных сокетов.
- `tests/guard/test_failover.py` — AC-F1…F11; `vds/tests/` — AC-F12.
- Регресс: существующие `tests/guard` должны остаться зелёными; `selftest`
  покрывает новые схемы.
- Живая приёмка (после G2): на ноутбуке с `enabled=true` и искусственно
  закрытым 443 — один переход на relay, затем `failover reset`.

---

## 15. Влияние на документацию (docsync)

| Путь | Что обновить |
|---|---|
| `ubuntuInstaller/doc/vpn-manager.md` | раздел `vpn guard failover`, конфиг, opt-in флаг, шаблоны уведомлений |
| `ubuntuInstaller/doc/PROGRAM_DESCRIPTIONS.md` | пункт про `vpn-failover` |
| `vds/README.md`, `vds/AGENTS.md` | `lockdown_off`, предупреждение allow-list |
| `vds/docs/SERVER-BASELINE.md` §5.15 | `lockdown_off` в списке событий |
| `vds/docs/team/specs/SPEC-20261116-probe-response.md` §16 | пометка «до WP-FAILOVER» + ссылка сюда |

---

## 16. Открытые вопросы

| OQ | Вопрос | Статус |
|---|---|---|
| OQ-1 | Desktop по умолчанию: opt-in флаг или безусловно | **закрыто 2026-11-18 (G2)** — отдельный opt-in `notify.failover_desktop=false`; на снятии лока (`lockdown_off`) — только уведомление, без авто-возврата |
| OQ-2 | Включать ли `G-02`/`G-03` (ТСПУ-подписи) в триггеры | **закрыто для v1 (G2)** — `G-02 reset_storm` **не** триггерит `vpn-failover` (только обычный finding/рекомендация `guard`): нельзя смешивать реакцию на серверный `lockdown` с реакцией на ТСПУ RST-инжект. Расширение — после полевой телеметрии |
| OQ-3 | Нужен ли `--with-udp`-лок как триггер (`G-04`) | **закрыто 2026-11-18 (arch-lead)** — для `asv2-reality` (443/tcp) серверный лок ловится через `G-01` (`dial_timeout`/`conn_refused`) и `G-09` (`endpoint_silent`). `G-04` (`tx_no_rx`/`awg_tx_no_rx`) — подпись тишины UDP/туннеля, релевантная только если в `trigger_profiles` попадут UDP/AWG-профили (`asv2-awg`, `relay`). Пока там только `["asv2-reality"]`, в v1 **выключен** — защита от ложных срабатываний при кратком простое трафика |
| OQ-4 | Возврат на прямой канал после снятия лока: авто или вручную | **закрыто** — вручную (ADR-015): `lockdown_off` только снимает `pin.lockdown_active` и уведомляет |
| OQ-5 | Хранить ли клиентский TG-токен на ноутбуке или слать через сервер | **закрыто 2026-11-18** (с поправкой к формулировке решения): файл **user-scope** `~/.config/vpn-manager/telegram.token` (тот же каталог, что `guard.json`; `$XDG_CONFIG_HOME` учитывается), права 0600, владелец — пользователь, токен только на клиенте, в конфиг пишется лишь путь `bot_token_file`. `/etc/vpnm/telegram.token` (root:root 0600) **отклонён**: `vpn-failover.service` — user-юнит (ADR-015), root-only файл ему не читается и канал молча деградировал бы в `telegram_no_token`; этот путь станет валиден только при переводе юнита в system-scope (отдельное решение, не v1) |
