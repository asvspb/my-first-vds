# SPEC-20261117-alert-watch — сторож угрозы на exit-узле: уведомления, heartbeat, деградация вместо ложных тревог

## Мета
- **Источник:** [REQ-20261117-alert-watch](../requirements/REQ-20261117-alert-watch.md) ←
  [research/notifications-and-resilience-2026-11-17.md](../../research/notifications-and-resilience-2026-11-17.md)
  (§6 «Сверка с кодом» принят как истина; формулировки исходного диалога с Gemini —
  нет).
- **Автор:** архитектор
- **Дата:** 2026-11-17
- **Статус:** **approved (G2)** — по объёму FR-1…FR-7. FR-8/FR-9 **вне этого цикла**
  (OQ-1/OQ-8 не закрыты), см. §9.2.
- **ADR:** **не требуется** (см. §9.3 — все решения обратимы и не меняют публичный
  контракт; новая CLI-команда аддитивна). Если цикл FR-8 выберет отдельный `awg2` /
  новый межузловой порт — ADR обязателен **в том цикле**.
- **Ревьюеры:** `vds-coder` (реализуемость), `vds-tester` (тест-план),
  `vds-debugger` (форензика по тегам).

---

## 0. TL;DR для кодера (что именно строим)

1. Новый пакет `src/alert/` + юнит `vds-alert-watch.{service,timer}` на **exit-узле**.
   Тик по умолчанию 2 мин, только чтение телеметрии, отправка в Telegram и/или SMTP
   на **stdlib**, состояние в `/var/lib/vds/alert-state.json`.
2. Пять источников сигнала: `threat` из `/var/lib/vds/probe-watch.json`, пульс
   плеча relay→exit (`awg show awg0 dump` + пир из `state.json`), доступность релея
   (TCP до `endpoint` пира), активный `lock-443` (`state.json["ufw_lockdown"]`),
   heartbeat.
3. **Главная поправка к REQ** (обоснование — §3.1): возраст handshake **сам по себе
   не является признаком блокировки**. На релее `awg1` по умолчанию **без**
   `PersistentKeepalive` (`src/amneziawg/config.py::ClientParams.keepalive = None`,
   решение И44), поэтому в простое handshake законно стареет часами. Пульс валиден
   только при **гейте активности**: трафик через ногу шёл недавно (`rx` пира вырос
   в пределах окна) ИЛИ состояние уже было классифицировано как проблемное.
   Иначе — `inconclusive` (не алерт).
4. **Телеметрия недоступна ≠ тихо**: отсутствующий/битый/устаревший
   `probe-watch.json`, недоступный `awg`, ненайденный пир-релей — это отдельный
   сигнал `telemetry_unavailable` и `ALERT-SKIP`, а не «канал мёртв».
5. Сторож **не** мутирует `probe-watch.json`, **не** вызывает `watch --record`,
   **не** дублирует `--auto-lockdown`. Он читает `state.json` только на чтение.

---

## 1. Цель и решение

Владелец должен узнать о блокировке/волне проб без включённого ноутбука. Уведомление
отправляет **зарубежный exit-узел** (на RU-рееле секретов нет и не будет — релей
считается отчуждаемым). Строим один независимый `oneshot`-таймер, который раз в
2 минуты читает уже существующую телеметрию (`probe-watch.json`, `awg show`,
`state.json`) и при **переходе** состояния отправляет одно короткое сообщение в
Telegram и/или SMTP (stdlib, без зависимостей). Heartbeat раз в сутки — dead-man
switch: «нет heartbeat» = сигнал проверить узел, а не «всё хорошо».

Почему отдельный юнит, а не хук в `vds gateway healthcheck` (OQ-7, обоснование §3.7):
разные домены отказа, разные каденции (5 мин против 2 мин), healthcheck уже имеет
**мутирующую** роль (rate-limited рестарт) и свои exit-коды, а главное — healthcheck
не должен читать файл с токенами: расширение поверхности секретов в компонент,
чей смысл — быть видимым в journal, недопустимо.

---

## 2. Архитектура

```
exit-узел (asv2)                                          канал доставки
┌──────────────────────────────────────────────────────┐   ┌───────────────┐
│ vds-alert-watch.timer (2m)                           │   │ api.telegram  │
│        │                                              │   │ .org/bot…     │
│        ▼                                              │   └──────▲────────┘
│ vds-alert-watch.service (oneshot, root)              │          │ urllib
│        │                                              │   ┌──────┴────────┐
│        ├─ checks.read_threat ───── /var/lib/vds/…json│   │ SMTP_SSL      │
│        │   (только чтение; missing/corrupt/stale     │   │ (:465)        │
│        │    различаются)                             │   └──────▲────────┘
│        ├─ checks.read_relay_signal ── awg show awg0  │          │ smtplib
│        │   dump + $INSTALL_DIR/gateway/state.json    │          │
│        ├─ checks.read_lockdown ───── state.ufw_lockdown          │
│        │                                              │          │
│        ├─ state.decide(event, severity, prev, now)  ──► cooldown │
│        │   (чистая функция: send / cooldown /         │  rate    │
│        │    duplicate / rate_limited / escalation)    │  limit   │
│        ▼                                              │          │
│   channels.send_all ──────────────────────────────────┼──────────┘
│        │                                              │
│        ▼                                              │
│   journal: ALERT-SENT / ALERT-FAILED / ALERT-SKIP     │
│   /var/lib/vds/alert-state.json (0600, FileLock)      │
└──────────────────────────────────────────────────────┘
        ▲                      ▲
        │ читает (не пишет)    │ читает (не пишет)
/var/lib/vds/probe-watch.json   /etc/vds/alert.env (0600, root)
(пишет только vds-probe-watch)  (единственный носитель секретов)
```

Точки отказа и их поведение — §5.4. Ключевой инвариант: **отсутствие данных никогда
не превращается в тревогу**.

Ограничение, которое надо принять сознательно: threat-level считается **часовым**
тиком `vds-probe-watch`, поэтому переход `quiet→elevated` доедет до владельца с
задержкой до 1 ч. Пульс плеча и доступность релея — с задержкой ≤ 1 тик (2 мин).
Это записано в §8 (риск R-2) и явно печатается в сообщении (`level since …`).

---

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/alert/__init__.py` | создать | маркер пакета + границы (только уведомления, без авто-действий) |
| `src/alert/paths.py` | создать | пути/юниты/лок-файл: `ALERT_ENV_PATH=/etc/vds/alert.env`, `ALERT_STATE_PATH=/var/lib/vds/alert-state.json`, `ALERT_LOCK_FILE=/var/run/vds-alert-watch.lock`, `ALERT_UNIT`, `ALERT_TIMER`, `PROBE_WATCH_PATH` (зеркало `SNAPSHOT_PATH`, см. ниже) |
| `src/alert/env.py` | создать | схема `alert.env`: парсинг/рендер, `parse_duration`, `AlertConfig`, маскирование |
| `src/alert/state.py` | создать | `alert-state.json`: load/save (0600, атомарно), `decide()` (чистая), учёт отправок и backoff |
| `src/alert/channels.py` | создать | `send_telegram` / `send_smtp` / `send_all` на stdlib, классификация ошибок без утечки секретов |
| `src/alert/checks.py` | создать | чистые парсеры и сигналы: `parse_awg_dump`, `read_threat`, `read_relay_signal`, `classify_relay`, `read_lockdown` |
| `src/alert/watch.py` | создать | тик: собрать сигналы → `decide` → отправить → теги → сохранить состояние; heartbeat |
| `src/alert/cli.py` | создать | `cmd_install` / `cmd_remove` / `cmd_test` / `cmd_status` (dry-run по умолчанию) |
| `systemd/vds-alert-watch.service.tpl` | создать | oneshot, `ReadWritePaths=/var/lib/vds /var/run`, caps `NET_ADMIN NET_RAW` |
| `systemd/vds-alert-watch.timer.tpl` | создать | `OnBootSec=3min`, `OnUnitActiveSec={interval_sec}s` |
| `src/main.py` | изменить | `alert_app` + 4 публичные + 1 служебная команда, **ленивые импорты** внутри функций |
| `src/logs/collect.py` | изменить | `WATCH_UNITS += "vds-alert-watch.service"`; журнальный excerpt в бандл — чтобы доставка была видна в конвейере ADR-012 |
| `docs/doc-sync.json` | изменить | правило `alert` (`src/alert/**` → README, AGENTS, SERVER-BASELINE, DEPLOY) |
| `README.md`, `AGENTS.md`, `docs/SERVER-BASELINE.md`, `docs/DEPLOY.md`, `docs/DEPLOY-RU-RELAY.md` | изменить | команда, юниты, секреты, шаг установки, precondition keepalive |
| `docs/research/notifications-and-resilience-2026-11-17.md` | изменить | пометка «реализовано» после приёмки (не раньше) |
| `TECHDEBT.md` | изменить | P24 (FR-8), P25 (FR-9) — см. §9.2 |

Удаляемых файлов нет. `src/gateway/probing.py`, `src/gateway/health.py`,
`src/system/ufw.py`, `src/gateway/store.py`, `systemd/vds-probe-watch.*`,
`systemd/vds-gateway-health.*` — **не трогаем** (§9.1).

### 3.1. Решение по FR-1 п.2–3: как exit читает пульс и как классифицирует

**Откуда берётся пир-релей.** На exit-узле релей — это *AWG-клиент* (`vds amneziawg
add-client relay`), а не протокол `relay` в `state.json`. Поэтому endpoint релея
**нельзя** взять из `state.protocols["relay"]` (это поле живёт на релее, REQ §FR-1
п.3 здесь неточен). Источник — `state.json` exit-узла: `clients[]` с
`protocol == "amneziawg"` и `name == ALERT_RELAY_PEER` (по умолчанию `"relay"`),
поля `extra.address` (`10.9.0.X/32`) и `extra.public_key`.

**Точная команда и парсинг.** Один вызов:

```
awg show awg0 dump
```

Формат `wg`/`awg dump`: первая строка — интерфейс (4 поля), далее по строке на пир
(8 полей через табуляцию):

```
<public_key> <preshared_key> <endpoint> <allowed_ips> <latest_handshake> <rx> <tx> <keepalive>
```

Пир опознаётся по совпадению `public_key` (приоритет) или `allowed_ips` с
`extra.address`. Из строки берём: `endpoint` (→ публичный IP релея для TCP-пробы),
`latest_handshake` (→ возраст через существующую `src/relay/config.py::handshake_age`,
переиспользуем, не дублируем), `rx` (→ гейт активности).

**Формат `dump` — предположение, требующее подтверждения на живом узле.** В этом
репозитории `awg show … dump` ещё не используется (есть только
`latest-handshakes`/`endpoints`/`endpoints`-парсеры), поэтому `parse_awg_dump`
обязан быть **терпимым**: табы и пробелы, любое число полей ≥ 8, непарсящиеся числа
пропускаются, пустой/битый вывод → `{}`. Никакого «додумывания»: если формат на
asv2 окажется иным, сторож уходит в `inconclusive` (не в ложную тревогу), а дефект
чинится в `checks.py` без изменения остальных слоёв. Подтверждение формата —
пункт AC-13 приёмки.

**Классификация (чистая функция, таблица истинности):**

| handshake (возраст) | активность ноги¹ | TCP до релея | итог |
|---|---|---|---|
| `< threshold` (300 с) | любая | любая | `ok` |
| `>= threshold` или `-1` (не было) | есть | `True` | **`blocked`** (трансграничный ТСПУ на плече) |
| `>= threshold` или `-1` | есть | `False` | **`relay_down`** (релей лёг / обратный путь) |
| `>= threshold` или `-1` | есть | `None` (проба не удалась) | `inconclusive` |
| `>= threshold` или `-1` | нет | любая | `idle` (не показательно — не алерт) |
| нет данных о пире / `awg` недоступен / state не читается | — | — | `inconclusive` |

¹ «активность ноги»: в state хранится `last_traffic_ts` — момент, когда дельта `rx`
пира между двумя тиками была > 0. Нога считается активной, если
`now − last_traffic_ts <= max(3 × interval, 10 мин)`. Это и есть «по ноге недавно
шёл трафик», без чего возраст handshake неинтерпретируем.

Почему так, а не «handshake > 300 с = алерт»: на релее `awg1` создаётся из
клиентского `.conf` exit-узла, где `PersistentKeepalive` **не пишется по умолчанию**
(`ClientParams.keepalive: Optional[int] = None`, И44 в
`src/amneziawg/config.py`) — и это осознанное радиомолчание. Без keepalive свежесть
handshake в простое ничего не значит, и наивное правило дало бы поток ложных тревог
каждую ночь. Гейт активности делает сигнал валидным и **без** изменения конфига
релея; деплой всё равно рекомендует `PersistentKeepalive = 113` на `awg1`
(`docs/DEPLOY-RU-RELAY.md`, WP-7) — тогда валидация строже и `idle` не наступает.

**Двухсторонняя классификация «плечо vs релей»** — TCP-проба до **релея** (не до
exit, у нас exit) плюс опциональный ICMP:

- Из `endpoint` берём **только host**: порт в `dump` — это UDP-порт AWG-сокета
  релея, для TCP-пробы он не годится. TCP-проба идёт на `ALERT_RELAY_PROBE_PORT`
  (по умолчанию `443` — на релее там Reality `tcp/443`; тот же номер, что
  `RELAY_PORT = 443` в `src/relay/paths.py`).
  `socket.create_connection((host, port), timeout=ALERT_TCP_TIMEOUT_S=3)`, закрыть.
- ICMP (`ping -c1 -W2`) — **опционально и только как уточнение текста**, не как
  триггер: обратный путь тоже может шейпиться (research §7 OQ-11). Если `ping`
  недоступен — поле `icmp_ok = None`, сообщение без него.
- Если `endpoint` пуст (`(none)`) — TCP-проба не выполняется (`tcp_ok = None`) →
  `inconclusive`, `ALERT-SKIP relay_pulse no_telemetry`.

**Что делать, если `awg show` недоступен или пир не найден** (REQ §6): вернуть
`inconclusive` с причиной (`awg_unavailable` / `peer_not_found` / `state_unreadable`),
напечатать `ALERT-SKIP relay_pulse no_telemetry`, показать это в
`vds alert status` как «пульс плеча: слеп (причина)», **не** отправлять «канал мёртв».
Повтор сигнала «слеп» — не чаще `ALERT_TELEMETRY_REMINDER_H` (24 ч).

### 3.2. Решение по «телеметрия недоступна» (≠ «тихо»)

`probing.load_snapshot` **намеренно** маскирует отсутствие/битый файл в пустой
снапшот (`{}` threat) — для `watch` это правильно, для сторожа неприемлемо: там
«тихо» и «нет данных» выглядели бы одинаково. Поэтому у `alert/checks.py` свой
минимальный читатель `json` (без импорта 2300-строчного `probing`), возвращающий
**пять** состояний:

| `status` | Условие | Что делает сторож |
|---|---|---|
| `ok` | файл читается, `threat.level ∈ {quiet,elevated,high}`, `ts` свежий | нормальная обработка уровня |
| `missing` | файла нет | `telemetry_unavailable` (ODD: возможно probe-watch не установлен) |
| `corrupt` | JSON не парсится / не объект | `telemetry_unavailable` + в сообщении «снапшот повреждён» |
| `no_level` | файл есть, `threat` пуст (таймер ещё не отработал) | `telemetry_unavailable` |
| `stale` | `ts` старше `max(3 × 3600 с, 3 × период таймера probe-watch)` | `telemetry_unavailable` + «телеметрия замерла N ч» |

`stale` — добавление архитектора: часовой таймер может умереть молча, и тогда
уровень в файле навсегда останется `quiet`. Порог 3 ч = 3 пропущенных часовых тика.

`PROBE_WATCH_PATH` в `alert/paths.py` — **зеркало** `probing.SNAPSHOT_PATH` с
комментарием-ссылкой; unit-тест `test_checks.py::test_snapshot_path_matches_probing`
сверяет равенство значений, чтобы дрейф путей не прошёл молча.

### 3.3. Интерфейсы (сигнатуры, не реализация)

```python
# src/alert/env.py
@dataclass(frozen=True)
class AlertConfig:
    channels: tuple[str, ...]            # ("tg","smtp") — порядок отправки
    tg_token: str = ""
    tg_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_to: tuple[str, ...] = ()        # SMTP_TO допускает список через запятую
    smtp_starttls: bool = False          # True → SMTP:587 + starttls()
    site_name: str = ""                  # подпись в сообщении (hostname по умолчанию)
    handshake_threshold_s: int = 300
    heartbeat_h: int = 24
    cooldown_min: int = 30
    rate_limit_per_hour: int = 6
    lock_reminder_h: int = 6
    telemetry_reminder_h: int = 24
    relay_peer: str = "relay"
    relay_probe_port: int = 443
    tcp_timeout_s: int = 3
    enabled_checks: tuple[str, ...] = ("threat", "relay_pulse", "lockdown")

def parse_duration(text: str) -> int: ...        # "30s"|"2m"|"24h" → секунды; ValueError
def load_config(path: str = ALERT_ENV_PATH) -> AlertConfig: ...   # отсутствие файла → defaults
def render_env(cfg: AlertConfig, *, with_secrets: bool) -> str: ...  # with_secrets=False → маски
def active_channels(cfg: AlertConfig) -> tuple[str, ...]: ...     # только сконфигурированные
def config_warnings(cfg: AlertConfig) -> list[str]: ...           # "tg: нет TG_CHAT_ID" и т.п.
```

```python
# src/alert/checks.py
ProbeStatus = Literal["ok", "missing", "corrupt", "no_level", "stale"]
RelayClass = Literal["ok", "blocked", "relay_down", "idle", "inconclusive"]

@dataclass(frozen=True)
class ThreatSignal:
    status: ProbeStatus
    level: Optional[str]      # quiet|elevated|high (None при non-ok)
    reason: str
    snapshot_ts: str
    age_sec: Optional[int]

@dataclass(frozen=True)
class RelaySignal:
    classification: RelayClass
    detail: str                        # awg_unavailable|peer_not_found|state_unreadable|...
    peer_found: bool
    handshake_age_sec: Optional[int]   # -1 = никогда; None = нет данных
    endpoint_host: str
    endpoint_port: int
    tcp_ok: Optional[bool]
    icmp_ok: Optional[bool]
    traffic_active: bool

@dataclass(frozen=True)
class AwgPeer:
    public_key: str
    endpoint: str          # "" если "(none)"
    allowed_ips: str
    latest_handshake: int
    rx: int
    tx: int

def parse_awg_dump(text: str) -> dict[str, AwgPeer]: ...   # чистый; ""/битый → {}
def read_threat(path: Path = PROBE_WATCH_PATH, now: datetime | None = None,
                timer_hours: int = 1) -> ThreatSignal: ...
def classify_relay(handshake_age_sec: Optional[int], threshold_s: int,
                   tcp_ok: Optional[bool], traffic_active: bool) -> RelayClass: ...
def read_relay_signal(*, cfg: AlertConfig, prev_state: dict, now: datetime,
                      run: Callable[..., ShellResult] = run_list,
                      state_path: str | None = None) -> RelaySignal: ...
def read_lockdown(state_path: str | None = None) -> dict: ...   # (get_lockdown, лениво)
```

```python
# src/alert/state.py
@dataclass(frozen=True)
class Decision:
    send: bool
    reason: str   # "send"|"escalation"|"cooldown"|"duplicate"|"rate_limited"|"disabled"

def load_state(path: Path = ALERT_STATE_PATH) -> tuple[dict, bool]: ...  # (state, corrupted)
def save_state(state: dict, path: Path = ALERT_STATE_PATH) -> bool: ...  # 0600, атомарно
def decide(event: str, severity: int, prev: dict, now: datetime,
           cooldown_min: int, rate_limit_per_hour: int) -> Decision: ...  # чистая
```

```python
# src/alert/channels.py
@dataclass(frozen=True)
class ChannelResult:
    channel: str     # "tg" | "smtp"
    ok: bool
    errclass: str    # ""|timeout|dns|conn|auth|http_4xx|http_5xx|tls|config

def send_telegram(cfg: AlertConfig, text: str, *, opener=None, timeout: float = 10) -> ChannelResult: ...
def send_smtp(cfg: AlertConfig, subject: str, text: str, *, smtp_factory=None,
              timeout: float = 15) -> ChannelResult: ...
def send_all(cfg: AlertConfig, subject: str, text: str, *, senders=None) -> list[ChannelResult]: ...
def backoff_delay_sec(fail_count: int) -> int: ...   # min(60 * 2**(n-1), 3600)
```

```python
# src/alert/watch.py
def run_tick(*, config_path: str = ALERT_ENV_PATH, no_send: bool = False,
             now: datetime | None = None, run=run_list, senders=None,
             probe_path: Path = PROBE_WATCH_PATH,
             state_path: Path = ALERT_STATE_PATH) -> int: ...   # exit 0 всегда
def format_message(kind: str, cfg: AlertConfig, payload: dict) -> tuple[str, str]: ...  # (subject, body)
```

```python
# src/alert/cli.py
def cmd_install(*, apply: bool = False, channel: str | None = None,
                interval: str = "2m", handshake_threshold: str = "300s",
                heartbeat: str = "24h", force: bool = False,
                allow_relay_node: bool = False, root: str = "/") -> int: ...
def cmd_remove(*, apply: bool = False, purge: bool = False, root: str = "/") -> int: ...
def cmd_test(*, root: str = "/") -> int: ...
def cmd_status(*, json_out: bool = False, root: str = "/") -> int: ...
```

`root` — тестовый префикс ФС, как у `core.units.install_unit/remove_unit`; при
`root != "/"` FileLock не берётся (та же конвенция).

### 3.4. CLI-поверхность

```bash
vds alert install  [--apply] [--channel tg,smtp] [--interval 2m]
                   [--handshake-threshold 300s] [--heartbeat 24h]
                   [--force] [--allow-relay-node]
vds alert remove   [--apply] [--purge]
vds alert test
vds alert status   [--json]
vds alert watch    [--config /etc/vds/alert.env] [--no-send]   # служебная: один тик
```

- `install` / `remove` — dry-run по умолчанию, `--apply` требует root; `test`
  требует root (читает `alert.env`); `status` без root работает в урезанном виде
  («конфиг недоступен — запустите под sudo»), `--json` сохраняет форму.
- **`install` на узле-рееле запрещён**: если `state.protocols` содержит `"relay"` —
  hard refuse (`exit 1`) с объяснением «секреты на RU-рееле не храним». Обход —
  только `--allow-relay-node` (флаг есть, но печатает `[warning]` и требует явного
  подтверждения; в доке помечен как «не делать»).
- `watch --no-send` — dry-run тика: вычисляет решения, печатает план, **не**
  отправляет и **не** пишет state. Единственный способ ручной отладки без риска
  дубля тревоги.

### 3.5. Формат `/etc/vds/alert.env` (0600, root, атомарная запись)

Формат — `KEY=VALUE`, `#`-комментарии, парсится `core.shell.load_env` (переиспользуем,
не пишем свой). Пишется `core.secrets.write_secret_atomic(mode=0o600)`.

```ini
# vds alert — каналы и параметры сторожа (0600). Значения не печатать.
# --- каналы (наличие пары ключей = канал включён) ---
TG_BOT_TOKEN=FIXTURE_TG_BOT_TOKEN
TG_CHAT_ID=111111111
SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_USER=alert@example.com
SMTP_PASS=FIXTURE_PW_SMTP
SMTP_FROM=alert@example.com
SMTP_TO=owner@example.com            # список через запятую допустим
SMTP_STARTTLS=0                      # 1 → порт 587 + starttls()
ALERT_CHANNELS=tg,smtp               # пусто → авто по наличию конфигурации
# --- параметры (не секреты, но файл всё равно 0600) ---
ALERT_SITE_NAME=asv2
ALERT_HANDSHAKE_THRESHOLD_S=300
ALERT_HEARTBEAT_H=24
ALERT_COOLDOWN_MIN=30
ALERT_RATE_LIMIT_PER_HOUR=6
ALERT_LOCK_REMINDER_H=6
ALERT_TELEMETRY_REMINDER_H=24
ALERT_RELAY_PEER=relay
ALERT_RELAY_PROBE_PORT=443
ALERT_TCP_TIMEOUT_S=3
ALERT_CHECKS=threat,relay_pulse,lockdown
```

Правила:
1. **Секреты в systemd `Environment=`/`EnvironmentFile=` не попадают**: юнит получает
   только путь (`--config /etc/vds/alert.env`), процесс читает файл сам. Причина —
   `systemctl show -p Environment`/`invocation` не должны светить токен.
2. Отсутствие конфигурации канала = канал выключен, `install` печатает `[warning]`
   и **не падает** (FR-2).
3. Фикстуры в тестах/доке — только `FIXTURE_*` и зарезервированные адреса (AGENTS §6).
4. `SMTP_PASS` — App Password; основной пароль не поддерживаем (в тексте ошибки
   подсказка, без значения).

### 3.6. Формат `/var/lib/vds/alert-state.json` (0600, root, `FileLock` на запись)

```json
{
  "version": 1,
  "updated": "2026-11-17T12:02:11+00:00",
  "sources": {
    "threat":      {"level": "elevated", "last_sent_level": "quiet",
                    "last_sent_type": "threat_elevated", "last_sent": "2026-11-17T12:02:11+00:00"},
    "relay_pulse": {"class": "ok", "last_traffic_ts": "2026-11-17T12:00:00+00:00",
                    "last_sent_type": "", "last_sent": ""},
    "lockdown":    {"active": false, "last_sent": ""},
    "heartbeat":   {"last_sent": "2026-11-17T03:00:00+00:00"},
    "telemetry":   {"probe_watch": {"status": "ok", "last_sent": ""}}
  },
  "window": ["2026-11-17T12:02:11+00:00"],
  "suppressed": {"threat_high": 3, "relay_pulse": 1},
  "failures": {"tg": {"count": 2, "next_attempt": "2026-11-17T12:10:00+00:00"},
               "smtp": {"count": 0, "next_attempt": ""}}
}
```

- `window` — метки отправок за последний час (для лимита N/час; старые вычищаются
  при каждой записи).
- `suppressed` — счётчики подавленного по типам; при снятии лимита один раз в час
  уходит `summary` и счётчики обнуляются.
- **Шкала `severity` для `decide()`** (иначе эскалация недетерминирована):
  `quiet=0`, `elevated=1`, `high=2`; `relay_pulse`: `ok=0`, `idle=0`,
  `inconclusive=0`, `blocked=2`, `relay_down=3`; `lockdown_on=2`, `heartbeat=0`,
  сводка/напоминания `=0`. Апгрейд = `severity_new > severity_last_sent` для того же
  типа → `reason="escalation"` (обходит cooldown и лимит).
- Битый JSON → состояние пересоздаётся пустым, в journal `ALERT-FAILED state corrupt`,
  тик продолжается (FR-3). Файл не удаляется молча.
- **Первый тик после `install`**: `sources.heartbeat.last_sent` пуст → отправляется
  один heartbeat немедленно (это и есть живое подтверждение, что канал настроен
  верно), он же считается суточным. Дальше — не чаще `ALERT_HEARTBEAT_H`.
- Все времена — **UTC** (ISO-8601 с offset); DST/timezone не участвуют.

### 3.7. Юнит и таймер

Почему не хук в `vds-gateway-health` (OQ-7) — четыре причины:
1. **Разные домены отказа.** `healthcheck --unit` по контракту возвращает `0` всегда,
   кроме катастрофы чтения `state.json` (`src/gateway/health.py`, докстринг §«Семантика
   exit-кодов»), а внутри уже принимает решения о рестарте юнитов
   (`MAX_RESTARTS_PER_HOUR = 3`). Встроив отправку туда, мы спрячем сбой доставки
   за «здоровым» exit-кодом.
2. **Секреты.** Healthcheck — компонент, чей смысл быть видимым в журнале и в
   `healthcheck`-выводе. Читать токены в нём = расширять поверхность секретов
   (нарушение §5/§6 AGENTS).
3. **Каденции.** 5 мин (health) ≠ 2 мин (пульс плеча). Один юнит — одна каденция;
   склеивание заставило бы либо ускорять healthcheck, либо тормозить алерты.
4. **Жизненный цикл.** `vds alert remove` не должен трогать healthcheck и наоборот;
   отдельный journal-стрим (`journalctl -u vds-alert-watch`) — то, чем будет
   пользоваться дебагер.

`systemd/vds-alert-watch.service.tpl`:

```ini
[Unit]
Description=VDS Alert Watch (threat / relay pulse / heartbeat notifications, exit node)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Секреты НЕ в Environment: процесс читает /etc/vds/alert.env (0600) сам.
ExecStart={python} -m src.main alert watch --config /etc/vds/alert.env
StandardOutput=journal
StandardError=journal
Nice=10
IOSchedulingClass=idle
CPUWeight=10
MemoryMax=96M
TimeoutStartSec=60
NoNewPrivileges=yes
# awg show — netlink (CAP_NET_ADMIN), ping — raw socket (CAP_NET_RAW)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ReadWritePaths=/var/lib/vds /var/run
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

`systemd/vds-alert-watch.timer.tpl`:

```ini
[Unit]
Description=VDS Alert Watch Timer (threat / relay pulse notification tick, exit node)

[Timer]
OnBootSec=3min
OnUnitActiveSec={interval_sec}s
RandomizedDelaySec=30s
AccuracySec=30s

[Install]
WantedBy=timers.target
```

Рендер — `core.units.install_unit(..., ctx={"python","repo_dir","install_dir",
"interval_sec"})`; новый ключ `interval_sec` считает `cmd_install` из `--interval`.
Никаких правок на сервере руками (AGENTS §6).

### 3.8. Journal-теги (FR-6)

Печатаются в stdout → systemd journal. Формат — одна строка, машиночитаемая:

```
ALERT-SENT <channel> <type>          # доставлено (по строке на канал)
ALERT-FAILED <channel> <errclass>    # не доставлено (errclass без секретов/URL)
ALERT-SKIP <type> <reason>           # ничего не отправлено
```

`type ∈ {threat_elevated, threat_high, threat_high_still, threat_release,
relay_blocked, relay_down, relay_recovered, lockdown_on, lockdown_still,
telemetry_unavailable, heartbeat, summary}`
`reason ∈ {cooldown, duplicate, disabled, rate_limited, no_telemetry, channel_not_configured}`
(три из REQ + расширение; расширение зафиксировано здесь, чтобы лог-парсеры не
угадывали).

**Решение по OQ-9:** в `vds logs` (`analyze`/`report`) новых структурных сигнатур
**не вводим** — `analyze` работает по ndjson-сэмплам, а не по journal
(`src/logs/report.py::cmd_analyze`), и подмешивать туда доставку алертов значило бы
смешать два конвейера. Вместо этого WP-6 добавляет `vds-alert-watch.service` в
`WATCH_UNITS` (`src/logs/collect.py`) и его журнальный excerpt в бандл — так состояние
сторожа попадает в телеметрию и в `vds logs capture`, а сами теги доступны
`journalctl -u vds-alert-watch`. Форензика доставки — там.

---

### 3.9. Уведомление о локе (FR-1 п.4)

`read_lockdown` = `src/system/ufw.py::get_lockdown(load_state())` (ленивый импорт).
Переход `active: false → true` → `lockdown_on` с TTL и `reason` из лока. Пока лок
активен — напоминание `lockdown_still` не чаще `ALERT_LOCK_REMINDER_H` (6 ч), а не
каждые 30 мин: при 48-часовом локе 30-минутный cooldown дал бы 96 сообщений, которые
всё равно упрутся в лимит 6/час и превратятся в поток сводок. Снятие лока — тихо
(это штатное поведение TTL, владельцу полезен факт «защита включена», а не «выключена»);
факт снятия виден в `status`.

---

## 4. Миграция и совместимость

Ничего не ломается: новые файлы, новый юнит, аддитивная CLI-команда. Схема
`state.json` **не меняется** (только чтение). `probe-watch.json` не меняется.

**Порядок установки на exit-узле** (в `docs/DEPLOY.md`, WP-7):

1. `sudo vds alert install` — dry-run: печатает план, список ожидаемых ключей
   `alert.env` (**имена**, не значения), какие каналы активны.
2. Создать `/etc/vds/alert.env` по шаблону из вывода, заполнить; `install` при
   `--apply` выставит `0600` и не перезапишет существующий файл без `--force`.
3. `sudo vds alert install --apply` — рендер юнитов, `daemon-reload`, `enable`,
   `start` таймера. Идемпотентно.
4. `sudo vds alert test` — реальная отправка «руками», без записи state.
5. `sudo vds alert status` — сверить: каналы, состояние юнитов, coverage (что
   «слепо» и почему).
6. `sudo vds alert watch --no-send` — прогнать тик без отправки, убедиться, что
   `relay_pulse` не `inconclusive`/`idle` при живом канале.

**Что с уже работающими таймерами:** ничего. `vds-probe-watch.timer`,
`vds-gateway-health.timer`, `vds-logs-sample.timer` продолжают работать как сейчас;
`vds-alert-watch` только читает их артефакты. Пересечения блокировок нет: у сторожа
свой lock `vds-alert-watch.lock`, у probe-watch — `vds-probe-watch.lock`
(чтение снапшота атомарно за счёт `os.replace`, блокировка на чтение не нужна —
это явное решение, а не недосмотр).

**Откат:** `sudo vds alert remove --apply` (юниты сняты, `alert.env` сохранён) →
`sudo vds alert remove --apply --purge` (удалить и `alert.env`). Состояние
`alert-state.json` удаляется только вместе с `--purge`. UFW, `probe-watch.json`,
`state.json` не затрагиваются — откат не оставляет следов в политике.

**Уже включённый `--auto-lockdown`:** семантика не меняется, сторож только
уведомляет о факте лока и его TTL (§3.9). Порядок установки не важен.

---

## 5. Безопасность и отказы

- **Секреты:** только `/etc/vds/alert.env`, 0600, root; атомарная запись
  `core.secrets.write_secret_atomic`; не в journal, не в вывод `--help`/`status`,
  не в `Environment=` юнита, не в тестах (только `FIXTURE_*`). `render_env(with_secrets=False)`
  — единственный путь для показа конфига.
  **Отдельно:** `urllib.error.HTTPError`/`URLError` содержат URL с токеном бота в
  `str(exc)` — в коде запрещено печатать/логировать `str(exc)` этих исключений;
  наружу идёт только `errclass` (`http_4xx`, `timeout`, `dns`, …). Это проверяется
  тестом (§6).
- **Только exit-узел:** `install` отказывает на узле, где `state.protocols` содержит
  `"relay"`. На релее секретов нет ни в одном файле.
- **Dry-run:** `install`/`remove` по умолчанию; `watch --no-send` для тика.
- **Мутации:** только `alert-state.json` (0600, `FileLock`) и `alert.env` (0600).
  `probe-watch.json`/`state.json` — только чтение; `systemctl` — только
  `enable/start/stop` собственных юнитов из шаблонов.
- **Идемпотентность:** повторный `install --apply` → те же два файла юнитов,
  `alert.env` не перезаписан (без `--force`), таймер не запускается дважды.
- **Отказы (failure modes):**

| Сценарий | Поведение |
|---|---|
| канал недоступен | `ALERT-FAILED <ch> <errclass>`, backoff `min(60·2^(n−1), 3600)` с, юнит **не** падает (exit 0) |
| оба канала упали | два `ALERT-FAILED`, state пишется, следующая попытка по backoff |
| `alert.env` отсутствует | каналы выключены, `ALERT-SKIP * channel_not_configured`, exit 0 (не спамим) |
| нет root | `install --apply`, `remove --apply`, `test` → сообщение + exit 1 (до мутаций/отправки) |
| `state.json` битый | пир не найден → `relay_pulse: inconclusive`, лок считается неактивным, `ALERT-SKIP` |
| `probe-watch.json` битый/нет | `telemetry_unavailable` (не «тихо»), напоминание 24 ч |
| часовой таймер probe-watch умер | `stale` → `telemetry_unavailable` («замерла N ч») |
| тик пропущен (suspend/reboot) | без «догоняющих» алертов: обрабатывается только текущее состояние; heartbeat — одно сообщение с «пропущено N ч» |
| таймер наложился | `FileLock` → второй тик отдаёт работу первому (паттерн probe-watch `LockError`) |
| `awg` нет / пир не найден | `ALERT-SKIP relay_pulse no_telemetry`, в `status` — «слеп (причина)» |

---

## 6. Тест-план

Всё — без root/сети/docker: сетевые и SMTP-вызовы инжектируются (`opener`,
`smtp_factory`, `run=`, `senders=`), файлы — в `tmp_path`.

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | `parse_duration` (s/m/h, мусор → ValueError); round-trip `render_env`→`load_env`; `with_secrets=False` не содержит ни одного значения секрета; `active_channels` по наличию пар; `config_warnings` | `tests/alert/test_env.py` |
| Unit | `load_state`: нет файла / битый → `(empty, True)`; `save_state` 0600 + атомарность (нет `.tmp` после); `decide()` таблица: cooldown подавляет, эскалация `elevated→high` проходит всегда, `rate_limited` при 6/час, `disabled` для выключенной проверки; `suppressed` инкремент | `tests/alert/test_state.py` |
| Unit | `send_telegram`: успех/`http_4xx`/`timeout`/`dns`; **токен не встречается ни в `errclass`, ни в любом сформированном тексте**; `send_smtp`: `SMTP_SSL` при 465, `SMTP+starttls` при `SMTP_STARTTLS=1`, `auth` при SMTPAuthenticationError; `send_all` независимость каналов; `backoff_delay_sec` | `tests/alert/test_channels.py` |
| Unit | `parse_awg_dump`: пустой вывод, только интерфейсная строка, `(none)` endpoint, 2+ пира, табы/пробелы, битые числа; `read_threat` пять состояний (ok/missing/corrupt/no_level/stale) с подменой путей и `now`; `classify_relay` — вся таблица §3.1 (6 строк); `PROBE_WATCH_PATH == probing.SNAPSHOT_PATH` | `tests/alert/test_checks.py` |
| Unit | `run_tick` с инжекцией всех источников: `quiet→elevated` → ровно одно сообщение + `ALERT-SENT`; повтор в окне → `ALERT-SKIP duplicate`; `elevated→high` → второе (эскалация); `high→quiet` → `threat_release`; handshake мёртв + TCP жив + активность → `relay_blocked`; то же с TCP мёртв → `relay_down` (одно сообщение, не два); handshake мёртв без активности → `idle`, ничего; `no_telemetry` → `ALERT-SKIP`, **не** алерт; битый state → работает, `ALERT-FAILED state corrupt`; heartbeat один раз в 24 ч; `--no-send` не пишет state | `tests/alert/test_watch.py` |
| Unit | `cmd_install` dry-run текст (план + имена ключей, ни одного значения); `--apply` с `root=tmp` → оба юнита в `<root>/etc/systemd/system/`, `alert.env` 0600; второй `--apply` не меняет `alert.env` (mtime/содержимое); `remove` сохраняет env, `--purge` удаляет; отказ на relay-узле; `status --json` — схема без секретов | `tests/alert/test_cli.py` |
| Integration (Docker) | **Не вводим.** Зависимости — stdlib HTTP/SMTP; проверяются инжекцией, а реальная сеть — только на живом узле. Docker не добавляет покрытия, но добавил бы сетевую зависимость в `pytest`. Обоснование фиксируется в этом SPEC. | — |
| Ручная приёмка (живой VDS) | чеклист ниже | `docs/DEPLOY.md` |

**Чеклист живой приёмки:** AC-1 (`--help`, идемпотентность, dry-run) · AC-2
(`quiet→elevated` → сообщение; повтор подавлен) · AC-3 (стоп `vds-relay-exit` на
рееле → `relay_blocked`; живой handshake 15-мин прогон → ноль алертов) · AC-4
(секретов нет в `journalctl`, `--help`, `status`, `git grep`; файл 0600) · AC-5
(mtime и содержимое `probe-watch.json` не изменились за 15 мин — сам сторож их не
трогал) · AC-6 (канал недоступен → `ALERT-FAILED` + backoff, юнит активен) · AC-7
(оба канала: пуш и письмо, по одному `ALERT-SENT`) · AC-8 (`pytest -q` зелёный,
новые тесты без root/сети/docker).
**Свои проверки:** AC-9 `telemetry_unavailable`: остановить `vds-probe-watch.timer`
на 3+ ч → приходит «телеметрия замерла», **не** «тихо» · AC-10 `install` на релее
отказывает, `alert.env` там не появляется · AC-11 ручной `watch --no-send` при живом
канале не отправляет и не меняет state · AC-12 `alert status --json` машинно читается
(`json.loads`) и не содержит значений секретов · AC-13 на живом узле
`awg show awg0 dump | head -3` даёт 8 полей на пира, `vds alert status --json`
показывает `peer_found: true` и вменяемый `handshake_age_sec` (подтверждение формата
§3.1).

---

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | Фундамент: пути, схема конфига, состояние и чистая логика подавления | `src/alert/__init__.py`, `src/alert/paths.py`, `src/alert/env.py`, `src/alert/state.py`, `tests/alert/__init__.py`, `tests/alert/test_env.py`, `tests/alert/test_state.py` | — | `compileall`; `pytest tests/alert/test_env.py tests/alert/test_state.py`; ни одного импорта `requests`; в `env.py` нет печати значений секретов |
| WP-2 | Каналы доставки на stdlib | `src/alert/channels.py`, `tests/alert/test_channels.py` | WP-1 | тест «токен не утекает в errclass/текст» зелёный; `SMTP_SSL`/starttls ветки; backoff |
| WP-3 | Телеметрия и классификация (awg dump, threat 5 состояний, лок) | `src/alert/checks.py`, `tests/alert/test_checks.py` | WP-1 | таблица §3.1 покрыта тестом построчно; `parse_awg_dump` без исключений на мусоре; `PROBE_WATCH_PATH` сверен с `probing.SNAPSHOT_PATH` |
| WP-4 | Тик сторожа: решения, сообщения, теги, heartbeat | `src/alert/watch.py`, `tests/alert/test_watch.py` | WP-1, WP-2, WP-3 | все сценарии §6 по `run_tick`; exit 0 при любом сбое канала; `--no-send` ничего не пишет |
| WP-5 | CLI + юниты + регистрация в `main.py` | `src/alert/cli.py`, `src/main.py`, `systemd/vds-alert-watch.service.tpl`, `systemd/vds-alert-watch.timer.tpl`, `tests/alert/test_cli.py` | WP-1…WP-4 | `python -m src.main alert --help` и 5 подкоманд видны; `install/remove` идемпотентны с `root=tmp`; отказ на relay-узле; шаблоны рендерятся `format()` без `KeyError` |
| WP-6 | Видимость в конвейере ADR-012 | `src/logs/collect.py` | WP-1 (имя юнита из `paths.py`) | `vds-alert-watch.service` в `WATCH_UNITS`; excerpt в бандле; существующие тесты `tests/logs/` зелёные |
| WP-7 | Доки, doc-sync, долг | `README.md`, `AGENTS.md`, `docs/SERVER-BASELINE.md`, `docs/DEPLOY.md`, `docs/DEPLOY-RU-RELAY.md`, `docs/research/notifications-and-resilience-2026-11-17.md`, `TECHDEBT.md`, `docs/doc-sync.json` | WP-5, WP-6 | `python3 tools/docsync.py audit --strict` без `fail`; имена `vds-alert-watch.service.tpl`/`.timer.tpl` **буквально** есть в `README.md` (reverse-units); leaf-команды `vds alert …` есть в `README.md`/`AGENTS.md`; P24/P25 в `TECHDEBT.md` |

Границы: каждый WP самодостаточен; пересечений файлов между WP нет — каждый файл
закреплён ровно за одним WP (`src/logs/collect.py` — только WP-6, `src/main.py` —
только WP-5).
Порядок: WP-1 → (WP-2 ∥ WP-3 ∥ WP-6) → WP-4 → WP-5 → WP-7.

---

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| R-1. Ложные тревоги пульса в простое (нет keepalive на `awg1`) | высокая без гейта | владелец перестаёт верить алертам | гейт активности (§3.1) + рекомендация `PersistentKeepalive = 113` в DEPLOY-RU-RELAY; `idle` в `status` |
| R-2. Волна проб видна с лагом до 1 ч (threat считается часовым тиком) | высокая | не «за минуту», как хотелось в REQ §1 | принято сознательно; лаг печатается в сообщении; будущее — снизить период probe-watch (вне цикла) |
| R-3. Токен утекает через текст исключения urllib | средняя | компрометация бота | запрет `str(exc)` для `HTTPError`/`URLError`; тест §6 |
| R-4. `probe-watch.json` читается неконсистентно во время записи | низкая | ложный уровень | атомарная запись `os.replace` у писателя; читаем без блокировки (документировано) |
| R-5. Rate-limit маскирует важную эскалацию | низкая | пропущенный `high` | эскалация обходит и cooldown, и лимит (FR-3 REQ) |
| R-6. `state.json` недоступен (pydantic-версия) | низкая | пульс слеп | `inconclusive` + `status`; не алерт |
| R-7. systemd sandbox режет `awg show`/`ping` | средняя | пульс/ICMP слеп | `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`; AC-11 на живом узле |
| R-8. `SMTP_TO`/`TG_CHAT_ID` устарел | низкая | тишина при инциденте | heartbeat раз в сутки обнаруживает поломку канала |
| R-9. формат `awg show … dump` на asv2 отличается от `wg(8)` | средняя | пульс слеп (`inconclusive`) | терпимый парсер (§3.1) + AC-13 до объявления приёмки |

---

## 9. Границы изменений

### 9.1. Что трогаем
- Новый пакет `src/alert/`, два новых шаблона `systemd/vds-alert-watch.*.tpl`.
- `src/main.py` — только добавление `alert_app` и пяти команд (ленивые импорты).
- `src/logs/collect.py` — только список `WATCH_UNITS` и список excerpt-юнитов.
- Доки по §11, `docs/doc-sync.json` (новое правило `alert`), `TECHDEBT.md`.

### 9.2. Что НЕ трогаем
- `src/gateway/probing.py` (threat-машина, `lock-443`, `--auto-lockdown`) — сторож
  только читает снапшот; `watch --record`, `probe-watch.json` не мутируются (ADR-014).
- `src/gateway/health.py` и `vds-gateway-health.*` — решение OQ-7.
- `src/system/ufw.py` — политика UFW, семантика `lock-443`, undo-журнал.
- Схема `state.json` (`GatewayState`, `ufw_lockdown`) — только чтение.
- Публичный CLI (кроме аддитивной `vds alert …`), `topology.json`, права файлов
  протоколов, systemd-юниты протоколов.

### 9.3. Почему без ADR
Все решения обратимы: отдельный юнит снимается `remove`, схема `alert.env`/`alert-state.json`
— новый файл (ломать нечего), каналы — stdlib. Публичный контракт меняется только
аддитивно (новая команда). Необратимых решений нет.

### 9.4. FR-8 и FR-9 — вынесено, не реализуется здесь

**FR-8 (изоляция 51825/udp на exit-узле) — блокирует OQ-1.** На asv2 `51825/udp` —
основной AWG-порт клиентов (mobile/Windows), поэтому `ufw allow from <relay>` с
удалением общего правила **оборвёт клиентов**. Решение на бумаге (рекомендация
архитектора, не реализация): **отдельный AWG-сервер на отдельном порту и отдельном
интерфейсе (`awg2`) для ноги релея**; whitelist-по-IP на общем порту отвергается
(ломает клиентов и жёстко привязывает политику к IP релея, который может меняться
при миграции), `nft`-фильтр по src на том же порту — второй по предпочтению
(сложнее в откате). Нужен факт с живого узла (`ss -ulnp | grep 51825`,
`ufw status numbered`, `awg show`), поэтому OQ-1 остаётся **открытым**.
→ `TECHDEBT.md` **P24** (см. WP-7; последний занятый номер на 2026-11-17 — P23,
кодер обязан перепроверить свободность при записи).

**FR-9 (манёвр порта/протокола на плече) — блокирует OQ-8.** Автоматика, способная
оборвать канал; другой риск-профиль и, вероятно, ADR (меняет межузловую схему).
→ `TECHDEBT.md` **P25**. Отдельный REQ в следующем цикле.

Оба пункта **не входят** ни в один WP этого SPEC.

---

## 10. Трассируемость

| REQ | WP | Файлы | Тест |
|---|---|---|---|
| FR-1 п.1 (threat-level) | WP-3, WP-4 | `checks.py`, `watch.py` | `test_checks::test_read_threat_*`, `test_watch::test_threat_*` |
| FR-1 п.2–3 (пульс + классификация) | WP-3, WP-4 | `checks.py` (`parse_awg_dump`, `classify_relay`) | `test_checks::test_classify_relay_table`, `test_watch::test_relay_*` |
| FR-1 п.4 (лок) | WP-3, WP-4 | `checks.read_lockdown`, `watch.py` | `test_watch::test_lockdown_*` |
| FR-2 (каналы) | WP-1, WP-2 | `env.py`, `channels.py` | `test_env.py`, `test_channels.py` |
| FR-3 (дедуп/лимиты) | WP-1 | `state.py` | `test_state::test_decide_*` |
| FR-4 (heartbeat) | WP-4 | `watch.py` | `test_watch::test_heartbeat_*` |
| FR-5 (CLI) | WP-5 | `cli.py`, `main.py`, `*.tpl` | `test_cli.py` |
| FR-6 (наблюдаемость) | WP-4, WP-6 | `watch.py`, `logs/collect.py` | `test_watch::test_tags_*`, `tests/logs/` |
| FR-7 (только уведомления) | WP-3, WP-4 | `checks.py`, `watch.py` | AC-5 + отсутствие записи в `probe-watch.json` |
| NFR stdlib | WP-2 | `channels.py` | grep-тест в DoD |
| NFR секреты | WP-1, WP-2, WP-5 | `env.py`, `channels.py`, `cli.py` | `test_channels::test_no_secret_leak`, AC-4 |
| FR-8 / FR-9 | — | TECHDEBT P24 / P25 | не в этом цикле |

---

## 11. Doc delta (обязателен до G2)

| Документ (класс) | Изменение | WP |
|---|---|---|
| `README.md` (living) | таблица команд: `vds alert install/remove/test/status/watch`; буквальные имена `vds-alert-watch.service.tpl`, `vds-alert-watch.timer.tpl` (reverse-units); где лежат секреты | WP-7 |
| `AGENTS.md` (living) | §3 структура (`src/alert/`), §4 команды, §4/§3 юниты; §6 — «секреты только exit-узел» | WP-7 |
| `docs/SERVER-BASELINE.md` (living) | новый юнит/таймер, `/etc/vds/alert.env` 0600 и `/var/lib/vds/alert-state.json`, чеклист восстановления, `PersistentKeepalive` precondition | WP-7 |
| `docs/DEPLOY.md` (living) | шаг установки сторожа (§4: 6 шагов), проверка канала, откат | WP-7 |
| `docs/DEPLOY-RU-RELAY.md` (living) | `PersistentKeepalive = 113` на `awg1` — precondition валидности пульса | WP-7 |
| `docs/doc-sync.json` (living-реестр) | правило `alert`: `src/alert/**` → README, AGENTS, SERVER-BASELINE, DEPLOY | WP-7 |
| `TECHDEBT.md` (living) | P24 (FR-8/OQ-1), P25 (FR-9/OQ-8) | WP-7 |
| `docs/research/notifications-and-resilience-2026-11-17.md` (snapshot) | пометка «реализовано» **после** живой приёмки | WP-7 |
| `docs/team/specs/SPEC-20261117-alert-watch.md` (snapshot) | этот документ | — |

Изменение `mode` в `docs/doc-sync.json` — не требуется (остаётся `warn`; правка —
только коммитом реестра, не env).

---

## 12. Решения архитектора по OQ

| OQ | Решение | Статус |
|---|---|---|
| **OQ-1** (51825 общий с клиентами?) | Требуется факт с живого asv2; реализация FR-8 вне цикла. Рекомендация: отдельный `awg2`/порт для ноги релея (whitelist-по-IP на общем порту отвергнут — рвёт клиентов). | **ОТКРЫТ**, блокирует только FR-8 |
| **OQ-3** (порог 300 с / тик 2 мин) | Принято, **но** порог валиден только вместе с гейтом активности (§3.1); без него 300 с в простое — ложные тревоги. Оба значения конфигурируемы. | **ЗАКРЫТ** |
| **OQ-4** (cooldown 30 мин / 6 в час) | Принято: 30 мин на тип события, 6/час глобально, эскалация вверх обходит и то, и другое; при превышении — одна сводка в час со счётчиками подавленного. | **ЗАКРЫТ** |
| **OQ-7** (отдельный юнит vs хук в health) | Отдельный юнит: разные exit-контракты, секреты, каденции, жизненные циклы (§3.7). | **ЗАКРЫТ** |
| **OQ-8** (манёвр в этом цикле?) | Отдельный REQ/ADR в следующем цикле (риск обрыва канала, меняет межузловую схему). | **ОТКРЫТ**, блокирует только FR-9 |
| **OQ-9** (структурный тег в `vds logs`) | Journal-тегов достаточно для v1; `analyze` работает по ndjson и не трогается. В конвейер добавляется только состояние самого юнита (`WATCH_UNITS`). | **ЗАКРЫТ** |
| **OQ-12** (получатели) | Один `TG_CHAT_ID`; `SMTP_TO` допускает список через запятую (бесплатно, риска нет). Multi-tenant вне v1. | **ЗАКРЫТ** |
| OQ-10 (IPv6 egress) | Не решаем: `urllib`/`smtplib` используют системный стек; отдельного v6-кода нет. Если v6 сломан — `ALERT-FAILED dns/conn`. | закрыт по умолчанию |
| OQ-11 (ложные «down» при шейпинге) | Снят конструкцией: TCP-проба до релея **никогда** не триггерит сама по себе — только вместе с мёртвым handshake и активностью; ICMP — лишь текст сообщения. | **ЗАКРЫТ** |

---

## Следующий шаг
→ `vds-coder`: WP-1 → (WP-2 ∥ WP-3 ∥ WP-6) → WP-4 → WP-5 → WP-7.
Далее `vds-tester` по §6 + чеклист живой приёмки; FR-8/FR-9 — отдельным REQ после
закрытия OQ-1/OQ-8.
