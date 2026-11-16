# ADR-014: клиентская наблюдаемость — демон `vpn guard`, контракт `guard.*` и приватность артефактов

- **Дата:** 2026-11-16
- **Статус:** accepted (G2 APPROVED 2026-11-16; пять правок ревью внесены)
- **Контекст SPEC:** [SPEC-20261116-vpn-guard](../team/specs/SPEC-20261116-vpn-guard.md)
  (§20.2 п.8: ADR обязателен — новый демон, постоянные артефакты,
  кросс-репо контракт)
- **Связанные:** ADR-002 (пути/юниты/state), ADR-005 (AmneziaWG),
  ADR-012 (log-forensics: приватность, retention, «анализатор не реагирует»),
  SPEC-20261116-log-forensics (§3 карта слепоты сервера, §5.1 поправка M1),
  SPEC-20261116-survivability (стадии, T-18…T-23), SPEC-20261116-probe-response
  (lock-443)

## Контекст

Серверный `vds logs` (ADR-012) видит **эффекты** на NIC и активные пробы.
Целый класс отказов виден только с клиента: SNI-drop, DNS-подмена,
whitelist-режим, «handshake прошёл — данные умерли» на конкретном пути
оператора. Сегодня клиент отвечает на «VPN не работает» тремя инструментами,
и все они — точечные снимки:

- `vpn monitor` — матрица каналов и активные пробы, без истории;
- `vpn doctor` — окружение, порты, DNS, бинари, без потока ошибок;
- `vpn repair` — снимок в лог и починка DNS, запускается уже после инцидента.

Окно ТСПУ часто 2–15 минут: пользователь замечает отказ, когда лог уже
прокручен, а типичная реакция (рестарт юнита) уничтожает улики.

Ограничения, определяющие дизайн:

- клиент и ноутбук — **без root**; `awg show`, pcap, eBPF недоступны;
- анализ **локальный**: ни логов, ни телеметрии наружу, никаких LLM;
- артефакты постоянные → приватность и TTL — часть контракта, а не «потом»;
- контракт читают два репозитория (`vds` и `ubuntuInstaller`) → нужен
  версионируемый `schema_hash`, а не «договорились на словах»;
- основной канал ноутбука — **AmneziaWG** (`UDP 51825`, сплит через
  `dnsmasq`), у которого app-логов не существует by design.

## Рассмотренные варианты

| Вариант | Плюсы | Минусы |
|---|---|---|
| **Потоковый клиентский демон + правила (выбран)** | секунды, без root/сети/LLM, детерминизм, доказательства в finding | свой код; дрейф форматов Xray/Hysteria2 |
| Батч `journalctl --since` по cron | просто | минуты задержки, пропуски = не «живое время» |
| `journalctl -n` polling | просто | дубли/пропуски, задержка |
| Только серверный анализ | нет нового демона | SNI/DNS/whitelist невидимы серверу |
| SIEM / log-shipping | централизованный поиск | сеть, утечка логов, новая инфраструктура |
| pcap/eBPF на клиенте | точные пакеты | root, тяжело, дублирует серверный forensics |
| Встроить в xray/hysteria | сигнал раньше | не наш код, форк |
| LLM-триаж | «умно» | недетерминизм, утечка логов |

## Решение

1. **Скоуп и владелец.** `vpn guard` — клиентский real-time демон
   (`scripts/vpn-manager/vpnm/guard/`), **read-only v1**: не вызывает
   `systemctl`, `vpn switch`, `repair`, UFW и не меняет конфиги. Серверный
   разбор остаётся за `vds logs`; guard — недостающий vantage, не дубль.
2. **Контракт.** JSON-схемы `guard.event/1`, `guard.finding/1`,
   `guard.coverage/1`, `guard.status/1`, `guard.incident/1`,
   `guard.server_verdict/1`, `guard.config/1` принадлежат клиенту и лежат в
   `scripts/vpn-manager/vpnm/guard/schemas/` (внутри пакета — иначе
   `pip install` не довезёт схемы и `schema_hash`/`selftest` сломаются);
   реестр enum'ов — `vpnm/guard/events.py`, хэш и загрузка —
   `vpnm/guard/schema.py`. Incidents в `guard.status/1` встроены в `$defs`
   (валидируется без резолвера), а `guard.incident.1.schema.json` — отдельный
   контракт, равенство копий проверяется тестом.
   Правила версионирования: в пределах major — только аддитивные поля;
   потребитель обязан игнорировать неизвестные ключи; `schema_hash` =
   sha256 канонического JSON-схемного файла (sorted keys, UTF-8, без
   пробелов).
3. **Источники.**
   - **S1 — user-journal (`journalctl --user -f -o json`), обязателен:**
     stdout/stderr Xray/Hysteria2 попадают туда по умолчанию; фильтр
     `_SYSTEMD_USER_UNIT` → `vpnm-*`; `vpn-guard.service` исключён по имени
     (нет самопоедания);
   - **S2 — system-journal, opt-in:** `dnsmasq`, `awg-quick@*`,
     `vpn-awg-split@*`, `cloudflared-proxy-dns`, `zapret`, `NetworkManager`,
     `systemd-resolved`. Без прав — `coverage.status=denied`, guard не
     просит sudo;
   - **S3 — structured-файлы + sysfs:** `state.json`, `last-speed.json`,
     `repair-*.log`, `server-verdict.json`, `activity.json`, а также
     `/sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes}`;
   - **S4 — netlink (`ip -o monitor route`)** — v1.1, opt-in.
4. **AmneziaWG как первоклассный канал.** `proto=amneziawg`; интерфейс
   обнаруживается по имени инстанса из lifecycle, fallback — скан
   `/sys/class/net/*/type == 65534 (ARPHRD_NONE)`; `awg0` не хардкодится;
   `awg show`/`sudo` не используются. Правило — ветка
   **G-04 `awg_tx_no_rx`** (внутри существующего каталога, без G-13):
   `awg_tx_growth` + `awg_rx_flat` в двух окнах по `awg_window_s` (120 с).
   Состояние `armed` ≠ `idle`: живой AWG при `idle` — баг.
5. **Правила и пороги.** Каталог **G-01…G-12 заморожен для v1**; пороги —
   только в коде/`guard.json`, пользовательские regex запрещены
   (детерминизм и безопасность). G-01 доказывает покрытие через
   `app_banner_ok` (≤ 15 с) или `dial_start/dial_timeout/conn_refused`
   (≤ 25 с) внутри того же `INVOCATION_ID`; при полной тишине —
   `insufficient_data` + G-12, а не ложный `tunnel_down`.
   **Авто-действий нет:** finding содержит только `action`-текст.
   Авто-реакции — отдельный ADR после ≥ 30 дней полевых данных.
6. **Юнит и sandbox.** Имя — **`vpn-guard.service`**, не `vpnm-*`:
   `runners.enabled_vpnm_units()` считает любой `vpnm-*.service` профилем, и
   `vpn down`/`vpn autostart off` могли бы отключить сам guard. Два профиля:
   `hardened` (ProtectedSystem=strict, NoNewPrivileges, SystemCallFilter,
   RestrictAddressFamilies=AF_UNIX, ReadWritePaths только
   `~/.local/share/vpn-manager/guard`) и `compat` (без namespace-опций) —
   выбор **только по факту** `226/NAMESPACE` на живом юните, с записью в
   `install-state.json` и `sources.unit_profile`.
7. **Приватность — часть контракта.**
   - сырой текст строки не персистится; хранятся счётчики, окна, хэши
     шаблонов (`sha1(template)[:12]`) и `evidence`;
   - маскирование до записи: UUID, hex≥32/base64≥24 (только свободный
     текст), `password`/`privateKey`/`shortId`/`obfs-password`, share-ссылки,
     URL с токенами, email; сниппеты по умолчанию **выключены**;
   - пост-сканер перед записью/`export` **не** считает секретом allowlist
     (`schema_hash`, `rules_hash`, `config_hash`, `raw_sha256`, `template`,
     `id`, `evidence_hash`) и значения `sha256:<64 hex>`; хит в свободном
     поле → finding без сниппета, `export` блокируется (код 2);
   - retention: findings 14 дней / 20 МБ (5 × 4 МБ), trace 1 час / 10 МБ,
     каталог 0700, файлы 0600; `export` ≤ 5 МБ и хосты → `<host>` по
     умолчанию.
8. **Кросс-vantage — только файл.** Демон не открывает сетевых сокетов
   (тест с monkeypatch `socket`). Единственная сетевая команда —
   `vpn guard sync` (один ssh-вызов), которая пишет
   `~/.local/share/vpn-manager/server-verdict.json` по allowlist.
   Источник — `vds gateway probe-watch watch --json` **без `--record`**:
   read-only зафиксирован кодом (`cmd_watch`: запись только под
   `if record:`) и серверным regression-тестом на неизменность
   `mtime`+`sha256` `/var/lib/vds/probe-watch.json` и gateway `state.json`
   (touch lock-файла не считается). Opt-in таймер — **60 мин**, свежесть
   `fetched_at` ≤ **65 мин** (серверный `vds-probe-watch.timer` тикает раз
   в час); `stage` — опциональное поле (`str`/`None`).
9. **Честная деградация.** Нет источника — `coverage.status=denied/lost`,
   а не «всё хорошо»; нет прав на системный журнал — `denied` + note;
   слепота app-логов — `app_signal=blind` + G-12 `observability`;
   лог уровня не меняется (это не задача guard).

## Красные флаги (git-гигиена, проверяется тест-сканером)

- артефакты guard живут в XDG-каталогах (`~/.local/share/vpn-manager/guard`,
  `~/.config/vpn-manager/guard.json`) и в репозиторий не попадают;
  `findings.jsonl`, `trace.ndjson`, `install-state.json` — runtime, не git;
- фикстуры тестов — только `FIXTURE_PW_*`/`FIXTURE_UUID_*` и
  зарезервированные `203.0.113.0/24` (RFC 5737), `11111111-2222-…`
  (AGENTS §6); «правдоподобные» пароли запрещены (ложные срабатывания
  детекторов);
- в finding/`export` не попадают IP третьих сторон, `ru_top`, `top`,
  payload, SNI, share-ссылки, UUID и ключи.

## Последствия

- **Положительные:** отказ объясняется за секунды с указанием слоя и стадии
  (`stage_hint`), с доказательствами и выполненными FP-проверками; инцидент
  фиксируется до того, как лог прокручен; клиентский и серверный vantage
  склеиваются по `schema_hash` без общих зависимостей; AWG (основной канал)
  перестаёт быть слепым пятном; приватность обеспечена конструктивно.
- **Отрицательные:** постоянный user-демон (смягчено `Nice=10`,
  `CPUQuota=10%`, `MemoryMax=128M`); без поднятого loglevel глубина
  app-сигналов ограничена — компенсируется `app_banner_ok`/`dial_*` и
  честным `insufficient_data`; схема-контракт требует синхронизации
  `schema_hash` в CI обоих репозиториев.
- **Трудно изменить позже:** имена схем `guard.*/1`, набор полей
  finding/coverage, privacy-контракт и retention — только новым ADR
  (аддитивные поля в пределах major допустимы).
- **Откат:** `vpn guard uninstall` (снимает юнит/таймер, сохраняет историю)
  или `vpn guard uninstall --purge` (удаляет каталог артефактов).
  Серверная сторона не меняется вообще — `vds logs`/probe-* не затронуты.
