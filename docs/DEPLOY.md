# DEPLOY — деплой VDS на новый сервер

> Пошаговый деплой VDS Orchestrator (Xray Reality + Hysteria2) на новый сервер
> Ubuntu 24.04 **без ИИ и без ручных швов**. Версия: 2026-11.

## Быстрая навигация

- Настройки ОС/сервера, которые **не** восстанавливаются автоматически:
  [SERVER-BASELINE](SERVER-BASELINE.md) (UFW-порты, swap, SSH, провайдер/DNS).

- [Вариант A: one-shot](#вариант-a-one-shot-рекомендуется) — одна команда с локальной машины
- [Вариант B: ручной](#вариант-b-ручной-деплой) — curl + последовательность `vds`-команд
- [Если GitHub заблокирован](#если-github-заблокирован)
- [Проверка после деплоя](#проверка-после-деплоя)
- [Известные ограничения](#известные-ограничения)

---

## Вариант A: one-shot (рекомендуется)

Скрипт `scripts/11_vds-deploy.sh` из репозитория [ubuntuInstaller](../../../ubuntuInstaller)
запускается на **локальной** машине. Он спрашивает IP, пользователя, домен и email —
и делает всё остальное. Список протоколов можно задать env'ом
(`VDS_PROTOCOLS`, по умолчанию `reality,hysteria2`), также как `VDS_IP` /
`VDS_DOMAIN` / `VDS_EMAIL` для неинтерактивного запуска:

```bash
bash ~/Dev/ubuntuInstaller/scripts/11_vds-deploy.sh
VDS_PROTOCOLS=reality,hysteria2,obfs,hop,xhttp,cdn,awg \
VDS_DOMAIN=vpn.example.ru VDS_EMAIL=admin@example.ru \
    bash ~/Dev/ubuntuInstaller/scripts/11_vds-deploy.sh
```

Установка протоколов идёт одной идемпотентной командой `vds gateway init --apply`
(SPEC-20261114) — см. [«Полное развёртывание: vds gateway init»](#полное-развёртывание-vds-gateway-init).

Что делает скрипт по шагам:

| Шаг | Действие |
|---|---|
| 1 | SSH-ключ: генерация при отсутствии → `ssh-copy-id` (пароль от сервера один раз) |
| 2 | `rsync` репо `vds/` → `/opt/my-vds/` (исключая `.git`, `state.json` и прочее — см. [ограничения](#известные-ограничения)) |
| 3 | `INSTALL_DIR=/opt/my-vds bash /opt/my-vds/install.sh` на сервере |
| 4 | Не-root юзер `vpn-accept` (idempotent) + `authorized_keys` от root |
| 5 | Авто-детект GitHub: недоступен → `VDS_GITHUB_MIRROR` в `/etc/environment` |
| 6–8 | `vds gateway init --apply --protocols <VDS_PROTOCOLS> [--domain/--email] --demo-clients` — Reality, Hysteria2, ACME/use-domain (при домене), выбранные транспорты, демо-клиенты, healthcheck-таймер |
| 9 | Печать полных share-links для импорта в клиентские приложения |

При ошибке на любом шаге скрипт печатает номер шага и однострочную команду докатки вручную.

---

## Полное развёртывание: vds gateway init

`vds gateway init` (SPEC-20261114) — идемпотентная команда установки всего gateway
с нуля: preflight (root, публичный IP, DNS, занятость портов) **до** мутаций,
затем последовательные шаги через существующие команды. Dry-run по умолчанию:
план и проверки без изменений; мутации только с `--apply`.

```bash
vds gateway init                                  # dry-run: план + проверки
vds gateway init --apply                          # reality + hysteria2 (как раньше)
vds gateway init --apply \
    --protocols reality,hysteria2,obfs,hop,xhttp,cdn,awg \
    --domain vpn.example.ru --email admin@example.ru \
    --sni www.cloudflare.com --hop-range 20000-20500 \
    --demo-clients
```

| Флаг | Default | Смысл |
|---|---|---|
| `--protocols` | `reality,hysteria2` | csv из `reality,hysteria2,obfs,hop,xhttp,cdn,awg` |
| `--domain` | — | домен для ACME/CDN/ссылок (обязателен вместе с `--email`) |
| `--email` | — | ACME (не сохраняется) |
| `--sni` | `www.google.com` | Reality dest/serverNames |
| `--hop-range` | `20000-20500` | диапазон port hopping при `hop` |
| `--cdn-domain` | = `--domain` | origin-домен CDN |
| `--demo-clients` | off | создать phone/mob/laptop и напечатать ссылки |
| `--apply` | off | исполнить (иначе dry-run) |
| `--require-domain` | off | DNS не подтверждён → exit 1 вместо skip с warning |

Шаги: Reality → Hysteria2 → (домен) ACME → apply-cert → use-domain → XHTTP → CDN
→ obfs → hop → AmneziaWG → healthcheck-таймер. Уже установленное скипается по
state (расхождение state/мёртвый юнит — warning и переустановка); при DNS,
не резолвящемся в публичный IP, доменные шаги (ACME/XHTTP/CDN) пропускаются с
warning, остальное ставится. Занятый чужим процессом порт → fail **до** любых
изменений, с владельцем порта. Повторный вызов — «изменений не требуется», exit 0.

### Приёмка на чистой VM/VDS (чеклист)

1. `vds gateway init --apply --domain … --email … --protocols reality,hysteria2,obfs,hop,xhttp,cdn,awg`
   → юниты `vds-xray` / `vds-hysteria2` / `vds-hysteria2-obfs` / `vds-hysteria2-hop` /
   `vds-amneziawg` active; порты 443/tcp, 443/udp, 8443/tcp, 2053/tcp, 51825/udp,
   51826/udp (+ hop-диапазон) слушаются (2053/tcp — только для CIDR
   Cloudflare); пути XHTTP/CDN-WS случайные (state.json); `vds gateway links
   --include-obfs` непустой; `vds-gateway-health.timer` активен.
2. Повторный тот же вызов — ни одной мутации, «изменений не требуется», exit 0.
3. Без `--domain`: acme/cdn пропущены с понятным warning, reality/hy2/awg работают.
4. Занятый порт (`python -m http.server 8443`) → init падает до установки,
   сообщает порт/владельца, ничего не ломает.

---

## Вариант B: ручной деплой

Всё выполняется **на сервере** от root.

### 1. Установка

```bash
# Опционально — базовая подготовка (юзер, SSH, UFW, Docker, swap)
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/main/preinstall.sh | bash

# Установка VDS Orchestrator
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/main/install.sh | bash
```

`install.sh` создаёт venv, ставит зависимости и симлинк `vds`.

### 2. Протоколы

```bash
vds xray install          # Xray VLESS Reality, TCP 443 (--sni www.google.com по умолчанию)
vds hysteria2 install     # Hysteria2 QUIC, UDP 443, self-signed (--port 443 по умолчанию)
```

Повторный запуск безопасен: «уже установлен» → exit 0, без перекачки бинарей.

### 3. Домен (опционально)

Требуется A-запись домена → публичный IP сервера и **открытый порт 80** (HTTP-01).

```bash
vds acme issue --domain example.com --email you@example.com
vds xray add-transport xhttp --domain example.com --mode port --apply --yes
vds xray use-domain --domain example.com
```

- `acme issue` — выпуск LE-сертификата + deploy-hook; «уже выдан» → exit 0.
- `add-transport xhttp`:
  - `--mode port` — XHTTP на публичном порту **8443** (рекомендуется при DPI-давлении);
  - `--mode fallback` — SNI-разделение за Reality на 443;
  - `--apply` — применить (по умолчанию dry-run), `--yes` — без интерактивного подтверждения.
  - инблэнд рендерится с `xhttpSettings: {mode: "auto", xPaddingBytes: "100-1000"}`
    (GR-25): сервер принимает stream-one/stream-up/packet-up и рандомизирует
    длину служебного padding'а — размывает размеры пакетов для DPI/ML.
    Минимальная версия Xray — **26.1.23** (ADR-010); `xray -test` в apply-гейте
    обязан вернуть OK, иначе конфиг откатывается из бэкапа. Старые клиенты
    (только `path`) продолжают подключаться — share-link не изменился.
  - миграция существующего XHTTP: повторный `--apply` дозаполняет
    `mode`/`xPaddingBytes` (path-секрет сохраняется); живой CDN-инбаунд
    (ws/2053) переносится из текущего config.json без потерь. После смены IP
    узла, пока DNS ещё смотрит на старый адрес, — `--skip-domain-check`
    (сертификат/SNI не меняются; только для этой миграции).
- `use-domain` — адрес Reality share-links заменяется с IP на домен.

### 4. Клиенты

```bash
vds xray add-client phone       # Reality-клиент (или --transport xhttp после шага 3)
vds hysteria2 add-client mob
```

Дубликат имени — ошибка; удаление клиентов через `vds xray remove --apply` / `vds hysteria2 remove --apply` (сначала dry-run).

### 5. Ссылки

```bash
vds gateway links               # все share-links, по одному на строку (name: link)
vds gateway status              # состояние state.json: клиенты, протоколы, домен
```

---

## Если GitHub заблокирован

Загрузка бинарей Xray/Hysteria2 идёт с `github.com`. Если сервер не может достучаться
(RKN-DPI и т.п.), включите зеркало через env `VDS_GITHUB_MIRROR`:

```bash
echo 'VDS_GITHUB_MIRROR=https://ghproxy.net' >> /etc/environment
```

Зеркала (проверены оба, подставьте рабочее):

- `https://ghproxy.net`
- `https://gh-proxy.com`

Проверка канала с сервера:

```bash
curl -s -o /dev/null -w '%{http_code}' --max-time 15 -L \
  https://github.com/XTLS/Xray-core/releases/download/v26.1.23/Xray-linux-64.zip.dgst
# 200 = direct; иначе пробуйте зеркало:
curl -s -o /dev/null -w '%{http_code}' --max-time 15 -L \
  https://ghproxy.net/https://github.com/XTLS/Xray-core/releases/download/v26.1.23/Xray-linux-64.zip.dgst
```

- Значение читается из **переменной окружения** (`os.environ` в `src/*/install.py`) —
  `.env`-файл в `/opt/my-vds` не подхватывается, поэтому пишем в `/etc/environment`
  (там его видят и login-shell, и неинтерактивные `ssh host cmd`).
- Конвенция gh-proxy: зеркало префиксует оригинальный URL целиком.
- Trade-off: при зеркале SHA256-файл `.dgst` тоже идёт через зеркало — доверие
  смещается на зеркало. Флаг сознательный, по умолчанию выключен.

Скрипт `11_vds-deploy.sh` делает этот детект автоматически (шаг 5).

---

## Проверка после деплоя

На сервере:

```bash
systemctl is-active vds-xray vds-hysteria2      # active active
ss -tlnp | grep -E ':(443|8443)\s'              # TCP 443 (Reality), 8443 (XHTTP, если домен)
ss -ulnp | grep ':443'                          # UDP 443 (Hysteria2)
vds gateway links                               # ссылки клиентов
```

С **внешней машины** (probe-resistance — сервер не должен паниковать на «мусор»):

```bash
# Reality (TCP 443): TLS с произвольным SNI отвечает и соединение закрывается штатно
curl -sv --max-time 10 https://<IP-СЕРВЕРА> -o /dev/null 2>&1 | tail -5

# XHTTP (TCP 8443, если домен): отвечает TLS-хендшейк
curl -sv --max-time 10 https://example.com:8443 -o /dev/null 2>&1 | tail -5

# Hysteria2 (UDP 443): проверить может только реальный клиент (hysteria/sing-box)
```

Финальная приёмка — импортировать ссылки из `vds gateway links` в клиентское
приложение (v2rayNG / Hiddify / sing-box) и проверить трафик с телефона.

### После деплоя: harden и мониторинг (чеклист)

```bash
vds system ufw harden --profile gateway --apply    # UFW-hardening (ADR-011; dry-run по умолчанию)
vds system ufw ssh-port --to 49222 --apply         # двухфазный перенос SSH; 22 закрывает --finalize
vds system ufw status                              # сводка UFW + pending-перенос
vds gateway probe-watch install --apply            # монитор зондирования tcp/443 + threat-level (И33)
vds gateway probe-watch ru-cidr install --apply    # RU-CIDR без релея: RU-PROBE-SUSPECT (+таймер)
```

При threat `high` (см. [SERVER-BASELINE](SERVER-BASELINE.md) §5.12):
`vds system ufw lock-443 --reason RU-PROBE-SUSPECT --ttl 48h --apply` —
изоляция 443 с TTL и undo; AWG/CDN/ssh остаются живы. Auto-lockdown по умолчанию
выключен (`vds gateway probe-watch config`).

### Сторож угрозы на exit-узле (SPEC-20261117-alert-watch)

Уведомления отправляет **exit-узел** (на RU-рееле секретов нет). Порядок:

1. `sudo vds alert install` — dry-run: план, имена ключей `alert.env` и
   запрошенные каналы (без `--channel` — «авто по парам ключей»). Ничего не
   пишется. Флаги: `--interval` (тик, 2m), `--handshake-threshold` (порог пульса
   плеча, 300s), `--heartbeat` (dead-man switch, 24h), `--force`,
   `--allow-relay-node` (на релее не использовать).
2. Создать `/etc/vds/alert.env` (0600): пары `TG_BOT_TOKEN`+`TG_CHAT_ID` и/или
   `SMTP_HOST`/`SMTP_FROM`/`SMTP_TO`/`SMTP_PASS` (App Password, не основной
   пароль). **Порт 587 требует обоих ключей:** `SMTP_PORT=587` и
   `SMTP_STARTTLS=1` — по умолчанию `SMTP_PORT=465` (implicit TLS), и STARTTLS
   на нём не работает. Параметры — `ALERT_*`; полный шаблон со значениями по
   умолчанию — это сам `/etc/vds/alert.env`, который создаёт `install --apply`
   (без `--force` существующий сохраняется). Минимально для почты
   (implicit TLS, порт 465):

   ```bash
   sudo install -m 0600 /dev/null /etc/vds/alert.env
   sudoedit /etc/vds/alert.env   # SMTP_HOST/SMTP_FROM/SMTP_TO/SMTP_PASS
   # для :587 дополнительно: SMTP_PORT=587 и SMTP_STARTTLS=1
   ```

3. `sudo vds alert install --apply` — рендер `vds-alert-watch.service`/`.timer`,
   `daemon-reload`, enable/start таймера. Идемпотентно; существующий `alert.env`
   не перезаписывается без `--force`.
4. `sudo vds alert test` (или `--channel smtp` — быстрая проверка почты) —
   реальная отправка, **без** записи state.
5. Каденция уведомлений: повтор того же уровня — `ALERT_COOLDOWN_MIN` (30 мин),
   «всё ещё high» — `ALERT_HIGH_REMINDER_H` (6 ч, диапазон 1..24; имя ключа видно
   в плане `vds alert install`), напоминание о
   локе — 6 ч; переходы уровня и снятие лока — мгновенно. Подавленные `*_still`
   не порождают сводку.

6. `sudo vds alert status` — сверить каналы, юниты и coverage (что «слепо» и
   почему). `--json` машинно читается и не содержит значений секретов. Без root
   статус работает в урезанном виде (`alert.env` 0600 не читается) — это норма,
   для coverage нужен `sudo`.
7. `ALERT_RELAY_IFACE` может быть списком (`awg2,wg-ws0`): пульс `ok`, если жив
   любой носитель — при ADR-016 это обязательно, иначе ложный `relay_blocked`
   в момент перехода на резерв.
8. `sudo vds alert watch --no-send` — прогнать тик без отправки: `relay_pulse` не
   должен быть `inconclusive` при живом канале (`idle` допустим, если на `awg1`
   не выставлен `PersistentKeepalive` — см. DEPLOY-RU-RELAY §4).

**Heartbeat (dead-man switch):** раз в `ALERT_HEARTBEAT_H`=24 ч уходит «Сторож
жив» с числом пропущенных часов и предупреждениями каналов — тишина дольше
суток сама по себе означает, что сторож или канал не работают.

**Откат:** `sudo vds alert remove --apply` (юниты сняты, `alert.env` сохранён) →
`--purge` (удалить и `alert.env`/`alert-state.json`). UFW, `probe-watch.json` и
`state.json` не затрагиваются. Диагностика доставки — `journalctl -u
vds-alert-watch` (теги `ALERT-SENT`/`ALERT-FAILED`/`ALERT-SKIP`).

---

## Изолированная нога relay→exit (P24, ADR-015)

Ставится на **exit-узле**, клиентский `awg0` (51825) не затрагивается:

```bash
# на релее — публичный ключ ноги awg1:
awg show awg1 public-key
# на exit: dry-run → apply
sudo vds relay exit-leg install --relay-ip <relay-ip> --public-key <awg1-pub>
sudo vds relay exit-leg install --relay-ip <relay-ip> --public-key <awg1-pub> --apply
```

Проверка: `systemctl is-active vds-awg-relay vds-awg-relay-pool`, `awg show awg2`
(peer релея), `ufw status | grep 51900` (только с IP релея), внешний скан портов
пула 51900–51911 с чужого IP — тишина. Откат: `sudo vds relay exit-leg remove --apply`.
Подробности и порядок с `relay init` — `docs/DEPLOY-RU-RELAY.md` §4.1.

Манёвр ноги (P25, ADR-015): `vds relay maneuver status|step|rollback` на релее;
opt-in таймер `vds relay maneuver install --apply [--enable-auto] [--interval 60s]`
(auto=off по умолчанию; детекция ≈180 с при 60s, реакция актуатора <60 с).
Подробности — `docs/DEPLOY-RU-RELAY.md` §4.2.

---

## Пробы при приёмке: серийно, с паузами (И26)

Не запускайте параллельно `openssl s_client`, `ssh` и клиентские пробы к
одному и тому же SNI: серия хендшейков сама вызывает behavioral-blackhole
TSPU (~120 с), и приёмка «ломает» канал, который проверяет. Пауза между
пробами ≥ 1 с, между разными транспортами — последовательно. `vpn probe`
соблюдает инвариант сам (`SAMPLE_PAUSE`/`SLEEP_BETWEEN`).

## Известные ограничения

1. **Один сервер = один домен.** `acme issue` и `xray add-transport` рассчитаны на
   один домен; второй домен на тот же Xray — без миграции state.
2. **`gateway/state.json` не синкать.** Это runtime-файл **живого** сервера (клиенты,
   протоколы, пароли). `rsync --delete` без exclude стирает его — реальный инцидент
   был. Скрипт 11 всегда исключает `gateway/state.json`; при ручном rsync —
   добавляйте `--exclude='gateway/state.json'` обязательно.
3. **DPI может задавить порт 8443.** Если XHTTP:8443 перестал проходить — переключитесь
   на fallback (SNI-разделение за Reality на 443):
   `vds xray remove-transport xhttp --apply --yes`, затем
   `vds xray add-transport xhttp --domain <домен> --mode fallback --apply --yes`,
   и пересоздайте XHTTP-клиентов (`vds xray add-client <имя> --transport xhttp`).
4. **Reality и Hysteria2 делят порт 443** (TCP vs UDP) — освобождать ничего не нужно,
   но любой сторонний сервис на 443 заблокирует установку (install проверяет `ss -tlnp`).
