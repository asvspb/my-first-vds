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
   51826/udp (+ hop-диапазон) слушаются; `vds gateway links --include-obfs`
   непустой; `vds-gateway-health.timer` активен.
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
  https://github.com/XTLS/Xray-core/releases/download/v25.1.1/Xray-linux-64.zip.dgst
# 200 = direct; иначе пробуйте зеркало:
curl -s -o /dev/null -w '%{http_code}' --max-time 15 -L \
  https://ghproxy.net/https://github.com/XTLS/Xray-core/releases/download/v25.1.1/Xray-linux-64.zip.dgst
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
