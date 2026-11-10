# SPEC-20261110-cdn-transport

## Мета
- **Источник:** [REQ-20261110-cdn-transport](../requirements/REQ-20261110-cdn-transport.md) (G1 READY)
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-10
- **Статус:** approved (G2)
- **ADR:** [ADR-006](../../adr/ADR-006-cdn-cloudflare-transport.md) (OQ-1..5)
- **Параллельный цикл:** AmneziaWG (G3). Файлы `src/amneziawg/*` — **не трогаем**.
  Единственный потенциально общий файл двух циклов — `src/main.py` (AWG-команды
  уже зарегистрированы; WP-3 этого SPEC вносит только добавляющие команды).
  При коллизии — сериализация WP-3 после AWG WP-4, у оркестратора.

## 1. Цель и решение

Пятый канал gateway-стека: **VLESS+WS+TLS за Cloudflare proxy** — цензор видит
IP Cloudflare, не 103.45.247.172. Реализация: отдельный proxied-DNS-элемент
`cdn.eu-cloud-xip.com` (orange cloud), отдельный Xray-инблэнд
vless+ws+tls на TCP **2053** с LE-сертификатом cdn-домена, share-link
`vless://…@cdn.eu-cloud-xip.com:2053`. Все существующие каналы (Reality 443,
Hysteria2 UDP 443, XHTTP-direct 8443 path `/xhttp`) не изменяются —
вычитающая интеграция в том же паттерне, что `add-transport xhttp` прошлого
цикла. DNS-перенос зоны в CF и включение proxy — ручные шаги владельца по
чеклисту §8 (OQ-5), код их не автоматизирует, но проверяет прекондишны.

## 2. Архитектура

```
CDN-клиент (v2rayNG/Hiddify)
   │ vless://…@cdn.eu-cloud-xip.com:2053  TLS SNI=cdn.eu-cloud-xip.com, ws path /cdnws
   ▼
Cloudflare edge (orange cloud на cdn.eu-cloud-xip.com)     ← DNS: A 103.45.247.172, proxied
   │ TLS терминируется на edge; CF→origin: HTTPS на ТОТ ЖЕ порт 2053 (факт CF)
   ▼
asv1: Xray inbound #3  vless+ws+tls, listen :2053 (все интерфейсы)
      TLS: LE-сертификат cdn.eu-cloud-xip.com (certbot, HTTP-01, выдан до orange)
      ▼ outbound freedom → интернет (exit-IP = 103.45.247.172)

Direct-каналы — без изменений:
  client → 103.45.247.172:443  Reality  (запись 103-45-247-172.eu-cloud-xip.com, grey)
  client → 103.45.247.172:8443 XHTTP-direct path /xhttp (тот же grey)
  client → 103.45.247.172:443/udp Hysteria2
  апекс eu-cloud-xip.com — grey (DNS-only)
```

Точки отказа: CF edge (E10 — известное ограничение, direct-каналы не зависят);
LE-продление cdn-домена через edge (E11 — fallback временного grey).

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/gateway/paths.py` | изменить (append) | Константы CDN: `CDN_ORIGIN_PORT_DEFAULT = 2053`, `CDN_WS_PATH = "/cdnws"`, `CDN_DOMAIN_HINT = "cdn."` (имя поддомена приходит флагом, константа — только подсказка для сообщений). Не задевая AWG-константы (строки 30–38). |
| `src/xray/config.py` | изменить | Расширить `XrayConfigParams` полями `cdn_enabled`, `cdn_client_ids`, `cdn_domain`, `cdn_cert_path`, `cdn_key_path`, `cdn_port`, `cdn_ws_path`; добавить `_cdn_inbound()` (vless+ws+tls, `wsSettings: {path, headers.Host: cdn_domain}`); append в `inbounds` только при `cdn_enabled=True`. Без CDN-полей рендер байт-в-байт прежний (золотой снапшот-тест уже есть — расширить кейс). |
| `src/xray/cdn.py` | **создать** | Весь CDN-механизм: прекондишны, install, remove, share-link render, state. Ниже — интерфейсы. |
| `src/xray/status.py` | изменить | Секция CDN-канала в выводе статуса (поддомен, транспорт ws, origin-порт, DNS-чек CF, cert-даты), маскирование уже общее (`_mask_secrets`). |
| `src/gateway/links.py` | изменить | `render_all_links` добавляет CDN-записи (делегирует в `cdn.render_cdn_share_link`). |
| `src/main.py` | изменить (добавляющие команды) | `xray add-cdn`, `xray remove-cdn` — **новые** команды, ленивый импорт `src.xray.cdn` внутри функций. Существующие команды не менять (аддитивное расширение CLI — ADR не требует). |
| `tests/xray/test_cdn_config.py` | создать | Рендер CDN-инблэнда + золотой снапшот «без CDN → прежний JSON». |
| `tests/xray/test_cdn.py` | создать | Юнит-тесты cdn.py на моках (DNS-чек, share-link формат, idempotency, store). |

Не создаются: `systemd/*` (новых юнитов нет — CDN-инблэнд живёт в
`vds-xray.service`), новые UFW-правила не требуются (2053/tcp открыть —
см. §4.2: одно правило, добавляет WP-2, откат — удаление этого правила).

**Публичные интерфейсы (сигнатуры, не реализация):**

```python
# src/xray/cdn.py
@dataclass(frozen=True)
class CdnParams:
    domain: str              # cdn.eu-cloud-xip.com (поддомен с proxied-записью)
    port: int = CDN_ORIGIN_PORT_DEFAULT
    ws_path: str = CDN_WS_PATH

def check_prerequisites(params: CdnParams) -> list[str]:
    """Вернуть список нарушений (пусто = ок): root; порт 2053 свободен (ss -tlnp);
    DNS поддомена резолвится в CF-диапазоны (cloudflare.com/ips, список
    зашит константой, обновляемый коммитом); cert файлы существуют."""

def is_cloudflare_ip(ip: str) -> bool: ...

def install_cdn(params: CdnParams, state_path: str | None = None) -> int:
    """FileLock; бэкап config.json; render+запись атомарно 0600; xray -test;
    рестарт vds-xray; state.protocols['xray-cdn'] = {domain, port, ws_path,
    cert_issued, clients:{}}; UFW allow 2053/tcp если не было."""

def remove_cdn(apply: bool, state_path: str | None = None) -> int:
    """dry-run по умолчанию (--apply); вычитание инблэнда; бэкап; xray -test;
    рестарт; вычистка CDN-клиентов из state; idempotent-отказ при повторе."""

def render_cdn_share_link(uuid: str, params: CdnParams, name: str) -> str: ...

def cdn_add_client(name: str, state_path: str | None = None) -> dict: ...
def cdn_remove_client(name: str, apply: bool, state_path: str | None = None) -> int: ...
```

**CLI-поверхность:**

```bash
vds xray add-cdn --domain cdn.eu-cloud-xip.com [--port 2053]
vds xray remove-cdn [--apply]        # dry-run по умолчанию
vds xray add-cdn-client <name>       # выдаёт share-link
vds xray remove-cdn-client <name> [--apply]
```

**Формат данных:**

- `state.json` → `protocols["xray-cdn"]`: `{"domain": "cdn.eu-cloud-xip.com",
  "port": 2053, "ws_path": "/cdnws", "clients": {"<имя>": {"uuid": "…"}},
  "cert_issued": "<ISO>"}` — права файла 0600 уже обеспечивает store.
- CDN-инблэнд (рендер, детерминированный порядок ключей):

```json
{
  "port": 2053,
  "protocol": "vless",
  "settings": {"clients": [{"id": "<uuid>"}], "decryption": "none"},
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "wsSettings": {"path": "/cdnws", "headers": {"Host": "cdn.eu-cloud-xip.com"}},
    "tlsSettings": {"certificates": [{"certificateFile": "…/fullchain.pem",
                                       "keyFile": "…/privkey.pem"}]}
  }
}
```

- Share-link (формат — юнит-тестом):
  `vless://<uuid>@cdn.eu-cloud-xip.com:2053?encryption=none&security=tls&sni=cdn.eu-cloud-xip.com&type=ws&host=cdn.eu-cloud-xip.com&path=%2Fcdnws#<name>`

## 4. Миграция и совместимость

### 4.1 Совместимость
Ничего не ломается по построению: CDN — добавляющий inbound + вычитающее
удаление; Reality-поля config.json (`realitySettings`) не читаются и не пишутся
CDN-кодом. Без `cdn_enabled` рендер прежний (тест-гейт WP-1).

### 4.2 Порядок развёртывания (важен, часть архитектуры)
1. Владелец переносит зону в CF, создаёт запись `cdn` **grey** (чеклист §8, шаги 1–5).
2. Оператор: `vds acme issue cdn.eu-cloud-xip.com` (HTTP-01 работает при grey;
   переиспользует механизм ADR-004 — сертификат кладётся в
   `/etc/letsencrypt/live/cdn.eu-cloud-xip.com/`).
3. Оператор: `vds xray add-cdn --domain cdn.eu-cloud-xip.com` — инблэнд на 2053,
   UFW allow 2053/tcp, рестарт vds-xray.
4. Владелец: переключить запись `cdn` в orange cloud + SSL/TLS Full (strict)
   + проверить WebSockets On (чеклист §8, шаги 6–8).
5. Приёмка §6.

### 4.3 Девиация от REQ (зафиксирована, правка REQ — на G5)
**FR-4** требует «порт ссылки — 443 (CF edge), НЕ origin-порт». Факт CF:
**edge-порт = origin-порт** (CF соединяется с origin на порту подключения
клиента). «443 → origin 443» упирается в Reality-инблэнд. Решение (ADR-006
OQ-3): ссылка и origin на **2053** (CF-supported HTTPS-порт). Альтернатива
«edge 443 + CF Origin Rules (port override)» отложена. Аналитик правит FR-4
текст REQ на G5-docs; приёмка §6 проверяет фактическое поведение (egress
через CF), а не букву «443».

## 5. Безопасность и отказы
- Секреты: uuid CDN-клиентов — в state.json (0600) и в share-link только в
  выводе команды; приватный ключ LE cdn-домена — 0600 certbot-пути; в логах —
  маскирование через `status._mask_secrets` (переиспользуем). CF API-токен —
  не появляется (OQ-5).
- Dry-run: `remove-cdn` / `remove-cdn-client` — dry-run по умолчанию + `--apply`.
- Откат: §«Как откатить» ADR-006 (toggle orange cloud → remove-cdn → бэкапы).
- Failure modes: E1 (нет CF в DNS / зона не перенесена — отказ до изменений);
  E5 (нет root — читаемая ошибка); E6/E7 — не применяются (загрузок нет);
  E8 (битый config.json — бэкап + отказ, `xray -test` гейтит рестарт);
  E9 (порт 2053 занят — `ss -tlnp` до изменений); E11 (LE-продление — §8 шаг 9).
- Блокировки: install/remove под `core.lock.FileLock`. Shell — только `run_list`.
- Хост-порт vs CF: UFW — ровно одно новое правило `2053/tcp`; политика UFW
  в остальном не трогается.

## 6. Тест-план
| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | рендер CDN-инблэнда: валидный JSON, детерминированный, приватный материал не в снапшоте; без cdn_enabled → байт-в-байт прежний | `tests/xray/test_cdn_config.py` |
| Unit | `is_cloudflare_ip` по списку диапазонов; share-link формат (host/port 2053/type=ws/path/host header); idempotency install/remove на моках; state-структура | `tests/xray/test_cdn.py` |
| Integration (Docker) | **не требуется** — e2e CDN без реального CF-домена не воспроизводим; заменяется [VDS]-приёмкой (как принято для каналов gateway) | — |
| Ручная приёмка (VDS) | чеклист §7 + инварианты §7.2 (Reality-gate) | живой asv1 |

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | Рендер: константы paths.py (append, вне AWG-блока) + `cdn_*` поля `XrayConfigParams` + `_cdn_inbound` + append-логика; юнит-тесты рендера | `src/gateway/paths.py`, `src/xray/config.py`, `tests/xray/test_cdn_config.py` | — | `python -m compileall -q src`; `pytest -q tests/xray/test_cdn_config.py tests/gateway` зелёный; золотой снапшот прежнего рендера не изменился |
| WP-2 | `src/xray/cdn.py`: прекондишны (root/порт/DNS-CF), `install_cdn` (FileLock, бэкап, атомарная запись 0600, `xray -test`, рестарт, UFW 2053/tcp, state), `remove_cdn` (dry-run/`--apply`, idempotent), `cdn_add_client`/`cdn_remove_client`; юнит-тесты на моках | `src/xray/cdn.py`, `tests/xray/test_cdn.py` | WP-1 | `pytest -q` весь зелёный; двойной прогон install на моках — без перегенерации uuid; grep: `shell=True` нет |
| WP-3 | CLI + вывод: `main.py` — `xray add-cdn/add-cdn-client/remove-cdn/remove-cdn-client` (ленивые импорты, только добавляющие команды); `status.py` — CDN-секция; `links.py` — CDN-записи через `cdn.render_cdn_share_link` | `src/main.py`, `src/xray/status.py`, `src/gateway/links.py` | WP-2 | `compileall`; `pytest -q` зелёный; `python -m src.main --help` показывает новые команды; существующие команды не изменены (diff-ревью) |

Границы: пересечений файлов между WP нет. `src/main.py` потенциально пересекается
с параллельным AWG-циклом — только добавляющие правки; при реальном конфликте —
сериализация WP-3 (решает оркестратор).

## 7.1 Владелец-шаги (НЕ work package кодера — чеклист панели CF + переноса зоны)

Исполняет владелец вручную в панели CF и у регистратора. Порядок привязан к
§4.2. Выполнять по шагам, отмечая выполненное:

1. **Перенос зоны** [регистратор + CF]: CF → Add site → `eu-cloud-xip.com`,
   план Free. CF импортирует существующие записи.
2. **Проверить импортированные записи** [CF DNS]: апекс `eu-cloud-xip.com` и
   `103-45-247-172` — статус **DNS-only (серое облако)**. Если CF включил
   proxy по умолчанию — выключить вручную. ⚠️ Это шаг-блокер инварианта.
3. **Сменить NS у регистратора** на выданные CF (`…ns.cloudflare.com`).
4. Дождаться делегирования (`dig NS eu-cloud-xip.com` — ответ CF).
5. **Создать запись** [CF DNS]: `cdn` → A `103.45.247.172`, статус **DNS-only
   (grey)** на данном шаге (сертификат выпускается direct).
6. [оператор, сервер] `vds acme issue cdn.eu-cloud-xip.com` → `vds xray add-cdn
   --domain cdn.eu-cloud-xip.com` (см. §4.2 шаги 2–3).
7. **Включить proxy** [CF DNS]: запись `cdn` → orange cloud.
8. **SSL/TLS** [CF]: режим **Full (strict)**; вкладка Network → **WebSockets: On**
   (на free — включено по умолчанию, убедиться).
9. **LE-продление (E11, после приёмки)**: `certbot renew --dry-run`; если
   HTTP-01 через edge падает (Always Use HTTPS и пр.) — на время продления
   переводить запись `cdn` в grey, затем обратно в orange; зафиксировать
   выбранную процедуру в заметке владельца.
10. **Откат канала** в любой момент: шаг 7 в обратную сторону (grey) — CDN
    недоступен, всё остальное не затронуто.

## 7.2 Ручная приёмка [VDS] (после WP-3 и §7.1)

- `dig +short cdn.eu-cloud-xip.com` → IP из диапазонов CF, не 103.45.247.172 [FR-2]
- `ss -tlnp` → xray слушает 2053; 443 и 8443 без изменений [FR-1]
- `diff` config.json: `realitySettings` и XHTTP-direct-инблэнд байт-в-байт [FR-1]
- Импорт CDN-ссылки в v2rayNG/Hiddify, e2e: трафик ходит, exit-IP 103.45.247.172 [FR-2/4]
- **Reality-gate (блокер)**: клиент `phone` по старой доменной ссылке работает —
  в т.ч. при зоне в CF (апекс grey); Hysteria2 `mob` аналогично; XHTTP-direct
  ссылка работает [§4 REQ]
- probe-resistance Reality: curl чужой SNI на 443 → сайт-маска [§4]
- `certbot renew --dry-run` для обоих сертификатов [E11]
- grep journal/вывода: uuid/ключи отсутствуют [NFR]

## 8. Риски
| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| Включение orange cloud на direct-записях (человеческая ошибка в §7.1-2/7) | низкая | критическое (Reality/Hysteria2 ломаются) | чеклист §7.1 шаг-блокер 2; приёмка Reality-gate; откат = toggle |
| CF free режет/блокирует WS или edge недоступен из сети клиента (E10) | низкая/средняя | канал не работает (direct не затронут) | документированное ограничение; запас — XHTTP packet-up CDN (future, ADR-006) |
| LE-продление через edge падает (E11) | средняя | тихая просрочка cert через ~90 дней | §7.1 шаг 9 (временно grey); напоминание в `vds xray status` (cert-даты) |
| Порт 2053 со временем займёт будущий сервис | низкая | конфликт | порт локализован в paths.py + `--port`; проверка E9 до установки |
| Конфликт `main.py` с AWG-циклом | низкая | merge-трудности | только добавляющие правки; сериализация WP-3 при коллизии |

## 9. Границы изменений
- **Трогаем:** файлы §3 (только их); UFW — одно правило 2053/tcp; state.json —
  новый ключ `protocols["xray-cdn"]`.
- **Не трогаем:** `src/amneziawg/*` (параллельный цикл); публичные CLI-команды
  прошлого цикла (только добавляем новые); `topology.json`/ZeroTier; схему
  секретов; права файлов вне новых; UFW-политику кроме одного правила;
  systemd-юниты (новых нет); `src/xray/install.py`, `src/hysteria2/*`,
  `src/xray/remove.py` (remove-cdn живёт в cdn.py); config.json Reality/XHTTP
  поля рендера прошлых циклов (золотой снапшот).

## 10. Трассируемость
| REQ | WP | Файлы | Тест |
|---|---|---|---|
| FR-1 | WP-1, WP-2, WP-3 | config.py, cdn.py, main.py | tests/xray/test_cdn_config.py, test_cdn.py; [VDS] §7.2 |
| FR-2 | WP-3 (status DNS-чек), §7.1 | status.py | [VDS] dig + e2e |
| FR-3 | WP-1 (tlsSettings), §7.1-8 | config.py, paths.py | рендер-тест; [VDS] cert |
| FR-4 | WP-2 (render_cdn_share_link), WP-3 | cdn.py, links.py | share-link юнит-тест; **девиация порт 2053 — §4.3** |
| FR-5 | WP-2, WP-3 | cdn.py, status.py, main.py | remove-idempotency тесты; [VDS] |
| §4 инвариант | все + §7.1 | — | Reality-gate §7.2 (блокер) |
| OQ-1..5 | — | — | ADR-006 |

## Следующий шаг
→ `vds-orchestrator`: назначить vds-coder WP-1 → WP-2 → WP-3; параллельно
передать владельцу чеклист §7.1 (шаги 1–5 до WP-приёмки); затем vds-tester §7.2.
Аналитику на G5: правка FR-4 (порт 2053, §4.3).
