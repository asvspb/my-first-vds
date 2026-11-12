# SPEC-20261112-p0-transport-upgrade

## Мета
- **Источник:** P0-пакет владельца «прокачка существующих протоколов и схем, не
  новые классы» (приоритизация 2026-11-12); идеи И1/И5
  ([youtube-ideas](../../research/youtube-ideas-2026-11.md));
  REQ-20261112-transport-hardening (циклы H-OBFS/H-HOP — согласован как база WP-1).
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-12
- **Статус:** approved (G2)
- **ADR:** [ADR-008](../../adr/ADR-008-hysteria2-port-hopping-firewall.md)
  (механизм port hopping); WP-2 расширяет [ADR-006](../../adr/ADR-006-cdn-cloudflare-transport.md)
  без новых необратимых решений; WP-3 аддитивен, ADR не требует.

## 1. Контекст и цель

Классы задач P0 (наблюдены на живом asv1 в эпизодах 2026-11-11..12,
CENSORSHIP-PATTERNS §0/§2a):

1. **Порто-специфичный шейпинг UDP** — Hysteria2 на единственном udp/443;
   ответ = port hopping (диапазон + mport в ссылке).
2. **Голый QUIC как самый заметный фингерпринт** — ответ = obfs salamander
   на новом порту (мягкий rollout, REQ FR-1..5).
3. **SPOF CDN-фронта** — единственная orange-запись asvpersonal.ru (ADR-006
  «Дополнение»); ответ = пул фронтов (И5).
4. **Неоднозначная диагностика «сервер мёртв»** — нет инструмента различить
   «TSPU-блок нашего IP» vs «глобальная деградация» vs «локальная проблема»
   (И1); ответ = blockcheck на базе внешних проб.

**Фактическое состояние кода (проверено 2026-11-12, честная база):**
- ACME/LE для Hysteria2 **уже реализован** (SPEC-20261109, ADR-004:
  `src/acme/install.py`, `src/acme/apply_cert.py`, `apply-cert --apply/--restore`,
  LE-ветка в `clients.add_client`, `cert_type` в `status`). Fallback-логика
  «нет домена/ACME → self-signed с insecure=1» — уже в проде. В WP-1 этот
  пункт **закрывается верификацией и документацией, новый код не пишется**.
- masquerade **уже** `type: proxy` на `https://download.microsoft.com/`
  (`src/hysteria2/config.py`) — «голой заглушки» нет; в WP-1 остаётся
  сделать URL конфигурируемым флагом.
- Новый код WP-1 = port hopping + salamander; WP-2 = пул фронтов (серверная
  часть существует и меньше, чем кажется клиенту, — см. §4); WP-3 = blockcheck.

## 2. Общая архитектура пакета

```
WP-1 Hysteria2:  client --udp dport 20000-20500 (mport)--> iptables REDIRECT --> hysteria udp/443
                 client --udp 51826 obfs salamander-----> vds-hysteria2-obfs (параллельный инстанс)
WP-2 CDN-пул:    client --> cdn1/cdn2.<zone> (orange, CF edge) --> origin :2053
                 (несколько LE-сертификатов в одном ws-инблэнде; выбор фронта — клиент)
WP-3 Blockcheck: vds gateway blockcheck: локальная проба + check-host.net (внешняя)
                 --> вердикт ip-block / global / local / unknown
```

Все три WP аддитивны: существующие каналы (Reality 443, XHTTP 8443, Hysteria2
443/udp, CDN 2053) не меняют поведения; каждый WP независимо мержабелен;
порядок реализации фиксирован WP-1 → WP-2 → WP-3.

## 3. WP-1 — Hysteria2 upgrade (port hopping + salamander + мелочи)

### 3.1 Решение

**Port hopping (REQ FR-17..20, ADR-008).** Сервер: iptables-chain
`VDS_HY2_HOP` (nat/PREROUTING) с `REDIRECT --to-ports 443` на диапазон,
персистентность через oneshot-юнит + идемпотентный apply-скрипт; UFW allow
`<range>/udp`. Клиентская ссылка получает `mport=<range>` (стандартный
параметр hysteria2/sing-box). Живой udp/443 не прерывается — правило только
добавляет путь.

**Obfs salamander (REQ FR-1..5).** Параллельный инстанс hysteria2 на новом
UDP-порту (по умолчанию 51826, вне занятых: 443, 8443, 2053, 51825 AWG) с
`obfs: {type: salamander, password: <gen_password()>}`; собственный конфиг
`/etc/hysteria/obfs.yaml` (0600) и юнит из шаблона. Тот же общий auth-пароль
инбаунда, что и у основного инстанса (переиспользуем из state — не второй
секрет для клиента). Ссылки с `obfs=salamander&obfs-password=...`.
`rotate-obfs` — новый obfs-пароль + рестарт obfs-инстанса (клиенты
пере-импортируют ссылку; прямой rotate на живом порту — только так, порт
обфускации при ротации не меняется — упрощение против REQ FR-5, см. §3.6
девиация). Soft rollout выполнен по построению: основной 443-инстанс не
трогаем вообще.

**TLS/ACME:** без нового кода. Проверить (кодер, чеклистом §3.5) связку
`acme issue` → `apply-cert --apply` → `add-client` (ссылка без insecure=1) →
`apply-cert --restore` (ссылки insecure=1 снова валидны); задокументировать в
VPN-PROTOCOLS фактический fallback-флоу.

**Masquerade:** флаг `--masquerade-url` на install (параметр в рендер уже
пробрасывается — не хватает только CLI).

### 3.2 Карта файлов

| Файл | Действие | Назначение |
|---|---|---|
| `src/gateway/paths.py` | изменить (append) | `HYSTERIA2_HOP_CHAIN = "VDS_HY2_HOP"`, `HYSTERIA2_HOP_SCRIPT = Path("/usr/local/sbin/vds-hy2-hop-apply.sh")`, `HYSTERIA2_HOP_UNIT = "vds-hysteria2-hop.service"`, `HYSTERIA2_OBFS_CONFIG_PATH = Path("/etc/hysteria/obfs.yaml")`, `HYSTERIA2_OBFS_UNIT = "vds-hysteria2-obfs.service"`, `HYSTERIA2_OBFS_PORT_DEFAULT = 51826`. Только append, не трогая блоки xray/awg/cdn. |
| `src/hysteria2/hop.py` | **создать** | Весь port-hopping: парсинг/валидация диапазона, iptables-цепочка, apply-скрипт+юнит, UFW, state, remove. Интерфейсы §3.3. |
| `src/hysteria2/obfs.py` | **создать** | Obfs-инстанс: add/remove/rotate, рендер конфига (через `config.render_config` с новым полем), state, share-links. |
| `src/hysteria2/config.py` | изменить | `Hysteria2ConfigParams.obfs_password: str \| None = None`; в `render_config` блок `obfs:` только при заданном пароле; без поля рендер байт-в-байт прежний (золотой тест). |
| `src/hysteria2/clients.py` | изменить | `render_share_link(..., mport: str \| None = None, obfs_password: str \| None = None)`; `add_client` подхватывает `hop_ports`/obfs-мета из state. |
| `src/hysteria2/status.py` | изменить | Секции hop (диапазон, наличие цепочки/юнита) и obfs (юнит, порт, пароль в `_known_secrets` для маскирования). |
| `systemd/vds-hysteria2-hop.service.tpl` | **создать** | oneshot: `ExecStart={hop_script}`, `After=network-online.target`, `WantedBy=multi-user.target` (контекст-переменная `hop_script`). |
| `systemd/vds-hysteria2-obfs.service.tpl` | **создать** | Копия vds-hysteria2.service.tpl с `{config_path}` = obfs.yaml (контекст уже параметризован в `install_unit`). |
| `src/main.py` | изменить (добавляющие) | Команды §3.4; ленивые импорты внутри функций. |
| `tests/hysteria2/test_hop.py` | **создать** | Валидация диапазона, идемпотентность iptables-команд на моках run_list, dry-run/apply, план remove. |
| `tests/hysteria2/test_obfs.py` | **создать** | Рендер obfs-блока, отсутствие obfs-блока без пароля, share-link формат, state-структура, порт-конфликт до мутаций. |
| `tests/hysteria2/test_config.py` | изменить | Кейс obfs-рендера + регресс «без obfs — прежний YAML». |
| `tests/hysteria2/test_clients.py` | изменить | mport/obfs-параметры ссылки. |
| `docs/VPN-PROTOCOLS.md` | изменить | Фактические команды hop/obfs; ACME-fallback-флоу (без нового кода). |

### 3.3 Интерфейсы (сигнатуры)

```python
# src/hysteria2/hop.py
def parse_port_range(raw: str) -> tuple[int, int]:
    """'20000-20500' -> (20000, 20500). ValueError: формат, start>=end,
    ширина > 1000 портов (ADR-008 §4), порт вне 1024-65535."""

def render_hop_script(start: int, end: int, listen_port: int, chain: str) -> str:
    """Идемпотентный sh: -N цепочки, -C||-A правило, jump из PREROUTING.
    Без секретов; детерминирован (для золотого теста)."""

def add_hop_ports(raw_range: str, apply: bool = False,
                  state_path: str | None = None) -> int:
    """root -> hysteria2 установлен -> parse_port_range -> все порты диапазона
    свободны/равны listen (ss) -> план [цепочка, jump, UFW allow range/udp,
    скрипт+юнит hop] -> dry-run по умолчанию; apply: render_hop_script +
    write 0755 + install_unit + немедленное применение тех же команд +
    ufw allow + state.protocols['hysteria2']['hop_ports']='20000-20500'.
    Идемпотентно: тот же диапазон в state + цепочка существует -> exit 0."""

def remove_hop_ports(apply: bool = False, state_path: str | None = None) -> int:
    """План [D jump, F+X цепочки, ufw delete, stop/disable юнита, rm скрипта];
    dry-run по умолчанию; нечего снимать -> exit 0."""

# src/hysteria2/obfs.py
def add_obfs(port: int = HYSTERIA2_OBFS_PORT_DEFAULT,
             state_path: str | None = None) -> int:
    """root -> hysteria2 установлен -> port_free(port,'udp') ДО мутаций ->
    obfs_password = gen_password() (не перегенерировать при повторном запуске,
    паттерн _ensure_password) -> render_config(obfs_password=...) ->
    write_secret_atomic(obfs.yaml, 0600) -> install_unit(obfs.tpl) -> restart
    -> state.protocols['hysteria2-obfs'] = {installed, port, obfs_password}."""

def remove_obfs(apply: bool = False, state_path: str | None = None) -> int:
def rotate_obfs(state_path: str | None = None) -> int:
    """Новый obfs-пароль -> перезапись obfs.yaml (write_secret_atomic) ->
    restart. Печатает: клиентам нужен ре-импорт ссылки (разрыв ~5 с)."""

def render_obfs_share_link(host: str, auth_password: str, obfs_password: str,
                           name: str, port: int, insecure: bool,
                           mport: str | None = None) -> str:
    """hysteria2://<auth>@<host>:<port>/?sni=..&obfs=salamander
    &obfs-password=<obfs>[&insecure=1][&mport=..]#<name>"""
```

**Формат state.json (дополнения, ключи новые — старые читатели не ломаются):**

```jsonc
protocols["hysteria2"]      += { "hop_ports": "20000-20500" }   // null/нет = hopping выключен
protocols["hysteria2-obfs"]  = { "installed": true, "port": 51826,
                                 "obfs_password": "<gen>" }      // 0600, маскируется в status
```

### 3.4 CLI-поверхность (новые команды, существующие не менять)

```bash
vds hysteria2 add-hop-ports 20000-20500 [--apply]   # dry-run по умолчанию
vds hysteria2 remove-hop-ports [--apply]
vds hysteria2 add-obfs [--port 51826]
vds hysteria2 remove-obfs [--apply]
vds hysteria2 rotate-obfs
vds hysteria2 install [--masquerade-url URL]         # новый опциональный флаг
```

### 3.5 Критерии приёмки WP-1

Unit (pytest, без root/сети — моки `run_list`/`requests` по паттерну
`tests/hysteria2/test_install.py::env`):
- `parse_port_range`: валидный/инверсный/широкий >1000/мусор.
- `render_hop_script`: золотой снапшот; в тексте нет секретов; команды
  содержат `-C`-проверки (идемпотентность).
- `add_hop_ports` dry-run: ни одного мутирующего вызова run_list/ufw.
- `add_hop_ports` apply дважды: второй прогон — без повторного `-A`
  (только `-C`-хиты), без изменения state.
- `render_config` с `obfs_password` содержит `obfs:`-блок; без — байт-в-байт
  прежний (регресс).
- obfs-ссылка: точный формат `obfs=salamander&obfs-password=`; auth-пароль
  obfs-инстанса равен основному (один секрет на транспорт).
- `mport` попадает в ссылку iff `hop_ports` есть в state.
- obfs-пароль входит в `_known_secrets()` (status-маскирование).
- Порт-конфликт obfs (port_free=False) → отказ ДО каких-либо мутаций.

Ручная приёмка [VDS] (живой asv1, по чеклисту tester'а):
- `add-hop-ports 20000-20500 --apply`: `iptables -t nat -S VDS_HY2_HOP`
  показывает правило; `ufw status` — диапазон; клиент sing-box с
  `ports: "20000-20500"` подключается (лог hopping); канал 443/udp не
  прервался (Reality-gate: клиент mob жив на всех шагах).
- `reboot` (окно владельца): после загрузки цепочка на месте (oneshot-юнит).
- `add-obfs`: юнит active, udp/51826 слушается; клиент с obfs подключается;
  голый 443 работает параллельно; `grep` journal — obfs-пароля нет.
- `remove-hop-ports --apply` / `remove-obfs --apply`: чистые откаты (цепочка
  удалена, UFW-правила нет, юниты сняты), остальной стек жив.
- ACME-верификация без нового кода: issue → apply-cert --apply → add-client
  (ссылка без insecure=1, sni=домен) → restore → старые insecure-ссылки живы.

### 3.6 Девиации от REQ-20261112 (зафиксированы, на G5 аналитику)
- **FR-5 (rotate-obfs на новом порту):** ротация выполняется на ТОМ ЖЕ порту
  с кратким разрывом; смена порта = `remove-obfs` + `add-obfs --port N`.
  Причина: «ротация на новом порту» удваивает число инстансов/секретов ради
  экономии 5-секундного разрыва obfs-канала, который и так резервный.
- **FR-3 (клиент vpn-manager):** вне репо vds — интерфейс совместимости
  зафиксирован §3.3 (формат ссылки), реализация парсера — в ubuntuInstaller.

### 3.7 Риски WP-1

| Риск | Мера |
|---|---|
| Ошибка в iptables-правиле рвёт чужой NAT | именованная цепочка + jump (ADR-008); dry-run; ручной откат ADR-008 |
| Диапазон конфликтует с будущими сервисами | диапазон всегда явный, в state, виден в `status`; ширина ≤1000 |
| obfs-порт блокируют как «неизвестный UDP» | это класс-риск AWG; ответ вне WP (rotate/смена порта — команды есть) |
| Сломать 443-инстанс при obfs-установке | obfs-код не пишет в `/etc/hysteria/config.yaml` и не трогает юнит 443 (гейт: diff конфига в приёмке) |
| UFW range-rule не совпадает с iptables-редиректом при частичном apply | add/remove хранят диапазон в state и чистят оба места одним планом |

## 4. WP-2 — Пул CDN-фронтов + автопереключение

### 4.1 Граница vds ↔ клиентский стек (честный ответ на вопрос REQ)

Фронты = **DNS-записи с orange cloud в CF** (панель, владелец; CF-API вне
скоупа — ADR-006 OQ-5). Серверная часть **существует и не нулевая**:

1. **TLS-покрытие фронта.** CF в Full (strict) валидирует origin-сертификат
   против SNI фронта → каждый фронт должен быть покрыт LE-сертификатом на
   origin. Это серверная работа: выпуск (существующий `acme issue`, HTTP-01
   при grey) + добавление пары certificateFile/keyFile в certificates-список
   CDN-инблэнда (Xray выбирает сертификат по SNI). Wildcard (\*.zone, DNS-01)
   отклонён: требует CF API-токен = новый секрет + новый ADR — future.
2. **Реестр фронтов в state** + генерация share-link на конкретный фронт
   (`add-cdn-client --front`), `gateway links` показывает все фронты.
3. **Документация схемы пула** для клиентской стороны.

**Healthcheck и автопереключение — клиентский репо (vpn-manager/ubuntuInstaller),
в vds НЕ реализуются.** Интерфейс совместимости (формат данных пула), который
кодер WP-2 фиксирует в docs/CDN-FRONTS.md:

```jsonc
// клиентский профиль (vpnm), поле fronts — массив, порядок = приоритет
{ "transport": "xray-cdn-ws", "fronts": [
    { "host": "cdn1.asvpersonal.ru", "port": 2053 },
    { "host": "cdn2.asvpersonal.ru", "port": 2053 }
  ], "ws_path": "/cdnws", "fallback": ["reality", "awg"] }
// healthcheck клиента: TCP+TLS до host:2053 (или generate_204 через канал);
// переключение: первый живой фронт по порядку; все мертвы -> fallback-транспорт.
```

Серверный гейт «фронт действительно работает» (для владельца/тестера):
`vds xray check-front <domain>` — TCP-коннект + SNI=<domain> к 127.0.0.1:2053
не вариант (SNI-маршрутизация по сертификатам локальна), поэтому проверка
внешняя: dig → CF-IP + опциональный curl через фронт (детали — §4.5).

### 4.2 Карта файлов

| Файл | Действие | Назначение |
|---|---|---|
| `src/xray/config.py` | изменить | `XrayConfigParams.cdn_cert_path/cdn_key_path` (скаляр) → дополнительно `cdn_extra_certs: list[tuple[str, str]] = []` (домен → (cert, key)); certificates-массив CDN-инблэнда собирается из основного + extra. Без extra — рендер байт-в-байт прежний. |
| `src/xray/cdn.py` | изменить | `CdnParams` без изменений; `state.protocols["xray-cdn"]["fronts"] = {domain: {cert_path, key_path}}`; `add_cdn_front(domain, apply)` / `remove_cdn_front(domain, apply)` / `list_fronts()`; `add_cdn_client(..., front: str \| None)` выбирает host ссылки; `_render_with_cdn` пробрасывает extra-certs. Прекондишны фронта: LE-файлы существуют, DNS резолвится в CF-диапазоны или публичный IP (grey-фаза). |
| `src/xray/status.py` | изменить | Строка на фронт: домен, наличие LE-файлов, `cert_days_left`, DNS-чек. |
| `src/gateway/links.py` | изменить | CDN-ссылки: по одной на фронт на клиента (host=фронт). |
| `src/main.py` | изменить (добавляющие) | `xray add-cdn-front <domain> [--apply]`, `xray remove-cdn-front <domain> [--apply]`, `xray list-cdn-fronts`; `add-cdn-client --front <domain>`. |
| `docs/CDN-FRONTS.md` | **создать** | Схема пула (§4.1), чеклист владельца по добавлению фронта (DNS grey → `acme issue` → `add-cdn-front` → orange), формат клиентского профиля. |
| `tests/xray/test_cdn.py` | изменить | Фронты: state-структура, рендер multi-cert, dry-run/apply, идемпотентность. |
| `tests/xray/test_cdn_config.py` | изменить | Golden: 2 сертификата в CDN-инблэнде; без extra — прежний JSON. |

### 4.3 Интерфейсы

```python
# src/xray/cdn.py (дополнения)
def add_cdn_front(domain: str, apply: bool = False,
                  state_path: str | None = None) -> int:
    """root -> CDN установлен -> LE fullchain/privkey <domain> существуют
    (иначе отказ с подсказкой `vds acme issue <domain>` при grey) -> DNS
    домена в CF-диапазонах или = public_ip -> план [добавить сертификат в
    certificates CDN-инблэнда, рестарт vds-xray, state.fronts[domain]] ->
    dry-run по умолчанию; apply: бэкап config.json -> перерендер ->
    xray -test гейт (fail: откат) -> рестарт -> state. Идемпотентно."""

def remove_cdn_front(domain: str, apply: bool = False,
                     state_path: str | None = None) -> int:
    """Вычитание сертификата из certificates + state.fronts.pop;
    dry-run по умолчанию; LE-сертификат certbot НЕ удаляем (пассивный)."""

def list_fronts(state_path: str | None = None) -> list[dict]:
    """[{domain, cert_days_left, dns_ok}] — для status и CLI."""
```

### 4.4 Критерии приёмки WP-2

Unit:
- Рендер CDN-инблэнда с `cdn_extra_certs` из двух фронтов: certificates
  содержит 3 записи (осн. + 2), порядок детерминирован; без extra —
  байт-в-байт прежний (golden-регресс).
- `add_cdn_front` без LE-файлов → отказ ДО мутаций, сообщение содержит
  подсказку `acme issue`.
- Dry-run: ни одной записи config.json/state.
- `add_cdn_client(front=...)` → host ссылки = фронт; без front → прежний
  домен.
- Идемпотентность: повторный add_cdn_front того же домена — exit 0 без
  рестарта.

Ручная [VDS] (после owner-шагов: DNS-запись grey → acme issue → orange):
- `dig +short cdn1.<zone>` → CF-IP; `openssl s_client -connect <фронт>:2053
  -servername cdn1...` (снаружи) показывает LE-сертификат cdn1.
- e2e через каждый фронт: 204 через socks, exit-IP = сервера.
- **Reality-gate + базовый CDN-gate**: существующие клиенты (phone/mob/laptop)
  работают до и после add/remove фронта (diff config.json: только
  certificates-массив CDN-инблэнда).
- Отказ одного фронта (владелец выключает orange) — остальные каналы живы;
  переключение клиента на второй фронт — клиентская сторона, проверяется в
  vpnm-цикле, не здесь.

### 4.5 Риски WP-1→WP-2 общие и WP-2

| Риск | Мера |
|---|---|
| Владелец включает orange ДО выпуска LE (порядок шагов) | прекондишн add_cdn_front: LE-файлы есть; чеклист CDN-FRONTS.md с серым шагом-блокером |
| SNI-фронт без сертификата → CF 526 на всём инблэнде | xray выбирает сертификат по SNI; лишний сертификат безвреден, недостающий — риск фронта, не канала; check в status |
| Расползание сертификатов/продления | каждый фронт = один certbot-сертификат, продлевается certbot.timer; E11-процедура (временно grey) — та же, что ADR-006 |
| Пул фронтов одного провайдера (все CF) не спасает от блокировки CF-класса | задокументированное ограничение (И6); мульти-CDN — future REQ |

## 5. WP-3 — netcheck blockcheck: «блок нашего IP» vs «глобальная деградация»

### 5.1 Решение

Новая диагностика `vds gateway blockcheck`: сравнение **локальной** достижимости
своего публичного TCP 443 (self-probe с сервера) с **внешней** (пассивный
запрос к check-host.net API: TCP-проба `<ip>:443` с узлов RU и мира; второй
запрос — контрольный на чужой широко доступный хост, чтобы отличить «наш IP
мёртв» от «у check-host проблемы»). Зависимостей новых нет (`requests` уже в
стеке). API недоступен/таймаут → вердикт `unknown`, **exit 0** (не ошибка) —
offline-режим по требованию.

### 5.2 Карта файлов

| Файл | Действие | Назначение |
|---|---|---|
| `src/core/netcheck.py` | изменить (append) | Классификатор + check-host-клиент (§5.3). Существующие функции не трогать. |
| `src/main.py` | изменить (добавляющие) | `gateway blockcheck [--timeout 30] [--json]` — ленивый импорт, тонкая обёртка. |
| `tests/core/test_netcheck.py` | изменить | Таблица истинности классификатора; клиент API на моках requests; offline → unknown. |
| `docs/CENSORSHIP-PATTERNS.md` | изменить | Ссылка на команду в §0/§335-контексте («план Б» — теперь инструментализовано). |

### 5.3 Интерфейсы

```python
# src/core/netcheck.py (дополнения)
BlockVerdict = Literal["ok", "ip_block_likely", "ru_segment_block_likely",
                       "global_degradation", "local_problem", "unknown"]

def classify_block(local_tcp_ok: bool | None,
                   target_external_ok: bool | None,
                   control_external_ok: bool | None,
                   ru_nodes_ok: int | None = None,
                   ru_nodes_total: int = 0) -> BlockVerdict:
    """Чистая функция (таблица — в тестах):
    local None/False + внешний ok        -> local_problem (сервис жив извне,
                                            локально нет: юнит/порт)
    local ok + control ok + target ok    -> ok (IP-блок маловероятен;
                                            недоступность у клиента =
                                            блок сегмента клиента — не наш IP)
    local ok + control ok + target fail  -> ip_block_likely (TSPU-блок IP)
    local ok + control fail + target fail-> global_degradation (check-host
                                            или мир деградировал — не различимо,
                                            честно так и пишем)
    target None (API молчит/timeout)     -> unknown
    """

def check_host_tcp(host: str, port: int = 443, timeout: float = 30.0,
                   max_nodes: int = 5) -> dict | None:
    """check-host.net: GET check-tcp?host=<host>:<port>&max_nodes=N с
    Accept: application/json -> poll GET check-result/<id> (интервал 3с,
    до timeout) -> {'nodes': {name: bool}, 'ru_ok': int, 'ru_total': int,
    'world_ok': int, 'world_total': int}. None при любом сбое сети/API
    (offline-режим; классификация не пытается угадать). Пассивный запрос,
    ничего кроме host:port наружу не уходит; node group не задаём — берём
    ответившие, RU определяем по префиксу имени узла 'ru.'."""

def run_blockcheck(timeout: float = 30.0) -> tuple[BlockVerdict, dict]:
    """Собрать evidences: local_tcp_ok (socket к public_ip():443 + unit_active
    vds-xray), target = check_host_tcp(public_ip()), control =
    check_host_tcp('93.184.216.34') [RFC-постоянный example.com IP — обновить
    константой при устаревании]. Вернуть (вердикт, evidence-dict для вывода)."""
```

Вывод CLI: вердикт тегом `[warning]/[info]` + таблица evidences (local, узлы
RU ok/total, мир ok/total, control) + рекомендация (ip_block_likely →
«CDN-канал/фронт или ротация IP»; ru_segment_block_likely при
ru_ok==0<world_ok → «блок на RU-сегменте, direct-каналы под вопросом, CDN
должен жить»). `--json` — machine-readable для скриптов/watchdog-future.

### 5.4 Критерии приёмки WP-3

Unit:
- `classify_block`: полная таблица (≥10 кейсов, включая None-входы и
  ru-only-фейл).
- `check_host_tcp` на моках requests: submit → 1 poll с результатом →
  агрегат ru/world; узел без результата к таймауту считается не-ok;
  RequestException → None; verified: exit-код не меняется от offline.
- `run_blockcheck` на моках: собирает evidences, не бросает исключений.
- Регресс: существующие `tests/core/test_netcheck.py` кейсы не изменены.

Ручная [VDS]:
- `vds gateway blockcheck` при живом сервере → `ok`, exit 0; время ≤ timeout.
- Симуляция: `iptables -I INPUT -p tcp --dport 443 -j DROP` на 60 с (окно
  владельца) → local_problem; снятие → ok. (Внешнюю симуляцию IP-блока не
  воспроизводим — вердикт ip_block_likely проверяется таблицей истинности и
  первым живым эпизодом.)
- Offline: `VDS_BLOCKCHECK_OFFLINE=1` не вводим; вместо этого мок-тест +
  живой прогон при недоступном API → `unknown`, exit 0.

### 5.5 Риски WP-3

| Риск | Мера |
|---|---|
| check-host.net меняет API/лимиты | клиент изолирован в одной функции, None-семантика; контрольный хост выявляет деградацию самого сервиса |
| Ложный ip_block_likely при малом числе узлов | max_nodes≥5 + контрольный запрос; verdict-текст всегда «вероятен», не констатация |
| Выход команды в автоматизацию до стабилизации | `--json` помечен experimental в help; watchdog-интеграция — отдельный будущий WP |

## 6. Порядок, зависимости, merge-стратегия

```
WP-1 (hysteria2) → WP-2 (xray/cdn) → WP-3 (core+gateway)   # порядок фиксирован
```
- Зависимостей по коду нет (разные модули); порядок — ресурсный и
  эксплуатационный (WP-1 даёт UDP-устойчивость раньше).
- **Пересечения файлов:** `src/main.py` (все три WP — только добавляющие
  команды; при параллельной разработке сериализует оркестратор),
  `src/gateway/paths.py` (WP-1 append в hysteria2-блок; WP-2 констант не
  добавляет). Остальных пересечений нет.
- Каждый WP мержится независимо: зелёный `pytest -q` + `compileall` без
  остальных WP.

## 7. Границы изменений (пакет)

**Трогаем:** только файлы из §3.2/§4.2/§5.2; UFW — одно range-правило (WP-1)
и ничего нового в WP-2 (2053 уже открыт); state.json — только новые ключи.

**Не трогаем:** сервер asv1 руками (deploy — отдельное решение владельца по
обычному чеклисту deploy); `src/amneziawg/*`, `src/zerotier/*`, `topology.json`;
публичные существующие CLI-команды (только добавляем); схему секретов и права
существующих файлов; systemd-юниты существующие (новые — только из
`systemd/*.tpl`); Reality/XHTTP-части config.json (golden-гейт WP-2);
CF-панель (владелец, чеклисты docs/CDN-FRONTS.md); клиентский репо
vpn-manager/ubuntuInstaller (только формат совместимости в документации);
CF API (токен не появляется).

## 8. Тест-план пакета (сводно)

| Уровень | Что | Где |
|---|---|---|
| Unit | генераторы (hop-скрипт, obfs-config, multi-cert CDN), state-структуры, классификатор blockcheck, share-links форматы, идемпотентность/dry-run на моках | §3.5/§4.4/§5.4 |
| Integration (Docker) | не требуется: файрвол/CF/протоколы не воспроизводимы в CI; паттерн проекта — [VDS]-приёмка | — |
| Ручная [VDS] | чеклисты §3.5/§4.4/§5.4, каждый содержит Reality-gate (существующие клиенты не задеты — блокер) | живой asv1 |

## 9. Work packages (кодерам)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | Port hopping + salamander + `--masquerade-url` + ACME-верификация (без нового ACME-кода) | §3.2 | — | `compileall`; `pytest -q` зелёный (включая новые test_hop/test_obfs и golden-регресс config); dry-run не мутирует (тест); grep нового кода: `shell=True` нет; VPN-PROTOCOLS.md обновлён |
| WP-2 | Пул CDN-фронтов: multi-cert CDN-инблэнд, add/remove/list-front, `--front` в клиенте, CDN-FRONTS.md | §4.2 | WP-1 (порядок; технически независимо) | `compileall`; `pytest -q` зелёный; golden «без extra-certs → прежний JSON»; новые команды в `--help`; существующие команды не изменены (diff-ревью) |
| WP-3 | blockcheck: классификатор + check-host-клиент + CLI + PATTERNS-ссылка | §5.2 | WP-1, WP-2 (порядок; технически независимо) | `compileall`; `pytest -q` зелёный (таблица истинности + offline-моки); offline → unknown/exit 0 (тест); регресс существующих netcheck-тестов |

## 10. Трассируемость

| Требование | WP | Файлы | Тест |
|---|---|---|---|
| P0-1 port hopping (REQ FR-17..20) | WP-1 | hop.py, clients.py, systemd tpl | test_hop.py; [VDS] §3.5 |
| P0-2 TLS-сертификат ACME + fallback | WP-1 (верификация; код — SPEC-20261109, готов) | docs/VPN-PROTOCOLS.md | [VDS] §3.5 ACME-чек |
| P0-3 obfs salamander (REQ FR-1..5) | WP-1 | obfs.py, config.py, systemd tpl | test_obfs.py; [VDS] |
| P0-4 masquerade на проксируемый сайт | WP-1 (уже proxy; флаг) | config/install/main | test_config.py |
| P0-5 пул CDN-фронтов (И5) | WP-2 | cdn.py, config.py, docs/CDN-FRONTS.md | test_cdn*.py; [VDS] §4.4 |
| P0-6 blockcheck (И1) | WP-3 | netcheck.py, main.py | test_netcheck.py; [VDS] §5.4 |
| Граница vds↔vpnm | §4.1, §3.6 | docs | — |

## Следующий шаг
→ `vds-orchestrator`: WP-1 → WP-2 → WP-3 последовательно (main.py-сериализация);
владельцу заранее — чеклист добавления CDN-фронта (docs/CDN-FRONTS.md после
WP-2) и окно reboot-проверки для hop-юнита; аналитику на G5 — девиации §3.6.

---
*Честность: пункты «TLS через ACME» и «masquerade» исходной постановки уже
реализованы в кодовой базе (ADR-004, config.py) и включены в WP-1 как
верификация/конфигурируемость; новый код WP-1 — port hopping и salamander.
Серверная часть WP-2 существует (сертификаты фронтов + реестр), но меньше
клиентской; healthcheck/автовыбор — репо vpn-manager.*
