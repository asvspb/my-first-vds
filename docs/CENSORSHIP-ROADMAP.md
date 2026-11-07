# Roadmap: внедрение лучших мировых практик обхода блокировок в VDS Orchestrator

> Дата: 2026-11-07. Статус: **фазы 0–2 реализованы 2026-11-07**
> (см. [SPEC-20261107-gateway-mvp](team/specs/SPEC-20261107-gateway-mvp.md),
> [TEST-20261107-gateway-mvp](team/reports/TEST-20261107-gateway-mvp.md));
> XHTTP/AmneziaWG/подписки/SNI-мультиплексор — **не реализованы**.
> Связанные документы: [VPN-PROTOCOLS.md](VPN-PROTOCOLS.md), [../TECHDEBT.md](../TECHDEBT.md).
> Текущее состояние проекта: ZeroTier/ZTNET, WireGuard (классический), Coturn;
> Xray VLESS Reality (TCP 443) и Hysteria2 (UDP 443, self-signed тестовый режим)
> — реализованы в MVP; AmneziaWG отсутствует.

---

## 1. Цели, модель угроз и границы

### 1.1. Цель

Превратить `vds` из «набора отдельных VPN-команд» в **self-hosted платформу обхода
блокировок**: один сервер раздаёт несколько транспортных профилей, клиент
переключается автоматически, оператор управляет всем из одного CLI/TUI.

### 1.2. Модель угроз (на что защищаемся)

| Угроза | Проявление | Ответ |
|---|---|---|
| DPI-детект по фингерпринту | ТСПУ ловит TLS/WS-паттерны | REALITY, XHTTP, NaiveProxy |
| Троттлинг по протоколу | скорость до ~0 при живом соединении | смена транспорта (TCP↔UDP), CDN-фронт |
| Блокировка по IP | IP сервера в реестре | CDN/domain fronting, ротация IP |
| Active probing | цензор сам стучится в порт | fallback на настоящий сайт, decoy-страница |
| Блокировка UDP целиком | Hysteria2/QIC мёртв | TCP-резерв (Reality/XHTTP) |
| Блокировка TCP 443 | Reality/XHTTP мёртв | UDP-резерв (Hysteria2/AmneziaWG) |

### 1.3. Non-goals

- Не строим публичный сервис подписок и не агрегируем чужие конфиги (см. анализ `free-vpn-anti-rkn` — это отдельная модель с чужими серверами).
- Не делаем «невидимый» протокол против целевого государства — только против пассивного DPI и активного зондирования.
- Не автоматизируем покупку VPS/домены.

### 1.4. Принципы (мировые практики)

1. **Defense in depth**: минимум два транспорта разного L4-типа + fallback.
2. **Mimicry over encryption tricks**: трафик должен выглядеть как легитимный (TLS к популярному сайту, HTTP/2, QUIC).
3. **Probe resistance**: при неверном/отсутствующем аутентификаторе сервер ведёт себя как обычный веб-сервер.
4. **Автоматизация секретов и ротации**: ключи не руками, конфиги 0600.
5. **Declarative state**: желаемое состояние в файле, идемпотентное применение (как `topology.json` в reconcile).
6. **Отказоустойчивость**: healthcheck + watchdog по образцу ZeroTier.
7. **Проверяемость**: юнит-тесты на генерацию конфигов, e2e-тест «сервер↔клиент» в loopback/Docker.
8. **Минимальное логирование** PII и секретов.

---

## 2. Целевая архитектура

```
                         ┌──────────────────────────────┐
                         │        Клиент (v2rayNG,      │
                         │  NekoRay, Hiddify, sing-box) │
                         └──────────────┬───────────────┘
                                        │ подписка / share-link
                                        ▼
┌─────────────────────────── Слой управления (vds CLI) ──────────────────────────┐
│  gateway init · profile add/list · sub export · status · watchdog · reconcile  │
└───────────────┬───────────────────────┬───────────────────────┬────────────────┘
                │                       │                       │
        ┌───────▼────────┐      ┌───────▼────────┐      ┌───────▼────────┐
        │  Xray-core     │      │  Hysteria2     │      │  AmneziaWG     │
        │  TCP 443       │      │  UDP 443       │      │  UDP 51820     │
        │  Reality/XHTTP │      │  QUIC          │      │  obfuscated WG │
        └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
                │                       │                       │
                └───────────────┬───────┴───────────────────────┘
                                ▼
                     ┌─────────────────────┐
                     │  Nginx stream (SNI) │  ← TLS-мультиплексор:
                     │  fallback / decoy   │    reality | xhttp | decoy-site
                     └──────────┬──────────┘
                                ▼
                     ┌─────────────────────┐
                     │  Интернет / VDS     │
                     └─────────────────────┘

Служебный контур: ACME (сертификаты) · UFW/iptables · BBR/sysctl ·
healthcheck-timer · JSON-профили (0600) · Prometheus-экспортёр (опц.)
```

### 2.1. Слои

| Слой | Компонент | Назначение |
|---|---|---|
| Транспорт | Xray-core, hysteria2, amneziawg | сами протоколы |
| Мультиплексирование | Nginx stream / Xray fallbacks | один порт 443 на несколько SNI |
| Оркестрация | `src/gateway/` | профили, генерация конфигов, жизненный цикл |
| Наблюдаемость | `src/sysinfo/` + timers | статусы юнитов, трафик, ошибки |
| Дистрибуция | `src/subscriptions/` | share-links, base64, Clash/sing-box JSON |

---

## 3. Матрица протоколов и сценариев

| # | Профиль | Транспорт | Когда использовать | Приоритет |
|---|---|---|---|---|
| 1 | VLESS + Reality (Vision) | TCP 443 | базовый; везде, где жив TCP | **P0** |
| 2 | Hysteria2 | UDP 443 QUIC | мобильные сети, потери пакетов, высокая скорость | **P0** |
| 3 | VLESS XHTTP через CDN | TCP + CDN | IP сервера заблокирован / нужен domain fronting | P1 |
| 4 | AmneziaWG | UDP 51820 | деградация Xray/QUIC; простой резерв | P1 |
| 5 | NaiveProxy / HTTP/2 CONNECT | TCP 443 | ловля Reality по фингерпринту; максимальная мимикрия | P2 |
| 6 | TUIC v5 | UDP QUIC | альтернатива Hysteria2 | P2 |
| 7 | Snowflake / WebRTC | P2P | экстремальные сценарии (нет своего IP) | P3 |

---

## 4. Фазы roadmap

Оценки — «идеальные инженерные дни» (без ожидания ревью/тестов на живом VDS).
Итого: **~30–40 дней** полного объёма; MVP (фазы 0–2) — **~8 дней**.

### Фаза 0 — Фундамент и рефакторинг (3 дня)

**Зачем:** без общих абстракций каждый протокол скопирует логику, и проект
превратится в набор несовместимых скриптов (см. P1/P3 в TECHDEBT).

**Работы:**
1. Выполнить P1–P3 из `TECHDEBT.md` (единый `load_env`, `docker_exec` на списках, версии зависимостей).
2. Вынести общие примитивы в `src/core/`:
   - `netcheck.py`: `port_free(port, proto)`, `public_ip()`, `resolve(host)`, `cert_days_left(path)`;
   - `secrets.py`: генерация UUID/паролей/ключей, запись файлов 0600;
   - `units.py`: установка/включение/остановка systemd-юнитов из шаблона.
3. Ввести `ProtocolAdapter` (ABC) — единый интерфейс протокола:

```python
# src/core/protocol.py
from abc import ABC, abstractmethod

class ProtocolAdapter(ABC):
    name: str
    default_port: int
    transport: str            # "tcp" | "udp"

    @abstractmethod
    def install(self, opts: dict) -> int: ...
    @abstractmethod
    def add_client(self, name: str) -> dict: ...   # -> профиль (dict)
    @abstractmethod
    def remove_client(self, name: str) -> int: ...
    @abstractmethod
    def status(self) -> dict: ...
    @abstractmethod
    def render_share_links(self, profile: dict) -> list[str]: ...
    @abstractmethod
    def remove(self) -> int: ...
```

4. `src/gateway/store.py` — хранилище профилей `/opt/vds-gateway/state.json` (0600), pydantic-модели:

```python
class ClientProfile(BaseModel):
    name: str
    protocol: str          # "vless-reality" | "hysteria2" | ...
    port: int
    uuid: str | None
    password: str | None
    sni: str | None
    extra: dict = {}

class GatewayState(BaseModel):
    version: int = 1
    domain: str = ""
    clients: list[ClientProfile] = []
    protocols: dict[str, dict] = {}   # protocol -> server params
```

**Deliverables:** `core/protocol.py`, `core/netcheck.py`, `core/secrets.py`, `core/units.py`, `gateway/store.py` + тесты на store.
**Acceptance:** `pytest` зелёный; `vds gateway status` читает пустое состояние без ошибок.

---

### Фаза 1 — Xray + VLESS Reality (4 дня) — MVP TCP

**Работы:**
1. `src/xray/install.py`:
   - установка Xray-core (официальный install-скрипт, но с проверкой контрольной суммы/версии);
   - генерация `uuid` (`xray uuid`) и `x25519` (`xray x25519`), сохранение приватного ключа 0600;
   - выбор SNI-маски: по умолчанию `www.google.com`, переопределяемо флагом;
   - рендер `/usr/local/etc/xray/config.json` (Reality, Vision flow, `dest`, `serverNames`, `shortIds`);
   - systemd `vds-xray.service` (`Restart=always`).
2. `src/xray/clients.py`: `add_client(name)` → профиль + share-link:

```
vless://<uuid>@<ip>:443?security=reality&sni=<sni>&fp=chrome&pbk=<pbk>&sid=<sid>&flow=xtls-rprx-vision#<name>
```

3. `src/xray/status.py`: `systemctl is-active`, `xray -test -config`, проверка порта, последние ошибки из journal.
4. CLI: `vds xray install|add-client|status|remove`, пункт в TUI.
5. Юнит-тест: рендер конфига из параметров → сравнение с эталоном; проверка, что приватный ключ не попадает в share-link.

**Acceptance:**
- на чистом VDS `vds xray install` → `systemctl is-active vds-xray` = active;
- клиент (v2rayNG/NekoRay) подключается по сгенерированной ссылке;
- `curl` с неверным SNI на 443 получает ответ настоящего `dest`, а не Xray (проверка probe resistance).

**Риски:** конфликт TCP 443 с существующим nginx — решается SNI-мультиплексором в фазе 5.

---

### Фаза 2 — Hysteria2 (3 дня) — MVP UDP

**Работы:**
1. `src/hysteria2/install.py`: бинарь + `/etc/hysteria/config.yaml`; ACME-сертификат (или self-signed + `insecure` для теста); `masquerade` на локальную decoy-страницу.
2. `sysctl`: `net.core.rmem_max/wmem_max`, `net.ipv4.tcp_congestion_control=bbr` — отдельный шаблон `/etc/sysctl.d/99-vds-gateway.conf`.
3. `src/hysteria2/clients.py`: пароль на клиента, share-link `hysteria2://...`.
4. `status`: порт UDP 443, journal, метрики `/metrics` (встроенный prometheus).
5. CLI + TUI.

**Acceptance:**
- `vds hysteria2 install` → юнит active, UDP 443 слушается;
- клиент подключается, скорость на мобильном > Reality (замер);
- отключение UDP на стороне ISP воспроизводит ожидаемый отказ → клиент переключается на Reality-профиль.

---

### Фаза 3 — XHTTP и CDN-фронт (5 дней) — P1

**Работы:**
1. Второй inbound Xray: `network: xhttp`, `mode: auto`, TLS-сертификат (ACME).
2. Роутинг по SNI/Path между Reality и XHTTP на одном 443:
   - либо Xray `fallbacks` внутри одного inbound,
   - либо Nginx `stream` + `ssl_preread` (SNI-мультиплексор) с upstream на 127.0.0.1:8443 (Reality) / :8444 (XHTTP) / :8080 (decoy).
3. Документированный сценарий Cloudflare (проксирование домена, режим Full (strict), ограничения бесплатного тарифа — только HTTP/WS/XHTTP).
4. `vds xray add-transport xhttp --domain example.com --path /up`.
5. Тест: без CDN и через CDN.

**Acceptance:** оба транспорта живут на одном 443, переключаются по SNI; при блокировке IP сервера доступ через CDN сохраняется.

---

### Фаза 4 — AmneziaWG (3 дня) — P1

**Работы:**
1. `src/amneziawg/`: установка `amneziawg-go`/DKMS-модуля, генерация `Jc/Jmin/Jmax/S1/S2/H1..H4` (обфускационные параметры), конфиг сервера и клиентов.
2. Раздача клиентских `.conf` + QR (терминальный QR через `qrcode`).
3. `status`, `remove`.

**Acceptance:** клиент AmneziaVPN/AmneziaWG подключается; при живом Reality работает как резерв; параметры обфускации уникальны на установку.

---

### Фаза 5 — Мультипротокольная оркестрация и подписки (4 дня) — P0/P1

**Работы:**
1. `src/gateway/init.py`: «hub» — один вызов поднимает Reality + Hysteria2 + (опц.) XHTTP, разводит порты, ставит SNI-мультиплексор, генерирует дефолтную decoy-страницу.
2. `src/subscriptions/`:
   - генерация «профиля клиента» сразу для всех включённых протоколов;
   - форматы: base64-список URI (стандарт подписок), Clash YAML, sing-box JSON, plain text;
   - локальный HTTP-сервер подписки (опц., с токеном) `vds gateway sub serve --port 8081`.
3. `vds gateway profile add phone --all-protocols` → выводит links + сохраняет в state.
4. `vds gateway reconcile` — декларативное состояние как в ZeroTier-reconcile: state.json vs реальные конфиги, dry-run/apply.

**Acceptance:** одна команда даёт клиенту файл подписки, который v2rayNG/Hiddify понимает целиком; добавление клиента не требует ручных правок конфигов.

---

### Фаза 6 — Hardening и безопасность (4 дня)

**Работы:**
1. **ACME**: `acme.sh` (без остановки сервиса, webroot/standalone по выбору), автопродление timer, проверка `cert_days_left` в `status`.
2. **UFW**: правила из `server-setup` — 22/443/51820 + UFW limit; Hysteria2 UDP; закрыть всё остальное.
3. **BBR + sysctl** (см. фазу 2) оформляется в отдельный модуль `system/network_tuning.py`.
4. **Decoy-сайт**: минимальный статический сайт (nginx), который отдаётся на все «неправильные» запросы к 443.
5. **Секреты**: state.json и конфиги 0600/0640, владелец root; `secrets.py` пишет атомарно; никаких ключей в логах (фильтр в `core/logger.py`).
6. **Fail2ban** (опц.) на попытки перебора, **логирование минимизировано**.
7. Ротация ключей: `vds gateway rotate-keys [--client name]`.

**Acceptance:** внешний сканер (nmap + curl с чужим SNI) видит только HTTPS к decoy/маске; сертификаты продлеваются автоматически; в `journalctl` нет UUID/паролей.

---

### Фаза 7 — Наблюдаемость и отказоустойчивость (3 дня)

**Работы:**
1. `vds gateway healthcheck` + timer каждые 2–5 минут (по образцу `vds-watchdog`):
   - порты слушаются, юниты active, сертификат не истёк, Xray/Hysteria отвечают на локальную проверку;
   - при сбое — перезапуск с лимитом (rate-limit из watchdog переиспользовать).
2. Экспорт метрик: `xray api stats` (трафик по клиенту) + `hysteria /metrics` → `sysinfo/dashboard.py` показывает:
   - активные протоколы, аптайм, трафик, число клиентов;
   - статус сертификата; последние ошибки.
3. Алерты (опц.): webhook (Telegram/SMTP) при недоступности > N минут.

**Acceptance:** dashboard показывает реальные цифры; симуляция падения юнита → watchdog восстанавливает за ≤ 2 цикла.

---

### Фаза 8 — Тестирование и валидация (4 дня)

**Работы:**
1. **Юнит-тесты** (pytest, без сети):
   - генераторы конфигов Xray/Hysteria2/AmneziaWG (снапшоты);
   - `ProtocolAdapter`-контракты для всех адаптеров;
   - `store` (roundtrip, права, миграции версии);
   - `netcheck` (занятость порта, парсинг).
2. **E2E в Docker** (`tests/e2e/`): контейнер-сервер (xray) + контейнер-клиент (xray-client/sing-box), проверка сквозного туннеля через loopback — в CI.
3. **Probe-resistance тест**: скрипт `curl` без/с неверным SNI → ожидается decoy; запомнить как регрессивный тест.
4. **Leak-тест**: DNS/WebRTC/IPv6 утечки на клиентской стороне (чеклист, не обязательно автоматизировать).
5. **Нагрузочный smoke** (опц.): iperf3 через каждый протокол, фиксация baseline скорости.

**Acceptance:** CI (GitHub Actions) гоняет unit + e2e; документированы результаты по каждому протоколу.

---

### Фаза 9 — Клиентская дистрибуция и документация (3 дня)

**Работы:**
1. `vds gateway export --format [base64|clash|singbox|qr|conf]` для каждого клиента.
2. README-раздел «Быстрый старт: свой сервер за 10 минут» + выбор протокола по сценарию.
3. Документ [VPN-PROTOCOLS.md](VPN-PROTOCOLS.md) обновить фактическими командами.
4. TUI: единый экран «Gateway» со статусами, добавлением клиента и выдачей ссылок.
5. Дисклеймер и легальные оговорки в README и при `gateway init`.

**Acceptance:** новый пользователь по README поднимает Reality + Hysteria2 на чистом Ubuntu 24.04 без ручных правок.

---

## 5. Детальный дизайн модулей

### 5.1. Структура каталогов (целевая)

```
src/
├── core/
│   ├── protocol.py        # ProtocolAdapter ABC
│   ├── netcheck.py        # порты, IP, DNS, сертификаты
│   ├── secrets.py         # uuid/пароли/ключи, атомарная запись 0600
│   ├── units.py           # рендер/установка systemd-юнитов
│   └── ... (существующие)
├── gateway/
│   ├── store.py           # GatewayState (pydantic), миграции
│   ├── init.py            # hub: все протоколы + SNI-мультиплексор
│   ├── reconcile.py       # state vs реальность, dry-run/apply
│   ├── healthcheck.py
│   └── rotate.py
├── xray/
│   ├── adapter.py         # ProtocolAdapter
│   ├── install.py
│   ├── clients.py
│   └── config.py          # рендер config.json
├── hysteria2/
├── amneziawg/
├── subscriptions/
│   ├── formats.py         # base64/clash/singbox
│   └── serve.py
└── system/
    └── network_tuning.py  # BBR, sysctl, UFW
```

### 5.2. CLI (целевой)

```bash
# установка одного протокола
vds xray install --sni www.google.com
vds hysteria2 install --domain vpn.example.com
vds amneziawg install

# мультипротокольный hub
vds gateway init --domain vpn.example.com --protocols reality,hysteria2
vds gateway status
vds gateway reconcile [--apply]
vds gateway healthcheck

# клиенты и подписки
vds gateway profile add phone --all-protocols
vds gateway profile list
vds gateway profile remove phone
vds gateway export phone --format base64
vds gateway export phone --format qr
vds gateway sub serve --port 8081

# обслуживание
vds gateway rotate-keys --client phone
vds gateway remove
```

### 5.3. Раскладка портов (один сервер)

| Порт | Протокол | Примечание |
|---|---|---|
| TCP 443 | Xray: Reality / XHTTP (SNI-роутинг) | nginx stream `ssl_preread` |
| TCP 8443 | Xray Reality (за мультиплексором) | localhost |
| TCP 8444 | Xray XHTTP (за мультиплексором) | localhost |
| TCP 8080 | Decoy-сайт (nginx) | отвечает всем «неправильным» |
| UDP 443 | Hysteria2 | QUIC |
| UDP 51820 | AmneziaWG | обфусцированный WG |
| TCP 22 | SSH | UFW limit |

### 5.4. Данные и секреты

- `/opt/vds-gateway/state.json` — профили (0600, root).
- `/usr/local/etc/xray/config.json`, `/etc/hysteria/config.yaml`, `/etc/amnezia/amneziawg/*.conf` — 0600.
- Приватные ключи никогда не попадают в share-link, логи и `git`.
- Фильтр логов: маскировать `uuid`, `password`, `privateKey` (`core/logger.py`).

---

## 6. Риски и меры

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| Конфликт портов на существующем сервере | высокая | блокер установки | `netcheck.port_free` + явные ошибки; SNI-мультиплексор вместо прямого захвата 443 |
| Reality детектится на конкретном ISP | средняя | профиль не работает | второй транспорт (Hysteria2/AmneziaWG) + документированный переключатель |
| ACME не выдаёт сертификат (нет домена) | средняя | Hysteria2/XHTTP недоступны | self-signed с `insecure` для теста; чёткая инструкция про домен |
| Утечка секретов в логи | средняя | компрометация | маскирование + тест на отсутствие ключей в выводе |
| Требования root ломают тестируемость | высокая | долго отлаживать | Docker-e2e + мок `run()` в unit-тестах |
| Блокировка IP сервера | средняя | всё падает | CDN-фронт (фаза 3), документированная ротация IP |
| Живой VDS нужен для приёмки | высокая | долгие циклы | чеклист «проверить на VDS» + минимум e2e в Docker |

---

## 7. Метрики успеха

1. Чистый Ubuntu 24.04 + `install.sh` + `vds gateway init` → рабочий сервер за ≤ 10 минут.
2. Минимум два транспорта разных L4-типов включены по умолчанию.
3. Клиент получает валидную подписку одной командой.
4. Probe-resistance: внешний сканер не отличает сервер от обычного HTTPS/decoy.
5. Watchdog восстанавливает сервис при падении за ≤ 2 цикла таймера.
6. CI зелёный (unit + Docker e2e), покрытие генераторов конфигов ≥ 80 %.
7. Ноль секретов в логах/git (проверяется тестом).

---

## 8. График (ориентир)

| Неделя | Фаза | Результат |
|---|---|---|
| 1 | 0 + 1 | Фундамент, рабочий Reality |
| 2 | 2 + 5 (базово) | Hysteria2, hub + подписки |
| 3 | 3 + 4 | XHTTP/CDN, AmneziaWG |
| 4 | 6 + 7 | Hardening, watchdog/metrics |
| 5 | 8 + 9 | Тесты, документация, релиз |

**Минимальный полезный релиз (MVP):** конец 2-й недели (Reality + Hysteria2 + hub + подписки).

---

## 9. Что делаем первым действием

1. Закрыть P1–P3 из `TECHDEBT.md` (иначе новые модули унаследуют те же дефекты).
2. Добавить `core/protocol.py`, `core/netcheck.py`, `core/secrets.py`, `gateway/store.py` и тесты.
3. Реализовать `src/xray/` — первый транспорт; приёмка на живом VDS.

## 10. Источники практик

- [Project X / Xray-core](https://github.com/XTLS/Xray-core) — VLESS, REALITY, XHTTP.
- [SagerNet / sing-box](https://github.com/SagerNet/sing-box) — универсальное ядро и формат подписок.
- [apernet / hysteria](https://github.com/apernet/hysteria) — Hysteria2, QUIC-транспорт и метрики.
- [amnezia-vpn / amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — обфускация WireGuard.
- [klzgrad / naiveproxy](https://github.com/klzgrad/naiveproxy) — HTTP/2 CONNECT мимикрия.
- [TSPU throttling analysis — Habr](https://habr.com/en/articles/990236) — актуальное поведение цензора.
