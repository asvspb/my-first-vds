# SPEC-20261110-amneziawg-transport

## Мета
- **Источник:** [REQ-20261110-amneziawg-transport](../requirements/REQ-20261110-amneziawg-transport.md)
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-10
- **Статус:** approved (G2)
- **ADR:** [ADR-005](../../adr/ADR-005-amneziawg-transport-decisions.md) — OQ-1..OQ-6 (порт, клиентский режим, источник пакетов, линия версий, kernel/userspace, PSK)

## 1. Цель и решение

Добавить четвёртый транспорт AmneziaWG (обфусцированный WireGuard, kernel-модуль
`amneziawg-dkms` из PPA `ppa:amnezia/ppa`) к живому asv1 как независимый
UDP-резерв: модуль `src/amneziawg/` по образцу `src/hysteria2/` (install /
add-client / status / remove), systemd-юнит из шаблона, серверный и клиентские
.conf с параметрами обфускации, интеграция с gateway store. AWG полностью
независим от работающих Reality/XHTTP/Hysteria2 — отдельный порт, отдельный
юнит, отдельный конфиг; ничего из существующего стека не перезапускается.
Клиентская сторона (OQ-2, вариант b): сервер только выдаёт `.conf`-файл,
подключение — через AmneziaVPN-приложение; root-раннер в vpn-manager — будущая
фаза. Все вердикты OQ-1..6 — в ADR-005.

## 2. Архитектура

```
внешний клиент (AmneziaVPN-приложение / awg-класс)
  └─ AWG (UDP 51825) ──► kernel-модуль amneziawg (iface awg0)
                          vds-amneziawg.service: awg-quick up /etc/amnezia/awg0.conf
                          obfuscation: Jc/Jmin/Jmax + S1,S2 + H1–H4 (1.5-набор, ADR-005)
     peer'ы — клиенты из state.json (protocol="amneziawg", PSK)

Параллельно, без изменений:
  Reality (TCP 443) · XHTTP (TCP 443→127.0.0.1:8443) · Hysteria2 (UDP 443)

Клиентский поток (v1):
  vds amneziawg add-client NAME → клиентский .conf (0600,
  $INSTALL_DIR/gateway/clients/amneziawg/NAME.conf) → импорт в AmneziaVPN
  (vpn-manager хранит копию профиля, туннель НЕ запускает)
```

Точки отказа: DKMS-сборка при установке (E1) и при апдейте ядра (мониторится
в status); порт-конфликт UDP 51825 (E3, проверка до изменений); рестарт
`vds-amneziawg` при add/remove клиента — единственный допустимый downtime.

**Формат данных** (`state.json`, version=1 без изменения версии — только
опциональные поля, ADR-002 совместимо):

```json
"protocols": { "amneziawg": { "installed": true, "port": 51825,
               "iface": "awg0", "pkg_version": "<apt-версия>" } },
"clients": [ { "name": "mob-awg", "protocol": "amneziawg", "port": 51825,
               "extra": { "address": "10.9.0.2/32", "private_key": "…",
                          "psk": "…", "conf_path": "…", "allowed_ips": "0.0.0.0/0,::/0" } } ]
```

Секреты (client `private_key`, `psk`; серверный приватный ключ — только в
`/etc/amnezia/awg0.conf` 0600) — только state.json/конфиги, не в логах/выводе.
Публичный ключ сервера — в `protocols["amneziawg"]["public_key"]` (не секрет).

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/gateway/paths.py` | изменить | + `AWG_UNIT="vds-amneziawg.service"`, `AWG_CONFIG_PATH=Path("/etc/amnezia/awg0.conf")`, `AWG_CLIENTS_DIR = GATEWAY_DIR / "clients" / "amneziawg"`, `AWG_PORT_DEFAULT = 51825`, `AWG_IFACE = "awg0"`, `AWG_ADDRESS_SUBNET = "10.9.0.0/24"` (RFC1918, вне используемых подсетей) |
| `src/amneziawg/__init__.py`, `config.py` | создать | чистые функции: генератор параметров обфускации (seed-детерминизм, валидация `Jmin<=Jmax`, `Jmax < MTU-128`, `H1..H4` попарно различимы, 1.5-набор по ADR-005), рендер серверного и клиентского .conf (снапшот-детерминизм), `awg genkey/genpsk` вызовы вынесены на уровень install/clients |
| `src/amneziawg/install.py` | создать | PPA + apt install (`amneziawg-tools`, `amneziawg-dkms`, pin через `apt-mark hold`), проверка порта `ss -ulnp` ДО изменений, UFW `allow 51825/udp` (при наличии ufw — паттерн `src/wireguard/install.py:164`), рендер `/etc/amnezia/awg0.conf` 0600, systemd-юнит из `systemd/vds-amneziawg.service.tpl`, идемпотентность, `FileLock`, state.protocols обновление |
| `src/amneziawg/clients.py` | создать | `add_client(name, no_psk=False)`: клиентские ключи (`awg genkey`/`genpsk`), IP из подсети `10.9.0.0/24`, peer в серверный .conf (бэкап + перезапуск юнита), запись в store (`ClientProfile.extra`), клиентский .conf в `AWG_CLIENTS_DIR/<name>.conf` 0600; дубль имени — StoreError (паттерн E4) |
| `src/amneziawg/status.py` | создать | `systemctl is-active`, `ss -ulnp` по порту, `awg show awg0` (latest handshake, transfer — ключи маскируются), версия DKMS-модуля, позиция в state; без секретов |
| `src/amneziawg/remove.py` | создать | dry-run по умолчанию (`--apply`): план (юнит, конфиг, клиенты из store) → стоп/disable, бэкап `awg0.conf` (`.bak-pre-remove`) → удаление конфига и клиентских .conf, вычистка store, опц. `apt-mark unhold`; пакеты PPA НЕ удаляются автоматически (purge — ручной шаг из ADR-005) |
| `src/gateway/links.py` | изменить | для `protocol="amneziawg"` — строка-плейсхолдер с путём к .conf (без секретов), поведение xray/hysteria2 не меняется (золотой тест) |
| `src/main.py` | изменить | ленивые импорты, команды § CLI-поверхность (паттерн `hysteria2_*`) |
| `systemd/vds-amneziawg.service.tpl` | создать | `ExecStart=awg-quick up /etc/amnezia/awg0.conf`, `ExecStop=awg-quick down awg0`, `After=network-online.target`; рендер в `/etc/systemd/system/` (конвенция шаблонов) |
| `tests/amneziawg/` | создать | §6 (unit, без root/сети) |
| `tests/gateway/` | изменить | кейсы: AWG-клиент в state, `links`-плейсхолдер, золотой снапшот старого `links`-вывода |

**Публичные интерфейсы (сигнатуры, не реализация):**

```python
# src/amneziawg/config.py
def gen_obfuscation_params(rng: random.Random) -> dict: ...        # {"Jc","Jmin","Jmax","S1","S2","H1".."H4"}; поднимает ValueError при нарушении ограничений
def render_server_conf(params: ServerParams) -> str: ...           # ServerParams: private_key, address, port, obf, peers[]
def render_client_conf(params: ClientParams) -> str: ...           # ClientParams: private_key, psk, address, server_pubkey, endpoint, allowed_ips, obf(S1,S2,H1–H4 — те же, что сервер), junk(Jc,Jmin,Jmax — свои)

# src/amneziawg/install.py
def install(port: int = AWG_PORT_DEFAULT) -> dict: ...             # идемпотентно; {"port","iface","pkg_version","public_key"}

# src/amneziawg/clients.py
def add_client(name: str, no_psk: bool = False) -> dict: ...       # {"conf_path"}; дубль — StoreError
def remove_client(name: str, apply: bool = False) -> dict: ...

# src/amneziawg/remove.py
def remove_transport(apply: bool = False) -> dict: ...             # dry-run план при apply=False
```

**CLI-поверхность:**

```bash
vds amneziawg install [--port 51825]
vds amneziawg add-client <name> [--no-psk]
vds amneziawg remove-client <name> [--apply]
vds amneziawg status
vds amneziawg remove [--apply]
```

**Серверный .conf (пример формы, значения — из генератора):**

```ini
[Interface]
Address = 10.9.0.1/24
ListenPort = 51825
PrivateKey = <server>
SaveConfig = false
Jc = 6
Jmin = 64
Jmax = 256
S1 = 88
S2 = 128
H1 = 2149340781
H2 = 1934967624
H3 = 1242853139
H4 = 881236702

[Peer]
# <name>
PublicKey = <client>
PresharedKey = <psk>
AllowedIPs = 10.9.0.2/32
```

Клиентский .conf: `[Interface]` (PrivateKey клиента, Address `10.9.0.x/32`,
DNS — не пишем в v1) + те же `S1,S2,H1–H4`; `Jc/Jmin/Jmax` — клиентские
(свой генератор, независимы от серверных — факт REQ/vpnsmith); `[Peer]`
(PublicKey сервера, PresharedKey, `Endpoint = <ip>:<port>` — ip берётся из
state/domain или `--endpoint`, AllowedIPs `0.0.0.0/0,::/0`,
PersistentKeepalive = 25).

## 4. Миграция и совместимость

- `state.json`: версия не меняется; добавляются только опциональные
  `protocols["amneziawg"]` и AWG-клиенты — старые `phone`/`mob` читаются
  как есть (инвариант REQ §4, юнит-тесты store).
- `gateway links/status`: для xray/hysteria2 вывод не меняется (золотой
  снапшот-тест); AWG добавляется отдельной веткой.
- `src/wireguard/` (классический WG) — не трогаем, конфиги не мигрируются.
- Обратимого миграционного шага нет: AWG добавляется с нуля, удаляется
  целиком (`remove --apply`).

## 5. Безопасность и отказы

- Секреты: серверный PrivateKey — `/etc/amnezia/awg0.conf` 0600; клиентские
  PrivateKey/PSK — state.json (0600) и клиентский .conf (0600); stdout/journal —
  только пути и маскированные идентификаторы.
- FileLock: install, add/remove-client, remove — под `core.lock.FileLock`.
- Dry-run: `remove`, `remove-client` — dry-run по умолчанию + `--apply`.
- Бэкап перед мутацией: `awg0.conf` → `.bak-pre-mutation` (add-client) /
  `.bak-pre-remove` (remove), state.json — атомарная запись store
  (tmp+replace, 0600).
- Failure modes (из REQ §7): E1 нет пакетов/PPA недоступен → отказ до
  изменений (ручной перенос .deb — в доке, не автоматизирован); E2 не
  применим (github не участвует; mirror-конвенция на AWG не распространяется —
  ADR-005); E3 порт занят → `ss -ulnp` до изменений, перечень занявших
  процессов, Hysteria2 не тронут; E4 дубль клиента → StoreError; E5 битый
  state.json → StoreError без traceback (паттерн store.py); E6 битый серверный
  .conf → бэкап + отказ, рестарт не выполняется; E7 повторный install →
  идемпотентно, ключи не перегенерированы; E8 нет root → читаемый отказ; E9
  обрыв при apt-установке → apt сам атомарен, повторный запуск докатывает;
  E10 права .conf шире 0600 → исправление при создании; E11 remove с живыми
  клиентами → план в dry-run, из store и диска при `--apply`; E12 имя
  интерфейса `awg0` → паттерн `awg*` в гварде (WP-5).
- Откат: ADR-005 «Как откатить» + `vds amneziawg remove --apply`;
  state.json восстанавливается из бэкапа store/точки до мутации.

## 6. Тест-план

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | генератор обфускации: seed-детерминизм, уникальность на «установку» (разные seed → разные значения), ограничения `Jmin<=Jmax`, `Jmax<MTU-128`, `H1..H4` попарно различимы; нарушение → ValueError, не тихий конфиг | `tests/amneziawg/test_obfuscation.py` |
| Unit | рендер серверного/клиентского .conf: снапшоты (фикстуры `FIXTURE_PW_*`, зарезервированные IP/UUID — конвенция AGENTS.md §6), 1.5-набор, отсутствие секретов в снапшотах; клиентский .conf = серверные S/H, свои J-параметры | `tests/amneziawg/test_render.py` |
| Unit | store: AWG-клиент round-trip, дубль имени, E5 битый JSON, старые клиенты не затронуты; `links`-плейсхолдер AWG + золотой снапшот xray/hysteria2-вывода | `tests/gateway/` |
| Unit | install/remove на моках shell: dry-run-план, идемпотентность (двойной прогон), port-check отказ, отсутствие вызовов `VDS_GITHUB_MIRROR`-логики | `tests/amneziawg/test_install_mock.py` |
| Unit | status-маскирование на моках (ключи не в выводе) | `tests/amneziawg/test_status_mock.py` |
| Integration (Docker) | — | не входит в цикл (E2E для AWG требует ядра/DKMS — невозможно в контейнере; приёмка на живом VDS) |
| Ручная приёмка (VDS asv1) | AC [VDS] REQ + §4 «Не ломать»: раскладка портов (`ss -tlnp`/`ss -ulnp`), `phone`/`mob` по старым каналам, права 0600, grep секретов в journal, двойной прогон install/add-client, импорт .conf в AmneziaVPN владельца (гейт OQ-4) | чеклист ACCEPT |

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| **WP-1** Генератор+рендер | `config.py`: gen_obfuscation_params (валидация), render_server_conf/render_client_conf; тесты | `src/amneziawg/__init__.py`, `src/amneziawg/config.py`, `tests/amneziawg/test_obfuscation.py`, `tests/amneziawg/test_render.py` | — | `compileall` exit 0; `pytest -q` зелёный; снапшоты без реальных секретов (фикстуры `FIXTURE_*`); нарушения ограничений → ValueError |
| **WP-2** Установка | `install.py` (PPA/apt/pin/port-check/UFW/state), шаблон юнита, paths-добавки, CLI `amneziawg install`; тесты на моках | `src/amneziawg/install.py`, `src/gateway/paths.py`, `systemd/vds-amneziawg.service.tpl`, `src/main.py` (только `amneziawg install`), `tests/amneziawg/test_install_mock.py` | WP-1 | pytest зелёный; port-check до изменений покрыт; идемпотентность (двойной прогон) покрыта; нет обращений к github/mirror-логике; код без `shell=True` |
| **WP-3** Клиенты + store | `clients.py` (add/remove-client, .conf 0600, peer в серверный конфиг), интеграция store (`protocol="amneziawg"`), `links.py`-плейсхолдер, CLI add/remove-client; тесты store/links | `src/amneziawg/clients.py`, `src/gateway/links.py`, `src/main.py`, `tests/amneziawg/`, `tests/gateway/` | WP-2 | pytest зелёный; E4/E5 покрыты; клиентский .conf рендерится по WP-1-функциям; секреты только в state/.conf; золотой снапшот links (xray/hysteria2) не сломан |
| **WP-4** Status + remove | `status.py` (маскирование, DKMS-версия), `remove.py` (dry-run по умолчанию, бэкап, вычистка store), CLI; тесты | `src/amneziawg/status.py`, `src/amneziawg/remove.py`, `src/main.py`, `tests/amneziawg/test_status_mock.py` | WP-3 | pytest зелёный; dry-run по умолчанию; маскирование ключей покрыто тестом; E11/E8-поведение покрыто на моках |
| **WP-5** Guard (.zshrc, минор, FR-7) | добавить паттерн `awg*` в `_check_vpn_active` (`~/Dev/ubuntuInstaller`, файл .zshrc ~стр.448); логика ZeroTier/vpn-manager-веток без изменений; проверка функции в изолированном shell (dummy-link/netns или мок `ip`/`awg`); синхронизация правки с репо ubuntuInstaller | файл `~/.zshrc` в репо ubuntuInstaller (вне этого репо) | WP-2 (известно имя `awg0`) | гвард возвращает 0 при фейковом `awg0`-интерфейсе и прежнее поведение без него; diff не трогает другие ветки функции; правка закоммичена в ubuntuInstaller |
| **WP-6** Приёмка [VDS] | чеклист ACCEPT: все AC [VDS] REQ + §4 «Не ломать» по промежуточным гейтам и финально; **гейт OQ-4: импорт клиентского .conf в AmneziaVPN владельца** | `docs/team/reports/ACCEPT-*.md` | WP-1..5 | PASS/FAIL-отчёт; любой Breaking → откат (ADR-005), цикл не принят; отказ импорта .conf → эскалация архитектору (правка ADR-005/SPEC, не «fix on the fly») |

Пересечение файлов: `src/main.py` затрагивают WP-2/3/4, `tests/` — WP-1/2/3/4 →
**сериализация строго WP-1→2→3→4** (WP-5 параллельно WP-2+; WP-6 в конце).
С другими циклами проектного репо конфликтов нет (файлы новые + изолированные
добавки в paths/main) — параллелизм с посторонними работами допустим.

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| PPA/launchpad недоступен с asv1 | низкая-средняя | блокер установки | E1: отказ до изменений; ручной перенос .deb (док); эскалация — тогда и только тогда пересмотр ADR-005 (сборка из исходников) |
| DKMS-модуль не собирается (headers/ядро) | низкая | блокер установки/апдейта ядра | проверка `linux-headers-$(uname -r)` до установки; статус показывает версию модуля; fallback userspace — вне v1, эскалация |
| AmneziaVPN владельца отвергает 1.5-набор .conf | низкая | среднее (перевыпуск конфигов) | WP-6 гейт импорта; правка ADR-005 → 2.0-набор; генератор параметризован (конфиг-флаг) заранее |
| Порт 51825 однажды займёт другой сервис | низкая | среднее | `--port` переопределяет; port-check при install и в status |
| Секреты просачиваются в вывод/status | низкая | высокое | маскирование + unit-тесты на моках + grep-шаг приёмки |
| AWG-клиентский .conf с `AllowedIPs 0.0.0.0/0` на устройстве ломает локальный роутинг | низкая | низкое (клиентская сторона) | v1 — полный туннель по умолчанию; split-tunnel — вне скоупа (REQ §6) |

## 9. Границы изменений

- **Трогаем:** `src/amneziawg/` (новое), `src/gateway/paths.py` (добавки),
  `src/gateway/links.py` (AWG-ветка), `src/main.py` (ленивые импорты новых
  команд), `systemd/vds-amneziawg.service.tpl` (новое), `tests/amneziawg/`,
  `tests/gateway/` (доп. кейсы), репо ubuntuInstaller — только функция
  `_check_vpn_active` (WP-5).
- **Не трогаем:** публичный CLI существующих команд (только добавление новых),
  `topology.json`, схему state.json (только опциональные поля), права 0600,
  systemd-юниты существующих сервисов и их шаблоны, `src/wireguard/`,
  `src/zerotier/`, `realitySettings`, порты/конфиги Reality/XHTTP/Hysteria2,
  UFW-правила кроме одного нового `allow 51825/udp`, sysctl.

## 10. Трассируемость

| REQ | WP | Файлы | Тест |
|---|---|---|---|
| FR-1 (install, E1/E2/E3/E7, mirror) | WP-2 | amneziawg/install.py, paths, unit-tpl | test_install_mock + [VDS] |
| FR-1 (генератор/валидация, уникальность) | WP-1 | amneziawg/config.py | test_obfuscation, test_render |
| FR-2 (add-client, .conf, store) | WP-3 | amneziawg/clients.py, links.py | tests/amneziawg, tests/gateway + [VDS] |
| FR-3 (status, маскирование) | WP-4 | amneziawg/status.py | test_status_mock + [VDS] |
| FR-4 (remove, dry-run, E11) | WP-4 | amneziawg/remove.py | мок-тесты + [VDS] |
| FR-5 (store/links/gateway) | WP-3 | links.py, store-кейсы | tests/gateway + [VDS] |
| FR-6 вариант (b) (OQ-2) | WP-3 (выдача .conf; vpn-manager-хранение — вне этого репо, только инструкция в выводе/доке) | amneziawg/clients.py | [VDS] импорт в AmneziaVPN |
| FR-7 (гвард, E12) | WP-5 | .zshrc (ubuntuInstaller) | изолированный shell-тест |
| §4 «Не ломать», NFR, откат | WP-6 | — | ACCEPT-чеклист |

## Следующий шаг
→ оркестратор назначает vds-coder на WP-1, далее строго WP-2→3→4 (пересечение
`src/main.py`/`tests`); WP-5 параллельно после WP-2; WP-6 — приёмка на asv1,
затем vds-tester.
