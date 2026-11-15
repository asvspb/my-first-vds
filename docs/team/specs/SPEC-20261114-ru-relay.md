# SPEC-20261114-ru-relay

## Мета
- **Источник:** [REQ-20261114-ru-relay](../requirements/REQ-20261114-ru-relay.md);
  [ADR-007](../../adr/ADR-007-ru-relay.md) (accepted 2026-11-14/15, «Девиации v1»);
  прямое указание владельца 2026-11-15.
- **Автор:** техлид+кодер (vds-coder)
- **Дата:** 2026-11-15
- **Статус:** draft → исполнение (WP-1..WP-5 в рабочем дереве; WP-6 = харднинг
  по находкам AWG-Router, 2026-11-15; без коммитов — ревью через оркестратора)
- **ADR:** ADR-007 (status accepted, раздел «Девиации v1» добавлен этим циклом)

## 1. Цель и решение

Поднять **RU-relay** (Фаза 1): на российском VDS — AWG-сервер UDP 443 (одна
инстанция, подсеть 10.10.0.0/24) + Xray Reality TCP 443 RU-SNI (фолбэк,
другой L4 на том же порте) + awg1-нога до asv1 (v4-only) + policy-routing
(RU-CIDR → direct eth0, остальное → awg1) + UFW + недельный таймер
обновления RU-CIDR. Три артефакта: (A) REQ/SPEC/ADR-девиации, (B) код
`src/relay/` + CLI `vds relay`, (C) ручной ранбук `docs/DEPLOY-RU-RELAY.md`.

**Ключевые решения:**
1. **CLI повторяет ранбук 1:1**: `vds relay init --apply` исполняет ровно
   шаги Фазы 2 из DEPLOY-RU-RELAY.md; ручной путь — резервный/обучающий.
2. **Переиспользование вместо копирования**: рендеры obfuscation-конфигов —
   `src/amneziawg/config.py` (validate/ServerParams/render_server_conf),
   юнит AWG-сервера — шаблон `systemd/vds-amneziawg.service.tpl` с другим
   именем юнита (`vds-relay-awg.service`), Reality — `src/xray/install.py`
   (`run_install(sni=...)`), состояние — gateway store
   (`protocols["relay"]`), путь-константы — свой `src/relay/paths.py`
   (НЕ src/gateway/paths.py — подсеть/порты/имена другие).
3. **Policy-routing через fwmark**: nftables prerouting помечает трафик
   awg0 → не-RU dst mark 0x1; `ip rule fwmark 0x1 table 100`; table 100 =
   default dev awg1; awg1-конфиг с `Table = off` (AllowedIPs 0.0.0.0/0 из
   add-client на asv1 не должен засорять main-table релея).
4. **MTU awg0 = 1280** (двойная инкапсуляция client→relay→asv1); awg1 —
   дефолт (одинарная). MSS-clamp в обе стороны (awg0-traffic и awg1-traffic)
   включён как страховка — находка AWG-Router (habr 1107904): clamp надёжнее
   одного MTU при двойной инкапсуляции, дешёвы две nft-правила в nat-таблице.
5. **Dry-run по умолчанию**: `relay init` печатает план (шаги + preflight),
   мутации только `--apply`; fail-fast по конвенции gateway/init.
6. **Домен**: `relay.asvpersonal.ru` A-запись DNS-only (серое облако;
   CF-прокси не пропускает UDP 443 AWG и не-HTTP TCP).
7. **Fail-safe «unreachable default» (находка AWG-Router)** ⭐: в table 100
   (выход через awg1) вместе с default dev awg1 прописывается
   `ip route replace unreachable default metric 4096` — при падении ноги
   до asv1 не-RU-трафик НЕ уходит с RU-IP релея напрямую (тихая деградация
   вместо утечки). Определяется живость ноги по возрасту handshake
   (RekeyAfter+70с, паттерн AWG-Router) в `relay status`; юнит
   `vds-relay-policy` идемпотентно восстанавливает пару правил.
8. **DNS через путь выхода (находка AWG-Router)**: DNS-запросы клиентов
   должны идти тем же путём, что и их трафик (иначе RU-CDN вернёт RU-узел
   и трафик сделает крюк). В dnsmasq-предложении (OQ-3) — форвард через
   awg1 с SO_MARK 0x1 (dnsproxy-паттерн AWG-Router); «тихий откат» на
   открытый RU-резолвер запрещён.
9. **I1-маски AWG (находка AWG-Router)** — замену дефолтного I1
   (DPI-сигнатура «всех AWG-серверов») на шаблоны QUIC Initial 1200B /
   STUN / DNS — НЕ в v1 (non-goal REQ §3: рисковать obf-валидацией до
   полевой приёмки); зафиксировано как OQ-5 / кандидат следующего WP.

## 2. Архитектура

```
клиент ──AWG udp/443 (awg0, 10.10.0.0/24)──> RU-relay ─┬─ dst ∈ RU-CIDR → eth0 (direct)
                                                       └─ прочее (fwmark 0x1, table 100) → awg1 → asv1:51825
клиент ──Reality tcp/443 (RU-SNI фолбэк)──> RU-relay (xray, state protocols["xray"])
nft inet vds_relay: set ru_cidr; prerouting iif awg0 daddr != @ru_cidr → mark 0x1
nat: postrouting oif awg1 masquerade; oif eth0 saddr 10.10.0.0/24 masquerade
     + mss-clamp обе стороны (tcp option set mss)
table 100: default dev awg1 + unreachable default metric 4096  # fail-safe
systemd: vds-relay-awg / vds-relay-exit / vds-relay-nat / vds-relay-policy /
         vds-relay-cidr.service + .timer (еженедельно, идемпотентно)
```

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/relay/__init__.py` | создать | пакет |
| `src/relay/paths.py` | создать | константы релея (iface/подсеть/порты/юниты/пути, INSTALL_DIR) |
| `src/relay/config.py` | создать | чистые рендеры: серверный awg0-conf (MTU), клиентский conf, awg1-sanitize (Table=off), nft-policy-файл, dnsmasq-предложение, план dry-run, парсер `awg show` |
| `src/relay/cidr.py` | создать | загрузка ipdeny RU → агрегация (ipaddress.collapse_addresses) → nft-файл; entry `python -m src.relay.cidr update` |
| `src/relay/init.py` | создать | preflight + план + apply (переиспользование amneziawg-install-хелперов и xray run_install) |
| `src/relay/status.py` | создать | юниты/маршруты/handshake-возраст/сводка |
| `src/relay/clients.py` | создать | add-client: пир awg0 (10.10.0.x), .conf 0600, append [Peer], рестарт юнита |
| `src/main.py` | изменить | `relay` typer-подприложение (ленивые импорты), пункт TUI-меню |
| `systemd/vds-relay-{exit,nat,policy}.service.tpl` | создать | oneshot-юниты релея |
| `systemd/vds-relay-cidr.service.tpl`, `vds-relay-cidr.timer.tpl` | создать | еженедельное обновление RU-CIDR |
| `tests/relay/` | создать | unit-тесты (без root/сети/docker) |
| `docs/DEPLOY-RU-RELAY.md` | создать | ручной ранбук Фазы 0/2 с проверками |
| `docs/adr/ADR-007-ru-relay.md` | изменить | proposed → accepted + «Девиации v1» |
| `README.md`, `AGENTS.md` | изменить | строка о `vds relay` (структура/стек) |

**Публичные интерфейсы:**

```python
# src/relay/config.py
def build_plan(args: RelayArgs) -> list[dict]: ...          # dry-run план (без секретов)
def render_relay_server_conf(params, mtu: int) -> str: ...
def sanitize_exit_conf(text: str, mtu: int = 1420) -> str:   # Table = off
def render_nft_policy(cidrs: list[str]) -> str: ...
def render_dnsmasq_proposal(ru_dns: str, exit_iface: str) -> str: ...
def parse_awg_show(text: str) -> dict[str, dict]: ...       # peer → latest_handshake/…

# src/relay/cidr.py
def aggregate(cidrs: Iterable[str]) -> list[str]: ...
def render_nft_cidr_file(cidrs: list[str]) -> str: ...
def update(timeout: int = 60) -> int: ...                   # apt-free, идемпотентно
```

**CLI-поверхность (полный --help с примерами у каждой):**

```bash
sudo vds relay init --exit 103.45.247.172 --domain relay.asvpersonal.ru --sni <RU-сайт> [--apply] [--exit-conf /path/awg-client.conf]
sudo vds relay status [--json]
sudo vds relay add-client <имя>
python -m src.relay.cidr update   # вызывается таймером vds-relay-cidr.service
```

## 4. Миграция и совместимость

- Существующие транспорты asv1 не затрагиваются (релей — отдельный сервер;
  на asv1 единственное изменение — `vds amneziawg add-client relay` —
  существующий механизм, клиенты не трогаются).
- `vds relay` — новое подприложение; прежние команды не меняются.
- Откат: `vds relay init` не поддерживает remove в v1 — демонтаж руками по
  ранбуку (раздел «Откат»); юниты идемпотентны, повторный apply дотягивает.

## 5. Безопасность и отказы

- Root-check до всего; порт-чек 443 tcp+udp ДО apt (preflight, паттерн E1).
- FileLock `/var/run/vds-relay.lock` на все мутации; конфиги атомарно 0600
  (write_secret_atomic); приватные ключи не в stdout/логах/state-выводе.
- Dry-run печатает план БЕЗ секретов (ключи/PSK не попадают в plan-строки).
- `awg show` парсится маскированно (только public-key-хвосты/время).
- awg1-конфиг с недостающими ключами не запускается: preflight PrivateKey-чек;
  отсутствие conf → шаг «перенесите конфиг с asv1» с понятным текстом.
- nft-файл атомарен; policy-юнит идемпотентен (nft -f флушит свою таблицу).

## 6. Тест-план

| Уровень | Что | Где |
|---|---|---|
| Unit | рендеры server/client conf (MTU/obf-валидация), sanitize (Table=off), nft-policy, dnsmasq, CIDR-агрегация, plan (шаги, без секретов, dry-run), parse_awg_show, аллокация 10.10.0.x, дубль имени | `tests/relay/` |
| CLI | `vds relay init` без --apply — exit 0 без мутаций на тестовом tmp-state; --help всех команд | ручная/CI |
| Поле (Фаза 0) | leg smoke-test до asv1:51825 | ранбук |
| Поле (Фаза 2) | `curl --interface awg1 ifconfig.me` = IP asv1; ya.ru мимо awg1 (tcpdump/mtr); reboot-тест | ранбук |

**Критерии приёмки:** AC-1..AC-5 из REQ-20261114 (§5).

## 7. Work packages

| WP | Задача | Файлы | Зависит | DoD |
|---|---|---|---|---|
| **WP-1** | REQ + SPEC + ADR-007 accepted/девиации | `REQ-20261114-ru-relay.md`, `SPEC-20261114-ru-relay.md`, `ADR-007` | — | файлы согласованы со скоупом |
| **WP-2** | `src/relay` ядро: paths/config/cidr + план/рендеры | `src/relay/{__init__,paths,config,cidr}.py` | WP-1 | чистые функции, импорт без root |
| **WP-3** | init/status/clients + systemd-шаблоны + main.py | `src/relay/{init,status,clients}.py`, `systemd/vds-relay-*.tpl`, `src/main.py` | WP-2 | dry-run план без мутаций; --apply переиспользует amneziawg/xray |
| **WP-4** | Unit-тесты tests/relay | `tests/relay/*` | WP-2/3 | pytest зелёный |
| **WP-5** | Ранбук DEPLOY-RU-RELAY + README/AGENTS | `docs/DEPLOY-RU-RELAY.md`, README, AGENTS | WP-3 | шаги ↔ CLI 1:1, проверки каждого шага |
| **WP-6** | Харднинг по находкам AWG-Router (habr 1107904): unreachable-default в table 100 (юнит policy), MSS-clamp обе стороны (nat-юнит), SO_MARK-форвард DNS в dnsmasq-предложении, handshake-возраст ноги в status | `src/relay/{config,init,status}.py`, `systemd/vds-relay-{nat,policy}.service.tpl`, ранбук §МSS/unreachable | WP-5 | unit-тесты рендеров + в ранбуке проверка « ноги умерла → трафик не уходит с RU-IP» |

## 8. Риски

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| UDP 443 шейпится на RU-хостере | средняя | нога мертва | Фаза 0 smoke-test до развёртывания; эскалация владельцу |
| /24 relay-хостера грязный | средняя | whitelist режет релей | критерий закупки; смена IP до оплаты |
| AllowedIPs 0.0.0.0/0 в awg1 рвёт маршруты релея | высокая | потеря ssh | Table = off (sanitize) + warn в preflight |
| nft/fwmark конфликт с docker/ufw | низкая | правила перетираются | своя таблица inet vds_relay; policy-юнит восстановит при ребуте |
| Двойная инкапсуляция MTU | высокая | обрывы TLS | MTU 1280 + MSS-clamp обе стороны (WP-6); тест SSL в приёмке |
| Падение ноги relay→asv1 → утечка не-RU-трафика с RU-IP | средняя | RU-IP видит «западный» трафик клиентов | unreachable default metric 4096 в table 100 (WP-6); status показывает живость ноги |

## 9. Границы

- **Трогаем:** файлы из §3.
- **Не трогаем:** asv1-модули (amneziawg/xray/hysteria2/acme — только
  импорты), zerotier/wireguard/coturn, CI.
- **Вне скоупа:** non-goals REQ §3.

## 10. Трассируемость

| Источник | WP | Тест |
|---|---|---|
| ADR-007 §Решение/R1a (v1-девиации) | WP-2/3 | tests/relay + поле |
| REQ FR-1..FR-7 | WP-2..4 | AC-1..4 |
| Указание владельца «документация и --help» | WP-3/5 | --help-обзор, ранбук |
| AWG-Router (habr 1107904, 2026-11-15): unreachable-default, MSS-clamp, DNS через путь выхода, I1-маски | WP-6 (+OQ-5) | unit-тесты рендеров; полевая проверка fail-safe в ранбуке |

## 11. Открытые вопросы

- OQ-1..OQ-3 REQ §6 (хостер, SNI same-DC, dnsmasq-исполнение).
- **OQ-4:** ipdeny RU-источник (ipv4 list) — единственный в v1; альтернативный
  источник (RIPE) — бэклог.
- **OQ-5:** кастомные I1-маски AWG (QUIC Initial 1200B / STUN / DNS вместо
  дефолтного — DPI-сигнатура), реализовано в AWG-Router (habr 1107904) —
  кандидат следующего WP после полевой приёмки v1.
