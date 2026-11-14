# SPEC-20261114-xhttp-split

## Мета
- **Источник:** [SPLIT-TRANSPORTS](../SPLIT-TRANSPORTS.md) §3.3/§5 (шаг 4);
  запрос владельца 2026-11-14 «xray-xhttp на подобие AWG».
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-14
- **Статус:** approved (G2); **G4 BLOCKED 2026-11-14** — код принят
  условно, end-to-end упирается в версию серверного Xray (25.1.1 vs клиент
  26.1.23, xhttp 400); варианты A/B/C — в
  [TEST-20261114-xhttp-split](../reports/TEST-20261114-xhttp-split.md)
- **ADR:** не требуется: клиентская схема, обратима; серверные контракты
  XHTTP (ADR-003) не меняются. CF-вариант закрыт (TEST-20261113-cdn-xhttp-cf).

## 1. Цель и решение

Сделать **системный зонный split для прямого XHTTP** (профиль `xray-xhttp`,
TCP 8443) по образцу AWG: браузер/приложения ходят без SOCKS, домены из
`/opt/awg-split/domains.txt` — через XHTTP-туннель, RU/исключения — напрямую.
Механика — та же, что у AWG (dnsmasq→nft-set→fwmark→table→dev), но `dev =
xray0` (tun xray-клиента), свои mark/table.

Ключевые решения:
1. **Xray tun-инбаунд** (`protocol: tun`, имя `xray0`, mtu 1420) + outbound
   VLESS+XHTTP из существующего профиля. Auto-route у xray нет — маршруты
   ведёт nft/fwmark, как у AWG.
2. **Параметризация split-скрипта**: `15_domain-split.sh` получает
   `--dev/--mark/--table` (по умолчанию — прежние AWG-значения), чтобы одна
   механика обслуживала AWG и XHTTP.
3. **Отдельный root-скрипт + templated unit** `vpn-xray-split@<profile>`
   (по образцу `vpn-awg-split@`), конфиг — `/etc/vpn-manager/xray-split-<p>.json`
   (0600), генерируется vpnm.
4. **Одна основная схема за раз**: `vpn scheme xhttp-split` останавливает
   AWG-split (и наоборот), иначе два tun/mark конфликтуют.
5. **Kill-switch**: при остановке/падении юнита `ExecStopPost` снимает
   nft-jump/ip-rule/table, чтобы не было blackhole; `vpn reset` — полный
   демонтаж (юнит + правила + DNS).

XHTTP через Cloudflare не рассматривается (CF не пропускает XHTTP —
[TEST-20261113-cdn-xhttp-cf](../reports/TEST-20261113-cdn-xhttp-cf.md)); только
прямой 8443.

## 2. Архитектура

```
systemd-resolved → dnsmasq (127.0.0.1:53) → DoH (cloudflared)
                 └─ nftset: домены из /opt/awg-split/domains.txt
nft inet/vds_split: mark 0x23000 для адресов из set
ip rule fwmark 0x23000 → table 23000 → default dev xray0
vpn-xray-split@<profile>.service:
   ExecStart = xray run -c /etc/vpn-manager/xray-split-<p>.json
   ExecStopPost = vds-xsplit-cleanup (снять jump/rule/table)
xray tun (xray0) → VLESS+XHTTP (tcp/8443) → сервер asv1 → интернет
```

AWG-split и XHTTP-split используют **один** `domains.txt` и одну DNS-цепочку;
различаются `dev`, `mark`, `table` и nft-таблицей.

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `ubuntuInstaller/scripts/15_domain-split.sh` | изменить | параметры `--dev/--mark/--table` (defaults: `awg0-split`, `0x21000`, `21000`); backward-compat |
| `ubuntuInstaller/scripts/17_xray-split.sh` | создать | root-скрипт: unit `vpn-xray-split@`, старт, split `--dev xray0 --mark 0x23000 --table 23000`, cleanup `--off` |
| `vpnm/xclient.py` | изменить | `xray_tun_config(link, tun_name="xray0", mtu=1420, socks_port=None) -> str` (tun inbound + xhttp outbound) |
| `vpnm/xsplit.py` | создать | генерация конфига в `/etc/vpn-manager` (через sudo), вызов 17-скрипта, статус, стоп, mutual exclusion с AWG |
| `vpnm/cli.py` | изменить | `vpn scheme xhttp-split [profile]`; `vpn scheme reset` гасит и xsplit; `vpn monitor` — канал `xray-split` |
| `vpnm/channels.py` | изменить | статус xray-split: unit active, iface `xray0`, mark/table, проба 204 |
| `vpnm/tui.py` | изменить | пункт «XHTTP split (системный)» (опционально, если успеваем) |
| `tests/test_xsplit.py` | создать | tun-конфиг, выбор профиля, mutual exclusion, статус, ошибки sudo |
| `ubuntuInstaller/doc/vpn-manager.md` | изменить | раздел «XHTTP split: как AWG», откат, ограничения |
| `vds/docs/SPLIT-TRANSPORTS.md` | изменить | §3.3/§5: статус «реализовано» после приёмки |

**Публичные интерфейсы:**

```python
# vpnm/xclient.py
def xray_tun_config(link: ProfileLink, tun_name: str = "xray0",
                    mtu: int = 1420,
                    config_dir: str = "/etc/vpn-manager") -> str: ...

# vpnm/xsplit.py
def resolve_profile(name: str | None = None) -> str: ...      # xray-xhttp
def apply(profile: str, run: RunCmd | None = None) -> tuple[bool, str]: ...
def stop(run: RunCmd | None = None) -> tuple[bool, str]: ...
def status() -> dict: ...   # unit/iface/mark/table/204
```

**CLI-поверхность:**

```bash
vpn scheme xhttp-split [profile]   # поднять системный XHTTP-split (root)
vpn scheme awg                     # mutual exclusion: сначала снимает xsplit
vpn scheme reset                   # снять всё (xsplit + awg + sysproxy + DoH)
```

**Скрипт 17 (root, идемпотентный):**

```bash
bash scripts/17_xray-split.sh --profile <p>      # unit + start + split
bash scripts/17_xray-split.sh --status
bash scripts/17_xray-split.sh --off              # stop/disable unit + cleanup
```

## 4. Миграция и совместимость

- `15_domain-split.sh` без новых флагов работает как раньше (AWG).
- `vpn scheme xhttp-split` — новая команда, существующие схемы не меняются.
- Awg-split и xsplit взаимоисключающие, переключение идемпотентно.
- Сервер (`vds`) не меняется: XHTTP уже слушает 8443 (`mode=port`).
- Откат: `vpn scheme reset` / `17_xray-split.sh --off`; оба снимают unit,
  правила и (по флагу) DNS-цепочку.

## 5. Безопасность и отказы

- Требуется root (`sudo -n`; при отсутствии — печатается ручная команда, как
  в `amneziawg.tunnel_control`).
- Конфиг xray-split — 0600, секреты (UUID) не в логах.
- **Kill-switch**: `ExecStopPost` снимает mark/rule/table; тест
  «stop юнита → интернет напрямую, без blackhole».
- Проверка порта/iface до старта: если `xray0` занят/не создаётся — fail с
  диагностикой.
- Конфликт схем: перед xsplit проверяется `vpn-awg-split@*` (stop), иначе
  fail с подсказкой.
- DNS: используется общий dnsmasq/DoH; при `--off` DNS не ломается
  (resolved возвращается к провайдеру только `vpn doh off`/`vpn reset`).

## 6. Тест-план

| Уровень | Что | Где |
|---|---|---|
| Unit | `xray_tun_config`: tun inbound (name/mtu), outbound xhttp (path/host), нет mux; resolve_profile; mutual exclusion; ошибки sudo/нет профиля | `tests/test_xsplit.py` |
| Shell | `bash -n` 15/17; `15 --status` без root; параметры `--dev/--mark/--table` не ломают AWG-дефолт | ручная/CI |
| Ручная приёмка (ноутбук) | `vpn scheme xhttp-split` → `xray0` up, nft mark/table, youtube/telegram через XHTTP, RU напрямую; `vpn scheme reset` — чисто; stop юнита — kill-switch | чеклист |
| Регресс | AWG-split, Reality/Hy2/CDN-профили, `vpn probe/speed`, `vpn reset` | `pytest` vpnm, ручной |

**Критерии приёмки:**

1. `vpn scheme xhttp-split` → unit active, iface `xray0`, `ip rule` + table
   23000 + nft mark; `curl https://www.youtube.com/generate_204` через split
   отвечает 204; RU-сайт (`ya.ru`) идёт напрямую.
2. `systemctl stop vpn-xray-split@<p>` → правила сняты, интернет напрямую,
   blackhole нет.
3. `vpn scheme awg` после xsplit → xsplit снят, AWG работает; обратно —
   так же.
4. `vpn scheme reset` → нет unit/iface/rule/table, DNS у провайдера.
5. `pytest -q` в `scripts/vpn-manager` зелёный; секретов в логах нет.
6. Провал без root: команда печатает ручную `sudo`-команду и exit≠0.

## 7. Work packages

| WP | Задача | Файлы | Зависит | DoD |
|---|---|---|---|---|
| **WP-1** | Параметризация `15_domain-split.sh` (`--dev/--mark/--table`), backward-compat | `scripts/15_domain-split.sh` | — | `bash -n`; AWG-дефолт не меняется; `--status` работает |
| **WP-2** | `xray_tun_config` + `17_xray-split.sh` (unit/split/cleanup) | `vpnm/xclient.py`, `scripts/17_xray-split.sh` | WP-1 | конфиг валиден (`xray -test`), unit стартует, split применяется вручную |
| **WP-3** | `vpnm/xsplit.py` + CLI/схемы/monitor/reset + TUI | `vpnm/xsplit.py`, `cli.py`, `channels.py`, `tui.py` | WP-2 | `vpn scheme xhttp-split` работает, mutual exclusion, статус |
| **WP-4** | Тесты + docs | `tests/test_xsplit.py`, `doc/vpn-manager.md`, SPLIT-TRANSPORTS | WP-3 | pytest зелёный; доки с чеклистом/откатом |

Пересечения: WP-2/3 — разные файлы; `cli.py` трогает только WP-3.
WP-4 — после WP-3.

## 8. Риски

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| Xray tun-схема/поведение отличается от ожидаемого | средняя | не поднимется iface | проверить `xray -test` + минимальный конфиг на ноутбуке до полного split |
| Конфликт nft/mark с AWG | средняя | часть трафика уйдёт не туда | разные таблицы/mark; mutual exclusion; тест переключения |
| Blackhole при падении xray | высокая | нет интернета | `ExecStopPost` cleanup + тест kill-switch |
| UDP-over-TCP | известно | звонки/игры хуже | документировать; AWG остаётся для UDP |
| Клиенты: только Xray-core | известно | не универсально | документировать; мобильным — Reality/CDN |
| Провайдерский троттлинг 8443 | средняя | скорость ниже | не решается схемой; откат на AWG/Reality |

## 9. Границы

- **Трогаем:** `scripts/15_domain-split.sh`, новый `scripts/17_xray-split.sh`,
  `vpnm/{xclient,xsplit,cli,channels,tui}.py`, тесты, `doc/vpn-manager.md`,
  `docs/SPLIT-TRANSPORTS.md`.
- **Не трогаем:** сервер `vds` (XHTTP уже есть), `state.json`, AWG-конфиги,
  sysproxy, `11_vds-deploy.sh`, CF/Argo.
- **Вне скоупа:** Reality-split (отдельная SPEC), subscription/QR, IPv6-split.

## 10. Трассируемость

| Источник | WP | Тест |
|---|---|---|
| SPLIT-TRANSPORTS §3.3/§5 | WP-1..3 | `tests/test_xsplit.py`, ручная §6 |
| «как AWG» (владелец) | WP-3 | AC-1/3/4 |
| XHTTP-only клиенты (GR-09) | docs WP-4 | матрица клиентов |

## 11. Открытые вопросы

- **OQ-1:** Xray tun settings — точная схема (`name`, `mtu`, `gateway`,
  `dns`); проверяется в WP-2 на живом xray 25.1.1.
- **OQ-2:** статус канала в `vpn monitor` — только unit/iface или ещё проба
  204 через tun (медленно)?
- **OQ-3:** `vpn scheme reset` должен ли снимать dnsmasq/DoH, если xsplit был
  единственной схемой (сейчас `vpn reset` уже гасит DoH).

## Следующий шаг

→ `vds-coder`: WP-1 → WP-2 → WP-3 → WP-4, отдельные коммиты; после WP-2 —
  ручная проверка tun на ноутбуке (до интеграции в vpnm). Приёмка — тестер
  по §6, отчёт `TEST-20261114-xhttp-split.md`.


## 12. Результат приёмки (stage 1)

Отчёт: [TEST-20261114-xhttp-split](../reports/TEST-20261114-xhttp-split.md).

- tun/unit/addr/rules/kill-switch — PASS (после ревью-фиксов `d8ff5a4`);
- vpnm — 379 unit-тестов, mutual exclusion/статус исправлены;
- **блокер:** xray 26.1.23-клиент ↔ 25.1.1-сервер XHTTP = 400; 26↔26 = 200,
  end-to-end через tun с временным 26-сервером = 200;
- разблокировка: A) обновить серверный Xray (ADR), B) второй 26-инбаунд на
  8445 только для xsplit, C) xsplit поверх Reality. Рекомендация — B.
