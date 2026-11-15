# SPEC-20261116-ufw-hardening

## Мета

- **Источник:** выжимка владельца от 2026-11-16 (передана оркестратором);
  [SERVER-BASELINE.md §5/§10](../../SERVER-BASELINE.md); [ADR-008](../../adr/ADR-008-hysteria2-port-hopping-firewall.md);
  [ADR-007](../../adr/ADR-007-ru-relay.md); [SPEC-20261114-ru-relay](SPEC-20261114-ru-relay.md);
  [TEAM.md §9](../../TEAM.md) («политика портов/UFW — только через REQ→SPEC→ADR»).
- **Автор:** vds-architect
- **Дата:** 2026-11-16
- **Статус:** draft (G2 — решения владельца по OQ-1/OQ-2 получены 2026-11-16,
  внесены; открыты OQ-3/OQ-4 — не блокируют G2)
- **ADR:** ADR-011-ufw-hardening (создаётся WP-1)

## 1. Цель и решение

Централизованный, идемпотентный, dry-run-first харднинг UFW для VPN-серверов
проекта: одна команда `vds system ufw harden` с тремя профилями (`gateway`,
`relay`, `exit-cascade`), которая дотягивает состояние до целевого, детектирует
уже существующие правила (relay init / amneziawg install / hysteria2 hop уже
трогают ufw) и никогда не делает `ufw reset`.

**Ключевые решения:**

1. **Форма — отдельный модуль `src/system/ufw.py`**, команда
   `vds system ufw harden [--profile …]`, НЕ встраиваемся в `gateway init` /
   `relay init` (принятые циклы не ломаем; их ufw-шаги остаются как есть).
   В relay/gateway-доки (README, DEPLOY, SERVER-BASELINE) добавляется строка-
   ссылка «далее — `sudo vds system ufw harden --profile …`». Исторические
   SPEC-файлы (SPEC-20261114-*) не редактируются — это принятые артефакты.
2. **Профили** (см. §3): правила выводятся из `state.protocols` gateway store
   (какие транспорты реально установлены), а не из жёсткого списка —
   harden открывает только то, что слушается/установлено.
3. **Детекция существующих правил:** парсер `ufw status` (text-вывод,
   разбор строк `ALLOW`, `LIMIT`, `Anywhere`) + `ufw status verbose` для
   default-policy. Правила, уже добавленные relay init (`allow 443/udp`),
   amneziawg install (`allow 51825/udp` + before.rules MASQUERADE),
   add-hop-ports (`allow 20000:20500/udp`) распознаются и НЕ дублируются
   (`ufw add` на существующее правило возвращает неуспех — считаем идемпотентным
   успехом при совпадении строки, отличаем «rule added» vs «Skipping adding»).
4. **Совместимость с probe-watch** (nft `inet vds_probe`, hook priority −140):
   ufw (iptables-nft) работает в своих стандартных цепочках INPUT/FORWARD/
   OUTPUT с базовыми приоритетами; таблица `vds_probe` — независимая, свои
   счётчики в prerouting до ufw-фильтрации — это наблюдение, не фильтрация.
   Взаимно перетереть не могут (разные таблицы nft). Требование к кодеру:
   harden не трогает `inet vds_probe` и не выполняет `nft flush` чего-либо,
   кроме ничего (ufw сам управляет своими цепочками). Падение/включение ufw
   счётчики не затрагивает. Зафиксировано как «правило знаний» в ADR-011.
5. **Docker обходит UFW** (nat PREROUTING/DOCKER раньше ufw-before-input) —
   фиксируется как правило знаний; в v1 Docker на проекте только ZTNET
   (выключен). Проверка: план (dry-run) сравнивает `ss -tlnp` / `ss -ulnp`
   слушающих портов против ожидаемого набора профиля и печатает
   [warning] «порты вне UFW-правил» (включая docker-proxy). Отдельный
   doctor/sysinfo-WP — вне скоупа (см. OQ-3).
6. **ICMP — НЕ трогаем вовсе** (решение владельца 2026-11-16: drop
   echo-request НЕ реализуем, опция удалена из спеки). Полное обоснование —
   «Правило знаний: ICMP и диагностика маршрута» — включается **verbatim**
   в SERVER-BASELINE §5 (обязательный контент WP-4, заполняется при приёмке).
   Кратко: (а) ТСПУ находит серверы пассивным DPI исходящего трафика, не
   пингом; (б) echo-request — главный диагностический инструмент (маршрут
   жив vs порт режется: ping, ping.pe, check-host.net); (в) Reality-сервер,
   отдающий TLS-сертификат на 443, но молча дропающий ICMP, — аномалия для
   эвристик. destination-unreachable / time-exceeded / parameter-problem /
   icmp type 3 code 4 (fragmentation-needed, PMTU) — никогда не блокировать.
7. **SSH-порт (решение владельца 2026-11-16: реализуем в v1).** Команда
   `vds system ufw ssh-port --to 49222` — НЕ перенос по умолчанию, перенос
   только явным флагом; вся механика в v1. Двухфазная (CLI не имеет права
   закрыть 22 в той же операции, что перенос — нужен живой второй терминал
   владельца):
   - **Фаза A (`ssh-port --to N --apply`):**
     1) `ufw limit N/tcp` ДО переноса; подтверждение по `ufw status`
        (строка `LIMIT IN` / `N/tcp ALLOW IN` для limit);
     2) `/etc/ssh/sshd_config.d/99-vds-port.conf` → `Port N`
        (атомарно 0600, idempotent, бэкап) + `sshd -t` → пусто иначе abort;
     3) Ubuntu 24.04 socket-activation: если `systemctl is-active ssh.socket`
        → drop-in `/etc/systemd/system/ssh.socket.d/99-port.conf`
        (`[Socket]\nListenStream=` (пустая — сброс дефолта 22)\n`ListenStream=N`)
        + `daemon-reload` + `restart ssh.socket`; иначе `restart ssh`;
     4) проверка `ss -tlnp | grep N` — слушается; else abort с откатом
        конфигов (из бэкапов);
     5) маркер в state: `state.protocols["ufw-ssh-port"] = {"pending": True,
        "port": N, "legacy_22_still_open": True, "ts": …}` + печать инструкции:
        «Проверьте вход по порту N со ВТОРОГО терминала, затем выполните
        `sudo vds system ufw ssh-port --finalize`.» — команда останавливается.
   - **Фаза B (`ssh-port --finalize`):** root + проверка слушания N +
     удаление правил 22 (`ufw delete limit 22/tcp`, `ufw delete allow 22/tcp`
     — с [skip], если нет) + `ufw delete allow 22` (легаси server-setup
     вариант) + маркер → `{"pending": False, "legacy_22_still_open": False}`;
     если порт N НЕ слушается — отказ с сохранением 22.
   - Профильные правила ssh после finalize: `limit N/tcp` (§3).
   - `ssh-port` доступен без профиля (для asv1-прод с любой профилем);
     под FileLock; идиомы dry-run те же (`--apply` опционален).
8. **Персистентность/ребут:** `ufw enable` персистентен сам. Наши юниты
   совместимы: `vds-amneziawg-nat` — идемпотентный oneshot (`-C || -A`), не
   зависит от ufw (шаблон это документирует); MASQUERADE-пersist для
   awg0 уже живёт в `/etc/ufw/before.rules` (amneziawg install), ufw
   перечитывает before.rules на enable/reload — дубля нет, дублировать
   before.rules-подход harden НЕ должен. `vds-probe-watch` ExecStartPre
   применяет свой nft-файл независимо. Полевое наблюдение о сосуществовании
   ufw + наши юниты: релей (relay init делает ufw allow 443/udp на живом
   сервере) — подтверждает coexistence; **но** факт «asv1 = ufw active» в
   постановке НЕ подтверждён SERVER-BASELINE (снимок 2026-11-14: UFW
   **inactive**) — регресс-проверка на asv1 является частью приёмки, а не
   предпосылкой (см. §7 поле-план и OQ-4).
9. **Откат:** `vds system ufw harden --undo` — снимает ровно то, что harden
   добавил (журнал применённых правил хранится в state: `state.protocols
   ["ufw"] = {profile, applied_rules, before_rules_backup, ts}`); если UFW
   был inactive до harden — `--undo` возвращает inactive (`ufw disable`).
   Ручной чеклист отката дублируется в SERVER-BASELINE §5 (стиль
   DEPLOY-RU-RELAY).
10. **Fail-safe порядок операций (обязательно).** SSH-правило — `limit` на
    **итоговом** порту (22, либо N если `ssh-port --finalize` выполнен —
    читается из state):
    1) root-чек + port-чек + парс текущего ufw-состояния;
    2) `ufw default deny incoming` / `allow outgoing` — пишутся, но ДО enable
       не активны;
    3) `ufw limit <ssh-port>/tcp` — **ssh-правило всегда первым из
       allow-набора**; при pending-переносе (`ssh-port` Фаза A не
       финализирована) — limit на ОБА порта (N + 22 до finalize);
   4) сервисные порты профиля (по state, с listeners-сверкой);
   5) forwarding: `DEFAULT_FORWARD_POLICY=ACCEPT` в `/etc/default/ufw`
      (sed-guard) — только профилям gateway/relay/exit-cascade;
      `ip_forward` НЕ пишем (уже persist в sysctl.d от amneziawg/relay —
      проверяем grep'ом и ругаемся, если 0);
   6) `ufw --force enable` — **строго последним**, только после подтверждения
      (парс вывода), что ssh-правило присутствует в наборе добавленных
      правил; если enable не удался — печатать откат-подсказку.

## 2. Архитектура

```
src/system/ufw.py            # план-билдер + apply/undo + ssh-port (FileLock, run_list)
src/main.py                  # регистрация `system ufw` (ленивый импорт)
tests/system/test_ufw.py     # unit: парсер, планы профилей, порядок шагов, ssh-port-фазы

CLI:
  vds system ufw harden --profile gateway|relay|exit-cascade
        [--allow-from IP] [--apply] [--undo] [--json]
  vds system ufw ssh-port --to 49222 [--apply]
  vds system ufw ssh-port --finalize [--apply]
```

Поток: preflight (root при --apply, ufw установлен, парс status) →
сборка плана (profile + state.protocols + listeners + текущие ufw-правила)
→ печать плана с diff-тегами `[add] [skip] [warn]` → `--apply`: FileLock →
шаги в порядке §1.9 → запись meta в state → `--undo`: реверс по meta.

## 3. Профили

| Профиль | default | ssh | Правила | Forwarding | Источник портов |
|---|---|---|---|---|---|
| **gateway** | deny in / allow out | `limit <итоговый порт>/tcp` (22; 49222 после `ssh-port --finalize`; при pending — оба) | 443/tcp (xray), 443/udp (hy2), 51825/udp (awg), 51826/udp (obfs), 8443/tcp (xhttp), 2053/tcp (cdn), 80/tcp (acme), hop-диапазон udp | FORWARD=ACCEPT, ip_forward-проверка | `state.protocols` (installed=true), hop — `hop_ports` |
| **relay** | deny in / allow out | `limit <итоговый порт>/tcp` | 443/tcp+443/udp — обычно уже открыты relay init: детекция, `[skip]` при наличии; ssh-лимит | FORWARD=ACCEPT | state.protocols["relay"] |
| **exit-cascade** | как gateway | `limit <итоговый порт>/tcp` | сервисные порты как gateway, **кроме 443**: `ufw allow from <relay-ip> to any port 443 proto tcp` + `… proto udp` (по установленным 443-транспортам); требует `--allow-from` | FORWARD=ACCEPT | state.protocols + `--allow-from` |

Правила панелей/метрик наружу НЕ открываются нигде (ZTNET 9993, dashboard —
только ssh-туннель; фиксируется как правило знаний в ADR-011).

## 4. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/system/ufw.py` | создать | plan-builder (чистые функции) + apply/undo + ssh-port двухфазный + preflight; сигнатуры ниже |
| `src/main.py` | изменить | подкоманда `system ufw harden` (ленивый импорт) |
| `tests/system/test_ufw.py` | создать | unit-тесты (без root/сети) |
| `docs/SERVER-BASELINE.md` | изменить | §5 переписан: «UFW hardening — vds system ufw harden», матрица портов по профилям, чеклист отката + verbatim «Правило знаний: ICMP и диагностика маршрута» от владельца (текст у оркестратора) + правило двухфазного ssh-переноса |
| `README.md`, `AGENTS.md` | изменить | строка о команде (структура/команды) |
| `docs/DEPLOY-RU-RELAY.md` | изменить | строка-ссылка «финальный шаг: ufw harden --profile relay» |
| `docs/adr/ADR-011-ufw-hardening.md` | создать | решения §1.1–§1.9 |

**Не трогаем:** `src/gateway/init.py`, `src/relay/init.py`, `src/amneziawg/*`
(их ufw-шаги остаются), `src/system/setup.py` (легаси-шаг 7 остаётся, но в
README помечаем: для нового харде­нинг использовать harden, не server-setup;
полный вывод setup.py из эксплуатации — отдельный REQ), systemd-шаблоны,
`topology.json`, схему секретов, UFW-политику дефолтов кроме описанной,
`ufw reset` — запрещён в новом коде.

**Публичные интерфейсы** (`src/system/ufw.py`, чистые — тестируются без root):

```python
def parse_ufw_status(text: str) -> UfwSnapshot  # rules + default-policy
def build_plan(profile: Profile, state: GatewayState,
               snapshot: UfwSnapshot, opts: HardeningOpts) -> list[PlanItem]
                                               # PlanItem: rule|config, action add/skip/warn, detail
def order_steps(plan: list[PlanItem]) -> list[PlanItem]  # ssh-первым, enable-последним
def diff_listeners(profile_ports: set[str], ss_lines: list[str]) -> list[str]  # warn-строки
def run_harden(profile, apply=False, undo=False, opts) -> int
def run_undo(state_path=None) -> int
def run_ssh_port(to: int | None, finalize: bool, apply: bool, state_path=None) -> int
    # Фаза A: ufw limit N + sshd_config.d/99-vds-port.conf + sshd -t +
    #          ssh.socket drop-in (или restart ssh) + ss-чек + pending-маркер;
    #          финализация запрещена в этой же операции.
    # Фаза B (--finalize): ss-чек N → ufw delete 22-правила → маркер pending=False.
def ssh_socket_active() -> bool  # systemctl is-active ssh.socket (Ubuntu 24.04)
def render_socket_dropin(port: int) -> str      # ListenStream= сброс + ListenStream=N
def render_sshd_port_conf(port: int) -> str
```

`state.protocols["ufw"]` (meta, без секретов):
`{"installed": True, "profile": "gateway", "ssh_port": 22,
"applied_rules": ["limit 22/tcp", "allow 443/tcp", …],
"before_rules_backup": "<path>|null", "ts": "2026-11-16T…"}`.

`state.protocols["ufw-ssh-port"]`:
`{"pending": True|False, "port": 49222, "legacy_22_still_open": True|False,
"sshd_conf_backup": "<path>", "socket_dropin": "<path>|null", "ts": …}`.
Пока `pending=True` — harden/статусная команда печатает [warning]
«перенос начат, порт 22 ещё открыт — выполните `ssh-port --finalize`
после проверки входа на N».

## 5. Миграция и совместимость

- asv2 (новый сервер): UFW inactive — идеальный стенд, план = всё `[add]`.
- asv1 / релей (прод): harden детектирует существующие правила и добавляет
  только недостающее; повторный запуск — дотягивает (идемпотентность —
  обязательный тест-кейс: двойной прогон, второй = все `[skip]`).
- Конфликтных зон нет: harden не переписывает before.rules MASQUERADE-секцию,
  не трогает nft-таблицы проекта, не рестартит юниты (кроме ssh.service/
  ssh.socket при явном `ssh-port --apply`).
- `server-setup` (легаси) с его `ufw --force reset` не запускается этим
  циклом; совместимость двух путей — вне скоупа.

## 6. Тест-план

| Уровень | Что | Где |
|---|---|---|
| Unit | `parse_ufw_status` (пустой вывод, verbose-строки, LIMIT, from-правила), планы 3 профилей по фикстурному state (без секретов; RESERVED-фикстуры только `FIXTURE_*`/203.0.113.0/24), порядок шагов: ssh-правило индекс < enable-индекс всегда, exit-cascade без --allow-from → ошибка, 443→from-правила, hop-диапазон, идемпотентность (второй план — 0 add), diff_listeners, undo-реверс по meta, ssh-port: рендеры (sshd conf, socket drop-in с пустым ListenStream=), pending-маркер, finalize удаляет 22 и не удаляет N, abort при `sshd -t` непустом / порт N не слушается, запрет «перенос+удаление 22 в одной операции» | `tests/system/test_ufw.py` |
| CLI | `vds system ufw harden --help`, `ssh-port --help`; dry-run exit 0 без мутаций (мок-окружение tmp) | ручная/CI |
| Поле asv2 | чеклист §7 | TEST-REPORT |
| Поле asv1/релей | регресс: harden не меняет работающие правила; `ufw status` diff до/после = только ожидаемое | TEST-REPORT |

**Критерии приёмки (из выжимки владельца):** `ufw status verbose` →
deny incoming / allow outgoing (+ allow routed при forwarding-профилях);
`grep DEFAULT_FORWARD_POLICY /etc/default/ufw` = ACCEPT;
`sysctl net.ipv4.ip_forward` = 1; ping-тест (echo-request проходит — ICMP
не трогаем, решение владельца); набор открытых портов = матрице
установленных сервисов; ssh-доступ сохранён после enable и после
ssh-переноса (обязательная проверка со второго терминала — в ранбуке).

## 7. Полевая приёмка (asv2 — чистый сервер)

1. `sudo vds system ufw harden --profile gateway` (dry-run) → план без мутаций,
   docker/listeners-предупреждения.
2. `sudo vds system ufw harden --profile gateway --apply` → ssh-сессия жива;
   `ufw status verbose` = целевое.
3. Повторный `--apply` → «все шаги уже применены» / только [skip].
4. Реальный клиент: Reality 443/tcp, Hy2 443/udp, AWG 51825/udp — работают;
   панель-порт (9993) снаружи закрыт.
5. `vds system ufw ssh-port --to 49222 --apply` → правила 22 живы, 49222
   слушается и открыт (`ufw status`, `ss -tlnp`); вход по 49222 проверяется
   владельцем со **второго терминала**; затем `ssh-port --finalize` →
   правило 22 удалено, вход на 22 невозможен, на 49222 работает. Отказ
   (нет входа на 49222): 22 остаётся открытым — восстановление sshd-конфига
   из бэкапов руками по ранбуку.
6. `--undo` → состояние до harden (ufw inactive на asv2-стенде).
7. Регресс asv1/релей: шаг 1 (dry-run) + один --apply; diff правил = пусто/ожидаемо;
   сервисы живы (`vds gateway status`).

## 8. Work packages

| WP | Задача | Файлы | Зависит | DoD |
|---|---|---|---|---|
| **WP-1** | ADR-011 (решения §1) + этот SPEC | `docs/adr/ADR-011-ufw-hardening.md` | — | ADR принят архитектором; SPEC согласован |
| **WP-2** | Модуль `src/system/ufw.py`: парсер, plan-билдеры 3 профилей, order_steps, listeners-diff, apply/undo-движок (FileLock, run_list, fail-safe порядок §1.10) | `src/system/ufw.py` | WP-1 | compileall; чистые функции импортируются без root; dry-run не мутирует |
| **WP-2b** | SSH-перенос: `run_ssh_port` (Фаза A/B), рендеры sshd_config.d/ssh.socket drop-in, pending-маркер + warn-интеграция в план harden, инструкция-остановка Фазы A | `src/system/ufw.py` | WP-2 | sshd-t/ss-чек-аборты покрыты; Фаза A не удаляет 22 — unit-кейс |
| **WP-3** | CLI + unit-тесты | `src/main.py`, `tests/system/test_ufw.py` | WP-2, WP-2b | `pytest -q` зелёный; `--help` полные; двойной apply — идемпотентен (unit-кейс) |
| **WP-4** | Документация: SERVER-BASELINE §5 — матрица портов по профилям, чеклист отката и **обязательный verbatim-контент от владельца**: «Правило знаний: ICMP и диагностика маршрута (решено 2026-11-16)» (полный текст выдан оркестратором — в §1.6 SRC, включить без сокращений) + смежное правило о двухфазном SSH-переносе 22→49222; строка-ссылка «далее — `vds system ufw harden --profile …`» в relay-ранбук/README/AGENTS | `docs/SERVER-BASELINE.md`, `README.md`, `AGENTS.md`, `docs/DEPLOY-RU-RELAY.md` | WP-2, WP-2b | команды ↔ код 1:1; правило знаний в тексте verbatim; чеклист отката; строка-ссылка в relay-ранбуке |
| **WP-5** | Полевая приёмка asv2 + регресс asv1/релей | (только TEST-REPORT, код не трогается) | WP-3, WP-4 | AC §6 подтверждены verbatim-выводом; OQ-1/OQ-2 закрыты решением владельца |

Пересечений файлов между WP-2/2b/3/4 нет; WP-2 → WP-2b → WP-3 последовательно
(main.py импортирует модуль WP-2/2b).

## 9. Риски

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| enable до ssh-правила → отрезались по ssh | критично | потеря доступа | порядок §1.10 + unit-тест на индекс enable; ранбук: держать открытой вторую ssh-сессию |
| ssh-перенос: вход на новый порт не проверен → закрыли 22 | критично | потеря доступа | двухфазность §1.7: CLI не удаляет 22 в Фазе A; finalize только по явной команде после проверки владельцем |
| ssh.socket (24.04) vs ssh.service — двойной источник Port | средняя | перенос не вступает в силу | §1.7 шаг 3: is-active ветвление + drop-in с пустым ListenStream=; ss-чек после restart обязательный |
| парсер ufw-status ломается на другой локали/версии | средняя | ложные skip/add | `LC_ALL=C` в run_list; парсер на текст + fallback-предупреждение при нераспознанной строке |
| hop-диапазон (500 портов) в UFW-статусе — парсинг | низкая | — | правило `20000:20500/udp` — один вывод строки |
| `--undo` после ручных правок ufw | низкая | снимает лишнее | undo снимает только строки из `applied_rules`; перед --apply в dry-run печатать, что попадёт в meta |
| server-setup (легаси reset) выполнен после harden | средняя | правила стёрты | README: harden идемпотентно дотягивает — просто повторить |
| sshd restart на живой сессии при Фазе A | низкая | текущая сессия не рвётся (sshd не убивает соединения), но проверить | ранбук: делать из активной сессии на 22; проверка входа на N до finalize |

## 10. Границы

- **Трогаем:** файлы §4.
- **Не трогаем:** gateway/relay init, amneziawg/hysteria2/xray, zerotier,
  systemd-шаблоны, ACME, CI, `src/system/setup.py`.
- **Вне скоупа:** doctor/sysinfo-интеграция Docker-проверки (OQ-3),
  fail2ban, провайдерский файрвол (панель хостера — вручную, SERVER-BASELINE §6).

## 11. Трассируемость

| Требование владельца | WP | Тест |
|---|---|---|
| deny/allow + ssh limit + порты сервисов | WP-2/3 | unit-планы + поле §7.2 |
| Каскад: 443 только from relay | WP-2 | unit exit-cascade + поле |
| FORWARD/forwarding, без дубля MASQUERADE | WP-2 | unit + grep-приёмка |
| Docker-правило знаний + проверка в плане | WP-2 | diff_listeners + поле §7.1 |
| SSH-перенос 22→49222 двухфазный (решение владельца) | WP-2b | unit-фазы + поле §7.5 |
| Порядок enable/ssh fail-safe | WP-2 | unit order_steps + ранбук |
| Проверки-приёмки AC | WP-5 | TEST-REPORT |
| Откат | WP-2/4 | unit undo + SERVER-BASELINE §5 |

## 12. Открытые вопросы (владельцу)

- ~~OQ-1 (ssh-порт)~~ — закрыто 2026-11-16: механика в v1, перенос только
  явным `ssh-port --to 49222`, двухфазный с ручным finalize.
- ~~OQ-2 (icmp-drop)~~ — закрыто 2026-11-16: НЕ реализуем, обоснование в §1.6.
- **OQ-3:** docker/listeners-проверка в doctor/sysinfo — отдельный WP после
  приёмки или оставить только warn в плане? (Не блокирует G2.)
- **OQ-4:** расхождение постановки с SERVER-BASELINE: «asv1 — ufw active,
  сосуществование подтверждено» vs снимок 2026-11-14 «UFW inactive».
  Регресс-проверка на asv1 включена в WP-5 независимо; уточните фактическое
  состояние перед приёмкой. (Не блокирует G2.)
