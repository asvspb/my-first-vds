# STATUS — живое состояние работ

> Обновляет оркестратор после каждого гейта. Единый источник правды о текущем цикле.
> Шаблон: [templates/STATUS.md](templates/STATUS.md).
> Счётчики тестов в исторических записях — моментальные снимки (OQ-9):
> актуальный baseline — `pytest -q`, число в живых доках не хранится.

## 2026-11-22: roadmap-цикл архлида (порядок A2→guard v1.1→C→B) + pre-flights

- **Промпт/вердикт:** [PROMPT-20261122-cycle-order-gemini-architect](reports/PROMPT-20261122-cycle-order-gemini-architect.md)
  → ORDER-DECISION архлида (A2 → guard v1.1 → C → B; 1 окно = 1 контур) +
  REVIEW WP-A1 (APPROVE с правками, все приняты).
- **WP-A0 (read-only, asv2):** `8443/tcp` занят **живым XHTTP-инбаундом xray**
  (path `/62985630…`, mode auto) — конфликт с wstunnel отсутствует; дельта И43
  = ровно 2 клиентских поля; `xray run -test` v26.1.23 с xmux+scMax* → OK.
  A2 — **без рестарта asv2** (ревью P1): только клиентский деплой vpnm +
  T-XM6 + окно probe/silence против живого asv2:8443.
- **WP-A1 ЗАПУШЕН:** ubuntuInstaller `fab43fb` (`XHTTP_SC`: scMaxEachPostBytes
  `800000-1200000`, scMinPostsIntervalMs `100-300` — соседи xmux) + vds
  `be73326` (SPEC §6). 🪤 **`origin` у meta-клона ubuntuMastering/ubuntuInstaller
  — локальный путь; GitHub-remote только в каноническом клоне
  `/home/asv-spb/Dev/ubuntuInstaller`** — первый пуш fab43fb ушёл в локальное
  зеркало, на GitHub доставлен из канонического клона (P0 ревью).
- **WP-B0 (compat-gate):** вердикт **ADR-005-AMENDMENT-REQUIRED** — сборки
  «AWG 1.5» в PPA нет; I1–I5 в kernel с дерева 2.0 (`ac946a9`); конфиги 3.1
  несовместимы со старыми клиентами (AmneziaVPN ≥5.0.1.5 = AWG 3.1);
  `amneziawg-go 1.5` — только беты; Rc1–Rc3 не подтвердились.
- **WP-B5 (ключевой факт):** **asv2, релей и ноутбук уже на kmod
  `3.1.20261113-02` / tools `v3.1.20260812`** (dpkg-строки «1.0.0» —
  упаковочные артефакты) → канарейка бинаря (WP-B2.1 вердикта) вычеркнута;
  B = конфиг-дельта I1–I5 в клиентские .conf + перевыпуск. maneuver.timer
  **не выключается** на окнах A2/C (ревью P1) — пауза только при реальном
  рестарте awg1/awg2 в B.
- **Скоуп B (ADR-005-lite, зафиксирован ревью):** только опциональные I1–I5
  (по умолчанию выкл), без S3/S4/диапазонных H/HeaderProtectionKey; после
  включения — 1 ночной тик C + 0 FP G-13 с CPS.
- **Открытые вопросы владельцу:** версии AmneziaVPN на телефонах (≥5.0.1.5?);
  G6-close 24.11 15:24 MSK + деплой клиентского бандла (D1/D3/D6 + D-17).
- **Порядок (финал):** G6-close → A2 (client-only) → guard v1.1 → C →
  B (ADR-005-lite). Соответствует условию смены порядка Риска №1
  ORDER-DECISION (B0 = amendment ⇒ C легально идёт после guard v1.1).

## 2026-11-20/21: оценка живучести + эшелоны до потолка (ревью архитектора)

- **Отчёт:** [REVIEW-20261120-resilience-roadmap](reports/REVIEW-20261120-resilience-roadmap.md)
  — зафиксирована оценка: закрыт SPOF «один UDP-транспорт» на магистрали
  relay↔exit (ADR-016, WP-P2P-1…6, живой цикл PASS); прогресс до практического
  потолка ~60–65%.
- **Эшелоны:** (1) утро 21.11 — P24 + деплой P28 → серверный контур 85–90%;
  (2) 24.11 G6 close → guard v1.1 (netlink + детекция «тихого удушения»);
  (3) v1.2 — мост client-findings ↔ server-verdict + политика эшелонов (Q7);
  (4) v2.0 Smart Failover + резерв IP/ASN после ≥30 дней поля.
- Ограничитель — полевые окна, не разработка: 21.11 P24 → 24.11 G6 →
  ≥30 дней статистики до клиентского авто-переключения.

## 2026-11-20: все 8 вопросов §6 vpn guard закрыты (Q1…Q8)

| # | Решение | Где |
|---|---|---|
| Q1 | контракт `schema_hash` между репо (клиент — источник правды) | D-17, `docs/contracts/guard-schema-hashes.json` |
| Q2 | v1.1 — каркас SPEC (S4 netlink, G-13, G-14, `server:`, D4) | [SPEC-v1.1](specs/SPEC-20261120-vpn-guard-v1.1.md) |
| Q3 | мост v1.2 `export → vds logs analyze --client-report` | **D-22** |
| Q4 | v2.0 Smart Failover: 4 критерия входа, границы, fail-safe | **D-24** |
| Q5 | P24/P25 — нога и манёвр (закрыты ранее) | ACCEPT P24/P25 |
| Q6 | CDN `:2053` — холодный резерв | ADR-006 §Дополнение, `f5794ce` |
| Q7 | политика эшелонов: две оси, источник `vpnm/scout/rank.py`; формат `server:` | **D-23** (закрывает OQ-V11-3) |
| Q8 | docsync `warn → block` | `d3c3840` |

**P1-поправка к `f5794ce` (факт кода):** `add_cdn()` уже берёт `ws_path` через
`gen_secret_path()` (`src/xray/cdn.py:857`), UFW уже строится по
`CLOUDFLARE_CIDRS_V4` (15 подсетей) через `cf_cidr_specs()`
(`src/system/ufw.py:57,119-130`) — прекондишн (2) переформулирован как
**проверка на живом хосте**, а не «закрыть». README: разорванный комментарий
склеен.

## 2026-11-20: WP-Q2-SPEC — каркас SPEC vpn guard v1.1 (draft)

- **Документ:** [SPEC-20261120-vpn-guard-v1.1](specs/SPEC-20261120-vpn-guard-v1.1.md)
  — статус **draft**; G2 и любой код v1.1 — строго после закрытия окна WP-G6
  (2026-11-24 15:24 MSK) и деплоя D1/D3/D6.
- **Состав:** S4 netlink (`netlink=false`), G-13 AWG packet-size ratio
  (вкл. по умолчанию, пороги — плейсхолдеры до калибровки по 7-дневному дампу),
  G-14 read-only `ss -tnip` по своим PID xray (`ss_tcp=false`), строка `server:`
  в человекочитаемом `status`, D4.
- **Инварианты:** 100 % read-only, 0 авто-действий, 0 сетевых сокетов
  (`NETLINK_SOCK_DIAG` — локальная интроспекция, только при opt-in), 0 sudo,
  0 секретов, схемы аддитивны, G-01…G-12 не трогаются, privacy G-14.
- **Вне v1.1:** ленивый sync (ждёт 5-мин сэмплер), мост `--client-report`
  (v1.2/Q3), Smart Failover (v2.0/Q4).
- **TECHDEBT:** заведён **P27** под D4 (`file_parse_error` TTL + атрибуция файла);
  коллизий номеров нет (P21–P26 заняты).

## 2026-11-20: DECISION Q6 — CDN-канал переведён в «холодный резерв»

- **Решение владельца:** код CDN (`src/xray/cdn.py`, обвязка `gateway/`, клиентские
  `vpnm/channels.py`, `guard/rules.py`) **не удаляется и не поднимается** на asv2;
  канал — dormant capability. Роль выживания при L3-блоке IP exit закрыта лучше
  (Reality+Hy2+AWG на asv2 + RU-relay с ногой `awg2`, P24/P25), потолок CF доказан
  полем (2026-11-13).
- **Уже закрыто кодом (surface-hardening §2.2):** `add_cdn()` берёт `ws_path`
  через `gen_secret_path()` (`src/xray/cdn.py:857`), `/cdnws` — legacy-дефолт
  старых профилей; UFW строится по `CLOUDFLARE_CIDRS_V4` (15 подсетей) через
  `cf_cidr_specs()` (`src/system/ufw.py:57,119-130`). Остаются риски: нет fallback
  у origin, LE на апексе сцепляет домен с IP, anti-DDoS хостера к AS13335.
- **Прекондишны реактивации:** (1) отказ связки «asv2 + RU-relay» либо CDN с PoP в
  РФ; (2) **проверить на живом хосте** (не «закрыть»): `ws_path != "/cdnws"`,
  `2053/tcp` покрыт `CLOUDFLARE_CIDRS_V4`, домен не сцеплен с SNI, нет fallback,
  anti-DDoS пропускает AS13335.
- **Доки:** ADR-006 §Дополнение 2026-11-20, CDN-FRONTS (статус-блок), ROADMAP
  (матрица §2.1, таблица транспортов, раскладка портов), GROWTH-POINTS GR-08 →
  «заморожен (P3)», SERVER-BASELINE (§5.2, §5.12, §6); старый буллит WP-5 в цикле
  doc-sync снят.
- **Код не менялся.** `vds gateway status`/UFW на asv2 — без `:2053`.

## 2026-11-20: DECISION Q8 + WP-Q1a — docsync `block` и контракт schema_hash
### WP-Q8 — docsync `warn` → `block` ✅

- **Решение владельца:** перевести `mode` в `docs/doc-sync.json` в `block`
  досрочно (не ждать 2026-11-30): критерий «один цикл `warn`» выполнен по существу
  (alert-watch, vpn-guard, P24/P25 — 12+ коммитов).
- **Pre-flight:** `docsync audit --strict` = OK; `core.hooksPath=.githooks`;
  `docsync debt` — после фикса метрики ровно **1** запись (TECHDEBT P26,
  зарегистрирован; его критерий закрытия — «формат признан внутренним»).
- **Фикс метрики:** `cmd_debt` теперь считает только обходы, реально пропустившие
  обязательные доки (docs-only коммиты с трейлером давали 6 фантомов из 7);
  тест `test_debt_ignores_docs_only_trailer`.
- **Контроль:** staged-правка `src/main.py` без доков → exit 1; с валидным
  `Docs: none — … (TECHDEBT P26)` → exit 0.
- **Откат:** `"mode": "warn"` коммитом либо `git config --unset core.hooksPath`.

### WP-Q1a — контракт `schema_hash` между репо (D-17) ✅

- **D-17 зафиксирован** (DECISION Q1): источник правды — клиентский lock
  `vpnm/guard/schemas/schema_hashes.json`; сервер вендорит только хэши.
- **Сервер:** `docs/contracts/guard-schema-hashes.json` (7 контрактов,
  `source_commit` `1e54011`) + `tests/gateway/test_guard_verdict_contract.py`
  (структура lock, поля `probe-watch watch --json`, сверка с клиентом при
  `VPN_MANAGER_REPO`, без сети). Негативный контроль: подмена хэша → тест падает
  с явным diff `только_клиент`/`только_сервер`.
- **D-16…D-21** записаны в `DECISIONS-vpn-guard.md` (реестровая дыра BRIEF §13
  закрыта); RSK-7 в SPEC переведён в «закрыт контрактом», добавлен §9.0.0.
- **Осталось (WP-Q1b, ubuntuInstaller):** ✅ **сделано 2026-11-20** — клиентский
  lock `vpnm/guard/schemas/schema_hashes.json` + тесты lock-файла в
  `tests/guard/test_guard_contract.py`, коммит `fa62312` (запушен).
  Негативный контроль: правка `guard.status/1` без обновления lock → AssertionError
  с парой хэшей; чистый wheel содержит 7 схем + lock. **Установка pipx/рестарт
  демона на ноутбуке — по-прежнему после 2026-11-24 15:24 MSK (окно G6).**
- **Клиентская гигиена (2026-11-20):** незакоммиченные `vpnm/cli.py` +
  `tests/test_cli_help_protocols.py` оформлены как `335ae8d` — в `vpn --help`
  блок «Протоколы, которые можно активировать», CDN помечен холодным резервом
  (Q6). Только коммит: pipx/демон не трогались, дерево ubuntuInstaller чистое.

## 2026-11-20: WP-P2P-3 — P2-доводка (P0-1 run_switch, гигиена IP, P1×2)

- **P0-1:** `run_switch(to=awg, apply=True)` падал с NameError
  (`_reset_p25_state` — старое имя) и сброс был **вне** lock. Теперь
  `reset_p25_state(None)` внутрь FileLock. Мок-тест: route replace awg1 +
  сброс серии (правильные поля) + dry-run без изменений.
- **P0-2:** реальный IP exit в интеграционных фикстурах (CONF_TEXT, дампы)
  заменён на RFC 5737 (198.51.100.10); grep по 213.108 в test_carriers — 0.
- **P1-2:** фолбэк пробы в `on_maneuver_rollback` унифицирован с остальными
  (`probe_fn or (lambda i, p: probe(i, p, run=run))`).
- **P2-1:** сбой `ip route` при автовыходе из exhausted → `hold` (не
  пробрасывается в maneuver).
- Уточнено (P1-1 из прошлого ревью): `save_state` tmp уже инициализирован;
  cleanup дополнительно защищён `if tmp:`.

## 2026-11-20: WP-P2P-6 — носитель №2 + селектор в бою (✅ ПРИНЯТ, WP-P2P-1…6 закрыты)

- **Отчёт:** [ACCEPT-20261120-p2p-carriers](reports/ACCEPT-20261120-p2p-carriers.md).
- **Полный живой цикл** (боевой блок пула `ct original proto-dst 51900-51911`,
  dead-man 600 с): 17:48:19 rollback P25 (пул мёртв) → **17:48:43 селектор
  переключил table 100 на wg-ws0** (24 с после rollback, pre-check ok) →
  13 мин клиентского трафика через носитель №2 (~1.4 МБ) → 18:01:19
  prefer_primary вернул awg1 (3 пробы + ≥600 с) + **сброс P25-серии** —
  ложного манёвра нет.
- **AC-таблица:** AC-1/S1 (скан тишина), AC-S2 (LE+SNI), AC-3/4, AC-2, AC-6,
  AC-S4, AC-S7 (drop 9443 15 с → reconnect, NRestarts=0), AC-S8 (bulk ~1.4 МБ
  при MTU 1240), AC-S9 (0 ложных relay_blocked, ALERT_RELAY_IFACE=awg2,wg-ws0).
- **P0 приёмки (закрыт на месте):** `write_env` без mkdir — на релее нет
  `/etc/vds`, env молча не записался; фикс + тест.
- **Итог:** класс «блок UDP-пула/протокола ноги» закрыт в бою; клиент не
  перенастраивался; exit не получал прав.

## 2026-11-20: WP-P2P-4 — deploy-hook LE + fallback_since (готово к ревью, `333d3e4`)

- **Deploy-hook** `/etc/letsencrypt/renewal-hooks/deploy/vds-wstunnel-reload.sh`
  (0755): case по `$RENEWED_DOMAINS` — продление `ws.<domain>` рестартирует
  только `vds-wstunnel-server.service`; hysteria (свой hook
  `vds-hysteria2-cert.sh`) и wstunnel не задевают друг друга. Ставится в
  `run_exit_install`.
- **P2 (dfe7f2c):** `exhausted_recovery_check` при автовыходе на wg-ws0
  выставляет `fallback_since` — иначе `min_age_ok` в fallback_tick остаётся
  False и prefer_primary никогда бы не вернул awg1. Плюс: сбой `ip route`
  при автовыходе → `hold`, не проброс.
- **Тесты:** фильтр домена, отказ IP, права 0755, fallback_since на
  wstun-восстановлении.

## 2026-11-20: WP-P2P-3 — P0×5/P1×4 фикс (ревизия, готово к ревью)

Ревью 769a7eb поймало 5 P0 (краши/потеря state на живом релее — тесты
пропустили, т.к. везде явно передавали probe и не гоняли живую связку
maneuver→carriers). Все закрыты + интеграционные мок-тесты:

- **P0-1:** параметр `probe` затенял модульную `probe()` → `probe_fn` во всех
  трёх точках; фолбэк `(probe_fn or probe)`. Тесты с `probe_fn=None` (только
  run-инъекция) на все три функции.
- **P0-2:** `run_step` fallback печатал `_carrier_result` вместо
  `carrier_result` — NameError.
- **P0-3:** rollback-хукам передавался ЧУЖОЙ state (maneuver-path в tick,
  gateway-state в `run_rollback`) — carriers перезаписал бы их. Теперь хук в
  tick без maneuver-path; из ручного `run_rollback` хук убран совсем (он
  выполняется при живом awg1 — селектор там только навредил бы).
- **P0-4:** `reset_p25_state` сбрасывал `st["consecutive_failures"]`, а серия
  живёт в `st["last_sample"]["consecutive_failures"]` (+ cooldown_until=None);
  тест заражает именно last_sample.
- **P0-5:** `exhausted_recovery_check` был мёртвым кодом — теперь
  `run_step`/`run_tick` (под локом) сначала `is_exhausted()` → автовыход
  (возврат на PRIMARY сбрасывает P25-серию), затем `is_fallback()`.
- **P1-1:** `_apply_switch` — лимит 3/час и сбой `ip route` сохраняют
  exhausted в state до raise; `fallback_tick` возврат обёрнут в try/except
  (maneuver ловит только ManeuverError/OSError).
- **P1-2:** `run_switch` сброс P25-серии перенесён внутрь FileLock.
- **P1-3:** `STATE_RECOVERING` выставляется при `recover_ok_streak ≥ 1`,
  сброс серии → `STATE_FALLBACK`.
- **P1-4:** `save_state` — `tmp=None` до try (UnboundLocalError при сбое
  mkstemp).
- **P2-1:** мусор в `__all__` почищен. **P2-2:** интеграционные мок-тесты
  `run_tick`/`run_step` без подмены probe — только общий `run_list`
  (awg1-пинг мёртв, wg-ws0 жив): rollback → переключение на wstunnel;
  fallback → ни одного `awg set`; exhausted + живой awg1 → recovery + сброс
  серии (P0-4-регресс).

## 2026-11-20: WP-P2P-3 — селектор носителей (готово к ревью, `769a7eb`)

- **`src/relay/carriers.py`:** state-машина `primary/fallback/recovering/exhausted`,
  state `/var/lib/vds/p2p-carriers.json` 0600 (aware-UTC, история ≤100), пробы
  `ping -I <iface> <peer>`, переключение = `ip route replace default dev … table 100`.
- **Хук P25:** оба rollback-ветки `tick()` и CLI `rollback` вызывают
  `on_maneuver_rollback()` (уже под локом P25 — анти-deadlock AC-7): pre-check
  `ping -I wg-ws0` → fallback, провал → exhausted (AC-S5, не переключаемся на
  мёртвый носитель).
- **P25 no-op в fallback (AC-S6):** `run_step`/`run_tick` при
  `active == wstunnel` вместо `tick()` выполняют `fallback_tick` — attempts не
  тратятся, `awg set` не вызывается.
- **prefer_primary (AC-6):** 3 пробы awg1 подряд + ≥600 с в fallback → возврат +
  **сброс P25-серии** (consecutive_failures=0, failed_ports=[], exhausted=False,
  healthy) — иначе старые 3/3 дали бы ложный манёвр.
- **Анти-джиттер:** `fallback → exhausted` по 3/3 провалам wg-ws0; автовыход при
  живом любом носителе; лимит 3 переключений/час.
- **Совместимость:** без `/etc/amnezia/wg-ws0.conf` всё no-op — существующие
  тесты maneuver не менялись, живой релей до выката WP-P2P-2 ведёт себя как раньше.
- **AC-S4:** policy-юнит через ExecStartPost `carrier-default-iface.sh` ставит
  table 100 по активному носителю из state (дефолт awg1, `ip link show`
  проверяется — юнит не падает); `After=wg-ws0` мягкий.
- **CLI:** `vds relay carrier status [--json]` / `switch --to awg|wstunnel [--apply]`.
- **Тесты:** +18 (матрица переходов, анти-джиттер, лимит, совместимость, AC-S4).

## 2026-11-20: WP-P2P-2 — P0/P1 фикс (юниты реально стартуют, атомарная policy)

- **P0-1:** `install_unit()` только enable'ит — добавлены явные
  `systemctl restart` в строгом порядке: exit `vds-wstunnel-nft` →
  `vds-awg-wg-ws0` → `vds-wstunnel-server` (nft/UFW первыми: drop WG-порта вне
  `lo` должен действовать **до** поднятия интерфейса); релей
  `vds-wstunnel-client` → `vds-awg-wg-ws0` → `vds-relay-nat` → `vds-relay-policy`.
  Раньше CLI печатал «поднято», а юниты стояли до ребута.
- **P0-2:** проверка `/usr/local/bin/wstunnel` **до** мутаций в обеих командах —
  без бинарника отказ с подсказкой вместо 203/EXEC и ложного `installed=True`.
- **P1-1:** conf `wg-ws0` на exit перезаписывается **всегда** (свой private_key
  сохраняется): ротация/исправление `--relay-public-key` больше не оставляет
  рассинхрон «new в state / old в conf».
- **P1-2:** nft-policy релея пишется в tmp → `nft -c -f` → `os.replace` → только
  затем рестарт policy-юнита: битый `ru-cidrs.txt` не уронит живую awg1-ногу.
- **P2:** атомарные записи nft/скрипта с mkdir; ключи читаются после dry-run
  (план показывается без `init`); ключ читается с late-binding путём (тесты).
- **Тесты +4 мок-`--apply`:** порядок рестартов (exit/relay), отказ без
  бинарника (ни одного рестарта), сохранность private_key при смене peer,
  `nft -c` до рестарта и отсутствие секретов в `state.json`. Всего **1457**.

## 2026-11-20: WP-P2P-2 ч. 2 — keygen, юниты, CLI, state (готово к ревью)

- **CLI (3 шага, ключи не пересекают узлы):** `wstunnel init` (релей: ключи
  `wg-ws0` в `/etc/amnezia/wg-ws0.priv` 0600 + prefix в env 0600; печатает
  только публичный) → `wstunnel server` (exit: conf, nft+UFW oneshot, юниты,
  LE обязателен; печатает публичный ключ exit) → `wstunnel client` (релей: conf
  `Table=off`/MTU 1240/Endpoint 127.0.0.1, юнит c `Wants/After=wstunnel-client`,
  перерендер `vds-relay-nat` с `p2p_iface=wg-ws0`, перерендер nft-политики).
- **state:** `protocols["p2p_wstunnel"]` = `{iface:"wg-ws0", public_key: <ключ
  ПИРА>, peer_ip:"10.12.0.2", domain, ws_port, wg_port, exit_public_key,
  installed}` — ровно контракт `_relay_peer_identity` (P0-1). Приватные ключи в
  state НЕ хранятся; в stdout — только публичные.
- **Юниты:** `vds-wstunnel-nft` (oneshot `nft -c -f` → `nft -f` + UFW «9443
  только с IP релея»), `vds-awg-wg-ws0` (plain AWG; на релее `Wants/After`
  клиента), `vds-wstunnel-server`/`-client` из WP-P2P-1.
- **table 100 не трогается** — переключение оставлено селектору (WP-P2P-3).
- **P2 ревью:** `run_install` печатает `expected_sha256()`; для `wg-ws0` без
  записи в state `_relay_peer_identity` возвращает «неизвестно», не проваливаясь
  в `clients[]` (тест).
- **Тесты:** +9 (prefix-парсинг, nft-скрипт apply/remove, keygen, чтение ключа,
  dry-run init без файлов, отказы server-команды), всего **1453**.

## 2026-11-20: фикс-пакет по ревью трёх WP (P0×2, P1×2, P2×2)

- **P0-1 (alert, ложный `relay_blocked` на резерве):** `_relay_peer_identity`
  выбирает источник **по интерфейсу** — `wg-ws0` → `protocols["p2p_wstunnel"]`
  (своя пара ключей, 10.12.0.2), `awg2` → `relay_leg`, `awg0` → `clients[]`.
  Раньше любой не-`awg0` брал `relay_leg` → `peer_not_found` на wg-ws0.
  Тест с **двумя разными ключами** (этого не хватало прежним тестам).
- **P0-2 (wstunnel не пропустил бы ни один пакет):** клиент форвардит на
  `127.0.0.1:<wg>`, а не `localhost:<wg>` — `--restrict-to` матчит строку, а
  `localhost` может резолвиться в `::1`. Тест сверяет target с `--restrict-to`.
- **P1-1 (NAT молча не работал бы):** в `vds-relay-nat.service` MASQUERADE
  пишется `-s {client_subnet} -o {p2p_iface}` — в `wg-ws0` уходят пакеты
  клиентов (10.10.0.0/24), а не 10.12.0.0/30; плейсхолдер `{p2p_subnet}` убран,
  перепутать нельзя (тест запрещает его возврат).
- **P1-2 (no-op):** `chain forward` из `render_exit_nft` удалена. На exit
  `DEFAULT_FORWARD_POLICY=ACCEPT` + «allow (routed)» — проверено на живом узле;
  поэтому awg2 работает без правил. Зафиксировано в доке: если политика станет
  `DROP`, нужен `ufw route allow in on wg-ws0 out on <wan>`, а не nft-иллюзия.
- **P2-1:** `WSTUNNEL_SHA256_BY_ARCH` (только amd64 проверен); arm64 → явная
  ошибка «не поддерживается», а не гарантированный провал sha256.
- **P2-2:** hostname валидируется строго (`ipaddress` + regex): IP, `[::1]`,
  `ws.example.net/path`, пробелы — отказ.
- **P2-3:** реальный поддомен в STATUS заменён на `ws.<domain>`.

## 2026-11-20: WP-P2P-2 (часть 1) — wg-ws0 plain, nft, NAT-ветка

- **DNS/LЕ готовы:** `ws.<domain>` → exit (DNS only, проверено с ноутбука
  и с exit через 8.8.8.8); LE выпущен `certbot --standalone`
  (`/etc/letsencrypt/live/ws.<domain>/`, до 2027-02-18).
- **Plain AWG:** `render_server_conf(obf={})` / `render_client_conf(obf={}, junk={})`
  не пишут `Jc/S1/H*` — внутри WSS обфускация только жжёт MTU/окно.
- **Конфиги `wg-ws0`:** exit `10.12.0.1/30` + пир `10.12.0.2/32` keepalive 25;
  релей `10.12.0.2/30`, `Table = off`, `MTU 1240`, `Endpoint = 127.0.0.1:<local>`,
  keepalive 25 обе стороны.
- **nft exit** (`vds_relay_wstun`): MASQUERADE 10.12/30 на WAN; `input` —
  WSS-порт только с IP релея, WG-порт **только lo** (kernel не умеет bind на
  loopback — замещаем nft), IPv6-дропы; `forward` — 10.12/30 наружу.
- **nft релея:** `iifname "wg-ws0" return` в prerouting (не метить fwmark 0x1) и
  `chain forward` с `maxseg size set rt mtu`.
- **NAT релея:** ветка `p2p_*` в `vds-relay-nat.service` (iptables, одна точка),
  по умолчанию пустая → правило не ставится; перерендер делает wstunnel-install.
- **Тесты:** +3 plain-режима, +6 рендеров (conf/nft), nat-шаблон; всего 1434.

## 2026-11-20: WP-P2P-1 — вендоринг wstunnel + юниты (готово к ревью)

- **Пиннинг (OQ-1):** `WSTUNNEL_VERSION=11.1.0`,
  `WSTUNNEL_SHA256=512edf4e…aa23` (digest релиза
  `wstunnel_11.1.0_linux_amd64.tar.gz`), url-шаблон GitHub Releases; никаких
  `latest`/`curl | sh`. Флаги сверены по README тега v11.1.0:
  server `wss://0.0.0.0:<port> --restrict-to 127.0.0.1:<wg> --tls-certificate …
  --tls-private-key …`; client `-L 'udp://127.0.0.1:<local>:localhost:<wg>?timeout_sec=0'
  --tls-verify-certificate wss://ws.<domain>:9443`.
- **Секрет в env, не в argv:** `WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX`
  (server) / `WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX` (client) — env-файлы 0600;
  ушла оговорка про видимость префикса в `ps`.
- **Безопасность распаковки:** только regular-файл `wstunnel`, без `..` и
  абсолютных путей, sha256 до распаковки, атомарный `os.replace` 0755.
- **Юниты:** `vds-wstunnel-{server,client}.service.tpl` — `Restart=always`,
  `RestartSec=5`, `StartLimitIntervalSec=0`, `ProtectSystem=strict`, env-файл.
- **CLI:** `vds relay wstunnel install --archive … [--apply]`, `… status [--json]`.
- **Тесты:** 22 (пиннинг, arch, sha-мисматч, traversal, отсутствие секрета в
  argv/env-имена, песочница шаблонов, dry-run, парсинг версии).

## 2026-11-20: WP-P2P-5 — alert-watch: список интерфейсов ноги (готово к ревью)

- `ALERT_RELAY_IFACE` принимает **список** (`awg2,wg-ws0`): новый
  `env.relay_ifaces()`, агрегирующий `checks.read_relay_signal`.
- Один интерфейс — прежнее поведение (прямой `_probe_one_iface`, все старые
  тесты не менялись). Несколько — проба каждого: `ok`, если жив **любой**;
  иначе худший живой вердикт; `peer_rx` = сумма (гейт активности).
- Тесты: парсинг списка, ok при живом втором, blocked когда мертвы оба
  (traffic+TCP-жив), один недоступен/другой ok, оба недоступны →
  `inconclusive awg_unavailable`, активность из любого носителя.
- Спека p2p обновлена попутными P2 ревью: `fallback → exhausted` — по **3/3**
  отказам с автовыходом из `exhausted`; `wg-ws0` на релее —
  `Endpoint=127.0.0.1:<local>` + `Wants/After=vds-wstunnel-client.service`.

## 2026-11-20: SPEC p2p link — ревизия после ревью (P0-1…P0-3, AC-S1…S9)

- **P0-1:** kernel AWG/WG **не умеет bind на loopback** — вместо невыполнимого
  «listen 127.0.0.1» зафиксирован nft-drop
  `iifname != "lo" udp dport <WG_WS_PORT> drop`. Стек — **`awg`** (на обоих
  узлах есть `awg`, `wg` нет; alert-watch читает `awg show`), обфускация
  выключена (`Jc=0, S1=S2=0`) — внутри TLS junk жжёт MTU/окно.
- **P0-2:** TLS/SNI исправлен — подключение к **`wss://ws.<domain>:9443`**
  (hostname, а не IP: иначе LE не валидируется и SNI не уходит). Убрана
  несуществующая схема `wg://` → UDP-форвард
  `udp://127.0.0.1:<local>:127.0.0.1:<wg-port>`; секрет-префикс через
  `EnvironmentFile` 0600 (оговорена видимость в argv, митигация — single-user
  root-узлы + `ProtectProc=invisible`).
- **P0-3:** селектор больше не переключается вслепую: pre-check
  `ping -I wg-ws0 10.12.0.1` перед `ip route replace`, при мёртвом резерве —
  сразу `exhausted` + alert. В `fallback` P25 **не крутит порты** (no-op,
  `attempts` не растёт) — иначе три ложных rollback свалят селектор.
- **P1:** реальный домен заменён плейсхолдерами; добавлен факт `9443/tcp`
  на asv2 (свободен) и `awg`/`wg` (awg есть, wg нет); AC-S1…S9 сведены в
  таблицу SPEC (включая AC-S9 про ложный `relay_blocked`); MASQUERADE `wg-ws0`
  закреплён за `vds-relay-nat.service` (iptables), **не** nft — тот
  перегенерируется `vds-relay-cidr.timer`.
- **P2:** keepalive 25 на обеих сторонах; второй LE по ADR-004 (`--standalone`
  80/tcp) + deploy-hook с фильтром `$RENEWED_DOMAINS`.
- **OQ закрыты решениями:** вендоринг `erebe/wstunnel` (версия+SHA256, без
  `curl|sh`), `ws.<domain>` (DNS — владелец), порт `9443`, `Restart=always` +
  keepalive, XHTTP на 8443 не трогаем.

## 2026-11-20: SPEC p2p link (draft) + read-only факты по OQ

- **SPEC:** [SPEC-20261120-p2p-link-multi-carrier](specs/SPEC-20261120-p2p-link-multi-carrier.md)
  — draft; ADR-016 принят, реализация после G2 спеки.
- **Факты с узлов (read-only):** на asv2 `8443/tcp` **занят XHTTP-инбаундом
  xray** → кандидат из ADR отпал; выбран **`9443/tcp`** (свободен на обоих
  узлах; 2053 не берём — порт резерва CDN). `wstunnel` **нет в apt** на обоих
  узлах → нужен вендоринг бинарника с SHA256 (OQ-1). LE: только
  `asv2.asvpersonal.ru` → нужен второй поддомен (DNS — за владельцем, OQ-2).
- **Контракт SPEC:** per-carrier NAT на обеих сторонах (10.11/30 awg,
  10.12/30 wg-ws0), `wg-ws0` MTU 1240 + MSS clamp, селектор с триггером на
  первом `rollback` P25, `prefer_primary` 3 пробы + 600 с, лимит 3/час,
  alert-watch — список интерфейсов `awg2,wg-ws0`.
- **Осталось до G2 спеки:** OQ-1 вендоринг wstunnel, OQ-2 DNS-поддомен,
  OQ-3 подтвердить 9443, OQ-4 reconnect-поведение wstunnel.

## 2026-11-20: ADR-016 — p2p link с L4-ортогональными носителями (✅ принят, G2)

- **Документ:** [ADR-016](../adr/ADR-016-p2p-link-multi-carrier.md) — статус
  **«принят»** (G2 APPROVED 2026-11-20, ревизия `b3c1a81`); дальше SPEC + WP.
- **MVP:** носитель №1 — существующий `awg2`/пул 51900–51911 (UDP, с манёвром
  P25 внутри); носитель №2 — `wstunnel-wg` (`wg-ws0` поверх wstunnel/TLS,
  TCP) как L4-ортогональный резерв; селектор — на RU-релее.
- **Per-carrier NAT:** у каждого носителя своя /30 (`10.11.0.0/30` awg,
  `10.12.0.0/30` wg-ws0) + свой MASQUERADE → exit отвечает в тот же интерфейс
  без правок на своей стороне; переключение = `ip route replace default dev …
  table 100` под FileLock.
- **5 инвариантов на G2:** изоляция порта wstunnel (не 443, UFW строго с IP
  релея, `--restrict-to`, случайный ws_path, настоящий LE-сертификат для
  пассивного DPI); единая иерархия автоматов (P25 внутри awg → селектор на
  **первом `rollback`**, возврат после 3 проб + cooldown 600 с); запрет петли
  (wstunnel через main table, `Table = off`); MTU/MSS clamp; нумерация
  и non-goal (блок IP exit не закрывается).
- **Фаза 2:** адаптер ZeroTier — только если ZT уже развёрнут для клиентского
  плеча (тот же UDP-класс, хуже фингерпринт, тянет контроллер).
- **Правки ревью G2:** триггер Уровня 2 — **первый `rollback`** P25 (не
  `exhausted`: 3 попытки × cooldown 600 с ≈ 22 мин, AC-2 → ≤ 240 с от блока);
  exit-сторона `10.12.0.0/30` (WG на loopback, NAT, forward/UFW) в §2 и откате;
  nft: `iifname "wg-ws0" return` + `chain forward` с MSS-clamp, старт policy-юнита
  синхронизирует носитель из state; проба `awg1` — активная (`ping -I`), маршрут
  `/30` в main; alert-watch ослепнет по `awg2` при уходе на `wg-ws0` → список
  интерфейсов (ложные `relay_blocked`); AC-5 — поток > 1 МБ при MTU < 1280.
- **Открыто до SPEC (§8 ADR-016):** пакет wstunnel для Ubuntu 24.04 и
  `--restrict-to`; занятость 8443/tcp на asv2/релее; второй LE-домен и механика
  продления при скалярном `state.protocols["acme"]`; поведение alert-watch.

## 2026-11-20: тюнинг сторожа — WP-AW-CADENCE + WP-PW-HYSTERESIS

Полевой разбор 24 ч (asv2): 101 уведомление, из них 68 (67 %) — «всё ещё high»
и сводки; при этом окна probe-watch 23/24 — `quiet`, а `high` стоял 24 ч с
`decay=0`. Две причины, обе — дефекты механики, а не «слишком чувствительный
детектор».

- **WP-AW-CADENCE (`3848f1e`):** `ALERT_HIGH_REMINDER_H` (дефолт 6 ч, 1..24) для
  `threat_high_still`; переходы в/из high — мгновенные; подавленные `*_still`
  больше не кормят `suppressed`/`summary`. Эффект: ≤4 карточки в сутки вместо
  45 + пустые сводки.
- **WP-PW-HYSTERESIS:** `decay` сбрасывает только подтверждённый
  `RU-PROBE-SUSPECT` (раньше — любой одиночный RU-IP в quiet-окне, из-за чего
  выход из high был недостижим на публичном IPv4); `HIGH_EXIT_WINDOWS` 72 → 24;
  кэш `seen_ru_ips` (TTL 24 ч, cap 500) вместо 1-часового nft-сета — сканер с
  периодом ~61 мин больше не «новый» каждый час; порог SUSPECT дополнен
  `Σ delta ≥ 6` при per-element счётчиках (2 фоновых сканера × 2 SYN = 4
  уровень не поднимают), на фолбэке — по числу IP.
- **Тесты:** профиль полевого лога (2 IP × 2 SYN) даёт `quiet`; серия (Σ ≥ 6
  два окна) → high; фоновый RU-IP decay не сбрасывает; выход из high за 24 окна;
  старый снапшот без `seen_ru_ips` грузится; в локе decay заморожен.
- **Деплой:** пока только WP-AW-CADENCE готов к выкату; WP-PW-HYSTERESIS — после
  ревью диффа (обратная совместимость снапшота проверена тестом).

## 2026-11-20: автопилот манёвра ВКЛЮЧЁН на релее (60 с)

- **Решение владельца** после Tail 3: критерий выполнен (AC-1 изоляция, AC-2
  ребут, ветка gate по `awg0` вживую) → `vds relay maneuver install --apply
  --enable-auto --interval 60s`.
- **Факт после включения:** `timer_enabled=true`, `auto_timer_active=true`,
  тики каждые 60 с: `state=healthy port=51900 liveness=ok ms=31 activity=1
  fails=0/3 acted=0`; `Result=success` (нет 226/NAMESPACE); нога на базе.
- **Поведение по умолчанию в коде не изменилось**: `auto=off`, включение — только
  явным `--enable-auto`. Стоп-кран: `systemctl disable --now
  vds-relay-maneuver.timer`; история — `/var/lib/vds/relay-maneuver.json`.
- **Первый тик после простоя** даёт `activity=0` (нет базовой выборки) — это
  защита от ложного триггера, а не сбой.

## 2026-11-20: Tail 3 ЗАКРЫТ — ветка gate по `awg0` валидирована вживую

- **Полигон:** за релеем живой клиент `10.10.0.4` с реальным трафиком
  (Δawg0 = 39.5 МБ/60 с); на exit — runtime `ct original proto-dst 51900 drop`
  (имитация блока порта ноги) + страховка автоснятия через 240 с.
- **Результат:** тик 1 `activity=0` (нет базовой выборки) → тик 2 `activity=1`
  (клиентский `awg0`) → тик 3 3/3 → **маневр 51900→51901, result=ok**, далее
  `healthy`, liveness 31 мс. Реакция ≈7 с после 3/3; детекция ≈45 с при ручном
  интервале 15 с (в проде 60 с → ≈180 с).
- **Клиент не заметил:** handshake живой, transfer вырос до 2.95 MiB rx /
  146 MiB sent через релей.
- **Уборка:** правило снято рестартом пула (0 `ct original`-правил), dead-man
  отменён, `rollback --apply` → база 51900 (liveness 31 мс, Endpoint персистнут),
  4 пира `awg0` не тронуты, таймер `auto=off`.
- **Осталось:** решение владельца по `--enable-auto` (AC-1 + AC-2 + ветка
  подтверждена + 0 ложных подозрений). Отчёт — ACCEPT P25 §3.1.

## Активный цикл: P24/P25 — манёвр ноги relay↔exit (2026-11-20)

- **ADR-015** + **SPEC-20261120** (G2 APPROVED): изоляция порта exit (`awg2`,
  пул 51900–51911 через nft REDIRECT) и манёвр ноги; триггер P25 — **data-plane
  liveness**, не `handshake_age` (WP-M0: handshake 5 ч при живом трафике).
- **WP-M0** (факты, [TEST-20261120-relay-leg-diag](reports/TEST-20261120-relay-leg-diag.md)):
  35 эпизодов/7 д, медиана **7 мин** (прежние 32 — артефакт cooldown alert-watch),
  IPv6-нога 47 мс, `PersistentKeepalive` на awg1 отсутствовал.
- **P24 — ✅ ВЫПОЛНЕНО И ПРИНЯТО 2026-11-20**
  ([ACCEPT-20261120-p24-exit-leg](reports/ACCEPT-20261120-p24-exit-leg.md)):
  `awg2`+пул+MASQUERADE на exit, cutover релея на `213.108.23.119:51900`,
  REDIRECT проверен через `:51901`, внешний скан пула молчит, `awg0` не тронут,
  сторож переведён на `ALERT_RELAY_IFACE=awg2` (peer_found, ok).
- **WP-M3 (ядро) + WP-M4 (opt-in таймер) — ЗАПУШЕНЫ и APPROVED**
  (`008b346`+`ee2b50f` M3; `add24c7`+`b7036c4`/`dd0b289` M4; `9335580` P2 to=):
  state-machine 6 состояний, liveness-окно 20 с, activity gate (шум keepalive
  отфильтрован: 92 Б/60 с ≪ 4096), anti-ping-pong 600 с/≤3 в час, `awg set
  listen-port 0 … endpoint` (полный 4-кортеж), `StateDirectory=vds` (иначе
  226/NAMESPACE на релее), `install_unit(enable=False)` для auto=off.
- **WP-M5 — ✅ ПРИНЯТ 2026-11-20**
  ([ACCEPT-20261120-p25-maneuver](reports/ACCEPT-20261120-p25-maneuver.md)):
  M3+M4 выкачаны на релей (полный rsync src/+systemd/, md5 сверен; auto=off,
  интервал 60s); живой блок `ct original proto-dst 51900` → 3/3 + activity →
  51901 за ~7 с после 3/3 (<60 с AC); rollback CLI вернул 51900.
- **Ребут-протокол (AC-2) — ✅ ПРОЙДЕН 2026-11-20** (по одному узлу: exit → релей):
  exit — 6/6 юнитов active, `awg2`/3 nft-цепочки/`ip_forward`/UFW живы, внешний
  скан пула (51900/51901/51911) молчит; релей — 5/5 юнитов active, `table 100`
  `default dev awg1`, fwmark→100, нога поднялась **сама** на `51900` из
  персистнутого `Endpoint` (handshake 72 с, ping 31 мс 0 %, egress = exit IP),
  `maneuver.timer` остался `disabled`; `awg1.conf.bak-pre-leg` снят.
- **Хвост 1 — ✅ ВЫПОЛНЕН 2026-11-21 05:31 UTC** (окно): legacy-пир релея
  `10.9.0.5` снят с `awg0` asv2 живым `awg set … peer … remove` (P24-prep,
  без рестарта юнита — `NRestarts=0`, ActiveEnterTimestamp не тронут,
  handshakes клиентов не сброшены); `awg0` = 3 пира (10.9.0.2/.3/.4), backup
  `.bak-pre-mutation` снят; нога релея жива (awg1 handshake свежий,
  `ping -I awg1` 3/3 ~31 мс, `table 100 = awg1`); alert `relay_blocked` = 0.
  Код на exit синхронизирован с HEAD (sha256 `clients.py`/`install.py`
  сверены с `git show`). Там же P28-деплой: hook регенерирован
  (`vds acme issue`, skip-ветка), фильтр на диске, smoke ws/unset → rc 0
  без рестарта — [TECHDEBT P28](../../TECHDEBT.md) закрыт.
- **Осталось:** `--enable-auto` — решение владельца после первого живого
  эпизода с клиентом за релеем (live-валидация ветки gate по `awg0`).

## Активный цикл: alert-watch + fast alerts/scout (2026-11-17)
- **SPEC:** [SPEC-20261117-alert-watch](specs/SPEC-20261117-alert-watch.md) — G2 APPROVED;
  **WP-1…WP-7 реализованы и запушены** (`4af69c6..2782349`; код + тесты + доки).
- **Сервер (vds):** `src/alert/` (7 модулей), юниты `vds-alert-watch.{service,timer}.tpl`,
  `vds alert install/remove/test/status/watch` (+ аддитивный `test --channel tg|smtp`),
  видимость в `WATCH_UNITS` (ADR-012), doc-sync правило `alert`. Проверка: полный
  `pytest -q` зелёный, `docsync audit --strict` OK; секреты только в
  `/etc/vds/alert.env` (0600).
- **Клиент (`ubuntuInstaller/scripts/vpn-manager`):** `vpnm/scout` WP-S1…S4 —
  `vpn scout [--json] [--sync]`, `vpn up --scout` (схема `scout.report/1`);
  `vpn guard notify-test` (контракт WP-G5 не менялся). Полный `pytest -q` зелёный;
  wheel содержит `vpnm/scout/*`, `SCHEMA = scout.report/1` импортируется из wheel.
- **Осталось:** живая приёмка AC-1…AC-13 на asv2 — `/etc/vds/alert.env` 0600,
  `vds alert test --channel smtp`, `awg show awg0 dump` (AC-13), простой 3+ ч
  (`stale`/`telemetry_unavailable`); `vpn scout` на ноутбуке; пометка
  «реализовано» в research-доке — после приёмки (SPEC §11).
- **Doc audit:** `docsync audit --strict` — OK (эта правка снимает warning по STATUS.md).

## Цикл doc-sync (SPEC-20261116-doc-sync) — WP-1…WP-4 закрыты
- **SPEC:** [SPEC-20261116-doc-sync](specs/SPEC-20261116-doc-sync.md) (G2; `tools/docsync.py`,
  `docs/doc-sync.json`, хуки `.githooks`, агентские DoD — коммит `26cdbf8`).
- **WP-5 выполнен досрочно:** режим `mode: block` включён 2026-11-20
  (DECISION Q8, см. верхний блок) — нарушения блокируют коммит, откат —
  `"mode": "warn"` коммитом или `git config --unset core.hooksPath`.

## Предложение на G2: survivability (SPEC-20261116-survivability)
- **SPEC:** [SPEC-20261116-survivability](specs/SPEC-20261116-survivability.md) —
  draft, ждёт `vds-architect` + техлида (G2). Не реализация.
- **Суть:** packet-level стадии 1/2/3 (freeze → probing → RST-инъекция /
  silent ClientHello drop / UDP response drop / L3-бан), новые правила
  **T-18…T-23** + поле `stage`, stage-aware ранбук, портфель мер S-01…S-15
  (P0: ранбук/keepalive/`surface audit`/XMUX; P1: failover/canary/пул фронтов;
  P2: SPA по **ADR-013**, ротация IP, anti-fingerprint).
- **Технические поправки:** `TcpInRsts` в nstat нет (есть `TcpEstabResets`/
  `TcpExtEmbryonicRsts`/`TcpOutRsts`); `syn_valid` не видит ClientHello;
  Δt<15 мс — сильная улика, абсолютным делает RTT-floor + TTL/TSopt/seq.
- **Ревью:** [ARCH-20261116-tspu-blindspots](reports/ARCH-20261116-tspu-blindspots.md) —
  8 слепых пятен глазами инженера ТСПУ (вход для intake; P0-кандидаты:
  Self-DoS в probe-watch, демаскировка 8443/2053, конфликт SNI/LE).
- **Дальше:** G2 → WP-S1/S2 (детект+stage) → WP-S3 (surface audit) →
  WP-S4 (canary); SPA (WP-S5) — только после приёмки probe-response v1.

## G2 APPROVED: vpn guard (SPEC-20261116-vpn-guard)
- **SPEC:** [SPEC-20261116-vpn-guard](specs/SPEC-20261116-vpn-guard.md) —
  **G2 APPROVED 2026-11-16** (`vds-architect` + техлид). Пять правок ревью
  внесены; открытых вопросов нет (OQ-1…OQ-20 закрыты). Не реализация.
- **Суть:** клиентский **real-time** анализатор логов (`journalctl --user -f`)
  — конвейер `tail → parse → normalize → window → rules → correlate →
  finding`; правила **G-01…G-12** (no-handshake, reset storm, post-handshake
  drop, UDP blackhole, auth/config, DNS, local-net, TLS, endpoint silent,
  unit flap, degraded, self-health), `stage_hint` ↔ T-18…T-23, merge с
  серверным `probe-watch --json` через файл (без сети в демоне).
- **Границы:** read-only v1 (никаких restart/repair/switch), user-space,
  без root/сети/LLM; findings 14 дней/20 МБ, только счётчики и хэши
  шаблонов; юнит `vpn-guard.service` (не `vpnm-*` — иначе `vpn autostart off`
  отключит guard).
- **Правки G2:** (1) `probe-watch watch` без `--record` закреплён как
  read-only + серверный regression-тест, sync 60 мин, свежесть 65 мин;
  (2) AmneziaWG (`awg-quick@*`/`vpn-awg-split@*`, `dnsmasq`, sysfs-счётчики)
  как полноценный канал — `idle` при живом AWG запрещён, ветка G-04
  `awg_tx_no_rx`; (3) sandbox-профили `hardened`/`compat` + проверка
  `226/NAMESPACE` и D-Bus; (4) пост-сканер не трогает `*_hash`/`*_sha256`;
  (5) G-01 через `app_banner_ok`/`dial_*`, иначе `insufficient_data`.
- **Реализация:** `ubuntuInstaller/scripts/vpn-manager` (`vpnm/guard/`);
  спека здесь, потому что процесс/гейты — в `vds`. **ADR-014** утверждён,
  создаётся в WP-G0.
- **Доклад для G2-аудитории:**
  [BRIEF-20261116-vpn-guard](reports/BRIEF-20261116-vpn-guard.md) — 13 слайдов,
  тезисы, риски и 6 вопросов к архитектору/техлиду. Промпт напарника
  (архитектор+техлид+ревьюер): [PROMPT-20261116-vpn-guard-arch-lead](reports/PROMPT-20261116-vpn-guard-arch-lead.md).
- **Дальше:** WP-G0…WP-G5 — ✅ PASS 2026-11-16 (G3/G4/G5 approve
  архитектора); **WP-G6** — 7 дней поля, бенч AC-5, AC-17, `kill -9`,
  `selftest` из wheel. AC-1…AC-17 — §14.2.
- **Статус цикла (2026-11-16):** ✅ **G0–G5 PASS**; приёмка —
  [ACCEPT-20261116-vpn-guard](reports/ACCEPT-20261116-vpn-guard.md).
  Коммиты: `ubuntuInstaller` — `4bc145e` (G0), `6ead3cc` (G2), `757e2f2` (G1),
  `a7e7a8f` (G2-фиксы), `b0297d8` (G3), `c84560d` (G4), `b10553a` (G5);
  `my-first-vds` — ADR-014 `f502985`, AC-16 `69225a7`, DECISIONS
  `b42d4cc`/`20b52ff`. Осталось: **WP-G6** — 7 дней `vpn-guard.service`
  на живом ноутбуке (AWG/Reality/XHTTP/Hy2), 24 ч бенч AC-5, AC-17 на чистом
  десктопе, реальный `kill -9`, `selftest` из установленного wheel.
- **Живой старт WP-G6 (2026-11-16):** pipx-wheel + `selftest` OK; unit
  `hardened` (без fallback), `state=armed`, iface `laptop`; sync с asv2 —
  `fresh=true`. AC-12/AC-15/AC-17 — PASS; 7-дневное наблюдение идёт.
  Отчёт: [TEST-20261116-vpn-guard-live-start](reports/TEST-20261116-vpn-guard-live-start.md).
- **Guard live-fix 2026-11-17 (`ubuntuInstaller 78ce00c`):** файл-подобный
  `stderr` (TextIOWrapper) и гонка `cursor.json.tmp` (два reader-потока) —
  исправлены; `journal:user/system` = ok, `cursor_write_failed` ушёл,
  `verdict` обновляется после `sync`. APPROVE 2026-11-17; HF-SSH `14999ec`
  тоже APPROVE. T0-снимок:
  [TEST-20261117-vpn-guard-checkpoint-t0](reports/TEST-20261117-vpn-guard-checkpoint-t0.md);
  следующая контрольная точка — T+24–48 ч.
- **Чекпоинт T+33 (2026-11-19):** окно непрерывности **17.11 15:24 → 24.11
  15:24 MSK** (сдвиг от T0 — рестарт после падения на отсутствующей схеме, D2);
  AC-5 в поле: RSS 22.1 MiB, CPU 0.28 %, `NRestarts=0`, `dropped=0`,
  `redaction_hits=0`. Findings 7d — 26: 13 G-06 / 7 G-07 (полевое доказательство
  DNS-дефекта и локальной сети), 3 G-12 `source_lost: sysfs:awg` (кандидат в
  калибровку G6), 3 G-09 — до фикса `c447171`, после него повторов нет.
  **D1/D3 закрыты в коде** (`ubuntuInstaller 612a64b`, деплой отложен до
  24.11 15:24): exit-код демона при штатном stop, баннер Hysteria2 2.x
  `INFO→client mode` (покрытие G-01) и AC-5 min-sample. Полевая серия
  19.11 выявила **D6** (`proto_hints` не заполнялся → `signals.xray/hysteria2`
  навсегда `blind`; фикс — store-hints + контент/имя-юнита fallback, реплей
  68 657 строк: `unparsed 1 → 0`); XHTTP в поле — N/A (нет на asv2). Отчёт:
  [TEST-20261119-vpn-guard-t33](reports/TEST-20261119-vpn-guard-t33.md).
- **Ревью (эволюция v1.0 → v2.0):** [ARCH-20261116-vpn-guard-evolution](reports/ARCH-20261116-vpn-guard-evolution.md) —
  стратегическая оценка + предложение v1.1 (ss/netlink, packet-size ratio,
  ленивый sync), v1.2 (`--client-report`) и v2.0 (Smart Failover, только через ADR).

## Инфраструктура (live-ops, 2026-11-14..16)
- **asv2 = основной AWG-exit** (213.108.23.119): deploy 2026-11-15 — UFW harden
  gateway-профиль (ADR-011), SSH → 49222, /48 IPv6, LE `asv2.asvpersonal.ru`
  (Hy2 secure, без insecure=1). **asv1 удалён 2026-11-16** — настройка
  пропущена, единственный боевой exit — asv2.
- **asv2: состав транспортов (2026-11-16):** оставить Reality 443/tcp +
  Hysteria2 443/udp + AmneziaWG 51825/udp; XHTTP :8443 и CDN :2053 не
  поднимать до GR-07 Self-Steal — иначе Cross_Port_Cert_Conflict на
  единственном боевом узле.
- **asv2: Wave 0 + W1-1 выкачены 2026-11-16** (`4fb1956`): HF-1 verified
  sessions, HF-2 (код; xhttp/cdn на asv2 нет), W1-1 probers4
  `{443,8443,2053}` + extra-счётчики. Юниты пере-рендерены с venv;
  `systemctl --failed` = 0, все vds-таймеры active, `logs sample` пишет
  телеметрию, `auto_lockdown=false`. Найден и закрыт EROFS-lock
  (`vds-logs-sample`: `ReadWritePaths=/var/lib/vds /var/run`).
  Отчёт: [DEPLOY-20261116-asv2-wave0-w1](reports/DEPLOY-20261116-asv2-wave0-w1.md).
  **HF-3 закрыт** (`fb3e8fe`, docs `83dc1cc`): `resolve_python()` =
  venv → `sys.executable` → PATH; проверено на asv2 install с чистым
  системным PATH — юниты рендерятся с venv, `systemctl --failed` = 0.
- **RU-relay: РАЗВЁРНУТ 2026-11-17** — LandVPS `vm354051`
  (`185.80.91.135`, AS216334, Москва), **Ubuntu 24.04.4** (переустановка
  шаблона 2026-11-17, второй прогон — без ошибок), 512 МБ + 1 ГБ swap;
  `vds-relay-{awg,exit,nat,policy,cidr}` + `vds-xray` active, UFW профиль
  relay, RU-CIDR 8664 агрегата. Живые проверки: клиент через релей →
  egress `213.108.23.119` (asv2), RU-сайты direct (ya.ru 0.13 с), фолбэк
  Reality SNI=ya.ru с ноутбука OK. Найдены и закрыты 4 дефекта раскатки
  (iptables на cloud-образе, идемпотентные порты, потеря public_key,
  потеря policy-маршрута при рестарте ноги → `PartOf=`). Отчёт:
  [DEPLOY-20261117-ru-relay-landvps](reports/DEPLOY-20261117-ru-relay-landvps.md).
  Открыто: DNS `relay.asvpersonal.ru` (A, DNS-only) — владелец; смена
  паролей панели/root; TECHDEBT P20 (remove-client). ОС закрыта: 24.04.4.
  Reboot-тест PASS (дважды — 22.04 и 24.04): 6/6 юнитов, policy-маршрут и
  NAT восстанавливаются сами. Клиенты перевыпущены (`~/.awg/relay.conf`,
  профиль `relay-reality`).
  **Клиентский старт 2026-11-17:** `vpn start relay` (ubuntuInstaller
  `bef29b1`+) — взаимоисключение с прямым контуром (`vpn start` гасит
  релей, `vpn start relay` гасит vpnm-*/AWG-split/xsplit), `vpn down` не
  трогает `vpn-guard.service`; режим в `vpnm.mode/1` (`mode.json`), guard
  читает его как подсказку, `activity.json` остаётся probe-маркером.
  Живой preflight на ноутбуке: без `sudo -n` `vpn start relay` → exit 1,
  прямой контур (`asv2-reality` + `@laptop`) не изменён.
  **Живой старт PASS 2026-11-17:** первый запуск падал на
  `vpn-awg-split@relay` — `awg-quick: Name or service not known:
  '354051.landvps.online:443'`. Причина: `vds relay add-client` берёт
  endpoint из `state.domain`, а это внутреннее имя LandVPS, не публикуемое
  в публичном DNS (`relay.asvpersonal.ru` ещё не создан). Ключи целы
  (пир `9tmMZ…` = серверный peer), сервер в порядке (`:443/udp`, UFW 443,
  pubkey совпадает). Фикс: `Endpoint = 185.80.91.135:443` в
  `~/.awg/relay.conf` (бэкап `.bak-pre-endpoint`) + серверные экспорты
  `laptop.conf` / `smoke-asv2.conf` (там же бэкапы). После фикса: юнит
  active, handshake есть, egress `213.108.23.119` (asv2), RU-сайты direct
  (`ya.ru 302 / 0.19 s`), `mode.json` = `relay`, `vpn status` печатает
  `RELAY (awg relay → 185.80.91.135)`. Постоянное решение — DNS-запись
  `relay.asvpersonal.ru` (владелец) либо `--endpoint` в `add-client`
  (TECHDEBT P22). `vpn status relay` — не подкоманда: режим показывает
  `vpn status`.
  **Закрыто 2026-11-17:** DNS `relay.asvpersonal.ru` → A `185.80.91.135`
  создан владельцем; endpoint возвращён на домен (`~/.awg/relay.conf`,
  бэкап `.bak-ip-endpoint`), серверные экспорты `laptop.conf` /
  `smoke-asv2.conf` — тоже домен. Живая проверка на домене: юнит active,
  egress `213.108.23.119`, `ya.ru 302 / 0.17 s`. **TECHDEBT P22 закрыт
  кодом:** `vds relay add-client --endpoint HOST[:PORT]` +
  `choose_endpoint()`: override → `state.domain` → канонический
  `relay.asvpersonal.ru` → публичный src-IP сервера → отказ с подсказкой.
  Ключевая деталь: резолв проверяется **с сервера**, а внутреннее имя
  хостера там резолвится (LandVPS-DNS), поэтому отсечка идёт по совпадению
  имени с hostname/FQDN машины. 12 новых тестов, полный прогон зелёный;
  код докатан на релей (`/opt/my-vds/src/...`, venv-PYTHONPATH) и проверен
  вживую: `choose_endpoint('354051.landvps.online')` →
  `relay.asvpersonal.ru:443` + warning, override — как задан. Ноутбук
  возвращён в **прямой контур**:
  `@laptop` active (handshake, endpoint asv2:51825, policy 0x21000),
  `@relay` остановлен, `mode.json` = `direct`.
  **Ранбук обновлён 2026-11-17:** тариф LandVPS RU-1 (KVM, 1 ГБ/20 ГБ,
  1 месяц до года, swap при 0.75 ГБ), 5-мин gate §0.3 через **asv2
  (213.108.23.119:51825)**, anti-DDoS UDP-проверка; asv1-IP удалён из команд.
  **Gate PASS 2026-11-17:** LandVPS `vm354051` (185.80.91.135, AS216334,
  Москва) — AWG UDP до asv2 работает (egress 213.108.23.119, Google 200/0.34 s),
  anti-DDoS UDP не режет. Отчёт:
  [TEST-20261117-ru-relay-gate](reports/TEST-20261117-ru-relay-gate.md).
  Остаток: решение OS 24.04 vs 22.04, DNS `relay.asvpersonal.ru` (A→IP,
  DNS-only), RU_SNI, затем `vds relay init --exit 213.108.23.119`.
- **probe-watch v3** (SPEC-20261116-probe-response): threat-level quiet/elevated/high,
  ru-cidr install, lock-443 TTL/undo/hop-guard, auto-lockdown off (default).
- **И44:** AWG/relay генераторы клиентов без дефолтного `PersistentKeepalive`
  (`--keepalive N` — явный opt-in, для NAT-дырки 113).

## Циклы 2026-11-14..16 (завершены)
- **xhttp-split — G4 PASS 2026-11-14:** [SPEC-20261114-xhttp-split](specs/SPEC-20261114-xhttp-split.md),
  [TEST-20261114-xhttp-split](reports/TEST-20261114-xhttp-split.md); Xray 26.1.23
  (ADR-010); схема обобщена на Reality (`vpn start reality/xhttp`, по умолчанию AWG).
- **RU-relay WP-1..5 — код принят 2026-11-15:** [ADR-007](../adr/ADR-007-ru-relay.md),
  [DEPLOY-RU-RELAY](../DEPLOY-RU-RELAY.md); юниты vds-relay-{exit,nat,policy,cidr}.
- **UFW hardening — ADR-011 + SPEC-20261116:** `vds system ufw harden/ssh-port/lock-443`;
  asv2 развёрнут по профилю gateway (см. выше).
- **probe-response — probe-watch v3:** [SPEC-20261116-probe-response](specs/SPEC-20261116-probe-response.md)
  (коммит `c31462e`): threat-level, RU-CIDR, lock-443 c TTL/undo/hop-guard.
- **И44 keepalive:** генераторы без метронома по умолчанию (коммит `8979673`).

## Архив: CDN-transport — VLESS за Cloudflare — ЗАВЕРШЁН 2026-11-10
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-10 (пятый канал: egress через
  CF, чтобы цензор видел IP Cloudflare)
- **REQ:** [REQ-20261110-cdn-transport](requirements/REQ-20261110-cdn-transport.md) (G1 READY)
- **SPEC:** [SPEC-20261110-cdn-transport](specs/SPEC-20261110-cdn-transport.md)
  + [ADR-006](../adr/ADR-006-cdn-cloudflare-transport.md) (OQ-1..5: proxied-запись
  `cdn.eu-cloud-xip.com`, апекс/`103-45-247-172` — grey; транспорт WS v1, XHTTP
  packet-up — future; origin-порт TCP 2053 (CF HTTPS-порты: 443/2053/2083/2087/2096/8443),
  edge-порт = origin-порт — девиация от FR-4; TLS Full (strict) + отдельный LE-cert
  cdn-домена; CF — ручные шаги владельца, CF-API — future)
- **Этап:** ✅ G6 Close — сервер установлен на asv1 (PPA, UDP 51825, юнит с P14-фиксом),
  клиент laptop + e2e (handshake + youtube 204/0.28s через AWG-туннель с ноутбука),
  NAT/forwarding (P15) персистентны. Финальная верификация:
  [TEST-20261110-amneziawg-cdn](reports/TEST-20261110-amneziawg-cdn.md) (AWG PASS, CDN-блокер B-1 найден и закрыт).
  Эксплуатация: split-конфиг ноутбука (`~/awg0-split.conf`, awg-quick) — youtube/telegram через AWG,
  остальное напрямую; на стороне провайдера владельца youtube-SNI DPI-иммунен к zapret-стратегиям.

### Открытые пункты цикла (CDN)
0. **ADR-007 RU-relay (proposed, ждёт владельца):** входной AWG-релей на RU VDS — покрытие mobile-whitelist вектора + дешёвая ротация exit-ноги по v6; [ADR-007](../adr/ADR-007-ru-relay.md); шаги внедрения внутри.
0. **Новый цикл (REQ готов, ждёт владельца): transport-hardening —** Salamander для Hysteria2 + ротация параметров/порта AWG; REQ: [REQ-20261112-transport-hardening](requirements/REQ-20261112-transport-hardening.md); UDP-over-TCP отложен.
1. **Девиация FR-4 (SPEC §4.3):** share-link CDN использует порт 2053, не 443 —
   факт CF «edge-порт = origin-порт», 443 занят Reality. Аналитик правит REQ на G5.
2. **Reality-gate приёмки (блокер G4):** после переноса зоны в CF клиент `phone`
   (Reality, доменная ссылка) и `mob` (Hysteria2) обязаны работать e2e —
   апекс/`103-45-247-172` grey-cloud. Нарушение → откат toggle orange + G4 FAIL.
3. LE-продление cdn-домена через CF edge (E11) — проверка `certbot renew --dry-run`
   на приёмке; fallback — временный grey на время продления (чеклист §7.1-9).

## Цикл AmneziaWG transport (фаза 4 roadmap) — ЗАВЕРШЁН 2026-11-10
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-10 (четвёртый UDP-транспорт:
  серверный модуль `src/amneziawg/`, клиентская выдача .conf, guard-минор .zshrc)
- **REQ:** [REQ-20261110-amneziawg-transport](requirements/REQ-20261110-amneziawg-transport.md) (G1 READY)
- **SPEC:** [SPEC-20261110-amneziawg-transport](specs/SPEC-20261110-amneziawg-transport.md)
  + [ADR-005](../adr/ADR-005-amneziawg-transport-decisions.md) (OQ-1..6: UDP 51825;
  клиентский режим (b) — conf + AmneziaVPN; источник — PPA `ppa:amnezia/ppa`
  (amneziawg-tools + amneziawg-dkms, kernel-модуль), mirror-конвенция не применима —
  задокументировано; AWG 1.5-набор параметров; PSK по умолчанию)
- **Этап:** ✅ G6 Close — сервер установлен на asv1 (PPA, UDP 51825, юнит с P14-фиксом),
  клиент laptop + e2e (handshake + youtube 204/0.28s через AWG-туннель с ноутбука),
  NAT/forwarding (P15) персистентны. Финальная верификация:
  [TEST-20261110-amneziawg-cdn](reports/TEST-20261110-amneziawg-cdn.md) (AWG PASS, CDN-блокер B-1 найден и закрыт).
  Эксплуатация: split-конфиг ноутбука (`~/awg0-split.conf`, awg-quick) — youtube/telegram через AWG,
  остальное напрямую; на стороне провайдера владельца youtube-SNI DPI-иммунен к zapret-стратегиям.
- **Владелец гейта:** architect → orchestrator

### Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 Генератор+рендер обфускации | vds-coder | ✅ done (fbd23d7) | — | — |
| WP-2 Install (PPA/port/UFW/юнит) | vds-coder | ✅ done (177831b, +P15) | — | — |
| WP-3 Клиенты+store/links | vds-coder | ✅ done (c782a2a) | — | — |
| WP-4 Status+remove | vds-coder | ✅ done (da4d9ba) | — | — |
| WP-5 Guard .zshrc (awg*) | vds-coder | ✅ done (35608e0, +P14-паттерн-фикс amnezia0) | — | — |
| WP-6 Приёмка [VDS] + гейт импорта в AmneziaVPN (OQ-4) | оркестратор + тестер (G4) | ✅ PASS (установка на asv1 + e2e ноутбук; импорт .conf в AmneziaVPN подтверждён трафиком 316+ МБ) | — | — |

### Гейты
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-10 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-10 | vds-analyst |
| G2 Spec | ✅ APPROVED | 2026-11-10 | vds-architect |
| G3 Build | ⏳ | — | vds-coder (WP-1..4, сериализация; WP-5 параллельно) |
| G4 Verify | ⏳ | — | vds-tester |
| G5 Docs | ⏳ | — | vds-docs |
| G6 Close | ⏳ | — | оркестратор |

### Открытые пункты цикла
1. **Гейт OQ-4:** клиентский .conf (AWG 1.5-набор) должен импортироваться в
   AmneziaVPN владельца (WP-6); отказ → правка ADR-005 на 2.0-набор (S1–S4 ≥12,
   H-диапазоны), не «fix on the fly».
2. Mirror-конвенция (ADR-001/VDS_GITHUB_MIRROR) на AWG-путь не распространяется:
   источник — Launchpad PPA; при недоступности PPA с asv1 — E1-отказ + ручной
   перенос .deb, эскалация к архитектору.

## Архив: Domain / XHTTP / ACME (фазы 3 + частично 6) — ЗАВЕРШЁН 2026-11-09
- **IDEA:** скоуп утверждён владельцем в чате 2026-11-09 (домен `103-45-247-172.eu-cloud-xip.com` → 103.45.247.172 проверен; три направления: XHTTP, ACME, домен для Reality)
- **REQ:** [REQ-20261109-domain-xhttp-acme](requirements/REQ-20261109-domain-xhttp-acme.md) (G1 READY)
- **SPEC:** [SPEC-20261109-domain-xhttp-acme](specs/SPEC-20261109-domain-xhttp-acme.md) + [ADR-003](../adr/ADR-003-xhttp-reality-coexistence.md) (OQ-1; уточнён фактом [VDS]: fallback не работает, основной режим `--mode port`) + [ADR-004](../adr/ADR-004-acme-http01-certbot.md) (OQ-2/OQ-4)
- **Этап:** ✅ G6 Close — [ACCEPT-20261109-domain-xhttp-acme](reports/ACCEPT-20261109-domain-xhttp-acme.md) PASS: LE на Hysteria2 (89 дн., автопродление), XHTTP e2e через домен:8443 (mode=port), Reality-домен; breaking-находка (старые hysteria2-ссылки требуют перевыпуска после LE) задокументирована; P13 закрыт; 226 passed <!-- docsync:ignore -->
- **Владелец гейта:** orchestrator / владелец

## Work packages
| WP | Кодер | Статус | Отчёт | Блокер |
|---|---|---|---|---|
| WP-1 ACME-выдача (certbot) | vds-coder | ✅ done | отчёт в сессии (157 passed) | — | <!-- docsync:ignore -->
| WP-2 Hysteria2 + LE | vds-coder | ✅ done | отчёт в сессии (180 passed) | — | <!-- docsync:ignore -->
| WP-3 XHTTP | vds-coder | ✅ done (+дельта path=/xhttp) | отчёт в сессии (213 passed) | fallback → --mode port (ADR-003 поправка) | <!-- docsync:ignore -->
| WP-4 Reality-домен | vds-coder | ✅ done | отчёт в сессии (223 passed) | — | <!-- docsync:ignore -->
| WP-5 Приёмка [VDS] | оркестратор + тестер (G4) | ✅ PASS | [ACCEPT-20261109-domain-xhttp-acme](reports/ACCEPT-20261109-domain-xhttp-acme.md) | — |

## Гейты
| Гейт | Статус | Дата | Кто |
|---|---|---|---|
| G0 Intake | ✅ | 2026-11-09 | owner + пользователь |
| G1 Ready | ✅ | 2026-11-09 | vds-analyst |
| G2 Spec | ✅ APPROVED | 2026-11-09 | vds-architect |
| G3 Build | ✅ | 2026-11-09 | vds-coder (WP-1..4 + follow-up D1–D3, P13) |
| G4 Verify | ✅ CONDITIONAL PASS (minor D1–D4, закрыты) | 2026-11-09 | vds-tester |
| G5 Docs | ✅ (ADR-003 поправка, ACCEPT-отчёт) | 2026-11-09 | оркестратор |
| G6 Close | ✅ | 2026-11-09 | ACCEPT PASS |

## Открытые пункты
1. **Breaking-заметка для владельца:** после `hysteria2 apply-cert` все старые
   hysteria2-ссылки (SNI=IP, insecure=1) НЕ работают (сервер отклоняет SNI≠домен) —
   перевыпустить (новые ссылки рендерятся с доменом, без insecure). Поправить
   REQ §4 и README на G5-docs follow-up.
2. OQ-5 (из REQ): пере-выдача ссылок существующим клиентам — вручную оператором,
   не автоматизирована (вне скоупа).
3. DNS-01 как запасной вариант ACME — только при появлении API-токена DNS-провайдера (будущий ADR).
4. Из прошлого цикла: TECHDEBT P4–P6; клиентская запись xhttp в state показывает
   port 443 при фактическом 8443 (косметика).

## Трассируемость
| IDEA | REQ | SPEC | Коммиты | TEST | DOC |
|---|---|---|---|---|---|
| чат 2026-11-09 | REQ-20261109-domain-xhttp-acme | SPEC-20261109-domain-xhttp-acme (+ADR-003/004) | aa01d98 (WP-1..4) + P13 | G4 CONDITIONAL PASS + ACCEPT PASS | ACCEPT-20261109-domain-xhttp-acme |

## Бэклог идей (вход для intake)

- **Точки роста схем/протоколов:** [docs/GROWTH-POINTS.md](../GROWTH-POINTS.md) —
  25 пунктов (GR-01…GR-25) с фактами, действиями и AC.
- **GR-25 (XHTTP padding/xmux) — живая приёмка 2026-11-16:** сервер
  `7af391b`, клиент `1807945`, миграция + CDN-preserve `9e43590`,
  `--skip-domain-check` `43d1ee6`. На asv1 (до его удаления) миграция
  применена (path/CDN/Reality-хэши не изменились, `xray -test` OK),
  **T-XM6 PASS**: 2–3 сокета, ротация в окне 3–5 мин, 451 МБ без разрыва.
  Отчёт: [TEST-20261116-gr25-asv1-txm6](reports/TEST-20261116-gr25-asv1-txm6.md).
  **asv1 удалён 2026-11-16** — DNS/ACME-остаток по нему снят; код GR-25
  готов для следующего XHTTP-узла (сервер + клиент).
  Долг: SHA256 `.dgst` в `vpnm/bins.py`.
- **asv1 SSH lockout — закрыт декомиссией 2026-11-16:** узел удалён
  владельцем, восстановление не требуется. Детали:
  [INCIDENT-20261116-asv1-ssh-lockout](reports/INCIDENT-20261116-asv1-ssh-lockout.md).
- **Цикл CDN-usability — G4 CLOSED 2026-11-13:**
  [SPEC-20261113-cdn-usability](specs/SPEC-20261113-cdn-usability.md),
  отчёт [TEST-20261113-cdn-mux](reports/TEST-20261113-cdn-mux.md) §9.
  Принято: TTFB p50/p95 в `vpn speed` (WP-2), CDN-baseline с контролем и
  smoke (WP-3). Откачено: mux через CF (1/5 против 5/5).
  **Проверено (2026-11-13):** XHTTP через Cloudflare **не работает** —
  [TEST-20261113-cdn-xhttp-cf](reports/TEST-20261113-cdn-xhttp-cf.md):
  CF проксирует 2083, но XHTTP (auto/packet-up/stream-up, h1/h2) — 0/2,
  таймауты; при этом XHTTP **напрямую** даёт TTFB 0.40 с (WS-CF — 2.45–2.88 с).
  Вывод: причина — маршрут CF, а не транспорт.
  **CF-эксперименты закрыты 2026-11-13 (решение владельца, результаты
  недостаточны):** mux — 1/5 против 5/5; XHTTP через CF — 0/2 (CF не
  пропускает XHTTP); [cloudflared tunnel](reports/TEST-20261113-cf-tunnel.md)
  — TTFB 2.97–4.64 с против 2.45–2.88 с, bulk 0 (HKG→AMS→NL). Инфраструктура
  откачена (туннель disabled и удалён, конфиг восстановлен).
  **CDN остаётся каналом выживания.** Возвращаться к CF-оптимизации не
  планируем; альтернатива — CDN с PoP в РФ или прямые XHTTP/Reality.
- **Цикл fresh-install-v3 — G4 code accepted 2026-11-14:**
  [SPEC-20261114-fresh-install-v3](specs/SPEC-20261114-fresh-install-v3.md),
  отчёт [TEST-20261114-fresh-install-v3](reports/TEST-20261114-fresh-install-v3.md).
  `vds gateway init` (dry-run/--apply): reality, hysteria2, acme, xhttp, cdn,
  obfs, hop, awg, healthcheck + `use-domain`; `11_vds-deploy.sh` → init
  (env `VDS_PROTOCOLS`). Закрыт GR-16 (hub). Осталось: приёмка на чистой VM
  (AC-1/3/4) — владелец.
- **xray-split (Reality/XHTTP) — G4 PASS (2026-11-14):**
  [SPEC-20261114-xhttp-split](specs/SPEC-20261114-xhttp-split.md),
  [TEST-20261114-xhttp-split](reports/TEST-20261114-xhttp-split.md).
  tun/unit/rules/kill-switch PASS; vpnm 392 теста. Серверный Xray обновлён <!-- docsync:ignore -->
  до 26.1.23 (ADR-010); Reality/XHTTP/CDN/Hy2 проверены. Ноутбук: youtube 204
  через split, example.com 200, ya.ru напрямую, `vpn monitor` ok,
  kill-switch и `vpn reset` — PASS. Схема обобщена: `vpn scheme xray-split
  [profile]` работает и для Reality (`phone`), и для XHTTP (`xhttp-web`);
  `xhttp-split` — алиас. Быстрый вход: `vpn start reality`,
  `vpn start xhttp` (`vpn start` по умолчанию — AWG). Исправлены: петля
  xray→свой tun (sockopt.mark),
  порядок DoH + ожидание готовности, один dnsmasq-конфиг,
  mkdir /etc/vpn-manager.
- **OS baseline (2026-11-14):** [SERVER-BASELINE](../SERVER-BASELINE.md) —
  инвентарь настроек ОС/сервера (авто vs вручную), UFW-матрица портов,
  чеклист восстановления агентом, дрейф asv1 (UFW off, swap 0, SSH-пароли,
  Docker нет).
- **Roadmap v2 (2026-11-13, ревизия архитектора):**
  [CENSORSHIP-ROADMAP](../CENSORSHIP-ROADMAP.md) — фазы 0–9 переведены в
  «статус + остаток», остаток разложен на волны **W1–W6**; W1 (hook+healthcheck)
  и W2 (per-user auth, [ADR-009](../adr/ADR-009-hysteria2-per-client-auth.md) —
  **proposed**) готовы к intake. Дефекты/долг — [TECHDEBT.md](../../TECHDEBT.md).

## Архитектурные решения (вне циклов)

### ZeroTier → архив/опционально (2026-11-10, решение владельца)
- **Пользовательский VPN-канал полностью заменён** gateway-стеком (Reality/XHTTP/
  Hysteria2 + AWG в работе): ZeroTier не нужен ни одному клиентскому сценарию
- Модуль `src/zerotier/` **сохраняется как опциональная утилита** (приватная
  management-сеть, ZTNET-панель); из основного пути деплоя ([DEPLOY.md](../DEPLOY.md),
  11_vds-deploy.sh) не входит и не будет входить
- Будущие баги ZT-стека (watchdog/reconcile/ZTNET) чинить по остаточному принципу,
  не поднимать их приоритет — приоритет gateway-стека выше
- Формальный признак в guard-скриптах (_check_vpn_active): ZT/WG остаются
  валидными признаками «VPN активен», но не обязательными

## Завершённые циклы

### Gateway MVP (фазы 0–2) — ЗАВЕРШЁН 2026-11-09
- **REQ:** [REQ-20261107-gateway-mvp](requirements/REQ-20261107-gateway-mvp.md) · **SPEC:** [SPEC-20261107-gateway-mvp](specs/SPEC-20261107-gateway-mvp.md) + [ADR-001](../adr/ADR-001-xray-install-mechanism.md) + [ADR-002](../adr/ADR-002-gateway-paths-units-state.md)
- Гейты G0–G6 все ✅; G6 Close — [VDS]-приёмка PASS 2026-11-09 ([ACCEPT-20261109](reports/ACCEPT-20261109-vds-asv1.md)): оба протокола на asv1, e2e подтверждён; закрыты P7–P12 + VDS_GITHUB_MIRROR (коммиты c1e7886..e5ececb).
- WP: WP-1 P1–P3+tests, WP-2 core, WP-3 gateway store+CLI, WP-4 Xray Reality, WP-5 Hysteria2 — все ✅ done.
- Наследованный бэклог: TECHDEBT P4–P6; баг install.sh:74 (`cp -r` на себя, ORCH-20261109 §4); pytest вне requirements (нужен requirements-dev.txt); глобальный фильтр маскирования логов → фаза 6; `HYSTERIA2_BIN_PATH` → `gateway/paths.py` при следующем ADR.
