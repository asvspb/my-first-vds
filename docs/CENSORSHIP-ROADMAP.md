# Roadmap: VDS Orchestrator — транспортные схемы и развитие

> **Версия:** 2 (ревизия архитектора) · **Дата:** 2026-11-13
> **База:** `vds` @ `73a0383` (499 unit), `ubuntuInstaller` @ `ea2b662` (vpnm 325 unit),
> сервер `asv1` (Ubuntu 24.04) — Reality, XHTTP, CDN, Hysteria2(+obfs), AWG, ACME в работе.
>
> **Что изменилось против v1:** фазы 0–4 фактически закрыты (включая CDN, ACME,
> hop/obfs и AmneziaWG), поэтому «план» переписан в «статус + остаток»; остаток
> разложен на волны W1–W6 и привязан к пунктам
> [GROWTH-POINTS](GROWTH-POINTS.md) (GR-01…GR-24) и [TECHDEBT](../TECHDEBT.md).
> Архитектурное решение по per-client auth — [ADR-009](adr/ADR-009-hysteria2-per-client-auth.md).
>
> Связанные документы: [VPN-PROTOCOLS.md](VPN-PROTOCOLS.md),
> [SPLIT-TRANSPORTS.md](SPLIT-TRANSPORTS.md) (AWG и аналоги в split-схеме),
> [CDN-FRONTS.md](CDN-FRONTS.md), [DEPLOY.md](DEPLOY.md),
> [docs/team/STATUS.md](team/STATUS.md), [docs/adr/](adr/).

---

## 1. Цели, модель угроз и границы

### 1.1. Цель

Превратить `vds` из «набора отдельных VPN-команд» в **self-hosted платформу обхода
блокировок**: один сервер раздаёт несколько транспортных профилей, клиент
переключается автоматически, оператор управляет всем из одного CLI/TUI.

### 1.2. Модель угроз

| Угроза | Проявление | Ответ (что уже есть / что в плане) |
|---|---|---|
| DPI-детект по фингерпринту | ТСПУ ловит TLS/WS-паттерны | Reality ✅, XHTTP ✅, Hysteria2+obfs ✅ |
| Троттлинг по протоколу | скорость ≈0 при живом соединении | смена L4-типа ✅ (TCP/UDP), hop — W4 |
| Блокировка по IP | IP сервера в реестре | CDN-фронт ✅ (один домен), пул фронтов — W4 |
| Active probing | цензор сам стучится в порт | Reality fallback ✅, decoy-маска Hysteria2 ✅, probe-тест — W6 |
| Блокировка UDP целиком | QUIC/AWG мёртв | TCP-резерв ✅ (Reality/XHTTP/CDN) |
| Блокировка TCP 443 | Reality/XHTTP/CDN мёртв | UDP-резерв ✅ (Hysteria2/AWG) |
| Утечка/компрометация ссылки | доступ у постороннего | **нет**: один пароль на всех → W2 (ADR-009) |
| Тихий сбой сервиса/сертификата | «вчера работало» | healthcheck — W1 |

### 1.3. Non-goals

- Публичный сервис подписок и агрегация чужих конфигов — отдельная модель, не наша.
- «Невидимый» протокол против целевого государства — только пассивный DPI и
  активное зондирование.
- Веб-панель/GUI (решение владельца, STATUS 2026-11-10), покупка VPS/доменов.
- Замена certbot собственной реализацией ACME — выигрыша нет.

### 1.4. Принципы

1. **Defense in depth** — минимум два транспорта разных L4-типов + fallback.
2. **Mimicry over encryption tricks** — трафик выглядит как легитимный.
3. **Probe resistance** — без валидного аутентификатора сервер ведёт себя как веб.
4. **Отзыв доступа — часть модели**, а не побочный эффект (новое, W2).
5. **Автоматизация секретов и ротации**; конфиги 0600, атомарная запись.
6. **Declarative state** — `state.json` как источник истины, идемпотентное применение.
7. **Отказоустойчивость** — healthcheck + rate-limited restart (по образцу ZeroTier).
8. **Проверяемость** — unit + Docker-e2e; живая приёмка на VDS по чеклисту.
9. **Минимальное логирование** PII и секретов.

---

## 2. Фактическая архитектура (as-is, 2026-11-13)

```
                    ┌────────────────────────────────────────────┐
                    │  Клиенты: v2rayNG · Hiddify/NekoBox/SFA ·  │
                    │  sing-box · AmneziaVPN                     │
                    └───────────────┬────────────────────────────┘
                                    │ share-link / QR / pull (ssh)
                                    ▼
┌──────────────────── Управление: vds CLI (root) ─────────────────────┐
│ gateway status|links|blockcheck · xray/hysteria2/amneziawg/acme     │
│ state: /opt/my-vds/gateway/state.json (0600, version=1)             │
└──────┬───────────────────┬───────────────────┬─────────────────────┘
       │                   │                   │
┌──────▼───────┐   ┌───────▼────────┐   ┌──────▼─────────┐
│ Xray-core    │   │ Hysteria2      │   │ AmneziaWG      │
│ TCP 443      │   │ UDP 443        │   │ UDP 51825      │
│ Reality      │   │  └ obfs 51826  │   │ obfuscated WG  │
│  └ XHTTP:8443│   │  └ hop 20k-20.5k│  │                │
│  └ CDN :2053 │   │                │   │                │
└──────┬───────┘   └───────┬────────┘   └──────┬─────────┘
       │ fallbacks (SNI)   │                   │
       └───────────────────┴───────────────────┘
                           ▼
              ACME/certbot (LE, HTTP-01, deploy-hook)
              sysctl/BBR · systemd-юниты из шаблонов
```

Ключевые отличия от v1-диаграммы: **Nginx stream/SNI-мультиплексор не нужен** —
сосуществование Reality/XHTTP решено `fallbacks` внутри Xray (ADR-003);
CDN-транспорт — отдельный origin-инблэнд на TCP 2053 (ADR-006); hop — nat-цепочка
`VDS_HY2_HOP` (ADR-008).

### 2.1. Слои (as-is)

| Слой | Компонент | Состояние |
|---|---|---|
| Транспорт | Xray (Reality/XHTTP/CDN), Hysteria2 (+obfs/hop), AWG | ✅ работает на asv1 |
| Мультиплексирование | Xray fallbacks (SNI), отдельные порты | ✅ |
| Оркестрация | `src/gateway/` (state, links, blockcheck) | ✅, hub/init — нет (W5) |
| Наблюдаемость | `src/sysinfo/` (железо), `status`-команды | ⚠️ нет таймера/метрик (W1, W5) |
| Дистрибуция | share-links, `profile pull` (ssh) | ⚠️ QR/подписки — вручную (W3) |
| Клиент | `vpnm` схемы proxy/cdn/private/awg | ⚠️ failover вручную (W5) |

---

## 3. Матрица протоколов и сценариев (с фактическим статусом)

| # | Профиль | Транспорт | Когда | Приоритет | Статус |
|---|---|---|---|---|---|
| 1 | VLESS + Reality (Vision) | TCP 443 | базовый, жив TCP | P0 | ✅ на asv1 |
| 2 | Hysteria2 | UDP 443 QUIC | mobile, потери, скорость | P0 | ✅ на asv1 |
| 3 | Hysteria2 + obfs (salamander) | UDP 51826 | прячется голый QUIC | P0 | ✅ на asv1 |
| 4 | Hysteria2 + port hopping | UDP 20k–20.5k → 443 | троттлинг по порту | P1 | ⚠️ код есть, не включён (W4) |
| 5 | VLESS + WS + TLS за CDN | TCP 2053 (origin) | блок IP / fronting | P1 | ✅ на asv1 (1 фронт) |
| 6 | VLESS XHTTP (fallback) | TCP 8443 (loopback) | TCP-резерв для Xray-клиентов | P1 | ✅, но клиенты ограничены |
| 7 | AmneziaWG | UDP 51825 | деградация Xray/QUIC | P1 | ✅ на asv1 |
| 8 | NaiveProxy / HTTP2 CONNECT | TCP 443 | ловля Reality по фингерпринту | P2 | ❌ |
| 9 | TUIC v5 | UDP QUIC | альтернатива Hysteria2 | P2 | ❌ (не планируем в W1–W6) |
| 10 | Snowflake/WebRTC | P2P | крайний случай | P3 | ❌ (вне скоупа) |

---

## 4. Фазы 0–9: фактический статус

| Фаза (v1) | Заявлено | Факт 2026-11-13 | Остаток |
|---|---|---|---|
| 0 Фундамент | core/*, adapter, store | ✅ core, protocol, store, units, secrets, lock | — |
| 1 Reality | install/clients/status | ✅ Reality на asv1 | update-путь (W4) |
| 2 Hysteria2 | install/clients/sysctl | ✅ + obfs + hop-код | per-user auth (W2), hop включить (W4) |
| 3 XHTTP + CDN | SNI-мультиплексор, CF | ✅ XHTTP-fallback, CDN origin 2053 | пул фронтов + проверка (W4) |
| 4 AmneziaWG | install/conf/QR | ✅ install/conf/status | QR (W3), ротация/purge (W6) |
| 5 Hub + подписки | init, sub, reconcile | ❌ нет | W3 (export/sub), W5 (init) |
| 6 Hardening | ACME, decoy, rotate | ⚠️ ACME HTTP-01 ✅, hook — дефект | hook (W1), DNS-01 (W5), rotate (W2/W6) |
| 7 Наблюдаемость | healthcheck, metrics, alerts | ❌ нет | W1 (health), W5 (metrics/alerts) |
| 8 Тесты/CI | unit + Docker-e2e + CI | ⚠️ unit ✅ (499/325), CI/e2e нет | W6 |
| 9 Дистрибуция | export qr/conf, TUI | ⚠️ links + pull по ssh | W3 (export/sub), W5 (TUI) |

---

## 5. Волны развития (W1–W6)

Оценки — инженерные дни без ревью и живой приёмки. Каждая волна — отдельный цикл
с гейтами G0–G6 (см. [TEAM.md](TEAM.md)); REQ делает аналитик, SPEC — архитектор.

### W1. Страховка от тихих сбоев — P0, ~2 дня

**Зачем:** сейчас сбой сертификата или юнита замечается только вручную, а
deploy-hook ACME обновляет **один** юнит из трёх.

| Пункт | Суть | DoD |
|---|---|---|
| GR-01 | hook обновляет `vds-hysteria2`, `vds-hysteria2-obfs`, `vds-xray` | `renew --dry-run` → новые отпечатки у всех трёх |
| GR-18 | `gateway healthcheck` + `systemd/vds-gateway-health.*` | stop юнита → восстановление ≤2 цикла; rate-limit |
| GR-12 | срок сертификата в healthcheck (`<14` warning, `<7` error) | симуляция истечения → warning |

**Файлы:** `src/acme/install.py`, новый `src/gateway/health.py`, `systemd/`, тесты.
**Гейты:** G2 (SPEC), G4 (живая приёмка на asv1).

### W2. Per-client auth Hysteria2 — P0, ~1.5 дня

**Зачем:** архитектурный потолок — сейчас нельзя отозвать клиента, утечка одной
ссылки компрометирует всех.

**Решение (ADR-009, proposed):** `auth.type: http` → локальный агент на loopback,
пользователи в `state.json` (schema v2), ссылки `user:pass@`.

| WP | Файлы | DoD |
|---|---|---|
| WP-1 store v2 + миграция | `gateway/store.py`, `tests/gateway/` | v1 читается, миграция идемпотентна, `default`-пользователь = старый пароль |
| WP-2 агент + юнит | новый `hysteria2/auth.py`, `systemd/vds-hy2-auth.service.tpl` | loopback-only, токен из state, лог без паролей |
| WP-3 config+install | `hysteria2/config.py|install.py` | `auth.http`, бэкап `.bak-pre-auth`, рестарт обоих инстансов |
| WP-4 clients/rotate | `hysteria2/clients.py`, `main.py` | `add/resolve` user:pass, `rotate-user`, `remove-client` отзывает |
| WP-5 status+docs | `hysteria2/status.py`, `VPN-PROTOCOLS.md` | «auth: http (N users)», e2e alice/bob |

**Риски:** fail-closed при падении агента → `Restart=always` + W1-healthcheck.
**Гейты:** G2 (ADR-009 accepted), G4 (e2e на asv1: alice → remove → 401, bob жив).

### W3. Поставка клиентам: QR, конфиги, подписки — P1, ~2.5 дня

**Зачем:** QR делается руками (`qrencode`), AWG-конфиг не отдаётся содержимым,
мобильные клиенты не умеют `ssh pull`.

| Пункт | Суть | DoD |
|---|---|---|
| GR-15 | `gateway export --format qr\|conf\|uri\|sub\|clash\|singbox` | QR сканируется (`zbarimg`), `sub` импортируется в v2rayNG/Hiddify |
| GR-17 | `gateway sub serve --port 8081 --token` (systemd) | 401 без токена, логи без секретов |
| GR-22 | флаги pull в TUI vpnm | TUI импортирует `mob`/`mob@obfs` |

**Файлы:** новый `src/gateway/export.py`, `src/subscriptions/`, `systemd/`,
`vpnm/tui.py`.
**Зависимости:** W2 не блокирует; после W2 ссылки становятся `user:pass` — экспорт
должен уметь оба формата.

### W4. Эксплуатация транспортов — P1, ~4 дня

| Пункт | Суть | DoD |
|---|---|---|
| GR-03 | включить hop на asv1 + матрица клиентов | tcpdump видит смену dst-портов; `status` показывает hop |
| GR-06 | `xray update [--apply]` | dry-run версий, откат на `.bak-old`, Reality-gate жив |
| GR-08 | `xray cdn-check` + пул фронтов | мёртвый фронт помечен, ссылка не выдаётся |
| GR-07 | `xray set-sni` + локальная проба decoy | смена SNI перевыпускает ссылки, `status` алертит мёртвый decoy |
| GR-09 | XHTTP: зафиксировать «xray-only» в матрице | док + TUI-фильтр |

**Зависимости:** GR-06 — до GR-07 (SNI-команда опирается на актуальный конфиг).

### W5. Оркестрация, подписки, наблюдаемость — P1/P2, ~5–6 дней

| Пункт | Суть | DoD |
|---|---|---|
| GR-16 | `gateway init` (hub, `--apply`) | чистая ВМ → ≥3 транспорта; идемпотентно |
| GR-19 | трафик по клиенту (`xray api stats`, `/metrics`) в `sysinfo` | uuid→имя, `--json` |
| GR-20 | `gateway backup/restore` + webhook-алерты | restore восстанавливает ссылки 1:1 |
| GR-11 | ACME DNS-01 + `acme status` | wildcard без порта 80 |
| GR-21 | `vpn scheme auto` (failover по probe) | блок 443 → переключение на CDN ≤2 цикла |

**Зависимости:** GR-19 ← W2 (имена пользователей), GR-21 ← W4 (живые профили),
GR-20 ← W1 (healthcheck-хук для алертов).

### W6. Инженерная гигиена и остаток P2 — ~4 дня

| Пункт | Суть |
|---|---|
| GR-24 | CI (ruff + pytest 3.10/3.12) + `tests/e2e/` (hysteria2/xray ↔ sing-box, `--check` конфигов) |
| GR-04 | `hysteria2 rotate-password` (main-инбаунд) |
| GR-05 | obfs `gecko` опция + `pinSHA256`-ссылки |
| GR-10 | явный `cert_domain` + миграция state |
| GR-13/14 | AWG rotate-obfuscation, purge, IPv6-профиль |
| GR-23 | blockcheck: кэш, локальные контрольные хосты |

---

## 6. Целевая структура модулей (обновлено)

```
src/
├── core/            logger, shell, lock, protocol, netcheck, secrets, units
├── xray/            Reality/XHTTP/CDN: install, config, clients, status, cdn, remove
│                    + update.py (W4), decoy-проба в status (W4)
├── hysteria2/       install, config, clients, hop, obfs, sysctl, status, remove
│                    + auth.py (W2), rotate.py (W2/W6)
├── amneziawg/       install, clients, config, status, remove
│                    + obfuscation-ротация/purge (W6)
├── acme/            install (HTTP-01 hook), apply_cert
│                    + dns01 (W5), status (W5)
├── gateway/         paths, store (schema v2 — W2), links, blockcheck
│                    + health.py (W1), export.py (W3), init.py (W5), backup.py (W5)
├── subscriptions/   formats + serve (W3)
├── sysinfo/         dashboard (+ stats W5)
└── system/          setup, cleanup, network_tuning
systemd/             vds-xray · vds-hysteria2(-hop/-obfs) · vds-amneziawg
                     + vds-hy2-auth (W2) · vds-gateway-health (W1) · vds-gateway-sub (W3)
tests/               unit (есть) + e2e/ Docker (W6)
```

---

## 7. Раскладка портов (фактическая)

| Порт | Что | Примечание |
|---|---|---|
| TCP 443 | Xray Reality (+ fallbacks на XHTTP) | основной TCP-транспорт |
| TCP 8443 | Xray XHTTP | **только loopback**, снаружи не слушается |
| TCP 2053 | CDN origin (VLESS+WS+TLS) | CF HTTPS-порт; edge-порт = origin |
| TCP 80 | ACME HTTP-01 | только на время выдачи/продления |
| UDP 443 | Hysteria2 | основной UDP-транспорт |
| UDP 20000–20500 | hop-диапазон → REDIRECT на 443 | nat-цепочка `VDS_HY2_HOP` (W4) |
| UDP 51826 | Hysteria2 obfs (salamander) | отдельный инстанс |
| UDP 51825 | AmneziaWG | awg0, 10.9.0.0/24 |
| TCP 22 | SSH | UFW limit (политика — DEPLOY) |
| loopback (W2) | hy2-auth http-agent | порт из `gateway/paths.py` |

---

## 8. Данные и секреты

- `state.json` — `/opt/my-vds/gateway/state.json`, 0600, `version=1` → **v2 (W2)**.
- Конфиги: `/usr/local/etc/xray/config.json`, `/etc/hysteria/{config,obfs}.yaml`,
  `/etc/amnezia/awg0.conf` — 0600.
- Клиентские артефакты: `/opt/my-vds/gateway/clients/amneziawg/*.conf` — 0600.
- LE: `/etc/letsencrypt/live/<domain>/` + deploy-hook `vds-hysteria2-cert.sh`.
- Правила: приватные ключи и пароли не попадают в share-link (кроме самого link),
  логи, git; атомарная запись (`core.secrets.write_secret_atomic`); файловые
  манифесты не дублируют секреты.
- **Новое (W2):** пользователи Hysteria2 — в state; агент — только loopback,
  сравнение паролей — constant-time, токен агента — секрет.

---

## 9. Риски и меры (обновлено)

| Риск | Вер. | Влияние | Мера |
|---|---|---|---|
| Сертификат продлился, юнит не перечитал | **высокая** | тихий отказ hy2-obfs/Xray | W1 (GR-01) + healthcheck |
| Утечка ссылки = доступ всем | высокая | компрометация | W2 (ADR-009), per-user revoke |
| Per-user auth: агент упал | средняя | fail-closed, все 401 | `Restart=always` + healthcheck W1 |
| Клиент не поддерживает obfs/hop | средняя | «не работает у пользователя» | матрица клиентов (W4), warning при pull |
| Дрейф версии Xray-core | средняя | несовместимость с Mihomo/новыми клиентами | W4 (`xray update`), матрица версий |
| CDN: один фронт, нет проверки | средняя | блок IP = нет резерва | W4 (пул + `cdn-check`) |
| Нет бэкапа state | средняя | потеря клиентов/секретов | W5 (`backup/restore`) |
| Регресс схемы конфига (как `obfs.salamander.password`) | средняя | сервис не стартует | W6 (CI + `--check` в e2e) |
| Живой VDS нужен для приёмки | высокая | долгие циклы | минимум e2e в Docker + чеклист |

---

## 10. Метрики успеха (пересмотрено)

1. Чистый Ubuntu 24.04 + `install.sh` + `vds gateway init --apply` → рабочий
   сервер за ≤ 10 минут (W5).
2. ≥3 транспорта разных L4-типов по умолчанию; hop и obfs включены осознанно (W4).
3. **Отзыв клиента работает за одну команду** и подтверждается e2e (W2).
4. Клиент получает подписку/QR одной командой, без ручного `qrencode` (W3).
5. Probe-resistance: сканер без SNI/аутентификатора видит decoy (W4/W6).
6. healthcheck восстанавливает сервис за ≤2 цикла; сертификат не протухает (W1).
7. CI зелёный (unit + Docker-e2e), включая кейс «конфиг проходит `--check`» (W6).
8. Ноль секретов в логах/git (тест есть, расширяется на агент W2).

---

## 11. График (ориентир, после ревизии)

| Неделя | Волна | Результат |
|---|---|---|
| 1 | W1 | hook на все юниты, healthcheck-таймер, срок сертификата |
| 2 | W2 | per-user auth (ADR-009), schema v2, отзыв клиента |
| 3 | W3 | `gateway export` (qr/sub/conf), подписка по токену, TUI-флаги |
| 4 | W4 | hop включён, `xray update`, пул фронтов, decoy-проба |
| 5 | W5 | `gateway init`, метрики, backup, DNS-01, `vpn scheme auto` |
| 6 | W6 | CI + Docker-e2e, ротация паролей/обфускации, `cert_domain` |

**Минимальный полезный релиз (MVP-2):** конец 2-й недели — W1+W2 (надёжность +
управляемый доступ) на уже работающем стеке.

---

## 12. Что делаем первым действием

1. **W1, GR-01** — правка deploy-hook (наименьшая цена, наибольший риск снят).
2. **W2, ADR-009 → accepted** — SPEC на per-user auth (WP-1…WP-5), затем код.
3. **W1, GR-18** — healthcheck-таймер (переиспользует rate-limit ZeroTier-watchdog).

Детализация пунктов, файлов и AC — в [GROWTH-POINTS.md](GROWTH-POINTS.md);
дефекты и долг — в [TECHDEBT.md](../TECHDEBT.md).

## 13. Источники практик

- [Project X / Xray-core](https://github.com/XTLS/Xray-core) — VLESS, REALITY, XHTTP.
- [SagerNet / sing-box](https://github.com/SagerNet/sing-box) — универсальное ядро и формат подписок.
- [apernet / hysteria](https://github.com/apernet/hysteria) — Hysteria2, QUIC, obfs, auth.
- [amnezia-vpn / amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — обфускация WireGuard.
- [klzgrad / naiveproxy](https://github.com/klzgrad/naiveproxy) — HTTP/2 CONNECT мимикрия.
- [TSPU throttling analysis — Habr](https://habr.com/en/articles/990236) — поведение цензора.
