# SPEC-20261109-domain-xhttp-acme

## Мета
- **Источник:** [REQ-20261109-domain-xhttp-acme](../requirements/REQ-20261109-domain-xhttp-acme.md)
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-09
- **Статус:** approved (G2)
- **ADR:** [ADR-003](../../adr/ADR-003-xhttp-reality-coexistence.md) (OQ-1: Reality+XHTTP на 443),
  [ADR-004](../../adr/ADR-004-acme-http01-certbot.md) (OQ-2/OQ-4: HTTP-01 + certbot)

## 1. Цель и решение

Добавить к живому прод asv1 (Reality TCP 443, Hysteria2 UDP 443) три работы:
(1) LE-сертификат на домен по HTTP-01 через certbot из apt и подмена
self-signed у Hysteria2 с авторотацией deploy-hook'ом; (2) VLESS XHTTP
(TLS по домену), слушающий на TCP 443 того же процесса Xray через
SNI-фолбэк на loopback 127.0.0.1:8443 — ноль новых публичных портов;
(3) минорный WP «домен для Reality»: только адрес в store/ссылках,
`dest`/`serverNames` не трогаем. Порядок реализации гарантирует: сначала
ACME (не касается 443/TCP), затем XHTTP (касается TCP 443 — самый
рискованный шаг идёт с verify-гейтом и бэкапом), затем Reality-домен.
OQ-3 вердикт: включаем (низкая стоимость, ссылки переживают смену IP;
конфиг Xray не меняется).

## 2. Архитектура

```
внешние клиенты
  ├─ Reality (TCP 443)  ──► Xray v25.1.1, inbound#1: vless+reality (без изменений в realitySettings)
  │                          streamSettings.fallbacks → alpn http/1.1,h2 → 127.0.0.1:8443
  ├─ XHTTP  (TCP 443)  ──► Xray, inbound#2 (127.0.0.1:8443): vless+xhttp+tls(cert=LE)
  └─ Hysteria2 (UDP 443) ─► vds-hysteria2, tls cert=/etc/hysteria/cert.pem (LE после WP-2)

certbot (apt) → LE HTTP-01 на :80 (standalone, секунды) 
             └─ renewal-hooks/deploy/vds-hysteria2-cert.sh → бэкап+копия cert/key (0600) → restart vds-hysteria2
```

Точки отказа: Xray restart при добавлении XHTTP (единственный TCP-downtime,
короткий, восстанавливаемый); certbot.timer (провал продления не валит
сервис — E3). Порт 80 по архитектуре свободен всегда — HTTP-01 устойчив.

**Формат данных:** `state.json` (ADR-002) дополняется:
`domain: "<домен>"` (уже есть в модели), `protocols["xhttp"] = {"port": 8443,
"mode": "fallback"}`, в `ClientProfile.extra["transport"] = "xhttp"` для
XHTTP-клиентов; Hysteria2-клиенты получают `sni=<домен>` и ссылку без
`insecure=1` при наличии домена+LE.

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/gateway/paths.py` | изменить | + `ACME_LETSENCRYPT_LIVE(dir-функция от домена)`, `XHTTP_INTERNAL_PORT=8443`, `XRAY_HTTP_BIND="127.0.0.1"` |
| `src/acme/__init__.py`, `src/acme/install.py` | создать | certbot из apt (проверка порта 80, netcheck DNS), issue/renew-статус, deploy-hook рендер+установка |
| `src/acme/apply_cert.py` | создать | подмена self-signed→LE у Hysteria2 (dry-run по умолчанию, бэкап `.bak-pre-le`, restore) |
| `src/hysteria2/clients.py` | изменить | share-link: при домене+LE в state — `hysteria2://…@<домен>:443/?sni=<домен>` без `insecure=1`; иначе как сейчас (строки 37–54) |
| `src/hysteria2/status.py` | изменить | + издатель/notAfter/остаток дней сертификата, рассинхрон домен-vs-self-signed (E10) |
| `src/hysteria2/config.py` | без изменений | cert/key пути уже параметризованы рендером |
| `src/xray/config.py` | изменить | рендер: опциональные `fallbacks` в streamSettings + второй XHTTP-inbound (детерминированный порядок ключей; `XrayConfigParams` + поля `domain, cert_path, key_path, xhttp_enabled`) |
| `src/xray/install.py` | изменить | `add_transport_xhttp(domain, mode)`: бэкап config.json → рендер → `xray -test` → restart; отказ если DNS≠IP (E1) или битый конфиг (E8); идемпотентность |
| `src/xray/remove.py` | изменить | `remove_transport_xhttp(apply)`: вычитание фолбэка/инблянда/XHTTP-клиентов, dry-run по умолчанию |
| `src/xray/clients.py` | изменить | `add_client(..., transport="reality")`: для `xhttp` — ссылка `security=tls&network=xhttp` с доменом; `use_domain` перегенерация адреса Reality-ссылок |
| `src/xray/status.py` | изменить | + XHTTP: порт/mode/сертификат |
| `src/main.py` | изменить (сериализовано: WP-1,2,3,4) | ленивые импорты, новые команды (§ CLI) |
| `systemd/` | без изменений | certbot.timer штатный; хук — не юнит |
| `tests/acme/`, `tests/xray/test_config_xhttp.py`, `tests/xray/test_links_xhttp.py`, `tests/hysteria2/test_links_domain.py` | создать | § 6 |

**Публичные интерфейсы (сигнатуры, не реализация):**

```python
# src/acme/install.py
def issue_certificate(domain: str, email: str) -> dict: ...      # {"cert":…, "days_left":…}; идемпотентно
def install_deploy_hook(domain: str) -> bool: ...
# src/acme/apply_cert.py
def apply_certificate(dry_run: bool = True) -> dict: ...
def restore_self_signed() -> dict: ...
# src/xray/install.py
def add_transport_xhttp(domain: str, mode: str = "fallback") -> dict: ...
# src/xray/config.py
def render_config(params: XrayConfigParams) -> str               # обратимо-совместимо: без xhttp-полей рендер байт-в-байт как сейчас
```

**CLI-поверхность:**

```bash
vds acme issue --domain <d> --email <e> [--dry-run]
vds hysteria2 apply-cert [--apply]      # dry-run по умолчанию; --restore откат
vds xray add-transport xhttp --domain <d> [--mode fallback|port]
vds xray remove-transport xhttp [--apply]
vds xray add-client <name> --transport xhttp
vds xray use-domain --domain <d>        # Reality: только store+ссылки (OQ-3)
```

## 4. Миграция и совместимость

- `state.json` обратно совместим: новые ключи — опциональные поля/словари;
  старые клиенты (`phone`, `mob`) не мигрируются, старые ссылки работают
  (инвариант REQ §4; client `mob` с insecure=1 не ломается подменой сертификата).
- `render_config` без xhttp-полей обязан выдавать текущий вывод байт-в-байт
  (юнит-тест золотым снапшотом) — иначе WP-3 блокируется.
- ADR нужны и написаны: ADR-003 (изменение живого конфига 443 — необратимо
  по духу: формат config.json с двумя инблндами), ADR-004 (выбор ACME-клиента).

## 5. Безопасность и отказы

- Секреты: LE key 0600 (`/etc/letsencrypt/...` — права certbot + наш хук
  копирует 0600); приватный материал не в логах/выводе/share-links.
- Dry-run: `apply-cert`, `remove-transport` — dry-run по умолчанию + `--apply`.
- Бэкап перед мутацией: `config.json` и `config.yaml`, `cert.pem/key.pem`
  (`.bak-pre-le`) — путь в выводе команды.
- Failure modes: E1 DNS≠IP → отказ до изменений; E2 порт 80 занят → читаемый
  отказ; E3 провал продления → старый сертификат работает; E4 идемпотентность
  каждого шага; E6/E7 загрузок нет (certbot из apt — github не участвует);
  E8 битый config.json → бэкап+отказ, `xray -test` гейтит рестарт; E10
  рассинхрон домен/self-signed → видно в `hysteria2 status`.
- Откат по WP — в таблице WP (§7) и в ADR-003/004 «Как откатить».

## 6. Тест-план

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | `render_config` с xhttp: валидный JSON, детерминизм, realitySettings не изменился, fallbacks+инблэнд присутствуют; золотой снапшот старого рендера | `tests/xray/test_config_xhttp.py` |
| Unit | XHTTP share-link формат: `security=tls&network=xhttp`, домен, нет private-key/key-пути в строке; hysteria2-линк: домен+LE → без insecure=1, sni=домен | `tests/xray/test_links_xhttp.py`, `tests/hysteria2/test_links_domain.py` |
| Unit | acme: рендер deploy-hook, логика «валиден → не перегенерировать», парсинг days_left на моках | `tests/acme/` |
| Unit | store: domain/protocols.xhttp сериализация, E10 рассинхрон-детект | `tests/gateway/` (доп. кейсы) |
| Integration (Docker, опц. в этом цикле) | — | не входит (фаза 8 roadmap) |
| Ручная приёмка (VDS asv1) | AC [VDS] REQ + секция «Не ломать» (§4 REQ): phone/mob по старым ссылкам, probe curl чужой SNI, ss-раскладка, права 0600, grep секретов в journal | чеклист ACCEPT |

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| **WP-1** ACME-выдача | `src/acme/` (install.py: certbot apt, issue, deploy-hook), paths.py-добавки, CLI `acme issue`, `tests/acme/` | `src/acme/*`, `src/gateway/paths.py`, `src/main.py` | — | `compileall` + `pytest -q` зелёный; issue-идемпотентность покрыта юнит-тестом; hook рендерится без секретов; команды без root дают читаемый отказ |
| **WP-2** Hysteria2+LE | `apply_cert.py` (apply/restore, dry-run, бэкап), линк без insecure при домене+LE, status cert-info/E10, CLI `hysteria2 apply-cert`, тесты | `src/acme/apply_cert.py`, `src/hysteria2/{clients,status}.py`, `tests/hysteria2/test_links_domain.py` | WP-1 | pytest зелёный; dry-run по умолчанию; restore-путь покрыт тестом на temp-каталогах; старая insecure-ссылка продолжает рендериться без изменений |
| **WP-3** XHTTP | рендер (fallbacks+инблэнд, mode-флаг), add/remove-transport с `xray -test` и бэкапом, xray-клиент `--transport xhttp` + share-link, xray-status, CLI | `src/xray/{config,install,remove,clients,status}.py`, `tests/xray/test_config_xhttp.py`, `tests/xray/test_links_xhttp.py` | WP-1 (нужен LE-cert) | pytest зелёный; золотой снапшот старого рендера байт-в-байт; E1/E8 покрыты юнит-тестами; **[VDS] verify-гейт**: на asv1 `phone` работает по старой ссылке после добавления XHTTP ДО приёмки XHTTP — иначе откат и `--mode port` (ADR-003) |
| **WP-4** Reality-домен (минорный, OQ-3 включён) | `xray use-domain`: state.domain + перегенерация Reality-адреса ссылок; dest/serverNames не меняются | `src/xray/clients.py`, `src/main.py` | WP-3 | pytest зелёный; юнит-тест: рендер Reality-конфига при use-domain не содержит домена в dest/serverNames; идемпотентность |
| **WP-5** Приёмка | чеклист ACCEPT: AC [VDS] REQ + «Не ломать» §4 REQ по промежуточным гейтам и финально | `docs/team/reports/ACCEPT-*.md` | WP-1..4 | отчёт PASS/FAIL; Breaking любой → откат WP-источника, цикл не принят |

Пересечение файлов: `src/main.py` и `src/xray/clients.py` затрагиваются
несколькими WP → **сериализация строго по порядку WP-1→2→3→4**, параллельное
назначение запрещено. Иначе пересечений нет.

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| fallbacks на Reality в v25.1.1 ведёт себя не как ожидается (Reality деградирует) | низкая-средняя | высокое (Breaking) | verify-гейт WP-3: `xray -test`, бэкап, проверка `phone` до приёмки XHTTP; план отката ADR-003; fallback-план `--mode port` |
| certbot-standalone не успеет отработать из-за перехвата 80 будущим сервисом | низкая | среднее | E2 читаемый отказ; DNS-01 — будущий ADR, не в этом цикле |
| Подмена сертификата валит Hysteria2 | низкая | высокое | бэкап+`--restore`; клиент `mob` insecure=1 валидацию не проверяет; приёмка «mob работает» |
| Рассинхрон домен/самоподписанный (E10) | средняя | низкое | статус-детект WP-2 |
| LE rate-limit при многократных выпусках | низкая | среднее | идемпотентность (`--keep-until-expiring`), issue один раз, далее renew |

## 9. Границы изменений

- **Трогаем:** `src/acme/` (новое), `src/xray/*`, `src/hysteria2/{clients,status}.py`,
  `src/gateway/paths.py` (добавки), `src/main.py` (ленивые импорты), `tests/`.
- **Не трогаем:** публичный CLI-контракт существующих команд (только добавление
  флагов/подкоманд — обратимо-совместимо), `topology.json`, схему секретов
  (state.json — только опциональные поля), права 0600, UFW-политику,
  systemd-юниты протоколов и `systemd/*.tpl` (certbot.timer — пакетный),
  `realitySettings` (`dest`/`serverNames`), порты существующих протоколов,
  `src/xray/config.py` старый рендер (золотой снапшот), DNS-провайдера.

## 10. Трассируемость

| REQ | WP | Файлы | Тест |
|---|---|---|---|
| FR-2.1 / OQ-2 / OQ-4 | WP-1 | src/acme, paths | tests/acme + [VDS] |
| FR-2.2, FR-2.3 | WP-2 | apply_cert, hysteria2 clients/status | test_links_domain + [VDS] |
| FR-1.1–FR-1.3 / OQ-1 | WP-3 | xray config/install/remove/clients/status | test_config_xhttp, test_links_xhttp + [VDS] verify |
| FR-3 / OQ-3 | WP-4 | xray/clients | use-domain тест + [VDS] |
| §4 «Не ломать» | WP-5 | — | ACCEPT-чеклист |

## Следующий шаг
→ оркестратор назначает vds-coder на WP-1 (строго последовательно WP-1→4);
после WP-3 — [VDS] verify-гейт на asv1 до приёмки XHTTP; затем vds-tester (WP-5).
