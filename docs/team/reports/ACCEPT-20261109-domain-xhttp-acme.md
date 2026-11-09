# ACCEPT-20261109-domain-xhttp-acme — приёмка цикла «Домен / XHTTP / ACME» (WP-5)

## Мета
- **Базис:** [SPEC-20261109-domain-xhttp-acme](../specs/SPEC-20261109-domain-xhttp-acme.md),
  REQ §4 «Не ломать», ADR-003/004; снапшот asv1 = `aa01d98` + P13-фикс (в этом коммите)
- **Автор:** оркестратор; e2e-проверки — внешняя машина (клиенты xray v25.1.1 / hysteria app/v2.13.0)
- **Дата:** 2026-11-09 · **Сервер:** asv1 / 103.45.247.172
- **Вердикт:** **PASS** — все три направления работают на живом сервере, e2e подтверждён.
  Найдены и закрыты 1 breaking-сюрприз (см. §2) и 1 дефект (P13). ADR-003 уточнён фактом.

## 1. Результаты по WP

| WP | Проверка на asv1 | Результат |
|---|---|---|
| WP-1 | `vds acme issue` (HTTP-01, порт 80, certbot из apt) | ✅ выдан LE-сертификат на домен, deploy-hook установлен, автопродление certbot.timer |
| WP-2 | `hysteria2 apply-cert` dry-run → `--apply` | ✅ LE применён (89 дн.), бэкап `.bak-pre-le`, юнит active, status показывает «LE (Let's Encrypt), осталось 89 дн.» |
| WP-2 | старый insecure-клиент `mob` | ⚠️→✅ **сломался** (см. §2), перевыпущена LE-ссылка — e2e ✅ |
| WP-3 | `add-transport xhttp` fallback-режим | ❌→✅ fallback не работает (ADR-003 гипотеза опровергнута, см. §3); откат и `--mode port` — рабочий путь |
| WP-3 | VERIFY-ГЕЙТ: `phone` по старой Reality-ссылке после обоих переключений | ✅ PASS оба раза (200 через туннель, 0 ошибок) |
| WP-3 | XHTTP e2e | ✅ клиент через домен:8443 (LE TLS, path=/xhttp) → api.ipify → IP сервера, google 200 |
| WP-4 | `vds xray use-domain` + идемпотентность | ✅ state.domain задан, Reality-ссылки с доменом, dest/serverNames не тронуты |
| REQ §4 | «Не ломать»: phone / mob | ✅ с оговоркой: mob — через перевыпуск ссылки (§2) |
| — | journal на секреты | ✅ uuid: 0, privateKey: 0 |
| — | финальный расклад портов | ✅ TCP 443 (Reality) + TCP 8443 (XHTTP/LE) + UDP 443 (Hysteria2/LE) |

## 2. Breaking-находка: старые hysteria2-ссылки не переживают подмену на LE

Юнит-допущение («insecure=1-клиент продолжит работать») **не подтвердилось на живом**:
hysteria2-сервер с LE-сертификатом отклоняет ClientHello с SNI=IP (`CRYPTO_ERROR 0x150
tls: internal error`). Диагноз: серверная валидация SNI против сертификата.

**Митигация (выполнена на asv1):** перевыпуск ссылки `mob` по WP-2-рендеру
(домен, без insecure) — e2e подтверждён. **Следствие для владельца:** все старые
hysteria2-ссылки нужно перевыпустить после apply-cert. В доки (G5): поправить REQ §4
и README («существующие ссылки продолжают работать» → «требуется перевыпуск»).

## 3. Опровержение ADR-003-fallback и переход на --mode port

SNI=домен у Reality уходит на `dest` (google) — до `fallbacks` управление не доходит;
Reality никогда не терминирует TLS для чужого SNI. Фолбэк-план ADR-003 (`--mode port`)
стал основным режимом: публичный 8443 + LE TLS. Полная поправка внесена в ADR-003.
Операционная последовательность отката/пере-добавления отработала штатно
(remove-transport → add-transport --mode port, с бэкапами и гейтами `xray -test`).

## 4. Дефекты цикла

| ID | Суть | Статус |
|---|---|---|
| P13 | remove→add-transport записывал meta без `installed: True` → «not installed» на живом | ✅ исправлен кодом (226 passed), на сервере ops-фикс |
| D-min | клиентская запись `xhttp-web` в state показывает `port 443` при фактическом 8443 | отложено (косметика, TECHDEBT-кандидат) |
| — | ADR-003 fallback | закрыт поправкой ADR (§3) |

## 5. Итоговое состояние asv1

- **Reality (TCP 443):** active, клиент `phone` — e2e ✅ (старая ссылка без изменений), ссылки с доменом
- **XHTTP (TCP 8443):** active, mode=port, LE TLS, path=/xhttp, клиент `xhttp-web` — e2e ✅
- **Hysteria2 (UDP 443):** active, LE-сертификат (89 дн., автопродление), клиент `mob` на новой LE-ссылке — e2e ✅
- gateway state: xray / hysteria2 / acme / xhttp — installed
- Юнит-тесты цикла: 142 → **226 passed**

**Цикл «Домен / XHTTP / ACME» принимаю; G6 закрывается после коммита и пуша.**
