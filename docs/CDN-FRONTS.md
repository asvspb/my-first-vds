# Пул CDN-фронтов (SPEC-20261112 WP-2, ADR-006 «Дополнение»)

> Схема резервирования CDN-канала: несколько orange-записей одного домена в
> Cloudflare вместо единственной (SPOF, наблюдён на asv1 в эпизодах
> 2026-11-11..12). Серверная часть — в VDS Orchestrator; healthcheck и
> автопереключение — клиентский репо (vpn-manager/ubuntuInstaller).

## 1. Схема пула

```
client ──> cdn1.<zone> (orange, CF edge) ──┐
client ──> cdn2.<zone> (orange, CF edge) ──┼──> origin <ip>:2053 (vless+ws+tls, Xray)
                ...                        │
```

- **Фронт** = DNS-запись `<имя>.<zone>` с orange cloud (proxied) в панели
  Cloudflare. Управление DNS — владелец вручную; CF-API вне скоупа
  (ADR-006 OQ-5, токен не появляется).
- **Origin-инблэнд** один: vless+ws+tls на TCP 2053 (ADR-006). Все фронты
  ведут в него; Xray выбирает TLS-сертификат по SNI.
- **TLS-покрытие**: CF в Full (strict) валидирует origin-сертификат против
  SNI фронта → каждый фронт обязан быть покрыт собственным LE-сертификатом
  на origin (выпуск `vds acme issue` при grey + пара certificateFile/keyFile
  в certificates CDN-инблэнда). Wildcard (\*.zone, DNS-01) отклонён —
  требует CF API-токен (new secret + new ADR), future.
- **Реестр фронтов**: `state.json` → `protocols["xray-cdn"]["fronts"] =
  {домен: {cert_path, key_path}}` (0600). Команды — ниже.
- **Healthcheck/автопереключение — НЕ в vds** (граница vds ↔ vpnm,
  SPEC §4.1): клиент пробует фронты по порядку приоритета; все мертвы →
  fallback-транспорт (reality/awg).

## 2. Команды vds (серверная часть)

```bash
vds xray add-cdn --domain cdn.<zone>            # базовый CDN (ADR-006), если ещё нет
vds xray add-cdn-front cdn1.<zone> [--apply]    # добавить фронт (dry-run по умолчанию)
vds xray add-cdn-front cdn2.<zone> --apply
vds xray list-cdn-fronts                        # домен, LE-файлы, срок, DNS-чек
vds xray remove-cdn-front cdn1.<zone> [--apply] # снять фронт (LE certbot НЕ удаляется)
vds xray add-cdn-client NAME --front cdn1.<zone>  # ссылка с host=фронт
vds gateway links                               # ссылки всех клиентов по всем фронтам
```

`gateway links` на клиента с фронтами печатает: основную строку
`name: vless://...@cdn.<zone>:2053...` + по строке на каждый фронт
`name@cdn1.<zone>: vless://...@cdn1.<zone>:2053...` (uuid общий — transport
один, меняется только host/sni).

## 3. Чеклист владельца: добавить фронт

> Порядок шагов важен: LE-выпуск (HTTP-01) требует, чтобы DNS-запись была
> **grey (DNS-only)** и указывала на публичный IP сервера; orange включается
> ПОСЛЕ выпуска — иначе валидация не пройдёт.

1. CF-панель: DNS → добавить `A`-запись `cdn1.<zone>` = публичный IP сервера,
   **DNS-only (grey)** — НЕ включать proxy.
2. Выпустить LE-сертификат на сервере:
   `vds acme issue --domain cdn1.<zone> --email <email>` (HTTP-01, порт 80
   должен быть открыт; продление — certbot.timer автоматически).
3. Добавить фронт в пул: `vds xray add-cdn-front cdn1.<zone>` (dry-run-план)
   → `vds xray add-cdn-front cdn1.<zone> --apply` (рестарт vds-xray —
   короткий downtime CDN-канала; Reality/XHTTP/Hysteria2 не затрагиваются).
4. CF-панель: включить **proxied (orange)** для `cdn1.<zone>`;
   SSL/TLS-режим зоны — Full (strict).
5. Проверка (можно на сервере): `dig +short cdn1.<zone>` → CF-IP;
   снаружи: `curl -sI https://cdn1.<zone>/` — отвечает LE-сертификатом
   фронта. `vds xray list-cdn-fronts` — `DNS ок`, LE-файлы есть.
6. e2e: клиент через `vds xray add-cdn-client NAME --front cdn1.<zone>`
   (или готовая строка `name@cdn1...` из `vds gateway links`) — 204 через
   socks, exit-IP = сервер.

Снятие фронта: `vds xray remove-cdn-front cdn1.<zone> --apply` (сертификат
certbot остаётся — пассивный; чтобы убрать совсем — certbot delete вручную).
Продление сертификата фронта — certbot.timer + тот же grey-шаг E11 только
если валидация не проходит через orange (см. ADR-006).

## 4. Формат совместимости (клиентский профиль vpnm)

Клиентский репо читает пул из вывода `vds gateway links` (ssh `vpn profile
pull`) или собирает вручную по этому формату:

```jsonc
// клиентский профиль (vpnm), поле fronts — массив, порядок = приоритет
{ "transport": "xray-cdn-ws",
  "fronts": [
    { "host": "cdn1.asvpersonal.ru", "port": 2053 },
    { "host": "cdn2.asvpersonal.ru", "port": 2053 }
  ],
  "ws_path": "/cdnws",
  "fallback": ["reality", "awg"] }
// healthcheck клиента: TCP+TLS до host:2053 (или generate_204 через канал);
// переключение: первый живой фронт по порядку; все мертвы -> fallback-транспорт.
```

Каждая строка CDN из `gateway links` — самодостаточный vless-uri:
`vless://<uuid>@<host>:2053?encryption=none&security=tls&sni=<host>&type=ws&host=<host>&path=%2Fcdnws#<name>`;
uuid/путь одинаковы для всех фронтов, отличается только host/sni.

## 5. Ограничения (задокументированные)

- Пул фронтов одного провайдера (все CF) не спасает от блокировки CF-класса
  целиком (И6); мульти-CDN — future REQ.
- CF-панель и DNS — ручные шаги владельца (чеклист §3); API-токен CF в
  репо/на сервере не появляется.
