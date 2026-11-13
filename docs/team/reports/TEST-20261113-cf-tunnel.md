# TEST-20261113-cf-tunnel — cloudflared tunnel для CDN: результат

> Тестер/архитектор: `vds-architect`. Дата: 2026-11-13.
> Цель: проверить, улучшает ли `cloudflared tunnel` (вместо публичного origin)
> скорость/стабильность `cdn-home` (VLESS+WS+TLS за Cloudflare).
> Владелец создал туннель и public hostname `cf-cdn-home.asvpersonal.ru`.

## 1. Что было сделано

1. `cloudflared 2026.11.0` установлен на asv1; токен — `/etc/cloudflared/token`
   (0600), коннектор зарегистрирован на PoP **ams07/ams13/ams17/ams18** (QUIC).
2. DNS: `cf-cdn-home.asvpersonal.ru` → CNAME на `<tunnel-id>.cfargotunnel.com`
   (proxied, 104.21.x/172.67.x) — создан владельцем через Public Hostname.
3. Первый прогон с remote-конфигом (service `https://localhost:2053`,
   originServerName `asvpersonal.ru`): коннектор активен, edge отвечает.
4. Локальный конфиг + credentials (из токена) и второй WS-инбаунд 2090 —
   для обхода Host-валидации (см. §2).
5. Замеры клиентом (`vless+ws`, путь `/cdnws`), затем полный откат.

## 2. Найденная особенность: Cloudflare маршрутизирует по Host

Xray WS-инбаунд CDN (`2053`) валидировал `Host: asvpersonal.ru`:

| Запрос | Результат |
|---|---|
| прямой origin, `Host: asvpersonal.ru` | **101** |
| прямой origin, `Host: cf-cdn-home.asvpersonal.ru` | 404 |
| через туннель, `Host: cf-cdn-home…` (origin ждёт apex) | 404 |
| через туннель, `Host: asvpersonal.ru` (CF уводит на apex-запись) | **526** |

Т.е. через туннель клиент обязан слать `Host` публичного hostname, а origin
должен его принимать. В тесте Host-проверка была временно снята на 2053
(и проверен отдельный инбаунд 2090) — после этого WS через туннель поднялся.

## 3. Результаты замеров

| Проверка | Результат |
|---|---|
| Туннель: edge `https://cf-cdn-home.asvpersonal.ru/` | 404 (дошло до origin), TTFB **2.41 / 2.20 с** |
| WS-хендшейк через туннель (после снятия Host-проверки) | **101 Switching Protocols** |
| **`cf-cdn-home` TTFB (example.com)** | **3.02 / 2.97 / 4.64 с** |
| `cf-cdn-home` bulk 1 МБ (OVH) | **0 байт**, timeout 40 с |
| `cf-cdn-home` GitHub README | 0 байт, timeout 25 с |
| **baseline `cdn-home` (публичный origin)** | TTFB **2.45–2.88 с**, bulk 0 |
| CF-RAY клиента | `…-HKG` — клиентский PoP **Гонконг**, origin NL (Амстердам) |

## 4. Вывод

1. **Туннель технически работает** (QUIC-коннектор, WS 101, трафик доходит),
   но **не улучшает**: TTFB 2.97–4.64 с против 2.45–2.88 с у публичного origin,
   bulk по-прежнему 0.
2. Причина — **маршрут Cloudflare**: клиент попадает на PoP HKG, туннель
   поднят в AMS, origin в NL → длинный путь; провайдерское душење TCP до CF
   сохраняется. Смена origin на исходящий туннель это не лечит.
3. Побочная находка: при туннеле обязательна согласованность `Host`
   (CF маршрутизирует по нему); для постоянной схемы нужен либо отдельный
   WS-инбаунд под tunnel-host, либо отказ от Host-валидации (UUID+path остаются
   аутентификацией — приемлемо, но это изменение продового конфига).

## 5. Что дальше (без иллюзий)

| Вариант | Ожидание |
|---|---|
| **Argo Smart Routing** (владелец, платно) | может сократить CF→origin/маршрут; проверить теми же замерами |
| **CDN с PoP в РФ** (Gcore/Bunny/Selectel) | убирает HKG-петлю, client→edge ближе; нужен аккаунт/NS |
| Оставить как есть | WS-CF — канал выживания; быстрым не станет |
| Прямой XHTTP (0.40 с) | только при прямом доступе к origin (RF), не CDN |

## 6. Откат (выполнен)

- `/usr/local/etc/xray/config.json` восстановлен из `config.json.bak-cftunnel`
  (2053 с Host-валидацией, без 2090), `xray -test` OK, юнит active,
  слушают 443/8443/2053.
- `cloudflared` остановлен и **disabled**; токен/credentials остались
  в `/etc/cloudflared/` (0600) — можно удалить/ротировать.
- Профиль `cf-cdn-home` и generated-конфиг удалены; apex WS sanity — **101**.
