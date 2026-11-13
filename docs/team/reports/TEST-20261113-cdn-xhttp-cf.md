# TEST-20261113-cdn-xhttp-cf — XHTTP через Cloudflare: PoC и результат

> Тестер/архитектор: `vds-architect`. Дата: 2026-11-13.
> Цель: проверить, даёт ли XHTTP поверх Cloudflare выигрыш против текущего
> WS-канала (`cdn-home`), прежде чем писать полноценную SPEC `cdn-xhttp-cf`
> (Mux.Cool отклонён ранее: TEST-20261113-cdn-mux).

## 1. Схема PoC (сервер asv1, временно)

К существующему Xray добавлен второй CDN-инбаунд:

```json
{
  "port": 2083,
  "protocol": "vless",
  "settings": {"clients": [{"id": "<CDN UUID>"}], "decryption": "none"},
  "streamSettings": {
    "network": "xhttp",
    "security": "tls",
    "xhttpSettings": {"path": "/cdnxhttp"},
    "tlsSettings": {"certificates": [{"certificateFile": ".../asvpersonal.ru/fullchain.pem",
                                      "keyFile": ".../asvpersonal.ru/privkey.pem"}]}
  }
}
```

2083 — один из портов, которые Cloudflare проксирует (443/2053/2083/2087/2096/8443),
т.е. панель CF менять не требовалось. Клиент — `vpn profile import` с
`type=xhttp&path=%2Fcdnxhttp&sni=asvpersonal.ru`.

## 2. Результаты

| Проверка | Результат |
|---|---|
| CF edge `https://asvpersonal.ru:2083/` | TLS 0.93 / 1.78 с, HTTP **404** (порт проксируется) |
| CF edge, ручной POST `/cdnxhttp` | HTTP **404** (до origin не доходит как XHTTP) |
| **через CF** (xray-xhttp клиент, mode `auto`) | **0/2** (timeout 25 с) |
| через CF, `mode=packet-up` (h1 и h2) | 0/2 (timeout) |
| через CF, `mode=stream-up` | 0/2 (timeout) |
| **напрямую** на origin 2083 (RF-клиент, корректный UUID) | **200**, TTFB **0.40 / 0.41 с** |
| напрямую XHTTP 8443 (существующий `xhttp-web`) | 200, TTFB 0.62 с |
| текущий WS через CF (`cdn-home`) | TTFB 2.45–2.88 с, bulk 1 МБ — timeout |

Логи клиента (debug): `XHTTP is dialing ... mode stream-up/packet-up, HTTP version 2/1.1`
— дальше без ответа; ошибок на сервере нет, входящих XHTTP-запросов от CF не видно.

## 3. Вывод

1. **XHTTP через Cloudflare не работает** (free-proxy): CF не пробрасывает
   XHTTP-семантику (HTTP/2 duplex / streaming POST) — все режимы (`auto`,
   `packet-up`, `stream-up`) дают таймаут. Ручной POST через CF получает 404,
   т.е. до нашего инбаунда запрос в нужном виде не доходит.
2. **XHTTP напрямую — быстрый**: TTFB 0.40–0.41 с против 2.45–2.88 с у WS через
   CF. Но это не «CDN»: клиент должен иметь прямой TCP до origin (в РФ — да,
   из-за границы провайдер режет TCP, см. HANDOFF §8.1). Существующий
   `xhttp-web` на 8443 уже покрывает этот сценарий (106 Мбит/с).
3. Причина «мёртвого» CDN — **маршрут CF**, а не транспорт и не mux.
   Мультиплексирование (Mux или XHTTP-через-CF) проблему не решает.

## 4. Что делать дальше

| Вариант | Нужен владелец? | Ожидание |
|---|---|---|
| `cloudflared tunnel` вместо публичного origin | **да** (CF-аккаунт, токен/логин) | убирает geo-фильтр TCP→origin, скрывает IP; latency CF остаётся |
| Argo Smart Routing | **да** (оплата) | лучше маршрут CF→origin, −20–30 % |
| CDN с PoP в РФ (Gcore/Bunny/Selectel) | **да** (аккаунт/оплата/DNS) | client→edge RTT ниже; WS или xhttp — по поддержке |
| Прямой XHTTP-профиль (домен + 2083) | нет | быстрый (0.4 с), но только для клиентов с доступом к origin; дублирует `xhttp-web` |
| Оставить WS-CF как есть | нет | канал выживания; скорость не растёт |

## 5. Откат (выполнен)

```
cp -a /usr/local/etc/xray/config.json.bak-xhttp-poc /usr/local/etc/xray/config.json
xray -test -c /usr/local/etc/xray/config.json   # Configuration OK
systemctl restart vds-xray                      # active
ss -ltn → только 443/8443/2053 (2083 нет)
vpn profile remove cdn-xhttp -f                 # профиль и generated-конфиг удалены
```

Бэкап `config.json.bak-xhttp-poc` оставлен на сервере для аудита.

## 6. Трассируемость

| Проверка | Факт |
|---|---|
| CF проксирует 2083 | да (TLS + 404 на edge) |
| CF пропускает XHTTP | **нет** (0/2 во всех режимах) |
| XHTTP direct | да (200, 0.4 с) |
| WS-CF baseline | 2.4–2.9 с TTFB, bulk timeout |
