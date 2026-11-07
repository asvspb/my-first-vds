# VPN-протоколы против блокировок (РКН) — обзор и план для VDS Orchestrator

> Дата: 2026-11-07. Справочный документ: состояние протоколов на сегодня,
> серверная реализация на VDS и план добавления модулей в оркестратор.
> Связанные документы: [../TECHDEBT.md](../TECHDEBT.md),
> [CENSORSHIP-ROADMAP.md](CENSORSHIP-ROADMAP.md) — пошаговый roadmap внедрения.

---

## 1. Состояние на ноябрь 2026

«Лучшего одного протокола» нет — ТСПУ дообучается. Рабочая стратегия —
своя связка из 2 протоколов с автопереключением в клиенте.

### Первый эшелон

| Протокол | Транспорт | Суть | Минус |
|---|---|---|---|
| **VLESS + Reality** (Xray, Vision) | TCP 443 | мимикрия под TLS 1.3 к сайту-маске; невалидные соединения прозрачно переправляются на настоящий `dest` | ТСПУ выборочно режет скорость Reality, ловит по фингерпринту на мобильных сетях |
| **Hysteria2** | UDP 443 (QUIC) | лучший по скорости, устойчив к потерям пакетов (мобильный интернет, Wi-Fi) | умирает целиком там, где UDP режется/троттлится |
| **VLESS XHTTP** | TCP/HTTP2 (можно через CDN) | маскировка под HTTP-запросы; можно прятать сервер за Cloudflare/российским CDN; устойчивее к фингерпринту, чем WebSocket | нужен домен + настоящий TLS-сертификат |

### Второй эшелон

- **AmneziaWG** — WireGuard с обфускацией заголовков («мусорные» пакеты). Простой и живучий, часто единственный вариант там, где Reality резанули.
- **Trojan / Shadowsocks-2022** — работают, но фингерпринт давно известен.

### Мёртвое для РКН

OpenVPN, классический WireGuard — детект за секунды. VMess, старый ss, HTTP-прокси — тоже.

### Рекомендация

На одном VDS: **VLESS Reality (TCP 443) + Hysteria2 (UDP 443)** — не конфликтуют
(разные L4-протоколы), клиент переключается автоматически. Fallback — XHTTP через CDN.

---

## 2. Общая серверная архитектура

Протоколы реализуются не «VPN-демонами», а проксирующими ядрами:

| Протокол | Ядро (сервер) | Порт | Транспорт |
|---|---|---|---|
| VLESS + Reality | **Xray-core** | 443 TCP | мимикрия под TLS 1.3 |
| VLESS XHTTP | **Xray-core** (тот же) | 443 TCP | HTTP-мимикрия |
| Hysteria2 | **hysteria2** (отдельный бинарь) | 443 UDP | QUIC |

Клиенты: v2rayNG, NekoRay, Hiddify, sing-box, V2Box (iOS) — конфиг импортируется
как ссылка или файл.

## 2.1. VLESS + Reality (Xray-core)

`/usr/local/etc/xray/config.json`:

```json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "<uuid>", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "www.google.com:443",
        "serverNames": ["www.google.com"],
        "privateKey": "<xray x25519 → приватный>",
        "shortIds": ["abcd1234"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

Клиент стучится на 443 как браузер; при невалидном handshake сервер
**прозрачно переправляет трафик на `dest`** — сканер видит «HTTPS к google.com».
Ключи: `xray x25519`. Клиентская ссылка:

```
vless://<uuid>@<ip>:443?security=reality&sni=www.google.com&fp=chrome&pbk=<public>&sid=<shortId>&flow=xtls-rprx-vision
```

## 2.2. VLESS XHTTP / SplithHTTP (Xray-core)

Тот же Xray, меняется `streamSettings`:

```json
{
  "network": "xhttp",
  "security": "tls",
  "tlsSettings": { "certificates": [{ "certificateFile": "...", "keyFile": "..." }] },
  "xhttpSettings": { "mode": "auto", "path": "/upload" }
}
```

Маскировка под GET/POST-запросы; можно проксировать через CDN — сервер не светит
свой IP. Нужны домен + Let's Encrypt. Режим `auto` чередует packet-up/stream-up,
ломая трафик-анализ.

## 2.3. Hysteria2

`/etc/hysteria/config.yaml`:

```yaml
listen: :443

tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.pem

auth:
  type: password
  password: "<пароль>"

bandwidth:
  up: 100 mbps
  down: 200 mbps
```

QUIC (UDP:443); TLS-сертификат через ACME (Let's Encrypt) или `masquerade`
(притворяться обычным сайтом при зондировании). Требуются настройки `sysctl`
(буферы). Клиентская ссылка: `hysteria2://<password>@<ip>:443/?sni=<домен>`.

---

## 3. План добавления в VDS Orchestrator

> **Статус: MVP реализовано 2026-11-07 (фазы 0–2), команды фактические.**
> Xray VLESS Reality (TCP 443) и Hysteria2 (UDP 443, self-signed + `insecure=1`,
> masquerade, sysctl BBR) установлены в оркестратор; общие примитивы —
> `src/core/protocol.py|netcheck.py|secrets.py|units.py`, состояние —
> `src/gateway/store.py` (`$INSTALL_DIR/gateway/state.json`, 0600).
> Нереализованное из плана ниже: XHTTP (фаза 3), ACME-сертификат (фаза 6,
> сейчас тестовый self-signed), подписки, SNI-мультиплексор, dashboard-карточки.
> См. [SPEC-20261107-gateway-mvp](team/specs/SPEC-20261107-gateway-mvp.md),
> [ADR-001](adr/ADR-001-xray-install-mechanism.md),
> [ADR-002](adr/ADR-002-gateway-paths-units-state.md).

Фактические команды (все требуют root; `remove` без `--apply` — dry-run):

```bash
vds gateway status                  # состояние gateway (state.json, клиенты, протоколы)

vds xray install [--sni MASK]       # Xray-core (пин версии + SHA256), Reality, Vision
vds xray add-client NAME            # профиль + share-link vless://...
vds xray status                     # юнит, xray -test, порт TCP 443, journal (маскируется)
vds xray remove [--apply]           # удаление: юнит, конфиг, бинарь+geodata, клиенты

vds hysteria2 install               # бинарь, self-signed TLS (CN=<ip>, 10 лет), masquerade, BBR
vds hysteria2 add-client NAME       # пароль + share-link hysteria2://...?insecure=1
vds hysteria2 status                # юнит, UDP 443, срок сертификата, journal
vds hysteria2 remove [--apply]      # удаление (sysctl-тюнинг не откатывается — ADR-002)
```

Изначальный план (частично выполнен, оставлен для контекста фаз 3+):

1. **`src/xray/`**
   - `install.py`: установка Xray-core, генерация uuid + x25519, конфиг с Reality
     и/или XHTTP, systemd-юнит. Переиспользовать `detect_network_architecture()`,
     `FileLock`, rich-вывод из core.
   - `add-client.py`: генерация клиентских ссылок VLESS.
   - `remove.py`.
2. **`src/hysteria2/`**
   - установка бинаря, yaml-конфиг, TLS (LE по домену), sysctl-настройки, unit.
3. **Проверка занятости порта 443** (`ss -tlnp`) перед установкой — через
   `core/shell.run`; конфликты с coturn/вебом.
4. **`sysinfo/dashboard.py`** — карточки статуса юнитов xray/hysteria.
5. **TUI-меню** (`src/main.py`) — пункты «Управление Xray», «Управление Hysteria2».

### Важно

- Дисклеймер: VPN-функциональность — исключительно для легального
  использования в соответствии с местным законодательством.
- Порты: Reality — TCP 443, Hysteria2 — UDP 443, XHTTP — TCP 443 (конфликтует
  с Reality: либо разные SNI/порты, либо fallback-иерархия в одном inbound).
- UFW: открыть 443/tcp и 443/udp в `server-setup`.
- Тестирование протоколов требует реального VDS — локально не проверить.

### Источники (состояние на 2026-11)

- [Сравнение VPN-протоколов — tainet.pro](https://tainet.pro/blog/vpn-protocols-comparison)
- [TSPU throttling analysis — Habr](https://habr.com/en/articles/990236)
- [Hysteria2 vs VLESS Reality vs Trojan speed test — nooblinux](https://nooblinux.com/hysteria2-vs-vless-reality-vs-trojan-speed-test)
- [Как быстро реализовать современный VPN — Habr](https://habr.com/ru/articles/1049680)
