# VPN-протоколы против блокировок (РКН) — обзор и фактическое состояние VDS Orchestrator

> Дата: 2026-11-07, актуализировано 2026-11-16. Справочный документ: состояние
> протоколов на сегодня, серверная реализация на VDS (что уже в оркестраторе — §3).
> Связанные документы: [../TECHDEBT.md](../TECHDEBT.md),
> [CENSORSHIP-ROADMAP.md](CENSORSHIP-ROADMAP.md) — пошаговый roadmap внедрения;
> матрица «угроза → транспорт» (какую угрозу закрывает каждый протокол) —
> [team/reports/REVIEW-20261120-protocols-threat-matrix.md](team/reports/REVIEW-20261120-protocols-threat-matrix.md).

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
  "xhttpSettings": {
    "path": "/<случайный-путь>",
    "mode": "auto",
    "xPaddingBytes": "100-1000"
  }
}
```

Маскировка под GET/POST-запросы; можно проксировать через CDN — сервер не светит
свой IP. Нужны домен + Let's Encrypt. Режим `auto` чередует packet-up/stream-up,
ломая трафик-анализ.

Серверные параметры анти-ML профилирования (GR-25,
[SPEC-20261116-xhttp-xmux-padding](team/specs/SPEC-20261116-xhttp-xmux-padding.md);
рендер — `src/xray/config.py::_xhttp_inbound`, Xray-core ≥ 26.1.23 по
[ADR-010](adr/ADR-010-xray-core-upgrade-26.md)):

- `mode: "auto"` — сервер принимает все режимы передачи (`stream-one`,
  `stream-up`, `packet-up`), выбор остаётся за клиентом;
- `xPaddingBytes: "100-1000"` — длина служебного padding'а в ответах
  рандомизируется в окне 100–1000 байт на каждый фрейм: гистограмма размеров
  пакетов (SPLT-анализ) размывается, классификатор не выделяет профиль Xray;
- путь (`path`) — секрет из `state.json` (0600), перерендер CDN/клиентов его
  не сбрасывает;
- клиентская сторона (ротация сокетов `xmux`, тот же `xPaddingBytes`) живёт в
  `ubuntuInstaller` (`vpnm/xclient.py`); серверный share-link не меняется:
  `vless://…&path=<path>&type=xhttp` — старые клиенты (только `path`)
  подключаются как раньше (§4 спеки).
- **миграция уже установленного XHTTP:** `vds xray add-transport xhttp --mode
  port --apply` дозаполняет `mode`/`xPaddingBytes`, если их ещё нет; `path`
  сохраняется. Живой CDN-инбаунд (ws/2053) переносится из текущего конфига
  без потерь — XHTTP+CDN на одном узле (asv1) не ломаются. При смене IP
  (DNS ещё старый) — `--skip-domain-check`: E1 пропускается, сертификат/SNI
  остаются прежними.

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

### 2.3.1. Port hopping (SPEC-20261112 WP-1, ADR-008)

Ответ на порто-специфичный шейпинг UDP: клиент прыгает по диапазону портов,
сервер редиректит весь диапазон на слушающий udp/443 через именованную цепочку
nat-таблицы `VDS_HY2_HOP` (REDIRECT + jump из PREROUTING; nat срабатывает до
UFW-фильтрации, поверх — одно UFW-правило на диапазон). Персистентность после
ребута — oneshot-юнит `vds-hysteria2-hop.service` с идемпотентным apply-скриптом
`/usr/local/sbin/vds-hy2-hop-apply.sh` (`-C`-проверки перед `-A`). Живой
udp/443 не прерывается: правило только добавляет путь. Диапазон — явный
аргумент, ширина ≤ 1000 портов, всегда в state (`hop_ports`) и виден в status.

```bash
vds hysteria2 add-hop-ports 20000-20500 [--apply]   # dry-run по умолчанию
vds hysteria2 remove-hop-ports [--apply]
```

Клиент получает `mport=20000-20500` в share-link (стандартный параметр
hysteria2/sing-box: `ports: "20000-20500"` в sing-box-конфиге):
`hysteria2://<password>@<ip>:443/?sni=<ip>&insecure=1&mport=20000-20500#name`.

### 2.3.2. Obfs salamander (SPEC-20261112 WP-1, REQ FR-1..5)

Ответ на «голый QUIC — самый заметный фингерпринт»: параллельный инстанс
hysteria2 на отдельном UDP-порту (по умолчанию 51826) с обфускацией
salamander. Собственный конфиг `/etc/hysteria/obfs.yaml` (0600) и юнит
`vds-hysteria2-obfs.service`; auth-пароль — тот же общий пароль основного
инстанса (один секрет на транспорт), obfs-пароль — отдельный генерируемый.
Основной udp/443 не трогается вовсе — soft rollout по построению. Ротация
obfs-пароля — на том же порту с кратким разрывом ~5 с (девиация FR-5, SPEC
§3.6); смена порта = `remove-obfs` + `add-obfs --port N`.

```bash
vds hysteria2 add-obfs [--port 51826]   # установить obfs-инстанс
vds hysteria2 rotate-obfs               # новый obfs-пароль + рестарт
vds hysteria2 remove-obfs [--apply]     # dry-run по умолчанию
```

Ссылка obfs-клиента: `add-client` печатает её второй строкой, `gateway links
--include-obfs` — отдельным рядом `<name>@obfs` (для `vpn profile pull`):
`hysteria2://<password>@<ip>:51826/?sni=<ip>&obfs=salamander&obfs-password=<obfs>&insecure=1#name`.

Серверный YAML: пароль обфускатора вложен в ключ типа — hysteria v2 читает
схему `obfs.salamander.password`, плоский `obfs.password` игнорируется и
ядро падает с `obfs.salamander.password: PSK must be at least 4 bytes`:

```yaml
obfs:
  type: salamander
  salamander:
    password: "<obfs-пароль>"
```

### 2.3.3. TLS/ACME fallback-флоу и masquerade (фактическое состояние)

Код ACME — SPEC-20261109/ADR-004, нового кода в WP-1 нет; фактический флоу:

1. `vds acme issue --domain <домен> --email <email>` — LE-сертификат
   (HTTP-01) + deploy-hook на продление (P28: hook с фильтром
   `${RENEWED_DOMAINS:-}` — срабатывает только на продление своего
   сертификата, unset/чужой домен → exit 0 без мутаций; продление второго
   сертификата `ws.<domain>` (ADR-016) hysteria не рестартует, hook
   wstunnel — наоборот).
2. `vds hysteria2 apply-cert --apply` — подмена self-signed на LE (бэкап
   `.bak-pre-le`), рестарт.
3. `vds hysteria2 add-client NAME` — ссылка БЕЗ `insecure=1`, sni=домен.

Окно 80/tcp (SPEC-20261124 quiet-exit, P1-5): `acme issue --window-80` —
80/tcp открывается ДО certbot (standalone биндит :80 сам) и закрывается в
finally; renewal-hooks `pre/vds-acme-80-open.sh` + `post/vds-acme-80-close.sh`
(маркер `/run/vds-acme-80-opened`, post выполняется certbot всегда,
tolerant exit 0) обслуживают штатный certbot.timer renew; периодический
fail-safe чек — `vds acme check-80-window` (80 открыт вне окна → WARN +
exit 1). В UFW-профиле `quiet-exit` правило `_PROTOCOL_RULES["acme"]`
игнорируется — 80/tcp автоматически не открывается (закрытие TECHDEBT P39).

### 2.3.4. host и sni в ссылке — разные поля (GR-10, 2026-11-13)

`hysteria2://` позволяет указать адрес подключения (`host`) отдельно от имени
в сертификате (`sni`). `vds` рендерит именно так:

- `host` — `state.domain` (или домен сертификата, если `state.domain` пуст);
- `sni` — домен развёрнутого сертификата, зафиксированный в
  `state.protocols["hysteria2"]["cert_domain"]`;
- `insecure=1` — только в self-signed режиме (host == sni).

`cert_domain` пишут: `vds hysteria2 apply-cert --apply`, ACME deploy-hook
(`vds hysteria2 set-cert-domain "$DOMAIN"` после подмены) и вручную
`vds hysteria2 set-cert-domain <domain>` (без аргумента — очистить).
`gateway healthcheck` сверяет CN `/etc/hysteria/cert.pem` с `sni` ссылок и
даёт error при расхождении — детект инцидента 2026-11-13, когда hook подменил
сертификат на домен CDN-фронта, а ссылки остались с прежним `sni`.

Хост LE-ссылки резолвит `hysteria2.clients.le_domain(state)` (общий для
`add-client` и `gateway links`): если `state.domain` расходится с `acme.domain`
и для `state.domain` есть live-каталог LE — берётся `state.domain`. Это
типовой случай, когда `acme.domain` — CDN-фронт за Cloudflare (UDP там не
обслуживается), а TLS hysteria2 завершается сертификатом домена сервера;
ссылка с чужим sni даёт у клиента `CRYPTO_ERROR 0x150`. Если live-каталога для
`state.domain` нет — fallback на `acme.domain`; без ACME вообще — legacy
IP + `insecure=1`.
4. `vds hysteria2 apply-cert --restore` — откат к self-signed; старые
   insecure-ссылки снова валидны.

Без домена/ACME — self-signed (CN=<ip>, 10 лет) и `insecure=1` в ссылках.
Masquerade — `type: proxy` на `https://download.microsoft.com/` (зондирование
видит настоящий сайт); URL конфигурируется флагом
`vds hysteria2 install --masquerade-url <URL>`.

---

### 2.4. Измерения скорости: эндпоинт важнее протокола (2026-11-13)

Скорость транспортов нельзя мерить на одном bulk-источнике. Живой пример:
`speed.cloudflare.com` из РФ отдавал **0–7 Мбит/с** на всех каналах, а
`proof.ovh.net` на тех же каналах — **62–75 Мбит/с**. Вывод «протокол X
медленный» был ошибкой методики; виноват эндпоинт.

Клиентский инструмент — `vpn speed` (vpnm):
- эндпоинты с фолбэком **OVH → Cloudflare → GitHub**, в отчёте видно, какой
  реально отдал байты;
- `--flows N` — агрегат параллельных потоков (отделяет «потолок канала» от
  «потолка одного TCP-потока»);
- серийные пробы (И26), egress-проверка каждого туннеля, отчёт
  `~/.local/share/vpn-manager/last-speed.json` (0600);
- live-таблица: статус → latency → Мбит/с → готово;
- CDN-профили по умолчанию **пропускаются** (CF не отдаёт bulk; включаются
  флагом `vpn speed --include-cdn`).

**Потолок CDN-через-CF (2026-11-13, закрыто):** TTFB 2.4–2.9 с, bulk 1 МБ —
timeout; Mux, XHTTP-через-CF и `cloudflared tunnel` выигрыша не дают (см.
[CDN-FRONTS](CDN-FRONTS.md), отчёты TEST-20261113-*). Дальнейшая оптимизация
CF не планируется; альтернатива — CDN с PoP в РФ (отдельный цикл).

Эталонный прогон на asv1 (2026-11-13, OVH): xhttp **106.3**, Reality **74.6**,
AWG **66.2**, Hy2 **41.4** Мбит/с; CDN — latency 2.39 с, bulk не отдался
(CF-специфика). Единичный поток при RTT ~70 мс даёт 7–20 Мбит/с — это предел
потока, а не шифра; `--flows 4` показывает реальную полосу канала.

Для доступности (а не скорости) — `vpn probe` / `vpn monitor`.

### 2.5. AmneziaWG (UDP 51825, ADR-005)

Обфусцированный WireGuard (AWG 1.5-набор: «мусорные» пакеты до хендшейка,
изменённые таймеры/размеры). Источник — PPA `ppa:amnezia/ppa`
(amneziawg-tools + amneziawg-dkms), mirror-конвенция ADR-001 не применяется.
UDP 51825; NAT/forwarding персистентны через `vds-amneziawg-nat.service.tpl`
(oneshot при загрузке). Клиент — `.conf` (0600) для импорта в AmneziaVPN;
поддерживается split (youtube/telegram через AWG, остальное напрямую).

**И44 — радиомолчание в простое (2026-11-16):** `PersistentKeepalive`
в клиентские конфиги **по умолчанию не пишется** — метроном 25 с работает
как DPI-маяк. NAT-дырка нужна только клиенту за NAT без входящего трафика:
`vds amneziawg add-client <имя> --keepalive 113` (то же — `vds relay
add-client`). Существующие конфиги не переписываются автоматически — при
необходимности пересоздать клиента.

**remove-client — живое удаление пира (2026-11-20, P24):** `vds amneziawg
remove-client <name> --apply` убирает [Peer] из awg0.conf и удаляет пир из
**поднятого** интерфейса `awg set awg0 peer <pub> remove` — рестарт юнита
не нужен, остальные пиры не теряют handshake (add-client по-прежнему
рестартует: новый пир обязан появиться на интерфейсе). Сбой живого
удаления → откат awg0.conf из бэкапа, клиентский .conf не тронут (он
удаляется только после успеха живого удаления); сбой `awg show` — отказ
до мутаций (не маскируется под stale-пир); stale-пир (нет на интерфейсе) —
conf-only.

**Изолированная нога relay→exit (P24, ADR-015):** на exit-узле нога релея
вынесена на отдельный `awg2` (10.11.0.0/30) с базовым портом `51900/udp`;
пул `51900–51911` доступен только с IP релея через nft REDIRECT, клиентский
`awg0` (51825) не затрагивается; для подсети ноги включён MASQUERADE на WAN (nft postrouting, требуется `ip_forward=1`). Ставится на exit: `vds relay exit-leg install
--relay-ip <ip> --public-key <awg1-pub> --apply`. Диагностика: `awg show awg2`
на exit, `awg show awg1` на релее. ⚠️ Возраст handshake **не** равен
недоступности: при живом трафике AmneziaWG держит сессию со старым handshake
(WP-M0, `TEST-20261120-relay-leg-diag.md`), поэтому liveness проверяют
пингом/трафиком внутри туннеля, а не по `latest handshake`.
Манёвр порта (P25): `vds relay maneuver step --apply` — runtime-смена
`listen-port 0` + endpoint по пулу, с liveness-окном 20 с и откатом; авто-таймер
opt-in в WP-M4.

**Селектор носителей (WP-P2P-3):** `vds relay carrier status` / `switch --to
awg|wstunnel` — при блоке UDP-пула `table 100` уходит на `wg-ws0` (первый
rollback P25), при восстановлении awg1 (3 пробы + 600 с) возвращается обратно.

**Plain-режим AWG (обфускация выключена, ADR-016):** для носителя `wg-ws0`
(WG **внутри** wstunnel/WSS) обфускация не применяется —
`render_server_conf(obf={})` / `render_client_conf(obf={}, junk={})` не пишут
строки `Jc/Jmin/Jmax/S1/S2/H1..H4` (для AmneziaWG это plain-WireGuard).
Причина: junk/S-паддинг внутри TLS только съедает MTU и TCP-окно, а маскирует
трафик уже сам WSS.

## 3. План добавления в VDS Orchestrator

> **Статус: реализовано и работает на asv1/asv2 (актуализировано 2026-11-16).**
> Установщики Xray/Hysteria2 скачивают релизы с GitHub; при DPI-блокировке
> можно задать `VDS_GITHUB_MIRROR` (gh-proxy-префикс) — реверсивно, off by
> default (см. ADR-001). Xray-core на серверах — 26.1.23 (ADR-010).
> Реализовано: Reality (TCP 443), XHTTP-инблэнд (TCP 8443, ADR-003), CDN
> VLESS+WS+TLS (origin 2053, ADR-006), Hysteria2 (UDP 443, self-signed +
> LE/ACME HTTP-01 по домену, ADR-004), port hopping (ADR-008), obfs salamander,
> AmneziaWG (ADR-005, §2.5), ACME + use-domain, `gateway init` (fresh-install),
> probe-watch v3 (threat-level/RU-CIDR + verified_session_ips/anti-Self-DoS,
> SPEC-20261116-probe-response §11.1), UFW-hardening (ADR-011). Пути XHTTP и
> CDN-WS — случайные при install (секрет в state.json; живые установки
> наследуют текущий, ротация `--regenerate-path --apply` → сразу
> `vpn profile pull`); 2053/tcp открыт только для CIDR Cloudflare
> (SPEC-20261116-surface-hardening). Состояние — `src/gateway/store.py`
> (`$INSTALL_DIR/gateway/state.json`, 0600).
> Нереализованное: подписки, SNI-мультиплексор, dashboard-карточки.
> См. [SPEC-20261107-gateway-mvp](team/specs/SPEC-20261107-gateway-mvp.md),
> [ADR-001](adr/ADR-001-xray-install-mechanism.md),
> [ADR-002](adr/ADR-002-gateway-paths-units-state.md).

Фактические команды (все требуют root; `remove` без `--apply` — dry-run):

```bash
vds gateway status                  # состояние gateway (state.json, клиенты, протоколы)
vds gateway links [--protocol P]    # share-links всех клиентов (P: xray | hysteria2)

vds xray install [--sni MASK]       # Xray-core (пин версии + SHA256), Reality, Vision
vds xray add-client NAME            # профиль + share-link vless://...
vds xray status                     # юнит, xray -test, порт TCP 443, journal (маскируется)
vds xray remove [--apply]           # удаление: юнит, конфиг, бинарь+geodata, клиенты

vds hysteria2 install [--masquerade-url URL]   # бинарь, self-signed TLS, masquerade, BBR
vds hysteria2 add-client NAME       # пароль + share-link hysteria2://...?insecure=1
vds hysteria2 status                # юнит, UDP 443, срок сертификата, journal
vds hysteria2 remove [--apply]      # удаление (sysctl-тюнинг не откатывается — ADR-002)
vds hysteria2 add-hop-ports 20000-20500 [--apply]  # port hopping (ADR-008)
vds hysteria2 remove-hop-ports [--apply]
vds hysteria2 add-obfs [--port 51826]              # obfs salamander (WP-1)
vds hysteria2 remove-obfs [--apply]
vds hysteria2 rotate-obfs
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
- UFW: 443/tcp и 443/udp открываются профилем `vds system ufw harden --profile
  gateway --apply` (ADR-011; `server-setup` — легаси-мастер, для файрвола
  использовать `harden`).
- Тестирование протоколов требует реального VDS — локально не проверить.

### Источники (состояние на 2026-11)

- [Сравнение VPN-протоколов — tainet.pro](https://tainet.pro/blog/vpn-protocols-comparison)
- [TSPU throttling analysis — Habr](https://habr.com/en/articles/990236)
- [Hysteria2 vs VLESS Reality vs Trojan speed test — nooblinux](https://nooblinux.com/hysteria2-vs-vless-reality-vs-trojan-speed-test)
- [Как быстро реализовать современный VPN — Habr](https://habr.com/ru/articles/1049680)
