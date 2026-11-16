# ARCH-20261116 — стек глазами инженера ТСПУ: 8 слепых пятен

> **Тип:** внешнее ревью (snapshot), не SPEC, не приёмка и не утверждённый план.
> **Автор:** главный архитектор (ответ на запрос владельца), 2026-11-16.
> **Аудитория:** владелец, `vds-orchestrator`, `vds-analyst` — как вход для intake.
> **Статус:** зафиксировано как есть; приоритеты §8 — предложение архитектора,
> решение об объёме и порядке — за владельцем.
> **Связанные документы:** [SPEC-20261116-survivability](../specs/SPEC-20261116-survivability.md)
> (G2, draft), [SPEC-20261116-probe-response](../specs/SPEC-20261116-probe-response.md),
> [ADR-011](../../adr/ADR-011-ufw-hardening.md), [ADR-012](../../adr/ADR-012-log-forensics.md),
> [ADR-014](../../adr/ADR-014-vpn-guard.md), [ADR-005](../../adr/ADR-005-amneziawg-transport-decisions.md),
> [ADR-007](../../adr/ADR-007-ru-relay.md), [GROWTH-POINTS](../../GROWTH-POINTS.md)
> (GR-03/GR-07), [DEPLOY-RU-RELAY](../../DEPLOY-RU-RELAY.md).

> Текст ответа сохранён с минимальной редактурой: разметка, ссылки на файлы,
> исправлена опечатка в первом слове. Смысл и формулировки — авторские.
> Проверка утверждений по коду — в §9 (добавлена при записи, не автором).

---

Если посмотреть на код обоих репозиториев (`src/xray/`, `src/hysteria2/`,
`src/amneziawg/`, `src/gateway/probing.py`, `src/logs/`, `src/system/ufw.py`
и клиентский `vpnm`) глазами инженера ТСПУ / систем активного зондирования РКН,
у текущего стека при всей его высокой культуре разработки есть **8 критических
слепых пятен и уязвимостей**.

Часть из них позволяет цензору пассивно классифицировать сервер за 1–2 сессии,
часть — детектировать его активным сканером в обход probe-watch, а часть может
заставить сервер заблокировать самого владельца.

Разложу их по слоям: от криптографических/протокольных маркеров до ошибок
в логике самозащиты.

---

## 1. Фатальная связка: LE-сертификат на 8443/443 + SNI = `www.google.com` в Reality

Это главная архитектурная дыра текущего сосуществования протоколов
([src/xray/config.py](../../../src/xray/config.py), [src/hysteria2/config.py](../../../src/hysteria2/config.py)):

**Как настроено сейчас.** На TCP 443 стоит Reality с `dest = www.google.com:443`
(`DEFAULT_SNI = "www.google.com"`). Одновременно на этом же IP на TCP 8443
(XHTTP) и UDP 443 (Hysteria2) отдаётся настоящий Let's Encrypt сертификат
вашего домена (`asvpersonal.ru` / `*.eu-cloud-xip.com`), который к тому же
светится в публичных логах Certificate Transparency (CT).

**Почему это подарок для ТСПУ:**

- `www.google.com` живёт исключительно в AS15169 (Google) со своими BGP-префиксами
  и Anycast. TLS-сессия с SNI = `www.google.com` на IP хостера
  (Hetzner / Aeza / LeaseWeb и т.д.) — это классический **ASN-SNI Mismatch**.
  Современные профили ТСПУ режут «чужой крупный SNI на VPS-подсети» даже без
  активных проб.
- Хуже того: активный сканер РКН при проверке IP стучится на 443/tcp, 8443/tcp
  и 443/udp. На 443/tcp без знания shortId он видит проксированный сертификат
  `google.com`, а на 8443/tcp и 443/udp (QUIC) тот же IP отдаёт ваш личный
  LE-сертификат! **Несоответствие сертификатов между TCP 443 и UDP 443 /
  TCP 8443 на одном IP = 100 % доказательство маскирующегося прокси (Reality).**

**Что делать:**

- Уходить от `www.google.com` на **Self-Steal** (собственный сайт-приманку на том
  же IP / в той же подсети хостера) либо хотя бы на домены из той же ASN, где
  стоит VDS.
- Если на сервере есть свой домен и LE-сертификат — намного безопаснее
  маскировать Reality под свой же домен (отдавая реальный Nginx/Caddy с тем же
  LE-сертификатом в fallback) или под соседний ресурс в том же ЦОД, чтобы
  TCP 443 и UDP 443 не противоречили друг другу.

## 2. XHTTP на 8443 и CDN на 2053 «кричат» о том, что они Xray

Посмотрите на `_xhttp_inbound` и `_cdn_inbound` в [src/xray/config.py](../../../src/xray/config.py):
у них нет fallbacks, ни веб-сервера перед ними, а пути захардкожены:
`XHTTP_PATH = "/xhttp"`, `CDN_WS_PATH = "/cdnws"`.

**Что видит активный бот РКН при подключении к `IP:8443` или `IP:2053`:**

- Порт 2053/tcp открыт в UFW для Anywhere (`0.0.0.0/0`), а не только для
  IP-диапазонов Cloudflare! Любой сканер из РФ может подключиться к `IP:2053`
  напрямую в обход Cloudflare, увидеть ваш LE-сертификат в TLS Handshake
  и сопоставить origin IP ↔ домен.
- При обычном `GET / HTTP/1.1` на 8443 или 2053 голый Xray без fallbacks не отдаёт
  валидную HTML-страницу с полноценными заголовками Nginx/Caddy — он отдаёт
  характерный ответ/обрыв голого Xray-инбаунда, а путь `/xhttp` находится в первых
  строках любого словаря сигнатур ТСПУ.

**Что делать:**

- Порт 2053 (CDN origin): закрыть в UFW для всего мира, разрешив вход только
  с официальных CIDR Cloudflare (`ips-v4`), либо вообще убрать наружный порт
  и спрятать за локальным сокетом / reverse-proxy.
- Пути `/xhttp` и `/cdnws`: генерировать рандомный `secret_path` при install
  (хранить в `state.json`), никогда не использовать литералы `/xhttp` и `/cdnws`.
- Fallback для 8443: добавить в `_xhttp_inbound` fallbacks на локальный порт
  с нейтральной статикой (или спрятать за тем же веб-сервером).

## 3. Слепота probe-watch ко всем портам, кроме 443

В [src/gateway/probing.py](../../../src/gateway/probing.py) жёстко зашито
`WATCH_PORT = 443` и только IPv4: таблица inet `vds_probe` считает `syn_bare`,
`syn_valid` и собирает `probers4` только на `tcp dport 443`.

Если сканер РКН/Censys бьёт по 8443/tcp (XHTTP), 2053/tcp (CDN origin),
51825/udp (AWG) или 51826/udp (Hy2 obfs) — probe-watch покажет `quiet`, 0 probers.

**Инерционность реакции.** `vds-probe-watch.timer` тикает раз в 1 час, а для
`THREAT_HIGH` нужно `HIGH_STREAK = 2` окна подряд. То есть от начала активной
атаки ТСПУ до срабатывания auto-lockdown проходит **от 1 до 2 часов**, когда IP
уже гарантированно занесён в блок-лист ТСПУ (серия проб ТСПУ длится 2–15 секунд!).

**Что делать:**

- Расширить nft-набор `probers4` на `tcp dport { 443, 8443, 2053 }`.
- Для детекта быстрых серий ТСПУ (T-07: 6–8 ClientHello за 10 с из одной /24
  подсети) связывать реакцию не с часовым probe-watch, а с 5-минутным
  `vds-logs-sample` (или легковесным демоном/таймером на 1–2 минуты).

## 4. Риск самострела (Self-DoS) в probe-watch: как сервер заблокирует самого владельца

Посмотрите на `read_awg_endpoints()` и `own_ips` в [src/gateway/probing.py](../../../src/gateway/probing.py)
(строки 490–530, 1659–1670): список «своих» IP (`own_ips`), которые исключаются
из `new_ru_ips`, автоматически собирается только из `awg show awg0 endpoints`.

**Сценарий самоблокировки:**

1. Вы открыли ноутбук в кафе / с мобильного интернета (новый российский IP)
   или у вас телефон живёт на Reality / XHTTP / Hysteria2 (без активного
   AWG-туннеля).
2. Вы (или ваше второе устройство с другого российского IP — домашний + мобильный)
   подключаетесь к 443/tcp (Reality).
3. Поскольку вас нет в `awg show awg0 endpoints` и нет в ручном
   `/etc/vds-probe-watch/allow-ips.txt`, nft записывает ваши собственные IP
   в `probers4` как `new_ru_ips`!
4. Два ваших IP (например, домашний провайдер + телефон с LTE, или смена IP
   роутером) за окно дают `new_ru_ips >= 2` (`NEW_RU_IPS_THRESHOLD = 2`) →
   вердикт `RU-PROBE-SUSPECT`!
5. Если включён auto-lockdown, во втором окне сервер включает `lock-443`
   и отрубает вам же доступ к 443 порту.

**Что делать:**

- Исключать из `new_ru_ips` не только пиров `awg0`, но и IP с установленными
  и передавшими трафик сессиями (например, conntrack /
  `ss -tn state established '( sport = :443 or sport = :8443 )'` с
  `bytes_acked > N` КБ, так как проба ТСПУ никогда не проходит аутентификацию
  VLESS/Hysteria2 и не прокачивает трафик).

## 5. Уязвимости Hysteria2 и AmneziaWG к блок-пробам и троттлингу UDP

**Hysteria2 на голом 443/udp + masquerade `download.microsoft.com`:**

- Голый QUIC на 443/udp в РФ режется ТСПУ по профилю протокола (даже без
  расшифровки), а при активной HTTP/3-пробе на 443/udp Hysteria2 проксирует
  `https://download.microsoft.com/` с `rewrite: true` — опять же чужой
  корпоративный сайт с IP мелкого хостера.
- При этом obfs salamander (51826) и Port Hopping (20000:20500) уже написаны
  в коде, но по дефолту не являются основным клиентским путём, а в `vpnm`
  (`xsplit.py`) системный tun-split сделан только для xray (Reality/XHTTP),
  тогда как Hysteria2 остаётся только SOCKS-прокси.

**Статичные порты 51825/udp (AWG) и 51826/udp (Hy2-obfs):**

- Порты 51820–51830 — это самый известный диапазон WireGuard/AmneziaWG.
  На многих региональных ТСПУ UDP-трафик на 51820–51830 попадает под усиленный
  эвристический фильтр по длинам пакетов и энтропии.
- В amneziawg пока используется набор параметров AWG 1.5 (Jc/Jmin/Jmax, S1/S2,
  H1–H4). Против обновлённых правил ТСПУ 2026 года (и особенно на мобильных
  операторах) критична поддержка **AWG 2.0** (диапазонные заголовки H1–H4 вида
  `min-max` и S3/S4 + I1–I5 сигнатурные пакеты маскировки под QUIC/DTLS/DNS)
  и уход с порта 51825 на нестандартный высокий UDP-порт (или UDP port hopping
  через iptables REDIRECT по аналогии с [src/hysteria2/hop.py](../../../src/hysteria2/hop.py)).

## 6. Разделение управляющего (SSH) и боевого (VPN) трафика на одном IP

Это классическая операционная ловушка при работе через VDS.

Когда вы делаете `vpn profile pull -H root@asv2`, `11_vds-deploy.sh` или будущий
`vpn guard sync` (раз в час по SSH на порт 49222), если этот SSH-коннект идёт
напрямую мимо туннеля с того же клиентского IP, ТСПУ видит одновременную
корреляцию:

- длинный поток `Client ↔ VDS:443` (якобы `www.google.com`);
- и параллельный `SSH Client ↔ VDS:49222` к тому же IP!

Ни один настоящий сервер `www.google.com` не принимает SSH от домашнего
пользователя из РФ параллельно с HTTPS-сессией. Это мгновенный триггер для
эвристики «User owns this proxy server».

**Что делать:**

- Любые SSH-сессии на боевой VDS (включая `vpn guard sync` и `profile pull`)
  должны либо принудительно маршрутизироваться внутрь уже поднятого VPN-туннеля
  (или через второй резервный канал/тор/релей), либо SSH на внешнем интерфейсе
  должен быть закрыт, а управление идти через внутренний IP туннеля
  (`10.8.0.1` в `awg0`).

## 7. Клиентский стек (ubuntuInstaller): утечки и детекторы на стороне ноутбука

**Bootstrap и утечка cloudflared DoH** (`scripts/13_dns-doh.sh`, `vpnm/doh.py`):

- `cloudflared` стучится на `1.1.1.1:443` / `1.0.0.1:443` напрямую мимо туннеля.
  Во многих регионах РФ IP `1.1.1.1` уже периодически троттлится или блокируется
  ТСПУ по TLS/SNI `cloudflare-dns.com`. Когда `cloudflared` залипает, рассыпается
  вся цепочка `systemd-resolved → dnsmasq → nftset routes`, и домены из
  `domains.txt` перестают попадать в `awg_split` / `xray_split`!
- **Решение:** пускать сам апстрим DoH (или резервный DoH/DNS) через VPN-туннель
  после его поднятия, либо иметь 2–3 независимых DoH-апстрима в
  dnsmasq/резолвере, не завязанных только на `1.1.1.1`.

**Два разных бинаря Xray на клиенте** (`vpnm/xclient.py`):

- `xray-split` (tun) работает на Xray 26.1.23, а обычные SOCKS-профили (`vpn up`) —
  на старом 25.1.1 (`~/.local/lib/vpn/xray`). В 25.1.1 старый uTLS-отпечаток Chrome
  и старая реализация XHTTP, которые уже отличаются от 26.1.23. Стоит унифицировать
  клиентский бинарь Xray на 26.1.23.

**Нет TCP Padding / Fragmentation на первом пакете Reality и нет Multiplexing
с padding:**

- В `vpnm/xclient.py` в `realitySettings` передаётся только `fingerprint: "chrome"`,
  но не используется client-side TLS fragmentation / `sockopt.dialerProxy`
  (например, пропуск первого ClientHello через локальный `zapret/nfqws`
  или встроенную фрагментацию Xray), и нет ротации `spiderX` (каждый раз пустой
  `spiderX` у всех клиентов).

## 8. Матрица приоритетов: что даст максимальный прирост живучести прямо сейчас

Если ранжировать по соотношению «эффект против РКН/ТСПУ ↔ трудозатраты»:

| # | Приоритет | Действие |
|---|---|---|
| 1 | **Критично / быстро — сервер** | Починить Self-DoS в probe-watch ([src/gateway/probing.py](../../../src/gateway/probing.py)): перестать считать валидных клиентов Reality/XHTTP/Hy2 чужими `new_ru_ips` (учитывать established-сессии с трафиком или авторизованных клиентов, а не только `awg show endpoints`). |
| 2 | **Критично / быстро — сервер** | Закрыть демаскировку Xray на 2053 и 8443 ([src/xray/config.py](../../../src/xray/config.py), [src/system/ufw.py](../../../src/system/ufw.py)): рандомизировать `XHTTP_PATH` и `CDN_WS_PATH` (убрать `/xhttp` и `/cdnws`); ограничить порт 2053/tcp в UFW подсетями Cloudflare. |
| 3 | **Высокий приоритет — архитектура 443** | Убрать конфликт `www.google.com` vs собственный LE-сертификат (GR-07 + Self-Steal): добавить команду смены/проверки SNI (`vds xray set-sni`) + `spiderX`, и перевести маскировку с `www.google.com` на домен той же ASN или на локальный Self-Steal fallback. |
| 4 | **Высокий приоритет — протоколы** | Ввести Port Hopping для AWG (UDP 20000:20500 → 51825) и увести дефолт с 51825: повторить паттерн [src/hysteria2/hop.py](../../../src/hysteria2/hop.py) (`iptables -t nat PREROUTING REDIRECT`) для AmneziaWG, чтобы клиент мог менять UDP-порт без перезапуска `awg0` на сервере. |
| 5 | **Средний приоритет — операционная гигиена** | Пустить SSH (49222) и `vpn guard sync` внутрь туннеля: чтобы `vpn guard sync` (и `profile pull`) при живом VPN шли через внутренний адрес туннеля (`10.8.0.1`) или проксировались через локальный SOCKS, не светя параллельный SSH к боевому IP перед ТСПУ. |

---

## 9. Трассируемость: проверка утверждений по коду (2026-11-16)

Проверено при записи документа; ссылки — на текущий `main` (рабочее дерево).

| # | Утверждение | Где в коде | Проверка |
|---|---|---|---|
| 1 | `DEFAULT_SNI = "www.google.com"` | [src/xray/config.py:32](../../../src/xray/config.py), [src/gateway/init.py:50](../../../src/gateway/init.py) | ✅ подтверждено (дефолт; фактическое значение на asv1 — в `state.json`) |
| 1 | LE-сертификат на 8443/443/udp 443 | `src/hysteria2/config.py` (TLS-блок), `src/xray/config.py` (XHTTP-инбаунд) | ✅ по коду; фактический cert — `vds hysteria2 status` / `xray status` |
| 2 | `XHTTP_PATH = "/xhttp"`, `CDN_WS_PATH = "/cdnws"` | [src/xray/config.py:38](../../../src/xray/config.py), [src/gateway/paths.py:66](../../../src/gateway/paths.py) | ✅ подтверждено |
| 2 | У XHTTP/CDN-инбаундов нет fallbacks | [src/xray/config.py:110,175](../../../src/xray/config.py) | ⚠️ **уточнение:** fallbacks есть только в `xhttp_mode="fallback"`; в `mode="port"` (используется на asv1 по ADR-003) инбаунд голый |
| 2 | 2053/tcp открыт «для Anywhere» | [src/system/ufw.py:316](../../../src/system/ufw.py) (транспорт→порт) | ⚠️ по коду правило добавляется как `allow 2053/tcp`; фактическое состояние — `vds system ufw audit` / `surface audit` на сервере |
| 3 | `WATCH_PORT = 443`, nft только tcp/udp 443 | [src/gateway/probing.py:74,165–190](../../../src/gateway/probing.py) | ✅ подтверждено |
| 3 | Таймер 1 ч, `HIGH_STREAK = 2` | [systemd/vds-probe-watch.timer.tpl](../../../systemd/vds-probe-watch.timer.tpl), [probing.py:90](../../../src/gateway/probing.py) | ✅ подтверждено: реакция 1–2 ч |
| 4 | `own_ips` только из `awg show` + `allow-ips.txt` | [probing.py:1659–1670](../../../src/gateway/probing.py), `OWN_IPS_FILE` | ✅ подтверждено |
| 4 | `NEW_RU_IPS_THRESHOLD = 2` | [probing.py:84](../../../src/gateway/probing.py) | ✅ подтверждено |
| 5 | Hysteria2: `masquerade download.microsoft.com`, `rewrite: true` | [src/hysteria2/config.py:12,75–79](../../../src/hysteria2/config.py) | ✅ подтверждено |
| 5 | AWG 1.5 (`Jc/Jmin/Jmax`, `S1/S2`, одиночные `H1–H4`), порт 51825 | [src/amneziawg/config.py:4,24,54–56](../../../src/amneziawg/config.py), [paths.py:38](../../../src/gateway/paths.py) | ✅ подтверждено; AWG 2.0 (S3/S4, диапазонные H, I1–I5) валидатор отвергает явно |
| 5 | Hop реализован только для Hysteria2 | [src/hysteria2/hop.py](../../../src/hysteria2/hop.py) | ✅ подтверждено; для AWG hop отсутствует |
| 5 | `vpn xsplit`: tun-split только для Xray | репозиторий `ubuntuInstaller` (`vpnm/xsplit.py`) | ⛔ не проверялось — другой репозиторий |
| 6 | SSH-порт 49222, перенос порта | [src/system/ufw.py](../../../src/system/ufw.py), [ADR-011](../../adr/ADR-011-ufw-hardening.md) | ✅ подтверждено (двухфазный `ssh-port`) |
| 7 | `vpnm/doh.py`, `scripts/13_dns-doh.sh`, `vpnm/xclient.py`, версии Xray 25.1.1/26.1.23 | репозиторий `ubuntuInstaller` | ⛔ не проверялось — другой репозиторий |

## 10. Как это ложится на существующие артефакты

| Пункт ревью | Уже есть в бэклоге/спеке | Статус покрытия |
|---|---|---|
| §1 конфликт SNI/LE | [GR-07](../../GROWTH-POINTS.md) (Reality: одна маска, нет проверки decoy, P2); survivability — anti-fingerprint | частично; Self-Steal и `set-sni` не оформлены как P0 |
| §2 пути и 2053 | survivability S-03 (`surface audit`); ADR-003 (режимы XHTTP) | частично; рандомизация путей и CF-only CIDR — новые пункты |
| §3 слепота probe-watch | survivability T-20 (`adjacent_port_sweep`) детектирует соседние порты по логам/UFW | частично; сам probe-watch по-прежнему видит только 443 |
| §4 Self-DoS | [SPEC-20261116-probe-response](../specs/SPEC-20261116-probe-response.md) §11 (`own_ips`, `allow-ips.txt`) | пробел подтверждён: established-клиенты не учитываются |
| §5 AWG/Hy2 | GR-03 (hop, P1), GR-05 (gecko/pin, P2), GR-13/14 (rotate/purge/IPv6, P2), ADR-005 (набор 1.5) | AWG-port-hopping и AWG 2.0 — новые пункты (нужен ADR) |
| §6 SSH и боевой IP | [ADR-011](../../adr/ADR-011-ufw-hardening.md) (ssh-port), survivability SPA (ADR-013) | операционное правило не зафиксировано; SPA — P2 |
| §7 клиент | отдельный цикл `ubuntuInstaller` (`vpnm`) | вне скоупа `vds`; передать в клиентский бэклог |
| §8 матрица | — | приоритеты архитектора; решение владельца |

## 11. Что предлагается сделать с этим документом

1. **Не превращать в SPEC целиком.** Это red-team вход: пункты §8.1–§8.2 —
   кандидаты в P0-хотфиксы (probe-response v2 / surface audit), §8.3–§8.5 —
   в ближайший intake.
2. **Решение по §4 (Self-DoS) — до включения auto-lockdown на бою:** текущая
   реализация может отрезать владельца; либо хотфикс, либо явное правило
   «auto-lockdown только с заполненным `allow-ips.txt` и established-исключением».
3. **Пункты §1–§2 (маскировка) и §5 (AWG 2.0/hop)** требуют ADR: меняют
   модель маскировки и параметры протокола, «на лету» не правятся.
4. **Клиентские пункты §6–§7** передать в цикл `ubuntuInstaller` (`vpnm`),
   в этом репозитории — только правило эксплуатации (SSH внутрь туннеля).
