# SPEC-20261116-xhttp-xmux-padding — GR-25: анти-ML профилирование XHTTP (`xPaddingBytes` + `xmux` ротация сокетов)

> **Статус:** draft → G1/G2
> **Источник:** [ARCH-20261116-tspu-blindspots](../reports/ARCH-20261116-tspu-blindspots.md),
> [GROWTH-POINTS.md](../../GROWTH-POINTS.md) (GR-25, P1).
> **Затрагиваемые репозитории:** `my-first-vds` (`src/xray/config.py`,
> `src/xray/clients.py`) + `ubuntuInstaller` (`scripts/vpn-manager/vpnm/xclient.py`,
> `vpnm/bins.py`).
> **Минимальная версия Xray-core:** `26.1.23` на сервере (уже развёрнут по
> [ADR-010](../../adr/ADR-010-xray-core-upgrade-26.md)) и на клиенте (унификация
> клиентского бинаря `vpnm` с `25.1.1` до `26.1.23`).
> **Смежное (вне скоупа этой спеки):** разбиение UDP-потока AmneziaWG —
> [awg-flow-splitting-2026-11-16](../../research/awg-flow-splitting-2026-11-16.md).

---

## 1. Проблема (почему дефолтный XHTTP заметен для ML-модели АСБИ)

Сейчас в `src/xray/config.py` (`_xhttp_inbound`) и в клиентском `vpnm/xclient.py`
(`_xray_outbound`) блок `xhttpSettings` содержит только `path` (и `host` на клиенте):

```json
"xhttpSettings": {
  "path": "/<secret_path>"
}
```

При дефолтных настройках:

- **Предсказуемый размер служебных фреймов (SPLT-анализ):** padding заголовков/
  запросов попадает в узкий дефолтный диапазон, что позволяет классификатору
  по первым 10–15 пакетам выделить профиль Xray XHTTP.
- **Долгоживущий H2/TLS-сокет («единая труба»):** при отсутствии явной политики
  ротации в `xmux` клиент стремится переиспользовать одно открытое соединение
  слишком долго, создавая в NetFlow/IPFIX аномалию «один TCP-сокет к неизвестному
  VPS качает сотни мегабайт десятки минут подряд».

## 2. Целевое решение и боевые параметры

Превратить поток клиент ↔ сервер из одного длинного соединения в непрерывную
последовательность коротких, перекрывающихся во времени HTTPS-сессий с высокой
дисперсией длин пакетов, неотличимую от активного браузерного сёрфинга по
медиа-сайту.

### 2.1. Параметры сервера (`src/xray/config.py` → `_xhttp_inbound`)

На стороне сервера в `streamSettings.xhttpSettings` добавляется диапазон
`xPaddingBytes`:

```json
"xhttpSettings": {
  "path": params.xhttp_path,
  "mode": "auto",
  "xPaddingBytes": "100-1000"
}
```

- `xPaddingBytes: "100-1000"` — сервер рандомизирует длину служебного padding'а
  в ответах в широком окне от 100 до 1000 байт (равномерное распределение на
  каждый фрейм), размывая гистограмму размеров пакетов (SPLT).
- `mode: "auto"` — сервер принимает как `stream-one` / `stream-up`, так и
  `packet-up` от клиентов.

### 2.2. Боевые параметры клиента (`ubuntuInstaller`: `vpnm/xclient.py` → `_xray_outbound`)

На стороне клиента в `streamSettings.xhttpSettings` задаются `xPaddingBytes`,
`mode: "auto"` и блок управления жизненным циклом сокетов `xmux`:

```json
"xhttpSettings": {
  "path": link.params.get("path", "/"),
  "host": link.params.get("host", sni),
  "mode": link.params.get("mode", "auto"),
  "xPaddingBytes": "100-1000",
  "xmux": {
    "maxConcurrency": "2-4",
    "maxConnections": 0,
    "cMaxReuseTimes": "32-64",
    "hMaxRequestTimes": "64-128",
    "hMaxReusableSecs": "180-300",
    "keepAlivePeriod": 0
  }
}
```

Обоснование каждого числа в `xmux` (против ТСПУ / АСБИ):

| Параметр | Боевое значение | Зачем именно такое значение |
|---|---|---|
| `maxConcurrency` | `"2-4"` | Держит от 2 до 4 параллельных суб-соединений (как современный Chrome к HTTP/2 origin). Убирает признак «одиночной VPN-трубы». |
| `maxConnections` | `0` | Отключает жёсткий потолок числа соединений при наличии `maxConcurrency` (требование Xray: `maxConcurrency` и `maxConnections` не должны конфликтовать). |
| `cMaxReuseTimes` | `"32-64"` | Один TCP/TLS-сокет переиспользуется максимум для 32–64 туннельных сессий (рандомно для каждого нового сокета), после чего принудительно закрывается (FIN) и рядом открывается новый TCP-сокет с новым sport. |
| `hMaxRequestTimes` | `"64-128"` | Внутри одного соединения проходит не более 64–128 HTTP-запросов, после чего соединение ротируется. |
| `hMaxReusableSecs` | `"180-300"` | Жёсткий TTL жизни одного сокета: 3–5 минут (с рандомным джиттером 180..300 с). Даже если пользователь непрерывно смотрит 2-часовой стрим, для DPI и NetFlow это выглядит как серия из ~30 независимых 3–5-минутных HTTPS-соединений без единого обрыва внутри туннеля! |
| `keepAlivePeriod` | `0` | Никакого периодического пинг-метронома в простое (аналог правила И44 для AWG: нет трафика — нет периодических маяков). |

> **Примечание по версиям Xray** (`cMaxLifetimeMs` vs `hMaxReusableSecs`):
> в Xray-core 26.1.23 время жизни HTTP-соединения в `xmux` задаётся в секундах
> полем `hMaxReusableSecs: "180-300"` (а ротация сокета по числу использований —
> `cMaxReuseTimes: "32-64"`). Оба поля принимают строковые диапазоны `"min-max"`,
> которые Xray разыгрывает случайно при создании каждого нового сокета.

## 3. Унификация клиентского бинаря Xray (ubuntuInstaller)

Сейчас в `vpnm/xclient.py` указано `XRAY_TUN_MIN_VERSION = "26.1.23"` для
`xray-split`, но `vpnm/bins.py` для обычных SOCKS-профилей качает пин `25.1.1`.

В рамках этой спеки пин в `vpnm/bins.py` поднимается до `v26.1.23`
(с соответствующим SHA256 из официального `.dgst`), чтобы и `vpn up`, и
`vpn start xhttp` (`xray-split`) гарантированно поддерживали единый синтаксис
`xPaddingBytes` и `xmux`.

## 4. Обратная совместимость и Share-link (`src/xray/clients.py` / `vpnm/links.py`)

- Серверный инбаунд с `xPaddingBytes: "100-1000"` полностью обратно совместим
  со старыми клиентами (Hiddify / v2rayNG / старый `vpnm`), которые подключаются
  только по `path`: сервер не отвергает клиентов с дефолтным `xmux`, а новые
  клиенты (`vpnm`) автоматически включают `xmux`-ротацию.
- В `render_xhttp_share_link()` (`src/xray/clients.py`) базовый формат URI
  (`vless://...&type=xhttp&path=...`) не ломается, чтобы ссылки продолжали
  импортироваться в мобильные клиенты (v2rayNG / Streisand) без ошибок парсинга
  неизвестных query-параметров.

## 5. Тест-кейсы (`vds-tester`)

### Сервер (`my-first-vds`)

- **T-XM1:** `render_config()` с `xhttp_enabled=True` включает `"mode": "auto"` и
  `"xPaddingBytes": "100-1000"` в `xhttpSettings`.
- **T-XM2:** `_xhttp_fields()` в `src/xray/cdn.py` не теряет `xhttpSettings` при
  пересборке конфига.
- **T-XM3 (живой/Docker smoke):** `xray -test -config config.json` на Xray 26.1.23
  возвращает `Configuration OK`.

### Клиент (`ubuntuInstaller`)

- **T-XM4:** `xray_config()` и `xray_tun_config()` для протокола `xray-xhttp`
  рендерят `xPaddingBytes: "100-1000"` и полный блок `xmux` (`maxConcurrency:
  "2-4"`, `cMaxReuseTimes: "32-64"`, `hMaxRequestTimes: "64-128"`,
  `hMaxReusableSecs: "180-300"`).
- **T-XM5:** `bins.py` пиннутый на `v26.1.23`; `xray -test` на сгенерированном
  клиентском конфиге проходит с кодом 0.
- **T-XM6 (A/B приёмка на ноутбуке):** при непрерывной прокачке 50 МБ через
  `xray-split` (xhttp) в `ss -tn dst <SERVER_IP>:8443` наблюдается 2–4
  параллельных сокета и их плавная ротация каждые 3–5 минут без разрыва
  пользовательского скачивания.
