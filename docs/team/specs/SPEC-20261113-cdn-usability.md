# SPEC-20261113-cdn-usability

## Мета
- **Источник:** задача владельца 2026-11-13 «почему вариант CF оказался
  неработоспособным; точки роста» + живые замеры (CF edge TLS 0.23 / 7.37 /
  0.45 с; cdn-home TTFB 1.2–1.6 с; 1 МБ через OVH 1.46 с; bulk в
  speed-тесте — 0 байт). REQ не заводился: SPEC самодостаточен, при
  необходимости аналитик оформит REQ пост-фактум.
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-13
- **Статус:** approved (G2); **G4 FAIL 2026-11-13** — WP-1 (mux) вернуть
  кодеру (mux через CF не работает), WP-2/WP-3 приняты; см.
  [TEST-20261113-cdn-mux](../reports/TEST-20261113-cdn-mux.md)
- **ADR:** не требуется (клиентская оптимизация, обратимо флагом; серверные
  контракты не меняются)

## 1. Цель и решение

CDN-канал (VLESS+WS+TLS через Cloudflare, origin 2053) работает, но ощущается
мёртвым: каждый запрос платит полный стек TLS→WS→VLESS, потому что
мультиплексирования нет (`mux: {}` в сгенерированном конфиге), а TLS-хендшейк
к CF периодически залипает на секунды. Цель — сделать CDN **пригодным
резервным браузерным каналом** и **измеримым**: включить Mux для WS-профиля
(одно соединение — много потоков), добавить честную диагностику TTFB
(p50/p95) в `vpn speed` (она работает даже когда bulk не отдаётся), и дать
воспроизводимый A/B-бенчмарк.

Решение: Mux — **только для `xray-cdn-ws`** (для Reality/Vision и XHTTP не
включаем: Vision несовместим с Mux, XHTTP мультиплексирует сам). По умолчанию
Mux **выключен** (обратная совместимость), включается настройкой
`vpn mux on` или разовым `vpn up <profile> --mux`. TTFB-замеры — часть
`vpn speed` (3 сэмпла по умолчанию, серийно, И26).

## 2. Архитектура

```
vpn up cdn-home --mux
  → xclient.xray_config(link, socks, mux=True)   # outbound.mux = {enabled, concurrency}
  → generated/cdn-home.json → user unit vpnm-cdn-home.service

vpn speed --include-cdn --ttfb-samples 3
  → для каждого канала: egress → latency → TTFB xN → bulk xN
  → live-таблица: latency | ttfb p50/p95 | Мбит/с | эндпоинт
  → last-speed.json: ttfb_samples / ttfb_p50_ms / ttfb_p95_ms

scripts/bench-cdn-mux.sh
  → nomux: vpn up cdn-home; 7×(TTFB example.com, 1 МБ OVH); vpn down
  → mux:   vpn up cdn-home --mux; то же; печать p50/p95/throughput
```

Точки отказа: CF TLS-залипание (внешнее, влияет на оба режима); mux при
одном медленном потоке может ухудшить bulk — поэтому A/B обязателен и
дефолт остаётся `off`.

## 3. Изменения в коде

Репозиторий: `ubuntuInstaller` (ветка `main`, каталог `scripts/vpn-manager/`).
`vds` **не трогаем**.

| Файл | Действие | Назначение |
|---|---|---|
| `vpnm/xclient.py` | изменить | `xray_config(..., mux: bool = False)`; блок `mux` только для `PROTOCOL_XRAY_WS` |
| `vpnm/runners.py` | изменить | `write_config(..., mux=False)`, `up(name, run=None, mux: bool \| None = None)`, `switch(...)` — проброс |
| `vpnm/settings.py` | изменить | `get_mux()/set_mux(bool)` в `settings.json` (0600) |
| `vpnm/cli.py` | изменить | `vpn mux on\|off\|status`; `vpn up <name> [--mux/--no-mux]`; `vpn speed --ttfb-samples N`; колонки TTFB |
| `vpnm/speed.py` | изменить | `measure_ttfb()`, поля `ttfb_samples/ttfb_p50_ms/ttfb_p95_ms`, события `ttfb` |
| `scripts/bench-cdn-mux.sh` | создать | A/B-бенчмарк (serial, паузы ≥1 с, И26) |
| `tests/test_xclient.py` | изменить | mux только WS; off по умолчанию; concurrency |
| `tests/test_runners.py` | изменить | mux-флаг доходит до конфига; настройка по умолчанию |
| `tests/test_speed.py` | изменить | парсер TTFB, p50/p95, события, серийность |
| `tests/test_cli_lifecycle.py` (или новый `test_mux.py`) | изменить | `vpn mux on/off/status`, `vpn up --mux` |
| `doc/vpn-manager.md` | изменить | mux, TTFB-колонки, bench-скрипт, ограничения |

**Публичные интерфейсы (сигнатуры):**

```python
# vpnm/xclient.py
def xray_config(link: ProfileLink, socks_port: int, mux: bool = False) -> str: ...

# vpnm/runners.py
def write_config(name: str, link: ProfileLink, socks_port: int,
                 mux: bool = False) -> Path: ...
def up(name: str, run: Optional[RunCmd] = None,
       mux: Optional[bool] = None) -> Path: ...   # None → settings.get_mux()
def switch(name: str, run: Optional[RunCmd] = None,
           mux: Optional[bool] = None) -> Path: ...

# vpnm/settings.py
def get_mux() -> bool: ...
def set_mux(enabled: bool) -> None: ...

# vpnm/speed.py
def measure_ttfb(socks_port: Optional[int], timeout: float,
                 run: RunCmd) -> Optional[float]: ...  # секунды
```

**CLI-поверхность:**

```bash
vpn mux on|off|status
vpn up cdn-home --mux          # разово, не меняя настройку
vpn up cdn-home --no-mux
vpn speed --include-cdn --ttfb-samples 3
```

**Формат конфига (ожидаемый блок для WS):**

```json
"outbounds": [{
  "...": "...",
  "mux": {"enabled": true, "concurrency": 8}
}]
```

Для Reality/XHTTP блок `mux` **отсутствует** даже при `mux=True` (в
`vpn mux status` писать: «mux применяется только к CDN-профилям»).

**Формат settings.json:**

```json
{"mux": true}
```

## 4. Миграция и совместимость

- Дефолт `mux=false` — существующие профили и ссылки не меняются; повторный
  `vpn up` без флага генерирует конфиг как раньше.
- `settings.json` читается терпимо: отсутствие ключа = false; посторонние
  ключи не удаляются.
- Серверные ссылки/порты/сертификаты не меняются; `vds` не правится.
- Откат: `vpn mux off` + `vpn up <profile> --no-mux`; файл конфига
  перегенерируется, ничего в state не мигрирует.

## 5. Безопасность и отказы

- Секреты: конфиг по-прежнему 0600; mux не добавляет секретов; в логах —
  только имена профилей.
- Рестарт при смене режима: `vpn up` уже останавливает/запускает юнит;
  A/B не должен оставлять два клиента на одном socks-порту.
- Failure modes:
  - mux включён, но CDN не поднялся → юнит inactive, `vpn doctor` подскажет;
  - TTFB не измерился (timeout) → `ttfb_p50_ms: null`, статус не меняется;
  - bulk не отдался, TTFB есть → статус «только задержка», не «ошибка».
- `vpn reset` должен снимать профиль независимо от режима mux.

## 6. Тест-план

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | `mux` появляется только для WS; дефолт off; `concurrency: 8`; settings roundtrip; TTFB-парсер и p50/p95; события `ttfb`; серийность (И26) | `tests/test_xclient.py`, `test_runners.py`, `test_speed.py`, `test_mux.py` |
| CLI | `vpn mux on/off/status`; `vpn up --mux/--no-mux`; `vpn speed --ttfb-samples` | `tests/test_cli_lifecycle.py` / `test_mux.py` |
| Integration (ручная, ноутбук) | A/B на живом `cdn-home`: 7×TTFB example.com + 1 МБ OVH в каждом режиме; p50/p95 и throughput | `scripts/bench-cdn-mux.sh` |
| Регресс | `vpn speed` без `--include-cdn` не меряет CDN; другие профили (±10 %); `pytest` vpnm и vds | `pytest -q` |

**Критерии приёмки (проверяет тестер):**

1. `pytest -q` в `scripts/vpn-manager` — зелёный (текущая база 341+).
2. `xray_config` для Reality/XHTTP не содержит `mux` ни при каких флагах.
3. A/B на `cdn-home`: **TTFB p50(mux) ≤ 0.7 × TTFB p50(nomux)** ИЛИ
   ≤ 0.7 с абсолютно; throughput 1 МБ ≥ 5 Мбит/с в режиме mux.
4. `vpn speed --include-cdn --ttfb-samples 3` показывает TTFB p50/p95 даже
   если bulk = 0 байт (статус «только задержка», не «нет данных»).
5. `vpn speed` без `--include-cdn` CDN не трогает (сохранить поведение
   2026-11-13).
6. `vpn reset` после A/B: нет iface/юнитов/socks-портов; `vpn status` — чистый.
7. В логах/отчётах нет ссылок/паролей; JSON-отчёт 0600.

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| **WP-1** | Mux для CDN: генератор + проброс + настройка + CLI `vpn mux` и `up --mux` | `vpnm/xclient.py`, `vpnm/runners.py`, `vpnm/settings.py`, `vpnm/cli.py` (только mux-команда/флаги), `tests/test_xclient.py`, `tests/test_runners.py`, `tests/test_mux.py` | — | `pytest` зелёный; WS-конфиг с mux, Reality/XHTTP без; дефолт off; `vpn mux status` честно говорит про ограничение CDN |
| **WP-2** | TTFB-диагностика в `vpn speed` | `vpnm/speed.py`, `vpnm/cli.py` (только speed-опции/колонки), `tests/test_speed.py`, `doc/vpn-manager.md` | WP-1 (для A/B, но код независим) | TTFB p50/p95 в таблице и JSON; серийно; статус «только задержка» |
| **WP-3** | A/B-бенчмарк + документация | `scripts/bench-cdn-mux.sh`, `doc/vpn-manager.md` (раздел bench) | WP-1, WP-2 | скрипт печатает p50/p95/throughput для nomux/mux; паузы ≥1 с; не оставляет включённых профилей |

Границы: WP-1 и WP-2 пересекаются только `vpnm/cli.py` — правки в разных
местах файла; при конфликте WP-1 мержится первым, WP-2 — ребейз. WP-3 не
трогает код.

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| Mux ухудшает bulk (один медленный поток) | средняя | CDN станет медленнее | дефолт off; A/B; порог из §6 |
| CF TLS-залипание искажает A/B | высокая | ложный вывод | 7 сэмплов + p50/p95; прогон в разное время; фиксировать дату/время |
| Mux ломает WS-апгрейд/прокси CF | низкая | профиль не поднимется | smoke `curl` через socks до/после; откат `--no-mux` |
| Пересечение правок cli.py | средняя | конфликт | порядок WP-1 → WP-2; разные секции |
| `nft`/юниты остаются от A/B | средняя | «мусор» в системе | `vpn reset` в конце bench; проверка в приёмке |

## 9. Границы изменений

- **Трогаем:** `scripts/vpn-manager/vpnm/{xclient,runners,settings,speed,cli}.py`,
  тесты vpnm, `doc/vpn-manager.md`, новый `scripts/bench-cdn-mux.sh`.
- **Не трогаем:** репозиторий `vds` (сервер), формат share-ссылок, схему
  профилей (только чтение), sysproxy, TUI (пункт меню менять не нужно),
  секреты/права файлов, systemd-шаблоны сервера.
- **Вне скоупа (отдельные SPEC):** `cloudflared tunnel` вместо публичного
  origin, XHTTP через CF, Argo Smart Routing, пул CDN-фронтов (GR-08).

## 10. Трассируемость

| Источник | WP | Файлы | Тест |
|---|---|---|---|
| Замер: TTFB 1.2–1.6 с, mux отсутствует | WP-1 | `xclient.py`, `runners.py`, `settings.py` | `test_xclient.py`, `test_runners.py`, `test_mux.py` |
| Замер: bulk 0 при живом TTFB | WP-2 | `speed.py`, `cli.py` | `test_speed.py` |
| A/B-требование владельца | WP-3 | `bench-cdn-mux.sh` | ручная приёмка §6 |

## Следующий шаг

→ `vds-coder` выполняет **WP-1 → WP-2 → WP-3** по одному (каждый — отдельный
коммит `feat(vpnm): …`); после каждого WP — `pytest -q` в
`scripts/vpn-manager`. Затем `vds-tester` (архитектор) по §6: unit + A/B на
`cdn-home` + регресс, с записью результатов в
`docs/team/reports/TEST-20261113-cdn-mux.md` (в репозитории `vds`).


## 11. Результат приёмки (2026-11-13)

Приёмка: [TEST-20261113-cdn-mux](../reports/TEST-20261113-cdn-mux.md).

- **WP-2** — PASS: TTFB p50/p95 в `vpn speed`, статус «только задержка»
  подтверждён на живом `cdn-home` (p50 2615 мс при bulk 0).
- **WP-3** — PASS с замечанием: нет контроля (прямой TLS к CF) и smoke;
  фейлы mux были ошибочно списаны на «TSPU-окно».
- **WP-1** — FAIL: mux через Cloudflare нестабилен (1/5 запросов; nomux 5/5
  в тот же момент; `concurrency` 1 и 2 не помогают). Решение: откатить mux,
  вынести «XHTTP through CF» в отдельную SPEC.
