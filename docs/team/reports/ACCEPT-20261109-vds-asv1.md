# ACCEPT-20261109-vds-asv1 — [VDS]-приёмка Gateway MVP (фазы 1–2)

## Мета
- **Базис:** чеклист §8 из [TEST-20261107-gateway-mvp](TEST-20261107-gateway-mvp.md);
  REPО-снапшот на asv1 = commit `e5ececb` (rsync, runtime `gateway/state.json` исключён из синка)
- **Автор:** оркестратор (vds-orchestrator); часть проверок независимо воспроизведена
  на внешней машине (probe-resistance, e2e-туннели)
- **Дата:** 2026-11-09 · **Сервер:** asv1 / 103.45.247.172 (Ubuntu 24.04.5, root)
- **Вердикт:** **PASS (19/28 прогнано, все PASS; 7 N/A|manual; 2 не прогнаны — см. §3)**.
  Оба протокола установлены, активны, **подтверждены end-to-end с внешней машины**.

## 1. Результаты по чеклисту

| # | Проверка | Результат | Примечание |
|---|---|---|---|
| 1–2 | install без root → отказ | **PASS** | `Требуется root`, exit 1, ничего не изменено (vpn-accept) |
| 3 | xray install при занятом 443 | **PASS** | «Порт 443/tcp занят (владелец: xray)» ДО изменений — наблюдалось в живом инциденте state-восстановления |
| 4–7 | установка xray, юнит active, TCP 443, config 0600 | **PASS** | |
| 8 | идемпотентный xray install | **PASS (после P12)** | до фикса — «порт занят»; после — «уже установлен», exit 0, конфиг не перегенерирован (md5) |
| 9 | нестандартный SNI | не прогнан | требует чистой системы; SNI-рендер покрыт юнит-тестами |
| 10 | add-client phone, share-link, нет privateKey | **PASS** | формат ссылки по REQ; privateKey только в config.json |
| 11 | дубль имени | **PASS** | StoreError, exit 1 |
| 12 | UUID/пароль/ключ не в journal | **PASS** | проверено grep по journalctl обеих юнитов: 0 совпадений (uuid, auth-пароль, privateKey) |
| 13 | xray status | **PASS** | active, конфиг валиден, порт слушается, journal маскирован |
| 14 | порча конфига → FAIL | **PASS с оговоркой** | статус корректно зеркалит `xray -test`; пустой/битый файл → «Конфиг невалидн … FAIL», сервис не поднимается; хвостовой мусор Xray-core парсит толерантно (особенность апстрима, не наш дефект); файл восстановлен |
| 15 | probe-resistance (FR-X.1) | **PASS** | с внешней машины: `curl https://www.google.com --resolve` через IP → 200, сертификат `CN=www.google.com` (Google Trust Services), чужой SNI → `*.google.com`; признаков Xray нет |
| 16–18 | hysteria2: порт-чек, установка, 0600, сертификат ~10 лет, идемпотентность | **PASS** | cert до 2036-11-06; повтор — «уже установлен», cert.md5 неизменен |
| 19 | add-client mob, share-link | **PASS** | |
| 20 | hysteria2 status | **PASS** | active, «осталось 3649 дн.», UDP 443 |
| 21 | bbr | **PASS** | `net.ipv4.tcp_congestion_control = bbr` |
| 22 | TCP и UDP 443 одновременно (FR-X.2) | **PASS** | xray (TCP) + hysteria (UDP) слушают 443 параллельно |
| 23 | zerotier diagnose | **N/A** | ZeroTier на asv1 не установлен (вне скоупа приёмки) |
| 24, 27 | remove dry-run | **PASS** | только план, ничего не удалено; sysctl помечен «НЕ трогаем» (ADR-002) |
| 25–26 | remove --apply + повтор | не прогнаны | `--apply` в CLI использует questionary-подтверждение, в не-TTY сессии недоступно (известный minor из TEST-20261107: `yes=` не экспонирован); удалить/переустановить можно вручную |
| 28 | эмуляция недоступности GitHub | **PASS (фактом)** | реальная недоступность GitHub (RKN-DPI) случилась в ходе приёмки; `VDS_GITHUB_MIRROR=https://ghproxy.net` обеспечил доставку, SHA256-проверки пройдены на живом хосте |

## 2. End-to-end с внешней машины (главный результат)

- **Hysteria2:** клиент app/v2.13.0 (внешняя машина) → `connected to server … udpEnabled: true`;
  `curl --socks5 → https://api.ipify.org` → **103.45.247.172, code 200**
- **Xray Reality:** клиент v25.1.1 (внешняя машина) → `Xray started`, 0 ошибок;
  `curl --socks5 → api.ipify.org` → **103.45.247.172, code 200**; google.com → 200

Оба туннеля реально пропускают трафик через сервер, TCP и UDP одновременно.

## 3. Дефекты, найденные и закрытые в ходе приёмки (все — WP + тесты + push)

| ID | Суть | Коммит |
|---|---|---|
| P8 | dgst-парсер не знал метку `SHA2-256=` апстрима | `5a159b5` |
| P9 | openssl pkeyopt alias `ec_param_gen_curve:prime256v1` не работал на OpenSSL 3.0.13 → `ec_paramgen_curve:P-256` | `96ac1e5` |
| P10 | юнит hysteria2 без subcommand `server` → client-mode crash-loop | `403ef0c` |
| P11 | порт-чек раньше installed-чека → идемпотентность сломана | `403ef0c` |
| P12 | `_installed()` сверял пин `v25.1.1` с выводом `Xray 25.1.1` → всегда False | `e5ececb` |
| — | `VDS_GITHUB_MIRROR` env-override (санкция техлида, ADR-001 поправлен) | `16b9d19` |

Юнит-тесты: 126 → **142 passed** за цикл приёмки.

## 4. Замечания оркестратора (операционные)

1. **runtime-файл state.json лежит внутри дерева деплоя** (`/opt/my-vds/gateway/state.json`);
   первый rsync с `--delete` стёр его. В fixе — exclude при синке. Предложение: перенести
   state в `/var/lib/vds-gateway/` при ближайшем ADR (не в снапшот-дерево).
2. Доставка GitHub-ассетов при DPI: официальный канал нестабилен, зеркала флапают
   (ghfast.top 504 на бинаре, ghproxy.net стабилен). В отчёте зафиксировано зеркало
   `ghproxy.net`; env-off по умолчанию.
3. Пункты 25–26: рекомендация — экспонировать `--yes` в CLI remove (уже в TECHDEBT).

## 5. Итоговое состояние asv1

- Xray v25.1.1: active, VLESS Reality www.google.com:443, клиент `phone`
- Hysteria2 app/v2.13.0: active, QUIC udp/443, сертификат до 2036, клиент `mob`
- gateway state: оба протокола installed; TCP и UDP 443 заняты штатно
- Оба протокола проверены живым трафиком с внешней машины

**[VDS]-приёмка MVP считаю выполненной; G6 может закрываться.**
