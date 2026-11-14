# TEST-20261114-xhttp-split — приёмка XHTTP-split (stage 1)

> Тестер/архитектор: `vds-architect`. Дата: 2026-11-14.
> SPEC: [SPEC-20261114-xhttp-split](../specs/SPEC-20261114-xhttp-split.md).
> Код: ubuntuInstaller `e7abe5e` (WP-1), `dcc1dfd` (WP-2), `631f098` (WP-3),
> `f29cf31` (WP-4), `d8ff5a4` (ревью-фиксы).
> Проверка: чистое Ubuntu 24.04 + systemd в контейнере (`/dev/net/tun`,
> privileged), stub `15_domain-split` (DNS/dnsmasq в контейнере не ставились),
> реальный XHTTP-профиль `xhttp-web` (asv1:8443).

## 1. Итог

| Слой | Вердикт |
|---|---|
| tun/unit/rules/kill-switch | **PASS** (после ревью-фиксов) |
| vpnm (scheme/monitor/mutual exclusion) | **PASS** по unit-тестам (379) |
| end-to-end XHTTP | **BLOCKED**: сервер 25.1.1 несовместим с клиентом 26.1.23 |

Код принят условно; **включать на проде нельзя**, пока не решён вопрос
версии серверного Xray (см. §4).

## 2. Что проверено

- `pytest -q` vpnm: **379 passed**; `bash -n` 15/17 — ok.
- Контейнер: `17 --profile test` → xray 26.1.23 скачан, SHA256 из `.dgst`
  совпал, `xray -test` OK, unit active, `xray0` up, IPv4 `10.66.0.1/30`,
  `ip rule fwmark 0x23000`, table 23000 → `dev xray0`.
- **Kill-switch**: `systemctl stop vpn-xray-split@test` → iface исчез,
  rule/table сняты, прямой `https://example.com` = 200 (blackhole нет).
- `17 --off` → unit-шаблон/правила/route сняты, интернет напрямую.

## 3. Найдено и исправлено при приёмке

| Дефект | Последствие | Фикс (`d8ff5a4`) |
|---|---|---|
| Xray tun не назначает IPv4 | пакеты уходили с чужим src, ответы не возвращались | `ip addr replace 10.66.0.1/30 dev xray0` в cleanup `--apply` |
| `ExecStartPost` обгонял создание tun | addr/rule не ставились | ожидание iface до 10 с |
| Повторный `17 --profile` | `xray -test`: device busy | stop юнита перед валидацией |
| `Xray-linux-*.zip` без проверки | supply-chain риск | SHA2-256 из `.dgst` (формат `SHA2-256=`), отказ при несовпадении; arm64 |
| zip не сохраняет exec-бит | «бинарь не найден» | `chmod 0755` перед install |
| mutual exclusion AWG | `systemctl is-active 'unit@*.service'` с glob не раскрывался — два tun могли сосуществовать | `amneziawg.local_instance()` |
| nft-статус без root | `vpn monitor` показывал «таблицы нет» | `sudo -n nft list table` |
| cleanup heredoc | `$(seq …)` раскрывался при генерации → syntax error | экранирование |

## 4. Блокер: Xray 25.1.1 (сервер) ↔ 26.1.23 (клиент)

Xray tun появился только в **26.1.23** (в 25.1.1 его нет), поэтому клиент
поднят на 26.x. Сервер asv1 запинен на **25.1.1** (`XRAY_VERSION`).

| Проверка | Результат |
|---|---|
| 26.1.23 клиент → 25.1.1 сервер (xhttp 8443) | **400 Bad Request** (`splithttp: unexpected status 400`) во всех режимах (`auto/packet-up/stream-up`) |
| 26.1.23 клиент → 26.1.23 сервер (временный инбаунд 8445) | **200 OK** |
| tun через 26-сервер (временный 8445) | **200 OK**, `curl --interface xray0` |
| 25.1.1 socks-профиль xhttp (текущий `xhttp-web`) | работает (106 Мбит/с) |

Временный 26-сервер и его конфиг удалены, asv1 не изменён (vds-xray 25.1.1,
443/8443/2053 active). 8445 закрыт.

## 5. Варианты разблокировки (нужно решение владельца)

| Вариант | Плюсы | Минусы |
|---|---|---|
| **A. Обновить серверный Xray до 26.x** | одна версия, xsplit работает, закрывает GR-06 | риск для Reality-клиентов (смена хендшейка/ML-KEM), нужен ADR + приёмка всех транспортов; откат бинаря |
| **B. Второй Xray 26 на отдельном порту (8445) только для xsplit** | Reality 25.1.1 не трогаем; изоляция риска | +1 процесс/юнит/порт на сервере, vds-код (`add-xhttp26`), конфиг/сертификат, мониторинг |
| **C. Xsplit поверх Reality вместо XHTTP** | обе версии совместимы (проверить), без серверных изменений | меняет SPEC (не XHTTP), Reality+Vision и tun — отдельные грабли; скорость ниже XHTTP |

Рекомендация: **B** как безопасный шаг (не ломает текущие клиенты), с
последующим A отдельным циклом (GR-06). C — только если B/A неприемлемы.

## 6. Состояние

- Ноутбук: xsplit не включён; `vpn scheme`/`reset` не менялись по факту
  (код есть, но без профиля на 26-сервер не применялся).
- asv1: без изменений, временный 26-процесс удалён.
- Контейнер/образы удалены.

## 7. Что дальше

1. Решение A/B/C.
2. При A/B: приёмка «youtube 204 через split, RU напрямую, stop → без
   blackhole, переключение AWG↔xsplit» на ноутбуке.
3. При B: SPEC-патч на второй инбаунд (порт 8445, отдельный юнит, состояние,
   ссылка профиля), затем повторный прогон §2.


---

## 8. Stage 2: обновление серверного Xray до 26.1.23 (вариант A)

Решение владельца: A. Выполнено на asv1 2026-11-14:

- бэкапы: `/usr/local/bin/xray.bak-25.1.1`, `/usr/local/etc/xray/config.json.bak-xray25`;
- скачан 26.1.23, SHA256 из `.dgst` совпал;
- **старый конфиг проходит `xray -test`** под 26 (менять не пришлось);
- рестарт `vds-xray`: active, 443/8443/2053 слушаются; `state.protocols["xray"].version` обновлён на `v26.1.23`.

Проверки после апгрейда (клиент на ноутбуке — Xray 25.1.1):

| Канал | Результат |
|---|---|
| Reality `phone` | 200, TTFB 0.35 с |
| XHTTP `xhttp-web` (25-клиент → 26-сервер) | 200, TTFB 0.81 с |
| CDN `cdn-home` | 200, TTFB 3.05 с (без изменений) |
| Hysteria2 `mob` | 200, TTFB 0.29 с (не затронут) |
| 26.1.23-клиент → 26-сервер XHTTP | **200** (ранее 400) |
| XHTTP-split в контейнере (26-клиент, 8443) | **200** через `xray0` |

Откат: вернуть `xray.bak-25.1.1` → `systemctl restart vds-xray` (конфиг не
менялся). ADR: [ADR-010](../../adr/ADR-010-xray-core-upgrade-26.md).

### Найдено на ноутбуке (follow-up)

`vpn scheme xhttp-split` на живом ноутбуке применился (unit/tun/addr/rules
поднялись, `dig @127.0.0.1 www.youtube.com` отвечал), но общий DNS перестал
резолвить не-split домены: `curl https://example.com` → timeout, при этом
`ya.ru` (прямой) работал. После `vpn reset` сеть/DNS восстановились.
Причина не изолирована: dnsmasq использует `server=127.0.0.1#5053` (DoH), а
`vpn scheme xhttp-split` не поднимает DoH-цепочку (в отличие от AWG-схемы,
где это делал `vpn start`). Кандидат в фикс: `17`/`xsplit` должен вызывать
`vpn doh on` (или 15 — проверять/поднимать cloudflared) до записи
dnsmasq-конфига; иначе `strict-order` уходит в мёртвый 5053.

Итог stage 2: **core PASS** (сервер 26 + tun/rules/kill-switch + e2e в
контейнере), **laptop full acceptance — conditional** до фикса DoH-цепочки.

---

## 9. Stage 3: финальная приёмка на ноутбуке (PASS)

После stage 2 (`vpn scheme xhttp-split`) всплыли три дефекта, все исправлены
и перепроверены:

| Дефект | Симптом | Фикс |
|---|---|---|
| **петля xray→свой tun** | домен сервера в зоне `com` попадал в nft-set → сокет xray к серверу маркировался 0x23000 и уходил в xray0; `proxy/tun: connection was refused`, таймауты | `sockopt.mark=0xca6c` в tun-конфиге; nft уже делает `meta mark 0xca6c return` |
| **DoH включался до снятия AWG** | `15 --off` внутри `_stop_awg_scheme` гасил dnsmasq/DoH, split оставался без DNS | `_ensure_doh` перенесён после снятия AWG |
| **два dnsmasq-конфига** | `awg-split.conf` + `xray_split.conf` → `illegal repeated keyword`, dnsmasq не стартует | один split-конфиг (`awg-split.conf`), `xray_split.conf` удаляется |
| `/etc/vpn-manager` отсутствовал | `install: No such file or directory` при записи конфига | `sudo install -d -m 0700` перед install |

Итоговые проверки (живой ноутбук, сервер 26.1.23):

| Проверка | Результат |
|---|---|
| `vpn scheme xhttp-split` | unit active, iface `xray0`, `10.66.0.1/30`, mark 0x23000/table 23000 |
| youtube через split | **204** |
| `example.com` (зона `com`) через split | **200** |
| `ya.ru` (RU) | **302**, маршрут через `wlp44s0` (напрямую) |
| `vpn monitor` | `xray-split: ok`, `dns-doh: ok` |
| kill-switch (`systemctl stop`) | rule/table сняты, `example.com` напрямую **200** |
| `vpn reset` | unit/iface/rules/DNS сняты, интернет **200**, dnsmasq/cloudflared inactive |

**Итог: G4 PASS.** XHTTP-split работает как системная схема «как AWG»:
split-зоны через tun xray0 → VLESS+XHTTP, RU/исключения — напрямую, kill-switch
без blackhole, `vpn reset` возвращает чистое состояние.

## 10. Follow-up (не блокирует)

- `vpn scheme awg` ↔ `xhttp-split` — проверить на живом ноутбуке (unit-тесты
  mutual exclusion есть; полный цикл не гонялся после финального фикса).
- `vpn speed` для xsplit (системный канал не socks) — измерять прямым curl;
  можно добавить канал в speed по аналогии с AWG.
- UDP-over-TCP остаётся ограничением XHTTP; для звонков/игр — AWG.

---

## 11. Обобщение на Reality (2026-11-14, PASS)

Схема переименована в **`vpn scheme xray-split [profile]`** и работает для
Reality и XHTTP; `xhttp-split` оставлен алиасом (автовыбор XHTTP).

Проверено на живом ноутбуке:

| Проверка | Reality (`phone`) | XHTTP (`xhttp-web`) |
|---|---|---|
| `vpn scheme xray-split …` | применён, unit active | применён (регресс) |
| youtube через split | **204** | **204** |
| `example.com` через split | **200** | **200** |
| `ya.ru` напрямую | **302** | **302** |
| `vpn monitor` | `xray-split: ok`, `dns-doh: ok` | то же |
| kill-switch (`systemctl stop`) | rules сняты, direct **200** | то же |
| `vpn reset` | чисто | чисто |

Дополнительно:
- `resolve_profile` принимает `xray-reality`/`xray-xhttp`, алиас
  `xhttp-split` фильтрует автовыбор по XHTTP;
- перед стартом split добавлено ожидание готовности DoH
  (`_wait_doh`) — устраняет флап резолвера при apply;
- unit/config/17/15 не менялись: транспорт задаётся профилем (flow Vision
  для Reality, path для XHTTP);
- тесты: **383 passed** (+4 Reality/алиас/DoH).

Ограничения Reality-split те же: UDP-over-TCP, системный tun только на
ноутбуке, порт 443 (лучшая маскировка, чем XHTTP).

---

## 12. Быстрый вход `vpn start [reality|xhttp|awg]` (2026-11-14, PASS)

`vpn start` без аргумента теперь поднимает Reality-split (раньше — AWG);
схема выбирается аргументом.

| Команда | Результат | Проверки |
|---|---|---|
| `vpn start` | Reality (`phone`) | youtube 204, example 200, ya.ru 302 |
| `vpn start xhttp` | XHTTP (`xhttp-web`) | youtube 204, example 200 |
| `vpn start awg` | AWG + доменный split | youtube 204, example 200, ya.ru 302 |
| `vpn start wireguard` | ошибка, exit 2 | подсказка `reality|xhttp|awg` |
| `vpn reset` после каждого | чисто | нет `xray0`, правил, DNS провайдера |

Детали:
- Reality/XHTTP берут первый подходящий профиль из `vpn profile list`;
  конкретный — `vpn scheme xray-split <profile>`;
- `start awg` снимает xray-split, `start reality|xhttp` — AWG (взаимоисключение);
- `vpn speed` для AWG-канала вызывает `vpn start awg` (не голый `start`);
- тесты: **392 passed** (+4 на дефолт/диспетчеризацию/ошибку).
