# Точки роста: схемы и протоколы (для техлида)

> Вход для intake (G0 IDEA) и планирования циклов. Собрано по фактическому коду,
> состоянию `asv1` и разбору эксплуатации, а не по общим соображениям.
>
> - **Дата:** 2026-11-12
> - **База:** `vds` @ `1f3e7d6`, `ubuntuInstaller` @ `ea2b662` (vpnm 325 passed, vds 499 passed)
> - **Сервер наблюдения:** `asv1` (`root@103.45.247.172`), Ubuntu 24.04
> - **Смежные документы:** [TECHDEBT.md](../TECHDEBT.md) (дефекты и долг),
>   [CENSORSHIP-ROADMAP.md](CENSORSHIP-ROADMAP.md) (фазы 0–9),
>   [VPN-PROTOCOLS.md](VPN-PROTOCOLS.md) (поведение протоколов),
>   [docs/team/STATUS.md](team/STATUS.md) (живой цикл), [docs/adr/](adr/)

## 0. Как читать

Каждый пункт: **факт** (что реально в коде/на сервере), **действие**, **ac** (критерий
приёмки), **оценка**, **файлы**. Приоритеты:

| Приоритет | Значение |
|---|---|
| **P0** | Тихий сбой или архитектурный потолок: чинить в ближайшем цикле |
| **P1** | Сильно повышает эксплуатационную ценность/удобство, дешёвый вход |
| **P2** | Полезно, но без немедленного риска; берётся после P0/P1 |

Оценки — «чистое» время кодера без ревью и живой приёмки.

## 1. Hysteria2 — самый большой запас

### GR-01. ACME deploy-hook не обновляет obfs-инстанс и Xray — **P0**

**Факт.** `src/acme/install.py` пишет hook, который делает
`install cert/key → systemctl restart vds-hysteria2`. Инстанс
`vds-hysteria2-obfs` использует те же `/etc/hysteria/cert.pem`/`key.pem`, но не
перезапускается; Xray (XHTTP/CDN) читает `certificateFile` из
`/etc/letsencrypt/live/...` и тоже не перечитывает файлы сам. На asv1 cert.pem
уже подменялся (`cert.pem.bak-pre-le` от 2026-11-09), т.е. сценарий живой.

**Действие.** В hook после установки сертификата: `systemctl restart` для всех
запущенных потребителей (`vds-hysteria2`, `vds-hysteria2-obfs`, `vds-xray`) —
только если юнит active/enabled; для Xray — `reload-or-restart`. Плюс регресс-тест
на текст hook (список юнитов) и e2e-проверка `certbot renew --dry-run --deploy-hook`.

**AC.** После `renew --dry-run` все три юнита имеют новый отпечаток сертификата;
`vds hysteria2 status` для obfs показывает `days_left`, равный LE; тест hook
зелёный.

**Оценка.** ~30 мин (+ 15 мин тест). **Файлы.** `src/acme/install.py`,
`tests/acme/`, `systemd/` (если понадобится reload-семантика).

### GR-02. Один auth-пароль Hysteria2 на всех клиентов — **P0**

**Факт.** `src/hysteria2/clients.py` (docstring): «ОДИН auth-пароль на инбаунд»;
`remove-client` не отзывает доступ — пароль остаётся в конфиге и в ссылках других
клиентов. Ротация = перевыпуск ссылок всем.

**Действие.** ADR + SPEC на `auth: {type: http}`: минимальный локальный сервис
(loopback, токен-список пользователей в `state.json`), fallback на
`type: password`, если сервис не поднят. Команды: `hysteria2 add-user`,
`remove-user`, `rotate-user`. Совместимость: ссылки не меняются (user:pass в
URI поддерживается hysteria2/sing-box).

**AC.** `remove-user bob` → handshake bob'а отклоняется, alice продолжает
работать; e2e на asv1 с двумя клиентами; state 0600, пароли в логах отсутствуют.

**Оценка.** 1–1.5 дня (ADR + код + e2e). **Файлы.** `src/hysteria2/*`,
`src/gateway/store.py`, `systemd/`, `docs/adr/`.

### GR-03. Port hopping реализован, но не эксплуатируется — **P1**

**Факт.** `src/hysteria2/hop.py` (ADR-008) и `systemd/vds-hysteria2-hop.service.tpl`
готовы; на asv1 `protocols["hysteria2"]["hop_ports"] = None`. При этом у клиентов
есть регресс: v2rayNG 2.3.8 / Xray-core 26.9.9 парсит `mport`, но трафик остаётся
на UDP/443 (2dust/v2rayNG#6224, откат на 2.3.7 лечил).

**Действие.** 1) Включить `add-hop-ports 20000-20500 --apply` на asv1 (UFW на
сервере выключен — проверить файрвол провайдера). 2) Матрица «клиент × hop × obfs»
в `docs/VPN-PROTOCOLS.md` §2.3.1 с версиями. 3) `status` показывает состояние
nat-цепочки и hop-диапазон.

**AC.** `tcpdump` на сервере видит смену dst-портов из диапазона при клиенте
sing-box; `vds hysteria2 status` отражает hop; матрица клиентов опубликована.

**Оценка.** 2–3 ч. **Файлы.** `src/hysteria2/hop.py`, `src/hysteria2/status.py`,
`docs/VPN-PROTOCOLS.md`.

### GR-04. Ротация основного пароля Hysteria2 — **P2**

**Факт.** `rotate-obfs` есть, ротации `auth.password` основного инбаунда — нет.

**Действие.** `hysteria2 rotate-password [--apply]`: новый пароль → config.yaml →
restart → перевыпуск всех hy2-ссылок в state + печать списка клиентов, которым
нужен ре-импорт (по аналогии с `rotate-obfs`).

**AC.** Dry-run показывает план; `--apply` меняет пароль, `gateway links` сразу
отдаёт новые ссылки, старые не подключаются.

**Оценка.** 2–3 ч. **Файлы.** `src/hysteria2/install.py|obfs.py` (паттерн),
`src/gateway/links.py`.

### GR-05. obfs: только salamander, нет pinSHA256 — **P2**

**Факт.** `src/hysteria2/config.py` рендерит фиксированный `type: salamander`;
ссылка умеет только `insecure=1` или LE.

**Действие.** 1) Опция `--obfs-type salamander|gecko` (sing-box 1.13+ понимает
`gecko`, см. `obfs.min_packet_size` в 1.14) с валидацией на импорте в vpnm.
2) Вариант ссылки с `pinSHA256` — для клиентов без нормальной проверки цепочки
(лист отпечатка из `openssl x509 -fingerprint -sha256`), отдельный флаг
`add-client --pin`.

**AC.** Конфиг с `gecko` проходит `hysteria server -c ... --check`; клиент
sing-box 1.14 подключается; pin-ссылка работает при подмене CA-пула.

**Оценка.** 4–6 ч. **Файлы.** `src/hysteria2/config.py|clients.py`,
`vpnm/links.py|xclient.py`.

## 2. Reality / XHTTP / CDN

### GR-06. Нет пути обновления Xray-core — **P1**

**Факт.** На asv1 `Xray 25.1.1`; клиенты идут на 26.x. Отдельной команды обновления
нет (`install` только ставит, если нет бинаря). Известно: Reality нового Xray
(≥26.7.11) несовместим с Mihomo; Mihomo-клиентам нужен `x25519mlkem768`, который
Xray включает начиная с 26.9.8.

**Действие.** `vds xray update [--apply]`: скачивание в tmp → `xray x25519 -i`/
`--version` → проверка `-test -config` → атомарная замена бинаря + бэкап `.bak-old`
→ рестарт → откат при неудаче. В `status` — версия и доступная. Матрица
«версия Xray ↔ клиент» в `VPN-PROTOCOLS.md`.

**AC.** Dry-run показывает текущую/новую версию; `--apply` на asv1 проходит,
конфиг валиден, Reality-gate (client `phone`) работает; откат на бэкап проверен.

**Оценка.** 4–6 ч. **Файлы.** `src/xray/install.py`, `src/xray/status.py`,
`src/main.py`.

### GR-07. Reality: одна маска и нет проверки decoy — **P2**

**Факт.** SNI по умолчанию `www.google.com`, задаётся только при `install`;
`status` проверяет конфиг и порт, но не то, что `dest` реально отдаёт валидный TLS.

**Действие.** `xray set-sni --sni X [--apply]` с перевыпуском Reality-ссылок
(public key/sid не меняются) + локальная проба: TLS-handshake на `dest:443` с
`sni` и проверка `notAfter`. В `status` — строка «decoy ok/fail».

**AC.** Смена SNI перевыпускает ссылки и поднимает Xray; при мёртвом decoy
`status` даёт warning, а не молчит.

**Оценка.** 3–4 ч. **Файлы.** `src/xray/config.py|install.py|status.py`.

### GR-08. CDN: пул фронтов реализован, но не используется — **P1**

**Факт.** `xray add-cdn-front` и рендер по фронтам есть, но на asv1
`protocols["xray-cdn"]["fronts"] = None`, один домен. Нет проверки, что фронт
реально proxied через Cloudflare и отвечает по WS.

**Действие.** 1) `xray cdn-check [--apply]`: по каждому фронту — DNS (CNAME/orange),
HTTP-проба `GET /` через 443 с Host, WS-проба с `Sec-WebSocket-Protocol`-хендшейком
(без VLESS-аутентификации). 2) `status` показывает таблицу фронтов. 3)
`add-cdn-front` предупреждает, если DNS не proxied.

**AC.** Мёртвый фронт помечается в status; клиентская ссылка на него не выдаётся
(или выдаётся с warning); повторный `add-cdn-front` идемпотентен.

**Оценка.** 1 день. **Файлы.** `src/xray/cdn.py`, `src/xray/status.py`,
`docs/CDN-FRONTS.md`.

### GR-09. XHTTP — «xray-only» транспорт — **P2**

**Факт.** XHTTP-инблэнд за SNI-фолбэком Reality работает, но sing-box/Hiddify его
не поддерживают, т.е. профиль бесполезен половине клиентской базы.

**Действие.** Решить осознанно и зафиксировать: (а) оставить как резерв для
Xray-клиентов (v2rayNG/FoXray) и убрать из рекомендаций для мобильных; (б) следить
за появлением xhttp в sing-box и добавить поддержку в `vpnm` при релизе. Пока —
явная колонка в матрице клиентов.

**AC.** В `docs/VPN-PROTOCOLS.md` и `doc/vds.md` матрица «клиент × XHTTP»;
`vpn scheme` не предлагает xhttp профиль для клиентов без поддержки.

**Оценка.** 1–2 ч (док + TUI-фильтр). **Файлы.** `docs/VPN-PROTOCOLS.md`,
`vpnm/xclient.py|channels.py`.

## 3. ACME / сертификаты

### GR-10. Явная привязка «домен → протокол» (`cert_domain`) — **P1**

**Факт.** На asv1 `acme.domain = asvpersonal.ru` (DNS → Cloudflare, это CDN-фронт),
а сертификат hysteria2 — LE на `103-45-247-172.eu-cloud-xip.com`. Сегодня ссылки
чинятся эвристикой `le_domain()` (state.domain + наличие live-каталога);
эвристика хрупкая.

**Действие.** Сохранять `cert_domain` в мете протокола при `apply-cert`/`acme issue`
и при установке XHTTP/CDN; рендеры берут его первым, `le_domain()` остаётся
fallback. Миграция state: при загрузке, если `cert_domain` нет — вывести из
наличия `/etc/letsencrypt/live/<domain>` и записать (однократно, под локом).

**AC.** На asv1 после миграции `gateway links` даёт те же ссылки без файловой
эвристики; юнит-тесты на приоритет `cert_domain`; миграция идемпотентна.

**Оценка.** 3–4 ч. **Файлы.** `src/gateway/store.py`, `src/acme/*`,
`src/hysteria2/clients.py`, `tests/`.

### GR-11. Только HTTP-01 — **P2**

**Факт.** `src/acme/install.py` — HTTP-01 на порту 80. Нет DNS-01: wildcard и
домены за Cloudflare (без grey-toggle) недоступны.

**Действие.** `acme issue --challenge dns-01 --dns-provider cloudflare` (токен в
env/`/etc/vds/secrets`, не в state) через `certbot-dns-cloudflare`; чек-лист
«когда DNS-01 нужен». Плюс проверка `days_left` в `acme status`.

**AC.** Сертификат выписан для `*.example.ru` без открытого 80; токен не попадает
в лог/git; `acme status` показывает остаток дней.

**Оценка.** 1 день. **Файлы.** `src/acme/install.py`, `src/main.py`,
`docs/DEPLOY.md`.

### GR-12. Нет мониторинга срока сертификатов — **P1**

**Факт.** `days_left` парсится в `src/hysteria2/status.py`, но никто не проверяет
его регулярно; таймеры есть только у ZeroTier.

**Действие.** Включить проверку в `gateway healthcheck` (GR-13): `< 14 дней` →
warning, `< 7` → error + запись в journal; для Xray/CDN — читать `notAfter` из
live-каталога.

**AC.** Симуляция «сертификат истекает завтра» даёт warning в healthcheck;
порог настраивается (env).

**Оценка.** 1–2 ч (в составе GR-13). **Файлы.** `src/gateway/health*.py`,
`systemd/`.

## 4. AmneziaWG

### GR-13. Нет ротации обфускации и purge — **P2**

**Факт.** Параметры `Jc/Jmin/Jmax/S1/S2/H1..H4` пишутся в state при install и
больше не меняются; `remove` оставляет пакеты PPA (сознательно), но нет способа
дочистить.

**Действие.** `amneziawg rotate-obfuscation [--apply]` — новые параметры (с
валидацией H1..H4 уникальны и вне диапазона 1..1023), рестарт, перевыпуск `.conf`
всем клиентам, список на ре-импорт. `amneziawg purge --apply` — удаление
`ppa:amnezia/ppa`, модуля DKMS, конфигов.

**AC.** Новые `.conf` подключаются (e2e на asv1); старые — нет; purge оставляет
систему без awg-следов (`dpkg -l | grep amnezia` пуст).

**Оценка.** 1 день. **Файлы.** `src/amneziawg/install.py|clients.py|remove.py`.

### GR-14. Нет QR/экспорта и IPv6-профиля — **P2**

**Факт.** `gateway links` отдаёт для AWG плейсхолдер с путём к `.conf`; QR мы
делали руками (`qrencode`). IPv6 в подсети/peers не поддержан.

**Действие.** Входит в GR-15 (`export --format qr|conf`); отдельно — опциональный
IPv6-адрес в `.conf` (`Address = 10.9.0.2/24, fd00:9::2/64`), флаг `--ipv6`.

**AC.** `vds gateway export laptop --format qr` печатает/сохраняет PNG, сканируется
AmneziaVPN; IPv6-профиль проходит handshake (если провайдер даёт v6).

**Оценка.** 4–6 ч. **Файлы.** `src/amneziawg/clients.py`, `src/gateway/*`.

## 5. Оркестрация и клиентская поставка

### GR-15. `vds gateway export --format qr|conf|sub|clash|singbox` — **P1**

**Факт.** QR генерится вручную вне продукта; `.conf` AWG не отдаётся содержимым;
подписок нет.

**Действие.** Один exporter: `qr` (PNG/SVG, `qrencode` как зависимость с
fallback-сообщением), `conf` (AWG), `uri` (по одной ссылке), `sub` (base64-список
URI — стандарт подписок), `clash`/`singbox` (YAML/JSON по профилям). Вывод в
stdout или `--out PATH` (0600). Секреты — только в файле/stdout, не в логах.

**AC.** `export mob --format qr --out /tmp/x.png` даёт сканируемый QR (проверка
`zbarimg`); `export --format sub` импортируется в v2rayNG/Hiddify как подписка;
AWG `--format conf` совпадает байт-в-байт с файлом на сервере.

**Оценка.** 1–1.5 дня. **Файлы.** `src/gateway/export.py` (новый),
`src/main.py`, `tests/gateway/`.

### GR-16. Нет `gateway init` (hub) — **P2**

**Факт.** Протоколы ставятся по одному; порядок, порты и пересечения держатся в
доке. Roadmap-фаза 5.

**Действие.** `vds gateway init [--profile minimal|full]`: Reality + Hysteria2
(+obfs/hop) + AWG (+XHTTP/CDN при домене) с проверкой занятости портов и итоговой
таблицей «что поднято, где ссылки». Dry-run по умолчанию? — нет: это установка,
поэтому `--apply` обязателен, как у `remove`.

**AC.** На чистой Ubuntu-ВМ 24.04 одна команда даёт рабочий набор из ≥3
транспортов; повторный запуск идемпотентен; провал шага не оставляет
полу-состояния (rollback/отчёт).

**Оценка.** 2–3 дня. **Файлы.** `src/gateway/init.py`, `src/main.py`.

### GR-17. Подписки по HTTP(S) — **P2**

**Факт.** `vpn profile pull` умеет только ssh+stdout. Мобильным клиентам нужен URL.

**Действие.** `vds gateway sub serve --port 8081 --token ... [--apply]` (systemd
unit): отдаёт base64/Clash/sing-box по токену, логи без ссылок, rate-limit; TLS —
через существующий LE-сертификат или за Cloudflare. `vpn profile pull --url`.

**AC.** v2rayNG импортирует подписку по URL; без токена — 401; в journal нет
токенов/ссылок.

**Оценка.** 2 дня. **Файлы.** новый `src/subscriptions/`, `systemd/`,
`vpnm/pull.py`.

## 6. Наблюдаемость и отказоустойчивость

### GR-18. `gateway healthcheck` + таймер — **P0**

**Факт.** Таймеры (`vds-watchdog`, `vds-reconcile`) есть только у ZeroTier.
Падение `vds-xray`/`vds-hysteria2(-obfs)`/`vds-amneziawg` замечается только
вручную; сертификаты не контролируются.

**Действие.** `vds gateway healthcheck [--apply]` + `systemd/vds-gateway-health.*`:
юнит active, порт слушается (`ss`), конфиг валиден (`xray -test`,
`hysteria --check`), сертификат `days_left`, локальная проба (TLS-хендшейк Reality,
UDP-проба hy2). Рестарт с rate-limit (переиспользовать логику
`zerotier/watchdog.py`: TERM → 5с → KILL, белый список). Exit-код для мониторинга.

**AC.** `systemctl stop vds-hysteria2` → healthcheck восстанавливает за ≤2 цикла;
лимит рестартов не даёт «шторм»; при истёкшем сертификате — warning, без рестарта.

**Оценка.** 1 день. **Файлы.** `src/gateway/health.py` (новый), `systemd/`,
`tests/gateway/`.

### GR-19. Нет учёта трафика по клиенту — **P2**

**Факт.** `sysinfo` показывает CPU/RAM/диск/Docker; трафика и числа активных
сессий нет. У Xray есть `xray api stats` (нужен stats-блок в конфиге), у
Hysteria2 — `/metrics`.

**Действие.** Включить stats-API на loopback, `vds gateway stats [--json]` и блок в
`sysinfo`: трафик по клиенту (uuid→имя из state), аптайм, активные соединения,
ошибки из journal за 15 мин.

**AC.** `stats` сопоставляет uuid с именем клиента; счётчики растут при трафике;
`--json` пригоден для внешнего мониторинга.

**Оценка.** 1–1.5 дня. **Файлы.** `src/xray/config.py|status.py`,
`src/sysinfo/`, `src/gateway/`.

### GR-20. Нет алертов и бэкапа состояния — **P2**

**Факт.** `state.json` — единственный источник клиентов и секретов; бэкапа нет.
Алертов (Telegram/webhook) нет.

**Действие.** 1) `vds gateway backup [--out DIR]` — tar `state.json` + конфиги
(0600) + манифест версий; `vds gateway restore --from FILE [--apply]` с проверкой
версии state. 2) Hook для healthcheck: webhook/Telegram при error (токен в env).

**AC.** Restore на чистом сервере восстанавливает ссылки 1:1 (сравнение
`gateway links` до/после); бэкап не содержит лишних секретов в открытом виде за
пределами архива (архив 0600).

**Оценка.** 6–8 ч. **Файлы.** `src/gateway/backup.py`, `src/gateway/health.py`.

## 7. Клиентская сторона (`vpnm`)

### GR-21. Ручное переключение схем вместо failover — **P1**

**Факт.** `vpn scheme proxy|cdn|private|awg` — ручной выбор; `probe.py` умеет
мерить доступность/задержку, но не влияет на выбор.

**Действие.** `vpn scheme auto --order proxy,cdn,awg`: probe всех профилей →
поднять первый живой → периодически перепроверять (таймер) → переключение при N
последовательных провалах, с гистерезисом (не дёргаться). Отдельно — «sticky»
профиль (не переключаться, только алерт).

**AC.** При блокировке Reality (эмуляция `iptables -j DROP` на 443) vpnm
переключается на CDN-профиль за ≤2 цикла; логи без секретов; ручной выбор
приоритетнее auto.

**Оценка.** 1–1.5 дня. **Файлы.** `vpnm/channels.py|probe.py|cli.py`,
`systemd/`-шаблоны vpnm.

### GR-22. Флаги pull только в CLI — **P2**

**Факт.** `--include-obfs` (и `--protocol` на сервере) доступны только в
командной строке; TUI-меню vpnm их не пробрасывает.

**Действие.** Добавить в `vpn pull`/TUI пункт «включая obfs» + отображение
профилей `<name>@obfs` в списке; при импорте — предупреждение, если клиент не
умеет obfs (по выбранной схеме).

**AC.** TUI импортирует пару `mob`/`mob@obfs`; в `vpn list` видно, какой профиль
obfs.

**Оценка.** 3–4 ч. **Файлы.** `vpnm/tui.py`, `vpnm/cli.py`.

### GR-23. blockcheck зависит от внешнего API — **P2**

**Факт.** `vds gateway blockcheck` использует check-host.net; при offline/лимите —
вердикт `unknown` (осознанно не ошибка).

**Действие.** Кэш результатов (15 мин), локальные контрольные хосты (2–3
независимых), экспоненциальный бэкофф; флаг `--no-external` — только локальная
проба.

**AC.** При недоступном API вердикт по локальным пробам; повторный вызов в течение
кэша не ходит в сеть.

**Оценка.** 4 ч. **Файлы.** `src/gateway/blockcheck.py`.

## 8. Инженерная гигиена (тесты/CI)

### GR-24. Нет CI и Docker-e2e для hop/obfs — **P1**

**Факт.** 499 unit-тестов vds и 325 vpnm гоняются локально; hop/obfs/ACME-hook
проверяются на живом asv1 вручную. `tests/e2e/` отсутствует. (Сегодняшний баг
`obfs.salamander.password` ловился только живым прогоном — ровно этот класс.)

**Действие.** 1) GitHub Actions: `pytest` (3.10/3.12) + `ruff` + `compileall`.
2) `tests/e2e/` на docker-compose: сервер (hysteria2 с obfs/без, xray reality) +
клиент sing-box, проверка туннеля через loopback; отдельный кейс «конфиг проходит
`hysteria server --check`» — дешёвый и ловит schema-регрессы без сервера.

**AC.** CI краснеет на регрессе схемы конфига (как сегодняшний bug); e2e-кейсы
hop/obfs зелёные в CI без root.

**Оценка.** 1 день. **Файлы.** `.github/workflows/`, `tests/e2e/`,
`requirements-dev.txt`.

## 9. Порядок взятия (предложение)

| Волна | Пункты | Почему |
|---|---|---|
| 1 | GR-01, GR-18, GR-12 | Дешёвые страховки от тихих сбоев (сертификаты, юниты) |
| 2 | GR-02 (ADR), GR-04 | Закрывают архитектурный потолок Hysteria2 |
| 3 | GR-15, GR-17, GR-22 | Поставка клиентам: QR/подписки без ручной работы |
| 4 | GR-03, GR-06, GR-08 | Эксплуатация: hop, обновление Xray, пул фронтов |
| 5 | GR-10, GR-11, GR-19 | Сертификаты/учёт/наблюдаемость |
| 6 | GR-21, GR-24, GR-13/14, GR-16, GR-20, GR-23 | Отказоустойчивость клиента, CI, AWG, hub, бэкап |

**Зависимости:** GR-02 → GR-04 (ротация на userpass); GR-01 ← GR-10 (хуку нужен
явный список потребителей и доменов); GR-17 ← GR-15 (общий exporter);
GR-21 ← GR-03/GR-08 (нужны живые профили для failover).

## 10. Сознательно не делаем (пока)

- Веб-панель/GUI — вне модели угроз и целей проекта (см. CENSORSHIP-ROADMAP §1.3).
- UDP-over-TCP (маска TCP для hy2) — отложен в REQ-20261112 (transport-hardening).
- Замена `pydantic`-моделей state на БД — файла 0600 достаточно.
- Своя реализация ACME (уходим от certbot) — не даёт выигрыша.

## 11. Источники факта

| Проверка | Наблюдение |
|---|---|
| `state.json` на asv1 | obfs active (udp/51826), hop `None`, CDN `fronts: None`, `acme.domain=asvpersonal.ru` |
| `/etc/hysteria/cert.pem` | LE, SAN `103-45-247-172.eu-cloud-xip.com` (≠ `acme.domain`) |
| hook `vds-hysteria2-cert.sh` | `systemctl restart vds-hysteria2` — только main |
| `xray version` | 25.1.1 |
| `src/hysteria2/clients.py` | один auth-пароль на инбаунд |
| `src/hysteria2/config.py` | обфускатор только `salamander` |
| `docs/CENSORSHIP-ROADMAP.md` | фазы 5–8 (подписки, hardening, наблюдаемость, e2e) не закрыты |
| `tests/` | hop/obfs — только unit, e2e нет |
