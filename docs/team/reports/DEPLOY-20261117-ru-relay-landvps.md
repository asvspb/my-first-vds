# DEPLOY-20261117-ru-relay-landvps — RU-relay развёрнут (ADR-007 v1)

> **Тип:** DEPLOY-отчёт (полевая раскатка + приёмка).
> **Дата:** 2026-11-17. **Провайдер:** LandVPS, VM `vm354051`, `185.80.91.135`
> (AS216334, Москва), IPv6 `2a12:b3c0:1:198::/48`.
> **ОС:** Ubuntu 22.04.5 LTS (отклонение от ADR — см. §5.1), 1 vCPU,
> 823 МБ RAM + 1 ГБ swap, 20 ГБ SSD.
> **Exit-нога:** asv2 `213.108.23.119:51825` (asv1 удалён 2026-11-16).
> **Код:** `my-first-vds` (ветка main, коммит с HF-REL-1..3), клиент не менялся.
> **Секреты:** в отчёте нет ключей/паролей — только публичные ключи-заглушки,
> IP и счётчики.

## 1. Что развёрнуто

```
vds-relay-awg.service     active   AWG-сервер udp/443, awg0 10.10.0.0/24, MTU 1280
vds-relay-exit.service    active   awg1 → asv2:51825 (handshake живой)
vds-relay-nat.service     active   MASQUERADE 10.10.0.0/24 → awg1 и → ens3
vds-relay-policy.service  active   nft vds_relay + ip rule fwmark 0x1 → table 100
vds-relay-cidr.timer      active   RU-CIDR 8664 агрегата (ipdeny ru.zone)
vds-xray.service          active   Reality tcp/443, SNI=ya.ru (фолбэк-нога)
```

UFW (профиль relay через `vds system ufw harden --profile relay --apply`):
`deny incoming` / `allow outgoing` / `limit 22/tcp` / `allow 443/udp` /
`allow 443/tcp`, `DEFAULT_FORWARD_POLICY=ACCEPT`.

## 2. Приёмка (живые проверки)

| Проверка | Результат |
|---|---|
| `curl --interface awg1 https://api.ipify.org` на релее | `213.108.23.119` (asv2) ✅ |
| `curl --interface ens3 https://api.ipify.org` | `185.80.91.135` (релей) ✅ |
| handshake awg1 → asv2 | живой, transfer идёт ✅ |
| Reality с ноутбука (`relay-reality` профиль) | egress `185.80.91.135` (прямая нога) ✅ |
| AWG-клиент → релей → asv2 (тест с asv2 как клиента) | egress `213.108.23.119` ✅ |
| RU-сайт через AWG-клиента (`ya.ru`) | 302, 0.13 с — RU-CIDR идёт напрямую ✅ |
| Foreign через AWG-клиента (`github.com`) | 200, 2.6 с (двойной хоп) ✅ |
| `systemctl --failed` | 0 ✅ |
| ufw после включения | SSH 22 доступен, правила на месте ✅ |

Маскировка Reality: `SNI=ya.ru` + в **той же /24** (`185.80.91.119`) реально
живёт Yandex-фронт (GlobalSign `*.yandex.by`, HTTP/2, captcha-страница) —
плаузибилити «сосед по стойке» сильная. Альтернативы из /24:
`185.80.91.87` (www.vk), `185.80.91.201` (*.x5.ru).

## 3. Найденные и исправленные дефекты (HF-REL-1..3)

### HF-REL-1 — `iptables` отсутствует на минимальном cloud-образе

`vds-relay-nat.service` падал с `status=127 / "iptables: not found"`:
на Ubuntu 22.04 cloud image нет `iptables`, хотя nftables/ufw ставятся
отдельно. `relay init --apply` останавливался на шаге NAT, оставляя
релей без policy-routing (трафик клиентов уходил бы напрямую).

Фикс: `_ensure_iptables()` в `src/relay/init.py` — проверка бинарника и
`apt-get install -y iptables` до старта NAT-юнита (идемпотентно).

### HF-REL-2 — повторный `relay init` блокировался своими же портами

После частичного сбоя повторный `--apply` отменялся: «порт(ы) 443 заняты»,
хотя держал их наш `vds-xray`/`vds-relay-awg`. Фикс: `_check_ports()` считает
443 занятым «своим» юнитом допустимым (`_own_unit_active()`), чужой владелец
по-прежнему блокирует.

### HF-REL-3 — потеря `public_key` при идемпотентном повторе

`_install_awg_server()` в идемпотентной ветке возвращал `state.protocols['relay']`,
которого после частичного сбоя ещё нет → `vds relay add-client` падал с
«нет public_key». Фикс: `_awg_meta_from_config()` восстанавливает public_key
(через `awg pubkey`, приватный ключ только в tmp-файле 0600), порт, MTU,
подсеть и все 9 параметров обфускации из `/etc/amnezia/awg0.conf`.

### HF-REL-4 — политика молча деградировала в прямой выход

Маршрут `default dev awg1 table 100` привязан к интерфейсу: любой
`restart vds-relay-exit` (или переподключение ноги) удаляет его ядром, а
oneshot-юнит `vds-relay-policy` с `RemainAfterExit=yes` не перезапускается.
Живой симптом: клиент через релей получал egress `185.80.91.135` (RU-IP
релея) вместо `213.108.23.119` — то есть деanon/деградация политики без
единой ошибки в логах. Фикс: `PartOf=vds-relay-exit.service` в
`systemd/vds-relay-policy.service.tpl` — политика перезапускается вместе с
ногой и возвращает маршрут/правило/set.

Тесты: `tests/relay/test_init.py` (+7): автоустановка iptables, идемпотентные
порты, восстановление метаданных, инвариант `PartOf` в шаблоне юнита.
Полный прогон `vds`: см. §6.

## 4. Клиенты

- `vds relay add-client laptop` → `/opt/my-vds/gateway/clients/relay/laptop.conf`
  (0600, endpoint `354051.landvps.online:443`, MTU 1280).
- На ноутбуке: `~/.awg/relay.conf` (0600) — для AWG-туннеля через релей
  (`vpn-awg-split@relay`, требует root).
- Reality-фолбэк: `vds xray add-client relay-laptop` → профиль
  `relay-reality` в vpn-manager (socks 2080, переключение `vpn switch`).
- Тестовые пиры (`relay-smoke`, `smoke-asv2`) удалены; в конфиге awg0
  остался только `laptop`.

## 5. Отклонения и открытые пункты

### 5.1 ОС 22.04 вместо 24.04

Gate и раскатка прошли, код проекта поддерживает 3.10+/systemd 249. Риски:
systemd/ssh-поведение отличается от 24.04 (ssh.socket-активации нет — SSH
остаётся на `ssh.service`), дрейф пакетов. Решение владельца: оставить
22.04 или переустановить шаблон на 24.04 (сеть/DC уже проверены; после
переустановки — повторный `vds relay init --apply`).

### 5.2 Домен релея — временный

`relay.asvpersonal.ru` живёт на Cloudflare (NS `peaches/rohin.ns.cloudflare.com`),
API-токена на машинах проекта нет. Пока используется
`354051.landvps.online` (A → 185.80.91.135). **Действие владельца:** создать
`A relay.asvpersonal.ru → 185.80.91.135`, **DNS-only (серое облако)**, затем
`sudo vds relay init --exit 213.108.23.119 --domain relay.asvpersonal.ru
--sni ya.ru --exit-conf /root/relay-awg1.conf --apply` и перевыпустить
клиентские конфиги (init идемпотентен, домен только в state/ссылках).

### 5.3 Пароли панели/root были в переписке

Рекомендация: сменить root-пароль и пароль панели LandVPS; вход по SSH — по
ключу (`~/.ssh/id_rsa` уже в `authorized_keys`, алиас `Host relay`).

### 5.4 Нет `vds relay remove-client`

Пир удаляется только правкой `/etc/amnezia/awg0.conf` + restart юнита
(так удалён `smoke-asv2`). Заведено в TECHDEBT P20.

### 5.5 IPv6

На интерфейсе фактически `/48` (`2a12:b3c0:1:198::/48`) при заявленном /64 —
для будущей v6-ноги достаточно; v1 работает по IPv4.

## 6. Трассируемость

| Что | Ссылка |
|---|---|
| Gate-приёмка Фазы 0 | [TEST-20261117-ru-relay-gate](TEST-20261117-ru-relay-gate.md) |
| Ранбук (обновлён по факту) | [DEPLOY-RU-RELAY](../../DEPLOY-RU-RELAY.md) |
| ADR | [ADR-007](../../adr/ADR-007-ru-relay.md) |
| UFW-профиль relay | [SERVER-BASELINE §5.11](../../SERVER-BASELINE.md) |
| Долги | `TECHDEBT.md` P20 |

Тесты: `tests/relay` — 65 passed; `pytest -q` целиком — 1060+ passed;
`python3 tools/docsync.py audit --strict` — 0.
