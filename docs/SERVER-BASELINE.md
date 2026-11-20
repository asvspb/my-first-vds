# SERVER-BASELINE — настройки ОС и сервера: что автоматизировано, что восстанавливать руками

> **Назначение:** единый документ для восстановления сервера после переустановки
> Ubuntu / переезда на новый VDS. Здесь перечислено **всё**, что не приходит
> само из `install.sh`/`gateway init`: настройки ОС, безопасность, сеть,
> провайдерские и DNS-вещи, данные и клиентская сторона. Всё, что можно
> описать командой, описано командой; агент/оператор может выполнить это
> позже вручную по чеклисту §7.
>
> **Снимок:** `asv1`, 2026-11-14. Значения могут дрейфовать — перед
> восстановлением сверяйте фактическое состояние, а не только таблицу.
>
> **⚠️ asv1 удалён 2026-11-16.** Документ сохраняется как исторический
> снимок профиля asv1 (2026-11-14); актуальный боевой узел — **asv2**
> (`213.108.23.119:49222`, dual-stack, UFW gateway, LE `asv2.asvpersonal.ru`).
> Для нового узла используйте §7 (чеклист) и `vds gateway init`.
> Связанные документы: [DEPLOY](DEPLOY.md) (установка),
> [MIGRATE-VDS](MIGRATE-VDS.md) (перенос данных),
> [SPEC fresh-install-v3](team/specs/SPEC-20261114-fresh-install-v3.md)
> (`gateway init`), [VPN-PROTOCOLS](VPN-PROTOCOLS.md) (порты/протоколы).

## 1. Профиль asv1 (исторический снимок 2026-11-14; узел удалён 2026-11-16)

| Параметр | Значение |
|---|---|
| Хостнейм | `asv1` |
| ОС | Ubuntu 24.04 LTS |
| IP / ASN / гео | `103.45.247.172` · AS41436 Kamatera · Амстердам (NL) |
| Домен | `103-45-247-172.eu-cloud-xip.com` (A → сервер, LE-сертификат) |
| CDN-домен | `asvpersonal.ru` (Cloudflare proxied, origin 2053) |
| Timezone | `Etc/UTC` |
| Swap | **нет** (0) |
| UFW | **inactive** |
| Docker | **не установлен** |
| fail2ban | не активен |
| NTP | `systemd-timesyncd`, синхронизация включена |
| DNS-резолвер | `8.8.8.8`, `8.8.4.4` (systemd-resolved) |
| `ip_forward` | `1` |
| `net.core.rmem_max` / `wmem_max` | `16777216` / `16777216` |
| TCP congestion / qdisc | `bbr` / `fq` |
| `net.core.somaxconn` | `4096` |
| `ulimit -n` | `1024` |
| SSH | порт 22, `PermitRootLogin prohibit-password`, **`PasswordAuthentication yes`** |
| Юниты gateway | xray, hysteria2, hysteria2-obfs, hysteria2-hop, amneziawg, health.timer — active |

## 1.1 Профиль asv2 (факт на 2026-11-16; основной AWG-exit)

| Параметр | Значение |
|---|---|
| IP / гео | `213.108.23.119` · зарубеж (ptr.network) |
| IPv6 | **да**: `2a0b:4140:9a2e::/48` (адрес `::2`, egress проверен) — первый dual-stack exit |
| Домен | `asv2.asvpersonal.ru` A + AAAA, **DNS-only** (CF-прокси нельзя), LE (89 дн.) |
| RAM | 2 ГБ |
| UFW | **active** (harden --profile gateway, 2026-11-16): deny in / allow out / allow routed |
| Порты | `49222/tcp LIMIT` (ssh, двухфазный перенос завершён), `443/tcp+udp`, `80/tcp` (ACME), `51825/udp`; после P24 — `51900/udp` **только с IP релея** (нога на `awg2`, пул 51900–51911 через nft REDIRECT; MASQUERADE `10.11.0.0/30` на WAN в той же nft-таблице, нужен `ip_forward=1`) |
| SSH | **только 49222** (limit), ключи; `PasswordAuthentication` — как в образе |
| Юниты | vds-xray, vds-hysteria2 (secure LE), vds-amneziawg + vds-amneziawg-nat, vds-probe-watch.timer (+ vds-gateway-health.timer, vds-probe-rucidr.timer — при установке); после P24 — `vds-awg-relay` (awg2) и `vds-awg-relay-pool` (nft REDIRECT); на релее opt-in — `vds-relay-maneuver.timer` + `vds-relay-maneuver.service` (`vds relay maneuver install`, WP-M4; `.service` enable=off, `StateDirectory=vds`, sandbox: `/etc/amnezia` в ReadWritePaths, `CAP_NET_ADMIN CAP_NET_RAW`, `AF_NETLINK`) |
| Роль | основной AWG-exit ноутбука (`vpn start`), AWG-подсеть 10.9.0.0/24 |

> asv1 удалён 2026-11-16; asv2 — единственный боевой exit (UFW gateway,
> ssh 49222). Исторический профиль asv1 — только для восстановления контекста.

## 2. Матрица «авто / вручную»

| Настройка | asv1 | Автоматически? | Где/как |
|---|---|---|---|
| apt update/upgrade, базовые пакеты | да | ⚠️ `preinstall.sh` / `vds server-setup` (в деплое **не** вызываются) | `bash preinstall.sh` |
| Python/venv, `vds` CLI | да | ✅ `install.sh` | — |
| Timezone UTC | да | ✅ `preinstall.sh`, `server-setup` | `timedatectl set-timezone UTC` |
| Пользователь + SSH-ключи | `vpn-accept` | ⚠️ интерактивно `vds server-setup` | см. §4 |
| SSH без паролей | **нет** (пароли разрешены) | ⚠️ `server-setup` (на asv1 не применено) | см. §4 |
| Swap 2G | нет | ⚠️ `server-setup` (в контейнерах недоступен) | см. §3 |
| unattended-upgrades | ? | ⚠️ `server-setup` | `dpkg -l unattended-upgrades` |
| UFW | **выключен** | ⚠️ `vds system ufw harden` (SPEC-20261116) | §5 |
| Docker | нет | ⚠️ `server-setup` (не нужен без ZTNET) | `vds zerotier install` |
| BBR + UDP-буферы | да | ✅ `hysteria2 install` (sysctl.d) | `vds hysteria2 install` |
| `ip_forward` + MASQUERADE | да | ✅ `amneziawg install` | `vds amneziawg install` |
| hop-цепочка + UFW-диапазон | да | ✅ `hysteria2 add-hop-ports --apply` (UFW: `20000-20500` → `20000:20500`) | — |
| obfs-инстанс | да | ✅ `hysteria2 add-obfs` | — |
| XHTTP / CDN | да | ✅ `xray add-transport` / `add-cdn` | — |
| certbot + таймер | да | ✅ `acme issue` | — |
| healthcheck-таймер | да | ✅ `gateway healthcheck --install-timer` | — |
| сторож угрозы (уведомления) | нет | ✅ `alert install --apply` (exit-узел; на релее запрещён) | §5.15 |
| fail2ban, NTP, journald, logrotate, limits | NTP да, остальное default | ❌ не автоматизировано | §3 |
| Провайдерский файрвол/anti-DDoS | неизвестно | ❌ только панель хостера | §6 |
| Cloudflare DNS/records | apex + CDN | ❌ только панель/API CF | §6 |
| state.json, клиенты, ключи, сертификаты | да | ❌ только миграция/бэкап | §8 |
| Клиентские настройки (vpnm, AWG Endpoint) | да | ❌ вручную/`profile pull` | §9 |

## 3. ОС: база, ядро, журналы

| Что | Команда восстановления | Проверка |
|---|---|---|
| Timezone | `timedatectl set-timezone UTC` | `timedatectl show -p Timezone --value` |
| NTP | `timedatectl set-ntp true` | `timedatectl show -p NTP --value` |
| Swap 2G | `fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab` | `swapon --show` |
| unattended-upgrades | `apt install -y unattended-upgrades && dpkg-reconfigure -f noninteractive unattended-upgrades` | `systemctl is-active unattended-upgrades` |
| journald (ограничить) | `mkdir -p /etc/systemd/journald.conf.d && printf '[Journal]\nSystemMaxUse=500M\n' > /etc/systemd/journald.conf.d/99-vds.conf && systemctl restart systemd-journald` | `journalctl --disk-usage` |
| logrotate (дефолт) | ничего (пакетный) | `logrotate --debug /etc/logrotate.conf` |
| fd-лимиты (PAM-сессии) | `printf "* soft nofile 65535\n* hard nofile 65535\n" > /etc/security/limits.d/99-vds.conf` | новый логин: `ulimit -n`. ⚠️ systemd-демоны **игнорируют** limits.d — их лимит задаётся `LimitNOFILE=` в юните; юниты проекта (vds-xray/vds-hysteria2 tpl) уже содержат LimitNOFILE |
| kernel/sysctl gateway | `vds hysteria2 install` (BBR, fq, rmem/wmem) | `sysctl net.ipv4.tcp_congestion_control net.core.rmem_max` |
| ip_forward + NAT (AWG) | `vds amneziawg install` | `sysctl net.ipv4.ip_forward`; `iptables -t nat -S POSTROUTING` |
| hop nat-цепочка | `vds hysteria2 add-hop-ports <range> --apply` | `iptables -t nat -S VDS_HY2_HOP` |

## 4. Пользователи и SSH

| Что | asv1 | Команда/файл |
|---|---|---|
| root | только по ключу (`prohibit-password`) | `/etc/ssh/sshd_config` |
| Отдельный юзер | `vpn-accept` (для деплоя/приёмки) | `useradd -m -s /bin/bash vpn-accept` |
| Ключи юзера | `/home/vpn-accept/.ssh/authorized_keys` (0600) | `install -d -m700 -o vpn-accept -g vpn-accept /home/vpn-accept/.ssh` + `cp` |
| Пароли SSH | **разрешены** (факт asv1) | для закрытия: `printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/99-vds.conf && systemctl restart ssh` |
| sudo без пароля (опционально) | ? | `/etc/sudoers.d/<user>` (440) |

> ⚠️ `vds server-setup` пишет `PasswordAuthentication no`, но на asv1 сейчас
> `yes` — при переустановке решайте осознанно (доступ по ключу должен быть
> проверен **до** отключения паролей).

**Правило имён `sshd_config.d` (first-match-wins):** побеждает ПЕРВАЯ
прочитанная директива; cloud-образы несут `50-cloud-init.conf` /
`60-cloudimg-settings.conf` с `PasswordAuthentication yes`. Override-файлы
проекта именовать с префиксом **`00-`** (`00-vds-ssh.conf`), чтобы читаться
раньше cloud-init. Исключение — **`Port`**: директива аддитивная (несколько
Port = слушаются все), поэтому `99-vds-port.conf` из §5.4 корректен при любом
порядке. Факт asv2: cloud-init-файла в `sshd_config.d` нет, но правило
обязательно для новых образов/релея.

**Откат переноса ssh-порта (файлы проекта, SPEC-20261116):** за файлы отвечает
двухфазная команда §5.4; вручную:
```bash
install -m600 /dev/null /tmp/port.conf.new && printf 'Port 22\nPort 49222\n' > /tmp/port.conf.new
cp /tmp/port.conf.new /etc/ssh/sshd_config.d/99-vds-port.conf        # вернуться к dual-listen
mkdir -p /etc/systemd/system/ssh.socket.d && printf '[Socket]\nListenStream=\nListenStream=22\nListenStream=49222\n' \
  > /etc/systemd/system/ssh.socket.d/99-port.conf                    # либо удалить drop-in = чистый 22
sshd -t && systemctl daemon-reload && systemctl restart ssh.socket   # вне socket-activation: restart ssh
ufw limit 22/tcp   # правило 22 вернуть, если было снято finalize'ом
```
Бэкапы прежних конфигов — `<STATE_PATH>/ufw-ssh-backups/` (создаёт Фаза A).

## 5. UFW hardening — `vds system ufw harden` (SPEC-20261116)

Устаревший путь `server-setup` (`ufw --force reset` + список `ssh,80,443,51820,9993`)
**не использовать**: он сбрасывает правила relay init / amneziawg / hop. Текущий
путь — идемпотентная команда harden (dry-run по умолчанию, `--apply` для применения,
`--undo --apply` для отката). Существующие правила (relay init `allow 443/udp`,
amneziawg `allow 51825/udp`, hop `20000:20500/udp`, CDN `2053/tcp`) детектируются
и не дублируются; `ufw reset` в новом коде запрещён.

### 5.1 Команды

```bash
sudo vds system ufw harden --profile gateway                          # dry-run: план
sudo vds system ufw harden --profile gateway --apply                  # asv2 (exit-сервер)
sudo vds system ufw harden --profile relay --apply                    # RU-релей
sudo vds system ufw harden --profile exit-cascade --allow-from <RELAY_IP> --apply
sudo vds system ufw harden --profile gateway --undo --apply           # откат по журналу
sudo vds system ufw status                                            # сводка + pending
```

Fail-safe порядок (SPEC §1.10): defaults → `ufw limit <ssh>/tcp` **первым** из
allow-набора → сервисные порты по `state.protocols` → DEFAULT_FORWARD_POLICY
(для всех профилей; при уже-active ufw — `ufw reload`) → `ufw --force enable`
**строго последним** и только при подтверждённом ssh-правиле. Ранбук: держать
открытой вторую ssh-сессию до завершения приёмки.

### 5.2 Матрица портов по профилям

Правила выводятся из `state.protocols` (открывается только установленное).
**Факт asv2 (harden применён 2026-11-16, приёмка PASS):** `49222/tcp LIMIT`,
`443/tcp+udp`, `80/tcp`, `51825/udp` (+v6-дубли).
**Целевой профиль asv1 (harden ещё НЕ применён — сейчас UFW inactive, ssh 22,
полевка после TSPU-окна):** `22→limit→49222`, `443/tcp` Reality, `443/udp`
Hy2, `8443/tcp` XHTTP(LE), `51825/udp` AWG (пиры живы); `2053/tcp` CDN —
🧊 холодный резерв (DECISION Q6), не открывается,
`20000-20500/udp` hop (в бою с 2026-11-13).

Примечание к `exit-cascade`: порты `51825/udp`, `8443/tcp`, `2053/tcp`, `80`
остаются открытыми всем — в v1 прямые клиенты (ноут/телефон) продолжают
ходить мимо релея, каскад ограничивает только 443. Если прямые клиенты
исключаются из схемы — сузить и эти порты (`--allow-from`).

| Порт | Назначение | gateway | relay | exit-cascade |
|---|---|---|---|---|
| `<ssh>/tcp` (limit) | SSH (22; 49222 после finalize; при pending — оба) | ✔ | ✔ | ✔ |
| 443/tcp | Reality / Xray | ✔ | ✔ (добавит, если нет) | только `allow from <RELAY_IP>` |
| 443/udp | Hysteria2 / AWG-релей | ✔ | ✔ (relay init уже открыл) | только `allow from <RELAY_IP>` |
| 51825/udp | AmneziaWG | ✔ (install уже открыл) | — | ✔ |
| 51826/udp | obfs salamander | ✔ | — | ✔ |
| 8443/tcp | XHTTP | ✔ | — | ✔ |
| 2053/tcp | CDN origin (CF) — 🧊 холодный резерв (Q6) | не открывается, origin не развёрнут | — | — |
| 80/tcp | ACME HTTP-01 | ✔ | — | ✔ |
| 20000:20500/udp | hop (если включён) | ✔ | — | ✔ |
| FORWARD / ip_forward | маршрутизация | ACCEPT + проверка | ACCEPT + проверка | ACCEPT + проверка |

Панели/метрики наружу НЕ открываются нигде (ZTNET 9993, dashboard — только ssh-туннель).
Docker обходит UFW (nat PREROUTING/DOCKER раньше ufw-before-input) — слушающие
порты вне плана печатаются как `[warning]` (включая docker-proxy; см. §5.7).

Проверка приёмки: `ufw status verbose` → deny incoming / allow outgoing;
`grep DEFAULT_FORWARD_POLICY /etc/default/ufw` → ACCEPT; `sysctl net.ipv4.ip_forward`
→ 1; `ping <ip>` отвечает (ICMP не трогаем); набор открытых портов = матрице.
Раздельный NAT: **стандарт проекта — systemd-юнит `vds-amneziawg-nat`**
(oneshot `-C||-A`, не зависит от ufw; asv1 improved 2026-11-13, asv2 —
install). `amneziawg install` дополнительно пишет MASQUERADE в
`/etc/ufw/before.rules` — живой дубль (факт asv2: оба присутствуют); при
inactive ufw before.rules не применяется, персистентность обеспечивает юнит.
harden MASQUERADE-секцию не трогает (SPEC §1.8); дедупликация before.rules —
TECHDEBT.

### 5.3 Правило знаний: ICMP и диагностика маршрута (решено 2026-11-16)

ICMP — **НЕ трогаем вовсе** (drop echo-request НЕ реализуем, опция удалена из
спеки). Обоснование: (а) ТСПУ находит серверы пассивным DPI исходящего трафика,
не пингом; (б) echo-request — главный диагностический инструмент (маршрут жив vs
порт режется: ping, ping.pe, check-host.net); (в) Reality-сервер, отдающий
TLS-сертификат на 443, но молча дропающий ICMP, — аномалия для эвристик.
destination-unreachable / time-exceeded / parameter-problem / icmp type 3 code 4
(fragmentation-needed, PMTU) — никогда не блокировать.

### 5.4 Правило двухфазного переноса SSH-порта 22 → 49222

Одна команда **не может** закрыть 22 в той же операции, что перенос (нужен живой
второй терминал владельца):

1. **Фаза A:** `sudo vds system ufw ssh-port --to 49222 --apply` —
   `ufw limit 49222/tcp` → `/etc/ssh/sshd_config.d/99-vds-port.conf`
   (**dual-listen: Port 22 + Port 49222**, вход по 22 гарантированно жив даже при
   режущем 49222 провайдер-файрволе) → `sshd -t` → ssh.socket drop-in (Ubuntu
   24.04: `ListenStream=` сброс + 22 + 49222) или `restart ssh` → ss-чек →
   pending-маркер → команда останавливается. Drop-in systemd пишется **0644**
   (0600 → «world-inaccessible»). При любом сбое Фазы A откат **сам** делает
   `daemon-reload` + `restart ssh.socket`/`ssh` + fallback `start ssh`, а не
   просит руками (пост-мортем asv1: иначе узел терял и 22, и 49222).
2. Владелец проверяет вход на 49222 **со ВТОРОГО терминала** (пока 22 жив, откат
   безопасен; при режущем 49222 облачном файрволе хостера — открыть порт в панели).
3. **Фаза B:** `sudo vds system ufw ssh-port --finalize --apply` — порядок:
   sshd-конфиг → только Port 49222 → restart → ss-чек → `ufw delete` правил 22 →
   pending снят. Если вход на 49222 не работает — НЕ финализировать: 22 остаётся
   открытым; восстановление из бэкапов `<state>/ufw-ssh-backups/` вручную.

### 5.5 Чеклист отката (ручной, стиль DEPLOY-RU-RELAY)

1. Посмотреть, что harden добавил: `sudo vds system ufw status` (meta `applied_rules`).
2. Автооткат: `sudo vds system ufw harden --undo --apply` — снимает ровно
   применённые правила (реверс), восстанавливает широкие 443-правила, удалённые
   каскадом; если ufw был inactive до harden — `ufw disable`.
3. Проверка после отката: `ufw status verbose`; ssh-сессия жива; VPN-клиенты
   работают (`vds gateway status`).
4. Ручной откат (если state потерян), построчно:
   ```bash
   ufw delete limit 22/tcp
   ufw delete allow 443/tcp
   ufw delete allow 443/udp          # НЕ удалять на релее — его открыл relay init
   ufw delete allow 20000:20500/udp  # НЕ удалять, если hop жив
   ufw disable                       # только если ufw был включён harden'ом
   ```
5. НЕ делать `ufw reset` — стирает правила relay init / amneziawg / CDN.

Проверка: `ufw status numbered`; снаружи — из **чистой** точки (не параллельно,
И26): `nc -vz <ip> <port>`, для UDP — реальный клиент.

### 5.6 Правило знаний: изоляция nft-таблиц (probe-watch ↔ UFW)

**Правило:** таблица `inet vds_probe` (probe-watch: `vds-probe-watch.service` +
`vds-probe-watch.timer`, hook priority −140) — независимая от UFW; не смешивать
и не выполнять `nft flush ruleset`.
**Почему:** ufw (iptables-nft) живёт в своих стандартных цепочках INPUT/FORWARD/
OUTPUT; счётчики vds_probe стоят в prerouting **до** ufw-фильтрации — это
наблюдение, не фильтрация; flush ruleset стёр бы обе таблицы.
**Проверка:** после `ufw reload` / enable — `nft list table inet vds_probe`
(цепочки и счётчики на месте, счётчики растут).
**Откат:** `sudo vds gateway probe-watch remove --apply` (юниты + таблица
снимаются целиком), затем reinstall.

### 5.7 Правило знаний: Docker обходит UFW

**Правило:** публикация портов Docker только на loopback (`-p 127.0.0.1:…`);
`-p 0.0.0.0:…` запрещён — nat PREROUTING/DOCKER стоит раньше ufw-before-input,
опубликованный порт открыт **мимо** любого UFW-правила.
**Почему:** правило знаний, не следствие текущего стека — Docker на проекте
только ZTNET (сейчас disabled; П.6 внешнего ревью).
**Проверка:** `ss -tulnp | grep docker-proxy` — слушающие адреса только
`127.0.0.1`/`::1`; harden печатает docker-proxy в `[warning]` (см. §5.2).
**Откат:** контейнер с `-p 127.0.0.1:…` (compose/`docker run` правка + recreate).

### 5.8 Правило знаний: персистентность после ребута

**Правило:** после ребута ничего не «оживает руками» — всё enabled: `ufw`,
`vds-amneziawg-nat` (идемпотентный oneshot, не зависит от ufw),
`vds-probe-watch.timer` (+`vds-probe-rucidr.timer`, `vds-gateway-health.timer`, если ставились), транспортные юниты (vds-xray/vds-hysteria2*/vds-amneziawg); relay-нога — юниты `vds-relay-{awg,exit,nat,policy,cidr}` из `vds relay init`
(релей развёрнут 2026-11-17 на LandVPS; после `restart vds-relay-exit` политика
перезапускается сама через `PartOf=`, иначе маршрут `table 100` теряется).
Исключение из «всё enabled» — **opt-in** `vds-relay-maneuver.timer`
(WP-M4/ADR-015): `vds relay maneuver install` ставит файлы, но не включает
таймер; включение осознанное (`--enable-auto` или `systemctl enable --now`).
sysctl-профиль проекта — `/etc/sysctl.d/99-vds-gateway.conf` (из
`systemd/sysctl/99-vds-gateway.conf.tpl`; BBR/буферы — hysteria2 install;
`net.netfilter.nf_conntrack_acct = 1` (byte-счётчики conntrack для
probe-watch verified-UDP, HF-1 SPEC-20261116-surface-hardening; на живых
серверах применяется переустановкой sysctl-профиля — без него фолбэк на
`[ASSURED]`); ip_forward — `99-vds-awg-forward.conf` от amneziawg install).
**Почему:** правило знаний П.7. NAT-персистентность — юнит
`vds-amneziawg-nat` (стандарт, см. §5.2: before.rules — живой дубль от
install, при inactive ufw не применяется и НЕ обеспечивает персистентность —
та самая грабля asv1 2026-11-13, закрытая юнитом).
**Проверка (reboot-гейт):** `systemctl is-enabled ufw vds-amneziawg-nat vds-probe-watch.timer …`
+ `sysctl --system` без ошибок + `sysctl net.ipv4.ip_forward` = 1.
**Откат:** недостающий юнит — reinstall соответствующего модуля (`vds … install`).

### 5.9 Правило: прогрев свежего IP

Свежевыпущенный IP прогревается (сутки-двое низкоамплитудного трафика) перед
боевой нагрузкой — иначе первая волна трафика на чистом IP триггерит эвристики.
**Боевой факт (asv2, 2026-11-15):** в первые ~30 минут ТСПУ душит именно
TCP-443 TLS-payload (SYN/ACK проходит, данные дропаются) при живом UDP-443 —
Reality «мёртв», Hy2 работает. Не чинить Xray в этом окне — греть Hy2 и ждать.
Детально: [CENSORSHIP-PATTERNS.md](CENSORSHIP-PATTERNS.md).

### 5.11 Правило знаний: детект активных проб РКН — L3/L4-телеметрия, не логи Xray

**Правило:** Внимание цензора оценивается только по почасовым дельтам
`vds gateway probe-watch` (`syn_bare` 40B vs `syn_valid` в set `probers4`
с timeout 1h, `udp_443`), НЕ по логам Reality-демона.
**Почему:** probe-resistance Reality молча уводит чужие plain-TLS пробы в
dest-fallback (валидный google-серт) и не пишет их в лог при default
loglevel — логи демона слепы к пробам. Единственный способ отличить фоновый
шум (масс-сканеры, голый SYN = 40 байт `ip length`) от целевого зондирования
ТСПУ — считать в ядре (nft hook −140) пакеты с валидным ClientHello
(`syn_valid`) от новых RU-IP.
**Проверка:** `vds gateway probe-watch` (дельты за час);
`systemctl status vds-probe-watch.timer` → `active (waiting)`.
W1-1 (SPEC-20261116-probe-coverage): `probers4` и аддитивные
`syn_valid_extra`/`syn_bare_extra` покрывают и 8443 (XHTTP) / 2053 (CDN
origin) — сканер этих портов виден в new_ru_ips; `RU-PROBE-SUSPECT`
гейтится суммой `syn_valid + syn_valid_extra` (пробы только по 8443/2053
в тихий час на 443 тоже срабатывают), `PROBE-BURST` — по-прежнему только
443. UDP-порты в probers4
слепы (только объёмный `udp_443`). Быстрый контур: тег
`[warning] [probe] FAST-CONTOUR: N probers/5min` в
`journalctl -u vds-logs-sample` при всплеске (≥ 10 уникальных IP/5 мин) —
юниты logs работают с `ProtectSystem=strict`; `ReadWritePaths=/var/lib/vds
/var/run` (sample и daily), иначе `FileLock(/var/run/vds-logs.lock)` падает
EROFS.
телеметрия без авто-действий.
**Откат:** рассинхрон снапшота со счётчиками ядра → переинициализация базовой
линии: `vds gateway probe-watch install --apply` (переустанавливает таблицу —
счётчики и снапшот с нуля; идемпотентно).

### 5.12 Правило знаний: реагирование на вердикты PROBE-BURST / RU-PROBE-SUSPECT

**Инвариант кэша:** `seen_ru_ips` в снапшоте хранит **aware-UTC** метки; naive-время
(`datetime.now()`) нормализуется при записи — смесь типов роняла бы `sorted()`
и сервис probe-watch (P0 ревью 2026-11-20).

**Правило:** `PROBE-BURST` (всплеск 40-байтных `syn_bare`) — конфигурацию не
менять. `RU-PROBE-SUSPECT` (≥2 новых RU-IP с валидным ClientHello в окне и,
при per-element счётчиках, Σ delta ≥ 6; «новизна» — окно 24 ч, а не час) —
готовить переключение клиента на резервный транспорт (Hy2 / asv1 / RU-relay).
**Почему:** PROBE-BURST — слепой масс-скан (Shodan/Censys), TLS-пейлоада не
несёт. RU-PROBE-SUSPECT = ТСПУ зафиксировал подозрительный паттерн и запустил
распределённое активное зондирование из подсетей РФ; если вслед за ним падает
AWG (UDP/51825) или Reality (TCP/443) — это подтверждённый бан по
протоколу/IP, а не локальный сбой. Вердикт активен только при наличии
`/etc/vds-relay/ru-cidrs.txt` (ставится `vds gateway probe-watch ru-cidr
install --apply` уже без relay-модуля — SPEC-20261116-probe-response §3;
до этого geo: unknown).
**Серверная реакция (SPEC-20261116-probe-response):** вердикты агрегируются
в threat-level `quiet/elevated/high` (high = RU-SUSPECT 2 окна подряд;
снапшот переживает рестарт; свои клиенты — AWG endpoints + серверный IP +
whitelist `/etc/vds-probe-watch/allow-ips.txt` — исключаются). Реакция —
только сетевая видимость 443 (UFW), никогда юниты/конфиги xray/hy/awg:

```bash
sudo vds gateway probe-watch ru-cidr install --apply     # RU-CIDR + еженедельный таймер
sudo vds system ufw lock-443 --allow-from IP[,IP] --ttl 48h --apply  # изоляция 443 (dry-run по умолчанию)
sudo vds system ufw lock-443 --status                     # состояние лока + TTL
sudo vds system ufw lock-443 --unlock --apply             # откат = одна команда (ровно снимок)
sudo vds gateway probe-watch config --auto-lockdown on --lockdown-allow IP --apply  # авто-лок при high (default off)
```

Лок не трогает AWG 51825/ssh (`2053/tcp` CDN и так не открыт — холодный резерв, Q6); Hy2-hop (asv1) остаётся открытым с
warning; TTL обязателен (default 48h, 1h..168h) — забытый лок невозможен
(auto-unlock тиком probe-watch). При downgrade лок НЕ снимается автоматически
(«мигалка» опаснее, §10 OQ-3). `harden` при активном локе отказывает
(обход `--force` с журналом).
**Проверка:** `vds gateway probe-watch` (вердикт + threat-level + ru_top);
`vds gateway probe-watch watch --json` (контракт полей `threat_level`,
`threat_reason`, `lockdown{active,since,ttl_until,allow_from}`, `ru_syn_new`);
`nft list set inet vds_probe probers4`.
**Откат (манёвр уклонения, на клиенте):** `vpn` переключение профиля с AWG
asv2 на Hysteria2 (port hopping + salamander) / транзитный RU-relay
(`185.80.91.135`, развёрнут 2026-11-17). CDN `:2053` в этом списке больше нет —
канал в холодном резерве (DECISION Q6), origin на asv2 не развёрнут.

### 5.13 Съём эталонного дампа пробы ТСПУ (при RU-PROBE-SUSPECT)

При вердикте RU-PROBE-SUSPECT можно снять внутренности проб (Cipher Suites,
SNI, TLS-отпечаток бота цензора) кольцевым захватом без мусора — только SYN и
первые пакеты с данными на 443, свой IP исключить, ротация 5×10 МБ:

```bash
tcpdump -i any -nn 'tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-push) != 0) \
  and not src host <СВОЙ_ДОМАШНИЙ_IP>' -s 512 -C 10 -W 5 -G 3600 \
  -w /var/tmp/tspu_probes.pcap
# разбор: TLS-отпечаток (JA3/JA4) сканера:
tshark -r /var/tmp/tspu_probes.pcap -Y "tls.handshake.type == 1" -V
```

Путь — `/var/tmp` (на диск; `/tmp` в Ubuntu 24.04 — tmpfs в RAM), `-G 3600`
гасит забытый фоновый захват через час.

Интерпретация: одиночный ClientHello vs серия из 8 специфических проб
(механика J3/TSPU active probing, схема ByeByeVPN — см. И40 банка идей);
длины мусорных проб <209 / >214 байт (эталон GFW Report / net4people — И41).
Дамп содержит метаданные соединений — в git не класть, локально, стереть
после разбора.

### 5.14 Матрица рисков правил знаний

| Правило | Главный риск при нарушении |
|---|---|
| §5.3 ICMP | потеря диагностики маршрута; аномалия «TLS есть, ICMP дропается» |
| §5.4 двухфазный ssh | потеря доступа: 22 закрыт при непроверенном 49222 |
| §5.6 nft-изоляция | снесённые счётчики/детект зондирования после flush |
| §5.7 Docker | порт открыт мимо UFW наружу |
| §5.8 персистентность | «после ребута всё молчит», ручной ремонт на сервере |
| §5.9 прогрев IP | ложная диагностика «Reality сломан» в 30-мин TCP-карантине |
| §5.5 откат | `ufw reset` стирает правила relay/amneziawg/hop |
| §5.11 детект через vds_probe | слепота к началу зондирования: Reality молча уводит пробы в dest-fallback, логи демона пусты |
| §5.12 раздельные реакции | паранойя на каждый масс-скан (BURST) или игнор реальной атаки (SUSPECT) → простой при блокировке |
| §5.13 дамп проб | tmpfs-переполнение RAM на слабых VDS; вечный фоновый tcpdump |
| §9 dnsmasq-инвариант | утечка split-доменов в открытый DNS или 30-мин NXDOMAIN-кеш |
| §9.1 чеклист аварии | починка исправного сервера при локальном сбое ноутбука |
| Fail-safe порядок §5.1 | enable без ssh-правила → отрезание по ssh |

### 5.15 Правило знаний: сторож угрозы `vds-alert-watch` (SPEC-20261117)

**Что это:** независимый oneshot-таймер на **exit-узле**, который раз в 2 мин
читает уже существующую телеметрию и при переходе состояния отправляет короткое
сообщение в Telegram и/или SMTP (stdlib), плюс напоминания после cooldown и
суточный heartbeat. Только уведомления: сторож **не** меняет `probe-watch.json`,
`state.json`, UFW и юниты протоколов.

**Юниты и файлы:**

| Артефакт | Путь | Права | Назначение |
|---|---|---|---|
| `vds-alert-watch.service` / `.timer` | `/etc/systemd/system/` | 0644 | рендер из `vds-alert-watch.service.tpl` / `vds-alert-watch.timer.tpl` |
| Конфиг каналов | `/etc/vds/alert.env` | 0600 | TG-токен / SMTP App Password — **единственный носитель секретов** |
| Состояние | `/var/lib/vds/alert-state.json` | 0600 | последние отправки, окно лимита, backoff каналов |

Секреты в `Environment=` юнита **не** попадают: процесс читает `alert.env` сам
(иначе `systemctl show -p Environment` светил бы токен).

**Песочница юнита:** `ProtectSystem=strict`, `ReadWritePaths=/var/lib/vds /var/run`,
`ProtectHome=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`. **`AF_NETLINK`
обязателен:** `awg show` читает состояние через netlink, и без него юнит получает
`Unable to access interface: Address family not supported by protocol` — пульс
уходит в `inconclusive` (`ALERT-SKIP relay_pulse no_telemetry`), хотя ручной
`vds alert status` данные видит. Симптом на живом узле — ровно эта пара строк.

**Сигналы:** `threat` из `/var/lib/vds/probe-watch.json` (missing/corrupt/
`no_level`/stale различаются — «нет данных» ≠ «тихо»); пульс плеча relay→exit
(`awg show awg0 dump` + пир `relay` из `state.json`, гейт активности: без
недавнего роста `rx` старый handshake — `idle`, не алерт); активный `lock-443`.

**Heartbeat (dead-man switch):** если с последней отправки прошло
`ALERT_HEARTBEAT_H`=24 ч, уходит «Сторож жив» с числом пропущенных часов и
предупреждениями каналов — тишина дольше суток сама по себе означает, что
сторож/канал не работает.

**Подавление:** повтор того же уровня — не чаще `ALERT_COOLDOWN_MIN`=30 мин, не
более `ALERT_RATE_LIMIT_PER_HOUR`=6 отправок в час; эскалация уровня обходит и
cooldown, и лимит; напоминание о локе — раз в `ALERT_LOCK_REMINDER_H`=6 ч, о
затяжном `high` (`threat_high_still`) — раз в `ALERT_HIGH_REMINDER_H`=6 ч
(диапазон 1..24; переходы в/из high — мгновенно), о недоступной телеметрии — раз
в `ALERT_TELEMETRY_REMINDER_H`=24 ч; подавлённое сводится в одну «сводку» за тик,
**кроме подавленных `*_still`** (они по определению не несут новой информации и
не должны порождать ежечасную пустую сводку); сбой канала — экспоненциальный
backoff (`60·2^(n−1)` с, до 1 ч).

**Проверка:** `sudo vds alert status` (каналы/юниты/coverage, `--json` без
секретов; без root — урезанный вид, `alert.env` 0600 не читается); `sudo vds alert test [--channel smtp]` — реальная отправка без
записи state; `journalctl -u vds-alert-watch` — теги `ALERT-SENT / ALERT-FAILED /
ALERT-SKIP`. Ручной тик — только `sudo vds alert watch --no-send`.

**Правило `PersistentKeepalive`:** на релее `awg1` по умолчанию **нет**
keepalive (И44), поэтому свежесть handshake в простое ничего не значит —
сторож валидирует сигнал гейтом активности, а деплой рекомендует
`PersistentKeepalive = 113` на `awg1` (см. `docs/DEPLOY-RU-RELAY.md`), тогда
`idle` не наступает.

**Откат:** `sudo vds alert remove --apply` (юниты сняты, `alert.env` сохранён) →
`sudo vds alert remove --apply --purge` (удалить `alert.env` и
`alert-state.json`). UFW/`probe-watch.json`/`state.json` не затрагиваются.

## 6. Провайдер и DNS (руками, без API-токена не автоматизируется)

| Что | Как | Проверка |
|---|---|---|
| Провайдерский файрвол | панель хостера: открыть TCP 22/80/443/8443, UDP 443/51825/51826 (+hop); `2053/tcp` — только при реактивации CDN (Q6) | `nc` с внешней точки; `traceroute` |
| Anti-DDoS / geo-фильтр | панель хостера. **Факт asv1:** TCP с не-РФ ASN получает `refused/timeout`, ICMP проходит. ⚠️ Только при реактивации CDN (Q6): origin `:2053` должен быть достижим с ASN Cloudflare (AS13335, не-РФ) — на asv1 подсети CF проходили; при смене панели/фильтра внести [cloudflare.com/ips-v4](https://www.cloudflare.com/ips-v4/) в белый список, иначе 521/522 | `check-host.net`: ICMP vs TCP; `curl -I https://<cdn>:2053/` |
| Cloudflare DNS (apex) | A → IP сервера, proxied для CDN (orange), иначе DNS-only | `dig +short <домен>` |
| LE-сертификаты | `vds acme issue --domain <домен> --email <email>` (после A-записи) | `openssl x509 -enddate`; `certbot renew --dry-run` |
| CDN-запись | origin-домен + порт 2053, Full (strict) | `curl -I https://<cdn-домен>:2053/` |
| TTL перед переездом | 300 за сутки | `dig` |

## 7. Агентский чеклист восстановления (последовательный, идемпотентный)

> Агенту: выполнять по шагам, после каждого — проверка; деструктивные
> операции (ufw reset, перезапись sshd, swap) — только с подтверждением
> владельца; секреты не печатать.

1. `bash preinstall.sh` (или `vds server-setup` интерактивно) → timezone, apt,
   пакеты. Проверка: `timedatectl`, `python3 -V`.
2. `bash install.sh` → venv, `vds`. Проверка: `vds --help`.
3. `vds gateway init --apply --protocols …` (см. SPEC) → протоколы, сертификаты,
   healthcheck. Проверка: `vds gateway status`, `systemctl is-active …`.
4. Порты/UFW: `sudo vds system ufw harden --profile <gateway|relay|exit-cascade> --apply`
   (dry-run по умолчанию — сначала план; §5). Проверка: `ufw status verbose`.
   После любых правок файрвола — reboot-гейт §5.8 (is-enabled + sysctl --system).
5. Провайдерский файрвол + DNS/CF по §6. Проверка: внешние пробы.
6. Данные: либо миграция (`20_vds-migrate.sh`, §8), либо новые клиенты
   (`vds … add-client`) и ре-импорт ссылок.
7. Клиенты (§9): `vpn profile pull`, AWG `.conf`, проверка `vpn speed`.
8. Опционально: swap, unattended-upgrades, journald, лимиты (§3), fail2ban.
9. Сторож угрозы (**только exit-узел**, §5.15): `sudo vds alert install --apply`
   → заполнить `/etc/vds/alert.env` (0600) → `sudo vds alert test` →
   `sudo vds alert status`. На RU-рееле `install` отказывает (секретов там нет).

## 8. Данные и секреты (миграция vs «с нуля»)

| Артефакт | Путь | Права | Как перенести |
|---|---|---|---|
| Состояние gateway | `/opt/my-vds/gateway/state.json` | 0600 | `20_vds-migrate.sh --apply` |
| AWG-клиенты | `/opt/my-vds/gateway/clients/amneziawg/*.conf` | 0600 | миграция (см. отчёт TEST fresh-install) |
| Конфиг Xray (ключи Reality) | `/usr/local/etc/xray/config.json` | 0600 | **только миграцией**; fresh install генерирует новые ключи → ссылки меняются |
| Hysteria2 | `/etc/hysteria/{config,obfs}.yaml`, `cert.pem`, `key.pem` | 0600 | миграция |
| AmneziaWG | `/etc/amnezia/awg0.conf` | 0600 | миграция |
| LE | `/etc/letsencrypt/` | 0600 | миграция или `acme issue` заново |
| Уведомления сторожа | `/etc/vds/alert.env` | 0600 | **не переносить на релей**: заново `vds alert test` на exit-узле (FR-2) |
| CDN/CF | панель | — | вручную |

«С нуля» = все ключи новые, клиентам нужен ре-импорт. Ссылки сохраняются
только при переносе `state.json` + `xray/config.json` (см. MIGRATE-VDS и
TEST-20261114-fresh-install-v3).

## 9. Клиентская сторона (ноутбук)

| Что | Команда/файл | Проверка |
|---|---|---|
| Импорт ссылок | `vpn profile pull -H root@<ip> --include-obfs` | `vpn profile list` |
| SSH-хост | `~/.config/vpn-manager/settings.json` | `vpn profile pull` без `-H` |
| AWG `.conf` | `vpn amneziawg add-client <name>` (scp) или `Endpoint = <ip>:51825` | `awg show`; `vpn start awg` |
| Split-зоны | `/opt/awg-split/domains.txt` (например, `youtu.be`) | `sudo bash scripts/15_domain-split.sh` |
| Проверка | `vpn speed`, `vpn probe`, `vpn monitor` | TTFB/throughput/статусы |
| DoH | `vpn doh on/off/status` | `resolvectl status` |

**Tradeoff fallback-резолвера (осознанный):** в awg-split.conf второй
апстрим `77.88.8.8` (Яндекс.DNS) держит RU-домены при падении DoH (инцидент
2026-11-11 «интернет мёртв»). Риск: при таймауте cloudflared dnsmasq
(`strict-order`) может уйти в fallback — запрос split-домена открытым UDP в
RU-резолвер = DNS-спуфинг/заглушка → битый IP в nft-сете. Живучесть vs
утечка; митигируется: strict-order (есть), здоровье cloudflared в
`vpn monitor`, долгосрочно — `server=/домен/`-маршрутизация только RU-зон в
77.88.8.8 вместо общего fallback.

**Инвариант dnsmasq (П.9, 2026-11-15):** `/etc/dnsmasq.d/awg-split.conf`
**генерируется** `scripts/15_domain-split.sh` — руками не править (править
`/opt/awg-split/domains.txt` + перезапуск dnsmasq). Чеклист-инвариант:
1. `grep conf-dir /etc/dnsmasq.conf` — строка **раскомментирована** (иначе
   awg-split.conf вообще не читается).
2. Апстримы в awg-split.conf: `127.0.0.1#5053` (cloudflared DoH) + fallback
   `77.88.8.8`; `neg-ttl=60` — от генератора, не руками.
3. Проверка: `dnsmasq --test`, `dig @127.0.0.1 youtu.be` → split-резолвер отвечает.

### 9.1 VPN не работает — чеклист первого порядка (П.10)

Порядок диагностики строго сверху вниз, **без слепых рестартов демонов**
(рестарт сбрасывает телеметрию probe-watch и маскирует картину зондирования):

1. **ping** сервера (`ping <ip>`): нет → сеть/ICMP/провайдер (§5.3: ICMP не
   режем — если пинг пропал, это внешняя политика или хостер).
2. **Туннель/split**: `awg show` (handshake свежий?), `vpn probe`; на ноутбуке —
   split-зоны §9 (dnsmasq-инвариант выше).
3. **DNS**: `dig @127.0.0.1 <split-домен>`; DoH `127.0.0.1#5053` жив?
4. **TCP-vs-UDP / ТСПУ-окно**: `check-host.net` ICMP vs TCP на 443; попробуйте
   другой транспорт (Reality↔Hy2↔CDN) — режется один протокол или всё.
5. **CDN-резерв**: клиенты переводятся на CDN-фронт (CDN-FRONTS.md), пока
   основной нога деградирует.
Только после п.1–5 — серверные действия (`vds gateway status`, journal), и
только осознанно рестарты.

## 10. Известные расхождения (дрейф asv1)

1. **UFW выключен**, `server-setup` не применялся; список портов в
   `server-setup` устарел — при включении UFW использовать
   `vds system ufw harden --profile …` (§5), не `server-setup`.
2. **Swap отсутствует** (0), хотя `server-setup` его создаёт.
3. **SSH-пароли разрешены** (`PasswordAuthentication yes`), хотя
   `server-setup` их отключает.
4. **Docker не установлен** (ZTNET не используется).
5. `ulimit -n = 1024` (дефолт) — под нагрузкой может быть мало.
6. DNS — публичные 8.8.8.8/8.8.4.4; DoH-цепочка (`vpn doh`) на клиенте,
   не на сервере.
7. Провайдер режет TCP с не-РФ ASN (проверено 2026-11-13) — это внешняя
   политика, не настройка ОС; учитывать при CDN/зарубежных клиентах.

## 11. Что нельзя «сохранить шаблоном»

- Провайдерская панель (файрвол, anti-DDoS, VNC) — нет API-доступа.
- Cloudflare (DNS/туннели/Argo) — нужен аккаунт/токен владельца.
- Бизнес-решения (включать ли swap/UFW/fail2ban, какой домен).
- Данные клиентов/сертификаты без миграции — это секреты, а не шаблон.

Всё остальное из §3–§5 и §7 — команды, которые агент может выполнить позже
по этому документу.
