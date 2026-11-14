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
> Связанные документы: [DEPLOY](DEPLOY.md) (установка),
> [MIGRATE-VDS](MIGRATE-VDS.md) (перенос данных),
> [SPEC fresh-install-v3](team/specs/SPEC-20261114-fresh-install-v3.md)
> (`gateway init`), [VPN-PROTOCOLS](VPN-PROTOCOLS.md) (порты/протоколы).

## 1. Профиль asv1 (факт на 2026-11-14)

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
| UFW | **выключен** | ⚠️ `server-setup`, **список портов устарел** | §5 |
| Docker | нет | ⚠️ `server-setup` (не нужен без ZTNET) | `vds zerotier install` |
| BBR + UDP-буферы | да | ✅ `hysteria2 install` (sysctl.d) | `vds hysteria2 install` |
| `ip_forward` + MASQUERADE | да | ✅ `amneziawg install` | `vds amneziawg install` |
| hop-цепочка + UFW-диапазон | да | ✅ `hysteria2 add-hop-ports --apply` | — |
| obfs-инстанс | да | ✅ `hysteria2 add-obfs` | — |
| XHTTP / CDN | да | ✅ `xray add-transport` / `add-cdn` | — |
| certbot + таймер | да | ✅ `acme issue` | — |
| healthcheck-таймер | да | ✅ `gateway healthcheck --install-timer` | — |
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
| fd-лимиты | `printf "* soft nofile 65535\n* hard nofile 65535\n" > /etc/security/limits.d/99-vds.conf` | новый логин: `ulimit -n` |
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
> `yes` — при переустановке решите осознанно (доступ по ключу должен быть
> проверен **до** отключения паролей).

## 5. UFW: фактическая матрица портов

`server-setup` открывает устаревший набор (`ssh,80/tcp,443/tcp,51820/udp,9993/udp`).
Для текущего стека при включении UFW нужно:

```bash
for p in 22/tcp 80/tcp 443/tcp 443/udp 8443/tcp 2053/tcp 51825/udp 51826/udp; do
  ufw allow "$p"
done
ufw allow 20000:20500/udp   # только если включён hop
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
```

| Порт | Назначение | Кто открывает |
|---|---|---|
| 22/tcp | SSH | вручную |
| 80/tcp | ACME HTTP-01 | `server-setup` |
| 443/tcp | Reality | `server-setup` |
| 443/udp | Hysteria2 | **вручную** |
| 8443/tcp | XHTTP | **вручную** |
| 2053/tcp | CDN origin (CF) | **вручную** |
| 51825/udp | AmneziaWG | `amneziawg install` |
| 51826/udp | obfs salamander | **вручную** |
| 20000–20500/udp | hop | `add-hop-ports` |

Проверка: `ufw status numbered`; снаружи — из **чистой** точки (не параллельно,
И26): `nc -vz <ip> <port>`, для UDP — реальный клиент.

## 6. Провайдер и DNS (руками, без API-токена не автоматизируется)

| Что | Как | Проверка |
|---|---|---|
| Провайдерский файрвол | панель хостера: открыть TCP 22/80/443/8443/2053, UDP 443/51825/51826 (+hop) | `nc` с внешней точки; `traceroute` |
| Anti-DDoS / geo-фильтр | панель хостера. **Факт asv1:** TCP с не-РФ ASN получает `refused/timeout`, ICMP проходит | `check-host.net`: ICMP vs TCP |
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
4. Порты/UFW по §5 (если UFW будет включён). Проверка: `ufw status`.
5. Провайдерский файрвол + DNS/CF по §6. Проверка: внешние пробы.
6. Данные: либо миграция (`20_vds-migrate.sh`, §8), либо новые клиенты
   (`vds … add-client`) и ре-импорт ссылок.
7. Клиенты (§9): `vpn profile pull`, AWG `.conf`, проверка `vpn speed`.
8. Опционально: swap, unattended-upgrades, journald, лимиты (§3), fail2ban.

## 8. Данные и секреты (миграция vs «с нуля»)

| Артефакт | Путь | Права | Как перенести |
|---|---|---|---|
| Состояние gateway | `/opt/my-vds/gateway/state.json` | 0600 | `20_vds-migrate.sh --apply` |
| AWG-клиенты | `/opt/my-vds/gateway/clients/amneziawg/*.conf` | 0600 | миграция (см. отчёт TEST fresh-install) |
| Конфиг Xray (ключи Reality) | `/usr/local/etc/xray/config.json` | 0600 | **только миграцией**; fresh install генерирует новые ключи → ссылки меняются |
| Hysteria2 | `/etc/hysteria/{config,obfs}.yaml`, `cert.pem`, `key.pem` | 0600 | миграция |
| AmneziaWG | `/etc/amnezia/awg0.conf` | 0600 | миграция |
| LE | `/etc/letsencrypt/` | 0600 | миграция или `acme issue` заново |
| CDN/CF | панель | — | вручную |

«С нуля» = все ключи новые, клиентам нужен ре-импорт. Ссылки сохраняются
только при переносе `state.json` + `xray/config.json` (см. MIGRATE-VDS и
TEST-20261114-fresh-install-v3).

## 9. Клиентская сторона (ноутбук)

| Что | Команда/файл | Проверка |
|---|---|---|
| Импорт ссылок | `vpn profile pull -H root@<ip> --include-obfs` | `vpn profile list` |
| SSH-хост | `~/.config/vpn-manager/settings.json` | `vpn profile pull` без `-H` |
| AWG `.conf` | `vpn amneziawg add-client <name>` (scp) или `Endpoint = <ip>:51825` | `awg show`; `vpn start` |
| Split-зоны | `/opt/awg-split/domains.txt` (например, `youtu.be`) | `sudo bash scripts/15_domain-split.sh` |
| Проверка | `vpn speed`, `vpn probe`, `vpn monitor` | TTFB/throughput/статусы |
| DoH | `vpn doh on/off/status` | `resolvectl status` |

## 10. Известные расхождения (дрейф asv1)

1. **UFW выключен**, `server-setup` не применялся; список портов в
   `server-setup` устарел (§5) — при включении UFW открыть вручную.
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
