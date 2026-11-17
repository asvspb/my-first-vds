# DEPLOY-RU-RELAY — ручной ранбук развёртывания RU-relay (ADR-007 v1)

> Рабочий путь Фазы 2, copy-paste по ssh на **чистый RU VDS** (Ubuntu 24.04).
> `vds relay init --apply` повторяет эти шаги 1:1 (SPEC-20261114-ru-relay);
> этот ранбук — источник правды и резерв, если CLI недоступен.
> Замены: `RELAY_IP` — IPv4 релея, `EXIT_IP` = `213.108.23.119` (asv2,
> SSH 49222), `RELAY_DOMAIN` = `relay.asvpersonal.ru`, `RU_SNI` — RU-сайт
> same-DC хостера. **asv1 (103.45.247.172) удалён 2026-11-16 — exit только asv2.**
>
> **Статус (2026-11-17, второй прогон): релей РАЗВЁРНУТ** — LandVPS `vm354051`
> (`185.80.91.135`, AS216334, Москва), **Ubuntu 24.04.4**, 0.75 ГБ + 1.5 ГБ swap.
> Юниты `vds-relay-{awg,exit,nat,policy,cidr}` + `vds-xray` active, UFW
> профиль relay применён. Gate-приёмка [Фазы 0](team/reports/TEST-20261117-ru-relay-gate.md),
> раскатка — [DEPLOY-отчёт](team/reports/DEPLOY-20261117-ru-relay-landvps.md).
> Exit-нога — **asv2 213.108.23.119** (asv1 удалён 2026-11-16).
> Открытые пункты: DNS `relay.asvpersonal.ru` (пока `354051.landvps.online`),
> решение по ОС 24.04 vs 22.04, смена паролей панели/root.

## Фаза 0 — закупка и gate-приёмка (до любого развёртывания)

### 0.1 Критерии выбора RU VDS (владелец)

- KVM (не LXC — нужен kernel-модуль amneziawg/DKMS), Ubuntu 24.04;
- Москва/СПб (RTT 10–20 мс от Волгограда), 150–300₽/мес;
- **dual-stack IPv6 обязателен** (даже если v1 — v4-only: критерий будущей
  ноги), UDP **без шейпинга**, **дешёвая смена IP**, **чистота /24 до годовой
  оплаты** (белые списки — «перо оператора + перо /24», И22);
- спросить у хостера список его фронт-доменов для Reality dest/SNI (И20).

#### 0.1.1 Тариф: что брать (пример LandVPS)

| Параметр | Требование | LandVPS RU-1 | Вердикт |
|---|---|---|---|
| Виртуализация | строго **KVM** (dkms/nftables/ip rule) | KVM | ✅ |
| ОС | Ubuntu 24.04 LTS | есть шаблон | ✅ |
| RAM/диск | runtime ~130–180 МБ; **сборка `amneziawg-dkms` (gcc) ~700–800 МБ пика** | RU-1: 1 ГБ / 20 ГБ SSD | ✅ **бери RU-1** |
| 0.75 ГБ промо | до сборки dkms обязателен swap | 0.75 ГБ | ⚠️ только с `1G swap` |
| Канал | без лимита PPS; транзит удваивается (in+out) | 200 Мбит/с безлимит | ✅ |
| Anti-DDoS | **не должен резать UDP :443 / :51825** | базовая защита | ⚠️ проверить smoke §0.3 |

**Не покупать сразу год.** Сначала **1 месяц** и gate-тест §0.3: железо
вторично, критично — как аплинк этого ДЦ проходит ТСПУ до **asv2
213.108.23.119** и не режет ли UDP анти-DDoS хостера. Потеря при провале —
стоимость тестового месяца (~250 ₽), не года.

Если берёшь 0.75 ГБ — **до** `apt install amneziawg-dkms`:
```bash
fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

#### 0.1.2 Проверки сразу после покупки (5 минут)

1. **ASN/сосед под RU_SNI:** `curl -s https://ipinfo.io/<RELAY_IP>` — найти
   живой RU-HTTPS (TLS 1.3 + H2) в том же /24 или ASN для Reality dest/SNI.
2. **IPv6:** включить в панели/тикете, проверить `ip -6 addr` и
   `ping6 -c3 2606:4700:4700::1111`. Для v1 хватает IPv4, но v6 — будущая
   вторая нога до asv2 (`/48` уже есть).
3. **Leg smoke §0.3** (UDP relay→asv2:51825).

### 0.2 DNS: A-запись relay (ОБЯЗАТЕЛЬНО до init)

```
relay.asvpersonal.ru.  A   <RELAY_IP>     # DNS-only / серое облако!
```

- CF-прокси (оранжевое облако) **не пропускает UDP 443 (AWG) и не-HTTP TCP** —
  только DNS-only;
- смена relay-IP при бане = правка одной A-записи, клиенты не трогаются.
- Проверка с релея: `dig +short relay.asvpersonal.ru` → RELAY_IP.

### 0.3 Leg smoke-test — UDP-handshake релей→asv2:51825 (GATE)

С **голого RU VDS**, до AWG-сервера и UFW-правил. Exit — asv2
(`213.108.23.119`, SSH 49222):

```bash
# на asv2: временный пир (конфиг в gateway/clients/amneziawg/)
ssh asv2 'vds amneziawg add-client relay-smoke'
scp -P 49222 asv2:/opt/my-vds/gateway/clients/amneziawg/relay-smoke.conf /tmp/awg1-smoke.conf

# на релее: нужен kernel-модуль (dkms), не только userspace-tools
apt update && apt install -y software-properties-common curl
add-apt-repository -y ppa:amnezia/ppa && apt update
apt install -y amneziawg-dkms amneziawg-tools
awg-quick up /tmp/awg1-smoke.conf     # Table=off не нужен: AllowedIPs ок на 2 мин
awg show                              # ожидаем latest handshake < 60 c
curl --interface awg1-smoke -I https://www.google.com   # <100 мс → UDP не шейпится
awg-quick down /tmp/awg1-smoke.conf

# на asv2: удалить временный пир
ssh asv2 'vds amneziawg remove-client relay-smoke --apply'
```

**Стоп-условие:** handshake не появляется за 2 мин или пакеты идут с дикими
потерями → **эскалация владельцу**: другой хостер/локация, до покупки года.
Частая причина — L3/L4 anti-DDoS хостера дропает кастомный UDP AmneziaWG.

## Фаза 2.0 — что выяснилось на живой раскатке (2026-11-17, LandVPS)

Проверено на чистом Ubuntu 22.04 cloud image. Все пункты уже учтены в коде
(`HF-REL-1..4`), ручной ранбук ниже — для случая «CLI недоступен».

1. **`iptables` может отсутствовать.** Минимальный образ 22.04 без `iptables`:
   `vds-relay-nat.service` падает с `status=127 / iptables: not found`, и
   релей остаётся без NAT/policy (трафик клиентов уходит напрямую).
   `relay init` теперь доустанавливает пакет сам; при ручном пути —
   `apt-get install -y iptables` ДО `systemctl start vds-relay-nat`.
   На **24.04** `iptables`/`ufw` стоят из коробки — проверено 2026-11-17.
2. **`policy-routing` привязан к интерфейсу awg1.** `ip route replace default
   dev awg1 table 100` исчезает при любом `restart vds-relay-exit`
   (ядро удаляет маршрут вместе с link), а oneshot-юнит с
   `RemainAfterExit=yes` сам не перезапускается → клиенты молча выходят
   напрямую через RU-IP релея. В шаблоне теперь `PartOf=vds-relay-exit.service`;
   при ручном пути после каждого рестарта ноги проверяйте
   `ip route show table 100` и при пустоте — `systemctl restart vds-relay-policy`.
3. **Повторный `relay init --apply` не блокируется своими портами.** 443,
   занятый `vds-xray`/`vds-relay-awg`, считается нормой (идемпотентность);
   чужой владелец — по-прежнему стоп.
4. **Метаданные AWG-сервера восстанавливаются из конфига.** Если первый
   `--apply` упал между созданием `/etc/amnezia/awg0.conf` и записью state,
   повторный init выводит `public_key`/обфускацию из конфига, и
   `relay add-client` работает (раньше — «нет public_key»).
5. **`ufw` тоже может отсутствовать** на cloud-образе — `vds system ufw
   harden --profile relay` сообщит об этом; `apt-get install -y ufw` →
   повторить. После включения проверьте, что SSH не потерян (правило
   `limit 22/tcp` ставится до `ufw --force enable`).
6. **Leg smoke на релее — только с `Table = off`.** Иначе `awg-quick`
   перехватывает default-route и рвёт SSH к релею (проверено: восстановление
   через exit-ноду). В `relay init` конфиг awg1 санитизируется автоматически.
7. **DNS релея.** CF-прокси (оранжевое облако) не пропускает UDP — только
   DNS-only. Пока A-записи нет, допустим технический домен хостера
   (`*.landvps.online`); после создания A-записи — повторный идемпотентный
   `relay init --domain relay.asvpersonal.ru --apply` + перевыпуск клиентских
   конфигов.

## Фаза 2 — развёртывание (каждый шаг с проверкой)

### 1. Бейзлайн сервера

```bash
ssh root@RELAY_IP
export INSTALL_DIR=/opt/my-vds
apt update && apt -y full-upgrade && apt -y install curl ufw nftables git python3 python3-venv
timedatectl set-timezone Europe/Volgograd
# клон/деплой репо vds (механизм ubuntuInstaller 11_vds-deploy.sh или git clone)
git clone <VDS_REPO> /opt/my-vds/vds && cd /opt/my-vds/vds
python3 -m src.main --help   # sanity
```

Проверка: `python3 -m src.main --help` печатает команды, `ufw status` = inactive
до конца настройки.

### 2. AWG-сервер UDP 443 (awg0, 10.10.0.0/24, MTU 1280)

```bash
cd /opt/my-vds/vds
sudo python3 -m src.main relay init \
  --exit 213.108.23.119 --domain relay.asvpersonal.ru --sni RU_SNI   # DRY-RUN: план
# (awg1-конфиг ещё нет — план покажет warn «перенесите с asv2»)
```

Либо руками (1:1 с планом):

```bash
add-apt-repository -y ppa:amnezia/ppa && apt update
apt install -y amneziawg-dkms amneziawg-tools && apt-mark hold amneziawg-tools amneziawg-dkms
# ключи: awg genkey | awg pubkey; обфускация: рандомный 1.5-набор (Jc 3-10,
# Jmin<Jmax<1292, S1/S2, H1..H4 попарно различны) → /etc/amnezia/awg0.conf:
#   [Interface] Address=10.10.0.1/24 ListenPort=443 MTU=1280 SaveConfig=false + Jc..H4
systemctl enable --now vds-relay-awg   # или ручной awg-quick up /etc/amnezia/awg0.conf
ufw allow 443/udp
```

Проверка: `ss -ulnp | grep :443` → awg-процесс; `ip link show awg0` → up.

### 3. Reality TCP 443 (RU-SNI фолбэк)

```bash
sudo python3 -m src.main xray install --sni RU_SNI
```

Проверка: `ss -tlnp | grep :443` → xray; `systemctl is-active vds-xray`.
RU-SNI обязателен: RU→RU TLS не подозрителен (PATTERNS §2.7 — здесь он
правильный; у старого asv1 на foreign IP та же маска была ошибкой — исторический урок).

### 4. awg1-нога до asv2

```bash
# на asv2:
ssh asv2 'vds amneziawg add-client relay'
scp -P 49222 asv2:/opt/my-vds/gateway/clients/amneziawg/relay.conf /root/relay-awg1.conf
# на релея:
sudo python3 -m src.main relay init \
  --exit 213.108.23.119 --domain relay.asvpersonal.ru --sni RU_SNI \
  --exit-conf /root/relay-awg1.conf --apply     # идемпотентно: дотягивает
```

sanitize при переносе (CLI делает автоматически; руками — добавить в
`[Interface]`): **`Table = off`** (иначе wg-quick положит default в main-table
релея и отрежет ssh!) и `MTU = 1420`.

Проверка: `ip link show awg1` → up; `awg show awg1 latest-handshakes` →
свежий handshake; `curl --interface awg1 ifconfig.me` → **IP asv2** (213.108.23.119).

### 5. ip_forward + MASQUERADE + UFW

```bash
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vds-relay-forward.conf
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -o awg1 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o awg1 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
ufw allow 443/udp && ufw allow 443/tcp && ufw allow 22/tcp && ufw --force enable
```

Проверка: `iptables -t nat -S POSTROUTING | grep MASQ` — два правила;
`ufw status | grep 443`.

> **Финальный шаг файрвола (SPEC-20261116):** после того как relay init /
> ручной ранбук отработали — `sudo vds system ufw harden --profile relay --apply`
> (dry-run по умолчанию; детектирует уже открытые `443/udp`+`443/tcp`, дотягивает
> deny-in/allow-out и ssh-лимит). Откат: `sudo vds system ufw harden --undo --apply`.
> Матрица портов и чеклист отката — [SERVER-BASELINE §5](SERVER-BASELINE.md).

### 6. Policy-routing: nft RU-CIDR set + fwmark + table 100

```bash
python3 -m src.relay.cidr update   # ipdeny → агрегат → /etc/vds-relay/ru-cidrs.txt + nft -f
```

Руками (если CLI-путь недоступен): сгенерировать
`/etc/vds-relay/nft-policy.conf` (формат — вывод `render_nft_policy`),
затем:

```bash
nft -f /etc/vds-relay/nft-policy.conf
ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 table 100
ip route replace default dev awg1 table 100
systemctl enable --now vds-relay-policy.service   # переживает ребут
```

Проверка: `nft list table inet vds_relay` — set ru_cidr с тысячами элементов;
`ip rule show | grep fwmark`; `ip route show table 100` → default dev awg1.
**Разводка трафика:** `mtr -n ya.ru` (RU — через eth0, НЕ awg1) и
`mtr -n 1.1.1.1` (хоп 1 = asv2); tcpdump: `tcpdump -ni awg1 host ya.ru` — тишина
(ya.ru идёт мимо awg1), `tcpdump -ni awg1 host 1.1.1.1` — пакеты есть.

### 7. Еженедельный CIDR-таймер

```bash
systemctl enable --now vds-relay-cidr.timer
systemctl list-timers vds-relay-cidr.timer
```

Юнит `vds-relay-cidr.service` рендерится с `resolve_python()`: venv внутри
`INSTALL_DIR` имеет приоритет над системным `python3`, поэтому `vds relay init`
не оставит таймер без зависимостей даже под `sudo` с чистым `PATH`.

### 8. MTU (зафиксировано)

- awg0 **MTU 1280** (двойная инкапсуляция client→relay→asv2) — в
  `/etc/amnezia/awg0.conf` и во всех клиентских .conf (`vds relay add-client`
  пишет автоматически);
- awg1 MTU 1420 (одинарная) — в `/etc/amnezia/awg1.conf`;
- MSS-clamp не требуется при 1280; если внешний путь требует —
  `iptables -t mangle -A FORWARD -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`.

### 9. Клиенты

- **Телефон:** `sudo vds relay add-client phone` → скопировать
  `/opt/my-vds/gateway/clients/relay/phone.conf` по ssh → импорт в
  AmneziaVPN; endpoint `relay.asvpersonal.ru:443`; DNS уходит на релей
  (AllowedIPs 0.0.0.0/0). И44: `PersistentKeepalive` по умолчанию не
  пишется (радиомолчание в простое); клиенту за NAT —
  `--keepalive 113`.
- **`DNS =` в клиентском conf не пишется** (проверено 2026-11-17 на
  Android/Windows). При `AllowedIPs 0.0.0.0/0` это типичная причина
  «подключено, но ничего не открывается»: клиент спрашивает DNS у
  локального роутера, а тот адрес уходит в туннель. Резолвера на
  `10.10.0.1` нет. Добавлять в `[Interface]` вручную:
  `DNS = 1.1.1.1` (через релей+exit) или `77.88.8.8` (RU-CIDR — релей
  пустит напрямую). Также убирать `::/0` из `AllowedIPs`: нога `awg1`
  v4-only, v6 в туннеле — чёрная дыра (источник IPv6-ENETUNREACH).
- **QR для телефона** (Android) — штатной команды у `vds` нет; рабочий
  путь: скопировать conf на ноутбук как `~/.awg/<name>.conf` (0600), затем
  `vpn amneziawg qr <name>` (терминал, секрет — через stdin) или
  `qrencode -t PNG -m 4 -o <name>-qr.png -r ~/.awg/<name>.conf` (PNG 0600).
  Имя не должно совпадать с локальными инстансами (`laptop`, `relay`) —
  `qr` сначала ищет `/etc/amnezia/amneziawg/<name>.conf`. Windows: QR не
  нужен — импорт файла. Автоматизация (`add-client --dns/--qr`) —
  TECHDEBT P23.
- **Endpoint клиента.** Порядок выбора: явный `--endpoint` → `state.domain`
  → канонический `relay.asvpersonal.ru` → публичный IP сервера. Имя,
  совпадающее с hostname/FQDN самой машины, **пропускается с warning**:
  LandVPS пишет в `state.domain` своё внутреннее имя
  (`354051.landvps.online`) — на сервере оно резолвится внутренним DNS, а у
  клиента NXDOMAIN. Если ни один домен не резолвится в публичный адрес,
  берётся IP (`ip route get`, src наружу): клиент поднимается, но при смене
  IP адрес надо перегенерировать. Явное значение —
  `--endpoint HOST[:PORT]` (например `--endpoint 185.80.91.135:443`).
  Симптом неверного endpoint на клиенте: `awg-quick: Name or service not
  known: '<host>:443'` и юнит в `failed` (TECHDEBT P22).
- **Ноутбук:** инстанция `vpn-awg-split@relay` в ubuntuInstaller
  (доменный split без изменений; меняется только выходная нога).
  Управление — `vpn start relay` (весь трафик → релей), `vpn start` —
  обратно на прямой контур, `vpn down` — выключить профили и релей
  (`vpn-guard.service` не трогается). Контуры взаимоисключающие: старт
  нового сначала гасит старый, при неудаче — отказ, а не два маршрута.
  Режим пишется в `~/.local/share/vpn-manager/mode.json` (schema
  `vpnm.mode/1`) — это контракт с `vpn guard`; `guard/activity.json`
  остаётся probe-маркером `{cmd,started,until}` и не перезаписывается.

### 10. Reboot-тест (приёмка)

```bash
reboot
# после подъёма:
systemctl is-active vds-relay-awg vds-relay-exit vds-relay-nat vds-relay-policy vds-xray
systemctl is-enabled vds-relay-cidr.timer
ip rule show | grep fwmark && ip route show table 100 | grep awg1
nft list table inet vds_relay | head
awg show awg1 latest-handshakes    # свежий handshake ≤ 2 мин
curl --interface awg1 ifconfig.me  # IP asv2
```

Всё зелёное → релей развёрнут. Эксплуатация: `sudo vds relay status`
(юниты/handshake-возраст/CIDR-возраст), поле — матрица whitelist-проверок
ADR-007 §Test-plan при первом включении whitelist у оператора.

## DNS-политика релея (предложение, исполнение — OQ-3)

Заблокированные домены не должны резолвиться через RU-резолверы.
Рендер предложения: `python3 -c "from src.relay.config import render_dnsmasq_proposal; print(render_dnsmasq_proposal())"`
— dnsmasq: RU-TLD → RU-резолвер напрямую; прочее → форвард через awg1
(`server=1.1.1.1@awg1`). Устанавливать после полевой проверки whitelist.

## Откат (демонтаж)

```bash
systemctl disable --now vds-relay-cidr.timer vds-relay-policy.service vds-relay-nat.service vds-relay-exit.service vds-relay-awg.service
ip rule del fwmark 0x1 table 100; ip route flush table 100; nft delete table inet vds_relay
rm -f /etc/amnezia/awg{0,1}.conf /etc/sysctl.d/99-vds-relay-forward.conf /etc/vds-relay/ru-cidrs.txt /etc/vds-relay/nft-policy.conf
iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o awg1 -j MASQUERADE
iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
ufw delete allow 443/udp; ufw delete allow 443/tcp
# xray: sudo vds xray remove --apply (если фолбэк больше не нужен)
```

## Non-goals v1 (не поднимать на релее)

W-strict-обход (только матрица проверки ADR-007), второй релей, v6-нога,
L7-цепочка xray→xray, мульти-инстанс AWG-сервера, Hysteria2, dnsmasq-исполнение.
