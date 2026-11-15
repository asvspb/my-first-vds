# DEPLOY-RU-RELAY — ручной ранбук развёртывания RU-relay (ADR-007 v1)

> Рабочий путь Фазы 2, copy-paste по ssh на **чистый RU VDS** (Ubuntu 24.04).
> `vds relay init --apply` повторяет эти шаги 1:1 (SPEC-20261114-ru-relay);
> этот ранбук — источник правды и резерв, если CLI недоступен.
> Замены: `RELAY_IP` — IPv4 релея, `ASV1_IP` = `103.45.247.172` (exit),
> `RELAY_DOMAIN` = `relay.asvpersonal.ru`, `RU_SNI` — RU-сайт same-DC хостера.

## Фаза 0 — закупка и gate-приёмка (до любого развёртывания)

### 0.1 Критерии выбора RU VDS (владелец)

- KVM (не LXC — нужен kernel-модуль amneziawg/DKMS), Ubuntu 24.04;
- Москва/СПб (RTT 10–20 мс от Волгограда), 150–300₽/мес;
- **dual-stack IPv6 обязателен** (даже если v1 — v4-only: критерий будущей
  ноги), UDP **без шейпинга**, **дешёвая смена IP**, **чистота /24 до годовой
  оплаты** (белые списки — «перо оператора + перо /24», И22);
- спросить у хостера список его фронт-доменов для Reality dest/SNI (И20).

### 0.2 DNS: A-запись relay (ОБЯЗАТЕЛЬНО до init)

```
relay.asvpersonal.ru.  A   <RELAY_IP>     # DNS-only / серое облако!
```

- CF-прокси (оранжевое облако) **не пропускает UDP 443 (AWG) и не-HTTP TCP** —
  только DNS-only;
- смена relay-IP при бане = правка одной A-записи, клиенты не трогаются.
- Проверка с релея: `dig +short relay.asvpersonal.ru` → RELAY_IP.

### 0.3 Leg smoke-test — UDP-handshake релей→asv1:51825 (GATE)

С **голого RU VDS**, до AWG-сервера и UFW-правил:

```bash
# на asv1: временный пир
sudo vds amneziawg add-client relay-smoke      # конфиг: /opt/my-vds/gateway/clients/amneziawg/relay-smoke.conf
# скопировать конфиг на релей:
scp asv1:/opt/my-vds/gateway/clients/amneziawg/relay-smoke.conf /tmp/awg1-smoke.conf

# на релея: поставить amneziawg-tools (только клинтские утилиты)
sudo add-apt-repository -y ppa:amnezia/ppa && sudo apt update
sudo apt install -y amneziawg-tools
# поднять как клиента:
sudo awg-quick up /tmp/awg1-smoke.conf          # если ругается на Table — Table = off не нужен: AllowedIPs 0.0.0.0/0 здесь ок на 2 мин
sudo awg show awg0 latest-handshakes            # или имя интерфейса из конфига
# ожидаем: свежий handshake (< 60 c) → UDP не шейпится
sudo awg-quick down /tmp/awg1-smoke.conf

# на asv1: удалить временный пир
sudo vds amneziawg remove-client relay-smoke --apply
```

**Стоп-условие:** handshake не появляется за 2 мин или приходит рваный
(шейпинг) → **эскалация владельцу**: другой хостер/локация, до покупки года.

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
  --exit 103.45.247.172 --domain relay.asvpersonal.ru --sni RU_SNI   # DRY-RUN: план
# (awg1-конфиг ещё нет — план покажет warn «перенесите с asv1»)
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
правильный; у asv1 на foreign IP та же маска была ошибкой).

### 4. awg1-нога до asv1

```bash
# на asv1:
sudo vds amneziawg add-client relay
scp asv1:/opt/my-vds/gateway/clients/amneziawg/relay.conf /root/relay-awg1.conf
# на релея:
sudo python3 -m src.main relay init \
  --exit 103.45.247.172 --domain relay.asvpersonal.ru --sni RU_SNI \
  --exit-conf /root/relay-awg1.conf --apply     # идемпотентно: дотягивает
```

sanitize при переносе (CLI делает автоматически; руками — добавить в
`[Interface]`): **`Table = off`** (иначе wg-quick положит default в main-table
релея и отрежет ssh!) и `MTU = 1420`.

Проверка: `ip link show awg1` → up; `awg show awg1 latest-handshakes` →
свежий handshake; `curl --interface awg1 ifconfig.me` → **IP asv1**.

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
`mtr -n 1.1.1.1` (хоп 1 = asv1); tcpdump: `tcpdump -ni awg1 host ya.ru` — тишина
(ya.ru идёт мимо awg1), `tcpdump -ni awg1 host 1.1.1.1` — пакеты есть.

### 7. Еженедельный CIDR-таймер

```bash
systemctl enable --now vds-relay-cidr.timer
systemctl list-timers vds-relay-cidr.timer
```

### 8. MTU (зафиксировано)

- awg0 **MTU 1280** (двойная инкапсуляция client→relay→asv1) — в
  `/etc/amnezia/awg0.conf` и во всех клиентских .conf (`vds relay add-client`
  пишет автоматически);
- awg1 MTU 1420 (одинарная) — в `/etc/amnezia/awg1.conf`;
- MSS-clamp не требуется при 1280; если внешний путь требует —
  `iptables -t mangle -A FORWARD -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`.

### 9. Клиенты

- **Телефон:** `sudo vds relay add-client phone` → скопировать
  `/opt/my-vds/gateway/clients/relay/phone.conf` по ssh → импорт в
  AmneziaVPN; endpoint `relay.asvpersonal.ru:443`; DNS уходит на релей
  (AllowedIPs 0.0.0.0/0).
- **Ноутбук:** инстанция `vpn-awg-split@relay` в ubuntuInstaller (доменный
  split без изменений; меняется только выходная нога).

### 10. Reboot-тест (приёмка)

```bash
reboot
# после подъёма:
systemctl is-active vds-relay-awg vds-relay-exit vds-relay-nat vds-relay-policy vds-xray
systemctl is-enabled vds-relay-cidr.timer
ip rule show | grep fwmark && ip route show table 100 | grep awg1
nft list table inet vds_relay | head
awg show awg1 latest-handshakes    # свежий handshake ≤ 2 мин
curl --interface awg1 ifconfig.me  # IP asv1
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
