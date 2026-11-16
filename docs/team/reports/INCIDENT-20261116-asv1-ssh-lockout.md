# INCIDENT-20261116-asv1-ssh-lockout — потеря SSH после Фазы A переноса порта

> **Тип:** INCIDENT (snapshot). **Дата:** 2026-11-16 ~20:05 UTC.
> **Узел:** asv1 `45.91.168.58`. **Статус:** открыт; нужен консольный доступ.
> **Секреты:** в отчёте нет ключей/UUID/паролей.

## Что произошло

1. `vds system ufw harden --profile gateway --apply` — UFW включён
   (`Status: active`, deny incoming; 22/tcp LIMIT, 443/tcp+udp, 8443/tcp,
   80/tcp, 51825/udp, 51826/udp, 20000:20500/udp, 2053/tcp только CF-CIDR).
   SSH по 22 после этого работал.
2. `vds system ufw ssh-port --to 49222 --apply` — Фаза A:
   - `ufw limit 49222/tcp`;
   - `/etc/ssh/sshd_config.d/99-vds-port.conf` → `Port 22` + `Port 49222`;
   - `sshd -t` — OK;
   - `ssh.socket` drop-in + daemon-reload + restart;
   - вывод: «Фаза A применена. Порт 22 ОСТАЁТСЯ открытым».
3. Сразу после: **22/tcp и 49222/tcp — Connection refused** (не timeout).
   Повтор через 10+ с — то же. То есть слушателя SSH нет; UFW ни при чём
   (22 и 49222 разрешены, отказ = нет bind).

## Что работает / что нет

- 443/tcp, 8443/tcp — доступны; 2053/tcp — timeout (ожидаемо: CF-CIDR);
  80/tcp — refused (нет certbot standalone, UFW allow 80 есть).
- SSH 22/49222 — **refused**; удалённого доступа нет.

## Вероятная причина

`ssh.socket` перезапущен, но не поднял ListenStream ни на 22, ни на 49222
(конфликт drop-in с `ssh.service`, либо socket-юнит ушёл в failed и не
перезапустился). `sshd -t` валиден, конфиг с двумя Port — значит проблема в
unit-слое, а не в sshd-конфиге.

## Восстановление (через консоль провайдера / VNC)

```bash
# 1. Диагностика
systemctl status ssh.socket ssh.service --no-pager
journalctl -u ssh.socket -n 50 --no-pager
ss -tlnp | grep -E ':(22|49222)\b'
cat /etc/ssh/sshd_config.d/99-vds-port.conf
ls -l /etc/systemd/system/ssh.socket.d/

# 2. Вернуть обычный ssh.service (22/tcp) — самый безопасный откат
systemctl disable --now ssh.socket
systemctl enable --now ssh.service
ss -tlnp | grep ':22\b'
# при необходимости:
ufw allow 22/tcp

# 3. Если нужен dual-listen: перезапустить socket после проверки drop-in
systemctl restart ssh.socket
ss -tlnp | grep -E ':(22|49222)\b'
```

После восстановления 22:
- проверить `ufw status` (22 LIMIT, 49222 LIMIT);
- НЕ выполнять `ssh-port --finalize`, пока 49222 не подтверждён рабочим входом;
- при необходимости откатить Фазу A: удалить drop-in `ssh.socket.d/*vds*`,
  `daemon-reload`, `systemctl restart ssh.service`, убрать
  `99-vds-port.conf` (оставить `Port 22`), `ufw delete limit 49222/tcp`.

## Что уже сделано до инцидента (не потеряно)

- GR-25 миграция XHTTP на asv1 + T-XM6 PASS (path/CDN/Reality сохранены).
- Telemetry: `probe-watch` + `ru-cidr` + `logs` таймеры active, `/etc/vds-relay/ru-cidrs.txt`.
- UFW hardening применён и активен.
- `gateway/state.json` содержит pending-маркер ssh-port (22 открыт по правилам,
  но sshd не слушает).
