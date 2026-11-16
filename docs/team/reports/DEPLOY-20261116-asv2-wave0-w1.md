# DEPLOY-20261116-asv2-wave0-w1 — выкатка HF-1/HF-2 + W1-1 на asv2

> **Тип:** DEPLOY-отчёт (snapshot), не SPEC.
> **Дата:** 2026-11-16 ~18:02–18:15 UTC. **Сервер:** asv2 (213.108.23.119:49222).
> **Код:** `my-first-vds` deployed HEAD = `4fb1956` (после фикса юнита logs).
> **Причина:** asv2 в `RU-PROBE-SUSPECT / elevated`, а probe-watch и logs-таймеры
> падали каждый тик (`ModuleNotFoundError: typer`), т.е. телеметрия отсутствовала.
> **Секреты:** в отчёте нет ключей/UUID/ссылок; только счётчики и пути.

## 1. Состояние до

- `/opt/my-vds` — код до HF-1/W1-1: `verified_session_ips` отсутствует,
  `syn_valid_extra` отсутствует; `xray/config.py` и `system/ufw.py` — до HF-2.
- `systemctl --failed`: `vds-probe-watch.service`, `vds-logs-sample.service`,
  `vds-logs-daily.service` — все с `ModuleNotFoundError: typer`
  (юниты рендерились с `/usr/bin/python3`, зависимости — в `/opt/my-vds/venv`).
- `vds gateway probe-watch watch --json` (ручной): `RU-PROBE-SUSPECT`,
  `threat_level=elevated`, `lockdown.active=false`, `auto_lockdown=false`.
- Бэкап: `/root/vds-pre-deploy-20261116-1802.tgz` (612K; `/opt/my-vds` без
  venv, `/etc/vds-probe-watch`, `/var/lib/vds`, unit-файлы).

## 2. Что сделано

1. `rsync -az -e "ssh -p 49222"` из локального `vds` в `/opt/my-vds`
   (excludes: `.git`, `.zcode`, `.opencode`, `venv`, `__pycache__`, `*.pyc`,
   `gateway/state.json`, `xhttp.log`). `gateway/state.json` не тронут.
2. `INSTALL_DIR=/opt/my-vds bash /opt/my-vds/install.sh` — venv уже есть,
   зависимости обновлены, `vds` wrapper жив.
3. Юниты пере-рендерены **с venv в PATH** (временный обход до HF-3):
   - `PATH=/opt/my-vds/venv/bin:$PATH vds gateway probe-watch install --apply`;
   - `... vds logs install --apply`;
   - `... vds gateway probe-watch ru-cidr install --apply` (8664 агрегата).
4. Найден и исправлен живой дефект: `vds-logs-sample.service` с
   `ProtectSystem=strict` не мог взять `FileLock(/var/run/vds-logs.lock)` —
   EROFS. Фикс `4fb1956`: `ReadWritePaths=/var/lib/vds /var/run` + тест;
   шаблон пере-развёрнут и юнит пере-рендерен.

Транспорты (`vds-xray`, `vds-hysteria2`, AWG) **не перезапускались**.

## 3. Состояние после

```
$ systemctl --failed
0 loaded units listed.

$ systemctl is-active vds-probe-watch.timer vds-logs-sample.timer \
    vds-logs-daily.timer vds-probe-rucidr.timer
active
active
active
active

$ vds logs status
последний сэмпл: 2026-11-16T18:14:19Z (threat=elevated)
disk_pct: 13%; capture: не запущен

$ vds gateway probe-watch watch --json | jq …
{"verdict":"quiet","threat_level":"elevated","syn_valid":1,
 "syn_valid_extra":0,"extra_ports":[8443,2053],"new_ru_ips":0,
 "lockdown":false}
```

- nft: `tcp dport { 443, 2053, 8443 } … update @probers4`,
  `syn_valid_extra`/`syn_bare_extra` объявлены; per-element counters — да.
- `vds gateway probe-watch config`: `auto_lockdown=False`.
- `vds gateway healthcheck`: xray/hysteria active, 443/tcp + 443/udp слушаются,
  AWG NAT на месте, сертификат 88 дн., SNI Hysteria2 = `asv2.asvpersonal.ru`.
- Код: `sha256(probing.py)=2d7541…`, `xray/config.py=27688b…`,
  `system/ufw.py=35a4f7…` — совпадают с локальным `4fb1956`;
  `verified_session_ips` — 9 вхождений, `syn_valid_extra` — 18.

## 4. Остаточные хвосты

1. **HF-3 — ✅ ЗАКРЫТ (`fb3e8fe`, docs `83dc1cc`):** добавлен
   `resolve_python()` (`venv` внутри `INSTALL_DIR` → `sys.executable` → PATH)
   и применён в `probing.py`, `logs/install.py`, `relay/init.py`.
   Живая проверка на asv2: `probe-watch install --apply` и `logs install
   --apply` с чистым системным `PATH` отрендерили
   `ExecStart=/opt/my-vds/venv/bin/python3`; `systemctl --failed` = 0,
   `logs sample` пишет (18:49:42Z). `vds-logs-daily` тоже получил
   `ReadWritePaths=/var/lib/vds /var/run`.
2. **HF-2:** код развёрнут, но XHTML/CDN-инбаунды на asv2 отсутствуют
   (Reality + Hysteria2 + AWG), поэтому рандомные пути/CF-CIDR не
   пере-рендеривались; на asv1 проверить отдельно при следующем деплое.
3. `threat_level=elevated` сохраняется — это состояние наблюдателя, а не
   ошибка; автоматический lockdown выключен.
4. `vds-logs-daily` теперь стартует; проверить отчёт `/var/lib/vds/forensics`
   после 04:15 UTC.

## 5. Откат

```bash
ssh asv2 'tar -xzf /root/vds-pre-deploy-20261116-1802.tgz -C / \
  && systemctl daemon-reload \
  && systemctl restart vds-probe-watch.timer vds-logs-sample.timer \
     vds-logs-daily.timer vds-probe-rucidr.timer'
```

Бэкап содержит код, `/etc/vds-probe-watch`, `/var/lib/vds` и unit-файлы.
`gateway/state.json` не входил в rsync и не менялся.

## 6. Трассируемость

| Что | Коммит |
|---|---|
| HF-1 verified sessions | `df72a9f` |
| HF-2 surface hardening | `41001ce`, `4530fa2` |
| W1-1 probe coverage | `b4b5dc1`, `6654434` |
| docs GR-25 / docsync | `f31c117`, `b097e4e` |
| logs sample unit `/var/run` | `4fb1956` |
