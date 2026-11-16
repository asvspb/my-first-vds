# TEST-20261117-vpn-guard-checkpoint-t0 — точка покоя WP-G6 (T0)

> **Тип:** TEST-отчёт (снимок T0, старт 7-дневного WP-G6).
> **Дата:** 2026-11-17 00:0x MSK. **Хост:** ноутбук `dragonMi`.
> **Код клиента:** `ubuntuInstaller` `78ce00c` (guard live-fix); сервер
> `my-first-vds` `0798218`. **Секреты:** нет; только счётчики/состояния.

## Сервис

```
vpn-guard.service: active/running, enabled, profile=hardened
с 2026-11-17 00:00:28 MSK
RSS: 16 068 608 B (~15.3 MiB) при MemoryMax=128M
```

Юнит: `ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX`,
`NoNewPrivileges=yes`, `Nice=10`, `CPUQuota=10%`.

## Источники и вердикт

```
[ok] journal:user
[ok] journal:system
[ok] state
[ok] file
[ok] verdict
[ok] sysfs:awg — iface=laptop
[off] netlink — v1.1, opt-in
signals: amneziawg=counters, dns=blind, hysteria2=blind, systemd=ok, xray=blind
```

`vpn guard sync --host root@asv2`: `verdict=quiet`, `threat=quiet`,
`fresh=true`, `lockdown=false`, `age_s=0`.

## Счётчики на T0

```
state=armed
counters: events=0, unparsed=0, dropped=0, findings=0,
          suppressed=0, redaction_hits=0
coverage: unparsed_ratio=0, notes=[speed_ring_restored:4,
          app_signal=blind (нет app-событий за прогон)]
findings.jsonl: 11 исторических (до restart)
```

`app_signal=blind` ожидаем в простое: app-события Xray/Hy2 пишутся при
старте/соединениях, окно пустое.

## Профили (после декомиссии asv1)

```
asv2-hy2      hysteria2    socks:2083
asv2-reality  xray-reality socks:2080
```

Активный — `asv2-reality` (egress 213.108.23.119); AWG-split `laptop` жив.
Мёртвые asv1-профили (`mob`, `phone`, `xhttp-web`, `cdn-home`) удалены.

## План контроля

- **T+24–48 ч:** `vpn guard status --json`, `vpn guard sync --host root@asv2`,
  `vpn guard findings`, `unparsed_ratio`, RSS/CPU.
- **T+7 дней:** AC-5 (RSS<80 МБ, CPU<1%, unparsed<5%), AC-17 живые проверки,
  реальный `kill -9`, `vpn guard selftest` из установленного wheel.
- Замечание архитектора P2 (не блокер): `CursorStore.save` — read-modify-write
  без `threading.Lock`; атомарная замена исключает битый файл, редкий потерянный
  тик курсора лечится следующим persist. Заведено в TECHDEBT P19.

## Трассируемость

| Что | Коммит |
|---|---|
| guard live-fix (stderr/cursor) | `ubuntuInstaller 78ce00c` |
| HF-SSH (UFW phase A) | `my-first-vds 14999ec` |
| T0/пост-мортем docs | `0798218` |
