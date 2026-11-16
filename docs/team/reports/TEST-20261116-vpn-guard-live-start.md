# TEST-20261116-vpn-guard-live-start — живой старт WP-G6 (AC-8/12/15/17)

> **Тип:** TEST-отчёт (снимок живой приёмки, не полный 7-дневный WP-G6).
> **Дата:** 2026-11-16 ~20:52 MSK. **Хост:** ноутбук `dragonMi` (Ubuntu 24.04).
> **Код:** `ubuntuInstaller` `origin/main` = `b10553a` (WP-G5).
> **Установка:** `pipx install --force …/scripts/vpn-manager` → wheel с
> `vpnm.guard` + 7 JSON-схемами (AC-12).
> **Секреты:** в отчёте нет значений ключей/UUID/паролей; только счётчики,
> пути и служебные хэши.

## 1. AC-12 — selftest из установленного пакета

```
$ vpn guard selftest
[ok] schemas — 7/7 схем
[ok] parser — signals=['app_banner_ok', 'conn_reset']
[ok] rules — 12 правил, rules_hash=sha256:ca07731aa5add14afa9a2c7c2e8afb23f05e361d09255d492d399648f0385b7e
[ok] post-scanner — reference hits=[], block_hits=2
[ok] selftest пройден
exit=0
```

7 схем загружены из установленного wheel, а не из исходников — AC-12 закрыт
для текущего пакета.

## 2. AC-17 — install, профиль sandbox

Dry-run:

```
"unit_profile": "hardened",
"unit_path": "/home/asv-spb/.config/systemd/user/vpn-guard.service",
"hmac_key_exists": false,
"journal_group": false
[info] dry-run: ничего не изменено; повторите с --apply
```

`--apply`:

```
"apply": true,
"unit_profile": "hardened",
"hmac_key_created": true,
"fallback_reason": null,
"notify_delivery": "not_requested"
[ok] unit profile: hardened
```

Единица запущена и включена: `vpn-guard.service` — `active (running)`,
`enabled`, `Memory: 12.9M` (лимит 128M), `Tasks: 3`.
В юните: `ProtectSystem=strict`, `SystemCallFilter=@system-service`,
`RestrictAddressFamilies=AF_UNIX`, `NoNewPrivileges=yes`, `Nice=10`,
`MemoryMax=128M`, `CPUQuota=10%`, `UMask=0077`.
`226/NAMESPACE` не возник — fallback `compat` не потребовался.

## 3. AC-15 / AC-8 — источники и AWG-инвариант

```
$ vpn guard sources
[ok] journal:user
[ok] state
[ok] file
[off] verdict — server-verdict.json нет (vpn guard sync)
[ok] sysfs:awg — iface=laptop
[off] netlink — v1.1, opt-in
signals: amneziawg=counters, dns=blind, hysteria2=blind, systemd=ok, xray=blind
[info] app_signal=blind (нет app-событий за прогон)
```

```
$ vpn guard status
[info] vpn-guard.service: running, enabled, profile=hardened
[info] state=armed, awg iface=laptop
[info] counters: events=0, unparsed=0, dropped=0, findings=0, suppressed=0, redaction_hits=0
[info] notify-send: not_requested
[info] coverage: app_signal=blind (нет app-событий за прогон)
```

`state=armed` при живом AWG (`vpn-awg-split@laptop`, iface `laptop`) — AC-15.
Интерфейс найден discovery без хардкода `awg0`.

`vpn guard status --json` валидируется схемой: `schema.validate(...) == []`
(`guard.status/1`) — AC-8.

`vpn autostart status` не трогает guard: `enabled units: vpnm-clean-proxy.service`
(guard включён отдельно, `vpn-guard.service`); `vpn status` показывает только
профиль `asv2-reality`, guard не задевает.

## 4. Sync серверного вердикта (при живом VPN)

```
$ vpn guard sync --host root@asv2 --timeout 20
{
  "ok": true,
  "host": "root@asv2",
  "path": "/home/asv-spb/.local/share/vpn-manager/server-verdict.json",
  "note": null,
  "verdict": "RU-PROBE-SUSPECT",
  "threat_level": "elevated",
  "raw_sha256": "sha256:c9c3fd20…",
  "fresh": true,
  "age_s": 0,
  "lockdown": false
}
[ok] verdict=RU-PROBE-SUSPECT threat=elevated fresh=True
```

После sync: `vpn guard sources` → `[ok] verdict`; `server-verdict.json` записан
(0600). Сеть — один ssh-вызов списком аргументов, без `--record`.

## 5. Наблюдения / остаток WP-G6

1. **`vpn guard status` не показывает блок `server_verdict`** (только
   `sources` → `[ok] verdict`). Схема `guard.status/1` поля не содержит;
   sync при этом успешен. Зафиксировать как UX-кандидат v1.1 (не блокер).
2. `app_signal=blind` при простое — ожидаемо: app-события Xray/Hy2 пишутся
   при старте/соединениях, окно `--since=-2m` пустое. Проверить при активном
   трафике.
3. `journal_group=false` (пользователь не в `systemd-journal`): S2
   (`dnsmasq`, `vpnm-awg-split@*`) остаётся `blind`; для S2 включить группу
   или `sources.system_journal=true` после выдачи прав. Сейчас AWG виден
   через sysfs (AC-15 не зависит от S2).
4. `linger=false`: guard живёт в user-session; после logout останавливается.
   Для 7-дневного непрерывного наблюдения держать сессию/включить linger
   осознанно.
5. 7-дневное наблюдение стартовало **2026-11-16 20:52 MSK**; ежедневно
   снимать `vpn guard status --json`, `vpn guard findings`, память/CPU юнита.

## 6. Итог

AC-12, AC-15, AC-17 — PASS на живом ноутбуке; AC-8 — PASS по схеме.
WP-G6 (7 дней + AC-5 + kill -9 + wheel-selftest) продолжается.
