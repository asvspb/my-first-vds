# TEST-20261117-ru-relay-gate — Фаза 0: leg smoke-test LandVPS → asv2

> **Тип:** TEST-отчёт (снимок gate-приёмки ADR-007 §0.3).
> **Дата:** 2026-11-17. **Провайдер/VM:** LandVPS `vm354051`,
> `185.80.91.135`, AS216334 (Москва), IPv6 `2a12:b3c0:1:198::/48`.
> **ОС:** Ubuntu 22.04.5 LTS (⚠️ ADR-007 требует 24.04 — см. §4).
> **Ресурсы:** 1 vCPU, 823 МБ RAM + **1 ГБ swap** (создан до dkms), 20 ГБ SSD.
> **Секреты:** root/panel-пароли и ключи в отчёт не попадают.

## 1. Gate (ADR-007 §0.3)

На asv2 создан временный AWG-пир `relay-smoke` (10.9.0.5/32), конфиг
перенесён на релей; на релее поставлены `amneziawg-dkms` + `amneziawg-tools`
(PPA, kernel 5.15.0-177, `/lib/modules/.../updates/dkms/amneziawg.ko`).

Для безопасности в smoke-конфиг добавлен **`Table = off`** (иначе `awg-quick`
перехватывает default-route и рвёт SSH к релею — проверено, восстановление
через asv2 → `10.9.0.5`).

```
awg show:
  interface: awg1-smoke
  endpoint: 213.108.23.119:51825

curl --interface awg1-smoke https://api.ipify.org  → 213.108.23.119
curl --interface awg1-smoke https://www.google.com → HTTP 200, 0.341 s
default route до/после: via 185.80.91.1 dev ens3 (не менялся)
```

**Вердикт: PASS.** Аплинк LandVPS/AS216334 не режет UDP AmneziaWG до asv2;
handshake и данные идут, задержка приемлемая. Anti-DDoS хоста не блокирует
кастомный UDP :51825.

Cleanup: пир `relay-smoke` удалён на asv2, `/tmp/awg1-smoke.conf` удалён,
`awg1-smoke` down; swap оставлен (нужен для dkms/сборки).

## 2. Отклонения от ADR-007

1. **ОС 22.04 вместо 24.04.** Gate прошёл, но ADR/SPEC и `SERVER-BASELINE`
   ориентированы на 24.04 (systemd 255, ssh socket generator, свежий Python).
   Решение: перед полным `vds relay init` переустановить шаблон на **Ubuntu
   24.04 LTS** (сеть/DC уже проверены), либо явно принять 22.04 как
   отклонение (риск: systemd/ssh-поведение и дрейф пакетов).
2. **RAM 0.75 ГБ.** dkms собирается только со swap (1 ГБ создан). Для
   рантайма 130–180 МБ хватает, но запас тонкий; 1 ГБ/20 ГБ (RU-1) — лучше.
3. **Домен.** Выдан `354051.landvps.online` — **не .ru**. Для whitelist-сценария
   нужен `relay.asvpersonal.ru` (A → 185.80.91.135, DNS-only) по ADR-007 R1.
   LandVPS-домен годится только для функционального теста, не для whitelist.
4. **IPv6:** панель заявляет /64, фактически на интерфейсе `/48`
   (`2a12:b3c0:1:198::/48`) — для будущей v6-ноги достаточно.

## 3. Что дальше (до `vds relay init`)

1. Решение владельца: **переустановка на Ubuntu 24.04** или принятие 22.04.
2. DNS: `relay.asvpersonal.ru A 185.80.91.135` (DNS-only, без CF-прокси).
3. `RU_SNI`: RU-сайт TLS 1.3+H2 (same-ASN/DC предпочтительно; допустим `ya.ru`).
4. Команда (dry-run → apply):
   `vds relay init --exit 213.108.23.119 --domain relay.asvpersonal.ru --sni <RU_SNI>`
   затем `vds relay init ... --apply` и приёмка по DEPLOY-RU-RELAY §1–10.
5. После настройки сменить root/panel-пароли (засветились в переписке).

## 4. Трассируемость

| Что | Ссылка/коммит |
|---|---|
| Gate-процедура | [DEPLOY-RU-RELAY §0.3](../../DEPLOY-RU-RELAY.md) |
| ADR | [ADR-007](../../adr/ADR-007-ru-relay.md) |
| Код релея | WP-1..5, `vds relay init` |
