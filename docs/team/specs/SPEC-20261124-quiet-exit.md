# SPEC-20261124-quiet-exit — Профиль «тихий exit», DR-перенацеливание релея, vpn start = relay-only и DMS

> **Статус:** 🟡 draft (G2-ревью запущено 2026-11-24). Автор: архлид (Gemini).
> **Основание:** PROMPT-20261124-quiet-exit-spec (`e81e5a3`), DECISION Q1-PRI…Q6-PRI,
> SERVER-BASELINE §12–14 (`6abd4cb`), ADR-007/015/016, TECHDEBT P37/P38.
> **Репозитории:** my-first-vds (WP-QX-1/2/4), ubuntuInstaller (WP-QX-3). Секреты: 0.

## 0. Инварианты
IQ-1: 0 публичных TCP (0.0.0.0/0); 9443/tcp и 51900–51911/udp — allowlist RELAY_IP; 80/tcp ≤ 30 с в certbot-hook.
IQ-2: на RU-реле нет SSH-ключей exit / TG_BOT_TOKEN / SMTP_PASS (ADR-007).
IQ-3: публичный SSH закрывается только фазой 2 (`--close-public-ssh --apply`) после живого OOB-1 (ssh 10.9.0.1) + VNC.
IQ-4: dry-run по умолчанию + `--apply`.
IQ-5: asv2 read-only до закрытия инцидента; WP-QX-3 не деплоится до DR-приёмки ES-1 и ACCEPT-G6; 1 окно = 1 контур.
IQ-6: vpn-guard I-2 (0 сетевых сокетов) не трогается; DMS — отдельный серверный таймер.

## 1. Q-S6 Прекондишены ES-1 (Go/No-Go до оплаты; WP-QX-0)
PRE-1 KVM (systemd-detect-virt=kvm) — Blocker. PRE-2 ≥1vCPU/1GiB/20GiB (+swap для dkms) — Blocker.
PRE-3 репутация /24 (rDNS, CT) — Blocker. PRE-4 политика замен IP, без годового лока — Blocker.
PRE-5 нет обратной петли через РФ в трассе (rt.ru/ttk/msk-ix) — Blocker.
PRE-6 чистый путь с релея и ноутбука (ping ≤50 мс 0% loss, TCP/UDP доходят, tcpdump видит SYN/UDP) — Blocker.
PRE-7 VNC-консоль (Blocker) + IPv6 /64+ (Desired).

## 2. Q-S1 Сервер (my-first-vds): gateway init --profile quiet-exit
Флаги: `--profile quiet-exit` (+ fail-fast при --protocols с reality/hysteria2/xhttp/cdn/obfs/hop), `--relay-ip` (обязателен), `--relay-pubkey` (pending без него), `--ws-prefix-file <путь>` (APPROVED QX-Q1: файл-артефакт релея передаётся владельцем через доверенный ноутбук, tmp 0600 с удалением после init; без файла wstunnel-server → pending, повторный init дозавершает; содержимое не в stdout/логах/argv; константа /etc/vds/wstunnel-client.env — fallback, рабочий файл exit = /etc/vds/wstunnel-server.env), `--ws-domain` + `--acme-email`.
Состав: amneziawg (awg0 51825/udp 10.9.0.1/24 + admin-клиент oob-laptop) + relay exit-leg (awg2 10.11.0.1/30, пул 51900–51911 REDIRECT от RELAY_IP) + acme (ws.<domain> + 30-с hook) + wstunnel server (wg-ws0 10.12.0.1/30, 9443/tcp) + ufw harden quiet-exit + alert install + **vds dms install**. НЕ ставятся: xray, hysteria2, zerotier, coturn. state.protocols["quiet_exit"]={installed, relay_ips, oob_ssh_only} аддитивно.
UFW (src/system/ufw.py): ветка quiet-exit игнорирует _PROTOCOL_RULES["acme"]/xray/hysteria (закрывает баг авто-открытия 80/tcp); allow 51825/udp (--no-direct-awg опция); per relay_ip: allow 51900/udp + 9443/tcp; OOB-1: allow in on awg0 to 10.9.0.1 port <ssh>; Фаза 1 — публичный SSH limit остаётся (IQ-3, warning), Фаза 2 `--close-public-ssh --apply` (подтверждение = --apply, APPROVED QX-Q2; без интерактива) с 3 preflight: (1) fresh handshake oob-laptop ≤ 3 мин; (2) sshd listener; **(3) UFW-правило OOB-1 реально есть в snapshot** (raw `ufw status verbose` содержит in on awg0 / to 10.9.0.1 / port) — иначе реальный lockout через default deny. Любой провал → abort exit 1.
diff_listeners: 51900/udp, 9443/tcp, 51825/udp штатные; слушатели на 443/8443/2053 → ERROR «нарушение quiet-exit».
ACME: v1 = HTTP-01 с 30-с окном: renewal-hooks pre/open + post/close (маркер /run/vds-acme-80-opened, post-hook выполняется certbot всегда); первичная выдача — try/finally. DNS-01 — отдельный ADR позже.

## 3. Q-S2 Релей: DR-перенацеливание (Фаза 1, ≤ 15 мин; ранбук в DEPLOY-RU-RELAY §DR-Cutover)
T+00: бэкапы 0600 (awg1.conf, wg-ws0, wstunnel-client.env, relay-maneuver.json, p2p-carriers.json); stop maneuver/carrier таймеров; ES-1 принял RELAY_IP и ключи.
T+02: awg1.conf Endpoint/PublicKey/обфускация от ES-1:awg2 (атомарно, .bak-pre-dr) → restart vds-relay-exit **и vds-relay-policy** (table 100!) → очистка failed_ports.
T+05: DNS ws.<domain> → ES1_IP (TTL 60–300 заранее) → wstunnel-client.env + PublicKey wg-ws0 → restart wstunnel-client + wg-ws0.
T+08: валидация 6/6: fwmark/table 100; ping -I awg1 10.11.0.1 + ipify==ES1_IP; wstunnel switch + ipify==ES1_IP + возврат на awg; carrier status зелёный; maneuver.timer вернуть + tick --apply exit 0; клиент-тест: ноут+Android на релейных профилях 0 правок → ipify==ES1_IP.
Откат: восстановить .bak-pre-dr → restart exit+policy+wstunnel-client → вернуть таймеры → ipify==ASV2_IP. Критерий отката ≤ 5 мин — по awg-carrier; сходимость wstunnel после отката может занять до TTL DNS и провалом не считается.

## 4. Q-S3 Клиент (ubuntuInstaller): vpn start = relay-only
`vpn start` default scheme "awg"→"relay" (vpnm/cli.py:1256–1257, `def start(scheme=typer.Argument("awg"...)` — фактическое изменение дефолта).
Прямые ветки без `--allow-direct` → fail-closed exit 2 (сообщение про min-risk); с флагом: awg = OOB-резерв (WARNING), reality/xhttp = только если не archived.
`vpn reset` — без изменений. rank.py BASE_SCORES: сегодня direct+awg=90, direct+reality=88, direct+hy2=85, relay+awg=82, xhttp=75, cdn=65 → ЦЕЛЕВЫЕ: relay+awg=92 > relay+reality=86 > direct+awg=80 > direct-reality=60 > hy2/xhttp=55 > cdn=50; archived — вне кандидатов. Правку делает ТОЛЬКО WP-QX-3 (guard v1.1 не трогает rank.py); docstring rank.py (таблица verbatim) синхронизировать.
Оператор после cutover: vpn sync (STALE) → vpn profile archive <name> --reason "min-risk-cutover" --apply.
**Очередь: WP-QX-3 ПОСЛЕ живого ES-1 + ACCEPT-G6, ДО guard v1.1** (можно в одном деплойном окне с клиентским бандлом).

## 5. Q-S4 P37 Dead-man-switch с первого дня
Оба узла шлют исходящий HTTPS GET (stdlib urllib) на уникальный URL Healthchecks (настроен владельцем → TG при просрочке). 0 входящих портов; на реле только DMS_PING_URL (0600). Gate: ping только при живых ногах (exit: awg0+awg2+wstunnel-server; relay: awg0 UP + table 100 + data-plane активного носителя), при сбое — /fail мгновенно. Тайминги: таймер 5m + RandomizedDelaySec=20s; Healthchecks period 5m grace 10m → алерт 10–15 мин, /fail ≤ 5 мин. Секрет: /etc/vds/dms.env 0600, маска как src/alert/env.py. Временный чек asv2:443 — отдельная диагностика инцидента, выключить после §6.

## 6. Q-S5 DR-протокол (evidence для ADR-017 Фазы 2)
Артефакт TEST-YYYYMMDD-dr-es1-cutover.md (без секретов/реальных IP). Этапы: 0 baseline ipify + бэкапы; 1 nmap ES-1 = 0 open + OOB-1 + DMS UP; 2 cutover ≤ 15 мин; 3 оба носителя ipify==ES1_IP + carrier зелёный; 4 клиентская приёмка 0 правок + bulk ≥ 5 МБ; 5 откат ≤ 5 мин (или документированный план возврата); 6 синтетика P37 → TG ≤ 15 мин. 6/6 PASS = входной гейт ADR-017/P38 Фазы 2.

## 7. WP-QX-1…4
WP-QX-0 (владелец): PRE-1…7 до оплаты. WP-QX-1 (vds, код пишется заранее, ∥): init-профиль + ufw + ACME-hook + тесты; AC: build_plan("quiet-exit") не открывает 80/443/8443/2053; --close-public-ssh падает без awg0 UP. WP-QX-4 (vds, ∥): src/dms/ + vds dms install/remove/test/status/ping + юниты; AC: URL не утекает, /fail при мёртвой ноге (мок urllib). WP-QX-2 (deploy): DR-Cutover раздел DEPLOY-RU-RELAY + живая репетиция (после QX-0/1/4). WP-QX-3 (ubuntuInstaller): после WP-QX-2 PASS; деплой строго после ACCEPT-G6 + P35.
Doc delta: README, AGENTS, DEPLOY, DEPLOY-RU-RELAY, SERVER-BASELINE, doc-sync.json (новый пакет src/dms), TECHDEBT P37-статус; ubuntuInstaller: doc/vpn-manager.md, SPEC-v1.1 §2.5, D-23.

## 8. Не проверено
Живые имена юнитов wstunnel на реле; тесты test_cli*/test_rank (старый дефолт awg, direct+awg=90); живые параметры ES-1 (WP-QX-0).

## 9. Находки сверки с кодом (новые дефекты)
- vpnm/cli.py:1224 — фактический дефолт vpn start = "awg" (direct).
- src/system/ufw.py:361 — _PROTOCOL_RULES["acme"]=("tcp","80"): профиль gateway **авто-открывает 80/tcp в мир** при установленном ACME. → TECHDEBT P39.


## 10. G2-правки (вердикт APPROVE-with-notes, 2026-11-24; обязательны кодеру)

### P0-1. Карта файлов WP-QX-1/4 (без неё WP не выдаётся)
- `src/system/ufw.py`: `"quiet-exit"` в `build_plan()` (валидация ~:446) + ветка в `profile_service_specs()` (~:365), игнорирующая `_PROTOCOL_RULES` (кроме amneziawg) + per-relay_ip allowlist; подавление `_PROTOCOL_RULES["acme"]` = закрытие P39.
- `src/gateway/init.py`: механизм профиля (сейчас профиля нет — только parse_protocols; параметр `profile` в build_plan/run_init).
- `src/acme/install.py` (или `src/acme/window_hook.py`): pre/post-hook + try/finally первичной выдачи.
- `src/dms/` (paths.py, env.py, gate.py, cli.py — по образцу src/alert/) + `systemd/vds-dms-*.{service,timer}.tpl`.
- Тесты: tests/system/test_ufw_quiet_exit.py, tests/gateway/test_init_quiet_exit.py, tests/dms/.

### P0-2. Состав наблюдения на quiet-exit + nft-совместимость
Не ставятся также: vds-gateway-health.timer, probe-watch/probe-rucidr, logs-детекторы на {443,8443,2053}; путь lock-443 на quiet-exit инертен (нет TCP-портов). UFW-план обязан учитывать существующие nft-таблицы vds_relay / vds_relay_wstun (ADR-016 I-2a) — без конфликтов.

### P1-3. Preflight --close-public-ssh: fresh handshake
Серверное доказательство живого OOB-1: `awg show awg0` latest-handshake пира oob-laptop ≤ 3 мин; без него exit 1. VNC-путь (OOB-2) указывается в плане до apply. AC WP-QX-1 дополнить.

### P1-4. Pending --relay-pubkey
exit-leg и wstunnel-server defer'ятся; UFW allowlist и awg0 ставятся сразу; повторный `init --profile quiet-exit --relay-pubkey … --apply` дозавершает (skip-логика по state, конвенция №7). В state: pending-шаги помечены.

### P1-5. ACME fail-safe
Post-hook может упасть → 80/tcp останется открытым навсегда. AC: падение post-hook → правило закрывается при следующем периодическом чеке (WARN/алерт: 80/tcp должен быть закрыт вне окна); маркер /run/vds-acme-80-opened идемпотентен в pre и post; порядок зафиксирован: UFW-окно открывается ДО вызова certbot (standalone биндит 80 сам), закрытие в finally.

### P1-6. IPv6
UFW IPV6=yes сохраняется; default deny действует на v6; allowlist — v4-only (RELAY_IP = A-запись). IPv6-OOB (PRE-7) — отдельное явное правило, вне скоупа этого цикла.

### P1-7. --no-direct-awg
Закрывает 51825/udp → OOB-1 умирает, единственный fallback — VNC. Preflight требует `--yes-i-have-vnc`, иначе abort. До P30/IPv6-OOB флаг не рекомендован.

### P1-8. Смена RELAY_IP (P30)
= правка state.protocols["quiet_exit"].relay_ips (аддитивно, FileLock) + re-harden `--profile quiet-exit --apply`; старое allowlist-правило удаляется. DMS-гат ловит период мёртвой ноги (/fail).

### P2 (принято)
cli.py: строка дефолта 1256–1257 (исправлено выше); BASE_SCORES «сегодня→целевое» (исправлено выше); откат ≤5 мин по awg-carrier (исправлено выше); DMS_PING_URL на реле = осознанный трейд-офф (утечка деградирует мониторинг релея, exit не затронут); FileLock на все мутации state; `--close-public-ssh` = деструктивная → явное подтверждение; DMS-юнит sandbox: RestrictAddressFamilies ВКЛЮЧАЕТ AF_INET (исходящий HTTPS — в отличие от alert-watch), env 0600, маска URL в status --json, шаблоны в systemd/; preflight WP-QX-2 сверяет живые имена юнитов на реле.
