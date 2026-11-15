# ADR-011: UFW hardening — отдельный модуль `src/system/ufw.py` с профилями, двухфазный ssh-перенос, ICMP без изменений

- **Дата:** 2026-11-16
- **Статус:** accepted (G2 — владелец/оркестратор, 2026-11-16)
- **Контекст SPEC:** [SPEC-20261116-ufw-hardening](../team/specs/SPEC-20261116-ufw-hardening.md) (WP-1)
- **Связанные:** ADR-007 (relay), ADR-008 (UFW-правило hop-диапазона), SERVER-BASELINE §5/§10

## Контекст

VPN-серверы проекта живут без файрвола: на asv1/снимке 2026-11-14 UFW
**inactive**, легаси-список портов в `server-setup` устарел. Порты сервисов
открывались точечно и по-разному: relay init (`ufw allow 443/udp`),
amneziawg install (`allow <port>/udp` + MASQUERADE в before.rules),
hysteria2 hop (`allow <range>/udp`, ADR-008), amneziawg remove (`ufw delete`).
Централизованного, идемпотентного способа «дотянуть» политику UFW до
целевого состояния нет. Осложнения: Docker обходит UFW (nat PREROUTING/DOCKER
раньше ufw-before-input; на проекте Docker только ZTNET, выключен);
probe-watch держит свою nft-таблицу `inet vds_probe` с hook priority −140;
ssh-перенос нестандартного порта на Ubuntu 24.04 имеет два источника Port
(ssh.service и socket-activation), и любой одноблочный перенос рискует
отрезать ssh-доступ.

## Рассмотренные варианты

| Вариант | Плюсы | Минусы |
|---|---|---|
| **Отдельный `src/system/ufw.py` + команда `vds system ufw harden` с профилями (выбран)** | принятые циклы gateway/relay init не ломаются; план выводится из state.protocols (открывается только то, что установлено); детекция существующих правил — идемпотентность; dry-run/--apply/--undo по конвенциям; изоляция от легаси `server-setup` с его `ufw --force reset` | ещё одна точка правды о портах — лечится тем, что источник = state.protocols + парсер ufw status, а не жёсткий список |
| Встроить в `gateway init` / `relay init` | один вход при развёртывании | ломает принятые циклы (SPEC-20261114-*), перемешивает ответственность «установить сервис» и «закрыть файрвол»; релей может жить без harden-профилей |
| Скрипт-ранбук (только документация) | нулевой код | нет идемпотентности/детекции/undo; повторяется в каждом деплое руками; ошибки порядка операций (enable до ssh-правила) не машинно-проверяемы |

## Решение

1. **Модуль и CLI:** `src/system/ufw.py` + `vds system ufw harden
   --profile gateway|relay|exit-cascade [--allow-from IP] [--apply] [--undo]`;
   конвенции: dry-run по умолчанию, FileLock, `run_list` (LC_ALL=C), без
   `ufw reset`, без правки чужих ufw-конфигов кроме описанного.
2. **Профили:** `gateway` (443 tcp+udp, AWG 51825, obfs/hop/xhttp/cdn/acme по
   state), `relay` (детекция уже открытых relay init, не дублировать),
   `exit-cascade` (443 только `allow from <relay-ip>`; требует `--allow-from`).
   Панели/метрики наружу не открываются нигде (ssh-туннель).
3. **Fail-safe порядок:** defaults → ssh-правило первым → сервисные порты →
   forwarding (`DEFAULT_FORWARD_POLICY=ACCEPT`, ip_forward только проверкой —
   persist уже в sysctl.d) → `ufw --force enable` строго последним. Unit-тест
   фиксирует «ssh-индекс < enable-индекс».
4. **Двухфазный ssh-перенос:** `vds system ufw ssh-port --to 49222 --apply`
   (limit 49222 → sshd_config.d/99-vds-port.conf → `sshd -t` → ssh.socket
   drop-in с пустым `ListenStream=` при socket-activation → ss-чек →
   pending-маркер и **остановка**) и `ssh-port --finalize` (удаление правил
   22 только после подтверждения входа владельцем со второго терминала).
   CLI не имеет права закрыть 22 в той же операции, что перенос.
5. **ICMP — без изменений** («Правило знаний: ICMP и диагностика маршрута,
   решено владельцем 2026-11-16», verbatim-текст в SERVER-BASELINE §5):
   echo-request не дропаем (ТСПУ находит пассивным DPI исходящего, не пингом;
   echo-request — главный диагностический инструмент; Reality-сервер,
   дропающий ICMP при живом TLS на 443, — аномалия для эвристик);
   destination-unreachable / time-exceeded / parameter-problem / icmp type 3
   code 4 (PMTU) — никогда не блокировать.
6. **Совместимость:** ufw (iptables-nft) и `inet vds_probe` — независимые
   nft-таблицы, перетереть друг друга не могут; MASQUERADE-persist для awg0
   уже в before.rules — harden не дублирует; юниты vds-amneziawg-nat /
   vds-relay-nat идемпотентны и не зависят от ufw.
7. **Откат:** `--undo` по журналу применённых правил в
   `state.protocols["ufw"]` (+ `ufw disable`, если UFW был inactive до
   harden); ручной чеклист — SERVER-BASELINE §5.

## Последствия

- **Позитив:** единый идемпотентный вход хардненинга для свежих (asv2) и
  живых (asv1, релей) серверов; порты выводятся из фактического state, а не
  из устаревших списков; ssh-риск переноса сведён к ручной двухфазности;
  ICMP-политика зафиксирована документально и не реимплементится по незнанию.
- **Негатив/цена:** вторая точка правды о портах (mitigated: source =
  state.protocols + парсер ufw status); парсер текстового вывода ufw
  чувствителен к локали (mitigated: LC_ALL=C + warning на нераспознанные
  строки); легаси `server-setup` с `ufw --force reset` остаётся
  несовместимым по духу — после него harden просто дотягивает повторным
  запуском, полный вывод setup.py из эксплуатации — отдельный REQ.
- Docker-обход UFW не устраняется (ZTNET выключен; правило знаний + listeners-
  warning в плане; doctor-интеграция — отдельный WP по OQ-3).
