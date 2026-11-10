# TEST-20261110-amneziawg-cdn — финальная верификация циклов AWG + CDN

## Мета
- **Автор:** vds-tester · **Дата:** 2026-11-10
- **Объект:** циклы AmneziaWG (WP-1..5 + P14/P15) и CDN (WP-1..3 + фикс-пасс G4)
- **Базис:** HEAD `5a5307a` + живой asv1 (read-only)

## Вердикты

| Цикл | Вердикт | Примечание |
|---|---|---|
| **A — AmneziaWG** | **PASS** | A-1 (MASQUERADE не персистентен) закрыт ops-ом на asv1 + A-2 (install не восстанавливал юнит) — кодом, 404 passed |
| **B — CDN** | **FAIL → исправлено** | B-1 (blocker: add-cdn удалял XHTTP-инблэнд 8443) — закрыт кодом с регресс-тестом на Reality+XHTTP-фикстуре; B-2 (нет remove-cdn-client) — добавлен; B-3/B-4 minor — закрыты |

## Ключевые находки и закрытия

| ID | Цикл | Серьёзность | Суть | Статус |
|---|---|---|---|---|
| B-1 | CDN | **blocker** | add-cdn молча удалял XHTTP-инблэнд 8443; тест-фикстура без xhttp не ловила | ✅ `_xhttp_fields()` переносит XHTTP-часть из текущего конфига; регресс `TestXhttpPreserved` |
| B-2 | CDN | major | отсутствовал `remove-cdn-client` | ✅ dry-run/apply + CLI |
| A-1 | AWG | major | повторный install не дотягивал P15-маршрутизацию (early-return) | ✅ idempotent-ветка вызывает `_setup_routing()`; on asv1 persist ops-ом |
| A-2 | AWG | minor | `_installed()` не проверял юнит | ✅ требует unit active |
| B-3 | CDN | minor | идемпотентность игнорировала смену порта | ✅ домен+порт+path |
| B-4 | CDN | minor | чтение config.json вне FileLock | ✅ под локом |

## Живой asv1 (read-only проверки)
- `vds-amneziawg` active, UDP 51825, ExecStop = новый tpl (P14), awg0.conf 0600
- peer `laptop` в state+links (conf 0600)
- e2e (вне G4, оркестратор): handshake ✅ + youtube через AWG-туннель 204/200 ✅
- «Не ломать»: Reality 443 + XHTTP 8443 + Hysteria2 443/udp не изменились

## База
`python -m compileall -q src` exit 0 · `pytest -q` **404 passed** · shell=True/секреты-детекторы — чисто

## Остаток до закрытия циклов
1. **AWG WP-6 гейт**: импорт `laptop.conf` в AmneziaVPN владельцем
2. **CDN**: владелец-шаги переноса зоны в CF (SPEC §7.1) → `vds acme issue --domain cdn.…` → `vds xray add-cdn --domain cdn.… --yes` → e2e через CF
