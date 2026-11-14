# TEST-20261114-fresh-install-v3 — приёмка `vds gateway init`

> Тестер/архитектор: `vds-architect`. Дата: 2026-11-14.
> SPEC: [SPEC-20261114-fresh-install-v3](../specs/SPEC-20261114-fresh-install-v3.md).
> Код: vds `a42b565`, `43faf4c`, `2dc9451`, `02ed731`;
> ubuntuInstaller `7f2bb73`, `40b151a`.

## 1. Итог

| WP | Вердикт |
|---|---|
| WP-1 (план/preflight/executor) | **PASS** после фикса (гейт `--protocols`, идемпотентность) |
| WP-2 (CLI `gateway init`) | **PASS** |
| WP-3 (deploy + docs) | **PASS** после фикса (префикс `vds`) |

Общий: **принято на уровне кода/unit/live dry-run**. Полная приёмка на
**чистой VM** (AC-1, AC-3, AC-4) не выполнялась — нужен новый сервер/VM;
перенесено в приёмку владельца.

## 2. Найдено на ревью (до фикса)

1. **`11_vds-deploy.sh` без префикса `vds`** — `ssh "$REMOTE" "gateway init …"`
   дал бы `command not found`. Исправлено: `INIT_ARGS/LINKS_ARGS` начинаются
   с `vds`, текст доката тоже.
2. **`build_plan` игнорировал `--protocols` для базовых шагов** — при
   `--protocols awg` план ставил Reality+Hy2. Исправлено: reality/hysteria2
   добавляются только при наличии в CSV; acme — только при доменном
   транспорте; hy2-cert — только для Hy2; xray-domain — только для Reality.
3. **Повторный init делал мутации** (AC-2): acme/hy2-cert/xray-domain/
   healthcheck выполнялись каждый раз. Добавлены skip-условия:
   `state.protocols['acme']` + домен + сертификат; `cert_domain == domain`;
   `state.domain == domain`; таймер активен/enabled.
4. `VDS_USER` не читался из env — реализован; `--demo-clients` передаётся
   только если в `VDS_PROTOCOLS` есть и reality, и hysteria2.

## 3. Проверки после фикса

| Проверка | Результат |
|---|---|
| `pytest -q` (vds) | **581 passed** |
| `pytest -q` (vpnm, регресс) | **349 passed** |
| `python -m compileall -q src` | ok |
| `bash -n scripts/11_vds-deploy.sh` | ok |
| `vds gateway init --help` | все флаги SPEC на месте |
| План `--protocols awg` (temp state) | ровно `awg`, `healthcheck` — без reality/hy2/acme |
| План `reality+cdn --domain` | `reality, acme, xray-domain, cdn, healthcheck`; без hy2-cert |
| Deploy-команда (симуляция) | `vds gateway init --apply --protocols reality\,hysteria2 …` |
| **Live dry-run на asv1** (полный набор + домен) | **все шаги SKIP**, «мутаций не выполнено»; ни одного RUN |
| Секреты в выводе | не печатаются (тест `test_no_secrets_in_output`) |

Live dry-run (asv1) подтвердил: Reality, Hy2, ACME, XHTTP, CDN, obfs, hop,
AWG и healthcheck-таймер распознаны как установленные; повторный init
ничего не меняет.

## 4. Что осталось (приёмка владельца на чистой VM/VDS)

1. `vds gateway init --apply --domain … --email … --protocols
   reality,hysteria2,obfs,hop,xhttp,cdn,awg` → все юниты active, порты
   443/8443/2053/51825/51826 (+hop) слушаются.
2. Повторный тот же вызов → «изменений не требуется», exit 0.
3. Без домена → acme/cdn skip с warning, reality/hy2/awg работают.
4. Занятый порт (`python -m http.server 8443`) → fail до мутаций.
5. `VDS_PROTOCOLS` не задан → deploy даёт прежний результат (Reality+Hy2).

Пункты 1–4 требуют чистого сервера; на asv1 всё уже установлено, поэтому
проверен только dry-run/skip-путь.

## 5. Примечания

- `gateway init` печатает существующие share-links в summary — это продукт
  команды, но в CI/логах учитывать (секреты клиентов). При необходимости
  скрыть за `--demo-clients` (OQ-4).
- `xray-domain` rollback в `_ROLLBACK` — «не поддерживается, правьте state»;
  для init это не деструктивный шаг, но стоит добавить `xray use-domain
  --clear` в будущем.
- `docs/research/youtube-ideas-2026-11.md` в vds — правка владельца, не
  входит в этот цикл.
