# MIGRATE-VDS — переезд сервера VDS Orchestrator на нового провайдера

> Чеклист миграции asv1-стиль-сервера (Xray Reality/XHTTP/CDN + Hysteria2 +
> AmneziaWG + ACME) со старого хостера на новый **без простоя** и **без
> перенастройки клиентов** (телефоны/ноутбук продолжают работать на тех же
> uuid/ключах). Версия: 2026-11.

## Быстрая навигация

- [Что привязано к серверу](#что-привязано-к-серверу)
- [Автоматический перенос](#автоматический-перенос-скрипт)
- [Чеклист миграции](#чеклист-миграции)
- [Ручной перенос состояния](#ручной-перенос-состояния)
- [Настройки ОС/сервера (вручную)](SERVER-BASELINE.md)
- [Откат](#откат)

## Что привязано к серверу

| компонент | привязка | миграция |
|---|---|---|
| CF DNS: домен → A | жёстко IP | правка записи в CF (TTL заранее 300) |
| LE-сертификаты | домен (HTTP-01) | переиздание на новом (`vds acme issue`) |
| **gateway/state.json** | uuid/ключи всех клиентов и протоколов | **обязательный перенос** — иначе перенастройка всех клиентов |
| /etc/hysteria2-секреты, /etc/amnezia server-key | приватный материал | перенос вместе с state.json (0600) |
| share-линки клиентов | домен в ссылке | если перенесён state.json — ссылки не меняются |
| AWG Endpoint в клиентских .conf | IP:порт | одна строка в клиентских конфигах |
| ноутбук: `vpn profile pull -H` | ssh-хост | `vpn profile pull -H root@<новый>` |
| ноутбук: Makefile deploy | IP | одна строка в Makefile |
| TSPU-блокировки старого IP | IP резидентского провайдера | бонус: новый IP обычно чистый |

## Автоматический перенос (скрипт)

`ubuntuInstaller/scripts/20_vds-migrate.sh` (запуск на локальной машине):

```bash
# 1) план (ничего не меняет, показывает что и куда):
bash ubuntuInstaller/scripts/20_vds-migrate.sh root@старый root@новый

# 2) перенос (state.json + секреты + сертификаты старый → новый, через локальный tmp):
bash ubuntuInstaller/scripts/20_vds-migrate.sh root@старый root@новый --apply
```

Скрипт: собирает на старом тарбол **только state и секреты** (gateway/state.json,
/etc/letsencrypt, /etc/hysteria, /etc/amnezia; код репозитория НЕ переносится —
он ставится `11_vds-deploy.sh`), гонит через локальный tmp (0600), разворачивает
на новом поверх свежего деплоя. Код репо переносится обычным
`11_vds-deploy.sh` (запустить ДО migrate).

## Чеклист миграции

1. **Подготовка (на старом сервере, пока жив):**
   - [ ] TTL DNS-записей домена → 300 сек (заранее, за сутки)
   - [ ]Backup снят скриптом (или вручную — см. ниже); хэш записан
2. **Новый сервер:**
   - [ ] `bash ubuntuInstaller/scripts/11_vds-deploy.sh` (one-shot: ключ → rsync
         кода → install.sh → xray+hysteria2 → домен/acme → демо-клиенты)
   - [ ] `20_vds-migrate.sh … --apply` — state.json/секреты/сертификаты
   - [ ] `systemctl status vds-xray vds-hysteria2` — active; `vds xray status`
         показывает прежних клиентов
   - [ ] `vds acme issue --domain asvpersonal.ru` (если сертификат не перенёсся
         валидным / DNS уже смотрит на новый IP)
3. **DNS (Cloudflare):**
   - [ ] A-запись домена → новый IP (оранжевое облако не менять: для CDN —
         оставить proxied, для direct — DNS-only)
   - [ ] `dig +short <домен>` → новый IP
4. **Ноутбук (vpn-manager):**
   - [ ] `vpn profile pull -H root@<новый>` (обновит ssh-host в settings)
   - [ ] AWG-конфиг: `Endpoint = <новый IP>:51825` (одна строка)
   - [ ] `vpn probe` → все профили ok; `vpn start` (split) → youtube 204
5. **Прочие устройства** (телефон и пр.): ничего, если state.json перенесён
   (uuid те же, домен тот же); иначе — переимпорт share-ссылок
6. **Старый сервер:** погасить через 1–2 дня (TTL, кэши резолверов), потом
   уничтожить у хостера

## Ручной перенос состояния

Равноценен `--apply`, для понимания что именно делает скрипт:

```bash
# на СТАРОМ:
tar czf /tmp/vds-state.tgz -C / \
    opt/my-vds/gateway/state.json etc/letsencrypt etc/hysteria etc/amnezia
scp root@старый:/tmp/vds-state.tgz /tmp/   # через локальный tmp, не сервер-сервер
# на НОВОМ:
tar xzf /tmp/vds-state.tgz -C /
chown -R root:root /opt/my-vds/gateway/state.json && chmod 0600 /opt/my-vds/gateway/state.json
systemctl restart vds-xray vds-hysteria2
```

⚠️ `state.json` — 0600, содержит все клиентские ключи; в логи/чаты не выкладывать,
тарбол после переноса удалить с обеих сторон.

## Откат

- DNS-запись обратно на старый IP → трафик вернётся на старый сервер
  (он всё это время работал — миграция не трогает старый сервер вообще,
  только читает)
- Клиенты на ноутбуке: `vpn profile pull -H root@старый` + вернуть AWG Endpoint
