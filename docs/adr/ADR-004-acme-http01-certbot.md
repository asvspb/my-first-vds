# ADR-004: ACME для Hysteria2 — HTTP-01 + certbot

- **Дата:** 2026-11-09
- **Статус:** accepted
- **Контекст SPEC:** [SPEC-20261109-domain-xhttp-acme](../team/specs/SPEC-20261109-domain-xhttp-acme.md)

## Контекст

Hysteria2 (UDP 443) работает с self-signed сертификатом; клиентские ссылки
несут `insecure=1`. Есть домен `103-45-247-172.eu-cloud-xip.com` → 103.45.247.172
(проверено владельцем). Порт 80 свободен (Xray — TCP 443, Hysteria2 — UDP 443).
Нужны: выдача LE-сертификата, устойчивое автоматическое продление, замена
сертификата без поломки существующего клиента `mob` (insecure=1 валидацию не
проверяет — подмена безопасна). Ограничение: RKN-DPI режет загрузку release с
github.com → всё, что качается, должно уважать `VDS_GITHUB_MIRROR` (ADR-001).

## Рассмотренные варианты

**Challenge:**

| Вариант | Плюсы | Минусы |
|---|---|---|
| HTTP-01 (порт 80, standalone) | порт 80 свободен и *по архитектуре* остаётся свободным: в нашем стеке на 80 ничего не ставится; не зависит от DNS-провайдера | если 80 однажды займут — E2: читаемый отказ, ничего не ломается |
| DNS-01 | не зависит от портов | нужен API-токен DNS-провайдера — владелец его не предоставил; хранение ещё одного секрета |
| TLS-ALPN-01 | без порта 80 | порт 443 занят Reality — не подходит |

**ACME-клиент:**

| Вариант | Плюсы | Минусы |
|---|---|---|
| certbot (apt, Ubuntu 24.04) | ставится из apt — **никакого github.com**, mirror не нужен вообще; systemd-таймер `certbot.timer` из коробки; renew-hooks (deploy) штатно; широкая документация | python-зависимости (~десятки МБ) — приемлемо для root-сервера |
| acme.sh | лёгкий, один shell-скрипт | установка — curl с github.com raw → упирается в DPI, нужен mirror и отдельный таймер своими руками |
| lego | одиночный статический бинарник | релизы с github.com → mirror-зависимость (ADR-001); свой таймер/хуки |

## Решение

**HTTP-01 (standalone) + certbot из apt.**

- Установка: `apt-get install -y certbot` (до изменений проверяем порт 80
  свободен; иначе читаемый отказ, E2).
- Выдача: `certbot certonly --standalone -d <domain> --non-interactive
  --agree-tos -m <email-оператора> --keep-until-expiring` — идемпотентно
  (`--keep-until-expiring` не перегенерирует валидный сертификат).
- Продление: штатный `certbot.timer` (2×/сутки); наш deploy-hook
  `/etc/letsencrypt/renewal-hooks/deploy/vds-hysteria2-cert.sh` срабатывает
  **только при фактическом продлении**: бэкап текущих
  `/etc/hysteria/{cert,key}.pem` → копия `live/<domain>/fullchain.pem,privkey.pem`
  в `/etc/hysteria/` с правами 0600 → `systemctl restart vds-hysteria2`.
  Hysteria2 в этот момент продолжает держать UDP 443, порт 80 не участвует в
  работе сервиса — конфликта с renew нет; standalone-certbot занимает 80
  лишь на секунды валидации.
- Устойчивость: продление не требует остановки Xray (TCP) — 80 свободен
  всегда; провал продления не убивает сервис (E3: старый сертификат
  продолжает работать, `status` показывает остаток дней).
- Валидация домена до выдачи: DNS A-запись → IP сервера (переиспользуем
  `core/netcheck`-примитив), отказ ДО изменений.

## Последствия

- Положительные: нулевая github-зависимость (сильнее, чем требование mirror);
  авторотация «из коробки»; одна точка интеграции — deploy-hook.
- Отрицательные / долг: certbot тянет python-стек; email для LE-аккаунта —
  параметр команды (не секрет, но не пишем в state.json без нужды).
- Трудно изменить позже: пути `/etc/letsencrypt/live/<domain>/` и хук —
  локализованы в `src/acme/` + `gateway/paths.py`.

## Как откатить

1. Удалить хук и юнит-зависимости: `rm /etc/letsencrypt/renewal-hooks/deploy/vds-hysteria2-cert.sh`.
2. Восстановить self-signed: бэкап, снятый перед подменой
   (`/etc/hysteria/cert.pem.bak-pre-le`, `key.pem.bak-pre-le`, 0600) →
   `vds hysteria2 apply-cert --restore` (команда из SPEC WP-2) → рестарт.
3. `certbot delete --cert-name <domain>` + `apt-get remove certbot` (опц.).
4. Клиент `mob` (старая ссылка insecure=1) работает в обоих состояниях.
