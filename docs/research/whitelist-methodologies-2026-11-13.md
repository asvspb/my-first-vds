# Digest: методики построения whitelist-bypass на 2026-11

> Проход 2026-11-13, vds-youtube-scout, пассивно. Внешние тезисы `[медиа]`/`[репо]`.
> Вердикт — рекомендация владельцу. Дополнение к И1–И21 копилки (новые идеи И22–И27).

## 1. Источники

| # | источник | тип | дата |
|---|---|---|---|
| S1 | github.com/kulikov0/whitelist-bypass (1.8k★, 191 commit, MIT) | фреймворк медиа-транспорта | активен 2026-11 |
| S2 | github.com/meid1/white-ip-relay (+ kand.guru «маркетплейс белых IP») | relay-агент + рынок | скелет |
| S3 | net4people/bbs#650 | исследования, SIM-замеры | 2026-08-19…11-02 |
| S4 | habr.com/ru/articles/1027276 + github.com/openlibrecommunity/twl | замеры (masscan 80 600 подсетей Мегафона) | 2026-04-25 |
| S5 | habr.com/ru/articles/1021160 + Sergei-thinker/vpn-setup | 4-слойная архитектура (гайд+репо, 3X-UI) | 2026-04-09 |
| S6 | habr.com/ru/articles/1047442 | behavioral-слой ТСПУ («заморозка», dpi-ch/Zapret) | 2026-06-15 |
| S7 | github.com/cacggghp/vk-turn-proxy (issue #164) | TURN-носитель | <1 Мбит/с |
| S8 | github.com/frank-underwood64/whitelists_bypass | промо RU-CDN+XHTTP | низкая зрелость |
| S9 | habr 1008164 / 1032348 / 1007570 | механика whitelist, внешний IP, чебурнет | 2026-03..05 |
| S10 | YakovSava/anti-whitelist-rus + topics/bypass-whitelists-for-russia | агрегаторы | 2026 |

## 2. Факты

1. **Носители стандартизовались в 3 класса**: (а) видео/WebRTC через whitelisted
   SFU (Telemost, VK Call, WB Stream, DION, Bitrix24, Blink); (б) TURN-релей
   whitelisted сервисов — **деградирует, <1 Мбит/с, шейпится** (S4, S7#164);
   (в) RU-CDN/белые ASN как фронт VLESS+XHTTP/Reality.
2. S1 — зрелый продукт: headless Go/Pion creator+joiner, DataChannel и VP8-видео
   (KCP+ChaCha20+pacing), tun2socks, gomobile Android/iOS, e2e в netns.
   Как класс — да; как стек — нет (чужие SFU = SPOF/ToS).
3. **Списки белых IP — перо оператора и перо локации** `[медиа, замеры]`:
   HLL/Timeweb проходили на одном /24 и проваливались на соседнем; публичные
   CIDR-списки ошибаются в обе стороны; yandex.ru на МТС СПб жив по IPv6 и мёртв
   по IPv4, инвертируется после airplane mode.
4. **Механика двухуровневая**: L3 CIDR (~63 126 белых IP ≈ 0.14%) + L7 SNI-drop;
   UDP почти полностью режется; TSPU на 2-м хопе (S4).
5. Reality + российский разрешённый SNI — самая устойчивая схема, но не гарантия:
   кейс «hysteria прошла, Reality+VLESS заблокировали» на живом whitelist (S3,
   2026-10). WS с разрешённым Host — 0 из 8 `[медиа]`.
6. **Поведенческий слой**: «заморозка» = AND(подозрительный ASN, JA3/JA4,
   >3 параллельных хендшейков за ~350–400 мс) → **blackhole ~120 с** (не RST);
   ring-фингерпринт заблокирован; Delta Chat ушёл на aws-lc-rs 2026-06-06 (S6).
   Ответы авторов: мультиплексирование (xHTTP/mux), CDN-индирекция, правдоподобные
   (не randomized) fingerprint-шаблоны.
7. Рынок white-IP индустриализуется: kand.guru, relay-агент (nftables, outbound-only);
   Минцифры просит хостинги выносить разрешённые ресурсы в отдельные подсети
   (Kommersant 2026-08-31) — второе подтверждение И19.
8. S5 — 4-слойная самовоспроизводимая архитектура (Reality → CF-CDN → RU-relay →
   Телемост-DataChannel); слой 2 автор сам отозвал («Yandex.Cloud ≠ Yandex»);
   3X-UI отклоняем по нашим правилам.

## 3. Новое vs известное

**Подтверждения:** И6/И9 (RU-фронт выживает), И7/И8 (медиа-транспорт = S1),
И19 (рынок white-IP), §2.7 (безопасный SNI = vk.com/yastatic.net), §3b (behavioral),
И13 (анти-паттерн randomized-фингерпринтов).

**Новое:** И22–И27 (см. youtube-ideas-2026-11.md).

## 4. Вердикт

**Go на наш собственный путь (И18 → И9 → ADR-007); заимствовать методику, не стек.**
Готовой «взять как базу» архитектуры нет. Методическая база сообщества сформировалась
и валидирует наш порядок; добавляет конкретики: RU-CDN профиль на XHTTP (не WS),
hysteria в test-matrix чекера, чекер различает RST vs blackhole и бьёт по конкретному
/24+SIM в день теста.
