"""Сторож угрозы на exit-узле (SPEC-20261117-alert-watch).

Границы пакета: **только уведомления**. Здесь нет и не должно быть авто-действий
(лок 443, рестарт юнитов, запись `probe-watch.json` / `state.json`): сторож читает
телеметрию и отправляет сообщение, решения принимает владелец.

Раскладка (SPEC §3, менять только новым SPEC):
    paths.py     — пути/имена юнитов/лок-файла
    env.py       — схема /etc/vds/alert.env (парсинг, рендер, маскирование)
    state.py     — /var/lib/vds/alert-state.json + чистая логика подавления
    channels.py  — доставка (stdlib: smtplib / urllib)
    checks.py    — чтение источников сигнала (threat / пульс плеча / лок)
    watch.py     — один тик: сигналы → decide → отправка → теги → state
    cli.py       — install / remove / test / status
"""
