"""DMS — dead-man-switch пинг на Healthchecks (SPEC-20261124-quiet-exit §5).

Оба узла (exit и relay) шлют исходящий HTTPS GET на уникальный URL
Healthchecks; ноль входящих портов. Ping уходит только при живых ногах
(gate, `src.dms.gate`); при мёртвой ноге — мгновенный `GET <URL>/fail`.
Секрет (`DMS_PING_URL`) — `/etc/vds/dms.env` (0600), маскируется как в
`src/alert/env.py`; URL не попадает в stdout/journal/`status --json`.
"""
