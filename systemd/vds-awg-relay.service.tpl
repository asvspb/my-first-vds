[Unit]
Description=VDS relay exit leg (awg2, dedicated leg port pool, ADR-015/P24)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Выделенная нога relay->exit: awg2 (10.11.0.0/30, P_base 51900/udp).
# Клиентский awg0 (51825/udp) не затрагивается — отдельный интерфейс.
# down обязан идти по пути конфига: awg-quick ищет iface в дефолтном каталоге
# /etc/amnezia/amneziawg, наш конфиг лежит в /etc/amnezia/awg2.conf (P14).
ExecStart=/usr/bin/awg-quick up {config_path}
ExecStop=/usr/bin/awg-quick down {config_path}

# Конфиг содержит приватный ключ awg2 (0600) — читается только awg-quick'ом.
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
