[Unit]
Description=VDS p2p carrier 2: wg-ws0 (AWG поверх wstunnel/WSS, ADR-016)
After=network-online.target{after_units}
Wants=network-online.target{wants_units}

[Service]
Type=oneshot
RemainAfterExit=yes
# Plain AWG (обфускация выключена): интерфейс живёт внутри WSS.
# Релей: Endpoint = 127.0.0.1:<local> (порт wstunnel client), Table = off —
# маршруты ведёт селектор (table 100), иначе wg-quick снесёт default в main.
# down обязан идти по пути конфига (P14: awg-quick ищет iface в дефолтном каталоге).
ExecStart=/usr/bin/awg-quick up {config_path}
ExecStop=/usr/bin/awg-quick down {config_path}

# Конфиг содержит приватный ключ (0600) — читается только awg-quick'ом.
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
