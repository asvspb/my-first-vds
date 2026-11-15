[Unit]
Description=VDS RU-relay exit leg (awg1 -> asv1:51825, ADR-007)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Конфиг awg1 переносится с asv1 (`vds amneziawg add-client relay`) и
# санитизируется relay init: Table = off — маршруты ведёт vds-relay-policy
# (fwmark 0x1 -> table 100), иначе wg-quick положил бы default в main-table
# релея и отрезал ssh.
ExecStart=/usr/bin/awg-quick up {config_path}
ExecStop=/usr/bin/awg-quick down {config_path}

NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
