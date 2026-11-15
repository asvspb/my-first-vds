[Unit]
Description=VDS probe-watch RU-CIDR update (ipdeny ru.zone -> /etc/vds-relay/ru-cidrs.txt, SPEC-20261116-probe-response §3)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Сбой сети: exit 1 без повреждения прежнего агрегата (см. probing_rucidr.py).
ExecStart={python} -m src.main gateway probe-watch ru-cidr update --apply

[Install]
WantedBy=multi-user.target
