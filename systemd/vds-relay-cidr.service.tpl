[Unit]
Description=VDS RU-relay CIDR update (ipdeny ru.zone -> nft ru_cidr, ADR-007)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Сбой сети: exit 1 без повреждения прежнего агрегата (см. src/relay/cidr.py).
ExecStart={python} -m src.relay.cidr update

[Install]
WantedBy=multi-user.target
