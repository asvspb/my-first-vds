[Unit]
Description=VDS Hysteria2 gateway ({name})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin_path} server -c {config_path}
Restart=always
RestartSec=3
LimitNOFILE=65535

# QUIC требует больших UDP-буферов (см. systemd/sysctl/99-vds-gateway.conf.tpl)
# и чтения /etc/hysteria (конфиг+сертификаты, 0600).
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/etc/hysteria

[Install]
WantedBy=multi-user.target
