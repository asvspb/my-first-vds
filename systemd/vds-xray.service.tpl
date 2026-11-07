[Unit]
Description=VDS Xray VLESS Reality ({name})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin_path} run -config {config_path}
Restart=always
RestartSec=3
LimitNOFILE=65535

# Ограничение поверхности атаки: Xray работает только со своим конфигом
# (0600) и geodata, в сеть писать не нужно.
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/usr/local/share/xray

[Install]
WantedBy=multi-user.target
