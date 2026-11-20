[Unit]
Description=vds wstunnel server — носитель №2 p2p (WSS/TLS, ADR-016)
Documentation=file:/opt/my-vds/docs/adr/ADR-016-p2p-link-multi-carrier.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Секрет path-prefix — только в env-файле (0600), не в argv.
EnvironmentFile=/etc/vds/wstunnel-server.env
ExecStart=/usr/local/bin/wstunnel server wss://0.0.0.0:{ws_port} \
    --restrict-to 127.0.0.1:{wg_port} \
    --tls-certificate {cert} \
    --tls-private-key {key}
Restart=always
RestartSec=5
StartLimitIntervalSec=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Сертификат читается из /etc/letsencrypt (только чтение)
ReadOnlyPaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
