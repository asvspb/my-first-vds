[Unit]
Description=vds wstunnel client — релей→exit по WSS (ADR-016)
Documentation=file:/opt/my-vds/docs/adr/ADR-016-p2p-link-multi-carrier.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Секрет path-prefix — только в env-файле (0600), не в argv.
EnvironmentFile=/etc/vds/wstunnel-client.env
ExecStart=/usr/local/bin/wstunnel client \
    -L udp://127.0.0.1:{local_udp}:localhost:{wg_port}?timeout_sec=0 \
    --tls-verify-certificate \
    wss://{domain}:{ws_port}
Restart=always
RestartSec=5
StartLimitIntervalSec=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
