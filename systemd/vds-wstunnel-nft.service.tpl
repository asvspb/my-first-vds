[Unit]
Description=VDS p2p carrier 2: nft + UFW для wstunnel (ADR-016)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Идемпотентно: nft -c -f (проверка) → nft -f (применение) + UFW-правило
# «9443/tcp только с IP релея». Переживает ребут (enabled oneshot).
ExecStart={script}

[Install]
WantedBy=multi-user.target
