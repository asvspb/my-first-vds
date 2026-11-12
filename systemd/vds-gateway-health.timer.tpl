[Unit]
Description=VDS Gateway Healthcheck Timer (W1 GR-18)

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
