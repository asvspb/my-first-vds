[Unit]
Description=VDS Logs Telemetry Sampler Timer (5 min, randomized 30s)

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
