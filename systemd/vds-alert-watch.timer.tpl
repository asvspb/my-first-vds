[Unit]
Description=VDS Alert Watch Timer (threat / relay pulse notification tick, exit node)

[Timer]
OnBootSec=3min
OnUnitActiveSec={interval_sec}s
RandomizedDelaySec=30s
AccuracySec=30s

[Install]
WantedBy=timers.target
