[Unit]
Description=VDS Probe Watch Timer (hourly active-probing snapshot, И33 v1)

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=1min

[Install]
WantedBy=timers.target
