[Unit]
Description=VDS DMS ping timer (dead-man-switch gate, quiet-exit P37)

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval_sec}s
RandomizedDelaySec=20s
AccuracySec=30s

[Install]
WantedBy=timers.target
