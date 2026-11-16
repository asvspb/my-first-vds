[Unit]
Description=VDS Logs Daily Analyze Timer (04:15, randomized 30s)

[Timer]
OnCalendar=*-*-* 04:15:00
RandomizedDelaySec=30
Persistent=true

[Install]
WantedBy=timers.target
