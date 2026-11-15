[Unit]
Description=VDS RU-relay CIDR weekly update timer (ADR-007)

[Timer]
# Еженедельно, воскресенье 04:30, разброс 10 мин — не бьётся с другими окнами.
OnCalendar=Sun *-*-* 04:30:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
