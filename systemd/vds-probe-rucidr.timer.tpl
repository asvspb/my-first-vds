[Unit]
Description=VDS probe-watch RU-CIDR weekly update timer (SPEC-20261116-probe-response §3)

[Timer]
# Еженедельно, воскресенье 04:40 (не бьётся с relay-cidr 04:30), разброс 10 мин.
OnCalendar=Sun *-*-* 04:40:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
