[Unit]
Description=VDS Relay Maneuver Timer (opt-in port failover tick, ADR-015/P25)

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval_sec}s
AccuracySec=5s
Unit=vds-relay-maneuver.service

[Install]
WantedBy=timers.target
