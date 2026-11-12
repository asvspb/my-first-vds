[Unit]
Description=VDS Gateway Healthcheck (units/ports/cert, rate-limited restart)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/my-vds
Environment=PYTHONPATH=/opt/my-vds
Environment=INSTALL_DIR=/opt/my-vds
# --unit: rc 0 всегда, кроме катастрофы (не читается state.json) — таймер
# не должен падать находками, которые healthcheck сам же чинит.
ExecStart=/opt/my-vds/venv/bin/python -m src.main gateway healthcheck --unit
StandardOutput=journal
StandardError=journal
IOSchedulingClass=idle
CPUWeight=1
