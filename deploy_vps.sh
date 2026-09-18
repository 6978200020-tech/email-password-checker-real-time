#!/usr/bin/env bash
set -euo pipefail

# Run this on an Ubuntu/Debian VPS from the project directory.
APP_DIR="${APP_DIR:-/opt/email-domain-auditor}"
SERVICE_NAME="${SERVICE_NAME:-email-domain-auditor}"
PYTHON="${PYTHON:-python3}"

sudo apt-get update
sudo apt-get install -y python3 python3-venv
sudo mkdir -p "$APP_DIR"
sudo cp server.py smtp_probe.py requirements.txt "$APP_DIR/"
sudo chown -R "$USER":"$USER" "$APP_DIR"

"$PYTHON" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/requirements.txt"

sudo tee "/etc/systemd/system/$SERVICE_NAME.service" >/dev/null <<EOF
[Unit]
Description=Privacy-safe email domain auditor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/server.py --host 127.0.0.1 --port 8765 --no-browser
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"
sudo systemctl --no-pager --full status "$SERVICE_NAME"
