#!/bin/bash
# Serves a static page on port 80 so the load balancer path can be tested end
# to end. Runs as an unprivileged user and only binds the low port.
set -euo pipefail

install -d -m 0755 /srv/www
hostname > /srv/www/index.html

cat > /etc/systemd/system/web.service <<'UNIT'
[Unit]
Description=Static test page
After=network-online.target

[Service]
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 -m http.server 80 --directory /srv/www
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now web.service
