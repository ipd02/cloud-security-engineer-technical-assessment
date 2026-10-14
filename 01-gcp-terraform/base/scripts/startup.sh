#!/bin/bash
# Serves a static page on port 80 so the load balancer path can be tested end
# to end. Runs as a dynamic unprivileged user and binds only the low port, nothing else.
set -euo pipefail

# Debian 13 GCE images may not ship python3. Install it through Cloud NAT if missing.
if ! command -v python3 >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-minimal
fi

install -d -m 0755 /srv/www
hostname > /srv/www/index.html

cat > /etc/systemd/system/web.service <<'UNIT'
[Unit]
Description=Static test page
After=network-online.target

[Service]
DynamicUser=yes
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
