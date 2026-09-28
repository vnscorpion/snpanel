#!/bin/bash
# Make the CL-0 prototype survive a reboot and a firewall reload.
set -euo pipefail

cat > /usr/local/sbin/snpanel-webswitch-restore <<'EOF'
#!/bin/bash
# Re-apply who owns 80/443, and let traffic redirected from 80/443 through the
# SNPanel firewall (it matches the post-NAT port, 8080/9080, otherwise).
live=$(cat /var/lib/snpanel/webserver 2>/dev/null || echo apache)
/usr/local/sbin/snpanel-webswitch "$live"
if nft list chain inet snpanel snpanel_input >/dev/null 2>&1 && \
   ! nft list chain inet snpanel snpanel_input | grep -q snpanel-webfailover; then
  h=$(nft -a list chain inet snpanel snpanel_input | grep 'tcp dport @protected return' | grep -oE 'handle [0-9]+' | cut -d' ' -f2)
  nft insert rule inet snpanel snpanel_input handle "$h" ct status dnat ct original proto-dst '{ 80, 443 }' return comment '"snpanel-webfailover"'
fi
EOF
chmod 755 /usr/local/sbin/snpanel-webswitch-restore

cat > /etc/systemd/system/snpanel-webswitch-restore.service <<'EOF'
[Unit]
Description=SNPanel: restore which web server answers 80/443 (CL-0 prototype)
After=network-online.target snpanel-firewall.service httpd.service lshttpd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/snpanel-webswitch-restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# the firewall may be reloaded at any time by the panel; re-check every minute
cat > /etc/systemd/system/snpanel-webswitch-restore.timer <<'EOF'
[Unit]
Description=SNPanel: keep the 80/443 redirect and its firewall rule in place (CL-0 prototype)

[Timer]
OnBootSec=30
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/snpanel-webwatch.service <<'EOF'
[Unit]
Description=SNPanel: LiteSpeed watchdog, fails over to Apache (CL-0 prototype)
After=snpanel-webswitch-restore.service

[Service]
ExecStart=/usr/local/sbin/snpanel-webwatch
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now snpanel-webswitch-restore.service snpanel-webswitch-restore.timer snpanel-webwatch.service
systemctl enable httpd lshttpd
systemctl is-enabled httpd lshttpd snpanel-webwatch snpanel-webswitch-restore.timer
