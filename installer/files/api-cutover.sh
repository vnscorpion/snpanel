#!/bin/bash
# Put the Rust API in front of the panel, for real, on the public port.
#
#   before:  browser --TLS--> uvicorn 0.0.0.0:2222        (Python serves it all)
#   after:   browser --TLS--> snpanel-api 0.0.0.0:2222     (Rust: auth, services)
#                                  |
#                                  `--> uvicorn 127.0.0.1:8000  (everything else)
#
# Two things make this safe to try on a live panel:
#
#   * the Python moves to loopback rather than going away, so every route that
#     is not ported still has its original implementation answering it;
#   * `rollback` below puts the old arrangement back with one command, and the
#     script calls it itself if the new front door does not come up.
#
# The Python instance binds 127.0.0.1 only. It speaks plain HTTP now that Rust
# terminates the TLS, and a plaintext port reachable from the container network
# would be a downgrade NT5 does not allow.
set -uo pipefail

PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s  -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }

# The group nginx belongs to: `www-data` on Debian, `nginx` on EL. Both units
# below take it as a supplementary group so the panel can read what the web
# server writes. Naming a group that does not exist is not a quiet failure -
# systemd refuses to start the unit at all.
WEB_GROUP="$(awk '$1=="user"{gsub(/;/,"",$2); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null)"
[[ -n "$WEB_GROUP" ]] || WEB_GROUP="www-data"
WEB_GROUP="$(id -gn "$WEB_GROUP" 2>/dev/null || printf '%s' "$WEB_GROUP")"

# The unit bodies are written from quoted heredocs, because they contain `$`
# sequences that must reach systemd untouched. So the group goes in as a
# placeholder and is substituted here.
substitute_web_group() {
  sed -i "s/__WEB_GROUP__/${WEB_GROUP}/" "$1"
}

rollback() {
    echo
    echo "!! rolling back to the Python front door"
    systemctl stop snpanel-rust snpanel-upstream 2>/dev/null
    systemctl start snpanel-api
    sleep 2
    curl -sk -o /dev/null -w '   panel is back: HTTP %{http_code}\n' --max-time 10 \
        https://127.0.0.1:2222/api/health
}

if [ "${1:-}" = "rollback" ]; then rollback; exit 0; fi

cat > /etc/systemd/system/snpanel-upstream.service <<'UNIT'
[Unit]
Description=SNPanel API (Python, behind the Rust front door)
After=network.target mariadb.service

[Service]
Type=exec
User=snpanel
Group=snpanel
SupplementaryGroups=__WEB_GROUP__ snpanel-sites
WorkingDirectory=/opt/snpanel/backend
EnvironmentFile=/opt/snpanel/backend/.env
Environment=HOME=/opt/snpanel
Environment=SNPANEL_USE_HELPER=true
# Loopback only: TLS is terminated in front of this now, so anything else
# would put a plaintext panel on the network.
#
# --proxy-headers with --forwarded-allow-ips 127.0.0.1 is what makes the
# X-Forwarded-For the Rust side appends authoritative: without it every
# proxied request is logged as coming from 127.0.0.1 and the login rate limit
# collapses onto a single key.
ExecStart=/opt/snpanel/backend/.venv/bin/python -m uvicorn app.main:app \
    --host 127.0.0.1 --port 8000 \
    --proxy-headers --forwarded-allow-ips 127.0.0.1 \
    --log-level warning
Restart=always
RestartSec=3
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=/opt/snpanel /home /var/backups/snpanel /etc/nginx/conf.d /etc/nginx/snpanel/custom /tmp /var/lib/snpanel /home/admin/snpanel_backups/da /var/lib/snpanel/da-import /var/lib/snpanel/import-stage
PrivateTmp=false
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
substitute_web_group /etc/systemd/system/snpanel-upstream.service

cat > /etc/systemd/system/snpanel-rust.service <<'UNIT'
[Unit]
Description=SNPanel API (Rust front door)
After=network.target snpanel-upstream.service
Wants=snpanel-upstream.service

[Service]
Type=exec
User=snpanel
Group=snpanel
SupplementaryGroups=__WEB_GROUP__ snpanel-sites
WorkingDirectory=/opt/snpanel/backend
EnvironmentFile=/opt/snpanel/backend/.env
Environment=STRANGLER_UPSTREAM=http://127.0.0.1:8000
Environment=SNPANEL_LOG=info
ExecStart=/usr/local/bin/snpanel-api-rust --listen 0.0.0.0:2222 --env /opt/snpanel/backend/.env
Restart=always
RestartSec=3
# NT5: the API stays unprivileged. It reads the certificates through the
# snpanel group (root:snpanel 0640), not by being root.
#
# NoNewPrivileges must stay **false**, exactly as it is on snpanel-api.service,
# and the reason is worth stating: the flag blocks setuid entirely, so `sudo`
# cannot run at all under it. With it set, every privileged operation failed
# with "the no new privileges flag is set" while the ordinary pages kept
# working - a firewall page that renders and does nothing. What actually
# confines this process is the sudoers allowlist and the helper's own argument
# checking, not this flag.
NoNewPrivileges=false
PrivateTmp=false
# AF_NETLINK is not optional: `nft` talks to the kernel over a netlink socket,
# and without it the helper still runs and still exits 0 - it just reports an
# inactive chain and blank counters. A firewall page that quietly says "off"
# about a firewall that is on is worse than one that errors.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
substitute_web_group /etc/systemd/system/snpanel-rust.service

systemctl daemon-reload

echo "=== the panel before the change ==="
curl -sk -o /dev/null -w '  https://127.0.0.1:2222/api/health -> HTTP %{http_code}  (Python)\n' \
    --max-time 10 https://127.0.0.1:2222/api/health

echo
echo "=== moving Python to loopback :8000 ==="
systemctl stop snpanel-api
systemctl start snpanel-upstream
for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8000/api/health)
    [ "$code" = "200" ] && break
    sleep 0.5
done
[ "$code" = "200" ] && ok "Python is answering on 127.0.0.1:8000" \
    || { bad "upstream" "HTTP $code"; journalctl -u snpanel-upstream -n 20 --no-pager --output=cat; rollback; exit 1; }

# It must NOT be reachable off loopback.
ip=$(hostname -I | awk '{print $1}')
off=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$ip:8000/api/health")
[ "$off" = "000" ] && ok "and is not reachable off loopback (plaintext stays inside)" \
                   || bad "exposure" "reachable on $ip:8000 (HTTP $off)"

echo
echo "=== starting the Rust front door on :2222 ==="
systemctl start snpanel-rust
for _ in $(seq 1 60); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://127.0.0.1:2222/api/health)
    [ "$code" = "200" ] && break
    sleep 0.5
done
[ "$code" = "200" ] && ok "Rust is serving TLS on :2222" \
    || { bad "front door" "HTTP $code"; journalctl -u snpanel-rust -n 30 --no-pager --output=cat; rollback; exit 1; }

journalctl -u snpanel-rust -n 12 --no-pager --output=cat | sed 's/^/  | /'

echo
echo "=== who answers what ==="
served=$(curl -sk --max-time 10 https://127.0.0.1:2222/api/ready | tr -d ' ')
case "$served" in *'"implementation":"rust"'*) ok "/api/ready reports the Rust implementation" ;;
                  *) bad "ready" "$served" ;; esac
case "$served" in *'"reachable":true'*) ok "the Python upstream is reachable from it" ;;
                  *) bad "upstream" "not reachable" ;; esac

echo
echo "=== NT5: still unprivileged ==="
u=$(ps -o user= -C snpanel-api-rust | head -1 | tr -d ' ')
[ "$u" = "snpanel" ] && ok "running as snpanel, not root" || bad "user" "running as $u"

echo
echo "  PASS: $PASS    FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || { rollback; exit 1; }
