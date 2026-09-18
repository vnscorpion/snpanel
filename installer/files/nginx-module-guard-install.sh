#!/bin/bash
# Stop a stale ModSecurity module from taking nginx down.
#
# The module is built against one nginx version. When dnf upgrades nginx to a
# different one, nginx cannot load it - and does not merely lose the WAF, it
# refuses to start. On a box serving real sites that is the whole web server
# gone, on a package update nobody was watching.
#
# The guard runs before nginx's own `-t` check. If the configuration is broken
# *and* the breakage mentions the module, it moves the load directive aside so
# nginx starts without the WAF, and says so loudly. Degraded beats down.
#
# It always exits 0: an ExecStartPre that fails prevents the start it is
# supposed to protect.
set -euo pipefail

GUARD=/usr/local/sbin/snpanel-nginx-module-guard
cat >"$GUARD" <<'GUARDSCRIPT'
#!/bin/bash
# Disable a ModSecurity module nginx cannot load, so nginx can still start.
# Installed by SNPanel. Always exits 0 on purpose.
set -uo pipefail

conf=/usr/share/nginx/modules/50-mod-http-modsecurity.conf
[[ -f "$conf" ]] || exit 0
nginx -t >/dev/null 2>&1 && exit 0

err="$(nginx -t 2>&1 || true)"
if grep -qi 'modsecurity' <<<"$err"; then
  mv -f "$conf" "${conf}.disabled-by-snpanel"
  version="$(nginx -v 2>&1 | sed 's#.*/##')"
  message="SNPanel: nginx could not load the ModSecurity module, so it was disabled to let nginx start. Rebuild it against nginx ${version} to restore the WAF."
  command -v logger >/dev/null 2>&1 && logger -t snpanel -p daemon.err -- "$message"
  echo "$message" >&2
fi
exit 0
GUARDSCRIPT
chmod 0755 "$GUARD"
echo "installed $GUARD"

# The distribution's unit runs `nginx -t` as its own ExecStartPre, and a
# failing one stops the start. The guard therefore has to run first, which
# means resetting the list and restating it. The two restated lines are copied
# from the unit as shipped; if the distribution changes them this drop-in has
# to be revisited, which is noted here so it is not a surprise.
install -d -m 0755 /etc/systemd/system/nginx.service.d
cat >/etc/systemd/system/nginx.service.d/10-snpanel-module-guard.conf <<'UNIT'
[Service]
# Reset and restate: ExecStartPre entries accumulate in order, and the guard is
# only useful before the `nginx -t` that would otherwise abort the start.
# The two lines after the guard are nginx.service's own, as shipped on EL10.
ExecStartPre=
ExecStartPre=/usr/local/sbin/snpanel-nginx-module-guard
ExecStartPre=/usr/bin/rm -f /run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
UNIT
systemctl daemon-reload
echo "installed the nginx drop-in"
systemctl cat nginx.service | grep -n "ExecStartPre" | sed 's/^/  /'
