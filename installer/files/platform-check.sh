#!/bin/bash
# Did this installation come out right?
#
# Run as root on the server, after install.sh. It checks the things that differ
# between Ubuntu and AlmaLinux, and the things that have to be identical on
# both, by asking the machine rather than by assuming a distribution:
#
#   * the web server's account comes from nginx.conf, not from a table;
#   * the Redis-compatible unit is whichever of redis-server/valkey exists;
#   * phpMyAdmin's paths are found, not guessed - EL capitalises them.
#
# Everything else is the same question on both platforms: does the API answer,
# can a website be created, does PHP run through nginx, and does the panel
# report its own WAF honestly.
#
# It creates one throwaway website and removes it again.
set -uo pipefail

PANEL_PORT="${PANEL_PORT:-2222}"
BASE="https://127.0.0.1:${PANEL_PORT}"
LOGIN_FILE="${LOGIN_FILE:-/root/login.txt}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s  -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip() { printf '  SKIP  %s  -- %s\n' "$1" "${2:-}"; SKIP=$((SKIP+1)); }

[[ $EUID -eq 0 ]] || { echo "run this as root"; exit 2; }

# --- what this machine calls things -----------------------------------------
WEB_USER="$(awk '$1=="user"{gsub(/;/,"",$2); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null)"
[[ -n "$WEB_USER" ]] || WEB_USER="www-data"
WEB_GROUP="$(id -gn "$WEB_USER" 2>/dev/null || printf '%s' "$WEB_USER")"

REDIS_SERVICE=""
for unit in redis-server valkey redis; do
  if systemctl cat "$unit" >/dev/null 2>&1; then REDIS_SERVICE="$unit"; break; fi
done

PMA_ROOT=""
for candidate in /usr/share/phpMyAdmin /usr/share/phpmyadmin; do
  [[ -d "$candidate" ]] && { PMA_ROOT="$candidate"; break; }
done
PMA_CONF=""
for candidate in /etc/phpMyAdmin /etc/phpmyadmin; do
  [[ -d "$candidate" ]] && { PMA_CONF="$candidate"; break; }
done

# Which PHP versions exist is a property of the machine, not a constant. Ubuntu
# 24.04 has 8.3 and 8.4 from Ondrej's PPA, Debian 13 more than either, and EL gets
# 8.3 and 8.4 from Remi. Hardcoding 8.4 here would have this check report a
# correctly installed 26.04 as missing its PHP.
PHP_PRESENT=()
for candidate in 8.1 8.2 8.3 8.4 8.5; do
  [[ -d "/etc/php/${candidate}/fpm" ]] && PHP_PRESENT+=("$candidate")
done
PHP_DEFAULT="${PHP_DEFAULT:-}"
if [[ -z "$PHP_DEFAULT" ]]; then
  # The newest present is what the installer makes the default.
  PHP_DEFAULT="${PHP_PRESENT[${#PHP_PRESENT[@]}-1]:-}"
fi

echo "=== this machine ==="
echo "  os:          $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "  web user:    ${WEB_USER}:${WEB_GROUP}"
echo "  redis unit:  ${REDIS_SERVICE:-none found}"
echo "  phpMyAdmin:  ${PMA_ROOT:-not installed}  (config ${PMA_CONF:-none})"
echo "  php:         ${PHP_PRESENT[*]:-none found}  (default ${PHP_DEFAULT:-none})"

echo
echo "=== services ==="
# The panel is served one of two ways. Before the Rust cutover, `snpanel-api`
# holds the port. After it, `snpanel-rust` holds the port and `snpanel-upstream`
# runs the Python behind it on loopback - and `snpanel-api` is stopped on
# purpose. Insisting on the first arrangement would report a correctly
# cut-over server as broken.
if systemctl is-active --quiet snpanel-rust; then
  ok "snpanel-rust is running (Rust front door)"
  systemctl is-active --quiet snpanel-upstream \
    && ok "snpanel-upstream is running (Python behind it)" \
    || bad "snpanel-upstream" "$(systemctl is-active snpanel-upstream 2>&1)"
elif systemctl is-active --quiet snpanel-api; then
  ok "snpanel-api is running"
else
  bad "the panel service" "neither snpanel-rust nor snpanel-api is active"
fi

units=(nginx mariadb)
[[ -n "$REDIS_SERVICE" ]] && units+=("$REDIS_SERVICE")
for unit in "${units[@]}"; do
  systemctl is-active --quiet "$unit" && ok "$unit is running" \
    || bad "$unit" "$(systemctl is-active "$unit" 2>&1)"
done
# PHP-FPM is php<v>-fpm on Debian and php<vv>-php-fpm on Remi; the installer's
# compatibility shim makes the Debian name reach both, so ask for that name.
if [[ ${#PHP_PRESENT[@]} -eq 0 ]]; then
  bad "php" "no /etc/php/<version>/fpm directory exists at all"
fi
for v in "${PHP_PRESENT[@]}"; do
  if systemctl cat "php${v}-fpm" >/dev/null 2>&1; then
    systemctl is-active --quiet "php${v}-fpm" && ok "php${v}-fpm is running" \
      || bad "php${v}-fpm" "$(systemctl is-active "php${v}-fpm" 2>&1)"
  else
    skip "php${v}-fpm" "not installed on this server"
  fi
done

echo
echo "=== the web server can reach what the panel writes ==="
id -nG "$WEB_USER" 2>/dev/null | grep -qw snpanel-sites \
  && ok "$WEB_USER is in snpanel-sites" || bad "group" "$(id -nG "$WEB_USER" 2>&1)"
id -nG snpanel 2>/dev/null | grep -qw "$WEB_GROUP" \
  && ok "snpanel is in $WEB_GROUP" || bad "group" "$(id -nG snpanel 2>&1)"

echo
echo "=== the API ==="
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "$BASE/api/health")
[[ "$code" == "200" ]] && ok "/api/health returns 200" || bad "health" "HTTP $code"

PW=$(sed -n 's/^Password: //p' "$LOGIN_FILE" 2>/dev/null)
JAR=$(mktemp)
CSRF=""
if [[ -z "$PW" ]]; then
  skip "login" "no password in $LOGIN_FILE"
else
  code=$(curl -sk -c "$JAR" -o /tmp/pc-login.json -w '%{http_code}' --max-time 20 \
      -X POST "$BASE/api/auth/login" \
      --data-urlencode "username=admin" --data-urlencode "password=$PW")
  [[ "$code" == "200" ]] && ok "login returns 200" || bad "login" "HTTP $code"
  grep -q snpanel_session "$JAR" && ok "a session cookie was set" || bad "cookie" "none"
  grep -q "#HttpOnly_.*snpanel_session" "$JAR" && ok "and it is HttpOnly" || bad "httponly" ""
  CSRF=$(awk '/snpanel_csrf/{print $NF}' "$JAR")

  code=$(curl -sk -b "$JAR" -o /tmp/pc-svc.json -w '%{http_code}' --max-time 20 "$BASE/api/services/list")
  [[ "$code" == "200" ]] && ok "/api/services/list returns 200" || bad "services" "HTTP $code"
  if [[ -n "$REDIS_SERVICE" ]]; then
    grep -q "\"$REDIS_SERVICE\"" /tmp/pc-svc.json \
      && ok "and names this machine's Redis unit ($REDIS_SERVICE)" \
      || bad "services body" "no mention of $REDIS_SERVICE"
  fi
fi

echo
echo "=== a website, end to end ==="
if [[ -z "$CSRF" ]]; then
  skip "website" "not logged in"
else
  domain="pcheck$$.example.com"
  code=$(curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
      -o /tmp/pc-site.json -w '%{http_code}' --max-time 90 \
      -X POST "$BASE/api/websites" \
      -d "{\"domain\":\"$domain\",\"php_version\":\"${PHP_DEFAULT}\",\"app_type\":\"php\",\"install_wordpress\":false}")
  case "$code" in
    200|201) ok "created through the API" ;;
    *) bad "create" "HTTP $code $(head -c 200 /tmp/pc-site.json)" ;;
  esac

  vhost="/etc/nginx/conf.d/${domain}.conf"
  [[ -f "$vhost" ]] && ok "vhost written" || bad "vhost" "$vhost missing"

  # Each site gets its own FPM pool, so the socket name is per-site. What
  # matters is that it is under /run/php and that the pool is listening.
  sock=$(sed -n 's/.*fastcgi_pass unix:\([^;]*\);.*/\1/p' "$vhost" 2>/dev/null | head -1)
  case "$sock" in
    /run/php/*.sock) ok "its FPM socket is under /run/php" ;;
    *) bad "fastcgi_pass" "${sock:-none}" ;;
  esac
  # php-fpm is reloaded asynchronously after the pool file is written, so the
  # socket appears a second or two later. Testing for it immediately is a race:
  # it passed on three platforms and failed on the fourth, which is what races
  # do rather than evidence about the platform.
  for _ in $(seq 15); do
    [[ -S "$sock" ]] && break
    sleep 1
  done
  [[ -S "$sock" ]] && ok "the pool is listening ($(stat -c '%U:%G %a' "$sock"))" \
    || bad "pool socket" "$sock did not appear within 15s"

  nginx -t >/dev/null 2>&1 && ok "nginx accepts its configuration" \
    || bad "nginx -t" "$(nginx -t 2>&1 | tail -1)"

  root=$(sed -n 's/^[[:space:]]*root[[:space:]]*\(.*\);/\1/p' "$vhost" 2>/dev/null | head -1)
  if [[ -n "$root" && -d "$root" ]]; then
    # Not a dotfile: the generated vhost denies those, correctly, and a 403
    # from that rule looks exactly like a broken PHP handler.
    printf '<?php echo "php-ok-".PHP_VERSION;' >"$root/snpanel-platform-check.php"
    chmod 0644 "$root/snpanel-platform-check.php"
    runuser -u "$WEB_USER" -- test -r "$root/snpanel-platform-check.php" \
      && ok "$WEB_USER can read a file the panel created" \
      || bad "readability" "$WEB_USER cannot read it"
    # nginx is reloaded asynchronously after a site is created, so a request
    # sent immediately can still be answered by the previous configuration.
    body=""
    for _ in $(seq 10); do
      body=$(curl -s --max-time 20 -H "Host: $domain" "http://127.0.0.1/snpanel-platform-check.php")
      case "$body" in php-ok-*) break ;; esac
      sleep 2
    done
    case "$body" in
      php-ok-*) ok "PHP runs through nginx: $body" ;;
      *) bad "php" "$(printf '%s' "$body" | head -c 120)" ;;
    esac
    rm -f "$root/snpanel-platform-check.php"
  else
    bad "document root" "${root:-not found in vhost}"
  fi

  site_id=$(sed -n 's/.*"id":[[:space:]]*\([0-9]*\).*/\1/p' /tmp/pc-site.json | head -1)
  [[ -n "$site_id" ]] && curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -o /dev/null \
    --max-time 60 -X DELETE "$BASE/api/websites/$site_id"
  rm -f "$vhost" 2>/dev/null
  nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null
fi

echo
echo "=== phpMyAdmin ==="
if [[ -z "$PMA_ROOT" ]]; then
  skip "phpMyAdmin" "not installed"
else
  [[ -f "$PMA_ROOT/snpanel-signon.php" ]] && ok "the signon script is in place" \
    || bad "signon" "missing from $PMA_ROOT"
  [[ -f "$PMA_CONF/conf.d/snpanel-signon.php" ]] && ok "the SSO config is in conf.d" \
    || bad "sso config" "missing from $PMA_CONF/conf.d"
  runuser -u "$WEB_USER" -- test -r "$PMA_CONF/config.inc.php" \
    && ok "$WEB_USER can read the phpMyAdmin config" \
    || bad "pma readable" "$WEB_USER cannot read $PMA_CONF/config.inc.php"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "http://127.0.0.1/phpmyadmin/")
  case "$code" in 200|302) ok "/phpmyadmin/ answers HTTP $code" ;; *) bad "phpmyadmin" "HTTP $code" ;; esac
fi

echo
echo "=== the WAF reports what is actually there ==="
# Not "is the WAF on" - whether the panel's answer matches the machine.
#
# Three things have to agree here, and an earlier version of this check was a
# third independent copy of the question that went stale: it knew about a
# packaged module and a compiled-in one, but not a module built from source and
# loaded with `load_module`, so it called the panel a liar when the panel was
# right. It now asks the same way the helper and the panel do, and then
# cross-checks against the helper rather than trusting itself.
engine=no
nginx -V 2>&1 | grep -qi modsecurity && engine=yes
[[ -e /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]] && engine=yes
grep -rqsiE '^[[:space:]]*load_module.*modsecurity' \
  /etc/nginx/nginx.conf /etc/nginx/modules-enabled/ /usr/share/nginx/modules/ 2>/dev/null && engine=yes
echo "  ModSecurity module present: $engine"

if [[ -x /usr/local/sbin/snpanel-helper ]] && id -u snpanel >/dev/null 2>&1; then
  helper_says=$(sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper waf-status 2>/dev/null \
    | sed -n '2s/^ *//p')
  case "$helper_says:$engine" in
    "installed:yes"|"not installed:no") ok "the helper agrees with this check ($helper_says)" ;;
    *) bad "helper disagrees" "helper says '$helper_says', this check says '$engine'" ;;
  esac
fi
if [[ -n "$CSRF" ]]; then
  curl -sk -b "$JAR" -o /tmp/pc-waf.json --max-time 20 "$BASE/api/waf/status" >/dev/null
  if [[ "$engine" == "no" ]]; then
    grep -qi 'not installed' /tmp/pc-waf.json \
      && ok "the panel reports it as not installed, which is true" \
      || bad "waf status" "the panel claims an engine this machine does not have"
  else
    grep -qi 'not installed' /tmp/pc-waf.json \
      && bad "waf status" "the panel reports no engine, but nginx has one" \
      || ok "the panel reports the engine, which is true"
  fi
fi
[[ -f /etc/nginx/conf.d/00-snpanel-http-flood.conf ]] \
  && ok "HTTP flood protection is configured (it needs no ModSecurity)" \
  || bad "flood conf" "missing"

echo
echo "================================================"
echo "  passed: $PASS   failed: $FAIL   skipped: $SKIP"
[[ "$FAIL" -eq 0 ]] || exit 1
