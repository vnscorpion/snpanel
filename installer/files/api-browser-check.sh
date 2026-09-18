#!/bin/bash
# Walk the flow a browser actually performs, against the public HTTPS endpoint,
# with the Rust process answering.
#
# Bearer tokens are the easy path and they are not what the panel uses: the SPA
# authenticates by cookie, and the cookie path is the one with CSRF on it. A
# port that only ever gets tested with `Authorization:` headers can have the
# whole double-submit mechanism broken and never notice.
set -uo pipefail

HOST=claude.sgd.ovh
IP=163.61.72.23
BASE="https://$HOST:2222"
R=(--resolve "$HOST:2222:$IP" --max-time 25)
JAR=$(mktemp)
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s  -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }

PW=$(sed -n 's/^Password: //p' /var/lib/machines/bp24/root/login.txt)

echo "=== the SPA itself (proxied through Rust to Python) ==="
body=$(curl -s "${R[@]}" "$BASE/" | head -c 400)
case "$body" in *"<div id=\"root\""*|*"<title>"*) ok "the panel page is served" ;;
                *) bad "index" "$(printf '%s' "$body" | head -c 80)" ;; esac
type=$(curl -s "${R[@]}" -o /dev/null -w '%{content_type}' "$BASE/")
case "$type" in text/html*) ok "as text/html ($type)" ;; *) bad "content-type" "$type" ;; esac

echo
echo "=== the certificate is the real one for this name ==="
subj=$(curl -sv "${R[@]}" "$BASE/api/health" 2>&1 | sed -n 's/.*subject: //p' | head -1)
issuer=$(curl -sv "${R[@]}" "$BASE/api/health" 2>&1 | sed -n 's/.*issuer: //p' | head -1)
echo "  subject: ${subj:-?}"
echo "  issuer:  ${issuer:-?}"
case "$subj" in *"$HOST"*) ok "served for $HOST without -k" ;; *) bad "certificate" "$subj" ;; esac

echo
echo "=== login by cookie, as the SPA does ==="
code=$(curl -s "${R[@]}" -c "$JAR" -o /tmp/bf-login.json -w '%{http_code}' \
    -X POST "$BASE/api/auth/login" \
    --data-urlencode "username=admin" --data-urlencode "password=$PW")
[ "$code" = "200" ] && ok "login returns 200" || { bad "login" "HTTP $code"; exit 1; }

grep -q snpanel_session "$JAR" && ok "a session cookie was set" || bad "cookie" "no snpanel_session"
grep -q snpanel_csrf "$JAR"    && ok "a CSRF cookie was set"    || bad "cookie" "no snpanel_csrf"
# The session cookie must be HttpOnly (curl's jar marks those with #HttpOnly_).
grep -q "#HttpOnly_.*snpanel_session" "$JAR" \
    && ok "the session cookie is HttpOnly, the CSRF one is not" \
    || bad "httponly" "$(grep snpanel_session "$JAR" | cut -c1-60)"

CSRF=$(awk '/snpanel_csrf/{print $NF}' "$JAR")

echo
echo "=== the session endpoint, authenticated by cookie alone ==="
body=$(curl -s "${R[@]}" -b "$JAR" "$BASE/api/auth/session")
case "$body" in *'"authenticated":true'*) ok "reports the session as authenticated" ;;
                *) bad "session" "$(printf '%s' "$body" | head -c 90)" ;; esac
case "$body" in *'"username":"admin"'*) ok "and names the right user" ;;
                *) bad "session user" "" ;; esac
case "$body" in *'"storage_used_bytes"'*) ok "with the storage figures the Dashboard renders" ;;
                *) bad "storage" "" ;; esac

echo
echo "=== CSRF: a cookie session cannot mutate without the header ==="
code=$(curl -s "${R[@]}" -b "$JAR" -o /tmp/bf-nocsrf.json -w '%{http_code}' \
    -X POST "$BASE/api/services/action" -H "Content-Type: application/json" \
    -d '{"name":"nginx","action":"status"}')
[ "$code" = "403" ] && ok "refused with 403 when X-CSRF-Token is absent" \
                    || bad "csrf" "HTTP $code - a cookie session could be driven from another site"

code=$(curl -s "${R[@]}" -b "$JAR" -o /tmp/bf-csrf.json -w '%{http_code}' \
    -X POST "$BASE/api/services/action" -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF" -d '{"name":"nginx","action":"status"}')
[ "$code" = "200" ] && ok "accepted with the header present" || bad "csrf ok" "HTTP $code"

# And a *wrong* header must not pass.
code=$(curl -s "${R[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/api/services/action" -H "Content-Type: application/json" \
    -H "X-CSRF-Token: not-the-right-value" -d '{"name":"nginx","action":"status"}')
[ "$code" = "403" ] && ok "and refused when the header does not match the cookie" \
                    || bad "csrf mismatch" "HTTP $code"

echo
echo "=== a proxied route reaches Python and comes back with the real data ==="
code=$(curl -s "${R[@]}" -b "$JAR" -o /tmp/bf-sites.json -w '%{http_code}' "$BASE/api/websites")
[ "$code" = "200" ] && ok "/api/websites proxied through (HTTP $code)" || bad "proxy" "HTTP $code"
grep -q "sgd.ovh" /tmp/bf-sites.json && ok "and returned the real website" \
    || bad "proxy body" "$(head -c 80 /tmp/bf-sites.json)"

echo
echo "=== the Firewall page, which is served by Rust and needs root ==="
# This is the page that found the last NT1 violation by hand, and the one that
# exercises the sudo trampoline: if the service unit blocks setuid, or does not
# allow AF_NETLINK for nft's socket, it renders with everything switched off
# and no error anywhere.
body=$(curl -s "${R[@]}" -b "$JAR" "$BASE/api/firewall/status")
case "$body" in *'"returncode":0'*) ok "the helper answered" ;;
                *) bad "firewall" "$(printf '%s' "$body" | head -c 120)" ;; esac
case "$body" in *'Status: enabled'*) ok "and reports the firewall as enabled" ;;
                *) bad "firewall status" "" ;; esac
case "$body" in *'Chain active: yes'*) ok "with the nftables chain active (needs AF_NETLINK)" ;;
                *) bad "nft" "the chain reads as inactive - netlink is blocked" ;; esac
case "$body" in *'"rules":['*) ok "and the structured rule list came back" ;;
                *) bad "rules" "" ;; esac

# A protected rule must be refused. Rule 0 is the cheap version of that check.
code=$(curl -s "${R[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' \
    -X DELETE "$BASE/api/firewall/rules/0" -H "X-CSRF-Token: $CSRF")
[ "$code" = "400" ] && ok "an impossible rule number is refused" || bad "rule guard" "HTTP $code"

echo
echo "=== logout invalidates the session everywhere (C27) ==="
TOK=$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' /tmp/bf-login.json)
code=$(curl -s "${R[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/api/auth/logout" -H "X-CSRF-Token: $CSRF")
[ "$code" = "200" ] && ok "logout returns 200" || bad "logout" "HTTP $code"

# The bearer token issued by that same login must now be refused: logout bumps
# token_version, which is what kills the *other* tabs and devices.
code=$(curl -s "${R[@]}" -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "$BASE/api/services/list")
[ "$code" = "401" ] && ok "the token from that session is refused afterwards" \
                    || bad "revocation" "HTTP $code - the session outlived its logout"

body=$(curl -s "${R[@]}" -b "$JAR" "$BASE/api/auth/session")
case "$body" in *'"authenticated":false'*) ok "and /session reports nobody is logged in" ;;
                *) bad "session after logout" "$(printf '%s' "$body" | head -c 90)" ;; esac

rm -f "$JAR"
echo
echo "  PASS: $PASS    FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
