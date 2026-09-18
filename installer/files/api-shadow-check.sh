#!/bin/bash
# Compare the two implementations on the live panel (plan §9.3).
#
# The login cases deliberately fail, and both sides share one Redis, so each
# run spends four attempts against the 8-per-minute limit on the 127.0.0.1
# key. Left alone, a second run inside the same minute would start getting 429s
# and the diff would report differences that are only an artefact of running
# it. The counters are therefore cleared first - and the fact that clearing
# *one* set of keys settles both sides is itself the evidence that Rust and
# Python share the same counters, which is what C9 requires.
set -uo pipefail

echo "=== clearing the shared login counters (both sides read these keys) ==="
before=$(redis-cli --scan --pattern 'snpanel:login:*' 2>/dev/null | wc -l)
redis-cli --scan --pattern 'snpanel:login:*' 2>/dev/null | xargs -r redis-cli del >/dev/null
echo "  removed $before key(s) under snpanel:login:*"

PW=$(sed -n 's/^Password: //p' /root/login.txt)

echo
echo "=== a token minted by PYTHON, used against RUST (C4) ==="
TOK=$(curl -s --max-time 20 -X POST http://127.0.0.1:8000/api/auth/login \
    --data-urlencode "username=admin" --data-urlencode "password=$PW" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$TOK" ]; then echo "  could not log in through Python"; exit 1; fi
echo "  got a token from the Python upstream"

code=$(curl -sk -o /tmp/rust-session.json -w '%{http_code}' --max-time 25 \
    -H "Authorization: Bearer $TOK" https://127.0.0.1:2222/api/auth/session)
echo "  Rust accepts it on /api/auth/session: HTTP $code"
head -c 260 /tmp/rust-session.json; echo

echo
echo "=== warming the shared release-check cache ==="
# /api/updates/status is the one endpoint that *mutates what it reports*: a
# stale release check refreshes the shared state file, and the helper's own
# output is a snapshot of that same file. Called cold, whichever side goes
# first refreshes and the second sees a file the first has just rewritten -
# a difference that is an artefact of the comparison, not of the port.
#
# Warming it means both sides find a fresh cache, neither writes, and the two
# snapshots are the same file. The five-minute window is the Python's own.
curl -s --max-time 45 -o /dev/null -H "Authorization: Bearer $TOK" \
    http://127.0.0.1:8000/api/updates/status
echo "  release check cached"

echo
echo "=== C3 across both implementations, on production ciphertext ==="
# The strongest form of the encryption contract: mint a phpMyAdmin hand-off
# through one implementation and consume it through the other. The token file
# carries the *decrypted* database password, so if the two disagreed about the
# Fernet key derivation by a single byte, the passwords below would differ -
# and every customer's stored database password would be unreadable after the
# migration. That is risk R1 in the plan.
password_via() {
    # $1 = the base URL that mints, $2 = the base URL that consumes
    local url token
    url=$(curl -sk --max-time 20 -H "Authorization: Bearer $TOK" \
        -X POST "$1/api/databases/1/phpmyadmin-sso" |
        sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
    token=${url##*snpanel_sso=}
    [ -n "$token" ] || { echo "MINT-FAILED"; return; }
    curl -sk --max-time 20 "$2/api/databases/phpmyadmin-sso/$token" |
        sed -n 's/.*"db_password":"\([^"]*\)".*/\1/p'
}

rust_minted=$(password_via https://127.0.0.1:2222 http://127.0.0.1:8000)
python_minted=$(password_via http://127.0.0.1:8000 https://127.0.0.1:2222)

if [ -z "$rust_minted" ] || [ "$rust_minted" = "MINT-FAILED" ]; then
    echo "  FAIL  Rust could not mint a hand-off"
elif [ "$rust_minted" = "$python_minted" ]; then
    echo "  PASS  Rust minted -> Python consumed, and the reverse, agree on the password"
    echo "        (${#rust_minted} characters, not shown)"
else
    echo "  FAIL  the two implementations decrypt the same ciphertext differently"
fi

echo
echo "=== shadow diff ==="
# Cleared again: the exchange above spent an attempt on each side.
redis-cli --scan --pattern 'snpanel:login:*' 2>/dev/null | xargs -r redis-cli del >/dev/null
/usr/local/bin/xtask-rust shadow-diff --token "$TOK" \
    --rust https://127.0.0.1:2222 --python http://127.0.0.1:8000
rc=$?

echo
echo "=== the counters the failed logins left behind ==="
redis-cli --scan --pattern 'snpanel:login:*' 2>/dev/null | sort | sed 's/^/  /'

exit $rc
