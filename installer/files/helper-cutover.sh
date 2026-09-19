#!/bin/bash
# Switch the panel from the bash privileged helper to the Rust one.
#
# Stage B of RUST_MIGRATION_PLAN.md. Deliberately not an all-or-nothing swap.
#
# How it works
# ------------
# The bash helper is moved aside to snpanel-helper.sh and the Rust binary takes
# its place at /usr/local/sbin/snpanel-helper. The Rust helper answers the
# operations it has ported and `exec`s the bash one for the rest, so:
#
#   - nothing about the panel changes: it calls the same path through the same
#     sudoers rule;
#   - every operation can move to Rust independently, and a half-migrated box
#     is a working box;
#   - `exec` keeps the environment (including SUDO_USER, which the bash helper
#     checks as its own authorisation), the standard file descriptors (so
#     operations that read a password or a crontab from stdin still work) and
#     the exit status.
#
# On top of that, this installs the socket the Rust API talks to directly.
# There the boundary is SO_PEERCRED - the kernel says who connected, and the
# caller cannot lie about it - rather than sudo and a verb allowlist. The API
# falls back to the sudo path whenever the socket is not usable, so enabling
# the socket cannot take the panel down.
#
# What boots, not only what runs
# ------------------------------
# The API cutover called `start`/`stop` and never `enable`/`disable`. A reboot
# silently reverted it, and a stray `systemctl start` put the old unit into a
# three-second restart loop that ran 71 times before anyone noticed. So every
# state change here uses `enable`/`disable`, and `status` reports what a reboot
# would come back to rather than what is running this minute.
#
# Usage:
#   helper-cutover.sh install <rust-helper> [<snpanel-extract>]
#   helper-cutover.sh verbs <list|->     # e.g. 'site-*,wp,wp-site', or - for all
#   helper-cutover.sh status
#   helper-cutover.sh rollback
set -uo pipefail

SBIN=/usr/local/sbin
LIVE="$SBIN/snpanel-helper"
BASH_HELPER="$SBIN/snpanel-helper.sh"
EXTRACTOR="$SBIN/snpanel-extract"
BACKUP_DIR=/var/backups/snpanel/helper-cutover
UNIT_DIR=/etc/systemd/system
SOCKET_UNIT=snpanel-helper.socket
SERVICE_UNIT=snpanel-helper.service
SOCKET_PATH=/run/snpanel/helper.sock
API_UNIT=snpanel-rust.service
DROPIN="$UNIT_DIR/$API_UNIT.d/helper-verbs.conf"
FILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() { echo "helper-cutover: $*" >&2; exit 1; }
note() { echo "  $*"; }

[[ $EUID -eq 0 ]] || fail "must run as root"

# Ask the socket a question that changes nothing, as the user the panel runs
# as. `nginx-test` is a read: it either parses the configuration or does not.
probe_socket() {
    local out
    out=$(runuser -u snpanel -- python3 - "$SOCKET_PATH" <<'PY' 2>&1
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(15)
try:
    s.connect(sys.argv[1])
    s.sendall(json.dumps({"version": 1, "request": {"op": "nginx-test"}}).encode() + b"\n")
    reply = s.makefile("rb").readline()
except OSError as e:
    print(f"UNREACHABLE {e}")
    sys.exit(1)
if not reply:
    print("NO REPLY")
    sys.exit(1)
try:
    answer = json.loads(reply)
except ValueError as e:
    print(f"MALFORMED {e}")
    sys.exit(1)
# Either answer proves the round trip. "ok" means nginx parsed; a refusal
# means the helper read the request, decided, and replied - which is the
# thing being tested here.
print("ANSWERED ok" if answer.get("ok") else "ANSWERED refused")
PY
)
    local rc=$?
    echo "$out"
    return $rc
}

install_units() {
    local src
    for src in "$SOCKET_UNIT" "$SERVICE_UNIT"; do
        [[ -f "$FILES_DIR/$src" ]] || fail "$FILES_DIR/$src is missing"
        install -o root -g root -m 0644 "$FILES_DIR/$src" "$UNIT_DIR/$src"
        note "installed $UNIT_DIR/$src"
    done
    systemctl daemon-reload
}

case "${1:-}" in
install)
    RUST_BIN="${2:-}"
    EXTRACT_BIN="${3:-}"
    [[ -n "$RUST_BIN" && -f "$RUST_BIN" ]] || fail "usage: $0 install <rust-helper> [<snpanel-extract>]"

    # Refuse to run twice: a second run would move the Rust binary aside as
    # though it were the bash one, and the fallback would then be a loop.
    if [[ -f "$BASH_HELPER" ]]; then
        fail "$BASH_HELPER already exists; the cutover has already been done"
    fi
    [[ -f "$LIVE" ]] || fail "$LIVE not found - is SNPanel installed?"

    # The Rust helper must be able to answer before it is put in the path.
    "$RUST_BIN" --help >/dev/null 2>&1 || fail "$RUST_BIN does not run on this machine"

    getent group snpanel >/dev/null || fail "the snpanel group does not exist"

    mkdir -p "$BACKUP_DIR"
    cp -a "$LIVE" "$BACKUP_DIR/snpanel-helper.bash.$(date -u +%Y%m%dT%H%M%SZ)"
    note "backed up the bash helper to $BACKUP_DIR"

    mv "$LIVE" "$BASH_HELPER"
    chown root:root "$BASH_HELPER"
    chmod 0750 "$BASH_HELPER"
    install -o root -g root -m 0750 "$RUST_BIN" "$LIVE"

    if ! "$LIVE" --help >/dev/null 2>&1; then
        mv -f "$BASH_HELPER" "$LIVE"
        fail "the Rust helper does not respond; rolled back"
    fi
    note "$LIVE is the Rust helper ($(stat -c%s "$LIVE") bytes)"
    note "$BASH_HELPER is the fallback ($(stat -c%s "$BASH_HELPER") bytes)"

    # site-archive-extract runs this as the site's own user, because an
    # archive is attacker-controlled input and the helper must not parse it
    # as root. Without it that verb reports itself missing and the bash
    # answers - correct, but not the cutover.
    if [[ -n "$EXTRACT_BIN" ]]; then
        [[ -f "$EXTRACT_BIN" ]] || fail "no such file: $EXTRACT_BIN"
        # 0755: it is run by an unprivileged site user and holds no privilege
        # of its own. This is the one binary here that is meant to be.
        install -o root -g root -m 0755 "$EXTRACT_BIN" "$EXTRACTOR"
        note "$EXTRACTOR installed ($(stat -c%s "$EXTRACTOR") bytes)"
    elif [[ ! -f "$EXTRACTOR" ]]; then
        note "WARNING: $EXTRACTOR is absent, so site-archive-extract stays on the bash"
    fi

    install_units
    # The socket is enabled, not the service: systemd owns the socket, starts
    # the helper on the first connection, and keeps the socket across a helper
    # restart so an update never shows the API a connection refused.
    #
    # `enable --now` and not `start`, because a reboot reads what is enabled.
    systemctl enable --now "$SOCKET_UNIT" >/dev/null 2>&1 \
        || fail "could not enable $SOCKET_UNIT"
    note "$SOCKET_UNIT is $(systemctl is-enabled "$SOCKET_UNIT" 2>/dev/null) and $(systemctl is-active "$SOCKET_UNIT" 2>/dev/null)"

    # Prove the round trip before declaring success. A socket that exists and
    # does not answer is worse than no socket, because the API would try it
    # first on every call.
    answer=$(probe_socket)
    if [[ "$answer" != ANSWERED* ]]; then
        systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1
        mv -f "$BASH_HELPER" "$LIVE"
        fail "the socket did not answer ($answer); rolled back"
    fi
    note "the socket answered: ${answer#ANSWERED }"

    echo
    echo "cutover complete. rollback:  $0 rollback"
    ;;

verbs)
    LIST="${2:-}"
    [[ -n "$LIST" ]] || fail "usage: $0 verbs <list|->"
    mkdir -p "$(dirname "$DROPIN")"
    if [[ "$LIST" == "-" ]]; then
        rm -f "$DROPIN"
        note "the allowlist is cleared: every verb the mapping answers goes over the socket"
    else
        cat > "$DROPIN" <<EOF
# Which verbs the panel sends over the helper socket.
#
# Written by helper-cutover.sh. An entry ending in * matches a prefix.
# Everything else keeps the path it has been using: sudo to the Rust helper,
# which answers what it can and execs the bash for the rest.
[Service]
Environment=SNPANEL_HELPER_VERBS=$LIST
EOF
        chmod 0644 "$DROPIN"
        note "the socket carries: $LIST"
    fi
    systemctl daemon-reload
    if systemctl is-active --quiet "$API_UNIT"; then
        systemctl restart "$API_UNIT" && note "restarted $API_UNIT"
    else
        note "$API_UNIT is not running; the setting applies when it next starts"
    fi
    ;;

status)
    echo "binaries:"
    if [[ -f "$BASH_HELPER" ]]; then
        printf '  %-34s %s\n' "$LIVE" "Rust ($(stat -c%s "$LIVE" 2>/dev/null) bytes)"
        printf '  %-34s %s\n' "$BASH_HELPER" "bash fallback"
    else
        printf '  %-34s %s\n' "$LIVE" "bash (no cutover)"
    fi
    printf '  %-34s %s\n' "$EXTRACTOR" "$([[ -f $EXTRACTOR ]] && echo present || echo absent)"

    echo "units (what a reboot comes back to, not what is running now):"
    for u in "$SOCKET_UNIT" "$SERVICE_UNIT"; do
        printf '  %-34s enabled=%s active=%s\n' "$u" \
            "$(systemctl is-enabled "$u" 2>/dev/null || echo -)" \
            "$(systemctl is-active "$u" 2>/dev/null || echo -)"
    done
    printf '  %-34s %s\n' "$SOCKET_PATH" "$([[ -S $SOCKET_PATH ]] && echo present || echo absent)"

    echo "allowlist:"
    if [[ -f "$DROPIN" ]]; then
        sed -n 's/^Environment=SNPANEL_HELPER_VERBS=/  /p' "$DROPIN"
    else
        echo "  (unset: every verb the mapping answers)"
    fi

    if [[ -S "$SOCKET_PATH" ]]; then
        echo "round trip:"
        echo "  $(probe_socket)"
    fi
    ;;

rollback)
    # Undo in the reverse order, and disable rather than stop, so a reboot
    # does not quietly restore half of it.
    if systemctl is-enabled "$SOCKET_UNIT" >/dev/null 2>&1 || systemctl is-active --quiet "$SOCKET_UNIT"; then
        systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1
        note "$SOCKET_UNIT disabled and stopped"
    fi
    systemctl stop "$SERVICE_UNIT" >/dev/null 2>&1
    rm -f "$DROPIN"
    systemctl daemon-reload

    if [[ -f "$BASH_HELPER" ]]; then
        mv -f "$BASH_HELPER" "$LIVE"
        chown root:root "$LIVE"
        chmod 0750 "$LIVE"
        note "$LIVE is the bash helper again"
    else
        note "$BASH_HELPER not found - the binary was already rolled back"
    fi

    if systemctl is-active --quiet "$API_UNIT"; then
        systemctl restart "$API_UNIT" && note "restarted $API_UNIT"
    fi
    ;;

*)
    echo "usage: $0 install <rust-helper> [<snpanel-extract>]"
    echo "       $0 verbs <list|->"
    echo "       $0 status"
    echo "       $0 rollback"
    exit 2
    ;;
esac
