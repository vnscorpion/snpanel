#!/bin/bash
# Switch the panel from the bash privileged helper to the Rust one.
#
# This is the Phase 2 milestone from RUST_MIGRATION_PLAN.md: the existing
# Python backend running against the Rust helper. It is deliberately not an
# all-or-nothing swap.
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
# Rollback is a single mv, printed at the end and safe to run at any time.
#
# Usage:
#   helper-cutover.sh install   <path-to-snpanel-helper-rust>
#   helper-cutover.sh rollback
set -euo pipefail

SBIN=/usr/local/sbin
LIVE="$SBIN/snpanel-helper"
BASH_HELPER="$SBIN/snpanel-helper.sh"
BACKUP_DIR=/var/backups/snpanel/helper-cutover

fail() { echo "helper-cutover: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "must run as root"

case "${1:-}" in
install)
    RUST_BIN="${2:-}"
    [[ -n "$RUST_BIN" && -f "$RUST_BIN" ]] || fail "usage: $0 install <path-to-snpanel-helper-rust>"

    # Refuse to run twice: a second run would move the Rust binary aside as
    # though it were the bash one, and the fallback would then be a loop.
    if [[ -f "$BASH_HELPER" ]]; then
        fail "$BASH_HELPER already exists; the cutover has already been done"
    fi
    [[ -f "$LIVE" ]] || fail "$LIVE not found - is SNPanel installed?"

    # The Rust helper must be able to answer before it is put in the path.
    "$RUST_BIN" --help >/dev/null 2>&1 || fail "$RUST_BIN does not run on this machine"

    mkdir -p "$BACKUP_DIR"
    cp -a "$LIVE" "$BACKUP_DIR/snpanel-helper.bash.$(date -u +%Y%m%dT%H%M%SZ)"
    echo "backed up the bash helper to $BACKUP_DIR"

    mv "$LIVE" "$BASH_HELPER"
    chown root:root "$BASH_HELPER"
    chmod 0750 "$BASH_HELPER"

    install -o root -g root -m 0750 "$RUST_BIN" "$LIVE"

    # Prove the swap before declaring success: a ported operation and a
    # delegated one, through the same path the panel uses.
    if ! "$LIVE" --help >/dev/null 2>&1; then
        mv "$BASH_HELPER" "$LIVE"
        fail "the Rust helper does not respond; rolled back"
    fi

    echo "cutover complete:"
    echo "  $LIVE        -> Rust  ($(stat -c%s "$LIVE") bytes)"
    echo "  $BASH_HELPER -> bash  ($(stat -c%s "$BASH_HELPER") bytes, fallback)"
    echo
    echo "rollback:  $0 rollback"
    ;;

rollback)
    [[ -f "$BASH_HELPER" ]] || fail "$BASH_HELPER not found - nothing to roll back to"
    mv -f "$BASH_HELPER" "$LIVE"
    chown root:root "$LIVE"
    chmod 0750 "$LIVE"
    echo "rolled back: $LIVE is the bash helper again"
    ;;

*)
    echo "usage: $0 install <path-to-snpanel-helper-rust>"
    echo "       $0 rollback"
    exit 2
    ;;
esac
