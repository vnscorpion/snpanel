#!/bin/bash
# run.sh - install SNPanel on a clean machine and check it, for the three
# supported distributions.
#
#     sudo bash tools/os-check/run.sh make    <machine>
#     sudo bash tools/os-check/run.sh boot    <machine>
#     sudo bash tools/os-check/run.sh install <machine> <source-tree>
#     sudo bash tools/os-check/run.sh check   <machine> [ENV=VALUE ...]
#     sudo bash tools/os-check/run.sh down    <machine>
#
# <machine> is ub24t (Ubuntu 24.04), deb13t (Debian 13) or alma10t
# (AlmaLinux 10) - see machine.sh. <source-tree> is a checkout with the musl
# binaries built into target/x86_64-unknown-linux-musl/release, which the
# installer prefers to a release download.
#
# `install` runs installer/install.sh the way the one-line installer does,
# with PANEL_URL answering its prompts and ENABLE_SSL=no, so the panel gets a
# self-signed certificate. Under systemd-nspawn MariaDB's package cannot
# create its system tables (RUST_MIGRATION_STATUS.md records it twice), so
# mariadb-nspawn-fix.sh is applied after the first attempt and the installer
# run again - on a real host neither is needed.
#
# `check` runs `xtask acceptance` and smoke.mjs on the machine; pass
# SMOKE_CLAMAV=1, SMOKE_MALDET=1 or SMOKE_DOCKER=1 for the heavy parts.
# Logs go to $LOG_DIR (default /var/tmp/snpanel-os-check).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:?usage: run.sh make|boot|install|check|down <machine> ...}"
NAME="${2:?usage: run.sh make|boot|install|check|down <machine> ...}"
ROOT="/var/lib/machines/$NAME"
LOG_DIR="${LOG_DIR:-/var/tmp/snpanel-os-check}"
mkdir -p "$LOG_DIR"

in_machine() { systemd-run --machine="$NAME" --quiet --pipe --wait "$@"; }

case "$ACTION" in
  make | boot | down)
    exec bash "$HERE/machine.sh" "$ACTION" "$NAME"
    ;;
  install)
    SRC="${3:?usage: run.sh install <machine> <source-tree>}"
    LOG="$LOG_DIR/install-$NAME.log"
    rm -rf "$ROOT/opt/snpanel-src"
    mkdir -p "$ROOT/opt/snpanel-src"
    tar -C "$SRC" --exclude=./.git --exclude=./node_modules --exclude=./frontend/node_modules \
      --exclude=./target/debug --exclude=./target/release -cf - . | tar -C "$ROOT/opt/snpanel-src" -xf -
    install -m 0755 "$HERE/mariadb-nspawn-fix.sh" "$ROOT/root/mariadb-nspawn-fix.sh"
    echo "=== installing on $NAME ($(grep PRETTY_NAME "$ROOT/etc/os-release"))" > "$LOG"
    for attempt in 1 2; do
      in_machine --setenv=PANEL_URL="http://snpanel.$NAME:2222" --setenv=PANEL_HOSTNAME="snpanel.$NAME" \
        --setenv=PANEL_DOMAIN="snpanel.$NAME" --setenv=PANEL_PORT=2222 --setenv=ENABLE_SSL=no \
        --setenv=DEBIAN_FRONTEND=noninteractive \
        /bin/bash -c 'cd /opt/snpanel-src && bash installer/install.sh' >> "$LOG" 2>&1
      rc=$?
      echo "INSTALLER_EXIT=$rc (attempt $attempt)" >> "$LOG"
      # The container limit: MariaDB's tables made as mysql.
      in_machine /bin/bash /root/mariadb-nspawn-fix.sh >> "$LOG" 2>&1
      [ "$rc" -eq 0 ] && break
    done
    grep -E "^==> |INSTALLER_EXIT" "$LOG" | tail -4
    ;;
  check)
    shift 2
    setenv=()
    for kv in "$@"; do setenv+=(--setenv="$kv"); done
    install -m 0644 "$HERE/smoke.mjs" "$ROOT/root/smoke.mjs"
    in_machine /opt/snpanel-src/target/x86_64-unknown-linux-musl/release/xtask acceptance \
      > "$LOG_DIR/$NAME-acceptance.log" 2>&1
    echo "acceptance rc=$?  $(grep -E 'passed:' "$LOG_DIR/$NAME-acceptance.log")"
    # The distribution's Node if there is one, else the one the panel installs.
    node=/usr/bin/node
    [ -x "$ROOT/usr/bin/node" ] || node=/opt/snpanel/node/22/bin/node
    in_machine "${setenv[@]}" "$node" /root/smoke.mjs > "$LOG_DIR/$NAME-smoke.log" 2>&1
    echo "smoke rc=$?  $(grep -E 'passed:' "$LOG_DIR/$NAME-smoke.log")"
    grep -hE "FAIL|SKIP" "$LOG_DIR/$NAME-acceptance.log" "$LOG_DIR/$NAME-smoke.log"
    ;;
  *)
    echo "usage: run.sh make|boot|install|check|down <machine> ..." >&2
    exit 2
    ;;
esac
