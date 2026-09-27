#!/bin/bash
# fail2ban.sh [helper] - the Fail2ban addon's RHEL path, for real, on
# AlmaLinux 10.
#
#     sudo bash tools/el-check/fail2ban.sh
#
# Boots a throwaway AlmaLinux 10 (alma-container.sh), puts in what the panel's
# installer would - EPEL, nftables, sshd - and drives the helper binary itself:
# fail2ban-install on a machine that has never had fail2ban, the panel's
# sign-in jail and its uid pin, an SSH client on this host banned and let go,
# recidive reading the server's own log, configure, a manual ban, stop. The
# machine is removed at the end, pass or fail.
#
# The helper is the static build - EL10's glibc is older than most build
# hosts' - which `cargo build --release --target x86_64-unknown-linux-musl
# -p snpanel-helper` makes. Needs root, systemd-nspawn, ssh and internet.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="${1:-$HERE/../../target/x86_64-unknown-linux-musl/release/snpanel-helper}"
NAME=alma10check
SUBNET=10.24.0
LOG="$(mktemp)"

[ -x "$HELPER" ] || { echo "no helper at $HELPER" >&2; exit 2; }
trap 'bash "$HERE/alma-container.sh" down "$NAME" "$SUBNET"; rm -f "$LOG"' EXIT
bash "$HERE/alma-container.sh" up "$NAME" "$SUBNET" || exit 1
install -D -m 0755 "$HELPER" "/var/lib/machines/$NAME/usr/local/sbin/snpanel-helper"
install -m 0755 "$HERE/fail2ban-inside.sh" "/var/lib/machines/$NAME/root/fail2ban-inside.sh"

inside() {
  systemd-run --machine="$NAME" --pipe --quiet --setenv=ATTACKER="$SUBNET.1" \
    /bin/bash /root/fail2ban-inside.sh "$1" 2>&1 | tee -a "$LOG"
}
# One sign-in as a user that does not exist; how far it got.
ssh_try() {
  timeout 12 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o PreferredAuthentications=password -o LogLevel=ERROR \
    "nosuchuser@$SUBNET.2" true 2>&1 | tail -1
}
host_check() {
  if [ "$1" = reached ]; then
    case "$2" in *"Permission denied"*) r=PASS ;; *) r=FAIL ;; esac
  else
    case "$2" in *"Permission denied"*) r=FAIL ;; *) r=PASS ;; esac
  fi
  echo "$r  from the host, sshd is $1: ${2:-timed out}" | tee -a "$LOG"
}

inside install
host_check reached "$(ssh_try)"
for _ in 1 2 3; do ssh_try > /dev/null; sleep 0.5; done
inside banned
host_check blocked "$(ssh_try)"
inside unban
host_check reached "$(ssh_try)"
inside rest

passed=$(grep -c '^PASS' "$LOG")
failed=$(grep -c '^FAIL' "$LOG")
echo
if [ "$failed" -eq 0 ] && [ "$passed" -gt 0 ]; then
  echo "PASS  $passed checks"
else
  echo "FAIL  $failed of $((passed + failed)) checks"
  exit 1
fi
