#!/bin/bash
# fail2ban-inside.sh <phase> - the Fail2ban addon on AlmaLinux, run inside the
# machine by fail2ban.sh, one phase at a time around the host's SSH attempts:
#
#   install  what the panel's installer puts in first, then fail2ban-install
#            on a machine that has never had fail2ban, and the sign-in jail
#   banned   the host's address, banned by the sshd jail
#   unban    fail2ban-unban lets it go
#   rest     recidive counted the bans, configure, a manual ban, stop
#
# Prints PASS or FAIL per check.
set -uo pipefail
H=/usr/local/sbin/snpanel-helper
ATTACKER="${ATTACKER:-10.24.0.1}"
check() { if eval "$1"; then echo "PASS  $2"; else echo "FAIL  $2"; fi; }
banned() { fail2ban-client status "$1" 2> /dev/null | sed -n 's/.*Banned IP list:\s*//p'; }
field() { "$H" fail2ban-status | python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

case "${1:-}" in
install)
  grep PRETTY_NAME /etc/os-release
  # The installer enables EPEL before anything else; nftables is the panel's
  # firewall; sshd is what the first jail watches.
  dnf -y -q install epel-release > /tmp/dnf-epel.log 2>&1
  dnf -y -q install nftables openssh-server openssh-clients iproute util-linux > /tmp/dnf-base.log 2>&1
  check "rpm -q epel-release nftables openssh-server > /dev/null" "EPEL, nftables and sshd are in"
  id snpanel > /dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin snpanel
  mkdir -p /var/log/nginx && touch /var/log/nginx/access.log /var/log/nginx/error.log
  systemctl enable --now sshd > /dev/null 2>&1
  check "systemctl is-active --quiet sshd" "sshd runs, as $(systemctl show -p Id --value sshd)"
  check "! rpm -q fail2ban-server > /dev/null 2>&1 && [ ! -e /var/log/fail2ban.log ]" "fail2ban has never been here"

  CONFIG='{"ignoreip":[],"bantime":600,"findtime":600,"maxretry":3,"jails":["sshd","snpanel-login","snpanel-wordpress","recidive"]}'
  echo "$CONFIG" | "$H" fail2ban-install > /tmp/install.out 2>&1
  rc=$?
  check "[ $rc -eq 0 ]" "fail2ban-install exits 0 ($(tail -1 /tmp/install.out))"
  check "rpm -q fail2ban-server python3-systemd > /dev/null" "fail2ban-server and python3-systemd are in: $(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' fail2ban-server)"
  check "! rpm -q fail2ban-firewalld > /dev/null 2>&1 && ! rpm -q fail2ban-sendmail > /dev/null 2>&1" "and not firewalld's actions or sendmail"
  check "systemctl is-enabled --quiet fail2ban && systemctl is-active --quiet fail2ban" "the service is on, and on at boot"
  check "[ \"\$(fail2ban-client ping 2> /dev/null)\" = 'Server replied: pong' ]" "the server answers"
  jails=$(fail2ban-client status 2> /dev/null | sed -n 's/.*Jail list:\s*//p')
  check "[ \"$jails\" = 'recidive, snpanel-login, snpanel-wordpress, sshd' ]" "four jails: $jails"
  check "fail2ban-client get sshd journalmatch | grep -q 'sshd.service'" "sshd is read from the journal, as sshd.service"
  uid=$(id -u snpanel)
  check "fail2ban-client get snpanel-login journalmatch | grep -q \"_UID=$uid\"" "the sign-in jail is pinned to the panel's uid ($uid)"
  check "fail2ban-client get sshd actions | grep -q nftables" "bans are nftables rules"

  for _ in 1 2 3; do logger -t snpanel-auth "login failure from 198.51.100.99"; done
  for _ in 1 2 3; do
    setpriv --reuid=snpanel --regid=snpanel --clear-groups logger -t snpanel-auth "login failure from 198.51.100.23"
  done
  for _ in $(seq 1 20); do [ -n "$(banned snpanel-login)" ] && break; sleep 0.5; done
  sleep 1
  check "[ \"$(banned snpanel-login)\" = 198.51.100.23 ]" "three failures from the panel's uid ban their address; three forged as root ban nobody: [$(banned snpanel-login)]"
  check "nft list ruleset | grep -q 198.51.100.23" "and the ban is an nftables rule"
  ;;
banned)
  for _ in $(seq 1 20); do [ -n "$(banned sshd)" ] && break; sleep 0.5; done
  check "[ \"$(banned sshd)\" = $ATTACKER ]" "the host's failed SSH sign-ins ban it: [$(banned sshd)]"
  check "nft list ruleset | grep -q $ATTACKER" "with an nftables rule"
  check "[ \"$(field "d['installed'] and d['running']")\" = True ]" "fail2ban-status: installed and running, version $(field "d['version']")"
  check "[ \"$(field "[j['banned'] for j in d['jails'] if j['name'] == 'sshd'][0]")\" = \"['$ATTACKER']\" ]" "and it lists the ban under sshd"
  ;;
unban)
  "$H" fail2ban-unban "$ATTACKER" > /tmp/unban.out 2>&1
  check "[ $? -eq 0 ]" "fail2ban-unban exits 0"
  check "[ -z \"$(banned sshd)\" ] && ! nft list ruleset | grep -q $ATTACKER" "the address is free again, rule and all"
  ;;
rest)
  check "grep -q 'Ban 198.51.100.23' /var/log/fail2ban.log" "the server writes the log made for it before its first start"
  failed=$(fail2ban-client status recidive | sed -n 's/.*Total failed:\s*//p')
  check "[ \"${failed:-0}\" -ge 2 ]" "and recidive reads it: both bans so far count ($failed)"

  CONFIG='{"ignoreip":["192.0.2.0/24"],"bantime":900,"findtime":600,"maxretry":4,"jails":["sshd","snpanel-login","snpanel-wordpress","nginx-http-auth","recidive"]}'
  echo "$CONFIG" | "$H" fail2ban-configure > /tmp/configure.out 2>&1
  check "[ $? -eq 0 ]" "fail2ban-configure exits 0 ($(tail -1 /tmp/configure.out))"
  check "[ \"$(fail2ban-client get sshd maxretry)\" = 4 ] && [ \"$(fail2ban-client get sshd bantime)\" = 900 ]" "the server has read it: maxretry 4, bantime 900"
  check "fail2ban-client status | grep -q nginx-http-auth" "nginx-http-auth is on"
  check "fail2ban-client get sshd ignoreip | grep -q 192.0.2.0/24" "the new exemption is in"

  "$H" fail2ban-ban recidive 203.0.113.50 > /tmp/ban.out 2>&1
  check "[ $? -eq 0 ] && [ \"$(banned recidive)\" = 203.0.113.50 ]" "fail2ban-ban recidive: [$(banned recidive)]"
  check "nft list ruleset | grep -q 203.0.113.50" "on every port, as an nftables rule"

  "$H" fail2ban-stop > /tmp/stop.out 2>&1
  check "[ $? -eq 0 ]" "fail2ban-stop exits 0"
  check "! systemctl is-active --quiet fail2ban && ! systemctl is-enabled --quiet fail2ban" "stopped, and off at boot"
  check "! nft list tables | grep -q f2b-table" "every ban lifted with it"
  check "[ \"$(field "d['installed'] and not d['running'] and d['jails'] == []")\" = True ]" "fail2ban-status: installed, not running"
  ;;
*)
  echo "usage: fail2ban-inside.sh install|banned|unban|rest" >&2
  exit 2
  ;;
esac
