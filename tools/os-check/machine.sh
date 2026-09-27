#!/bin/bash
# machine.sh make|boot|down <name> - a clean machine to install SNPanel on.
#
#   ub24t    Ubuntu 24.04 (noble), debootstrap, the components a stock server
#            image has enabled: main restricted universe multiverse
#   deb13t   Debian 13 (trixie), debootstrap, main non-free-firmware
#   alma10t  AlmaLinux 10, the official almalinux:10 image from Docker Hub
#
# Booted the way deb13 is - systemd-nspawn@.service with PrivateUsers=no and a
# virtual Ethernet link, which the host's networkd gives a /28 with DHCP and
# masquerading - so the only difference between the machines is the
# distribution. The Debian family asks networkd for its address; AlmaLinux has
# no networkd, and gets the next address of the same /28 from the host.
set -euo pipefail
ACTION="${1:?usage: machine.sh make|boot|down <name>}"
NAME="${2:?usage: machine.sh make|boot|down <name>}"
ROOT="/var/lib/machines/$NAME"
DOMAIN="snpanel.$NAME"

debian_family() {
  local suite="$1" mirror="$2" components="$3" extra="$4"
  debootstrap --components="$components" \
    --include="systemd,systemd-sysv,dbus,ca-certificates,curl,gnupg,sudo,iproute2,iputils-ping,less,vim-tiny,openssh-server,cron,tzdata,locales,${extra}" \
    "$suite" "$ROOT" "$mirror" > "/var/log/debootstrap-$NAME.log" 2>&1
  systemctl --root="$ROOT" enable systemd-networkd.service > /dev/null 2>&1 || true
}

almalinux() {
  local work token digest
  work="$(mktemp -d)"
  token="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/almalinux:pull" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  get() {
    curl -fsSL -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      "https://registry-1.docker.io/v2/library/almalinux/manifests/$1"
  }
  get 10 > "$work/m.json"
  digest="$(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
print(next((m["digest"] for m in d.get("manifests", []) if m.get("platform", {}).get("architecture") == "amd64"), ""))' "$work/m.json")"
  [ -n "$digest" ] && get "$digest" > "$work/m.json"
  python3 -c 'import json,sys; [print(l["digest"]) for l in json.load(open(sys.argv[1]))["layers"]]' "$work/m.json" \
    | while read -r layer; do
        curl -fsSL -H "Authorization: Bearer $token" \
          "https://registry-1.docker.io/v2/library/almalinux/blobs/$layer" | tar -xz -C "$ROOT"
      done
  rm -rf "$work"
}

make() {
  [ -e "$ROOT" ] && { echo "$ROOT exists; run down first" >&2; exit 1; }
  mkdir -p "$ROOT"
  case "$NAME" in
    ub24t)
      debian_family noble http://archive.ubuntu.com/ubuntu main,universe "lsb-release,software-properties-common,rsyslog"
      rm -f "$ROOT/etc/apt/sources.list"
      cat > "$ROOT/etc/apt/sources.list.d/ubuntu.sources" <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
      ;;
    deb13t)
      debian_family trixie http://deb.debian.org/debian main "rsyslog"
      rm -f "$ROOT/etc/apt/sources.list"
      cat > "$ROOT/etc/apt/sources.list.d/debian.sources" <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
      ;;
    alma10t) almalinux ;;
    *) echo "unknown machine $NAME" >&2; exit 2 ;;
  esac
  # nspawn wants a machine-id to boot; an empty one is filled on first boot.
  : > "$ROOT/etc/machine-id"
  rm -f "$ROOT/etc/resolv.conf"
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$ROOT/etc/resolv.conf"
  echo "$NAME" > "$ROOT/etc/hostname"
  printf '127.0.0.1 localhost\n127.0.1.1 %s %s\n::1 localhost ip6-localhost ip6-loopback\n' "$NAME" "$DOMAIN" > "$ROOT/etc/hosts"
  mkdir -p /etc/systemd/nspawn
  printf '[Exec]\nPrivateUsers=no\n\n[Network]\nVirtualEthernet=yes\n' > "/etc/systemd/nspawn/$NAME.nspawn"
  grep PRETTY_NAME "$ROOT/etc/os-release"
  du -sh "$ROOT"
}

boot() {
  machinectl start "$NAME"
  for _ in $(seq 1 60); do
    systemd-run --machine="$NAME" --quiet --pipe --wait /bin/true > /dev/null 2>&1 && break
    sleep 1
  done
  if [ "$NAME" = alma10t ]; then
    # The host side's /28, and the next address in it for the machine.
    local host_cidr host_ip prefix last pid
    # The host's networkd gives its side an address once the link has a
    # carrier, and nothing inside AlmaLinux brings host0 up.
    pid="$(machinectl show "$NAME" -p Leader --value)"
    nsenter -t "$pid" -n ip link set host0 up
    for _ in $(seq 1 30); do
      host_cidr="$(ip -4 -o addr show "ve-$NAME" scope global 2>/dev/null | awk '{print $4}' | head -1)"
      [ -n "$host_cidr" ] && break
      sleep 1
    done
    [ -n "$host_cidr" ] || { echo "ve-$NAME got no address from the host" >&2; return 1; }
    host_ip="${host_cidr%/*}"
    prefix="${host_ip%.*}"
    last="${host_ip##*.}"
    nsenter -t "$pid" -n ip addr add "${prefix}.$((last + 1))/28" dev host0 2> /dev/null || true
    nsenter -t "$pid" -n ip route replace default via "$host_ip"
  fi
  for _ in $(seq 1 60); do
    if systemd-run --machine="$NAME" --quiet --pipe --wait /usr/bin/curl -fsS --max-time 5 -o /dev/null https://deb.debian.org/ > /dev/null 2>&1; then
      echo "$NAME is up: $(machinectl show "$NAME" -p Addresses --value 2>/dev/null || true)"
      systemd-run --machine="$NAME" --quiet --pipe --wait /bin/sh -c 'ip -4 -o addr show host0 | awk "{print \$4}"'
      return 0
    fi
    sleep 2
  done
  echo "$NAME booted but has no way out" >&2
  return 1
}

down() {
  machinectl terminate "$NAME" 2> /dev/null || true
  for _ in $(seq 1 30); do
    machinectl show "$NAME" > /dev/null 2>&1 || break
    sleep 1
  done
  rm -rf "$ROOT" "/etc/systemd/nspawn/$NAME.nspawn" "/var/log/debootstrap-$NAME.log"
}

case "$ACTION" in
  make) make ;;
  boot) boot ;;
  down) down ;;
  *) echo "usage: machine.sh make|boot|down <name>" >&2; exit 2 ;;
esac
