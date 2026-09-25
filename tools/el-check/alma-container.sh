#!/bin/bash
# alma-container.sh up|down [name] [subnet] - a throwaway AlmaLinux 10 machine
# under systemd-nspawn, for the checks in this directory.
#
# `up` fetches the official almalinux:10 image from Docker Hub with nothing but
# curl - the registry's HTTP API: an anonymous pull token, the amd64 manifest,
# its layer, which for a distribution's base image is the root filesystem -
# boots it in a network namespace of its own, so nothing it does to nftables
# reaches the host, and gives it a way out through one masquerade rule.
# `down` removes the machine, its root filesystem and that rule.
#
# Needs root, systemd-nspawn, curl, python3 and nft on the host.
set -euo pipefail

ACTION="${1:?usage: alma-container.sh up|down [name] [subnet]}"
NAME="${2:-alma10check}"
SUBNET="${3:-10.24.0}"
ROOT="/var/lib/machines/$NAME"
IMAGE=library/almalinux
TAG=10

down() {
  machinectl terminate "$NAME" 2>/dev/null || true
  for _ in $(seq 1 20); do
    machinectl show "$NAME" > /dev/null 2>&1 || break
    sleep 0.5
  done
  nft -a list chain ip nspawnnat post 2>/dev/null \
    | awk -v s="saddr $SUBNET.0/24 " 'index($0, s) {print $NF}' \
    | while read -r handle; do nft delete rule ip nspawnnat post handle "$handle"; done \
    || true
  ip link del "ve-$NAME" 2> /dev/null || true
  rm -rf "$ROOT" "/var/log/nspawn-$NAME.log"
}

fetch() {
  local work token manifest digest
  work="$(mktemp -d)"
  token="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${IMAGE}:pull" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  manifest() {
    curl -fsSL -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      "https://registry-1.docker.io/v2/${IMAGE}/manifests/$1"
  }
  manifest "$TAG" > "$work/index.json"
  # An index names one manifest per architecture; a plain manifest names layers.
  digest="$(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
print(next((m["digest"] for m in d.get("manifests", [])
            if m.get("platform", {}).get("architecture") == "amd64"), ""))' "$work/index.json")"
  if [ -n "$digest" ]; then manifest "$digest" > "$work/index.json"; fi
  mkdir -p "$ROOT"
  python3 -c 'import json,sys; [print(l["digest"]) for l in json.load(open(sys.argv[1]))["layers"]]' "$work/index.json" \
    | while read -r layer; do
        curl -fsSL -H "Authorization: Bearer $token" \
          "https://registry-1.docker.io/v2/${IMAGE}/blobs/${layer}" | tar -xz -C "$ROOT"
      done
  rm -rf "$work"
}

up() {
  down
  fetch
  grep PRETTY_NAME "$ROOT/etc/os-release"
  # A container image has no machine-id, which nspawn wants before it boots,
  # and whatever resolv.conf its build host had.
  : > "$ROOT/etc/machine-id"
  rm -f "$ROOT/etc/resolv.conf"
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$ROOT/etc/resolv.conf"

  systemd-nspawn --directory="$ROOT" --machine="$NAME" --boot \
    --private-network --network-veth --capability=CAP_NET_ADMIN,CAP_NET_RAW \
    > "/var/log/nspawn-$NAME.log" 2>&1 &
  for _ in $(seq 1 60); do
    machinectl show "$NAME" > /dev/null 2>&1 && ip link show "ve-$NAME" > /dev/null 2>&1 && break
    sleep 1
  done

  # The image has no iproute2 and no networkd: the host's `ip`, inside the
  # machine's network namespace, brings it up.
  local pid
  pid="$(machinectl show "$NAME" -p Leader --value)"
  ip addr add "$SUBNET.1/24" dev "ve-$NAME" 2> /dev/null || true
  ip link set "ve-$NAME" up
  nsenter -t "$pid" -n ip addr add "$SUBNET.2/24" dev host0 2> /dev/null || true
  nsenter -t "$pid" -n ip link set host0 up
  nsenter -t "$pid" -n ip route replace default via "$SUBNET.1"

  if [ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]; then
    echo "note: turning on net.ipv4.ip_forward, which the machine needs to get out"
    sysctl -qw net.ipv4.ip_forward=1
  fi
  nft list table ip nspawnnat > /dev/null 2>&1 || nft add table ip nspawnnat
  nft list chain ip nspawnnat post > /dev/null 2>&1 \
    || nft add chain ip nspawnnat post '{ type nat hook postrouting priority srcnat; }'
  nft add rule ip nspawnnat post ip saddr "$SUBNET.0/24" masquerade

  for _ in $(seq 1 30); do
    systemd-run --machine="$NAME" --pipe --quiet /usr/bin/curl -fsS --max-time 5 -o /dev/null \
      https://repo.almalinux.org/ 2> /dev/null && { echo "$NAME is up at $SUBNET.2"; return 0; }
    sleep 1
  done
  echo "$NAME booted but cannot reach repo.almalinux.org" >&2
  return 1
}

case "$ACTION" in
  up) up ;;
  down) down ;;
  *) echo "usage: alma-container.sh up|down [name] [subnet]" >&2; exit 2 ;;
esac
