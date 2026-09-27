#!/bin/bash
# garage-setup.sh start|stop - a one-node Garage (https://garagehq.deuxfleurs.fr)
# on 127.0.0.1:3900 for the S3 tests: an S3 store that checks every
# signature, listings included. Prints the key it made as JSON on start.
set -euo pipefail
G=/opt/snpanel-probe/garage
D=/tmp/garage-test
C="$D/garage.toml"
case "${1:-start}" in
  stop)
    [ -f "$D/pid" ] && kill "$(cat "$D/pid")" 2>/dev/null || true
    rm -rf "$D"
    exit 0 ;;
esac
if [ ! -x "$G" ]; then
  mkdir -p "$(dirname "$G")"
  curl -sSfL --max-time 300 -o "$G.part" https://garagehq.deuxfleurs.fr/_releases/v1.1.0/x86_64-unknown-linux-musl/garage
  chmod 755 "$G.part"
  mv "$G.part" "$G"
fi
[ -f "$D/pid" ] && kill "$(cat "$D/pid")" 2>/dev/null || true
rm -rf "$D"
mkdir -p "$D/meta" "$D/data"
cat > "$C" <<EOF
metadata_dir = "$D/meta"
data_dir = "$D/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(openssl rand -hex 32)"
[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = ".s3.garage.localhost"
EOF
"$G" -c "$C" server > "$D/server.log" 2>&1 &
echo $! > "$D/pid"
for _ in $(seq 1 50); do
  "$G" -c "$C" status > /dev/null 2>&1 && break
  sleep 0.2
done
node=$("$G" -c "$C" node id -q | cut -d@ -f1)
"$G" -c "$C" layout assign -z dc1 -c 1G "$node" > /dev/null
"$G" -c "$C" layout apply --version 1 > /dev/null
"$G" -c "$C" key create panel-test > "$D/key.txt"
"$G" -c "$C" bucket create backups > /dev/null
"$G" -c "$C" bucket allow --read --write --owner backups --key panel-test > /dev/null
key=$(awk '/Key ID:/ {print $3}' "$D/key.txt")
secret=$(awk '/Secret key:/ {print $3}' "$D/key.txt")
printf '{"key":"%s","secret":"%s"}\n' "$key" "$secret"
