#!/usr/bin/env bash
# Build a Hosting Edition bundle: this checkout's source plus its release
# binaries, in the layout installer/update.sh installs from.
#
#   bash installer/hosting/make-bundle.sh            # on a build machine
#   -> dist/snpanel-hosting-<version>-<commit>.tar.gz (+ .sha256)
#
# Needs cargo with the x86_64-unknown-linux-musl target. The frontend is not
# built here: update.sh builds it on the server, as for every release.
set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$ROOT"
TARGET=x86_64-unknown-linux-musl
BINS=(snpanel-helper snpanel-extract snpanel-api snpanel snpanel-install)
ALLOW_DIRTY=0
CARGO_ARGS=(--release --locked)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --offline) CARGO_ARGS+=(--offline) ;;
    -h|--help) sed -n 2,9p "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ "$ALLOW_DIRTY" == 0 && -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "The checkout has uncommitted changes; commit them or pass --allow-dirty." >&2
  exit 1
fi

cargo build "${CARGO_ARGS[@]}" --target "$TARGET" \
  -p snpanel-helper -p snpanel-api -p snpanel-cli -p snpanel-installer

rev="$(git rev-parse --short=10 HEAD)"
version="$(tr -d '[:space:]' <VERSION)"
name="snpanel-hosting-${version}-${rev}"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
stage="$work/snpanel-hosting"
mkdir -p "$stage"

git archive --format=tar HEAD | tar -x -C "$stage"
mkdir -p "$stage/target/$TARGET/release"
for b in "${BINS[@]}"; do
  install -m 0755 "target/$TARGET/release/$b" "$stage/target/$TARGET/release/$b"
done
printf '%s\n' "$(git rev-parse HEAD)" >"$stage/HOSTING_BUILD"
( cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS )

mkdir -p dist
tar -czf "dist/$name.tar.gz" -C "$work" snpanel-hosting
( cd dist && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256" )
echo "dist/$name.tar.gz"
cat "dist/$name.tar.gz.sha256"
