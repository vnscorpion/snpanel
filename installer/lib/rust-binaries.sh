# shellcheck shell=bash
# Fetching the Rust binaries, shared by install.sh and update.sh.
#
# Moved out of install.sh rather than copied into update.sh. The checksum
# check below is the only thing standing between a release asset fetched over
# the network and a binary that runs as root; two copies of it is two places
# for one of them to drift into being weaker.
#
# Sourced, not executed. The caller provides `log` and `fail`, and sets:
#
#   RUST_SOURCE_ROOT   a checkout to prefer locally built binaries from
#   SNPANEL_GITHUB     where releases come from
#
# and reads back `RUST_BIN_DIR` (empty when nothing is available) and
# `RUST_BIN_TMP` (a directory to clean up, when one was made).

RUST_BIN_DIR="${RUST_BIN_DIR:-}"
RUST_BIN_TMP="${RUST_BIN_TMP:-}"
RUST_ASSET_BASE="${RUST_ASSET_BASE:-snpanel-rust-x86_64-linux-musl}"
SNPANEL_GITHUB="${SNPANEL_GITHUB:-https://github.com/vnscorpion/snpanel}"

# Every binary the archive must carry.
#
# Checked as a set before anything is installed: an archive missing one is a
# broken release, and finding that out halfway through placing the others
# leaves a box with a mismatched pair.
RUST_REQUIRED_BINARIES=(snpanel-helper snpanel-extract snpanel-api snpanel)

resolve_release_tag() {
  local tag="${SNPANEL_VERSION:-}"
  if [[ -z "$tag" && -f "${RUST_SOURCE_ROOT}/VERSION" ]]; then
    tag="v$(tr -d '[:space:]' <"${RUST_SOURCE_ROOT}/VERSION")"
  fi
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s' "$tag"
}

fetch_rust_binaries() {
  # A tree that has been built wins. Somebody running this from a checkout is
  # testing what they built, and downloading a release over it would make the
  # run say nothing about their work.
  local built="${RUST_SOURCE_ROOT}/target/x86_64-unknown-linux-musl/release"
  if [[ -x "${built}/snpanel-helper" ]]; then
    RUST_BIN_DIR="$built"
    log "Using locally built Rust binaries from ${built}"
    return 0
  fi

  local tag
  if ! tag="$(resolve_release_tag)"; then
    log "No release tag to fetch Rust binaries for"
    return 1
  fi

  local base="${SNPANEL_RUST_ASSET_BASE:-${SNPANEL_GITHUB}/releases/download/${tag}}"
  local tmp archive sums
  tmp="$(mktemp -d)"
  archive="${tmp}/${RUST_ASSET_BASE}.tar.gz"
  sums="${tmp}/SHA256SUMS"

  if ! curl -fsSL --connect-timeout 10 --max-time 300 \
        "${base}/${RUST_ASSET_BASE}.tar.gz" -o "$archive"; then
    rm -rf -- "$tmp"
    log "No Rust binaries published for ${tag}"
    return 1
  fi
  # The checksum is not optional. These binaries run as root, and a release
  # asset is fetched over the network from a host this script does not
  # otherwise trust with anything.
  if ! curl -fsSL --connect-timeout 10 --max-time 60 "${base}/SHA256SUMS" -o "$sums"; then
    rm -rf -- "$tmp"
    fail "Rust binaries for ${tag} have no SHA256SUMS; refusing to install them"
  fi
  if ! ( cd "$tmp" && sha256sum --check --ignore-missing --status SHA256SUMS ); then
    rm -rf -- "$tmp"
    fail "The Rust binaries for ${tag} do not match their published checksums"
  fi
  if ! tar xzf "$archive" -C "$tmp"; then
    rm -rf -- "$tmp"
    fail "Could not unpack the Rust binaries for ${tag}"
  fi

  local unpacked="${tmp}/${RUST_ASSET_BASE}"
  [[ -d "$unpacked" ]] || unpacked="$tmp"
  local missing=()
  local name
  for name in "${RUST_REQUIRED_BINARIES[@]}"; do
    [[ -x "${unpacked}/${name}" ]] || missing+=("$name")
  done
  if (( ${#missing[@]} )); then
    rm -rf -- "$tmp"
    fail "The Rust archive for ${tag} is missing: ${missing[*]}"
  fi

  RUST_BIN_DIR="$unpacked"
  RUST_BIN_TMP="$tmp"
  log "Fetched Rust binaries for ${tag}"
}
