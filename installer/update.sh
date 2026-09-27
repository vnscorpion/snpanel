#!/usr/bin/env bash
# Update SNPanel from GitHub.
#
# By default this script downloads the newest stable release zip to a temporary
# directory, syncs the source into /opt/snpanel, rebuilds the frontend, refreshes
# helper scripts, restarts the API, and reloads nginx for customer vhosts. A git
# checkout is only used for --branch or --skip-pull development workflows.
#
# Usage:
#   sudo bash installer/update.sh
#   sudo bash installer/update.sh --branch main
#   sudo bash installer/update.sh --tag v1.0.57
#   sudo bash installer/update.sh --help

set -euo pipefail

log()  { echo ""; echo "==> $1"; }
fail() { echo "ERROR: $1" >&2; exit 1; }

# Skip expensive, idempotent steps when the inputs that drive them have not
# changed since the last successful update. State lives in /var/lib/snpanel so
# it survives everything except a fresh install.
SNPANEL_UPDATE_STATE_DIR=/var/lib/snpanel/update-state

fingerprint() {
  # fingerprint <path> [path ...] -> one sha256 over the contents of every
  # file under those paths (paths are stable, so hashing them too is fine).
  # Missing paths are skipped, not an error: if one later appears the hash
  # changes and the step re-runs. Returns non-zero only when nothing exists.
  local existing=() p
  for p in "$@"; do [[ -e "$p" ]] && existing+=("$p"); done
  [[ ${#existing[@]} -gt 0 ]] || return 1
  # Hash the content hashes only, not the "  <name>" sha256sum prints after
  # them: the same files under a different prefix (a release temp dir, or
  # /usr/local/sbin vs the source tree) must fingerprint the same.
  find "${existing[@]}" -type f -exec sha256sum {} + 2>/dev/null \
    | awk '{print $1}' | LC_ALL=C sort | sha256sum | awk '{print $1}'
}

step_inputs_changed() {
  # step_inputs_changed <name> <path> [path ...]
  # true (0) when the fingerprint differs from the stored one (or is forced).
  local name="$1"; shift
  [[ "${SNPANEL_FORCE_FULL_UPDATE:-}" == "1" ]] && return 0
  local now stored=""
  now="$(fingerprint "$@")" || return 0
  [[ -n "$now" ]] || return 0
  [[ -f "$SNPANEL_UPDATE_STATE_DIR/$name" ]] && stored="$(cat "$SNPANEL_UPDATE_STATE_DIR/$name" 2>/dev/null)"
  [[ "$now" != "$stored" ]]
}

step_mark_done() {
  # step_mark_done <name> <path> [path ...] - call only after the step succeeded
  local name="$1"; shift
  local now; now="$(fingerprint "$@")" || return 0
  mkdir -p "$SNPANEL_UPDATE_STATE_DIR"
  printf '%s' "$now" >"$SNPANEL_UPDATE_STATE_DIR/$name"
}

usage() {
  cat <<'USAGE'
Usage:
  sudo bash installer/update.sh [--release]
  sudo bash installer/update.sh --tag v1.0.57
  sudo bash installer/update.sh --branch main

Options:
  --release          Update to the newest matching release tag (default).
  --tag TAG          Pin an exact release tag.
  --branch NAME      Update from a remote branch.
  --channel MODE     Set update mode: release, tag, or branch.
  --remote NAME      Git remote to fetch from or create on clone (default: origin).
  --skip-pull        Sync the current SOURCE_DIR without fetching/checking out.
  --app-dir DIR      Production deployment dir (default: /opt/snpanel).
  -h, --help         Show this help.

Environment:
  APP_DIR, SOURCE_DIR, REPO_URL, GIT_REMOTE, UPDATE_CHANNEL, BRANCH,
  RELEASE_TAG, RELEASE_PATTERN, RELEASE_ZIP_URL, SKIP_PULL.

Notes:
  The release channel selects the newest matching release tag and downloads a
  zip archive. Use --tag or UPDATE_CHANNEL=tag with RELEASE_TAG to pin a tag.
  Use RELEASE_ZIP_URL with {tag} only for non-GitHub archive URLs.
USAGE
}

require_arg() {
  local opt="$1" value="${2-}"
  [[ -n "$value" && "$value" != --* ]] || fail "$opt requires a value"
}

for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    usage
    exit 0
  fi
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

if [[ -z "${SNPANEL_UPDATE_STABLE_COPY:-}" ]]; then
  _original_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  _stable_copy="$(mktemp /tmp/snpanel-update.XXXXXX.sh)"
  cp "$_original_script" "$_stable_copy"
  chmod 0700 "$_stable_copy"
  SNPANEL_UPDATE_STABLE_COPY="$_stable_copy" \
    SNPANEL_UPDATE_ORIGINAL_SCRIPT="$_original_script" \
    exec /bin/bash "$_stable_copy" "$@"
fi

cleanup_stable_copy() {
  rm -f "${SNPANEL_UPDATE_STABLE_COPY:-}" "${SNPANEL_UPDATE_PREVIOUS_COPY:-}" 2>/dev/null || true
}
trap cleanup_stable_copy EXIT

# --- Config ----------------------------------------------------------------
APP_DIR="${APP_DIR:-/opt/snpanel}"                 # Production deployment dir
DEFAULT_SOURCE_DIR="/opt/snpanel-source"           # Dev/branch checkout dir only

# The Rust API binary, and which unit serves the panel.
#
# Both facts, and they are different questions. Whether the *binary* exists
# gates the one-shots below - the site refresh, the orphan sweep - which talk
# to the database and the helper and work the same whichever process serves
# HTTP. Which unit to *restart* has only one right answer: the one that is
# serving.
#
# A box installed since the panel became the Rust binary has no
# `snpanel-rust` unit and falls through to `snpanel-api`, which runs that
# binary. One that cut over while both existed still has both.
#
# Restarting the wrong one is two failures at once. The change does not take
# effect, because the process serving the panel never reloaded it; and
# snpanel-api cannot bind the panel port while Rust holds it, so with
# Restart=always it loops forever. Measured on a cut-over box: NRestarts
# climbed to 4 in thirty seconds, running Alembic on every pass, and nothing
# looked wrong from outside because Rust kept answering.
RUST_API="${RUST_API:-/usr/local/bin/snpanel-api-rust}"

# Which `snpanel-install` to run a phase with.
#
# The one this update fetched wins: it is the release being installed, and a
# phase should write what that release says. The one already on the box is the
# fallback, and it is why `install.sh` puts it in /usr/local/sbin rather than
# leaving it in the release directory - an update that cannot reach the
# release still refreshes what it can, which is the tolerance this script has
# always had for the other binaries.
#
# Printing nothing when there is neither is deliberate: the caller runs
# `"$(phase_runner)"`, which then fails, and every call site treats that as a
# warning rather than a stop. A box with no phase runner at all is one that
# has never been installed.
phase_runner() {
  if [[ -n "${RUST_BIN_DIR:-}" && -x "${RUST_BIN_DIR}/snpanel-install" ]]; then
    printf '%s' "${RUST_BIN_DIR}/snpanel-install"
  else
    printf '%s' /usr/local/sbin/snpanel-install
  fi
}

panel_unit() {
  if systemctl is-enabled snpanel-rust >/dev/null 2>&1; then
    echo snpanel-rust
  else
    echo snpanel-api
  fi
}

restart_panel() {
  local unit
  unit="$(panel_unit)"
  systemctl restart "$unit"
}

# Resolve where THIS script lives. If it's inside a real git checkout we use
# that. Otherwise we fall back to /opt/snpanel-source so users running the
# script from the deploy dir still get a usable workflow.
_SCRIPT_SOURCE="${SNPANEL_UPDATE_ORIGINAL_SCRIPT:-${BASH_SOURCE[0]}}"
_SCRIPT_DIR="$(cd "$(dirname "$_SCRIPT_SOURCE")/.." && pwd)"
if [[ -d "$_SCRIPT_DIR/.git" ]]; then
  SOURCE_DIR="${SOURCE_DIR:-$_SCRIPT_DIR}"
else
  SOURCE_DIR="${SOURCE_DIR:-$DEFAULT_SOURCE_DIR}"
fi

# The per-distribution table, shared with the installer. Sourced from the tree
# being deployed, which is where it lives. An older tree - from before
# platform.sh existed - has none, so the Debian values stand in: that is the
# only platform such a tree could have been installed on.
if [[ -f "${SOURCE_DIR}/installer/platform.sh" ]]; then
  # shellcheck source=platform.sh
  source "${SOURCE_DIR}/installer/platform.sh"
  detect_platform >/dev/null
else
  OS_FAMILY="debian"
  WEB_USER="www-data"
  WEB_GROUP="www-data"
  pkg_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }
  pkg_update_index() { DEBIAN_FRONTEND=noninteractive apt-get update --allow-releaseinfo-change; }
fi

REPO_URL="${REPO_URL:-https://github.com/vnscorpion/snpanel.git}"
GIT_REMOTE="${GIT_REMOTE-origin}"                 # remote name in the local checkout
UPDATE_CHANNEL="${UPDATE_CHANNEL-release}"        # release, branch, or tag
BRANCH="${BRANCH-main}"                           # used when UPDATE_CHANNEL=branch
RELEASE_TAG="${RELEASE_TAG-}"                     # used when UPDATE_CHANNEL=tag
RELEASE_PATTERN="${RELEASE_PATTERN:-v[0-9]*.[0-9]*.[0-9]*}"
RELEASE_ZIP_URL="${RELEASE_ZIP_URL:-}"             # optional archive URL template with {tag}
SKIP_PULL="${SKIP_PULL:-false}"
UPDATE_STATE_FILE="${UPDATE_STATE_FILE:-/var/lib/snpanel/update-status.json}"
RELEASE_WORK_DIR="${RELEASE_WORK_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel) require_arg "$1" "${2-}"; UPDATE_CHANNEL="$2"; shift 2 ;;
    --release) UPDATE_CHANNEL="release"; shift ;;
    --branch) require_arg "$1" "${2-}"; UPDATE_CHANNEL="branch"; BRANCH="$2"; shift 2 ;;
    --tag) require_arg "$1" "${2-}"; UPDATE_CHANNEL="tag"; RELEASE_TAG="$2"; shift 2 ;;
    --remote) require_arg "$1" "${2-}"; GIT_REMOTE="$2"; shift 2 ;;
    --skip-pull) SKIP_PULL="true"; shift ;;
    --app-dir) require_arg "$1" "${2-}"; APP_DIR="$2"; shift 2 ;;
    -h|--help)
      usage
      exit 0 ;;
    *) fail "Unknown arg: $1" ;;
  esac
done

# --- Validate config --------------------------------------------------------
require_git_ref_name() {
  local kind="$1" value="$2"
  [[ -n "$value" ]] || fail "$kind cannot be empty"
  [[ "$value" != -* ]] || fail "$kind must not start with '-'"
  case "$kind" in
    BRANCH)
      git check-ref-format --branch "$value" >/dev/null 2>&1 \
        || fail "BRANCH has invalid git ref characters: $value"
      ;;
    RELEASE_TAG)
      git check-ref-format "refs/tags/$value" >/dev/null 2>&1 \
        || fail "RELEASE_TAG has invalid git ref characters: $value"
      ;;
  esac
}

[[ -n "$REPO_URL" ]] || fail "REPO_URL cannot be empty"
[[ -n "$GIT_REMOTE" ]] || fail "GIT_REMOTE cannot be empty"
[[ "$GIT_REMOTE" != -* ]] || fail "GIT_REMOTE must not start with '-'"
if ! [[ "$GIT_REMOTE" =~ ^[A-Za-z0-9._-]+$ ]]; then
  fail "GIT_REMOTE must match [A-Za-z0-9._-]+ (got: $GIT_REMOTE)"
fi
if [[ "$UPDATE_CHANNEL" != "release" && "$UPDATE_CHANNEL" != "branch" && "$UPDATE_CHANNEL" != "tag" ]]; then
  fail "UPDATE_CHANNEL must be release|branch|tag (got: $UPDATE_CHANNEL)"
fi
[[ "$SKIP_PULL" == "true" || "$SKIP_PULL" == "false" ]] || fail "SKIP_PULL must be true|false"
if [[ "$UPDATE_CHANNEL" == "branch" ]]; then
  require_git_ref_name BRANCH "$BRANCH"
fi
if [[ "$UPDATE_CHANNEL" == "tag" ]]; then
  require_git_ref_name RELEASE_TAG "$RELEASE_TAG"
fi
if [[ "$UPDATE_CHANNEL" == "release" && -n "$RELEASE_TAG" ]]; then
  echo "INFO: ignoring RELEASE_TAG in release channel; use --tag to pin ${RELEASE_TAG}."
fi

env_get() {
  local file="$APP_DIR/backend/.env" key="$1"
  [[ -f "$file" ]] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

env_set_default() {
  local file="$APP_DIR/backend/.env" key="$1" value="$2"
  if ! grep -q "^${key}=" "$file"; then
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

env_set() {
  # Replace a value, or add it if the key is new. Written through a temporary
  # file and copied back so the .env keeps its owner and its 0640 mode.
  local file="$APP_DIR/backend/.env" key="$1" value="$2" tmp
  [[ -f "$file" ]] || return 0
  tmp="$(mktemp)"
  KEY="$key" VALUE="$value" awk '
    BEGIN { key = ENVIRON["KEY"]; value = ENVIRON["VALUE"]; written = 0 }
    index($0, key "=") == 1 { if (!written) { print key "=" value; written = 1 } next }
    { print }
    END { if (!written) print key "=" value }
  ' "$file" >"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}

ensure_git_remote() {
  if git remote get-url "$GIT_REMOTE" >/dev/null 2>&1; then
    return 0
  fi
  log "Adding git remote ${GIT_REMOTE} -> ${REPO_URL}"
  git remote add "$GIT_REMOTE" "$REPO_URL"
}

latest_release_tag() {
  git ls-remote --tags --refs "$REPO_URL" "refs/tags/${RELEASE_PATTERN}" \
    | awk '{ sub("refs/tags/", "", $2); print $2 }' \
    | sort -V \
    | tail -n 1
}

release_archive_url() {
  local tag="$1" repo="$REPO_URL" base
  if [[ -n "$RELEASE_ZIP_URL" ]]; then
    printf '%s\n' "${RELEASE_ZIP_URL//\{tag\}/$tag}"
    return 0
  fi
  case "$repo" in
    https://github.com/*)
      base="${repo%.git}"
      ;;
    git@github.com:*)
      base="https://github.com/${repo#git@github.com:}"
      base="${base%.git}"
      ;;
    *)
      fail "Cannot derive release zip URL from REPO_URL. Set RELEASE_ZIP_URL or use --branch."
      ;;
  esac
  printf '%s/archive/refs/tags/%s.zip\n' "$base" "$tag"
}

download_release_source() {
  local tag="$1" archive extract_dir archive_url
  RELEASE_WORK_DIR="$(mktemp -d /tmp/snpanel-release-update.XXXXXX)"
  archive="${RELEASE_WORK_DIR}/snpanel-release.zip"
  extract_dir="${RELEASE_WORK_DIR}/extract"
  archive_url="$(release_archive_url "$tag")"
  log "Downloading release ${tag}"
  curl -fL --connect-timeout 10 --max-time 300 "$archive_url" -o "$archive"
  mkdir -p "$extract_dir"
  unzip -q "$archive" -d "$extract_dir"
  SOURCE_DIR="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR/backend" && -d "$SOURCE_DIR/frontend" ]] \
    || fail "Release archive does not contain backend/frontend source"
}

reset_worktree_to_ref() {
  local ref="$1" branch_name="${2-}"
  if [[ -n "$branch_name" ]]; then
    git checkout -f -B "$branch_name" "$ref"
  else
    git checkout -f --detach "$ref"
  fi
  git reset --hard "$ref"
}

current_panel_version() {
  if [[ -f "$APP_DIR/VERSION" ]]; then
    tr -d '[:space:]' <"$APP_DIR/VERSION"
    return 0
  fi
  # Older boxes kept it in backend/app/core/version.py; that file is gone
  # with the rest of the Python, and $APP_DIR/VERSION above is authoritative.
  return 1
}

write_update_state() {
  local status="$1" ref="${2:-}" message="${3:-}" now current latest
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  current="$(current_panel_version)"
  latest="${ref#v}"
  [[ "$latest" == "$ref" ]] && latest=""
  install -d -m 0750 "$(dirname "$UPDATE_STATE_FILE")"
  python3 - "$UPDATE_STATE_FILE" "$status" "$ref" "$latest" "$current" "$message" "$now" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
status, ref, latest, current, message, now = sys.argv[2:8]
try:
    state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
except Exception:
    state = {}

if current:
    state["current_version"] = current
if latest:
    state["latest_tag"] = ref
    state["latest_version"] = latest
state["last_update_status"] = status
if ref:
    state["last_update_ref"] = ref
if message:
    state["last_update_message"] = message
if status in {"checking", "updating"}:
    state["last_update_started_at"] = now
elif status in {"completed", "failed"}:
    state["last_update_finished_at"] = now
path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  if id -u snpanel >/dev/null 2>&1; then
    chown snpanel:snpanel "$UPDATE_STATE_FILE" 2>/dev/null || true
  fi
  chmod 0640 "$UPDATE_STATE_FILE" 2>/dev/null || true
}

# Write progress markers (percent / phase / message) into the update state file
# without touching the existing status/version fields. Safe to call at any time.
update_progress() {
  local percent="$1" phase="$2" message="${3:-}"
  install -d -m 0750 "$(dirname "$UPDATE_STATE_FILE")"
  python3 - "$UPDATE_STATE_FILE" "$percent" "$phase" "$message" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
percent, phase, message = sys.argv[2:5]
try:
    state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
except Exception:
    state = {}
try:
    state["progress_percent"] = int(percent)
except (ValueError, TypeError):
    state["progress_percent"] = 0
if phase:
    state["progress_phase"] = phase
if message:
    state["progress_message"] = message
path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  if id -u snpanel >/dev/null 2>&1; then
    chown snpanel:snpanel "$UPDATE_STATE_FILE" 2>/dev/null || true
  fi
  chmod 0640 "$UPDATE_STATE_FILE" 2>/dev/null || true
}

UPDATE_REF=""
cleanup_release_work_dir() {
  if [[ -n "${RELEASE_WORK_DIR:-}" && -d "$RELEASE_WORK_DIR" ]]; then
    rm -rf -- "$RELEASE_WORK_DIR"
  fi
}

finish_update_script() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    local cur_pct=0
    if [[ -f "$UPDATE_STATE_FILE" ]]; then
      cur_pct="$(python3 - "$UPDATE_STATE_FILE" <<'PY' 2>/dev/null || true
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("progress_percent", 0))
except Exception:
    print(0)
PY
)"
    fi
    update_progress "${cur_pct:-0}" "failed" "Update failed with exit code ${rc}" || true
    write_update_state "failed" "${UPDATE_REF:-}" "Update failed with exit code ${rc}" || true
  fi
  cleanup_release_work_dir
  cleanup_stable_copy
}
trap finish_update_script EXIT

# Trap ERR so any failing command records a failed progress marker. With
# `set -e` the EXIT trap above performs the actual state write; this is a
# secondary safety net for non-fatal paths that call `|| true`/return codes.
trap 'update_progress "${progress_percent:-0}" "failed" "Update failed at phase: ${progress_phase:-unknown}" 2>/dev/null || true' ERR

detect_server_ip() {
  hostname -I 2>/dev/null | awk '{print $1}' || true
}

remove_filebrowser_runtime() {
  systemctl disable --now filebrowser 2>/dev/null || true
  rm -f /etc/systemd/system/filebrowser.service
  rm -rf /etc/systemd/system/filebrowser.service.d
  rm -rf /etc/filebrowser /var/lib/filebrowser
  rm -f /usr/local/bin/filebrowser
  sed -i '/^FILEBROWSER_PORT=/d' "$APP_DIR/backend/.env" 2>/dev/null || true
  systemctl daemon-reload
}

ensure_panel_https() {
  # The panel takes an admin password and hands out a session token, so it has
  # no business answering in the clear. A server with no domain has nothing a
  # certificate authority will sign, so it gets a self-signed certificate: a
  # warning the operator clicks through once beats a password on the wire.
  local panel_port="$1" server_ip="$2" cert key host mode live_dir
  cert="$(env_get PANEL_SSL_CERT)"
  key="$(env_get PANEL_SSL_KEY)"
  host="$(env_get PANEL_DOMAIN)"
  mode="$(env_get PANEL_SSL_MODE)"

  # If the panel answers on a domain that already has a real certificate, use
  # it: a name the browser trusts beats one it warns about, and there is nothing
  # to choose between when the panel's own hostname is the domain in question.
  live_dir="/etc/letsencrypt/live/${host}"
  if [[ -n "$host" && -f "${live_dir}/fullchain.pem" && -f "${live_dir}/privkey.pem" \
        && "$mode" != "letsencrypt" && "$mode" != "domain" ]]; then
    log "Panel domain ${host} already has a certificate; using it"
    install -d -o root -g snpanel -m 0750 /etc/snpanel
    install -m 0640 -o root -g snpanel "${live_dir}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
    install -m 0640 -o root -g snpanel "${live_dir}/privkey.pem" /etc/snpanel/panel-privkey.pem
    env_set PANEL_SSL_CERT "/etc/snpanel/panel-fullchain.pem"
    env_set PANEL_SSL_KEY "/etc/snpanel/panel-privkey.pem"
    env_set PANEL_SSL_MODE "domain"
    env_set PANEL_URL "https://${host}:${panel_port}"
    env_set ALLOWED_ORIGINS "https://${host}:${panel_port}"
    PANEL_SWITCHED_TO_HTTPS="https://${host}:${panel_port}"
    return 0
  fi

  if [[ -n "$cert" && -n "$key" && -f "$cert" && -f "$key" ]]; then
    return 0
  fi
  host="${host:-${server_ip:-127.0.0.1}}"
  echo "==> Panel has no certificate; generating a self-signed one"
  install -d -o root -g snpanel -m 0750 /etc/snpanel
  local san="DNS:${host}"
  [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && san="IP:${host}"
  [[ -n "$server_ip" && "$server_ip" != "$host" ]] && san="${san},IP:${server_ip}"
  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout /etc/snpanel/panel-selfsigned-privkey.pem \
      -out /etc/snpanel/panel-selfsigned-fullchain.pem \
      -subj "/CN=${host}" -addext "subjectAltName=${san}" >/dev/null 2>&1; then
    echo "    Could not generate a certificate; leaving the panel on HTTP" >&2
    return 0
  fi
  chown root:snpanel /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
  chmod 0640 /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
  env_set PANEL_SSL_CERT "/etc/snpanel/panel-selfsigned-fullchain.pem"
  env_set PANEL_SSL_KEY "/etc/snpanel/panel-selfsigned-privkey.pem"
  env_set PANEL_SSL_MODE "selfsigned"
  env_set PANEL_URL "https://${host}:${panel_port}"
  env_set ALLOWED_ORIGINS "https://${host}:${panel_port}"
  PANEL_SWITCHED_TO_HTTPS="https://${host}:${panel_port}"
}

write_tools_nginx_config() {
  local panel_cert panel_key panel_domain server_ip panel_port host
  # These are `.env` keys, not shell variables - this script never sets them
  # in its own environment, so they have to be read out of the file the way
  # the bash that used to be here read them.
  panel_cert="$(env_get PANEL_SSL_CERT)"
  panel_key="$(env_get PANEL_SSL_KEY)"
  panel_domain="$(env_get PANEL_DOMAIN)"
  panel_port="$(env_get PANEL_PORT)"; panel_port="${panel_port:-2222}"
  server_ip="$(detect_server_ip)"
  host="${panel_domain:-$server_ip}"

  # `snpanel-install tools-vhost`. The block is
  # `snpanel_installer::tools_vhost`, with a fixture for each of its two
  # shapes - with a panel certificate and without.
  #
  # The certificate has to be on disk and not only named in `.env`: an
  # `ssl_certificate` pointing at a file that is not there stops nginx from
  # starting at all, which takes every site on the box with it.
  PANEL_SSL_CERT="$panel_cert" PANEL_SSL_KEY="$panel_key" \
  PHPMYADMIN_ROOT="${PHPMYADMIN_ROOT:-/usr/share/phpmyadmin}" \
  PHP_DEFAULT="${PHP_DEFAULT:-8.4}" \
    "$(phase_runner)" tools-vhost \
    || fail "Could not write the tools vhost"

  # `snpanel-install phpmyadmin-signon`, which was the three `sed -i -E` calls
  # that used to sit at the end of this function: the address the sign-on shim
  # posts its token to, the `secure` flag on its cookie, and phpMyAdmin's
  # `PmaAbsoluteUri`. The substitutions are `snpanel_core::phpmyadmin`, and
  # they are checked row by row against what GNU `sed` produced.
  #
  # Never fatal, the same as the `|| true` on each of the three. phpMyAdmin is
  # optional and an update has other work to finish.
  PANEL_PORT="$panel_port" PANEL_DOMAIN="$panel_domain" SERVER_IP="$server_ip" \
  PANEL_SSL_CERT="$panel_cert" PANEL_SSL_KEY="$panel_key" \
  PHPMYADMIN_ROOT="${PHPMYADMIN_ROOT:-/usr/share/phpmyadmin}" \
  PHPMYADMIN_CONF_DIR="${PHPMYADMIN_CONF_DIR:-/etc/phpmyadmin}" \
    "$(phase_runner)" phpmyadmin-signon \
    || log "Could not update phpMyAdmin's single-sign-on shim"
  : "$host"
}

configure_fastcgi_cache() {
  # `snpanel-install nginx-conf` writes both this and the WebSocket upgrade
  # map, which `configure_proxy_upgrade_map` used to write - that function is
  # gone rather than left empty. Both files have golden fixtures.
  #
  # The map is not optional: without it a `proxy_set_header Connection
  # $connection_upgrade` in any site config makes nginx refuse to start.
  "$(phase_runner)" nginx-conf \
    || fail "Could not write the shared nginx configuration"
}

migrate_nginx_wordpress_csp_worker_src() {
  # `snpanel-install migrate-csp`, which was embedded `python3` here. What to
  # write is `snpanel_installer::update::migrations::csp`, pinned to a corpus
  # taken from real policies - this edits vhosts an operator did not ask it to
  # touch, so being nearly right is not good enough.
  #
  # Not fatal: a box whose editor still blocks workers is a box with a
  # cosmetic fault, and stopping the update over it would be worse.
  "$(phase_runner)" migrate-csp || \
    echo "WARNING: could not migrate the Content-Security-Policy in existing vhosts"
}

# Cron lines written before the PHP pinning fix call a bare `php`, which
# resolves through /etc/alternatives to the newest installed version instead of
# the version the website runs on, and carry shell-quoted redirections such as
# '>/dev/null' that never redirect anything. Repair both in place.
migrate_site_cron_php_binary() {
  local db_path="$APP_DIR/backend/snpanel.db"
  [[ -f "$db_path" ]] || return 0
  [[ -d /var/spool/cron/crontabs ]] || return 0
  SNPANEL_DB_PATH="$db_path" python3 - <<'PY'
import os
import re
import shlex
import sqlite3
import subprocess
from pathlib import Path

PHP_VERSION_RE = re.compile(r"^\d\.\d$")
INTERPRETER_RE = re.compile(r"(&&\s+)((?:/usr/bin/)?php(?:\d\.\d)?)(\s)")
MARKER_RE = re.compile(r"#\s*snpanel:([a-z0-9.\-]{3,253})\s*$")
QUOTED_REDIRECT_RE = re.compile(r"""\s'((?:\d?>>?|\d?>&\d)[^']*)'""")

php_versions = {}
with sqlite3.connect(f"file:{os.environ['SNPANEL_DB_PATH']}?mode=ro", uri=True) as db:
    for domain, php_version in db.execute("select domain, php_version from websites"):
        php_versions[(domain or "").lower()] = (php_version or "").strip()


def php_binary(domain):
    version = php_versions.get(domain, "")
    if not PHP_VERSION_RE.fullmatch(version):
        return None
    candidate = f"/usr/bin/php{version}"
    return candidate if Path(candidate).exists() else None


for spool in sorted(Path("/var/spool/cron/crontabs").iterdir()):
    if not spool.is_file():
        continue
    try:
        original = spool.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    lines = original.splitlines()
    changed = False
    for index, line in enumerate(lines):
        marker = MARKER_RE.search(line)
        if not marker:
            continue
        new_line = line
        # Unquote redirections so /bin/sh treats them as syntax again.
        new_line = QUOTED_REDIRECT_RE.sub(lambda match: " " + match.group(1), new_line)
        binary = php_binary(marker.group(1).lower())
        if binary:
            new_line = INTERPRETER_RE.sub(
                lambda match: f"{match.group(1)}{shlex.quote(binary)}{match.group(3)}",
                new_line,
                count=1,
            )
        if new_line != line:
            lines[index] = new_line
            changed = True
    if not changed:
        continue
    content = "\n".join(lines) + "\n"
    result = subprocess.run(
        ["runuser", "-u", spool.name, "--", "crontab", "-"],
        input=content,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        print(f"Repaired snpanel cron entries for {spool.name}")
    else:
        print(f"WARNING: could not rewrite crontab for {spool.name}: {result.stderr.strip()}")
PY
}

ensure_terminal_tools() {
  local missing=()
  command -v composer >/dev/null 2>&1 || missing+=(composer)
  command -v zip >/dev/null 2>&1 || missing+=(zip)
  command -v unzip >/dev/null 2>&1 || missing+=(unzip)
  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Installing terminal/file-manager tools: ${missing[*]}"
    pkg_update_index
    pkg_install "${missing[@]}"
  fi
}

harden_existing_panel_users() {
  local user home_dir site_dir secret
  getent group snpanel-sftp >/dev/null || return 0
  chown root:root /home
  chmod 0711 /home
  chmod a-s /home 2>/dev/null || true
  chmod -t /home 2>/dev/null || true
  while IFS= read -r user; do
    [[ -n "$user" ]] || continue
    case "$user" in
      root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|_apt|nobody|snpanel|snpanel-sites|snpanel-sftp|mysql|redis|nginx)
        continue ;;
    esac
    id -u "$user" >/dev/null 2>&1 || continue
    getent group "$user" >/dev/null || groupadd "$user" 2>/dev/null || true
    usermod -aG "$user" "$WEB_USER" 2>/dev/null || true
    home_dir="/home/$user"
    usermod --home "$home_dir" --shell /usr/sbin/nologin --gid "$user" "$user" 2>/dev/null || true
    mkdir -p "$home_dir"
    chown "root:$user" "$home_dir"
    chmod 0751 "$home_dir"
    chmod a-s "$home_dir" 2>/dev/null || true
    chmod -t "$home_dir" 2>/dev/null || true
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -b -k "$home_dir" 2>/dev/null || true
    fi
    find "$home_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | while IFS= read -r -d '' site_dir; do
      [[ "$(basename "$site_dir")" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || continue
      chown -R "$user:snpanel-sites" "$site_dir" 2>/dev/null || true
      if command -v setfacl >/dev/null 2>&1; then
        setfacl -Rb "$site_dir" 2>/dev/null || true
        find "$site_dir" -type d -exec setfacl -k {} + 2>/dev/null || true
      fi
      find "$site_dir" -type d -exec chmod 755 {} + 2>/dev/null || true
      find "$site_dir" -type d -exec chmod a-s {} + 2>/dev/null || true
      find "$site_dir" -type d -exec chmod -t {} + 2>/dev/null || true
      find "$site_dir" -type f -exec chmod 644 {} + 2>/dev/null || true
      for secret in wp-config.php .env .my.cnf; do
        find "$site_dir" -type f -name "$secret" -exec chmod 640 {} + 2>/dev/null || true
      done
    done
    if [[ -d "/var/lib/php/uploads/$user" ]]; then
      chown "$user:snpanel-sites" "/var/lib/php/uploads/$user" 2>/dev/null || true
      chmod 2700 "/var/lib/php/uploads/$user" 2>/dev/null || true
      chmod g+s "/var/lib/php/uploads/$user" 2>/dev/null || true
    fi
  done < <(getent group snpanel-sftp | awk -F: '{gsub(",", "\n", $4); print $4}')
}

install_panel_runtime() {
  local env_file="$APP_DIR/backend/.env"
  [[ -f "$env_file" ]] || return 0
  local panel_port panel_url server_ip
  panel_port="$(env_get PANEL_PORT)"
  panel_port="${panel_port:-2222}"
  server_ip="$(detect_server_ip)"
  panel_url="$(env_get PANEL_URL)"
  panel_url="${panel_url:-http://${server_ip:-127.0.0.1}:${panel_port}}"

  env_set_default PANEL_PORT "$panel_port"
  env_set_default PANEL_URL "$panel_url"
  env_set_default PANEL_DOMAIN ""
  env_set_default PANEL_SSL_CERT ""
  env_set_default PANEL_SSL_KEY ""
  env_set_default PANEL_SSL_MODE ""
  ensure_panel_https "$panel_port" "$server_ip"
  env_set_default FRONTEND_DIST "$APP_DIR/frontend/dist"
  env_set_default REDIS_URL "redis://localhost:6379/0"
  env_set_default RATE_LIMIT_BACKEND "redis"
  if [[ -z "$(env_get ALLOWED_ORIGINS)" ]]; then
    env_set_default ALLOWED_ORIGINS "$panel_url"
  fi

  remove_filebrowser_runtime

  getent group snpanel-sites >/dev/null || groupadd --system snpanel-sites
  getent group snpanel-sftp >/dev/null || groupadd --system snpanel-sftp
  if ! command -v setfacl >/dev/null 2>&1; then
    pkg_update_index
    pkg_install acl
  fi
  usermod -aG snpanel-sites snpanel 2>/dev/null || true
  usermod -aG snpanel-sites "$WEB_USER" 2>/dev/null || true
  # A recursive chown + four chmod sweeps over every file of every site. It
  # retrofits old installs to the current permission policy; once that policy
  # (which lives in this script) is applied it does not drift, so re-run it
  # only when the script itself changed. The panel sets permissions correctly
  # on every site it creates in between.
  if step_inputs_changed user-hardening "${SNPANEL_UPDATE_ORIGINAL_SCRIPT:-$SOURCE_DIR/installer/update.sh}"; then
    harden_existing_panel_users
    step_mark_done user-hardening "${SNPANEL_UPDATE_ORIGINAL_SCRIPT:-$SOURCE_DIR/installer/update.sh}"
  else
    echo "  (site directory permissions already match this release; skipping the sweep)"
  fi
  install -d -o root -g snpanel -m 2775 /etc/nginx/conf.d
  chmod g+s /etc/nginx/conf.d 2>/dev/null || true
  install -d -o root -g snpanel -m 2775 /etc/nginx/snpanel/custom
  chmod g+s /etc/nginx/snpanel/custom 2>/dev/null || true
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel /var/lib/snpanel/geoip
  # DirectAdmin import staging dirs
  install -d -o snpanel -g snpanel -m 0750 /home/admin/snpanel_backups/da
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel/da-import
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel/import-stage
  # `snpanel-install sftp-access`, the third copy of this edit to go. The
  # splice, the `sshd -t` and the rollback are `runtime::apply_sftp_block`,
  # shared with `install.sh` and `snpanel fix-permissions`.
  #
  # A warning here and fatal in the installer, which is the difference that
  # has always been between them: an update has other work to finish, and
  # losing the SFTP block is a feature not working while stopping leaves the
  # box half-updated.
  "$(phase_runner)" sftp-access || \
    echo "WARNING: invalid SSHD configuration; skipped SNPanel SFTP password block"

  # `snpanel-install update-units`: seven unit files and one drop-in.
  #
  # Not `systemd-units`, which is the install's phase. That one also writes
  # `snpanel-api.service` and `enable --now`s it - and on a box that has cut
  # over to `snpanel-rust` that starts a second panel on the port the first
  # is already listening on. An update writes the drop-in instead, which is
  # what this script has always done.
  #
  # The seven come from the installer's own `unit_files`, so the two lists
  # cannot drift; a test asserts that and that the bodies are the same bytes.
  # Verified on the container against this block before it was removed: all
  # eight files identical.
  #
  # Both enables are inside the phase and neither is fatal, the same as the
  # `|| true` that was on them here.
  # `$panel_port`, not `$PANEL_PORT`. The heredoc this replaces interpolated
  # the upper-case name, which this script never sets: under `set -u` that
  # aborted the update at this line, having written nothing. It was reachable
  # on every path - the helper starts the update with `systemd-run` and nine
  # `Environment=` properties, and `PANEL_PORT` is not one of them - but it
  # has never shipped: the release on a box still has the older block, whose
  # `ExecStart` named a wrapper script and needed no port at all.
  BACKUP_ROOT="${BACKUP_ROOT:-}" APP_DIR="$APP_DIR" PANEL_PORT="$panel_port" \
    "$(phase_runner)" update-units \
    || fail "Could not write the panel's systemd units"
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/snpanel.conf /etc/nginx/sites-available/snpanel.conf 2>/dev/null || true
  write_tools_nginx_config
  # The platform's phpMyAdmin: EL's is /usr/share/phpMyAdmin, where the fixed
  # Debian path found nothing and the sign-on URL was never corrected.
  local signon="${PHPMYADMIN_ROOT:-/usr/share/phpmyadmin}/snpanel-signon.php"
  if [[ -f "$signon" ]]; then
    local scheme="http"
    if [[ -n "$(env_get PANEL_SSL_CERT)" && -n "$(env_get PANEL_SSL_KEY)" ]]; then
      scheme="https"
    fi
    sed -i -E "/api\/databases\/phpmyadmin-sso/s#'[^']+/api/databases/phpmyadmin-sso/'#'${scheme}://127.0.0.1:${panel_port}/api/databases/phpmyadmin-sso/'#" "$signon" || true
  fi
}

panel_healthcheck() {
  local port
  port="$(env_get PANEL_PORT)"
  port="${port:-2222}"
  curl -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:${port}/api/health" >/dev/null 2>&1 \
    || curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1
}

remove_panel_auto_update_timer() {
  systemctl disable --now snpanel-auto-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/snpanel-auto-update.service /etc/systemd/system/snpanel-auto-update.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
}

refresh_snpanel_mariadb_grants() {
  local defaults_file="$APP_DIR/.my.cnf"
  local mysql_bin
  mysql_bin="$(command -v mariadb || command -v mysql || true)"
  [[ -n "$mysql_bin" ]] || return 0
  local password
  password=""
  if [[ -f "$defaults_file" ]]; then
    password="$(awk -F= '
      /^\[client\]/ { in_client=1; next }
      /^\[/ { in_client=0 }
      in_client && $1 == "password" {
        value=$0; sub(/^[^=]*=/, "", value); gsub(/^"|"$/, "", value); print value; exit
      }
    ' "$defaults_file")"
  fi
  if [[ -z "$password" ]]; then
    password="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)"
  fi
  "$mysql_bin" <<SQL
CREATE USER IF NOT EXISTS 'snpanel'@'localhost' IDENTIFIED BY '${password}';
ALTER USER 'snpanel'@'localhost' IDENTIFIED BY '${password}';
GRANT ALL PRIVILEGES ON *.* TO 'snpanel'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
  cat >"$defaults_file" <<MYCNF
[client]
user=snpanel
password="${password}"
host=localhost

[mysqldump]
user=snpanel
password="${password}"
host=localhost
MYCNF
  chown snpanel:snpanel "$defaults_file"
  chmod 0600 "$defaults_file"
}

ensure_panel_runtime_ownership() {
  id -u snpanel >/dev/null 2>&1 || return 0
  [[ -d "$APP_DIR/backend" ]] && chown -R snpanel:snpanel "$APP_DIR/backend" 2>/dev/null || true
  [[ -d "$APP_DIR/frontend" ]] && chown -R snpanel:snpanel "$APP_DIR/frontend" 2>/dev/null || true
  [[ -f "$APP_DIR/.my.cnf" ]] && chown snpanel:snpanel "$APP_DIR/.my.cnf" 2>/dev/null || true
  [[ -f "$APP_DIR/.my.cnf" ]] && chmod 0600 "$APP_DIR/.my.cnf" 2>/dev/null || true
  [[ -d /var/lib/snpanel ]] && chown snpanel:snpanel /var/lib/snpanel 2>/dev/null || true
  [[ -d /var/lib/snpanel/geoip ]] && chown -R snpanel:snpanel /var/lib/snpanel/geoip 2>/dev/null || true
  [[ -d /var/lib/snpanel/assets ]] && chown -R snpanel:snpanel /var/lib/snpanel/assets 2>/dev/null || true
  # The two directory modes setup_panel_user gives. `rsync -a` hands both the
  # source tree's own - a release archive's 0755, a checkout's 0775 - and the
  # database inside backend/ is 0644: a backend/ others can enter is a
  # database others can read. The app directory is passed through, never
  # listed: the Node runtimes applications run on live under it.
  if [[ -d "$APP_DIR/backend" ]]; then chmod 0750 "$APP_DIR/backend"; fi
  if [[ -d "$APP_DIR" ]]; then chmod 0711 "$APP_DIR"; fi
  [[ -f "$APP_DIR/backend/.env" ]] && chmod 0640 "$APP_DIR/backend/.env"
}

# --- Snapshot the SQLite DB before doing anything ---------------------------
backup_db() {
  local db_path="$APP_DIR/backend/snpanel.db"
  if [[ ! -f "$db_path" ]]; then
    return 0
  fi
  local snap_dir="${BACKUP_ROOT:-/var/backups/snpanel}/db-snapshots"
  install -d -m 0750 "$snap_dir"
  if id -u snpanel >/dev/null 2>&1; then
    chown snpanel:snpanel "$snap_dir" 2>/dev/null || true
  fi
  local stamp
  stamp=$(date -u +%Y%m%d-%H%M%S)
  local snap="$snap_dir/snpanel-$stamp.db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db_path" ".backup '$snap'"
  else
    cp -a "$db_path" "$snap"
  fi
  echo "DB snapshot saved: $snap"
  # Keep the 10 most recent snapshots.
  ls -1t "$snap_dir"/snpanel-*.db 2>/dev/null | tail -n +11 | xargs -r rm -f
}

if [[ -n "${SNPANEL_UPDATE_STAGE2:-}" ]]; then
  log "Continuing with the updater shipped in this release"
else
  log "Backing up SQLite DB before update"
  backup_db
  write_update_state "checking" "" "Checking for SNPanel releases"
  update_progress 5 "checking" "Backing up SQLite DB before update"
fi

# --- Fetch source -----------------------------------------------------------
if [[ "$SKIP_PULL" == "true" ]]; then
  if [[ "$(readlink -f "$SOURCE_DIR")" == "$(readlink -f "$APP_DIR")" ]]; then
    fail "SOURCE_DIR ($SOURCE_DIR) and APP_DIR ($APP_DIR) must be different."
  fi
  UPDATE_REF="${SNPANEL_UPDATE_REF_OVERRIDE:-local:${SOURCE_DIR}}"
  write_update_state "updating" "$UPDATE_REF" "Syncing SNPanel from ${SOURCE_DIR}"
else
  case "$UPDATE_CHANNEL" in
    release)
      log "Checking latest release from ${REPO_URL}"
      RELEASE_TAG="$(latest_release_tag)"
      [[ -n "$RELEASE_TAG" ]] || fail "No release tags found matching $RELEASE_PATTERN"
      UPDATE_REF="$RELEASE_TAG"
      write_update_state "updating" "$UPDATE_REF" "Updating SNPanel from ${UPDATE_REF}"
      download_release_source "$RELEASE_TAG"
      echo "Release: ${RELEASE_TAG}"
      ;;
    tag)
      [[ -n "$RELEASE_TAG" ]] || fail "--tag requires a release tag"
      UPDATE_REF="$RELEASE_TAG"
      write_update_state "updating" "$UPDATE_REF" "Updating SNPanel from ${UPDATE_REF}"
      update_progress 15 "fetching" "Downloading release ${RELEASE_TAG}"
      download_release_source "$RELEASE_TAG"
      echo "Release: ${RELEASE_TAG}"
      ;;
    branch)
      if [[ "$(readlink -f "$SOURCE_DIR")" == "$(readlink -f "$APP_DIR")" ]]; then
        fail "SOURCE_DIR ($SOURCE_DIR) and APP_DIR ($APP_DIR) must be different."
      fi
      if [[ ! -d "$SOURCE_DIR/.git" ]]; then
        if [[ -e "$SOURCE_DIR" && -n "$(ls -A "$SOURCE_DIR" 2>/dev/null)" ]]; then
          source_backup="${SOURCE_DIR}.release-archive-$(date -u +%Y%m%d-%H%M%S)"
          log "Archiving non-git release source to ${source_backup}"
          cd /
          mv "$SOURCE_DIR" "$source_backup"
        fi
        log "Cloning ${REPO_URL} to ${SOURCE_DIR} with remote ${GIT_REMOTE}"
        git clone -o "$GIT_REMOTE" "$REPO_URL" "$SOURCE_DIR"
      fi
      cd "$SOURCE_DIR"
      ensure_git_remote
      remote_branch="${GIT_REMOTE}/${BRANCH}"
      log "Pulling latest from ${remote_branch}"
      update_progress 15 "fetching" "Pulling latest from ${remote_branch}"
      git fetch --prune "$GIT_REMOTE" "+refs/heads/${BRANCH}:refs/remotes/${GIT_REMOTE}/${BRANCH}" --tags
      UPDATE_REF="$remote_branch"
      write_update_state "updating" "$UPDATE_REF" "Updating SNPanel from ${UPDATE_REF}"
      reset_worktree_to_ref "$remote_branch" "$BRANCH"
      echo "HEAD: $(git rev-parse --short HEAD) - $(git log -1 --pretty=%s)"
      ;;
    *)
      fail "Unsupported UPDATE_CHANNEL: $UPDATE_CHANNEL"
      ;;
  esac
fi

# --- Validate ---------------------------------------------------------------
[[ -d "$SOURCE_DIR/backend"  ]] || fail "Missing $SOURCE_DIR/backend"
[[ -d "$SOURCE_DIR/frontend" ]] || fail "Missing $SOURCE_DIR/frontend"

# The installed updater is a copy of this file, and it used to be replaced at
# the very end. One failure anywhere before that point left the broken copy in
# place with no way to update past it — the updater could never fix itself.
# Refreshing it here, as soon as the new source is known good enough to read,
# means the next run always has the newer script.
if [[ -f "$SOURCE_DIR/installer/update.sh" ]]; then
  install -m 0755 -o root -g root "$SOURCE_DIR/installer/update.sh" /usr/local/sbin/snpanel-update
fi

# bash reads a script as it runs, which is why this one re-execs a copy of
# itself out of /tmp. That copy is the updater from the release before this
# one, so anything an update changes about updating itself only takes effect
# the next time somebody updates. The release that moved the panel onto its own
# start-up script showed how that ends: the new panel ran under the old command
# line, and SNI stayed off, until the server was updated a second time.
#
# The new source is on disk and has just been checked, so hand over to its
# updater here - once, guarded by SNPANEL_UPDATE_STAGE2. SOURCE_DIR is passed
# along already prepared, so the second stage fetches nothing again.
if [[ -z "${SNPANEL_UPDATE_STAGE2:-}" && -f "$SOURCE_DIR/installer/update.sh" ]] \
  && ! cmp -s "$SOURCE_DIR/installer/update.sh" "${SNPANEL_UPDATE_STABLE_COPY:-/nonexistent}"; then
  log "The updater changed in this release; continuing with the new one"
  update_progress 20 "syncing" "Handing over to the updater from ${UPDATE_REF:-the new release}"
  stage2_copy="$(mktemp /tmp/snpanel-update-stage2.XXXXXX.sh)"
  cp "$SOURCE_DIR/installer/update.sh" "$stage2_copy"
  chmod 0700 "$stage2_copy"
  # The command line was consumed by the argument loop at the top, so the
  # second stage takes its configuration from the environment. exec replaces
  # this process, so the EXIT trap here never runs: the second stage is handed
  # everything this one would have cleaned up.
  SNPANEL_UPDATE_STAGE2=1 \
  SNPANEL_UPDATE_STABLE_COPY="$stage2_copy" \
  SNPANEL_UPDATE_PREVIOUS_COPY="${SNPANEL_UPDATE_STABLE_COPY:-}" \
  SNPANEL_UPDATE_ORIGINAL_SCRIPT="$SOURCE_DIR/installer/update.sh" \
  SNPANEL_UPDATE_REF_OVERRIDE="${UPDATE_REF:-}" \
  RELEASE_WORK_DIR="${RELEASE_WORK_DIR:-}" \
  SOURCE_DIR="$SOURCE_DIR" \
  SKIP_PULL=true \
    exec /bin/bash "$stage2_copy"
fi

# --- The Rust binaries ------------------------------------------------------
#
# Fetched here rather than where they are installed, which is several hundred
# lines further down. Everything between the two that writes a managed file
# does it through `snpanel-install`, and a phase cannot run a binary that has
# not been fetched yet - the same ordering `install.sh` got wrong once and now
# has a test for.
#
# Only the fetch moves. Installing them stays where it was: replacing the
# panel's own binary is a restart, and doing it earlier would move that
# restart into the middle of the migrations.
#
# Failure is tolerated, as it always has been. `phase_runner` falls back to
# the copy already on the box, and an update that cannot reach the release
# still refreshes everything that does not come from one.
if [[ -f "$SOURCE_DIR/installer/lib/rust-binaries.sh" ]]; then
  RUST_SOURCE_ROOT="$SOURCE_DIR"
  # shellcheck source=lib/rust-binaries.sh
  source "$SOURCE_DIR/installer/lib/rust-binaries.sh"
  fetch_rust_binaries || log "No Rust binaries for this release; using the installed ones"
fi

# --- Sync code into APP_DIR -------------------------------------------------
log "Syncing source to $APP_DIR"
mkdir -p "$APP_DIR"

if command -v rsync >/dev/null 2>&1; then
  # --filter='protect ...' keeps the destination file even when --delete
  # would otherwise remove it because the source side doesn't have it. We use
  # this for runtime artefacts that the installer creates: .env,
  # snpanel.db, .my.cnf.
  rsync -a --delete \
    --filter='protect /.env' \
    --filter='protect /snpanel.db' \
    --filter='protect /.my.cnf' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$SOURCE_DIR/backend/" "$APP_DIR/backend/"
  rsync -a --delete \
    --filter='protect /node_modules' \
    --filter='protect /node_modules/**' \
    --filter='protect /dist' \
    --filter='protect /dist/**' \
    --filter='protect /.vite' \
    --filter='protect /.vite/**' \
    "$SOURCE_DIR/frontend/" "$APP_DIR/frontend/"
else
  cp -r "$SOURCE_DIR/backend/."  "$APP_DIR/backend/"
  cp -r "$SOURCE_DIR/frontend/." "$APP_DIR/frontend/"
fi
if [[ -f "$SOURCE_DIR/VERSION" ]]; then
  install -m 0644 "$SOURCE_DIR/VERSION" "$APP_DIR/VERSION"
fi
ensure_panel_runtime_ownership

log "Removing deprecated panel auto update timer"
remove_panel_auto_update_timer

# Defensive: if .env still doesn't exist (e.g. fresh deploy syncing on top of
# nothing), leave a clear error message.
if [[ ! -f "$APP_DIR/backend/.env" ]]; then
  fail "$APP_DIR/backend/.env is missing. Run installer/install.sh first or restore .env from backup."
fi
log "Installing direct panel runtime"
update_progress 25 "syncing" "Syncing source into ${APP_DIR}"
install_panel_runtime
log "Configuring Nginx FastCGI cache"
configure_fastcgi_cache
ensure_terminal_tools
# A box updated from a version that had one still carries it. Nothing runs
# out of it any more, and leaving several hundred megabytes of dead Python on
# every machine to avoid one `rm` would be the wrong trade.
if [[ -d "$APP_DIR/backend/.venv" ]]; then
  log "Removing the Python virtualenv; the panel is the Rust binary now"
  rm -rf "$APP_DIR/backend/.venv"
fi

# --- Refresh helper + sudoers (idempotent) ---------------------------------
# --- Rust binaries ---------------------------------------------------------
#
# Until now an update refreshed the Python and left every Rust binary alone.
# On a cut-over box that means the panel itself - snpanel-rust runs the
# installed binary, so an updated box went on serving the code it was
# installed with, indefinitely, with nothing saying so.
#
# Only the API binary and the CLI are refreshed here. The Rust *helper* is
# deliberately left alone: which path it occupies depends on
# whether that cutover has been done, and the arrangement below already
# threads that needle for the bash fallback. Replacing the privileged binary
# on the same pass is a separate change with its own failure modes.
# The binaries were fetched much earlier, so the phases between here and
# there could run. This is where they are put on the box, which for the panel
# is a restart.
if [[ -n "${RUST_BIN_DIR:-}" ]]; then
  if [[ -x "${RUST_BIN_DIR}/snpanel-api" ]]; then
    log "Refreshing /usr/local/bin/snpanel-api-rust"
    install -m 0755 -o root -g root "${RUST_BIN_DIR}/snpanel-api" \
      /usr/local/bin/snpanel-api-rust
  fi
  if [[ -x "${RUST_BIN_DIR}/snpanel-install" ]]; then
    install -m 0750 -o root -g root "${RUST_BIN_DIR}/snpanel-install" \
      /usr/local/sbin/snpanel-install
  fi
  if [[ -x "${RUST_BIN_DIR}/snpanel" ]]; then
    # The binary takes the `snpanel` name; the two older names follow it.
    install -m 0755 -o root -g root "${RUST_BIN_DIR}/snpanel" /usr/local/sbin/snpanel
    ln -sfn /usr/local/sbin/snpanel /usr/local/sbin/snpanelctl
    ln -sfn /usr/local/sbin/snpanel /usr/local/sbin/snpanel-cli
  fi
  [[ -n "${RUST_BIN_TMP:-}" ]] && rm -rf -- "$RUST_BIN_TMP"
  RUST_BIN_TMP=""
fi

# Gated on the sudoers file, not on the bash helper this used to refresh.
# That script is deleted; gating on it would have skipped this whole block -
# the sudoers refresh, the retune and the clock - silently, on every update.
if [[ -f "$SOURCE_DIR/installer/files/snpanel-sudoers" ]]; then
  log "Refreshing /etc/sudoers.d/snpanel and the machine tuning"
  update_progress 40 "runtime" "Refreshing panel helper and runtime"
  if id -u snpanel >/dev/null 2>&1; then
    # The helper itself was refreshed with the other binaries above; what is
    # left here is the sudoers file that decides who may call it.
    install -m 0440 -o root -g root  "$SOURCE_DIR/installer/files/snpanel-sudoers"   /etc/sudoers.d/snpanel
    visudo -c -f /etc/sudoers.d/snpanel >/dev/null
    # And the helper's own units, which only a fresh install used to write:
    # a change to its sandbox - MemoryDenyWriteExecute, which stopped every
    # Node application from deploying - never reached a box installed before
    # it. Socket-activated, so stopping the service is enough; the next call
    # starts it under the new unit.
    for unit in snpanel-helper.service snpanel-helper.socket; do
      if [[ -f "$SOURCE_DIR/installer/files/${unit}" ]]; then
        install -m 0644 -o root -g root "$SOURCE_DIR/installer/files/${unit}" "/etc/systemd/system/${unit}"
      fi
    done
    systemctl daemon-reload
    systemctl stop snpanel-helper.service 2>/dev/null || true
    sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper wp --info >/dev/null
    # The OWASP rule set's include is written only when its mode is set, and
    # one written before the setup-file fix names no crs-setup.conf: CRS then
    # answers every request on every site that loads it with a 500. Written
    # again here, in the mode it is in.
    crs_mode="$(tr -d '[:space:]' < /etc/nginx/modsec/snpanel-crs-mode 2>/dev/null || true)"
    if [[ "$crs_mode" == "detect" || "$crs_mode" == "block" ]]; then
      sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper waf-crs-mode "$crs_mode" >/dev/null \
        || echo "  (warning: could not rewrite the OWASP CRS include; switch the WAF off and on again from the panel)"
    fi
    # The retune output is a function of the helper's logic and this machine's
    # RAM/CPU; neither moves between two updates of the same release. Skip the
    # pair (and the autotune unit, which just runs the same two) when the
    # helper is unchanged. `snpanel-autotune.service` stays enabled for boot.
    #
    # The input is the installed binary now rather than the bash script: it is
    # the file whose logic decides the numbers.
    if step_inputs_changed autotune /usr/local/sbin/snpanel-helper; then
      sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper php-pools-retune >/dev/null || \
        echo "  (warning: could not retune existing PHP-FPM pools; site refresh will retry later)"
      sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper mariadb-retune >/dev/null || \
        echo "  (warning: could not retune MariaDB; update will continue with existing settings)"
      step_mark_done autotune /usr/local/sbin/snpanel-helper
    else
      echo "  (PHP-FPM and MariaDB tuning unchanged for this release; skipping the retune)"
    fi
    systemctl enable snpanel-autotune.service >/dev/null 2>&1 || true
    # The helper is fresh now, so the clock unit can run without flashing
    # up as a failed unit first.
    systemctl reset-failed snpanel-timesync.service >/dev/null 2>&1 || true
    systemctl start snpanel-timesync.timer >/dev/null 2>&1 || true
    systemctl start snpanel-timesync.service >/dev/null 2>&1 || \
      echo "  (warning: could not sync the clock now; the timer will retry)"
  else
    echo "  (snpanel user not found; skipping helper refresh - run install.sh first)"
  fi
fi

if [[ -f "$SOURCE_DIR/installer/rescue-firewall.sh" ]]; then
  log "Refreshing firewall rescue command"
  install -m 0755 -o root -g root "$SOURCE_DIR/installer/rescue-firewall.sh" /usr/local/sbin/snpanel-rescue-firewall
  ln -sfn /usr/local/sbin/snpanel-rescue-firewall /usr/local/sbin/snpanel-rescue-ufw-blocklist
fi

# The IP change command was a separate script refreshed here. It is
# `snpanel change-ip`, and the binary carrying it is refreshed with the
# others above.

if [[ -f "$SOURCE_DIR/installer/update.sh" ]]; then
  log "Refreshing panel update command"
  install -m 0755 -o root -g root "$SOURCE_DIR/installer/update.sh" /usr/local/sbin/snpanel-update
fi

# The SSH menu was a bash script here; it is the `snpanel` binary now and is
# refreshed with the other binaries above, along with its `snpanelctl` and
# `snpanel-cli` symlinks.

log "Ensuring Nginx ModSecurity WAF engine is installed"
if id -u snpanel >/dev/null 2>&1; then
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper waf-install || \
    echo "WARNING: WAF engine installation failed; continuing without ModSecurity."
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper certbot-auto-renew-install >/dev/null 2>&1 || true
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper firewall-blocklist-timer-install >/dev/null 2>&1 || true
  # Existing servers get the per-hostname certificate copies on this update, so
  # the panel opens on every domain here and not only on PANEL_DOMAIN.
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper panel-sni-sync >/dev/null 2>&1 || true
  # Vhosts were rewritten above; put the IPv6 listen directives back if the
  # switch is on. A no-op on the servers that never turned it on.
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper ipv6-apply >/dev/null 2>&1 || true
else
  echo "  (snpanel user not found; skipping WAF install - run install.sh first)"
fi

# --- Malware scanner: retrofit LMD on servers that already run the scanner --
# The scanner is opt-in; only touch a server whose admin turned it on. LMD adds
# fast site-root scans, a daily incremental scan and named malware families on
# top of ClamAV. A failure here is not fatal - the panel has an Install button.
if id -u snpanel >/dev/null 2>&1 \
   && grep -q '"malware_scan_enabled":[[:space:]]*true' /var/lib/snpanel/panel-settings.json 2>/dev/null \
   && [[ ! -x /usr/local/sbin/maldet ]]; then
  log "Installing Linux Malware Detect (scanner is enabled on this server)"
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper maldet-install || \
    echo "  (LMD install failed - use the Install LMD button on the Malware page)"
fi
if id -u snpanel >/dev/null 2>&1 && [[ -x /usr/local/sbin/maldet ]]; then
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper maldet-update-sigs >/dev/null 2>&1 || true
  # rfxn's installer enables maldet.service (the Level 2 monitor). The panel
  # owns that switch - keep it off unless the admin turned real-time on.
  if ! grep -q '"malware_realtime_enabled":[[:space:]]*true' /var/lib/snpanel/panel-settings.json 2>/dev/null; then
    systemctl disable --now maldet >/dev/null 2>&1 || true
  fi
fi

# --- Firewall: move IP blocking from UFW/Nginx to the packet filter --------
#
# The backend differs by platform and snpanel-helper picks it: iptables plus
# ipset on Debian, nftables on EL, which ships no legacy iptables binary at all.
if [[ "$OS_FAMILY" == "rhel" ]]; then
  log "Migrating firewall to nftables"
else
  log "Migrating firewall to iptables + ipset"
fi
if ! command -v ipset >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
  if [[ "$OS_FAMILY" == "rhel" ]]; then
    # Nothing to repair here: nftables comes with the base install, and there
    # is no apt to have left a half-configured package behind.
    pkg_install nftables ipset >/dev/null 2>&1 || true
  elif ! DEBIAN_FRONTEND=noninteractive apt-get install -y iptables ipset >/dev/null 2>&1; then
    # Seen in the field: a stuck libsystemd-shared pin leaves libipset13 (and
    # so ipset) "not going to be installed" - apt itself suggests the fix.
    # Older installs never got iptables/ipset in this state; every update run
    # is a chance to repair it instead of leaving the firewall unenforced
    # forever behind a WARNING nobody reads.
    echo "  iptables/ipset install failed; repairing broken apt dependencies"
    DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables ipset >/dev/null 2>&1 || \
      echo "WARNING: could not install iptables/ipset; firewall migration skipped."
  fi
fi
if [[ "$OS_FAMILY" == "rhel" ]]; then
  firewall_tool_present=$(command -v nft >/dev/null 2>&1 && echo yes || echo no)
else
  firewall_tool_present=$(command -v ipset >/dev/null 2>&1 && echo yes || echo no)
fi
if id -u snpanel >/dev/null 2>&1 && [[ "$firewall_tool_present" == "yes" ]]; then
  # firewall-migrate imports surviving UFW rules, removes UFW and the Nginx
  # geo-map blocklist, then applies the iptables chain and ipsets.
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper firewall-migrate || \
    echo "WARNING: firewall migration failed; run 'snpanel-rescue-firewall' if the server is unreachable."
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper firewall-blocklist-run >/dev/null 2>&1 || true
else
  echo "  (skipping firewall migration; snpanel user or packet-filter tooling missing)"
fi

# --- Restore ownership so snpanel user can read/write the deploy ------------
if id -u snpanel >/dev/null 2>&1; then
  ensure_panel_runtime_ownership
fi

# --- Backend ---------------------------------------------------------------
# Nothing to install: the panel is a binary, refreshed above with the other
# Rust binaries.

log "Refreshing MariaDB grants"
refresh_snpanel_mariadb_grants

log "Running database migrations"
update_progress 65 "backend" "Running database migrations"
# Alembic's revisions 0001-0031 are frozen and gone with the Python; a
# database that has them is stamped at the head this build expects, and
# anything after is Rust's, recorded in its own table. Run as the snpanel
# user so the SQLite file keeps its ownership.
if [[ -x "$RUST_API" ]] && id -u snpanel >/dev/null 2>&1; then
  runuser -u snpanel -- env HOME="$APP_DIR" SNPANEL_USE_HELPER=true \
    "$RUST_API" --env "$APP_DIR/backend/.env" --migrate \
    || fail "The schema migration failed; the update stops here rather than \
running new code against a half-migrated database"
fi
systemctl enable --now snpanel-backup-scheduler.timer >/dev/null 2>&1 || true
systemctl enable --now snpanel-malware-scheduler.timer >/dev/null 2>&1 || true

SITE_REFRESH_INPUTS=(
  # Was the bash helper; the binary that renders a vhost is the input now.
  "/usr/local/sbin/snpanel-helper"
  "${RUST_API:-/usr/local/bin/snpanel-api-rust}"
)
if ! step_inputs_changed site-refresh "${SITE_REFRESH_INPUTS[@]}"; then
  log "Managed site config unchanged since last update; skipping the per-site refresh"
elif [[ -x "${RUST_API:-/usr/local/bin/snpanel-api-rust}" ]] && id -u snpanel >/dev/null 2>&1; then
  # Rust where it is installed. This sweep warns per site and carries on:
  # an update that stopped at the first bad site would leave every site
  # after it un-refreshed and the panel half-updated.
  log "Refreshing managed site permissions"
  runuser -u snpanel -- env HOME="$APP_DIR" SNPANEL_USE_HELPER=true \
    "${RUST_API:-/usr/local/bin/snpanel-api-rust}" --env "$APP_DIR/backend/.env" --refresh-sites \
    || log "WARNING: the site refresh did not complete"
fi

# Clear what deleted websites left on disk. A Let's Encrypt renewal config for a
# site nobody hosts wakes certbot.timer twice a day and starts failing the day
# the domain stops pointing here, which is how a site removed months ago becomes
# a permanently failed unit with no obvious cause.
#
# Everything is copied into /root/snpanel-removed before it is deleted: these are
# customer certificates, and "unreferenced" is a strong inference rather than a
# certainty. The helper refuses outright if the panel cannot say which domains
# are live, so a failed query cannot turn into a delete.
if [[ -x "$RUST_API" ]] && id -u snpanel >/dev/null 2>&1; then
  # Rust where it is installed. A flag rather than a request to the panel:
  # an update runs while the panel may be stopped, and the sweep still has to
  # happen. The Python stays below for a box that has not cut over.
  log "Clearing orphaned certificates and configs"
  runuser -u snpanel -- env HOME="$APP_DIR" SNPANEL_USE_HELPER=true \
    "$RUST_API" --env "$APP_DIR/backend/.env" --clean-orphans \
    || log "WARNING: orphan cleanup did not complete"
fi

# journald ships with no size limit and falls back to 10% of the filesystem;
# btmp has no logrotate rule on Ubuntu at all. Measured on a live server: a
# 2.7G journal and 130M of btmp, against 51M for every nginx log combined,
# nearly all of it SSH password-guessing noise. Existing installs need this as
# much as new ones, so update.sh applies it too.
#
# Self-gating: the files are only written when their content differs, and
# journald is only restarted when its drop-in actually changed - an update
# should not bounce the logging daemon for nothing.
JOURNALD_DROPIN=/etc/systemd/journald.conf.d/99-snpanel-size.conf
JOURNALD_WANTED=$(cat <<'JOURNALD'
# Managed by SNPanel.
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=2week
JOURNALD
)
if [[ "$(cat "$JOURNALD_DROPIN" 2>/dev/null)" != "$JOURNALD_WANTED" ]]; then
  log "Capping journald size"
  mkdir -p /etc/systemd/journald.conf.d
  printf '%s\n' "$JOURNALD_WANTED" >"$JOURNALD_DROPIN"
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=500M >/dev/null 2>&1 || true
fi

BTMP_RULE=/etc/logrotate.d/btmp
BTMP_WANTED=$(cat <<'BTMP'
# Managed by SNPanel.
/var/log/btmp {
    su root root
    missingok
    weekly
    create 0660 root utmp
    rotate 4
    compress
    notifempty
}
BTMP
)
if [[ "$(cat "$BTMP_RULE" 2>/dev/null)" != "$BTMP_WANTED" ]]; then
  log "Adding btmp log rotation"
  printf '%s\n' "$BTMP_WANTED" >"$BTMP_RULE"
  chmod 644 "$BTMP_RULE"
fi

# Repair for servers where PHP's MySQL extension went missing. Seen for real:
# php8.3-mysql in dpkg state "rc" - removed, config files left behind - so
# /etc/php/8.3/mods-available still held mysqli.ini while the matching .so was
# gone. WordPress on that version could not reach its database at all, and
# `wp core update` failed with "missing the MySQL extension".
#
# phpenmod alone does NOT fix this, and is actively harmful here: with the .so
# absent it still writes the conf.d symlink, exits 0, and every later `php`
# invocation prints three "Unable to load dynamic library" warnings. So check
# for the .so first and reinstall the package when it is missing; only then
# enable the modules.
for php_ini_dir in /etc/php/*/; do
  php_ver="$(basename "$php_ini_dir")"
  [[ -d "/etc/php/${php_ver}/cli/conf.d" ]] || continue
  command -v "php${php_ver}" >/dev/null 2>&1 || continue
  if "php${php_ver}" -m 2>/dev/null | grep -qx mysqli; then
    continue
  fi

  php_ext_dir="$("php${php_ver}" -i 2>/dev/null | sed -n 's/^extension_dir => \([^ ]*\).*/\1/p' | head -1)"
  if [[ -n "$php_ext_dir" && ! -f "${php_ext_dir}/mysqli.so" ]]; then
    log "PHP ${php_ver} is missing the MySQL extension; installing php${php_ver}-mysql"
    apt_get install -y "php${php_ver}-mysql" >/dev/null 2>&1 || \
      log "WARNING: could not install php${php_ver}-mysql; WordPress on PHP ${php_ver} will not reach its database"
  fi

  # Only enable what is actually present, so a failed install cannot leave
  # dangling symlinks behind.
  if [[ -n "$php_ext_dir" && -f "${php_ext_dir}/mysqli.so" ]]; then
    for mod in mysqlnd mysqli pdo_mysql; do
      # phpenmod is a Debian tool. Remi writes each extension's .ini as its
      # package installs, so on EL there is nothing to enable.
      [[ "$OS_FAMILY" == "debian" ]] && phpenmod -v "$php_ver" "$mod" 2>/dev/null || true
    done
    systemctl reload "php${php_ver}-fpm" 2>/dev/null || true
  fi
done

log "Restarting snpanel-api"
mkdir -p /etc/systemd/system/snpanel-api.service.d
cat >/etc/systemd/system/snpanel-api.service.d/10-snpanel-helper.conf <<'SERVICE'
[Service]
NoNewPrivileges=false
ProtectSystem=false
RestrictSUIDSGID=false
CapabilityBoundingSet=~
SystemCallFilter=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SERVICE
systemctl daemon-reload
restart_panel

# --- Frontend --------------------------------------------------------------
update_progress 80 "frontend" "Building frontend"
cd "$APP_DIR/frontend"

FRONTEND_INPUTS=(src public index.html package.json package-lock.json)
FRONTEND_REBUILT=0
if [[ -f dist/index.html ]] && ! step_inputs_changed frontend "${FRONTEND_INPUTS[@]}"; then
  log "Frontend unchanged since last update; keeping the built bundle"
else
  FRONTEND_REBUILT=1
  log "Building frontend"
  if ! command -v node >/dev/null 2>&1; then
    log "WARNING: Node.js not found, installing..."
    pkg_update_index
    pkg_install nodejs npm
  fi
  echo "Node version: $(node --version)"
  echo "npm version: $(npm --version)"

  rm -rf dist .vite node_modules/.vite

  # Reinstall only when the dependency set actually moved, not just its mtime.
  if [[ ! -d node_modules ]] || step_inputs_changed frontend-deps package.json; then
    log "Installing npm dependencies..."
    rm -rf node_modules package-lock.json
    npm install
    step_mark_done frontend-deps package.json
  fi
  log "Building frontend with VITE_API_URL=/api..."
  VITE_API_URL=/api npm run build 2>&1 || { log "BUILD FAILED"; exit 1; }

  [[ -f dist/index.html ]] || fail "Frontend build failed: dist/index.html missing"
  HASHED=$(grep -oE 'index-[a-zA-Z0-9_-]+\.js' dist/index.html | head -n1 || true)
  echo "Built bundle: ${HASHED:-unknown}"
  step_mark_done frontend "${FRONTEND_INPUTS[@]}"
fi

# Make sure nginx (as ${WEB_USER}) can read the built bundle. The app
# directory above it only needs passing through, which its 0711 allows; o+r
# on it let anyone list it.
chmod o+rX "$APP_DIR/frontend" 2>/dev/null || true
chmod -R o+rX "$APP_DIR/frontend/dist" 2>/dev/null || true

# The API scans dist/assets at start, so a fresh bundle (new hashed filenames)
# needs one more restart. An unchanged bundle does not.
if [[ "$FRONTEND_REBUILT" == "1" ]]; then
  log "Restarting $(panel_unit) after frontend build"
  restart_panel
fi

# --- Reload Nginx ----------------------------------------------------------
log "Reloading nginx"
update_progress 92 "restarting" "Restarting services and reloading nginx"
migrate_nginx_wordpress_csp_worker_src
migrate_site_cron_php_binary
nginx -t
systemctl reload nginx

# --- Did turning HTTPS on actually work? -----------------------------------
if [[ -n "${PANEL_SWITCHED_TO_HTTPS:-}" ]]; then
  panel_port_now="$(env_get PANEL_PORT)"; panel_port_now="${panel_port_now:-2222}"
  https_ok="no"
  for _ in {1..20}; do
    if curl -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:${panel_port_now}/api/health" >/dev/null 2>&1; then
      https_ok="yes"; break
    fi
    sleep 1
  done
  if [[ "$https_ok" != "yes" ]]; then
    # An operator locked out of the panel cannot fix the panel. Put it back.
    log "Panel did not come up over HTTPS; reverting to HTTP"
    env_set PANEL_SSL_CERT ""
    env_set PANEL_SSL_KEY ""
    env_set PANEL_SSL_MODE ""
    env_set PANEL_URL "http://$(detect_server_ip):${panel_port_now}"
    env_set ALLOWED_ORIGINS "http://$(detect_server_ip):${panel_port_now}"
    PANEL_SWITCHED_TO_HTTPS=""
    restart_panel
  fi
fi

# --- Health check ----------------------------------------------------------
log "Health check"
update_progress 98 "healthcheck" "Running API health check"
for _ in {1..20}; do
  if panel_healthcheck; then
    echo "API is healthy."
    echo ""
    echo "Update completed."
    echo "If the browser still shows the old UI, hard refresh (Ctrl + Shift + R)."
    if [[ -n "${PANEL_SWITCHED_TO_HTTPS:-}" ]]; then
      echo ""
      echo "  The panel now answers over HTTPS only:"
      echo "      ${PANEL_SWITCHED_TO_HTTPS}"
      echo "  The old http:// address will not load. The certificate is self-signed,"
      echo "  so the browser warns once; to replace it with a real one, point a domain"
      echo "  at this server and use Panel settings -> SSL."
    fi
    write_update_state "completed" "${UPDATE_REF:-}" "Update completed"
    update_progress 100 "completed" "Update completed"
    exit 0
  fi
  sleep 1
done

echo "API did not respond. Check logs:"
echo "  journalctl -u snpanel-api -n 100 --no-pager"
write_update_state "failed" "${UPDATE_REF:-}" "API health check failed after update"
update_progress 0 "failed" "API health check failed after update"
exit 1
