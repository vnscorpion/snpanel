# shellcheck shell=bash
# Shared by the Hosting Edition scripts in installer/hosting/. Sourced.
#
# Every step is a pair of functions: `<name>_done` looks at the machine and
# says whether the step's result is already there, `<name>_run` makes it so.
# Nothing is remembered in a state file that the machine itself cannot
# confirm, so a script can be re-run after any failure or reboot, and
# `--check` reports on a machine that was converted by hand.

set -Eeuo pipefail

HOSTING_DIR="${HOSTING_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
FILES="$HOSTING_DIR/files"
APP_DIR="${APP_DIR:-/opt/snpanel}"
ENV_FILE="$APP_DIR/backend/.env"
PANEL_DB="$APP_DIR/backend/snpanel.db"
HELPER="/usr/local/sbin/snpanel-helper"
API_BIN="/usr/local/bin/snpanel-api-rust"
CLI_BIN="/usr/local/sbin/snpanel"
STATE_DIR="/var/lib/snpanel/upgrade"
LOG_FILE="${LOG_FILE:-/var/log/snpanel-upgrade.log}"

CHECK=0
ASSUME_YES=0
PENDING=0

if [[ -t 1 ]]; then
  C_OK=$'\e[32m' C_WARN=$'\e[33m' C_ERR=$'\e[31m' C_DIM=$'\e[2m' C_B=$'\e[1m' C_0=$'\e[0m'
else
  C_OK="" C_WARN="" C_ERR="" C_DIM="" C_B="" C_0=""
fi

_stamp() { date '+%F %T'; }
log()  { printf '%s\n' "$*"; printf '%s %s\n' "$(_stamp)" "$*" >>"$LOG_FILE" 2>/dev/null || true; }
info() { log "${C_DIM}  $*${C_0}"; }
warn() { log "${C_WARN}! $*${C_0}"; }
die()  { log "${C_ERR}x $*${C_0}"; exit 1; }

on_error() {
  local code=$? line=${1:-?}
  log "${C_ERR}x Dừng ở dòng $line (mã $code). Xem $LOG_FILE, sửa nguyên nhân rồi chạy lại lệnh: các bước đã xong sẽ được bỏ qua.${C_0}"
  exit "$code"
}
trap 'on_error $LINENO' ERR

# run <cmd...>: echo it to the log, run it, keep its output in the log.
run() {
  printf '%s $ %s\n' "$(_stamp)" "$*" >>"$LOG_FILE" 2>/dev/null || true
  "$@" 2>&1 | tee -a "$LOG_FILE"
  return "${PIPESTATUS[0]}"
}

# step <name> <title>: skip it when <name>_done says so, report it under
# --check, run it and confirm it otherwise.
step() {
  local name="$1" title="$2"
  if "${name}_done"; then
    log "${C_OK}✓${C_0} $title ${C_DIM}(đã xong)${C_0}"
    return 0
  fi
  if [[ "$CHECK" == 1 ]]; then
    log "${C_WARN}•${C_0} $title ${C_DIM}(chưa làm)${C_0}"
    PENDING=$((PENDING + 1))
    return 0
  fi
  log "${C_B}→ $title${C_0}"
  "${name}_run"
  if ! "${name}_done"; then
    die "$title: đã chạy nhưng kết quả chưa đúng như mong đợi"
  fi
  log "${C_OK}✓${C_0} $title"
}

need_root() { [[ $EUID -eq 0 ]] || die "Cần chạy bằng root"; }

confirm() {
  # confirm <word> <message>: the operator types <word>, or --yes was given.
  local word="$1" message="$2" answer=""
  [[ "$ASSUME_YES" == 1 ]] && return 0
  [[ -t 0 ]] || die "$message Chạy lại với --yes để xác nhận khi không có terminal."
  printf '%s\nGõ %s để tiếp tục: ' "$message" "$word"
  read -r answer
  [[ "$answer" == "$word" ]] || die "Đã huỷ"
}

env_get() {
  # env_get KEY: the value in the panel's .env, without quotes.
  [[ -f "$ENV_FILE" ]] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

panel_port() { local p; p="$(env_get PANEL_PORT)"; printf '%s' "${p:-2222}"; }

is_cloudlinux() { [[ -f /etc/cloudlinux-release ]]; }
lve_loaded() { [[ -d /sys/module/kmodlve ]]; }
unit_file_exists() { grep -q "^$1.service" <<<"$(systemctl list-unit-files --no-legend "$1.service" 2>/dev/null || true)"; }

# install_file <src under files/> <dest> <mode>
install_file() {
  install -D -m "$3" "$FILES/$1" "$2"
}

# same_file <src under files/> <dest>
same_file() { [[ -f "$2" ]] && cmp -s "$FILES/$1" "$2"; }

sqlite_ro() {
  # sqlite_ro <sql>: rows from the panel's database, tab separated.
  python3 - "$PANEL_DB" "$1" <<'PY'
import sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=10)
for row in con.execute(sys.argv[2]):
    print("\t".join("" if v is None else str(v) for v in row))
PY
}

# The panel accounts that have a Linux account: customers, resellers and
# the administrator.
panel_linux_users() {
  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] && id -u "$u" >/dev/null 2>&1 && printf '%s\n' "$u"
  done < <(sqlite_ro "SELECT username FROM users ORDER BY id")
}

# --- the panel's API, as the administrator ------------------------------------
API_TOKEN=""
api_base() {
  local port; port="$(panel_port)"
  if curl -ks --max-time 5 -o /dev/null "https://127.0.0.1:$port/api/health"; then
    printf 'https://127.0.0.1:%s/api' "$port"
  else
    printf 'http://127.0.0.1:%s/api' "$port"
  fi
}

# api_login: SNPANEL_ADMIN_PASSWORD from the environment, or asked for.
# The password never reaches a command line.
api_login() {
  [[ -n "$API_TOKEN" ]] && return 0
  local pass="${SNPANEL_ADMIN_PASSWORD:-}" user="${SNPANEL_ADMIN_USER:-admin}" base out
  if [[ -z "$pass" ]]; then
    [[ -t 0 ]] || return 1
    read -rsp "Mật khẩu đăng nhập panel của $user (để trống để bỏ qua): " pass; echo
    [[ -n "$pass" ]] || return 1
  fi
  base="$(api_base)"
  out="$(printf 'username=%s&password=%s' \
      "$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$user")" \
      "$(printf '%s' "$pass" | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))')" \
    | curl -ks --max-time 20 -X POST "$base/auth/login" --data-binary @- \
        -H 'Content-Type: application/x-www-form-urlencoded')" || return 1
  API_TOKEN="$(printf '%s' "$out" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("access_token") or "")
except Exception: print("")')"
  if [[ -z "$API_TOKEN" ]]; then
    warn "Đăng nhập panel không được (sai mật khẩu, hoặc tài khoản bật 2FA)."
    return 1
  fi
}

api() {
  # api <METHOD> <path> [json]
  curl -ks --max-time 60 -X "$1" "$(api_base)$2" \
    -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' ${3:+--data-binary "$3"}
}

# The panel's URL as the helper's panel-url-set takes it: scheme host port.
panel_url_parts() {
  local url; url="$(env_get PANEL_URL)"
  python3 - "$url" "$(panel_port)" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1] or "")
scheme = u.scheme if u.scheme in ("http", "https") else "https"
host = u.hostname or ""
print(scheme, host, u.port or sys.argv[2])
PY
}

mkdir -p "$STATE_DIR" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null || true
