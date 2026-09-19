#!/usr/bin/env bash
set -euo pipefail

SNPANEL_INSTALLER_VERSION="${SNPANEL_INSTALLER_VERSION:-v1.0.0}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run this installer as root"
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Cannot find /etc/os-release"
  exit 1
fi

# A coarse pre-check, so an unsupported OS is refused before the release
# tarball is downloaded. installer/platform.sh holds the authoritative table
# and is sourced once the source tree is in place; if the two ever disagree
# that file wins, and this check has only cost a wasted download.
source /etc/os-release
case "${ID:-}" in
  ubuntu)
    case "${VERSION_ID:-}" in
      24.04) OS_PRECHECK=ok ;;
      *) OS_PRECHECK=no ;;
    esac
    ;;
  debian)
    case "${VERSION_ID%%.*}" in
      12|13) OS_PRECHECK=ok ;;
      *) OS_PRECHECK=no ;;
    esac
    ;;
  almalinux|rocky|rhel|ol|centos)
    [[ "${VERSION_ID%%.*}" == "10" ]] && OS_PRECHECK=ok || OS_PRECHECK=no
    ;;
  *)
    OS_PRECHECK=no
    ;;
esac
if [[ "${OS_PRECHECK}" != "ok" ]]; then
  echo "This installer supports Ubuntu 24.04, Debian 12/13 and AlmaLinux 10"
  echo "Current OS: ${PRETTY_NAME:-unknown}"
  exit 1
fi

if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  SCRIPT_DIR=""
  PROJECT_ROOT=""
fi
BACKEND_SRC="${PROJECT_ROOT:+${PROJECT_ROOT}/backend}"
FRONTEND_SRC="${PROJECT_ROOT:+${PROJECT_ROOT}/frontend}"

if [[ ! -t 0 ]]; then
  # `[[ -r /dev/tty ]]` is the wrong test. In a session-less context (a CI
  # runner, a systemd unit, some container shells) /dev/tty exists and its
  # permission bits say readable, so the test passes -- then the open fails
  # with ENXIO and the install dies after claiming a terminal was available.
  # Make the open itself the test. It is probed in a subshell first because a
  # failed `exec` redirection terminates a non-interactive shell outright.
  if (exec </dev/tty) 2>/dev/null; then
    exec </dev/tty
  elif [[ -n "${PANEL_URL:-}" ]]; then
    : # Nothing left to prompt for: PANEL_URL supplies hostname and port.
  else
    echo "ERROR: This installer needs an interactive terminal." >&2
    echo "       Run it from SSH or export SNPANEL_URL/PANEL_PORT first." >&2
    exit 1
  fi
fi

# When running via curl ... | bash, BASH_SOURCE[0] may be unset. When running
# via bash <(curl ...), BASH_SOURCE[0] resolves to /dev/fd/N, so PROJECT_ROOT
# becomes /dev and BACKEND_SRC becomes /dev/backend. Detect this and download
# the release tarball via curl.
SNPANEL_GITHUB="${SNPANEL_GITHUB:-https://github.com/vnscorpion/snpanel}"
SNPANEL_REPO_SLUG="${SNPANEL_GITHUB#*github.com/}"
if [[ -z "${BACKEND_SRC}" || ! -d "${BACKEND_SRC}" ]]; then
  # --- resolve release tag (no git required) -------------------------
  if [[ -z "${SNPANEL_VERSION:-}" ]]; then
    SNPANEL_VERSION="${SNPANEL_INSTALLER_VERSION:-}"
  fi
  if [[ -z "${SNPANEL_VERSION:-}" ]]; then
    SNPANEL_VERSION="$(curl -fsSL "https://api.github.com/repos/${SNPANEL_REPO_SLUG}/tags?per_page=1" \
      | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\(v[^"]*\)".*/\1/p' | head -1)" || true
  fi
  if [[ ! "${SNPANEL_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Could not detect latest SNPanel release tag." >&2
    echo "       Set SNPANEL_VERSION=vX.Y.Z and retry, e.g.:" >&2
    echo "       SNPANEL_VERSION=v1.0.59 bash <(curl -fsSL ...)" >&2
    exit 1
  fi

  SNPANEL_CLONE_DIR="$(mktemp -d)"
  echo ""
  echo "==> Source not found locally - downloading ${SNPANEL_VERSION} to ${SNPANEL_CLONE_DIR}"

  curl -fsSL "${SNPANEL_GITHUB}/archive/refs/tags/${SNPANEL_VERSION}.tar.gz" \
    | tar xz -C "${SNPANEL_CLONE_DIR}" --strip-components=1

  PROJECT_ROOT="${SNPANEL_CLONE_DIR}"
  SCRIPT_DIR="${PROJECT_ROOT}/installer"
  BACKEND_SRC="${PROJECT_ROOT}/backend"
  FRONTEND_SRC="${PROJECT_ROOT}/frontend"
  trap 'cd /; rm -rf "${SNPANEL_CLONE_DIR}"' EXIT
fi

PANEL_URL="${PANEL_URL:-}"
# Filled in by enable_ipv6_when_available: off | on:<address> | failed
IPV6_RESULT="off"
PANEL_HOSTNAME="${PANEL_HOSTNAME:-}"
PANEL_DOMAIN=""
PANEL_PORT="${PANEL_PORT:-2222}"
# Opt-in only: set PANEL_TIMEZONE=Asia/Ho_Chi_Minh (or any zoneinfo name) to have
# the installer set the server timezone. Left blank, the installer never touches
# it - TOTP runs off UTC, so the clock sync below is what actually matters.
PANEL_TIMEZONE="${PANEL_TIMEZONE:-}"
SERVER_IP=""
ENABLE_SSL="${ENABLE_SSL:-auto}"
SSL_EMAIL="${SSL_EMAIL:-}"
NODE_MAJOR="${NODE_MAJOR:-22}"
# Left empty on purpose: which PHP versions exist depends on the release, and
# that is not known until detect_platform has run. Setting them here would bake
# 24.04's answer into a 26.04 install, where 8.3 and 8.4 do not exist at all.
# An operator who names versions explicitly still wins.
PHP_DEFAULT="${PHP_DEFAULT:-}"
PHP_VERSIONS="${PHP_VERSIONS:-}"
APP_DIR="${APP_DIR:-/opt/snpanel}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/snpanel}"
ADMIN_PASSWORD=""

log() {
  echo ""
  echo "==> $1"
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

# The per-distribution table. Sourced here rather than at the top of the file
# because detect_platform reports through fail(), and because SCRIPT_DIR is
# only known once the release tarball has been unpacked.
if [[ -z "${SCRIPT_DIR}" || ! -f "${SCRIPT_DIR}/platform.sh" ]]; then
  fail "Cannot find ${SCRIPT_DIR:-<unknown>}/platform.sh - the installer needs it to know which distribution it is on."
fi
# shellcheck source=platform.sh
source "${SCRIPT_DIR}/platform.sh"

detect_server_ip() {
  hostname -I 2>/dev/null | awk '{print $1}' || true
}

find_sshd() {
  if command -v sshd >/dev/null 2>&1; then
    command -v sshd
    return 0
  fi
  for candidate in /usr/sbin/sshd /usr/local/sbin/sshd; do
    [[ -x "$candidate" ]] && { echo "$candidate"; return 0; }
  done
  return 1
}

validate_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || fail "Invalid PANEL_PORT: $1"
  (( $1 >= 1 && $1 <= 65535 )) || fail "PANEL_PORT out of range: $1"
}

detect_ssh_ports() {
  local sshd_bin
  sshd_bin="$(find_sshd || true)"
  {
    if [[ -n "$sshd_bin" ]]; then
      "$sshd_bin" -T 2>/dev/null | awk '$1 == "port" {print $2}'
    fi
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      awk '{print $4}' <<<"$SSH_CONNECTION"
    fi
    awk '
      tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2 }
      tolower($1) == "listenaddress" {
        for (i = 2; i <= NF; i++) {
          value = $i
          gsub(/^\[/, "", value)
          gsub(/\]$/, "", value)
          if (value ~ /:[0-9]+$/) {
            sub(/^.*:/, "", value)
            print value
          }
        }
      }
    ' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
  } | awk '$1 ~ /^[0-9]+$/ && $1 >= 1 && $1 <= 65535 {print $1}' | sort -nu
}

is_domain_name() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
}

need_dir() {
  [[ -d "$1" ]] || fail "Missing directory $1. Upload backend, frontend, and installer."
}

validate_sources() {
  need_dir "$BACKEND_SRC"
  need_dir "$FRONTEND_SRC"
  [[ -f "${PROJECT_ROOT}/VERSION" ]] || fail "Missing VERSION"
  [[ -f "${BACKEND_SRC}/requirements.txt" ]] || fail "Missing backend/requirements.txt"
  [[ -f "${FRONTEND_SRC}/package.json" ]] || fail "Missing frontend/package.json"
}

ask_panel_url() {
  validate_port "$PANEL_PORT"
  if [[ -n "$PANEL_URL" ]]; then
    PANEL_URL="${PANEL_URL%/}"
    if [[ "$PANEL_URL" =~ ^https?:// ]]; then
      PANEL_HOSTNAME="$(echo "$PANEL_URL" | sed -E 's#^https?://([^/:]+).*#\1#')"
      parsed_port="$(echo "$PANEL_URL" | sed -nE 's#^https?://[^/:]+:([0-9]+).*#\1#p')"
    else
      PANEL_HOSTNAME="$(echo "$PANEL_URL" | sed -E 's#^([^/:]+).*#\1#')"
      parsed_port="$(echo "$PANEL_URL" | sed -nE 's#^[^/:]+:([0-9]+).*#\1#p')"
    fi
    if [[ -n "${parsed_port:-}" ]]; then
      PANEL_PORT="$parsed_port"
      validate_port "$PANEL_PORT"
    fi
  fi

  if [[ -z "$PANEL_HOSTNAME" ]]; then
    read -rp "Enter panel hostname (optional, blank = server IP): " PANEL_HOSTNAME
  fi
  PANEL_HOSTNAME="${PANEL_HOSTNAME#http://}"
  PANEL_HOSTNAME="${PANEL_HOSTNAME#https://}"
  PANEL_HOSTNAME="${PANEL_HOSTNAME%%/*}"
  if [[ "$PANEL_HOSTNAME" == *:* ]]; then
    parsed_port="${PANEL_HOSTNAME##*:}"
    PANEL_HOSTNAME="${PANEL_HOSTNAME%%:*}"
    [[ -n "$parsed_port" ]] && PANEL_PORT="$parsed_port"
    validate_port "$PANEL_PORT"
  fi
  if [[ -z "${PANEL_URL:-}" ]]; then
    read -rp "Enter panel port [${PANEL_PORT}]: " panel_port_answer
    if [[ -n "$panel_port_answer" ]]; then
      PANEL_PORT="$panel_port_answer"
      validate_port "$PANEL_PORT"
    fi
  fi

  if [[ -z "$PANEL_HOSTNAME" ]]; then
    SERVER_IP="$(detect_server_ip)"
    [[ -n "$SERVER_IP" ]] || fail "Cannot detect server IP. Set PANEL_HOSTNAME manually."
    PANEL_DOMAIN=""
    PANEL_URL="http://${SERVER_IP}:${PANEL_PORT}"
    ENABLE_SSL="no"
    return 0
  fi

  PANEL_DOMAIN="$PANEL_HOSTNAME"

  if [[ "$PANEL_DOMAIN" == "localhost" || "$PANEL_DOMAIN" == "127.0.0.1" || "$PANEL_DOMAIN" =~ ^[0-9.]+$ ]]; then
    ENABLE_SSL="no"
    PANEL_URL="http://${PANEL_DOMAIN}:${PANEL_PORT}"
  elif [[ "$ENABLE_SSL" == "auto" ]]; then
    if ! is_domain_name "$PANEL_DOMAIN"; then
      fail "Invalid panel domain: $PANEL_DOMAIN"
    fi
    read -rp "Enable Let's Encrypt SSL for ${PANEL_DOMAIN}:${PANEL_PORT}? [Y/n]: " ssl_answer
    ssl_answer="${ssl_answer:-Y}"
    if [[ "$ssl_answer" =~ ^[Nn]$ ]]; then
      ENABLE_SSL="no"
      PANEL_URL="http://${PANEL_DOMAIN}:${PANEL_PORT}"
    else
      ENABLE_SSL="yes"
      PANEL_URL="https://${PANEL_DOMAIN}:${PANEL_PORT}"
    fi
  elif [[ "$ENABLE_SSL" == "yes" ]]; then
    is_domain_name "$PANEL_DOMAIN" || fail "Invalid panel domain: $PANEL_DOMAIN"
    PANEL_URL="https://${PANEL_DOMAIN}:${PANEL_PORT}"
  else
    ENABLE_SSL="no"
    PANEL_URL="http://${PANEL_DOMAIN}:${PANEL_PORT}"
  fi

  if [[ "$ENABLE_SSL" == "yes" && -z "$SSL_EMAIL" ]]; then
    read -rp "Enter email for Let's Encrypt registration: " SSL_EMAIL
    [[ -n "$SSL_EMAIL" ]] || fail "Email is required to issue SSL"
  fi
}

# A freshly-booted Ubuntu runs unattended-upgrades for the first few minutes,
# holding the dpkg locks. Every apt call here went straight to
# "Could not get lock /var/lib/dpkg/lock-frontend", which killed the install
# partway through -- leaving a half-configured box. Wait the lock out instead.
apt_get_locked() {
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if (( waited == 0 )); then
      echo "Waiting for another package manager to finish..."
    fi
    if (( waited >= 300 )); then
      fail "Timed out after 5 minutes waiting for the dpkg lock."
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  DEBIAN_FRONTEND=noninteractive apt-get "$@"
}

# Repositories that are not on the base image. On Ubuntu this is a no-op -
# Ondrej's PPA is added by install_php, where it is used. On EL both EPEL and
# Remi are needed before the base transaction, because EPEL carries three
# packages the base list asks for (certbot, phpMyAdmin, composer).
enable_extra_repos() {
  case "$OS_FAMILY" in
    debian)
      :
      ;;
    rhel)
      pkg_installed epel-release || dnf -y install epel-release
      # CRB is enabled out of the box on AlmaLinux 10, but not on every EL
      # rebuild, and some EPEL packages need it. Enabling it twice is harmless.
      dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
      pkg_installed remi-release || dnf -y install "https://rpms.remirepo.net/enterprise/remi-release-${OS_MAJOR}.rpm"
      ;;
  esac
}

install_base_packages() {
  if [[ "$OS_FAMILY" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
  fi

  enable_extra_repos
  pkg_update_index

  local pkgs=("${BASE_PACKAGES[@]}" "${EXTRA_PACKAGES[@]}")
  if ! pkg_install "${pkgs[@]}"; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      # Seen on some VPS images: a stuck package pin (e.g. libsystemd-shared)
      # leaves an unrelated dependency "not going to be installed" and apt
      # itself suggests this fix. Repair once and retry before giving up -
      # otherwise the whole install dies here instead of a targeted failure.
      echo "Package install hit a broken dependency; repairing and retrying..."
      apt_get_locked --fix-broken install -y || true
      apt_get_locked install -y "${pkgs[@]}"
    else
      fail "Base package installation failed; see the dnf output above."
    fi
  fi

  systemctl enable --now nginx mariadb "$REDIS_SERVICE"
  systemctl enable --now "$SSH_SERVICE" 2>/dev/null || systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true
  # The panel schedules website cron jobs through this daemon. Ubuntu has it
  # running already; a minimal EL image does not.
  systemctl enable --now "$CRON_SERVICE" 2>/dev/null || true

  prepare_phpmyadmin_platform
}

# EPEL packages phpMyAdmin for Apache, and three of the differences from
# Debian's package are load-bearing rather than cosmetic:
#
#   * /etc/phpMyAdmin is root:apache mode 0750, so nginx cannot read it. The
#     panel would answer a blank 500 with nothing in phpMyAdmin's own log.
#   * config.inc.php includes no conf.d, which is where the panel delivers its
#     single-sign-on configuration. One appended include reproduces Debian's
#     behaviour, placed last in the file so the panel's settings win.
#   * /etc/nginx/default.d/phpMyAdmin.conf contains `fastcgi_pass php-fpm;`,
#     naming an upstream nothing defines, so `nginx -t` fails outright - and
#     it would publish phpMyAdmin on every vhost outside the panel's control.
prepare_phpmyadmin_platform() {
  [[ "$OS_FAMILY" == "rhel" ]] || return 0
  [[ -d "$PHPMYADMIN_CONF_DIR" ]] || return 0

  rm -f /etc/nginx/default.d/phpMyAdmin.conf

  install -d -o root -g "$WEB_GROUP" -m 0750 "${PHPMYADMIN_CONF_DIR}/conf.d"
  chgrp -R "$WEB_GROUP" "$PHPMYADMIN_CONF_DIR"
  chmod 0750 "$PHPMYADMIN_CONF_DIR"

  if ! grep -q 'SNPanel conf.d include' "${PHPMYADMIN_CONF_DIR}/config.inc.php" 2>/dev/null; then
    cat >>"${PHPMYADMIN_CONF_DIR}/config.inc.php" <<'PMACONF'

// SNPanel conf.d include. Debian's phpMyAdmin reads ${PHPMYADMIN_CONF_DIR}/conf.d and
// the panel delivers its single-sign-on configuration as a file there; EPEL's
// package has no such directory, so this reproduces it. Last in the file, so
// the panel's settings override the defaults above.
foreach (glob(__DIR__ . '/conf.d/*.php') ?: [] as $snpanel_conf) {
    include $snpanel_conf;
}
PMACONF
  fi
}

install_nodejs() {
  if [[ "$NODE_FROM_NODESOURCE" == "yes" ]]; then
    curl -fsSL --connect-timeout 10 --max-time 180 "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    pkg_install nodejs
  else
    # AlmaLinux 10's AppStream carries nodejs 22, which is the version the
    # panel asks for, so nothing is piped from a vendor script here. npm is a
    # separate package on EL, and a weak dependency, so ask for it by name.
    pkg_install nodejs
    if pkg_exists npm; then
      pkg_install npm
    fi
  fi
  node - <<'NODE'
const major = Number(process.versions.node.split('.')[0]);
if (major < 20) {
  throw new Error(`Node.js 20+ is required, current: ${process.version}`);
}
console.log(`Using Node.js ${process.version}`);
NODE
  npm --version
}

install_ioncube_loader() {
  local version="$1" arch url tmp archive loader target_dir target loader_ini_dir php_bin
  if command -v dpkg >/dev/null 2>&1; then
    arch="$(dpkg --print-architecture)"
  else
    arch="$(uname -m)"
  fi
  case "$arch" in
    amd64|x86_64)
      url="https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
      ;;
    *)
      echo "Skipping ionCube Loader: unsupported architecture ${arch}"
      return 0
      ;;
  esac

  pkg_install ca-certificates curl tar >/dev/null
  tmp="$(mktemp -d)" || fail "Cannot create ionCube temporary directory"
  archive="${tmp}/ioncube_loaders.tar.gz"
  # A slow CDN must not cost the whole installation. This function already
  # skips when the architecture has no loader, and when the PHP version has
  # none - so a missing loader is an outcome it is built to tolerate. Making
  # a timeout fatal instead meant one 29MB download from a third party could
  # end an install that had already configured nginx, PHP and the database.
  # It is a commercial-code loader; nothing in the panel needs it.
  local attempt
  for attempt in 1 2 3; do
    if curl -fsSL --connect-timeout 10 --max-time 300 "$url" -o "$archive"; then
      break
    fi
    if [ "$attempt" -eq 3 ]; then
      rm -rf -- "$tmp"
      echo "Skipping ionCube Loader: download failed after ${attempt} attempts"
      return 0
    fi
    echo "ionCube Loader download failed (attempt ${attempt}); retrying"
    sleep 5
  done
  if ! tar -xzf "$archive" -C "$tmp"; then
    rm -rf -- "$tmp"
    echo "Skipping ionCube Loader: the downloaded archive could not be unpacked"
    return 0
  fi
  loader="${tmp}/ioncube/ioncube_loader_lin_${version}.so"
  if [[ ! -f "$loader" ]]; then
    rm -rf -- "$tmp"
    echo "Skipping ionCube Loader: no loader found for PHP ${version}"
    return 0
  fi

  target_dir="/usr/local/ioncube"
  target="${target_dir}/ioncube_loader_lin_${version}.so"
  install -d -o root -g root -m 0755 "$target_dir"
  install -m 0644 -o root -g root "$loader" "$target"
  rm -rf -- "$tmp"

  # Debian keeps a conf.d per SAPI, Remi a single php.d shared by both, so the
  # number of directories to write differs by platform rather than the content.
  while read -r loader_ini_dir; do
    [[ -d "$loader_ini_dir" ]] || continue
    printf 'zend_extension=%s\n' "$target" >"${loader_ini_dir}/00-ioncube.ini"
    chown root:root "${loader_ini_dir}/00-ioncube.ini"
    chmod 0644 "${loader_ini_dir}/00-ioncube.ini"
  done < <(php_conf_dirs "$version")

  # Ask the interpreter by path: on EL there is no php<version> on PATH until
  # the compatibility shim has run, and this has to work either way.
  php_bin="$(php_binary "$version")"
  if [[ -x "$php_bin" ]]; then
    if ! "$php_bin" -v 2>&1 | grep -qi 'ionCube'; then
      while read -r loader_ini_dir; do
        rm -f "${loader_ini_dir}/00-ioncube.ini"
      done < <(php_conf_dirs "$version")
      fail "ionCube Loader failed to load for PHP ${version}"
    fi
  fi
  echo "ionCube Loader enabled for PHP ${version}"
}

# The panel's Python service layer is written against Debian's PHP layout: it
# reads and writes /etc/php/<version>/fpm/{php.ini,conf.d,pool.d,php-fpm.conf}
# and restarts php<version>-fpm. Rather than thread an OS abstraction through
# forty call sites in the backend, EL presents those names as symlinks into the
# Remi tree, which makes the existing code correct there.
#
# This is a compatibility shim, not a port, and it is worth being explicit
# about what it does not paper over:
#
#   * Remi shares one php.d between the CLI and FPM SAPIs, so a value the panel
#     sets for FPM also reaches CLI. Debian keeps the two separate.
#   * The panel's "install another PHP version" action shells out to apt-get
#     and remains Debian-only; on EL it fails rather than half-working.
setup_php_compat_shim() {
  local version="$1" compact etc_dir unit
  compact="$(php_compact "$version")"
  etc_dir="$(php_etc_dir "$version")"

  # conf.d and pool.d are Debian's names for Remi's php.d and php-fpm.d. They
  # are created inside the Remi tree so that the single /etc/php/<v>/fpm
  # symlink below resolves both of them.
  ln -sfn php.d "${etc_dir}/conf.d"
  ln -sfn php-fpm.d "${etc_dir}/pool.d"

  install -d -o root -g root -m 0755 "/etc/php/${version}"
  ln -sfn "$etc_dir" "/etc/php/${version}/fpm"

  # `systemctl restart php8.4-fpm` has to reach php84-php-fpm. A unit file that
  # is a symlink is a systemd alias, so both names drive the same service.
  unit="/usr/lib/systemd/system/php${compact}-php-fpm.service"
  if [[ -f "$unit" ]]; then
    ln -sfn "$unit" "/etc/systemd/system/php${version}-fpm.service"
    systemctl daemon-reload
  fi

  # `php8.4 -v` is used by the installer and by the panel's PHP tuning page.
  ln -sfn "$(php_binary "$version")" "/usr/local/bin/php${version}"
}

# Remi's default pool runs as apache and listens on a Remi-specific socket
# path. The panel's generated vhosts point at /run/php/php<version>-fpm.sock
# and its Python validation regex insists on that shape, so the pool is moved
# to match and handed to the web user rather than the other way round.
configure_php_fpm_pool() {
  local version="$1" pool socket
  pool="$(php_fpm_pool_dir "$version")/www.conf"
  socket="$(php_fpm_socket "$version")"
  [[ -f "$pool" ]] || return 0

  # /run is a tmpfs, so the directory has to be recreated on every boot.
  cat >/etc/tmpfiles.d/snpanel-php.conf <<'TMPFILES'
d /run/php 0755 root root -
TMPFILES
  systemd-tmpfiles --create /etc/tmpfiles.d/snpanel-php.conf >/dev/null 2>&1 || true
  install -d -o root -g root -m 0755 /run/php

  sed -i -E \
    -e "s#^;?[[:space:]]*user[[:space:]]*=.*#user = ${WEB_USER}#" \
    -e "s#^;?[[:space:]]*group[[:space:]]*=.*#group = ${WEB_GROUP}#" \
    -e "s#^;?[[:space:]]*listen[[:space:]]*=.*#listen = ${socket}#" \
    -e "s#^;?[[:space:]]*listen\.owner[[:space:]]*=.*#listen.owner = ${WEB_USER}#" \
    -e "s#^;?[[:space:]]*listen\.group[[:space:]]*=.*#listen.group = ${WEB_GROUP}#" \
    -e "s#^;?[[:space:]]*listen\.mode[[:space:]]*=.*#listen.mode = 0660#" \
    -e "s#^;?[[:space:]]*listen\.acl_users[[:space:]]*=.*#listen.acl_users = ${WEB_USER}#" \
    "$pool"
}

# Debian's PHP archive. There is no `add-apt-repository` here - the package
# that provides it is not even in Debian - so the repository is added the
# ordinary way.
#
# `signed-by` scopes the key to this one source. A key dropped into
# trusted.gpg.d would be trusted to sign for *every* repository on the machine,
# which is a much larger promise than "these PHP packages are Ondrej's".
add_sury_repo() {
  local codename keyring=/usr/share/keyrings/sury-php.gpg
  codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
  [[ -n "$codename" ]] || fail "cannot determine the Debian codename for the PHP repository"

  if [[ ! -f "$keyring" ]]; then
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL --connect-timeout 10 --max-time 60 https://packages.sury.org/php/apt.gpg \
      -o "${keyring}.tmp" || fail "could not download the sury.org signing key"
    install -m 0644 -o root -g root "${keyring}.tmp" "$keyring"
    rm -f "${keyring}.tmp"
  fi

  printf 'deb [signed-by=%s] https://packages.sury.org/php/ %s main\n' \
    "$keyring" "$codename" >/etc/apt/sources.list.d/sury-php.list
  chmod 0644 /etc/apt/sources.list.d/sury-php.list

  if ! pkg_update_index; then
    # Leave nothing behind that would break every later apt-get update - the
    # lesson from adding a PPA for a release that did not have one.
    rm -f /etc/apt/sources.list.d/sury-php.list
    pkg_update_index || true
    fail "packages.sury.org has no suite for ${codename}; the panel will use the PHP the distribution carries"
  fi
}

install_php() {
  if [[ "$OS_FAMILY" == "debian" && "$PHP_FROM_PPA" == "yes" ]]; then
    add-apt-repository -y ppa:ondrej/php
    pkg_update_index
  elif [[ "${PHP_FROM_SURY:-no}" == "yes" ]]; then
    add_sury_repo
  fi

  if [[ ! " ${PHP_VERSIONS} " =~ " ${PHP_DEFAULT} " ]]; then
    fail "PHP_DEFAULT=${PHP_DEFAULT} must be included in PHP_VERSIONS='${PHP_VERSIONS}'"
  fi

  for version in $PHP_VERSIONS; do
    mapfile -t packages < <(php_ext_packages "$version")

    available_packages=()
    missing_packages=()
    for package in "${packages[@]}"; do
      if pkg_exists "$package"; then
        available_packages+=("$package")
      else
        missing_packages+=("$package")
      fi
    done

    if [[ ${#missing_packages[@]} -gt 0 ]]; then
      echo "Skipping PHP packages not available in repo: ${missing_packages[*]}"
    fi

    if [[ ${#available_packages[@]} -eq 0 ]]; then
      fail "No package found for PHP ${version}. Remove ${version} from PHP_VERSIONS."
    fi

    pkg_install "${available_packages[@]}"

    if [[ "$OS_FAMILY" == "debian" ]]; then
      # Installing php<v>-mysql is not the same as enabling it, and enabling a
      # module whose .so is absent is worse than leaving it alone: phpenmod
      # writes the symlink anyway and exits 0, after which every `php` run
      # prints "Unable to load dynamic library". Enable only what is present.
      php_ext_dir="$("php${version}" -i 2>/dev/null | sed -n 's/^extension_dir => \([^ ]*\).*/\1/p' | head -1)"
      if [[ -n "$php_ext_dir" && -f "${php_ext_dir}/mysqli.so" ]]; then
        for mod in mysqlnd mysqli pdo_mysql; do
          phpenmod -v "$version" "$mod" 2>/dev/null || true
        done
      fi
    else
      # Remi writes each extension's .ini into php.d as its package installs,
      # so there is no enable step here - and no phpenmod to misuse.
      setup_php_compat_shim "$version"
      configure_php_fpm_pool "$version"
    fi

    install_ioncube_loader "$version"

    ini_file="$(php_ini_path "$version")"
    if [[ -f "$ini_file" ]]; then
      sed -i \
        -e 's/^\s*;\?\s*upload_max_filesize\s*=.*/upload_max_filesize = 1024M/' \
        -e 's/^\s*;\?\s*post_max_size\s*=.*/post_max_size = 1024M/' \
        -e 's/^\s*;\?\s*memory_limit\s*=.*/memory_limit = 1024M/' \
        -e 's/^\s*;\?\s*max_execution_time\s*=.*/max_execution_time = 300/' \
        -e 's/^\s*;\?\s*max_input_time\s*=.*/max_input_time = 600/' \
        -e 's/^\s*;\?\s*max_input_vars\s*=.*/max_input_vars = 10000/' \
        -e 's/^\s*;\?\s*max_file_uploads\s*=.*/max_file_uploads = 100/' \
        "$ini_file"
    fi

    systemctl enable --now "$(php_service "$version")"
  done

  if [[ "$OS_FAMILY" == "debian" ]]; then
    update-alternatives --set php "/usr/bin/php${PHP_DEFAULT}" || true
  else
    # Remi's SCL packages deliberately keep out of /usr/bin, so there is no
    # alternatives group to select: the default is a symlink we own.
    ln -sfn "$(php_binary "$PHP_DEFAULT")" /usr/bin/php
  fi
}

configure_fastcgi_cache() {
  install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0755 /var/cache/nginx/snpanel-fastcgi
  find /var/cache/nginx/snpanel-fastcgi -mindepth 1 -delete
  cat >/etc/nginx/conf.d/00-snpanel-fastcgi-cache.conf <<'NGINX'
fastcgi_cache_path /var/cache/nginx/snpanel-fastcgi levels=1:2 keys_zone=SNPANEL_FASTCGI:32m inactive=30m max_size=256m use_temp_path=off;
fastcgi_cache_key "$scheme$request_method$host$request_uri";
NGINX
}

# WebSocket upgrade map, shared by every proxied vhost. Without it a
# `proxy_set_header Connection $connection_upgrade` in a site config makes
# nginx fail to start, so this has to exist before any proxy vhost is written.
configure_proxy_upgrade_map() {
  cat >/etc/nginx/conf.d/00-snpanel-upgrade-map.conf <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
NGINX
}

write_modsec_base_conf() {
  install -d -o root -g root -m 0755 /etc/nginx/modsec /etc/nginx/modsec/sites
  {
    [[ -f /etc/modsecurity/modsecurity.conf ]] && echo "Include /etc/modsecurity/modsecurity.conf"
    echo "SecRuleEngine On"
    echo "SecRequestBodyAccess Off"
  } >/etc/nginx/modsec/snpanel-base.conf
}

write_modsec_main_conf() {
  write_waf_default_rules
  write_modsec_base_conf
  touch /etc/nginx/modsec/snpanel-custom.conf
  {
    echo "Include /etc/nginx/modsec/snpanel-base.conf"
    echo "Include /etc/nginx/modsec/snpanel-default.conf"
    echo "Include /etc/nginx/modsec/snpanel-custom.conf"
  } >/etc/nginx/modsec/snpanel-main.conf
}

write_http_flood_nginx_conf() {
  install -d -o root -g root -m 0755 /etc/nginx/snpanel /etc/nginx/conf.d
  if [[ ! -f /etc/nginx/snpanel/http-flood-zones.conf ]]; then
    cat >/etc/nginx/snpanel/http-flood-zones.conf <<'CONF'
# Managed by SNPanel. Shared zones for per-website HTTP flood protection.
map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key {
    default $binary_remote_addr;
    1 "";
}
limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;
CONF
  fi
  cat >/etc/nginx/conf.d/00-snpanel-http-flood.conf <<'CONF'
# Managed by SNPanel. Shared zones for per-website HTTP flood protection.
include /etc/nginx/snpanel/http-flood-zones.conf;
CONF
  rm -f /etc/nginx/conf.d/snpanel-http-flood.conf /etc/nginx/snpanel/http-flood-server.conf 2>/dev/null || true
  chown root:root /etc/nginx/conf.d/00-snpanel-http-flood.conf /etc/nginx/snpanel/http-flood-zones.conf
  chmod 0644 /etc/nginx/conf.d/00-snpanel-http-flood.conf /etc/nginx/snpanel/http-flood-zones.conf
}

write_waf_default_rules() {
  install -d -o root -g root -m 0755 /etc/nginx/modsec
  cat >/etc/nginx/modsec/snpanel-default.conf <<'RULES'
# SNPanel default WAF rules: lightweight WordPress, Laravel, and PHP probes only.
SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/\.user\.ini(?:\.|$)|/\.git/|/composer\.(?:json|lock)(?:$|[?])|/(?:phpinfo|info)\.php(?:$|[?])|/(?:config|database|db)\.php\.(?:bak|old|save|txt)(?:$|[?]))" "id:1001301,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP sensitive file probe'"
SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)" "id:1001302,phase:2,deny,status:403,log,msg:'SNPanel blocked PHP path traversal'"
SecRule REQUEST_URI "@rx (?i)(?:/(?:c99|r57|shell|cmd|wso)\.php(?:$|[?])|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php(?:$|[?]))" "id:1001303,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP runtime probe'"
SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/artisan(?:$|[?])|/server\.php(?:$|[?])|/storage/logs/[^?]*\.log(?:$|[?])|/bootstrap/cache/[^?]*\.php(?:$|[?]))" "id:1001201,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel sensitive path'"
SecRule REQUEST_URI "@rx (?i)(?:/_ignition/execute-solution(?:$|[?]))" "id:1001202,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel Ignition RCE probe'"
SecRule REQUEST_URI "@rx (?i)(?:/wp-config\.php(?:\.|$|[?])|/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])|/wp-admin/includes/[^?]*\.php(?:$|[?])|/wp-includes/[^?]*\.php(?:$|[?]))" "id:1001101,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress sensitive path'"
SecRule ARGS:author "@rx ^[0-9]+$" "id:1001103,phase:2,deny,status:403,log,msg:'SNPanel blocked WordPress author enumeration'"
SecRule REQUEST_URI "@rx (?i)(?:/wp-admin/install\.php(?:$|[?])|/wp-admin/setup-config\.php(?:$|[?]))" "id:1001104,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress installer probe'"
RULES
}

install_waf_engine() {
  # HTTP flood protection is plain nginx - a map plus limit_conn_zone - and
  # works on every platform. Only the ModSecurity rule engine is packaged on
  # some distributions and not others, so the two are separated here.
  if [[ "$WAF_AVAILABLE" != "yes" ]]; then
    echo "ModSecurity for nginx is not packaged on ${OS_PRETTY}:"
    echo "  nginx-mod-modsecurity, modsecurity and modsecurity-crs are all absent,"
    echo "  and mod_security is the Apache module, not nginx's."
    echo "Configuring HTTP flood protection only. The panel's WAF page will"
    echo "report the rule engine as unavailable, which is the truth - it is not"
    echo "silently disabled."
    write_waf_default_rules
    write_http_flood_nginx_conf
    nginx -t
    systemctl reload nginx || true
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  if ! pkg_installed libnginx-mod-http-modsecurity; then
    pkg_update_index
    # The library is not named here. It was `libmodsecurity3` on 24.04 and is
    # `libmodsecurity3t64` on 26.04 after the 64-bit time_t transition, and the
    # nginx module depends on whichever one this release has - so asking for the
    # module alone is both correct and version-proof.
    pkg_install libnginx-mod-http-modsecurity modsecurity-crs || \
      pkg_install libnginx-mod-http-modsecurity
  fi
  install -d -o root -g root -m 0755 /etc/nginx/modsec /etc/nginx/modsec/sites
  write_waf_default_rules
  touch /etc/nginx/modsec/snpanel-custom.conf
  if [[ -f /etc/modsecurity/modsecurity.conf-recommended && ! -f /etc/modsecurity/modsecurity.conf ]]; then
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  fi
  if [[ -f /etc/modsecurity/modsecurity.conf ]]; then
    sed -i -E 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
  fi
  if [[ -f /usr/share/nginx/modules-available/mod-http-modsecurity.conf ]]; then
    install -d /etc/nginx/modules-enabled
    ln -sfn /usr/share/nginx/modules-available/mod-http-modsecurity.conf /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf
  fi
  write_modsec_main_conf
  write_http_flood_nginx_conf
  nginx -t
  systemctl reload nginx || true
}

install_wp_cli() {
  if ! command -v wp >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 10 --max-time 180 -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x /usr/local/bin/wp
  fi
}

copy_sources() {
  mkdir -p "$APP_DIR" "$BACKUP_ROOT"
  rm -rf "${APP_DIR}/backend" "${APP_DIR}/frontend"
  cp -r "$BACKEND_SRC" "${APP_DIR}/backend"
  cp -r "$FRONTEND_SRC" "${APP_DIR}/frontend"
  install -m 0644 "$PROJECT_ROOT/VERSION" "${APP_DIR}/VERSION"
}

build_frontend() {
  cd "${APP_DIR}/frontend"
  rm -rf node_modules package-lock.json dist .vite
  npm install
  VITE_API_URL=/api npm run build
  if [[ ! -f dist/index.html ]]; then
    fail "Frontend build failed: ${APP_DIR}/frontend/dist/index.html is missing"
  fi
  # Nginx (as ${WEB_USER}) needs to read the bundle. The frontend is public anyway.
  chmod o+rX "${APP_DIR}" "${APP_DIR}/frontend" 2>/dev/null || true
  chmod -R o+rX "${APP_DIR}/frontend/dist"
  echo "Frontend built: $(grep -oE 'index-[a-zA-Z0-9_-]+\.js' dist/index.html | head -n1 || echo 'unknown')"
}

setup_panel_user() {
  if ! getent group snpanel-sites >/dev/null; then
    groupadd --system snpanel-sites
  fi
  if ! getent group snpanel-sftp >/dev/null; then
    groupadd --system snpanel-sftp
  fi
  if ! id -u snpanel >/dev/null 2>&1; then
    useradd --system --home-dir "$APP_DIR" --shell "$NOLOGIN_SHELL" --user-group snpanel
  fi
  usermod -aG "$WEB_GROUP" snpanel || true
  usermod -aG snpanel-sites snpanel || true
  usermod -aG snpanel-sites "$WEB_USER" || true

  # Allow snpanel to write into /etc/nginx/conf.d (vhost files).
  install -d -o root -g snpanel -m 2775 /etc/nginx/conf.d
  install -d -o root -g snpanel -m 2775 /etc/nginx/snpanel/custom
  # setgid so new files inherit the snpanel group; allows future writes.
  chmod g+s /etc/nginx/conf.d || true
  chmod g+s /etc/nginx/snpanel/custom 2>/dev/null || true

  # Make the panel data dirs writable by snpanel.
  install -d -o snpanel -g snpanel -m 0750 "$APP_DIR"
  install -d -o snpanel -g snpanel -m 0750 "$BACKUP_ROOT"
  # DirectAdmin import staging dirs
  install -d -o snpanel -g snpanel -m 0750 /home/admin/snpanel_backups/da
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel/da-import
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel/import-stage

  # MariaDB: create an admin user that snpanel can use without password
  # (auth via a defaults-file in ~snpanel/.my.cnf, mode 0600).
  local mariadb_password
  mariadb_password="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)"
  # ALTER as well as CREATE. `CREATE USER IF NOT EXISTS` does nothing when the
  # account is already there - including nothing to its password - so a second
  # install run would write a new password into .my.cnf while the account kept
  # the old one, and every database action in the panel would then fail with
  # "Access denied for user 'snpanel'@'localhost'". Re-running the installer is
  # a normal thing to do after a failure, so it has to converge rather than
  # half-apply.
  local grant_sql
  grant_sql="
    CREATE USER IF NOT EXISTS 'snpanel'@'localhost' IDENTIFIED BY '${mariadb_password}';
    ALTER USER 'snpanel'@'localhost' IDENTIFIED BY '${mariadb_password}';
    GRANT ALL PRIVILEGES ON *.* TO 'snpanel'@'localhost' WITH GRANT OPTION;
    FLUSH PRIVILEGES;
  "
  mariadb -e "$grant_sql" 2>/dev/null || mysql -e "$grant_sql"

  cat >"${APP_DIR}/.my.cnf" <<MYCNF
[client]
user=snpanel
password="${mariadb_password}"
host=localhost

[mysqldump]
user=snpanel
password="${mariadb_password}"
host=localhost
MYCNF
  chown snpanel:snpanel "${APP_DIR}/.my.cnf"
  chmod 0600 "${APP_DIR}/.my.cnf"

  # The file and the account have to agree. They did not, once, and the symptom
  # was a 500 from every database page rather than anything pointing here.
  if ! sudo -u snpanel env HOME="$APP_DIR" mariadb -e "SELECT 1" >/dev/null 2>&1; then
    fail "the panel cannot authenticate to MariaDB with the credentials just written to ${APP_DIR}/.my.cnf"
  fi
}

setup_sftp_access() {
  local sshd_config="/etc/ssh/sshd_config" backup
  getent group snpanel-sftp >/dev/null || groupadd --system snpanel-sftp
  install -d -o root -g root -m 0755 /run/sshd
  rm -f /etc/ssh/sshd_config.d/99-snpanel-sftp.conf 2>/dev/null || true
  touch "$sshd_config"
  backup="${sshd_config}.snpanel.bak"
  cp "$sshd_config" "$backup"
  sed -i '/^# BEGIN SNPANEL SFTP USERS$/,/^# END SNPANEL SFTP USERS$/d' "$sshd_config"
  cat >>"$sshd_config" <<'SSHD'
# BEGIN SNPANEL SFTP USERS
# Allow SNPanel Linux users to log in with SFTP using their panel password.
# SSH shells are intentionally disabled; /home/%u is a root-owned chroot.
Match Group snpanel-sftp
    PasswordAuthentication yes
    ChrootDirectory /home/%u
    ForceCommand internal-sftp -d /
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding no
    PermitTunnel no
# END SNPANEL SFTP USERS
SSHD
  if ! sshd -t; then
    cp "$backup" "$sshd_config"
    fail "Invalid SSHD configuration for SNPanel SFTP users"
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

# Does this sudo still have the `requiretty` setting? Asked by handing visudo a
# file that uses it, because that is the same parser that will judge ours.
sudoers_understands_requiretty() {
  local probe rc=0
  probe="$(mktemp)" || return 1
  printf 'Defaults:root !requiretty\nroot ALL=(ALL) ALL\n' >"$probe"
  chmod 0440 "$probe"
  visudo -c -f "$probe" >/dev/null 2>&1 || rc=1
  rm -f "$probe"
  return "$rc"
}

install_privileged_helper() {
  install -m 0750 -o root -g snpanel "${SCRIPT_DIR}/files/snpanel-helper.sh" /usr/local/sbin/snpanel-helper
  sed -i "s#^APP_DIR=\"/opt/snpanel\"#APP_DIR=\"${APP_DIR}\"#" /usr/local/sbin/snpanel-helper
  install -m 0755 -o root -g root "${SCRIPT_DIR}/update.sh" /usr/local/sbin/snpanel-update
  install -m 0440 -o root -g root "${SCRIPT_DIR}/files/snpanel-sudoers" /etc/sudoers.d/snpanel
  # `requiretty` was removed in sudo 1.9.17. Ubuntu 26.04's build rejects the
  # whole file over the negation; AlmaLinux 10 ships the same sudo version and
  # accepts it. The line exists because RHEL once enabled requiretty globally
  # and the helper runs with no TTY, so it is dropped only where sudo does not
  # know the setting - and that is decided by asking visudo, not by branching
  # on the distribution.
  if ! sudoers_understands_requiretty; then
    sed -i '/^Defaults:snpanel[[:space:]]*!requiretty$/d' /etc/sudoers.d/snpanel
  fi
  visudo -c -f /etc/sudoers.d/snpanel >/dev/null
  install -m 0755 -o root -g root "${SCRIPT_DIR}/rescue-firewall.sh" /usr/local/sbin/snpanel-rescue-firewall
  ln -sfn /usr/local/sbin/snpanel-rescue-firewall /usr/local/sbin/snpanel-rescue-ufw-blocklist
  if [[ -f "${PROJECT_ROOT}/change_IP.sh" ]]; then
    install -m 0755 -o root -g root "${PROJECT_ROOT}/change_IP.sh" /usr/local/sbin/snpanel-change-ip
  fi
}

install_panel_cli() {
  install -m 0755 -o root -g root "${SCRIPT_DIR}/files/snpanelctl" /usr/local/sbin/snpanel
  ln -sfn /usr/local/sbin/snpanel /usr/local/sbin/snpanelctl
  sed -i "s#APP_DIR=\"\${APP_DIR:-/opt/snpanel}\"#APP_DIR=\"\${APP_DIR:-${APP_DIR}}\"#" /usr/local/sbin/snpanel /usr/local/sbin/snpanelctl 2>/dev/null || true
}

validate_privileged_helper() {
  sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper wp --info >/dev/null
}

setup_backend() {
  cd "${APP_DIR}/backend"
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  ADMIN_PASSWORD="${SNPANEL_ADMIN_PASSWORD:-$(openssl rand -base64 24 | tr -d '\n')}"

  cat > .env <<ENV
APP_ENV=production
SECRET_KEY=$(openssl rand -hex 32)
COMMAND_DRY_RUN=false
DATABASE_URL=sqlite:///${APP_DIR}/backend/snpanel.db
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_BACKEND=redis
ALLOWED_ORIGINS=${PANEL_URL}
BACKUP_ROOT=${BACKUP_ROOT}
SSL_EMAIL=${SSL_EMAIL}
PANEL_URL=${PANEL_URL}
PANEL_DOMAIN=${PANEL_DOMAIN}
PANEL_PORT=${PANEL_PORT}
PANEL_SSL_CERT=
PANEL_SSL_KEY=
FRONTEND_DIST=${APP_DIR}/frontend/dist
# Which PHP version the panel acts on when a site does not name one. Written
# here because this is the only place that knows what was installed: Ubuntu
# 24.04 gets 8.3 and 8.4, 26.04 carries 8.5 alone, and EL gets 8.3 and 8.4 from
# Remi. Without it the panel fell back to a constant and asked the helper about
# a version the machine did not have.
DEFAULT_PHP_VERSION=${PHP_DEFAULT}
ENV

  # Lock down the env file: contains SECRET_KEY and ALLOWED_ORIGINS.
  chmod 0640 "${APP_DIR}/backend/.env"

  # Make panel files writable before seed creates the SQLite DB and admin Linux user.
  chown -R snpanel:snpanel "${APP_DIR}/backend"
  chown -R snpanel:snpanel "${APP_DIR}/frontend" 2>/dev/null || true

  sudo -u snpanel env HOME="$APP_DIR" SNPANEL_USE_HELPER=true SNPANEL_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    "${APP_DIR}/backend/.venv/bin/python" -m app.seed
  deactivate || true
}

wait_for_backend() {
  for _ in {1..30}; do
    if curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${PANEL_PORT}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  journalctl -u snpanel-api -n 80 --no-pager || true
  fail "snpanel-api did not respond at http://127.0.0.1:${PANEL_PORT}/api/health"
}

setup_systemd() {
  cat >/usr/local/sbin/snpanel-api-start <<STARTER
#!/usr/bin/env bash
# app.serve builds the uvicorn server in Python: the same options the command
# line used to take, plus one certificate per hostname. The panel is therefore
# reachable on every domain on this machine that has a certificate, instead of
# only on the one PANEL_DOMAIN names.
#
# Trusted forwarders: only the local Nginx (127.0.0.1) is allowed to set
# X-Forwarded-For / X-Forwarded-Proto. Anything else (direct hits on
# the configured panel port) cannot spoof the audit log IP or the login rate-limit key.
set -euo pipefail
cd ${APP_DIR}/backend
exec ${APP_DIR}/backend/.venv/bin/python -m app.serve
STARTER
  chmod 0755 /usr/local/sbin/snpanel-api-start

  cat >/etc/systemd/system/snpanel-api.service <<SERVICE
[Unit]
Description=SNPanel API
After=network.target mariadb.service

[Service]
Type=exec
User=snpanel
Group=snpanel
SupplementaryGroups=${WEB_GROUP} snpanel-sites
WorkingDirectory=${APP_DIR}/backend
EnvironmentFile=${APP_DIR}/backend/.env
Environment=HOME=${APP_DIR}
Environment=SNPANEL_USE_HELPER=true
ExecStart=/usr/local/sbin/snpanel-api-start
Restart=always
RestartSec=3

# Hardening. These settings must not block the sudo helper; privileged work is
# restricted by /usr/local/sbin/snpanel-helper and /etc/sudoers.d/snpanel.
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=${APP_DIR} /home ${BACKUP_ROOT} /etc/nginx/conf.d /etc/nginx/snpanel/custom /tmp /var/lib/snpanel /home/admin/snpanel_backups/da /var/lib/snpanel/da-import /var/lib/snpanel/import-stage
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=false
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=~

[Install]
WantedBy=multi-user.target
SERVICE

  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel /var/lib/snpanel/geoip
  cat >/etc/systemd/system/snpanel-backup-scheduler.service <<SERVICE
[Unit]
Description=SNPanel scheduled backup runner
After=network.target mariadb.service

[Service]
Type=oneshot
User=snpanel
Group=snpanel
SupplementaryGroups=${WEB_GROUP} snpanel-sites
WorkingDirectory=${APP_DIR}/backend
EnvironmentFile=${APP_DIR}/backend/.env
Environment=HOME=${APP_DIR}
Environment=SNPANEL_USE_HELPER=true
ExecStart=${APP_DIR}/backend/.venv/bin/python -m app.services.backup_scheduler
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=${APP_DIR} /home ${BACKUP_ROOT} /etc/nginx/conf.d /etc/nginx/snpanel/custom /tmp /var/lib/snpanel /home/admin/snpanel_backups/da /var/lib/snpanel/da-import /var/lib/snpanel/import-stage
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

  cat >/etc/systemd/system/snpanel-backup-scheduler.timer <<'SERVICE'
[Unit]
Description=Run SNPanel scheduled backups every minute

[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=15s
Persistent=true

[Install]
WantedBy=timers.target
SERVICE

  cat >/etc/systemd/system/snpanel-malware-scheduler.service <<SERVICE
[Unit]
Description=SNPanel weekly malware scan runner
After=network.target ${CLAMAV_SERVICE}

[Service]
Type=oneshot
# The runner blocks until the scan it starts finishes (a whole-server scan can
# take hours). Without this, systemd's 90s default start timeout kills it and
# the scan lands in 'interrupted'.
TimeoutStartSec=infinity
User=snpanel
Group=snpanel
SupplementaryGroups=${WEB_GROUP} snpanel-sites
WorkingDirectory=${APP_DIR}/backend
EnvironmentFile=${APP_DIR}/backend/.env
Environment=HOME=${APP_DIR}
Environment=SNPANEL_USE_HELPER=true
ExecStart=${APP_DIR}/backend/.venv/bin/python -m app.services.malware_schedule
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=${APP_DIR} /home ${BACKUP_ROOT:-/var/backups/snpanel} /tmp /var/lib/snpanel
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

  cat >/etc/systemd/system/snpanel-malware-scheduler.timer <<'SERVICE'
[Unit]
Description=Ask every quarter of an hour whether the weekly malware scan is due

[Timer]
# Often enough that a server asleep at the appointed hour still scans when it
# comes back, while the runner itself refuses to start twice in one window.
OnBootSec=5min
OnUnitActiveSec=15min
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
SERVICE

  # snpanel-helper refuses to run unless SUDO_USER names the panel account, so
  # this unit sets it. The sibling boot units (firewall, blocklist) do the same:
  # the helper then runs as root here with no real sudo in front of it.
  cat >/etc/systemd/system/snpanel-autotune.service <<'SERVICE'
[Unit]
Description=Auto tune SNPanel PHP-FPM pools and MariaDB for this VPS
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper php-fpm-retune
ExecStart=/usr/local/sbin/snpanel-helper mariadb-retune
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
SERVICE

  # Keep the clock honest. TOTP logins reject every code once it drifts past
  # ~30s, and many budget VPS hosts block outbound UDP 123 so systemd-timesyncd
  # never converges - snpanel-helper time-sync then falls back to an HTTPS Date
  # header.
  timedatectl set-ntp true >/dev/null 2>&1 || true
  # Timezone is the operator's call - only touched when PANEL_TIMEZONE is set.
  if [[ -n "$PANEL_TIMEZONE" ]]; then
    if timedatectl set-timezone "$PANEL_TIMEZONE" >/dev/null 2>&1; then
      log "Server timezone set to ${PANEL_TIMEZONE}"
    else
      log "WARNING: PANEL_TIMEZONE='${PANEL_TIMEZONE}' is not a valid zone; timezone left unchanged"
    fi
  fi
  cat >/etc/systemd/system/snpanel-timesync.service <<'SERVICE'
[Unit]
Description=Correct the SNPanel server clock when NTP cannot reach the network
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper time-sync
RemainAfterExit=no
SERVICE
  cat >/etc/systemd/system/snpanel-timesync.timer <<'SERVICE'
[Unit]
Description=Check the SNPanel server clock at boot and hourly

[Timer]
OnBootSec=45s
OnUnitActiveSec=1h
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
SERVICE

  systemctl daemon-reload
  systemctl disable --now snpanel-auto-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/snpanel-auto-update.service /etc/systemd/system/snpanel-auto-update.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now snpanel-api
  systemctl enable --now snpanel-backup-scheduler.timer
  systemctl enable --now snpanel-malware-scheduler.timer
  systemctl enable snpanel-autotune.service >/dev/null 2>&1 || true
  systemctl start snpanel-autotune.service >/dev/null 2>&1 || true
  systemctl enable snpanel-timesync.timer >/dev/null 2>&1 || true
  if id -u snpanel >/dev/null 2>&1; then
    # Start the clock unit only once the helper that answers `time-sync` is in
    # place, so it never flashes up as a failed unit mid-install.
    systemctl start snpanel-timesync.timer >/dev/null 2>&1 || true
    systemctl start snpanel-timesync.service >/dev/null 2>&1 || true
    sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper certbot-auto-renew-install >/dev/null 2>&1 || true
    sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper firewall-blocklist-timer-install >/dev/null 2>&1 || true
    # Certificates the panel can answer a handshake with, plus the renewal hook
    # that keeps them fresh.
    sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper panel-sni-sync >/dev/null 2>&1 || true
  fi
  wait_for_backend
}

write_tools_nginx_config() {
  local api_scheme="http" tools_scheme="http" pma_secure="false" ssl_block=""
  if [[ -n "${PANEL_SSL_CERT:-}" && -n "${PANEL_SSL_KEY:-}" && -f "${PANEL_SSL_CERT}" && -f "${PANEL_SSL_KEY}" ]]; then
    api_scheme="https"
    tools_scheme="https"
    pma_secure="true"
    printf -v ssl_block '\n    listen 443 ssl http2 default_server;\n    ssl_certificate %s;\n    ssl_certificate_key %s;' "$PANEL_SSL_CERT" "$PANEL_SSL_KEY"
  fi

  cat >/etc/nginx/conf.d/00-snpanel-tools.conf <<NGINX
server {
    listen 80 default_server;${ssl_block}
    server_name _;
    client_max_body_size 1100M;

    # Panel certificates are issued through this, so the panel no longer has to
    # stop nginx to prove it owns its own hostname.
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files \$uri =404;
        access_log off;
        auth_basic off;
    }

    location = /phpmyadmin {
        return 301 /phpmyadmin/;
    }

    location /phpmyadmin/ {
        alias ${PHPMYADMIN_ROOT}/;
        index index.php;
        try_files \$uri \$uri/ =404;
    }

    location ~ ^/phpmyadmin/(.+\.php)$ {
        alias ${PHPMYADMIN_ROOT}/\$1;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME ${PHPMYADMIN_ROOT}/\$1;
        fastcgi_param SCRIPT_NAME /phpmyadmin/\$1;
        # Twig raises its deprecations as E_USER_DEPRECATED, which php.ini's
        # E_ALL & ~E_DEPRECATED does not exclude, so Debian's pairing of
        # phpMyAdmin 5.2 with Twig 3.21 shows the administrator a wall of
        # notices about a library they cannot change. Silenced here and only
        # here: a customer's own site may well want its deprecations.
        fastcgi_param PHP_VALUE "error_reporting=E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED";
        fastcgi_pass unix:/run/php/php${PHP_DEFAULT}-fpm.sock;
        fastcgi_read_timeout 300;
    }
}
NGINX

  local host
  host="${PANEL_DOMAIN:-$SERVER_IP}"
  [[ -n "$host" ]] || host="$(detect_server_ip)"
  sed -i -E "/api\/databases\/phpmyadmin-sso/s#'[^']+/api/databases/phpmyadmin-sso/'#'${api_scheme}://127.0.0.1:${PANEL_PORT}/api/databases/phpmyadmin-sso/'#" ${PHPMYADMIN_ROOT}/snpanel-signon.php 2>/dev/null || true
  sed -i -E "s#('secure' => )(true|false)#\1${pma_secure}#" ${PHPMYADMIN_CONF_DIR}/conf.d/snpanel-signon.php ${PHPMYADMIN_ROOT}/snpanel-signon.php 2>/dev/null || true
  sed -i -E "/PmaAbsoluteUri/s#'https?://[^']+/phpmyadmin/'#'${tools_scheme}://${host}/phpmyadmin/'#" ${PHPMYADMIN_CONF_DIR}/conf.d/snpanel-signon.php 2>/dev/null || true
}


# phpMyAdmin's own storage account, the one it calls the control user.
#
# Debian's package sets this up through dbconfig-common at unpack time. If
# MariaDB is not running then - which is exactly the case when an install is
# retried after the database failed to start - dbconfig records the password it
# chose and creates nothing, and never tries again because the package counts
# as configured. phpMyAdmin then connects with credentials for an account that
# does not exist and shows every administrator:
#
#   mysqli::real_connect(): (HY000/1045): Access denied for user
#   'phpmyadmin'@'localhost' (using password: YES)
#
# The values come from dbconfig rather than being invented here, so the
# package's own configuration stays true.
setup_phpmyadmin_control_user() {
  local conf=/etc/dbconfig-common/phpmyadmin.conf
  [[ "$OS_FAMILY" == "debian" ]] || return 0
  [[ -f "$conf" ]] || return 0

  local pma_user pma_pass pma_db schema
  pma_user="$(sed -n "s/^dbc_dbuser='\(.*\)'$/\1/p" "$conf" | head -1)"
  pma_pass="$(sed -n "s/^dbc_dbpass='\(.*\)'$/\1/p" "$conf" | head -1)"
  pma_db="$(sed -n "s/^dbc_dbname='\(.*\)'$/\1/p" "$conf" | head -1)"
  [[ -n "$pma_user" && -n "$pma_pass" && -n "$pma_db" ]] || return 0

  # ALTER as well as CREATE: an account that already exists keeps its old
  # password through `CREATE USER IF NOT EXISTS`, which is how a mismatch like
  # this one survives a re-run.
  mariadb -e "
    CREATE DATABASE IF NOT EXISTS \`${pma_db}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
    CREATE USER IF NOT EXISTS '${pma_user}'@'localhost' IDENTIFIED BY '${pma_pass}';
    ALTER USER '${pma_user}'@'localhost' IDENTIFIED BY '${pma_pass}';
    GRANT ALL PRIVILEGES ON \`${pma_db}\`.* TO '${pma_user}'@'localhost';
    FLUSH PRIVILEGES;
  " || { echo "WARNING: could not create the phpMyAdmin control user; its configuration storage will be unavailable"; return 0; }

  # The storage is only useful with its tables in it.
  for schema in /usr/share/phpmyadmin/sql/create_tables.sql \
                /usr/share/doc/phpmyadmin/examples/create_tables.sql; do
    [[ -f "$schema" ]] || continue
    mariadb "$pma_db" <"$schema" >/dev/null 2>&1 || true
    break
  done

  if mariadb -u "$pma_user" -p"$pma_pass" -e "SELECT 1" >/dev/null 2>&1; then
    echo "phpMyAdmin control user ready (${pma_user}, database ${pma_db})"
  else
    echo "WARNING: the phpMyAdmin control user still cannot connect"
  fi
}

setup_phpmyadmin_sso() {
  local blowfish_secret
  blowfish_secret="$(openssl rand -hex 32)"
  local pma_host pma_scheme pma_secure
  pma_host="${PANEL_DOMAIN:-$SERVER_IP}"
  [[ -n "$pma_host" ]] || pma_host="$(detect_server_ip)"
  pma_scheme="http"
  pma_secure="false"
  if [[ "$ENABLE_SSL" == "yes" ]]; then
    pma_scheme="https"
    pma_secure="true"
  fi

  cat >${PHPMYADMIN_CONF_DIR}/conf.d/snpanel-signon.php <<PHP
<?php
\$cfg['blowfish_secret'] = '${blowfish_secret}';
\$i = 1;
\$cfg['Servers'][\$i]['auth_type'] = 'signon';
\$cfg['Servers'][\$i]['SignonSession'] = 'SNPanelPmaSignon';
\$cfg['Servers'][\$i]['SignonCookieParams'] = [
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => ${pma_secure},
    'httponly' => true,
    'samesite' => 'Lax',
];
\$cfg['Servers'][\$i]['SignonURL'] = '/phpmyadmin/snpanel-signon.php';
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['only_db'] = '';
\$cfg['SessionSavePath'] = '/var/lib/php/sessions';
\$cfg['PmaAbsoluteUri'] = '${pma_scheme}://${pma_host}/phpmyadmin/';
PHP

  cat >${PHPMYADMIN_ROOT}/snpanel-signon.php <<'PHP'
<?php
declare(strict_types=1);

session_save_path('/var/lib/php/sessions');
ini_set('session.use_cookies', 'true');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => __SNPANEL_PMA_COOKIE_SECURE__,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_name('SNPanelPmaSignon');
if (!session_start()) {
    http_response_code(500);
    exit('Cannot start signon session');
}

$token = $_GET['snpanel_sso'] ?? '';
if (!preg_match('/^[A-Za-z0-9_-]{20,}$/', $token)) {
    http_response_code(403);
    exit('Invalid token');
}

$apiUrl = '__SNPANEL_API_BASE__' . rawurlencode($token);
$ch = curl_init($apiUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER => ['Accept: application/json'],
]);
$response = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($status !== 200 || !$response) {
    http_response_code(403);
    exit('Expired token');
}

$data = json_decode($response, true);
if (!is_array($data) || empty($data['db_user']) || empty($data['db_password'])) {
    http_response_code(403);
    exit('Invalid signon data');
}

session_regenerate_id(true);
$_SESSION = [];
$_SESSION['PMA_single_signon_user'] = $data['db_user'];
$_SESSION['PMA_single_signon_password'] = $data['db_password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
$_SESSION['PMA_single_signon_port'] = '';
$_SESSION['PMA_single_signon_cfgupdate'] = [
    'only_db' => $data['db_name'] ?? '',
];
$_SESSION['PMA_single_signon_HMAC_secret'] = bin2hex(random_bytes(16));
session_write_close();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Location: /phpmyadmin/index.php?server=1');
exit;
PHP

  local api_scheme="http"
  if [[ "$ENABLE_SSL" == "yes" ]]; then
    api_scheme="https"
  fi
  sed -i "s#__SNPANEL_API_BASE__#${api_scheme}://127.0.0.1:${PANEL_PORT}/api/databases/phpmyadmin-sso/#" ${PHPMYADMIN_ROOT}/snpanel-signon.php
  sed -i "s#__SNPANEL_PMA_COOKIE_SECURE__#${pma_secure}#" ${PHPMYADMIN_ROOT}/snpanel-signon.php

  chown root:${WEB_GROUP} ${PHPMYADMIN_CONF_DIR}/conf.d/snpanel-signon.php
  chmod 640 ${PHPMYADMIN_CONF_DIR}/conf.d/snpanel-signon.php
  chmod 644 ${PHPMYADMIN_ROOT}/snpanel-signon.php
}

# EL ships its default `server { listen 80 default_server; ... }` inside
# nginx.conf itself, where Debian ships it as a separate site file that the
# next line deletes. The panel's tools vhost also declares default_server, so
# leaving it in place makes nginx refuse to start with "duplicate default
# server for 0.0.0.0:80". The block is commented out rather than cut, so an
# administrator can still see what the distribution had put there.
neutralise_distro_default_site() {
  [[ "$OS_FAMILY" == "rhel" ]] || return 0
  local conf=/etc/nginx/nginx.conf
  [[ -f "$conf" ]] || return 0
  grep -q 'SNPanel: distribution default server disabled' "$conf" && return 0
  [[ -f "${conf}.snpanel-orig" ]] || cp -a "$conf" "${conf}.snpanel-orig"

  awk '
    BEGIN { state = 0; depth = 0 }
    state == 0 && /^[[:space:]]*server[[:space:]]*\{/ {
      print "    # SNPanel: distribution default server disabled. The panel serves"
      print "    # the default vhost from conf.d/00-snpanel-tools.conf, and two"
      print "    # default_server blocks make nginx refuse to start."
      state = 1
    }
    state == 1 {
      opens = gsub(/\{/, "{")
      closes = gsub(/\}/, "}")
      depth += opens - closes
      print "#" $0
      if (depth <= 0) { state = 2 }
      next
    }
    { print }
  ' "$conf" >"${conf}.snpanel-new" || fail "Could not rewrite ${conf}"
  mv "${conf}.snpanel-new" "$conf"
}

setup_nginx() {
  neutralise_distro_default_site
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/snpanel.conf /etc/nginx/sites-available/snpanel.conf 2>/dev/null || true
  write_tools_nginx_config
  nginx -t
  systemctl reload nginx
}

setup_firewall() {
  # IP filtering is driven by snpanel-helper, which picks its backend per
  # platform - iptables plus ipset on Ubuntu, nftables on EL. Any UFW install
  # left over from an older SNPanel release is removed here.
  local ssh_port helper="/usr/local/sbin/snpanel-helper"
  set +e
  # sshd -T (used by the helper) misses ports only visible from the live SSH
  # session or a non-default sshd_config, so seed those explicitly first.
  while read -r ssh_port; do
    [[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] || continue
    sudo -u snpanel env HOME="$APP_DIR" sudo -n "$helper" firewall-allow-port "$ssh_port" tcp >/dev/null 2>&1
  done < <(detect_ssh_ports || true)
  sudo -u snpanel env HOME="$APP_DIR" sudo -n "$helper" firewall-migrate
  # A fresh install always enforces; firewall-migrate only inherits the
  # previous state when upgrading an existing box.
  sudo -u snpanel env HOME="$APP_DIR" sudo -n "$helper" firewall-enable
  set -e
  return 0
}

setup_selfsigned_ssl() {
  # No domain, or Let's Encrypt declined. The panel still takes an admin
  # password, so it gets a certificate of its own rather than answering in the
  # clear: the browser warns once, which is one warning more than plain HTTP
  # gives anybody.
  local host san
  host="${PANEL_DOMAIN:-${SERVER_IP:-127.0.0.1}}"
  san="DNS:${host}"
  [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && san="IP:${host}"
  [[ -n "${SERVER_IP:-}" && "$SERVER_IP" != "$host" ]] && san="${san},IP:${SERVER_IP}"
  install -d -o root -g snpanel -m 0750 /etc/snpanel
  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout /etc/snpanel/panel-selfsigned-privkey.pem \
      -out /etc/snpanel/panel-selfsigned-fullchain.pem \
      -subj "/CN=${host}" -addext "subjectAltName=${san}" >/dev/null 2>&1; then
    echo "WARNING: could not generate a self-signed certificate; the panel stays on HTTP" >&2
    return 0
  fi
  chown root:snpanel /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
  chmod 0640 /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
  PANEL_SSL_CERT=/etc/snpanel/panel-selfsigned-fullchain.pem
  PANEL_SSL_KEY=/etc/snpanel/panel-selfsigned-privkey.pem
  PANEL_URL="https://${host}:${PANEL_PORT}"
  sed -i \
    -e "s#^PANEL_SSL_CERT=.*#PANEL_SSL_CERT=${PANEL_SSL_CERT}#" \
    -e "s#^PANEL_SSL_KEY=.*#PANEL_SSL_KEY=${PANEL_SSL_KEY}#" \
    -e "s#^PANEL_URL=.*#PANEL_URL=${PANEL_URL}#" \
    -e "s#^ALLOWED_ORIGINS=.*#ALLOWED_ORIGINS=${PANEL_URL}#" \
    "${APP_DIR}/backend/.env"
  grep -q "^PANEL_SSL_MODE=" "${APP_DIR}/backend/.env" \
    && sed -i "s#^PANEL_SSL_MODE=.*#PANEL_SSL_MODE=selfsigned#" "${APP_DIR}/backend/.env" \
    || echo "PANEL_SSL_MODE=selfsigned" >>"${APP_DIR}/backend/.env"
  write_tools_nginx_config
  nginx -t && systemctl reload nginx
  systemctl restart snpanel-api
  for _ in {1..20}; do
    if curl -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:${PANEL_PORT}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  # Better a panel that answers than a locked-out operator: put it back and say so.
  echo "WARNING: the panel did not come up over HTTPS; reverting to HTTP" >&2
  PANEL_URL="http://${host}:${PANEL_PORT}"
  PANEL_SSL_CERT=""
  PANEL_SSL_KEY=""
  sed -i \
    -e "s#^PANEL_SSL_CERT=.*#PANEL_SSL_CERT=#" \
    -e "s#^PANEL_SSL_KEY=.*#PANEL_SSL_KEY=#" \
    -e "s#^PANEL_SSL_MODE=.*#PANEL_SSL_MODE=#" \
    -e "s#^PANEL_URL=.*#PANEL_URL=${PANEL_URL}#" \
    -e "s#^ALLOWED_ORIGINS=.*#ALLOWED_ORIGINS=${PANEL_URL}#" \
    "${APP_DIR}/backend/.env"
  systemctl restart snpanel-api
}

setup_ssl() {
  if [[ "$ENABLE_SSL" != "yes" ]]; then
    setup_selfsigned_ssl
    return 0
  fi

  certbot certonly --standalone \
    -d "$PANEL_DOMAIN" \
    --email "$SSL_EMAIL" \
    --agree-tos \
    --non-interactive \
    --pre-hook "systemctl stop nginx || true" \
    --post-hook "systemctl start nginx || true" \
    --deploy-hook "install -d -o root -g snpanel -m 0750 /etc/snpanel && install -m 0640 -o root -g snpanel /etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem /etc/snpanel/panel-fullchain.pem && install -m 0640 -o root -g snpanel /etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem /etc/snpanel/panel-privkey.pem && systemctl restart snpanel-api || true"
  install -d -o root -g snpanel -m 0750 /etc/snpanel
  install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
  install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem" /etc/snpanel/panel-privkey.pem
  PANEL_SSL_CERT=/etc/snpanel/panel-fullchain.pem
  PANEL_SSL_KEY=/etc/snpanel/panel-privkey.pem
  sed -i \
    -e "s#^PANEL_SSL_CERT=.*#PANEL_SSL_CERT=/etc/snpanel/panel-fullchain.pem#" \
    -e "s#^PANEL_SSL_KEY=.*#PANEL_SSL_KEY=/etc/snpanel/panel-privkey.pem#" \
    -e "s#^PANEL_URL=.*#PANEL_URL=${PANEL_URL}#" \
    -e "s#^ALLOWED_ORIGINS=.*#ALLOWED_ORIGINS=${PANEL_URL}#" \
    "${APP_DIR}/backend/.env"
  write_tools_nginx_config
  nginx -t
  systemctl reload nginx
  systemctl restart snpanel-api
  for _ in {1..20}; do
    if curl -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:${PANEL_PORT}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  journalctl -u snpanel-api -n 80 --no-pager || true
  fail "snpanel-api did not respond after enabling panel SSL"
}

print_summary() {
  echo ""
  echo "=================================================="
  echo "Panel URL: ${PANEL_URL}"
  echo "User: admin"
  echo "Password: ${ADMIN_PASSWORD}"
  case "$IPV6_RESULT" in
    on:*) echo "IPv6: enabled on ${IPV6_RESULT#on:}" ;;
    failed) echo "IPv6: detected but not enabled - turn it on in Panel settings" ;;
    *) echo "IPv6: not available on this server" ;;
  esac
  echo "=================================================="
}

write_login_info() {
  local tmp
  (
    if command -v flock >/dev/null 2>&1; then
      flock -x 9
    fi
    tmp="$(mktemp /root/login.txt.XXXXXX)"
    chmod 600 "$tmp"
    cat >"$tmp" <<INFO
Panel URL: ${PANEL_URL}
User: admin
Password: ${ADMIN_PASSWORD}
INFO
    mv -f "$tmp" /root/login.txt
  ) 9>/root/.snpanel-login.lock
  chmod 600 /root/login.txt
}

source_version() {
  if [[ -f "${PROJECT_ROOT}/VERSION" ]]; then
    tr -d '[:space:]' <"${PROJECT_ROOT}/VERSION"
    return 0
  fi
  sed -nE 's/^APP_VERSION = "([^"]+)"/\1/p' "${PROJECT_ROOT}/backend/app/core/version.py" 2>/dev/null | head -n 1
}

write_update_state() {
  local version now
  version="$(source_version)"
  version="${version:-1.0.59}"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel /var/lib/snpanel/geoip
  cat >/var/lib/snpanel/update-status.json <<STATE
{
  "current_version": "${version}",
  "latest_tag": "v${version}",
  "latest_version": "${version}",
  "last_checked_at": "${now}",
  "last_update_finished_at": "${now}",
  "last_update_ref": "v${version}",
  "last_update_status": "installed"
}
STATE
  chown snpanel:snpanel /var/lib/snpanel/update-status.json 2>/dev/null || true
  chmod 0640 /var/lib/snpanel/update-status.json
}

cleanup_release_source() {
  [[ "${CLEAN_RELEASE_SOURCE:-true}" == "true" ]] || return 0
  [[ "$PROJECT_ROOT" == "/opt/snpanel-source" ]] || return 0
  [[ ! -d "${PROJECT_ROOT}/.git" ]] || return 0
  log "Removing release source from ${PROJECT_ROOT}"
  cd /
  rm -rf "$PROJECT_ROOT" /tmp/snpanel-release /tmp/snpanel-release.zip
}

enable_ipv6_when_available() {
  # A fresh install takes the network as it finds it: a machine that already
  # has a global IPv6 address should serve on it without somebody having to go
  # and find the switch. Servers that update into this are left alone - their
  # admin decides.
  #
  # This cannot conjure an address the provider assigned but never configured;
  # only the ones the machine actually holds are detected.
  id -u snpanel >/dev/null 2>&1 || return 0
  local status
  status="$(sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper ipv6-status 2>/dev/null || true)"
  if [[ "$status" != *"available=yes"* ]]; then
    log "No global IPv6 address on this server; IPv6 stays off"
    IPV6_RESULT="off"
    return 0
  fi
  local address
  address="$(printf '%s\n' "$status" | sed -n 's/^addresses=//p' | head -n1)"
  if sudo -u snpanel env HOME="$APP_DIR" sudo -n /usr/local/sbin/snpanel-helper ipv6-enable >/dev/null 2>&1; then
    log "IPv6 detected (${address}); websites and panel will answer on it too"
    IPV6_RESULT="on:${address}"
  else
    log "WARNING: IPv6 was detected but could not be enabled; turn it on from Panel settings"
    IPV6_RESULT="failed"
  fi
}

configure_log_limits() {
  # systemd-journald ships with no size limit: it falls back to 10% of the
  # filesystem, which on a 72G disk is 7.2G. Measured on a live server, the
  # journal had reached 2.7G - 53 times the size of every nginx log put
  # together - fed mostly by SSH password-guessing hitting sshd thousands of
  # times an hour. nginx's own logs were never the problem; they rotate daily,
  # keep 14 days and compress, and totalled 51M.
  #
  # A drop-in rather than an edit of journald.conf, so a distribution upgrade
  # cannot quietly revert it.
  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-snpanel-size.conf <<'JOURNALD'
# Managed by SNPanel.
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=2week
JOURNALD
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=500M >/dev/null 2>&1 || true

  # btmp records every failed login and Ubuntu ships no rule for it. On the
  # same server it had grown to 130M across two files, holding 62,000 failed
  # SSH attempts. `su root root` is required because /var/log is root:syslog
  # and group-writable, and logrotate refuses to act on a file in a directory
  # it considers unsafe unless told whose identity to use.
  cat >/etc/logrotate.d/btmp <<'BTMP'
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
  chmod 644 /etc/logrotate.d/btmp
}

main() {
  detect_platform
  # The platform knows which PHP versions this release can actually provide.
  PHP_VERSIONS="${PHP_VERSIONS:-$PLATFORM_PHP_VERSIONS}"
  PHP_DEFAULT="${PHP_DEFAULT:-$PLATFORM_PHP_DEFAULT}"
  log "PHP versions for this platform: ${PHP_VERSIONS} (default ${PHP_DEFAULT})"
  validate_sources
  ask_panel_url

  log "Installing base packages"
  install_base_packages

  log "Installing Node.js"
  install_nodejs

  log "Installing PHP ${PHP_VERSIONS}"
  install_php

  log "Configuring Nginx FastCGI cache"
  configure_fastcgi_cache
  configure_proxy_upgrade_map

  log "Configuring WAF engine and HTTP flood protection"
  if ! install_waf_engine; then
    echo "WARNING: WAF engine installation failed; continuing without ModSecurity."
  fi

  log "Installing WP-CLI"
  install_wp_cli

  log "Copying source to ${APP_DIR}"
  copy_sources

  log "Building frontend"
  build_frontend

  log "Creating snpanel system user, MariaDB credentials and filesystem ACLs"
  setup_panel_user

  log "Configuring SFTP access for panel users"
  setup_sftp_access

  log "Installing privileged helper and sudoers rule"
  install_privileged_helper

  log "Installing SSH maintenance menu"
  install_panel_cli

  log "Validating privileged helper"
  validate_privileged_helper

  log "Configuring backend"
  setup_backend

  log "Creating systemd service (hardened, runs as snpanel user)"
  setup_systemd

  log "Configuring phpMyAdmin SSO"
  setup_phpmyadmin_control_user
  setup_phpmyadmin_sso

  log "Preparing Nginx for customer websites"
  setup_nginx

  log "Configuring firewall"
  setup_firewall

  log "Capping log growth (journald + btmp)"
  configure_log_limits

  log "Configuring SSL"
  setup_ssl

  log "Checking for IPv6"
  enable_ipv6_when_available

  write_login_info
  write_update_state

  print_summary
  cleanup_release_source
}

main "$@"
