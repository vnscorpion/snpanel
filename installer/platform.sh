#!/usr/bin/env bash
# Per-distribution values for the SNPanel installer.
#
# The Rust side solves this with `snpanel_osabi::platform::Platform`; this is
# the same table for the shell. It is one file on purpose: when a value is
# wrong you want a single place to look, and writing this from EL9 habits
# produced four wrong values that measuring on AlmaLinux 10.2 corrected -
#
#   * EL10 has no `redis` package at all. Valkey replaced it, as `valkey`,
#     with a `valkey.service` unit. Wire-compatible on 6379, so REDIS_URL is
#     unchanged; only the unit name differs.
#   * phpMyAdmin *is* packaged, in EPEL, at /usr/share/phpMyAdmin - with the
#     project's own capitalisation, unlike Debian's lowercase path.
#   * AlmaLinux 10.2 ships dnf 4.20, not dnf5, so the dnf4 CLI applies and the
#     `crb` repository is already enabled out of the box.
#   * Node.js 22 is in the AppStream repository, so EL needs no NodeSource.
#
# Remi's PHP layout was checked the same way and rhel.rs had it right:
# php84-php-fpm.service, /etc/opt/remi/php84/php-fpm.d,
# /opt/remi/php84/root/usr/bin/php, with PHP 8.3.33 and 8.4.25 both present.

# shellcheck disable=SC2034  # every value here is consumed by install.sh

detect_platform() {
  [[ -f /etc/os-release ]] || fail "Cannot find /etc/os-release"
  # shellcheck disable=SC1091
  source /etc/os-release

  OS_ID="${ID:-}"
  # AlmaLinux 10.0 reports VERSION_ID=10 and 10.2 reports 10.2, so compare the
  # major only - a point release is not a different platform.
  OS_MAJOR="${VERSION_ID%%.*}"
  OS_PRETTY="${PRETTY_NAME:-${OS_ID} ${VERSION_ID:-}}"

  case "${OS_ID}" in
    ubuntu)
      case "${VERSION_ID:-}" in
        24.04) ;;
        *) fail "Only Ubuntu 24.04 is supported. Current OS: ${OS_PRETTY}" ;;
      esac
      platform_debian
      ;;
    debian)
      case "${OS_MAJOR}" in
        12|13) ;;
        *) fail "Only Debian 12 and 13 are supported. Current OS: ${OS_PRETTY}" ;;
      esac
      platform_debian
      ;;
    almalinux|rocky|rhel|ol|centos)
      [[ "${OS_MAJOR}" == "10" ]] || fail "Only version 10 of the RHEL family is supported. Current OS: ${OS_PRETTY}"
      platform_rhel10
      ;;
    *)
      fail "This installer supports Ubuntu 24.04 and AlmaLinux 10. Current OS: ${OS_PRETTY}"
      ;;
  esac

  echo "Platform: ${OS_PRETTY} -> ${OS_FAMILY}"
}

platform_debian() {
  OS_FAMILY="debian"

  WEB_USER="www-data"
  WEB_GROUP="www-data"

  SSH_SERVICE="ssh"
  REDIS_SERVICE="redis-server"
  CRON_SERVICE="cron"
  # The panel's malware scanner unit orders itself after ClamAV.
  CLAMAV_SERVICE="clamav-daemon.service"
  NOLOGIN_SHELL="/usr/sbin/nologin"

  PHPMYADMIN_ROOT="/usr/share/phpmyadmin"
  PHPMYADMIN_CONF_DIR="/etc/phpmyadmin"

  # Node.js comes from NodeSource here; Ubuntu's own nodejs is too old.
  NODE_FROM_NODESOURCE="yes"
  # libnginx-mod-http-modsecurity is packaged on Debian/Ubuntu.
  WAF_AVAILABLE="yes"

  # Ubuntu gets PHP from Ondrej\'s PPA, which is where 8.3 and 8.4 come from.
  #
  # Only 24.04 reaches here. 26.04 was tried and dropped: the PPA publishes no
  # `resolute` suite - checked against the PPA itself, where the newest is
  # noble - so the only PHP available there is the distribution's 8.5, and a
  # panel that cannot install the version a customer's site runs is not
  # support. Revisit when the PPA publishes for it.
  PHP_FROM_PPA="yes"
  PLATFORM_PHP_VERSIONS="8.3 8.4"
  PLATFORM_PHP_DEFAULT="8.4"

  BASE_PACKAGES=(
    ca-certificates curl gnupg git composer
    nginx mariadb-server redis-server openssh-server
    python3 python3-pip python3-venv
    certbot python3-certbot-nginx
    tar zip unzip openssl iptables ipset phpmyadmin acl
  )
  EXTRA_PACKAGES=()

  # Ubuntu and Debian share a package manager and a filesystem layout, and not
  # much else that matters here.
  if [[ "${OS_ID:-ubuntu}" == "debian" ]]; then
    # There is no `add-apt-repository` on Debian, and the package that provides
    # it is not even in the archive - asking for it fails the first
    # transaction. PHP comes from packages.sury.org instead, added with a
    # keyring and a sources list. It carries 7.4 through 8.5 for trixie, which
    # is more than the Ubuntu PPA offers.
    PHP_FROM_PPA="no"
    PHP_FROM_SURY="yes"
    # NodeSource publishes no trixie suite; Debian's own nodejs is 20.19, and
    # the panel asks for 20 or newer.
    NODE_FROM_NODESOURCE="no"
    case "${OS_MAJOR:-13}" in
      13) PLATFORM_PHP_VERSIONS="8.3 8.4"; PLATFORM_PHP_DEFAULT="8.4" ;;
      *)  PLATFORM_PHP_VERSIONS="8.2 8.3"; PLATFORM_PHP_DEFAULT="8.3" ;;
    esac
  else
    PHP_FROM_SURY="no"
    # Ubuntu keeps the package that provides add-apt-repository.
    BASE_PACKAGES=(software-properties-common "${BASE_PACKAGES[@]}")
  fi
}

platform_rhel10() {
  OS_FAMILY="rhel"

  # nginx runs as `nginx` here, not `www-data`. Every group membership and
  # every file the web server has to read follows from this one value.
  WEB_USER="nginx"
  WEB_GROUP="nginx"

  SSH_SERVICE="sshd"
  # Not `redis` - see the header.
  REDIS_SERVICE="valkey"
  CRON_SERVICE="crond"
  # EL packages ClamAV as a templated unit, not clamav-daemon.
  CLAMAV_SERVICE="clamd@scan.service"
  NOLOGIN_SHELL="/sbin/nologin"

  PHPMYADMIN_ROOT="/usr/share/phpMyAdmin"
  PHPMYADMIN_CONF_DIR="/etc/phpMyAdmin"

  # AppStream carries nodejs 22.23.2, which is the version the panel asks for,
  # so there is no reason to pipe a vendor script into bash here.
  NODE_FROM_NODESOURCE="no"
  # Measured on 10.2: nginx-mod-modsecurity, modsecurity and modsecurity-crs
  # are all absent, and `mod_security` is the Apache module, not nginx's. The
  # WAF engine therefore cannot be installed from packages, and the installer
  # says so rather than leaving a panel that claims a WAF it has not got.
  WAF_AVAILABLE="no"

  # Remi carries both, and the installer sets them up together.
  PHP_FROM_PPA="no"
  PHP_FROM_SURY="no"
  PLATFORM_PHP_VERSIONS="8.3 8.4"
  PLATFORM_PHP_DEFAULT="8.4"

  BASE_PACKAGES=(
    ca-certificates curl gnupg2 git
    nginx mariadb-server valkey openssh-server openssh-clients
    python3 python3-pip
    tar zip unzip openssl acl
    # EL10 has no legacy iptables binary, only the nft shim. The panel's
    # firewall backend is nftables here, chosen by snpanel-osabi.
    nftables ipset
    policycoreutils-python-utils
    chrony cronie crontabs
    nodejs
    # Ubuntu's cloud image ships these; a minimal EL image does not. sudo is
    # not optional - the panel runs every privileged action through
    # `sudo -n snpanel-helper`, and without /etc/sudoers.d the install stops
    # dead. rsync only makes the updater take its faster path.
    sudo rsync
  )
  # In EPEL, which enable_extra_repos installs before the base transaction.
  EXTRA_PACKAGES=(certbot python3-certbot-nginx phpmyadmin composer)
}

# --- package manager ---------------------------------------------------------

pkg_update_index() {
  case "$OS_FAMILY" in
    debian) apt_get_locked update --allow-releaseinfo-change ;;
    rhel)   dnf -y makecache ;;
  esac
}

pkg_install() {
  case "$OS_FAMILY" in
    debian) apt_get_locked install -y "$@" ;;
    rhel)   dnf -y install "$@" ;;
  esac
}

# Is this package installable? Used to skip PHP extensions a repository does
# not carry, rather than failing a whole transaction over one optional module.
#
# `apt-cache show` is the obvious idiom and the wrong one: it succeeds for a
# name the archive merely references. On Ubuntu 26.04, `apt-cache show
# php7.4-fpm` returns 0 while `apt-cache policy` reports `Candidate: (none)`.
# A false yes here puts an uninstallable package into one `apt-get install`,
# which fails the whole transaction - the opposite of what this check is for.
pkg_exists() {
  local candidate
  case "$OS_FAMILY" in
    debian)
      candidate="$(apt-cache policy "$1" 2>/dev/null | sed -n 's/^  Candidate: //p')"
      [[ -n "$candidate" && "$candidate" != "(none)" ]]
      ;;
    rhel)   dnf -q info "$1" >/dev/null 2>&1 ;;
  esac
}

pkg_installed() {
  case "$OS_FAMILY" in
    debian) dpkg -s "$1" >/dev/null 2>&1 ;;
    rhel)   rpm -q "$1" >/dev/null 2>&1 ;;
  esac
}

# --- PHP layout --------------------------------------------------------------
#
# Remi's layout is not a variant spelling of Debian's. PHP 8.4 is
# `php84-php-fpm` as a service, `/opt/remi/php84/root/usr/bin/php` as a binary,
# `/etc/opt/remi/php84/php.ini` as its configuration, and `php84-php-<ext>` as
# an extension package. install_php bridges the difference for the panel by
# presenting the Debian-shaped paths as symlinks into this tree; see
# setup_php_compat_shim in install.sh for what that covers and what it does not.

php_compact() { printf '%s' "${1//./}"; }

# The real unit name. The shim also installs a `php<version>-fpm` alias,
# because the panel's Python service layer restarts that name.
php_service() {
  case "$OS_FAMILY" in
    debian) printf 'php%s-fpm' "$1" ;;
    rhel)   printf 'php%s-php-fpm' "$(php_compact "$1")" ;;
  esac
}

php_binary() {
  case "$OS_FAMILY" in
    debian) printf '/usr/bin/php%s' "$1" ;;
    rhel)   printf '/opt/remi/php%s/root/usr/bin/php' "$(php_compact "$1")" ;;
  esac
}

php_etc_dir() {
  case "$OS_FAMILY" in
    debian) printf '/etc/php/%s/fpm' "$1" ;;
    rhel)   printf '/etc/opt/remi/php%s' "$(php_compact "$1")" ;;
  esac
}

php_ini_path() { printf '%s/php.ini' "$(php_etc_dir "$1")"; }

# Where a drop-in .ini goes, one per line. Debian keeps a separate conf.d per
# SAPI; Remi has a single php.d read by both CLI and FPM, so a value the panel
# sets for FPM also applies to CLI there. That is a real behavioural
# difference, not a path detail, and it is why this returns a list.
php_conf_dirs() {
  case "$OS_FAMILY" in
    debian) printf '/etc/php/%s/cli/conf.d\n/etc/php/%s/fpm/conf.d\n' "$1" "$1" ;;
    rhel)   printf '/etc/opt/remi/php%s/php.d\n' "$(php_compact "$1")" ;;
  esac
}

php_fpm_pool_dir() {
  case "$OS_FAMILY" in
    debian) printf '/etc/php/%s/fpm/pool.d' "$1" ;;
    rhel)   printf '/etc/opt/remi/php%s/php-fpm.d' "$(php_compact "$1")" ;;
  esac
}

# The socket the panel's generated vhosts point at. Debian's php-fpm listens
# here by default; on EL the pool is rewritten to match, because the path is
# baked into the panel's nginx templates and its Python validation regex.
php_fpm_socket() { printf '/run/php/php%s-fpm.sock' "$1"; }

# The packages for one PHP version, one per line.
#
# The two lists are not the same set with different prefixes. On Remi: `mysql`
# is `mysqlnd`; `sqlite3` is folded into `pdo`; `curl`, `fileinfo`, `json` and
# `posix` are inside `php-common` and have no package of their own; `zip` and
# `redis` are PECL builds; and imagick exists only as the ImageMagick 7 build,
# `pecl-imagick-im7`. Callers probe each name with pkg_exists and skip what is
# missing, so a version without one optional module still installs.
php_ext_packages() {
  local v="$1" c
  case "$OS_FAMILY" in
    debian)
      local ext
      for ext in fpm cli mysql sqlite3 gd xml mbstring curl zip opcache intl bcmath redis imagick; do
        printf 'php%s-%s\n' "$v" "$ext"
      done
      ;;
    rhel)
      c="$(php_compact "$v")"
      local pkg
      for pkg in fpm cli common mysqlnd pdo gd xml mbstring opcache intl bcmath soap pecl-zip pecl-redis6 pecl-imagick-im7; do
        printf 'php%s-php-%s\n' "$c" "$pkg"
      done
      ;;
  esac
}
