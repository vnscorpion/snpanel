#!/usr/bin/env bash
# /usr/local/sbin/snpanel-helper
#
# Root-privileged trampoline for the SNPanel API daemon.
# This is the ONLY code that runs as root for the daemon.
# Installed by install.sh as root:root mode 0750, callable only by user
# 'snpanel' through sudo (see /etc/sudoers.d/snpanel).
#
# Every operation here is the trust boundary. Validate aggressively.

set -euo pipefail

if [[ "${SUDO_USER:-}" != "snpanel" ]]; then
  echo "snpanel-helper must be invoked by user 'snpanel' via sudo" >&2
  exit 2
fi

# Reset PATH so an attacker cannot ship a shadow binary in snpanel's PATH.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# `valkey` is EL10's Redis: that distribution ships no `redis` package at all.
# Both names are allowed on both platforms - this is an allowlist, and naming a
# unit that does not exist locally fails harmlessly at systemctl.
# The PHP entries track ALLOWED_PHP_VERSIONS in the panel rather than whichever
# versions one release happens to ship: Ubuntu 24.04 gets 8.3 and 8.4 from
# Ondrej's PPA, 26.04 carries only 8.5, and EL gets 8.3 and 8.4 from Remi. An
# allowlist entry for a version this machine does not have is harmless - the
# service simply does not exist - whereas a missing one means the panel cannot
# restart the PHP it is actually running.
ALLOWED_SERVICES=(nginx mariadb redis-server valkey snpanel-api
                  php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm)

# The account nginx runs as: `www-data` on Debian, `nginx` on EL, or whatever an
# administrator has put in nginx.conf. Reading the running configuration beats a
# per-distribution table here for two reasons: this file is the trust boundary,
# and sourcing another file to learn two strings widens it; and nginx.conf is
# the thing that actually decides who has to be able to read a customer's files.
WEB_USER="$(awk '$1=="user"{gsub(/;/,"",$2); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null)"
[[ -n "$WEB_USER" ]] || WEB_USER="www-data"
WEB_GROUP="$(id -gn "$WEB_USER" 2>/dev/null || printf '%s' "$WEB_USER")"
# WP-CLI needs a HOME it can write a cache into. Debian gives www-data
# /var/www; EL gives nginx /var/lib/nginx. Asking passwd covers both and any
# third case, and /var/www remains the fallback for a passwd entry with none.
WEB_USER_HOME="$(getent passwd "$WEB_USER" 2>/dev/null | cut -d: -f6)"
[[ -n "$WEB_USER_HOME" && -d "$WEB_USER_HOME" ]] || WEB_USER_HOME="/var/www"

# Packages have no configuration file to read, so this one does dispatch on the
# distribution.
if [[ -r /etc/os-release ]] && grep -Eq '^(ID|ID_LIKE)=.*(rhel|centos|fedora|almalinux|rocky)' /etc/os-release; then
  OS_FAMILY="rhel"
else
  OS_FAMILY="debian"
fi

pkg_update_index() {
  case "$OS_FAMILY" in
    debian) DEBIAN_FRONTEND=noninteractive apt-get update --allow-releaseinfo-change ;;
    rhel)   dnf -y makecache ;;
  esac
}

pkg_install() {
  case "$OS_FAMILY" in
    debian) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    rhel)   dnf -y install "$@" ;;
  esac
}

# An operation that exists only on Debian. Refusing with the reason beats
# reaching apt-get and reporting "command not found", which reads like a broken
# PATH rather than a settled fact about the distribution.
deny_debian_only() {
  [[ "$OS_FAMILY" == "debian" ]] && return 0
  deny "$1 is only available on Debian and Ubuntu; this system is ${OS_FAMILY}"
}
ALLOWED_ACTIONS=(start stop restart reload status is-active is-enabled)
HOME_ROOT="/home"
NGINX_CONF_DIR="/etc/nginx/conf.d"
PHP_CONF_DIRS=(/etc/php/{5.6,7.4,8.0,8.1,8.2,8.3,8.4,8.5}/fpm/conf.d)
SNPANEL_SITES_GROUP="snpanel-sites"
# Default permissions for everything inside a site tree. 0644/0755 is what every
# hosting panel gives a customer, and what PHP applications, SFTP clients and
# their documentation assume. Sites stay separated by the PHP-FPM open_basedir
# of each pool, by the SFTP chroot and by the panel terminal, not by these bits.
SITE_FILE_MODE="0644"
SITE_DIR_MODE="0755"
# Files that carry database credentials are kept off the default mode.
SITE_SECRET_FILES=(wp-config.php .env .my.cnf)
SNPANEL_SFTP_GROUP="snpanel-sftp"
# One directory per certificate, so the panel can answer a TLS handshake with
# the certificate for whichever hostname the browser asked for. The panel runs
# as 'snpanel' and cannot read /etc/letsencrypt, hence the copies.
PANEL_SNI_DIR="/etc/snpanel/sni"
# IPv6 is off until somebody turns it on, and this file is what says so. It is
# the only truth: the panel reads it, the tools vhost is rendered from it, and
# an update re-applies it. World readable on purpose - it holds no secret and
# the panel runs as 'snpanel'.
PANEL_IPV6_MARKER="/etc/snpanel/ipv6-enabled"
MALWARE_JOBS_DIR="/var/lib/snpanel/malware-scan-jobs"
# Left out of a whole-server scan: kernel filesystems that are not files at
# all, read-only squashfs images, package caches that are re-downloadable, and
# the signature database itself. Scanning them costs hours and finds nothing.
MALWARE_SCAN_PRUNE=(/proc /sys /dev /run /snap /var/lib/docker /var/lib/lxcfs /var/lib/clamav /var/cache/apt/archives)
APP_DIR="/opt/snpanel"
ENV_FILE="${APP_DIR}/backend/.env"
DEFAULT_PANEL_PORT="2222"
SOURCE_DIR="/opt/snpanel-source"
UPDATE_SCRIPT="/usr/local/sbin/snpanel-update"
SNPANEL_DATA_DIR="/var/lib/snpanel"
BACKUP_ROOT="/var/backups/snpanel"
FIREWALL_BLOCKLIST_URLS="${SNPANEL_DATA_DIR}/firewall-blocklists.urls"
FIREWALL_BLOCKLIST_WORK="${SNPANEL_DATA_DIR}/firewall-blocklists.current"
FIREWALL_DIR="${SNPANEL_DATA_DIR}/firewall"
FIREWALL_RULES_FILE="${FIREWALL_DIR}/rules.tsv"
FIREWALL_STATE_FILE="${FIREWALL_DIR}/state"
FIREWALL_CHAIN="SNPANEL-INPUT"
FIREWALL_PROTECTED_PORTS=(22 80 443 465 587)
NGINX_SNPANEL_DIR="/etc/nginx/snpanel"
NGINX_BLOCKLIST_DIR="$NGINX_SNPANEL_DIR"
NGINX_BLOCKLIST_CONF="/etc/nginx/conf.d/snpanel-ip-blocklist.conf"
NGINX_BLOCKLIST_RULES="${NGINX_SNPANEL_DIR}/ip-blocklist-geo.conf"
NGINX_BLOCKLIST_SERVER_CONF="${NGINX_SNPANEL_DIR}/ip-blocklist-server.conf"
NGINX_CUSTOM_DIR="${NGINX_SNPANEL_DIR}/custom"
NGINX_HTTP_FLOOD_CONF="/etc/nginx/conf.d/00-snpanel-http-flood.conf"
NGINX_HTTP_FLOOD_LEGACY_CONF="/etc/nginx/conf.d/snpanel-http-flood.conf"
NGINX_HTTP_FLOOD_ZONES="${NGINX_BLOCKLIST_DIR}/http-flood-zones.conf"
NGINX_HTTP_FLOOD_SERVER_CONF="${NGINX_BLOCKLIST_DIR}/http-flood-server.conf"
PHP_FPM_DEFAULT_WORKER_MB=128
PHP_FPM_DEFAULT_REQUEST_TERMINATE_TIMEOUT=300
MARIADB_TUNING_CONF="/etc/mysql/mariadb.conf.d/90-snpanel-tuning.cnf"

deny() { echo "snpanel-helper: $*" >&2; exit 1; }

ensure_snpanel_data_dir() {
  install -d -o snpanel -g snpanel -m 0750 "$SNPANEL_DATA_DIR"
}

ensure_nginx_conf_dir_writable() {
  install -d -o root -g root -m 0755 "$NGINX_BLOCKLIST_DIR"
  if getent group snpanel >/dev/null 2>&1; then
    install -d -o root -g snpanel -m 2775 "$NGINX_CONF_DIR"
    install -d -o root -g snpanel -m 2775 "$NGINX_CUSTOM_DIR"
    chmod g+s "$NGINX_CONF_DIR" 2>/dev/null || true
    chmod g+s "$NGINX_CUSTOM_DIR" 2>/dev/null || true
  else
    install -d -o root -g root -m 0755 "$NGINX_CONF_DIR"
    install -d -o root -g root -m 0755 "$NGINX_CUSTOM_DIR"
  fi
}

file_has_nul() {
  local path="$1"
  python3 - "$path" <<'PY'
import sys

with open(sys.argv[1], "rb") as handle:
    data = handle.read()
sys.exit(0 if b"\0" in data else 1)
PY
}

env_get() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

env_set() {
  local key="$1" value="$2" escaped
  [[ -f "$ENV_FILE" ]] || deny "$ENV_FILE not found"
  escaped="$(printf '%s' "$value" | sed -e 's/[&|]/\\&/g')"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

detect_ip() {
  hostname -I 2>/dev/null | awk '{print $1}' || true
}

is_ipv4() {
  local value="$1" part
  local -a parts
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a parts <<<"$value"
  for part in "${parts[@]}"; do
    (( 10#$part >= 0 && 10#$part <= 255 )) || return 1
  done
}

is_domain() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
}

require_panel_scheme() {
  [[ "$1" == "http" || "$1" == "https" ]] || deny "invalid panel scheme: $1"
}

require_panel_host() {
  local host="$1"
  if is_domain "$host" || is_ipv4 "$host" || [[ "$host" == "localhost" ]]; then
    return 0
  fi
  deny "invalid panel host: $host"
}

allow_panel_port() {
  # Panel/SSH/web ports are always derived from the environment, so re-applying
  # the iptables chain is enough to open a newly selected panel port.
  #
  # This must never fail the caller (panel-ssl-install, panel-url-set, ...):
  # a firewall problem here is not the SSL/URL change failing. `|| true`
  # alone does not guarantee that - firewall_apply (via firewall_require_tools)
  # calls deny(), which does `exit`, and exit in a plain command tears down
  # this whole process before `|| true` ever gets a status to swallow. Run it
  # in a subshell so that exit only ends the subshell.
  local port="$1"
  require_port "$port"
  ( firewall_apply ) >/dev/null 2>&1 || true
}

schedule_panel_restart() {
  local unit
  systemctl daemon-reload || true
  if command -v systemd-run >/dev/null 2>&1; then
    unit="snpanel-api-delayed-restart-$(date +%s)"
    systemd-run --unit="$unit" --on-active=2s /bin/systemctl restart snpanel-api >/dev/null 2>&1 || true
  else
    (sleep 2; systemctl restart snpanel-api >/dev/null 2>&1 || true) >/dev/null 2>&1 &
  fi
}

refresh_tools_nginx() {
  local port cert key domain host api_scheme tools_scheme pma_secure ssl_block php_version
  port="$(env_get PANEL_PORT)"; port="${port:-$DEFAULT_PANEL_PORT}"
  cert="$(env_get PANEL_SSL_CERT)"; key="$(env_get PANEL_SSL_KEY)"
  domain="$(env_get PANEL_DOMAIN)"; host="${domain:-$(detect_ip)}"
  php_version="${PHP_DEFAULT:-8.4}"
  api_scheme="http"; tools_scheme="http"; pma_secure="false"; ssl_block=""
  local v6_http="" v6_https=""
  if ipv6_is_enabled; then
    # default_server is per address:port, so [::]:80 may carry it as well.
    v6_http=$'\n    listen [::]:80 default_server;'
    v6_https=$'\n    listen [::]:443 ssl http2 default_server;'
  fi
  if [[ -n "$cert" && -n "$key" && -f "$cert" && -f "$key" ]]; then
    api_scheme="https"; tools_scheme="https"; pma_secure="true"
    printf -v ssl_block '\n    listen 443 ssl http2 default_server;%s\n    ssl_certificate %s;\n    ssl_certificate_key %s;' "$v6_https" "$cert" "$key"
  fi
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true
  ensure_nginx_conf_dir_writable
  firewall_purge_nginx_blocklist 2>/dev/null || true
  write_http_flood_nginx_conf 2>/dev/null || true
  cat >/etc/nginx/conf.d/00-snpanel-tools.conf <<NGINX
server {
    listen 80 default_server;${v6_http}${ssl_block}
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
    location = /phpmyadmin { return 301 /phpmyadmin/; }
    location /phpmyadmin/ { alias /usr/share/phpmyadmin/; index index.php; try_files \$uri \$uri/ =404; }
    location ~ ^/phpmyadmin/(.+\.php)$ { alias /usr/share/phpmyadmin/\$1; include fastcgi_params; fastcgi_param SCRIPT_FILENAME /usr/share/phpmyadmin/\$1; fastcgi_param SCRIPT_NAME /phpmyadmin/\$1; fastcgi_pass unix:/run/php/php${php_version}-fpm.sock; fastcgi_read_timeout 300; }
}
NGINX
  sed -i -E "/api\/databases\/phpmyadmin-sso/s#'[^']+/api/databases/phpmyadmin-sso/'#'${api_scheme}://127.0.0.1:${port}/api/databases/phpmyadmin-sso/'#" /usr/share/phpmyadmin/snpanel-signon.php 2>/dev/null || true
  sed -i -E "s#('secure' => )(true|false)#\1${pma_secure}#" /etc/phpmyadmin/conf.d/snpanel-signon.php /usr/share/phpmyadmin/snpanel-signon.php 2>/dev/null || true
  [[ -n "$host" ]] && sed -i -E "/PmaAbsoluteUri/s#'https?://[^']+/phpmyadmin/'#'${tools_scheme}://${host}/phpmyadmin/'#" /etc/phpmyadmin/conf.d/snpanel-signon.php 2>/dev/null || true
  nginx -t
  systemctl reload nginx || true
}

configure_unattended_upgrades() {
  local enabled="$1" mode="$2" reboot="$3" origins
  [[ "$enabled" == "on" || "$enabled" == "off" ]] || deny "enabled must be on/off"
  [[ "$mode" == "security" || "$mode" == "all" ]] || deny "mode must be security/all"
  [[ "$reboot" == "on" || "$reboot" == "off" ]] || deny "auto reboot must be on/off"
  # unattended-upgrades is an apt-specific mechanism with an apt-specific
  # configuration format. EL's nearest equivalent, dnf-automatic, is configured
  # nothing like it, so this refuses rather than half-applying a policy that the
  # panel would then display as active.
  deny_debian_only "automatic security updates"

  DEBIAN_FRONTEND=noninteractive apt-get update --allow-releaseinfo-change
  DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades apt-listchanges

  if [[ "$enabled" == "off" ]]; then
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
APT
    systemctl disable --now unattended-upgrades.service 2>/dev/null || true
    echo "OS auto updates disabled"
    return 0
  fi

  origins='        "${distro_id}:${distro_codename}-security";'
  if [[ "$mode" == "all" ]]; then
    origins='        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-updates";
        "${distro_id}:${distro_codename}-security";'
  fi

  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT
  cat >/etc/apt/apt.conf.d/51snpanel-unattended-upgrades <<APT
Unattended-Upgrade::Allowed-Origins {
${origins}
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$([[ "$reboot" == "on" ]] && echo true || echo false)";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
APT
  systemctl enable --now unattended-upgrades.service 2>/dev/null || true
  echo "OS auto updates enabled (${mode}, reboot=${reboot})"
}

run_os_update_now() {
  export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
  pkg_update_index
  if [[ "$OS_FAMILY" == "rhel" ]]; then
    # The two Dpkg::Options below ask apt to keep a configuration file the
    # administrator has edited. rpm does that by default - it installs the new
    # one alongside as .rpmnew - so the EL form needs no equivalent flags.
    dnf -y upgrade
    return
  fi
  apt-get \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    upgrade -y
}

run_os_update() {
  local unit="snpanel-os-update"
  if systemctl is-active --quiet "${unit}.service"; then
    echo "OS update is already running: ${unit}.service"
    return 0
  fi
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run \
      --unit="$unit" \
      --collect \
      --description="Update OS packages for SNPanel" \
      /bin/bash -lc 'export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none; apt-get update --allow-releaseinfo-change; apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade -y'
    echo "OS update started: ${unit}.service"
    echo "Check progress: journalctl -u ${unit}.service -f"
    return 0
  fi
  nohup /bin/bash -lc 'export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none; apt-get update --allow-releaseinfo-change; apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade -y' \
    >/var/log/snpanel-os-update.log 2>&1 &
  echo "OS update started in background. Log: /var/log/snpanel-os-update.log"
}

run_panel_update() {
  [[ -f "$UPDATE_SCRIPT" ]] || deny "missing $UPDATE_SCRIPT"
  local unit="snpanel-panel-update"
  if systemctl is-active --quiet "${unit}.service"; then
    echo "Panel update is already running: ${unit}.service"
    return 0
  fi
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run \
      --unit="$unit" \
      --collect \
      --description="Update SNPanel from GitHub" \
      --property="Environment=SOURCE_DIR=${SOURCE_DIR}" \
      --property="Environment=APP_DIR=${APP_DIR}" \
      --property="Environment=REPO_URL=${REPO_URL:-https://github.com/vnscorpion/snpanel.git}" \
      --property="Environment=GIT_REMOTE=${GIT_REMOTE:-origin}" \
      --property="Environment=UPDATE_CHANNEL=${UPDATE_CHANNEL:-release}" \
      --property="Environment=BRANCH=${BRANCH:-main}" \
      --property="Environment=RELEASE_TAG=${RELEASE_TAG:-}" \
      --property="Environment=RELEASE_PATTERN=${RELEASE_PATTERN:-v[0-9]*.[0-9]*.[0-9]*}" \
      --property="Environment=SKIP_PULL=${SKIP_PULL:-false}" \
      /bin/bash "$UPDATE_SCRIPT"
    echo "Panel update started: ${unit}.service"
    echo "Check progress: journalctl -u ${unit}.service -f"
    return 0
  fi
  nohup env \
    SOURCE_DIR="$SOURCE_DIR" \
    APP_DIR="$APP_DIR" \
    REPO_URL="${REPO_URL:-https://github.com/vnscorpion/snpanel.git}" \
    GIT_REMOTE="${GIT_REMOTE:-origin}" \
    UPDATE_CHANNEL="${UPDATE_CHANNEL:-release}" \
    BRANCH="${BRANCH:-main}" \
    RELEASE_TAG="${RELEASE_TAG:-}" \
    RELEASE_PATTERN="${RELEASE_PATTERN:-v[0-9]*.[0-9]*.[0-9]*}" \
    SKIP_PULL="${SKIP_PULL:-false}" \
    /bin/bash "$UPDATE_SCRIPT" \
    >/var/log/snpanel-panel-update.log 2>&1 &
  echo "Panel update started in background. Log: /var/log/snpanel-panel-update.log"
}

write_modsec_base_conf() {
  install -d -o root -g root -m 0755 /etc/nginx/modsec /etc/nginx/modsec/sites
  {
    [[ -f /etc/modsecurity/modsecurity.conf ]] && echo "Include /etc/modsecurity/modsecurity.conf"
    echo "SecRuleEngine On"
    # Request bodies are not buffered: uploads on a shared host are large and
    # frequent, and buffering them costs memory on every PHP site at once.
    #
    # The consequence is easy to miss and was live for months: with body access
    # off the nginx connector never runs phase 2 at all, so a phase:2 rule is
    # silently dead - it loads, it shows as enabled, and it never matches.
    # Every rule SNPanel ships is therefore phase:1, which sees the URI and the
    # query string. test_waf_rules_are_phase_1 enforces that.
    #
    # Turning this on is what a payload-inspecting rule set (OWASP CRS) needs,
    # and it must arrive together with CRS's exclusion tuning: on its own it
    # would make the traversal rule match "../" inside any post body a customer
    # saves.
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

write_waf_default_rules() {
  install -d -o root -g root -m 0755 /etc/nginx/modsec
  cat >/etc/nginx/modsec/snpanel-default.conf <<'RULES'
# SNPanel default WAF rules: lightweight WordPress, Laravel, and PHP probes only.
SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/\.user\.ini(?:\.|$)|/\.git/|/composer\.(?:json|lock)(?:$|[?])|/(?:phpinfo|info)\.php(?:$|[?])|/(?:config|database|db)\.php\.(?:bak|old|save|txt)(?:$|[?]))" "id:1001301,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP sensitive file probe'"
SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)" "id:1001302,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP path traversal'"
SecRule REQUEST_URI "@rx (?i)(?:/(?:c99|r57|shell|cmd|wso)\.php(?:$|[?])|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php(?:$|[?]))" "id:1001303,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP runtime probe'"
SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/artisan(?:$|[?])|/server\.php(?:$|[?])|/storage/logs/[^?]*\.log(?:$|[?])|/bootstrap/cache/[^?]*\.php(?:$|[?]))" "id:1001201,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel sensitive path'"
SecRule REQUEST_URI "@rx (?i)(?:/_ignition/execute-solution(?:$|[?]))" "id:1001202,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel Ignition RCE probe'"
SecRule REQUEST_URI "@rx (?i)(?:/wp-config\.php(?:\.|$|[?])|/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])|/wp-admin/includes/[^?]*\.php(?:$|[?])|/wp-includes/[^?]*\.php(?:$|[?]))" "id:1001101,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress sensitive path'"
SecRule ARGS:author "@rx ^[0-9]+$" "id:1001103,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress author enumeration'"
SecRule REQUEST_URI "@rx (?i)(?:/wp-admin/install\.php(?:$|[?])|/wp-admin/setup-config\.php(?:$|[?]))" "id:1001104,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress installer probe'"
RULES
}

ORPHAN_ARCHIVE_ROOT=/root/snpanel-removed

orphan_live_domains() {
  # The panel owns the truth about which domains exist, so it hands the list in
  # on stdin rather than the helper guessing from the filesystem it is about to
  # delete from. Anything that is not a valid domain is dropped, not trusted.
  local line
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | tr -d '[:space:]' | tr 'A-Z' 'a-z')"
    [[ -n "$line" ]] || continue
    is_domain "$line" || continue
    printf '%s\n' "$line"
  done
}

orphan_cert_covers_live() {
  # A lineage named for a dead site can still carry a live name as a SAN, and
  # deleting it would take that live site's HTTPS down.
  local cert="$1" live_file="$2" san
  [[ -f "$cert" ]] || return 1
  while read -r san; do
    [[ -n "$san" ]] || continue
    grep -qxF "$san" "$live_file" && return 0
  done < <( { openssl x509 -ext subjectAltName -noout -in "$cert" 2>/dev/null || true; } \
            | grep -oE 'DNS:[^,]+' | sed 's/DNS://g; s/ //g' )
  return 1
}

cleanup_orphans() {
  # Remove what is left on disk for websites this panel no longer has.
  #
  # Everything is copied into /root/snpanel-removed first. These are customer
  # certificates and configuration: "unreferenced" is a strong inference, not a
  # certainty, and an admin who removed a site by accident should be able to get
  # it back. Nothing here is ever deleted without a copy.
  local mode="${1:-clean}" live_file stamp archive panel_domain name base
  local -i certs=0 rules=0 baks=0 manual=0 sni=0
  live_file="$(mktemp)"
  orphan_live_domains >"$live_file"
  panel_domain="$(env_get PANEL_DOMAIN)"
  [[ -n "$panel_domain" ]] && printf '%s\n' "$panel_domain" >>"$live_file"
  # An empty list almost certainly means the caller failed, not that the server
  # hosts nothing. Refuse rather than delete everything on the machine.
  if [[ ! -s "$live_file" ]]; then
    rm -f "$live_file"
    deny "refusing to clean orphans: no live domains were supplied"
  fi

  stamp="$(date -u +%Y%m%d-%H%M%S)"
  archive="${ORPHAN_ARCHIVE_ROOT}/orphans-${stamp}"
  [[ "$mode" == "clean" ]] && install -d -m 0700 "$archive"

  is_live() { grep -qxF "$1" "$live_file"; }

  # 1. Let's Encrypt lineages for sites that are gone. These are the ones that
  #    matter: the renewal config keeps waking certbot.timer and starts failing
  #    the day the domain stops pointing here.
  for conf in /etc/letsencrypt/renewal/*.conf; do
    [[ -f "$conf" ]] || continue
    name="$(basename "$conf" .conf)"
    is_domain "$name" || continue
    is_live "$name" && continue
    orphan_cert_covers_live "/etc/letsencrypt/live/${name}/cert.pem" "$live_file" && continue
    echo "cert	${name}"
    certs+=1
    if [[ "$mode" == "clean" ]]; then
      install -d -m 0700 "${archive}/certs"
      cp -a "$conf" "${archive}/certs/" 2>/dev/null || true
      tar czhf "${archive}/certs/${name}.tar.gz" -C /etc/letsencrypt/live "$name" 2>/dev/null || true
      certbot delete --cert-name "$name" --non-interactive >/dev/null 2>&1 || true
    fi
  done

  # 2. Per-site WAF rule files. delete_waf_site_rules has the check that matters
  #    - a file a running vhost still names must never go - so reuse it.
  for f in /etc/nginx/modsec/sites/*.conf; do
    [[ -f "$f" ]] || continue
    name="$(basename "$f" .conf)"
    is_domain "$name" || continue
    is_live "$name" && continue
    echo "waf-rules	${name}"
    rules+=1
    if [[ "$mode" == "clean" ]]; then
      install -d -m 0700 "${archive}/waf"
      cp -a "$f" "${archive}/waf/" 2>/dev/null || true
      delete_waf_site_rules "$name" >/dev/null 2>&1 || true
    fi
  done

  # 3. Vhost backups nginx never reads. Only for domains with no vhost left.
  for f in /etc/nginx/conf.d/*.conf.bak*; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    name="${base%%.conf.bak*}"
    is_domain "$name" || continue
    is_live "$name" && continue
    [[ -f "/etc/nginx/conf.d/${name}.conf" ]] && continue
    echo "vhost-backup	${base}"
    baks+=1
    if [[ "$mode" == "clean" ]]; then
      install -d -m 0700 "${archive}/vhost"
      cp -a "$f" "${archive}/vhost/" 2>/dev/null || true
      rm -f "$f"
    fi
  done

  # 4. Uploaded certificates for sites that are gone.
  for d in /etc/nginx/snpanel/ssl/sites/*/; do
    [[ -d "$d" ]] || continue
    name="$(basename "$d")"
    is_domain "$name" || continue
    is_live "$name" && continue
    echo "manual-ssl	${name}"
    manual+=1
    if [[ "$mode" == "clean" ]]; then
      install -d -m 0700 "${archive}/manual-ssl"
      tar czf "${archive}/manual-ssl/${name}.tar.gz" -C /etc/nginx/snpanel/ssl/sites "$name" 2>/dev/null || true
      remove_manual_ssl "$name" >/dev/null 2>&1 || true
    fi
  done

  # 5. SNI copies the panel serves on :2222. sync_panel_sni_certificates drops
  #    copies whose source is gone, so this only reports what it will clear.
  for d in "$PANEL_SNI_DIR"/*/; do
    [[ -d "$d" ]] || continue
    name="$(basename "$d")"
    is_domain "$name" || continue
    is_live "$name" && continue
    echo "sni-copy	${name}"
    sni+=1
  done

  if [[ "$mode" == "clean" ]]; then
    sync_panel_sni_certificates >/dev/null 2>&1 || true
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx >/dev/null 2>&1 || true
    fi
    rmdir "$archive" 2>/dev/null || true
  fi
  rm -f "$live_file"
  echo "summary	certs=${certs} waf-rules=${rules} vhost-backups=${baks} manual-ssl=${manual} sni-copies=${sni}"
  [[ "$mode" == "clean" && -d "$archive" ]] && echo "archive	${archive}"
  return 0
}

CRS_MODE_FILE=/etc/nginx/modsec/snpanel-crs-mode
CRS_CONF=/etc/nginx/modsec/snpanel-crs.conf
CRS_AUDIT_LOG=/var/log/nginx/snpanel-modsec-audit.log

crs_rules_dir() {
  # Debian/Ubuntu ship the rules under one of these; the setup file sits either
  # beside them or one level up.
  local dir
  for dir in /usr/share/modsecurity-crs/rules /etc/modsecurity/crs/rules /usr/local/owasp-crs/rules; do
    [[ -d "$dir" ]] && { echo "$dir"; return 0; }
  done
  return 1
}

crs_setup_file() {
  local f
  for f in /etc/modsecurity/crs/crs-setup.conf /usr/share/modsecurity-crs/crs-setup.conf \
           /etc/modsecurity/crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf.example; do
    [[ -f "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

# Is nginx's ModSecurity module actually loaded?
#
# The rule set is useless without it, and worse than useless to install: nginx
# rejects its entire configuration on an unknown `modsecurity` directive, so a
# half-configured WAF takes the whole machine's sites down at the next reload.
# This asks nginx rather than the distribution, so a Debian box whose WAF
# package failed to install gets the same answer as an EL box that has none.
waf_engine_present() {
  # Three ways nginx can have the module, and it needs all three checked:
  #   1. Debian's package drops a load directive here;
  #   2. a static build mentions it in the configure arguments;
  #   3. a module built from source is loaded by a `load_module` directive,
  #      which appears in neither of the above - `nginx -V` reports only what
  #      nginx was compiled with, not what it has loaded.
  # Missing the third would mean building the module by hand and having the
  # panel still insist there is no engine.
  [[ -e /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]] && return 0
  # A here-string, not a pipe. Under `set -o pipefail`, `nginx -V | grep -q`
  # reports failure when grep *matches*: grep exits early, nginx dies of
  # SIGPIPE, and that status becomes the pipeline's.
  grep -qi modsecurity <<<"$(nginx -V 2>&1 || true)" && return 0
  # `load_module` is only legal in the main context, so it lives in nginx.conf
  # or in a file included from it at the top level. Reading those is the same
  # technique the panel uses; `nginx -T` would also work here, but only because
  # this runs as root, and two implementations of one question should not be
  # able to disagree.
  # The same *.conf globs nginx itself includes - not the directories. A
  # recursive grep also reads files nginx never loads, and the guard that
  # disables a broken module renames it to .disabled-by-snpanel rather than
  # deleting it, so a directory search reported a disabled module as present.
  grep -qsiE '^[[:space:]]*load_module.*modsecurity' \
    /etc/nginx/nginx.conf \
    /etc/nginx/modules-enabled/*.conf \
    /usr/share/nginx/modules/*.conf 2>/dev/null
}

install_waf_crs() {
  export DEBIAN_FRONTEND=noninteractive
  if ! waf_engine_present; then
    deny "the OWASP rule set needs nginx's ModSecurity module, which is not installed on this server. AlmaLinux 10 packages neither the module nor the rule set, so there is nothing to install; the WAF page reports the engine as unavailable for this reason."
  fi
  if ! crs_rules_dir >/dev/null; then
    pkg_update_index || true
    pkg_install modsecurity-crs \
      || deny "could not install modsecurity-crs from this system's repositories"
  fi
  crs_rules_dir >/dev/null || deny "modsecurity-crs installed but no rules directory found"
  echo "OWASP CRS rules: $(crs_rules_dir)"
  echo "OWASP CRS setup: $(crs_setup_file || echo 'none - using built-in defaults')"
}

write_crs_conf() {
  # mode: detect | block
  #
  # CRS scores a request across many rules and acts only when the total crosses
  # a threshold, unlike SNPanel's own rules which deny on a single match.
  #
  # Detect mode puts the threshold out of reach so 949110 never refuses
  # anything, and adds a SNPanel rule that reads the same score and only logs.
  #
  # That extra rule is not decoration. Individual CRS rules score silently -
  # measured on a live server, a request that 949110 blocks with a 403 in block
  # mode produces exactly one log line, from 949110 itself. Raise the threshold
  # and the logging goes with it, so the obvious form of detect mode observes
  # nothing at all.
  #
  # Two things that look like alternatives and are not. SecRuleUpdateActionById
  # on 949110: libmodsecurity answers "action has not expected to be used with
  # UpdateActionByID" and the rejected directive takes the rest of the rule set
  # with it. SecRuleEngine DetectionOnly: it would also stop SNPanel's own rules
  # denying on that site, trading real protection for observation.
  #
  # Where to read the results: the audit log configured below. That is where the
  # verdict lands, together with every CRS rule that contributed to the score -
  # on a live server, one SQLi probe recorded 942100, 942190 and 942360 next to
  # the SNPanel line saying the score reached 15. The nginx error_log is the
  # wrong place to look, and the shared /var/log/nginx/error.log doubly so,
  # since each vhost writes to its own.
  local mode="$1" rules setup
  rules="$(crs_rules_dir)" || deny "OWASP CRS is not installed"
  setup="$(crs_setup_file || true)"
  install -d -o root -g root -m 0755 /etc/nginx/modsec
  # The audit log is opened by the nginx worker, so it has to exist and be
  # writable by it before the config is loaded.
  touch "$CRS_AUDIT_LOG"
  chown "${WEB_USER}:adm" "$CRS_AUDIT_LOG" 2>/dev/null || true
  chmod 0640 "$CRS_AUDIT_LOG"
  {
    echo "# SNPanel OWASP CRS include - generated, do not edit"
    echo "# mode: ${mode}"
    # CRS needs request bodies; without them it sees only the URL and the rule
    # set is largely decorative.
    echo "SecRequestBodyAccess On"
    echo "SecRequestBodyLimit 13107200"
    echo "SecRequestBodyNoFilesLimit 131072"
    # Anything over the limit is inspected as far as it goes and then passed.
    # Rejecting instead would turn every large media upload into a 413.
    echo "SecRequestBodyLimitAction ProcessPartial"
    # Record what matched. Without this there is no audit log at all on this
    # machine: Debian's modsecurity.conf is not shipped by the nginx connector
    # package, so nothing configures one.
    echo "SecAuditEngine RelevantOnly"
    echo "SecAuditLogParts ABIJDEFHZ"
    echo "SecAuditLogType Serial"
    echo "SecAuditLog ${CRS_AUDIT_LOG}"
    [[ -n "$setup" ]] && echo "Include ${setup}"
    if [[ "$mode" == "detect" ]]; then
      echo "SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=1000000,setvar:tx.outbound_anomaly_score_threshold=1000000\""
    else
      echo "SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4\""
    fi
    echo "SecAction \"id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=1\""
    echo "Include ${rules}/*.conf"
    if [[ "$mode" == "detect" ]]; then
      # After the rules, so the score is final. 5 and 4 are the thresholds block
      # mode uses, so this reports exactly what block mode would have refused.
      echo "SecRule TX:ANOMALY_SCORE \"@ge 5\" \"id:1009001,phase:2,pass,log,auditlog,msg:'SNPanel CRS detect: inbound score %{tx.anomaly_score}, block mode would have refused this request'\""
      echo "SecRule TX:OUTBOUND_ANOMALY_SCORE \"@ge 4\" \"id:1009002,phase:4,pass,log,auditlog,msg:'SNPanel CRS detect: outbound score %{tx.outbound_anomaly_score}, block mode would have refused this response'\""
    fi
  } >"${CRS_CONF}.tmp"
  install -m 0644 -o root -g root "${CRS_CONF}.tmp" "$CRS_CONF"
  rm -f "${CRS_CONF}.tmp"
  printf '%s\n' "$mode" >"$CRS_MODE_FILE"
  chmod 0644 "$CRS_MODE_FILE"
}

set_waf_crs_mode() {
  local mode="$1"
  case "$mode" in
    off|detect|block) ;;
    *) deny "usage: waf-crs-mode <off|detect|block>" ;;
  esac
  # Switching it *off* must always work, whatever the machine has - that is the
  # way out of a bad state, and refusing it would be the wrong kind of strict.
  if [[ "$mode" != "off" ]] && ! waf_engine_present; then
    deny "cannot turn the OWASP rule set on: nginx has no ModSecurity module on this server, so the rules would not run. Recording the setting anyway would show a protection in the panel that is not there."
  fi
  if [[ "$mode" == "off" ]]; then
    rm -f "$CRS_CONF"
    printf 'off\n' >"$CRS_MODE_FILE"
    chmod 0644 "$CRS_MODE_FILE"
    echo "OWASP CRS disabled"
    return 0
  fi
  install_waf_crs >/dev/null
  write_crs_conf "$mode"
  echo "OWASP CRS mode: ${mode}"
}

nginx_memory_pss_mb() {
  # PSS, not RSS. nginx parses the rule set in the master and the workers fork,
  # so those pages are shared: summing RSS across processes counts them once per
  # worker and overstates the cost several times over. Reading smaps_rollup for
  # another user's processes needs root, which is why this lives in the helper.
  python3 - <<'PY' 2>/dev/null || echo 0
import os, re
pss = 0
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        if open(f'/proc/{pid}/comm').read().strip() != 'nginx':
            continue
        roll = open(f'/proc/{pid}/smaps_rollup').read()
    except OSError:
        continue
    m = re.search(r'^Pss:\s+(\d+) kB', roll, re.M)
    if m:
        pss += int(m.group(1))
print(pss // 1024)
PY
}

waf_crs_status() {
  local mode="off"
  [[ -f "$CRS_MODE_FILE" ]] && mode="$(tr -d '[:space:]' <"$CRS_MODE_FILE")"
  echo "mode=${mode}"
  echo "nginx_pss_mb=$(nginx_memory_pss_mb)"
  echo "ram_available_mb=$(free -m | awk '/^Mem:/{print $7}')"
  echo "ram_total_mb=$(free -m | awk '/^Mem:/{print $2}')"
  echo "installed=$(crs_rules_dir >/dev/null && echo yes || echo no)"
  echo "conf=$([[ -f "$CRS_CONF" ]] && echo yes || echo no)"
  echo "rule_files=$( { crs_rules_dir >/dev/null && ls "$(crs_rules_dir)"/*.conf 2>/dev/null | wc -l; } || echo 0)"
  echo "sites_including=$(grep -lF "Include ${CRS_CONF}" /etc/nginx/modsec/sites/*.conf 2>/dev/null | wc -l)"
}

save_waf_custom_rules() {
  install -d -o root -g root -m 0755 /etc/nginx/modsec
  write_waf_default_rules
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if file_has_nul "$tmp"; then
    rm -f "$tmp"
    deny "WAF rules cannot contain NUL bytes"
  fi
  if [[ $(wc -c <"$tmp") -gt 65536 ]]; then
    rm -f "$tmp"
    deny "WAF custom rules must be 64 KB or smaller"
  fi
  install -m 0644 -o root -g root "$tmp" /etc/nginx/modsec/snpanel-custom.conf
  rm -f "$tmp"
  write_modsec_main_conf
  nginx -t
  systemctl reload nginx
  echo "WAF custom rules saved"
}

delete_waf_site_rules() {
  # Deleting a website used to leave /etc/nginx/modsec/sites/<domain>.conf
  # behind for ever. Harmless to serve, but it hides real state: a rule fix
  # looks half-applied because stale files still carry the old text, and the
  # directory fills with names nobody hosts.
  local domain="$1" target loaded
  require_domain "$domain"
  target="/etc/nginx/modsec/sites/${domain}.conf"
  # A vhost still pointing at this file would make `nginx -t` fail on the next
  # reload and take every site on the box down with it. Never remove a file
  # something still references, whatever the caller believes.
  #
  # Ask nginx what it actually loads rather than grepping conf.d: the directory
  # is full of .conf.bak copies nginx never reads, and matching those refused
  # every legitimate cleanup.
  if ! loaded="$(nginx -T 2>/dev/null)"; then
    deny "refusing to delete WAF rules for ${domain}: nginx config could not be read"
  fi
  if grep -qF "modsecurity_rules_file ${target}" <<<"$loaded"; then
    deny "refusing to delete WAF rules for ${domain}: a vhost still references them"
  fi
  rm -f "$target" "${target}".bak.*
  echo "Removed WAF rules for ${domain}"
}

save_waf_site_rules() {
  local domain="$1" tmp target backup=""
  require_domain "$domain"
  install -d -o root -g root -m 0755 /etc/nginx/modsec /etc/nginx/modsec/sites
  write_modsec_base_conf
  tmp="$(mktemp)"
  cat >"$tmp"
  if file_has_nul "$tmp"; then
    rm -f "$tmp"
    deny "WAF rules cannot contain NUL bytes"
  fi
  if [[ $(wc -c <"$tmp") -gt 163840 ]]; then
    rm -f "$tmp"
    deny "WAF site rules must be 160 KB or smaller"
  fi
  target="/etc/nginx/modsec/sites/${domain}.conf"
  if [[ -f "$target" ]]; then
    backup="${target}.bak.$(date +%s)"
    cp "$target" "$backup"
  fi
  install -m 0644 -o root -g root "$tmp" "$target"
  rm -f "$tmp"
  if ! nginx -t; then
    if [[ -n "$backup" && -f "$backup" ]]; then
      mv -f "$backup" "$target"
    else
      rm -f "$target"
    fi
    deny "Nginx rejected WAF site rules"
  fi
  rm -f "$backup" 2>/dev/null || true
  systemctl reload nginx
  echo "WAF site rules saved: ${domain}"
}

install_waf_engine() {
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s libnginx-mod-http-modsecurity >/dev/null 2>&1; then
    deny_debian_only "installing the nginx ModSecurity module"
    pkg_update_index
    pkg_install libnginx-mod-http-modsecurity modsecurity-crs libmodsecurity3 || \
      pkg_install libnginx-mod-http-modsecurity libmodsecurity3
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
  systemctl reload nginx
  echo "WAF engine installed with SNPanel lightweight WordPress/Laravel/PHP rules."
}

install_clamav_engine() {
  export DEBIAN_FRONTEND=noninteractive
  pkg_update_index
  if ! dpkg -s clamav clamav-daemon >/dev/null 2>&1; then
    pkg_install clamav clamav-daemon
  fi
  # Ensure the daemon socket directory exists and the service is enabled.
  install -d -o clamav -g clamav -m 0755 /run/clamav 2>/dev/null || true
  systemctl enable --now clamav-daemon
  # Triggers an initial signature database refresh in the background.
  freshclam >/dev/null 2>&1 || true
  echo "ClamAV installed and clamav-daemon enabled."
}

# --- Linux Malware Detect (LMD / maldet) ------------------------------------
MALDET_BIN="/usr/local/sbin/maldet"
MALDET_HOME="/usr/local/maldetect"
MALDET_CONF="${MALDET_HOME}/conf.maldet"
MALDET_TARBALL_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"

maldet_write_conf() {
  # Panel-owned settings on top of whatever the rfxn installer shipped. The
  # panel drives scheduling and never auto-quarantines, so its cron is off.
  [[ -f "$MALDET_CONF" ]] || return 0
  local key val kv
  for kv in \
    "quarantine_hits=0" "quarantine_clean=0" "quarantine_suspend_user=0" \
    "scan_clamscan=1" "scan_ignore_root=0" "scan_find_h10k_alert=0" \
    "autoupdate_signatures=1" "autoupdate_version=1" "cron_daily_scan=0" \
    "email_alert=0" "default_monitor_mode=users"
  do
    key="${kv%%=*}"; val="${kv#*=}"
    if grep -qE "^${key}=" "$MALDET_CONF"; then
      sed -i -E "s#^${key}=.*#${key}=\"${val}\"#" "$MALDET_CONF"
    else
      printf '%s="%s"\n' "$key" "$val" >>"$MALDET_CONF"
    fi
  done
  # The panel owns the schedule; disarm the installer's daily cron.
  [[ -f /etc/cron.daily/maldet ]] && chmod a-x /etc/cron.daily/maldet
  return 0
}

install_maldet_engine() {
  export DEBIAN_FRONTEND=noninteractive
  # clamscan is the scan engine; the resident daemon is deliberately not
  # enabled - maldet runs clamscan one-shot so the ~1.3GB of signatures are
  # only resident during a scan.
  if ! command -v clamscan >/dev/null 2>&1; then
    pkg_update_index
    pkg_install clamav || deny "could not install the clamav package (scan engine)"
  fi
  freshclam >/dev/null 2>&1 || true
  command -v wget >/dev/null 2>&1 || command -v curl >/dev/null 2>&1 || pkg_install wget
  # inotifywait is what maldet's Level 2 monitor runs; Debian does not ship it.
  command -v inotifywait >/dev/null 2>&1 || pkg_install inotify-tools || true

  if [[ ! -x "$MALDET_BIN" ]]; then
    local tmp tarball
    tmp="$(mktemp -d /tmp/snpanel-maldet.XXXXXX)"
    tarball="${tmp}/maldetect.tar.gz"
    if command -v wget >/dev/null 2>&1; then
      wget -q --timeout=30 -O "$tarball" "$MALDET_TARBALL_URL" || { rm -rf "$tmp"; deny "could not download LMD from rfxn.com (offline? use the panel button later)"; }
    else
      curl -fsSL --connect-timeout 15 --max-time 120 "$MALDET_TARBALL_URL" -o "$tarball" || { rm -rf "$tmp"; deny "could not download LMD from rfxn.com (offline? use the panel button later)"; }
    fi
    # Asked of gzip, not of `file`: Debian's minimal install ships no `file`,
    # and an absent command reads exactly like a corrupt download. gzip is
    # already a hard requirement here - `tar -xzf` on the next line needs it -
    # and `gzip -t` checks the whole archive's CRC, not just two magic bytes.
    gzip -t "$tarball" 2>/dev/null || { rm -rf "$tmp"; deny "the LMD download is not a valid gzip archive (rfxn.com returned $(wc -c <"$tarball") bytes)"; }
    tar -xzf "$tarball" -C "$tmp" || { rm -rf "$tmp"; deny "could not unpack the LMD archive"; }
    local srcdir
    srcdir="$(find "$tmp" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
    [[ -n "$srcdir" && -x "$srcdir/install.sh" ]] || { rm -rf "$tmp"; deny "LMD archive layout not recognised"; }
    ( cd "$srcdir" && ./install.sh ) || { rm -rf "$tmp"; deny "the LMD installer failed"; }
    rm -rf "$tmp"
  fi
  [[ -x "$MALDET_BIN" ]] || deny "maldet is still not present after install"
  maldet_write_conf
  # The rfxn installer enables maldet.service (the inotify monitor). SNPanel
  # owns Level 2: keep it off until the admin turns it on.
  systemctl disable --now maldet >/dev/null 2>&1 || true
  "$MALDET_BIN" -u --force >/dev/null 2>&1 || true
  echo "LMD installed at ${MALDET_HOME}; ClamAV engine present (daemon not enabled)."
}

maldet_monitor_running() {
  local pid
  if [[ -f "${MALDET_HOME}/tmp/inotifywait.pid" ]]; then
    pid="$(cat "${MALDET_HOME}/tmp/inotifywait.pid" 2>/dev/null)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && return 0
  fi
  # Fallback: any inotifywait watching /home is maldet's monitor.
  pgrep -f "inotifywait.*(/home|maldet)" >/dev/null 2>&1
}

write_inotify_sysctl() {
  cat >/etc/sysctl.d/60-snpanel-inotify.conf <<'SYSCTL'
# Raised by SNPanel so the LMD real-time monitor can watch every site file.
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
SYSCTL
  sysctl --system >/dev/null 2>&1 || true
}

run_maldet_scan() {
  # run_maldet_scan <job-id> <all|recent> <days> <path>...
  local job="$1" mode="$2" days="$3"; shift 3
  [[ "$job" =~ ^[0-9a-f]{8,64}$ ]] || deny "invalid scan job id"
  [[ "$mode" == "all" || "$mode" == "recent" ]] || deny "scan mode must be all|recent"
  [[ "$days" =~ ^[0-9]{1,4}$ ]] || deny "scan days must be an integer"
  [[ -x "$MALDET_BIN" ]] || deny "maldet is not installed"
  install -d -o snpanel -g snpanel -m 0750 "$MALWARE_JOBS_DIR"
  local out="${MALWARE_JOBS_DIR}/${job}.maldet.out"
  local rep="${MALWARE_JOBS_DIR}/${job}.maldet.report"
  rm -f "$out" "$rep"

  local -a targets=()
  local p resolved
  for p in "$@"; do
    resolved="$(readlink -m -- "$p")"
    case "$resolved" in
      /) targets+=("/") ;;
      /home|/home/*) [[ -d "$resolved" ]] && targets+=("$resolved") ;;
      *) deny "scan path must be / or under /home: $resolved" ;;
    esac
  done
  [[ ${#targets[@]} -gt 0 ]] || deny "no valid scan path"

  local -a co=()
  # A whole-machine scan skips the kernel/pkg-cache noise; a /home scan does not
  # need it. maldet takes one -co per override.
  if [[ " ${targets[*]} " == *" / "* ]]; then
    local ignore
    ignore="$(printf '%s\n' "${MALWARE_SCAN_PRUNE[@]}" | paste -sd, -)"
    co=(-co "scan_ignore=${ignore}")
  fi

  # Foreground on purpose: -b daemonises and the helper would return before the
  # report exists. The panel already runs this call in a background job.
  local rc=0
  if [[ "$mode" == "recent" ]]; then
    nice -n 19 ionice -c3 "$MALDET_BIN" "${co[@]}" -r "${targets[0]}" "$days" >"$out" 2>&1 || rc=$?
  else
    nice -n 19 ionice -c3 "$MALDET_BIN" "${co[@]}" -a "${targets[@]}" >"$out" 2>&1 || rc=$?
  fi

  local scanid
  scanid="$(grep -oE '[0-9]{6}-[0-9]{4}\.[0-9]+' "$out" | head -n1)"
  if [[ -z "$scanid" && -f "${MALDET_HOME}/sess/session.last" ]]; then
    scanid="$(cat "${MALDET_HOME}/sess/session.last" 2>/dev/null)"
  fi
  # The report body is the session file maldet wrote, not `maldet -e` output.
  : >"$rep"
  if [[ -n "$scanid" && -f "${MALDET_HOME}/sess/session.${scanid}" ]]; then
    cat "${MALDET_HOME}/sess/session.${scanid}" >>"$rep"
  fi
  chown snpanel:snpanel "$out" "$rep" 2>/dev/null || true
  chmod 0640 "$out" "$rep" 2>/dev/null || true
  printf 'scanid=%s\n' "${scanid:-none}"
  printf 'exit=%s\n' "$rc"
}

# Does Ondrej's PPA publish packages for this Ubuntu release?
#
# Asked over the network, before adding anything. `add-apt-repository` happily
# writes a source for a suite the PPA does not have, and the machine is then
# left with an apt configuration that fails on every update - the installer's
# and the updater's included. Ubuntu 26.04 (resolute) is such a release: the
# newest suite the PPA publishes is noble.
ondrej_ppa_publishes_this_release() {
  local codename
  codename="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")"
  [[ -n "$codename" ]] || return 1
  curl -fsI --max-time 20 \
    "https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/${codename}/Release" \
    >/dev/null 2>&1
}

# Is this package installable here?
#
# Not `apt-cache show`: that succeeds for a name the archive merely references.
# On Ubuntu 26.04 it says yes to php7.4-fpm, which has no installable version -
# so a refusal built on it told the user 7.4 was available on a release that
# has no such package.
apt_installable() {
  local candidate
  candidate="$(apt-cache policy "$1" 2>/dev/null | sed -n 's/^  Candidate: //p')"
  [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

# Which PHP versions this machine can install right now, from the repositories
# it already has. Used to make a refusal useful rather than just a refusal.
php_versions_installable() {
  local v out=""
  for v in 5.6 7.4 8.0 8.1 8.2 8.3 8.4 8.5; do
    apt_installable "php${v}-fpm" && out+="${v} "
  done
  printf '%s' "${out%% }"
}

install_php_version() {
  local version="$1"
  # On EL the installer sets up 8.3 and 8.4 with Remi's package names and with
  # the compatibility shim that presents Debian's /etc/php/<version>/fpm layout
  # to the panel. Adding a version here would need both, and doing only the
  # first is worse than refusing: the packages would install, the panel would
  # list the version, and every tuning action against it would fail on a path
  # that does not exist.
  if [[ "$OS_FAMILY" == "rhel" ]]; then
    deny "installing additional PHP versions from the panel is not supported on ${OS_FAMILY} yet; PHP 8.3 and 8.4 are set up by the installer"
  fi
  export DEBIAN_FRONTEND=noninteractive
  require_php_version "$version"
  if [[ -f /etc/php/"$version"/fpm/php-fpm.conf ]]; then
    echo "PHP $version is already installed; ensuring SNPanel extension set..."
  fi
  if ! apt_installable "php${version}-fpm"; then
    # `.sources` as well as `.list`: add-apt-repository writes deb822 on
    # current Ubuntu, so a check that reads only *.list never sees its own work
    # and adds the repository again on every attempt.
    if ! grep -rqs "ondrej/php" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
      if ! ondrej_ppa_publishes_this_release; then
        deny "PHP ${version} is not available on this system. Ondrej's PPA does not publish packages for this Ubuntu release, so only the versions the distribution carries can be installed: $(php_versions_installable). Nothing was changed."
      fi
      echo "Adding ondrej/php PPA for PHP $version..."
      pkg_update_index
      apt-get install -y software-properties-common || true
      add-apt-repository -y ppa:ondrej/php 2>/dev/null || true
    fi
    pkg_update_index
    if ! apt_installable "php${version}-fpm"; then
      deny "PHP ${version} is still not available after refreshing the package lists. Installable versions here: $(php_versions_installable)"
    fi
  fi
  echo "Installing PHP $version..."
  local packages=(
    "php${version}-fpm"
    "php${version}-cli"
    "php${version}-mysql"
    "php${version}-sqlite3"
    "php${version}-curl"
    "php${version}-gd"
    "php${version}-mbstring"
    "php${version}-xml"
    "php${version}-zip"
    "php${version}-opcache"
    "php${version}-intl"
    "php${version}-bcmath"
    "php${version}-redis"
    "php${version}-imagick"
  )
  local available_packages=() missing_packages=() package
  for package in "${packages[@]}"; do
    # apt_installable, not `apt-cache show`: a name the archive merely
    # references passes the latter, and putting it into the single apt-get
    # install below fails the whole transaction rather than skipping the one
    # optional extension this loop exists to skip.
    if apt_installable "$package"; then
      available_packages+=("$package")
    else
      missing_packages+=("$package")
    fi
  done
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    echo "Skipping PHP packages not available in repo: ${missing_packages[*]}"
  fi
  [[ ${#available_packages[@]} -gt 0 ]] || deny "No package found for PHP ${version}"
  pkg_install "${available_packages[@]}" || { echo "Failed to install PHP $version"; return 1; }
  install_ioncube_loader "$version"
  # Enable and start PHP-FPM
  systemctl enable "php${version}-fpm" 2>/dev/null || true
  systemctl start "php${version}-fpm" 2>/dev/null || true
  echo "PHP $version installed successfully"
}

install_ioncube_loader() {
  local version="$1" arch url tmp archive loader target_dir target loader_ini_dir
  require_php_version "$version"
  arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
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
  tmp="$(mktemp -d)" || deny "cannot create ionCube temporary directory"
  archive="${tmp}/ioncube_loaders.tar.gz"
  if ! curl -fsSL --connect-timeout 10 --max-time 300 "$url" -o "$archive"; then
    rm -rf -- "$tmp"
    deny "failed to download ionCube Loader"
  fi
  if ! tar -xzf "$archive" -C "$tmp"; then
    rm -rf -- "$tmp"
    deny "failed to unpack ionCube Loader"
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

  for loader_ini_dir in /etc/php/"$version"/cli/conf.d /etc/php/"$version"/fpm/conf.d; do
    [[ -d "$loader_ini_dir" ]] || continue
    printf 'zend_extension=%s\n' "$target" >"${loader_ini_dir}/00-ioncube.ini"
    chown root:root "${loader_ini_dir}/00-ioncube.ini"
    chmod 0644 "${loader_ini_dir}/00-ioncube.ini"
  done

  if command -v "php${version}" >/dev/null 2>&1; then
    if ! grep -qi 'ionCube' <<<"$("php${version}" -v 2>&1 || true)"; then
      rm -f /etc/php/"$version"/cli/conf.d/00-ioncube.ini /etc/php/"$version"/fpm/conf.d/00-ioncube.ini
      deny "ionCube Loader failed to load for PHP ${version}"
    fi
  fi
  echo "ionCube Loader enabled for PHP ${version}"
}

validate_php_config_file() {
  local file="$1" line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    case "$line" in *$'\r'*) deny "PHP config contains a carriage return" ;; esac
    [[ "$line" == *"="* ]] || deny "invalid PHP config line: $line"
    key="$(printf '%s' "${line%%=*}" | xargs)"
    value="$(printf '%s' "${line#*=}" | xargs)"
    case "$key" in
      display_errors)
        [[ "$value" == "On" || "$value" == "Off" ]] || deny "invalid display_errors value"
        ;;
      memory_limit|upload_max_filesize|post_max_size)
        [[ "$value" =~ ^[0-9]{1,6}[KMG]?$ ]] || deny "invalid PHP size value for $key"
        ;;
      max_execution_time|max_input_time)
        [[ "$value" =~ ^[0-9]{1,4}$ ]] || deny "invalid integer value for $key"
        (( 10#$value >= 1 && 10#$value <= 3600 )) || deny "$key out of range"
        ;;
      max_input_vars)
        [[ "$value" =~ ^[0-9]{1,7}$ ]] || deny "invalid integer value for $key"
        (( 10#$value >= 100 && 10#$value <= 1000000 )) || deny "max_input_vars out of range"
        ;;
      *)
        deny "unsupported PHP config directive: $key"
        ;;
    esac
  done <"$file"
}

validate_php_tune_file() {
  # A separate allowlist from the panel's PHP config page: these are the keys
  # the tuner is allowed to size from the machine, and nothing else reaches a
  # file that root writes into PHP's configuration directory.
  local file="$1" line key value
  while IFS= read -r line; do
    line="${line%%;*}"
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -n "$line" ]] || continue
    [[ "$line" == *=* ]] || deny "invalid PHP tuning line: $line"
    key="$(printf '%s' "${line%%=*}" | sed 's/[[:space:]]*$//')"
    value="$(printf '%s' "${line#*=}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    case "$key" in
      memory_limit|realpath_cache_size)
        [[ "$value" =~ ^[0-9]{1,6}[KkMmGg]?$ ]] || deny "invalid size for $key"
        ;;
      realpath_cache_ttl|opcache.memory_consumption|opcache.interned_strings_buffer|opcache.max_accelerated_files|opcache.revalidate_freq)
        [[ "$value" =~ ^[0-9]{1,7}$ ]] || deny "invalid integer for $key"
        ;;
      opcache.enable|opcache.enable_cli|opcache.validate_timestamps|opcache.save_comments)
        [[ "$value" =~ ^[01]$ ]] || deny "$key must be 0 or 1"
        ;;
      opcache.jit)
        # Named modes, or the four-digit form PHP also accepts.
        [[ "$value" =~ ^(disable|off|on|tracing|function|[0-9]{4})$ ]] || deny "invalid opcache.jit value"
        ;;
      opcache.jit_buffer_size)
        [[ "$value" =~ ^[0-9]{1,6}[KkMmGg]?$ ]] || deny "invalid size for opcache.jit_buffer_size"
        ;;
      expose_php|zlib.output_compression)
        [[ "$value" =~ ^(On|Off|0|1)$ ]] || deny "$key must be On or Off"
        ;;
      *)
        deny "unsupported PHP tuning directive: $key"
        ;;
    esac
  done <"$file"
}

write_php_tune() {
  local version="$1" conf_dir target tmp size
  require_php_version "$version"
  conf_dir="/etc/php/${version}/fpm/conf.d"
  [[ -d "$conf_dir" ]] || deny "PHP FPM config directory not found: $conf_dir"
  target="${conf_dir}/95-snpanel-tune.ini"
  tmp="$(mktemp "${conf_dir}/.95-snpanel-tune.ini.XXXXXX")" || deny "cannot create temporary PHP tuning file"
  if ! cat >"$tmp"; then
    rm -f -- "$tmp"
    deny "failed to read PHP tuning file"
  fi
  size="$(wc -c <"$tmp" | tr -d '[:space:]')"
  if (( size <= 0 || size > 8192 )); then
    rm -f -- "$tmp"
    deny "PHP tuning file size out of range"
  fi
  validate_php_tune_file "$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$target"
  # The CLI reads its own directory; opcache settings there are harmless and
  # realpath cache helps WP-CLI too.
  if [[ -d "/etc/php/${version}/cli/conf.d" ]]; then
    install -m 0644 -o root -g root "$target" "/etc/php/${version}/cli/conf.d/95-snpanel-tune.ini"
  fi
  systemctl reload "php${version}-fpm" 2>/dev/null || systemctl restart "php${version}-fpm"
  echo "PHP ${version} tuned: ${target}"
}

write_php_opcache_switch() {
  # Its own file, read after the tuning one and before the administrator's:
  # regenerating the tuning file must not turn opcache back on for somebody who
  # turned it off deliberately.
  local version="$1" enabled="$2" conf_dir target
  require_php_version "$version"
  [[ "$enabled" =~ ^[01]$ ]] || deny "opcache switch must be 0 or 1"
  conf_dir="/etc/php/${version}/fpm/conf.d"
  [[ -d "$conf_dir" ]] || deny "PHP FPM config directory not found: $conf_dir"
  target="${conf_dir}/96-snpanel-opcache.ini"
  cat >"$target" <<INI
; Generated by SNPanel. OPcache on/off for PHP ${version}.
; Read after 95-snpanel-tune.ini, so this wins over the tuner.
opcache.enable = ${enabled}
INI
  chown root:root "$target"
  chmod 0644 "$target"
  if [[ -d "/etc/php/${version}/cli/conf.d" ]]; then
    install -m 0644 -o root -g root "$target" "/etc/php/${version}/cli/conf.d/96-snpanel-opcache.ini"
  fi
  systemctl reload "php${version}-fpm" 2>/dev/null || systemctl restart "php${version}-fpm"
  echo "OPcache PHP ${version}: $([[ "$enabled" == "1" ]] && echo enabled || echo disabled)"
}

write_php_config() {
  local version="$1" conf_dir target tmp size
  require_php_version "$version"
  conf_dir="/etc/php/${version}/fpm/conf.d"
  target="${conf_dir}/99-snpanel.ini"
  [[ -d "$conf_dir" ]] || deny "PHP FPM config directory not found: $conf_dir"
  tmp="$(mktemp "${conf_dir}/.99-snpanel.ini.XXXXXX")" || deny "cannot create temporary PHP config"
  if ! cat >"$tmp"; then
    rm -f -- "$tmp"
    deny "failed to read PHP config"
  fi
  size="$(wc -c <"$tmp" | tr -d '[:space:]')"
  if (( size <= 0 || size > 8192 )); then
    rm -f -- "$tmp"
    deny "PHP config size out of range"
  fi
  validate_php_config_file "$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$target"
  systemctl restart "php${version}-fpm"
  echo "PHP ${version} config updated: ${target}"
}

waf_status() {
  echo "ModSecurity module:"
  if waf_engine_present; then
    echo "  installed"
  else
    echo "  not installed"
  fi
  echo "Rules file:"
  [[ -f /etc/nginx/modsec/snpanel-main.conf ]] && echo "  /etc/nginx/modsec/snpanel-main.conf" || echo "  missing"
  echo "Default rules:"
  [[ -f /etc/nginx/modsec/snpanel-default.conf ]] && echo "  /etc/nginx/modsec/snpanel-default.conf" || echo "  missing"
  echo "Custom rules:"
  [[ -f /etc/nginx/modsec/snpanel-custom.conf ]] && echo "  /etc/nginx/modsec/snpanel-custom.conf" || echo "  missing"
  echo "Managed profile:"
  echo "  SNPanel built-in lightweight WordPress/Laravel/PHP rules"
  echo "Timers:"
  systemctl list-timers apt-daily-upgrade.timer --no-pager 2>/dev/null || true
}

audit_log() {
  local quoted="" arg
  for arg in "$@"; do
    printf -v quoted '%s %q' "$quoted" "$arg"
  done
  if command -v logger >/dev/null 2>&1; then
    logger -t snpanel-helper -- "cmd=${cmd:-unknown}${quoted}"
  fi
}

##############################################################################
# Firewall engine: iptables + ipset
#
# Single source of truth is $FIREWALL_RULES_FILE (TSV) plus the parsed URL
# blocklist in $FIREWALL_BLOCKLIST_WORK. Every apply rebuilds the SNPANEL-INPUT
# chain and reloads the ipsets from those files, so the runtime state can
# always be recreated from disk (including after a reboot).
#
# Chain layout (jumped to from INPUT position 1):
#   lo / ESTABLISHED,RELATED        -> RETURN   (fall through to other tools)
#   allow sets (ip, ip+port)        -> RETURN
#   deny sets (ip, ip+port)         -> DROP
#   URL blocklist set               -> DROP
#   protected + user open ports     -> RETURN
#   ICMP / ICMPv6                   -> RETURN
#   [when enabled] everything else  -> DROP
#
# RETURN (not ACCEPT) keeps the chain cooperative: fail2ban and any other
# INPUT rules still get to inspect packets SNPanel allows.
##############################################################################

FW_SETS_V4=(snpanel-allow4 snpanel-allowp4 snpanel-deny4 snpanel-denyp4 snpanel-block4)
FW_SETS_V6=(snpanel-allow6 snpanel-allowp6 snpanel-deny6 snpanel-denyp6 snpanel-block6)

firewall_require_tools() {
  command -v iptables >/dev/null 2>&1 || deny "iptables is not installed"
  command -v ipset >/dev/null 2>&1 || deny "ipset is not installed"
}

firewall_has_ipv6() {
  command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT >/dev/null 2>&1
}

ensure_firewall_dir() {
  ensure_snpanel_data_dir
  install -d -o root -g root -m 0750 "$FIREWALL_DIR"
  [[ -f "$FIREWALL_RULES_FILE" ]] || { : >"$FIREWALL_RULES_FILE"; chmod 0640 "$FIREWALL_RULES_FILE"; }
  [[ -f "$FIREWALL_STATE_FILE" ]] || printf 'enabled\n' >"$FIREWALL_STATE_FILE"
}

firewall_state() {
  ensure_firewall_dir
  local value
  value="$(head -n 1 "$FIREWALL_STATE_FILE" 2>/dev/null | tr -d '[:space:]')"
  [[ "$value" == "disabled" ]] && echo "disabled" || echo "enabled"
}

firewall_set_state() {
  ensure_firewall_dir
  [[ "$1" == "enabled" || "$1" == "disabled" ]] || deny "invalid firewall state: $1"
  printf '%s\n' "$1" >"$FIREWALL_STATE_FILE"
}

# Ports that must never be closed by the panel: SSH (from sshd), the panel
# port, and the standard web/mail ports.
firewall_protected_ports() {
  local panel_port ssh_ports
  panel_port="$(env_get PANEL_PORT)"; panel_port="${panel_port:-$DEFAULT_PANEL_PORT}"
  ssh_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' || true)"
  if [[ -z "$ssh_ports" ]]; then
    # `sshd -T` fails on a config it cannot validate. Falling back to the raw
    # config keeps a custom SSH port from being closed on us.
    ssh_ports="$(awk 'tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2 }' \
      /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)"
  fi
  {
    printf '%s\n' "${FIREWALL_PROTECTED_PORTS[@]}"
    printf '%s\n' $ssh_ports
    printf '%s\n' "$panel_port"
  } | grep -E '^[0-9]{1,5}$' | sort -un
}

# ---- ipset ----------------------------------------------------------------

firewall_set_spec() {
  # echo the create spec for a set name
  case "$1" in
    *allowp4|*denyp4) echo "hash:net,port family inet hashsize 1024 maxelem 262144" ;;
    *allowp6|*denyp6) echo "hash:net,port family inet6 hashsize 1024 maxelem 262144" ;;
    *4) echo "hash:net family inet hashsize 4096 maxelem 1048576" ;;
    *6) echo "hash:net family inet6 hashsize 4096 maxelem 1048576" ;;
    *) deny "unknown ipset: $1" ;;
  esac
}

firewall_ensure_sets() {
  local name
  for name in "${FW_SETS_V4[@]}"; do
    # shellcheck disable=SC2046
    ipset create "$name" $(firewall_set_spec "$name") -exist
  done
  if firewall_has_ipv6; then
    for name in "${FW_SETS_V6[@]}"; do
      # shellcheck disable=SC2046
      ipset create "$name" $(firewall_set_spec "$name") -exist
    done
  fi
}

# Load a set atomically: fill a temporary set, then swap it in. Keeps the
# running firewall consistent even while a 100k-entry blocklist is loading.
firewall_load_set() {
  local name="$1" spec tmp file entry
  spec="$(firewall_set_spec "$name")"
  tmp="${name}-tmp"
  file="$(mktemp)"
  {
    printf 'create %s %s\n' "$tmp" "$spec"
    printf 'flush %s\n' "$tmp"
    # A blocklist can run to hundreds of thousands of addresses, and bash reads
    # them one at a time; awk does the same work in a fraction of the time, and
    # this runs on every firewall change.
    awk -v set="$tmp" 'NF { print "add " set " " $0 " -exist" }'
  } >"$file"
  ipset destroy "$tmp" 2>/dev/null || true
  if ! ipset restore -! <"$file"; then
    rm -f "$file"
    ipset destroy "$tmp" 2>/dev/null || true
    deny "failed to load firewall set $name"
  fi
  rm -f "$file"
  # shellcheck disable=SC2046
  ipset create "$name" $spec -exist
  ipset swap "$tmp" "$name"
  ipset destroy "$tmp" 2>/dev/null || true
}

firewall_is_ipv6() {
  [[ "$1" == *:* ]]
}

# ---- rules file -----------------------------------------------------------
# TSV columns: id <TAB> action <TAB> ip <TAB> port <TAB> protocol
# ip is empty for port-only rules; port is empty for whole-host rules.

firewall_rules() {
  ensure_firewall_dir
  grep -E '^[0-9]+\b' "$FIREWALL_RULES_FILE" 2>/dev/null || true
}

firewall_next_id() {
  local max
  max="$(firewall_rules | cut -f1 | sort -n | tail -n 1)"
  echo $(( ${max:-0} + 1 ))
}

firewall_add_rule() {
  local action="$1" ip="$2" port="${3:-}" protocol="${4:-tcp}" id existing
  case "$action" in allow|deny) ;; *) deny "invalid firewall action: $action" ;; esac
  if [[ -n "$ip" ]]; then
    ip="$(require_ip_or_cidr_normalized "$ip")"
  fi
  if [[ -n "$port" ]]; then
    require_port "$port"
    require_proto "$protocol"
  else
    protocol=""
  fi
  [[ -n "$ip" || -n "$port" ]] || deny "a firewall rule needs an IP or a port"
  if [[ -z "$ip" && "$action" == "deny" ]]; then
    deny "closing a port for every source is not supported; the firewall denies unlisted ports already"
  fi
  if [[ -z "$ip" && -n "$port" ]]; then
    local protected
    protected="$(firewall_protected_ports | tr '\n' ' ')"
    case " $protected " in *" $port "*) echo "Port ${port} is already open as a protected panel port"; return 0 ;; esac
  fi
  existing="$(firewall_rules | awk -F'\t' -v a="$action" -v i="$ip" -v p="$port" -v pr="$protocol" '$2==a && $3==i && $4==p && $5==pr { print $1; exit }')"
  if [[ -n "$existing" ]]; then
    echo "Rule already exists (#${existing})"
    firewall_apply >/dev/null
    return 0
  fi
  id="$(firewall_next_id)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$action" "$ip" "$port" "$protocol" >>"$FIREWALL_RULES_FILE"
  firewall_apply >/dev/null
  echo "Rule #${id} added"
}

firewall_delete_rule() {
  local id="$1" tmp
  [[ "$id" =~ ^[0-9]+$ ]] || deny "invalid rule id: $id"
  [[ -n "$(firewall_rules | awk -F'\t' -v id="$id" '$1 == id')" ]] || deny "rule #${id} not found"
  tmp="$(mktemp)"
  firewall_rules | awk -F'\t' -v id="$id" '$1 != id' >"$tmp"
  install -m 0640 -o root -g root "$tmp" "$FIREWALL_RULES_FILE"
  rm -f "$tmp"
  firewall_apply >/dev/null
  echo "Rule #${id} deleted"
}

# Re-delimit a tab-separated stream so bash can read it.
#
# `IFS=$'\t' read` looks like it splits on tabs and does not: tab is IFS
# whitespace, so runs of tabs collapse into a single delimiter and an empty
# field in the middle of a row shifts everything after it one place left. The
# rules file has empty fields by design - a rule that opens a port to every
# source has no IP - so every consumer of it has to avoid that read.
#
# `|` is not IFS whitespace, and cannot appear in an action, an address, a
# port or a protocol; each is validated before it is written. Setting NF pads
# short rows and rebuilds the record with OFS, so the field count is exactly
# what the caller asked for.
firewall_read_tsv() {
  awk -F'\t' -v OFS='|' -v want="${1:-5}" '{
    for (i = NF + 1; i <= want; i++) { $i = "" }
    NF = want
    print
  }'
}

# ---- apply ----------------------------------------------------------------

firewall_sync_sets() {
  local rules
  rules="$(firewall_rules)"
  firewall_ensure_sets

  local want_v6=0
  firewall_has_ipv6 && want_v6=1

  # Manual allow/deny rules
  local action ip port protocol entry
  local -a allow4=() allow6=() allowp4=() allowp6=() deny4=() deny6=() denyp4=() denyp6=()
  # Port-only rules (no IP) are skipped here on purpose: they are not set
  # members, they become a plain accept rule in firewall_apply_family.
  while IFS='|' read -r _id action ip port protocol; do
    [[ -n "$ip" ]] || continue
    if [[ -n "$port" ]]; then
      entry="${ip},${protocol}:${port}"
      if firewall_is_ipv6 "$ip"; then
        [[ "$action" == "allow" ]] && allowp6+=("$entry") || denyp6+=("$entry")
      else
        [[ "$action" == "allow" ]] && allowp4+=("$entry") || denyp4+=("$entry")
      fi
    else
      if firewall_is_ipv6 "$ip"; then
        [[ "$action" == "allow" ]] && allow6+=("$ip") || deny6+=("$ip")
      else
        [[ "$action" == "allow" ]] && allow4+=("$ip") || deny4+=("$ip")
      fi
    fi
  done < <(printf '%s\n' "$rules" | firewall_read_tsv 5)

  printf '%s\n' "${allow4[@]:-}"  | firewall_load_set snpanel-allow4
  printf '%s\n' "${allowp4[@]:-}" | firewall_load_set snpanel-allowp4
  printf '%s\n' "${deny4[@]:-}"   | firewall_load_set snpanel-deny4
  printf '%s\n' "${denyp4[@]:-}"  | firewall_load_set snpanel-denyp4
  if (( want_v6 )); then
    printf '%s\n' "${allow6[@]:-}"  | firewall_load_set snpanel-allow6
    printf '%s\n' "${allowp6[@]:-}" | firewall_load_set snpanel-allowp6
    printf '%s\n' "${deny6[@]:-}"   | firewall_load_set snpanel-deny6
    printf '%s\n' "${denyp6[@]:-}"  | firewall_load_set snpanel-denyp6
  fi

  # URL blocklists
  local block4 block6
  block4="$(mktemp)"; block6="$(mktemp)"
  if [[ -s "$FIREWALL_BLOCKLIST_WORK" ]]; then
    grep -v ':' "$FIREWALL_BLOCKLIST_WORK" | sed '/^[[:space:]]*$/d' >"$block4" || true
    grep ':'    "$FIREWALL_BLOCKLIST_WORK" | sed '/^[[:space:]]*$/d' >"$block6" || true
  fi
  firewall_load_set snpanel-block4 <"$block4"
  (( want_v6 )) && firewall_load_set snpanel-block6 <"$block6"
  rm -f "$block4" "$block6"
}

firewall_apply_family() {
  local ipt="$1" fam="$2" state="$3"
  local sa sap sd sdp sb icmp
  if [[ "$fam" == "6" ]]; then
    sa=snpanel-allow6; sap=snpanel-allowp6; sd=snpanel-deny6; sdp=snpanel-denyp6; sb=snpanel-block6
    icmp="ipv6-icmp"
  else
    sa=snpanel-allow4; sap=snpanel-allowp4; sd=snpanel-deny4; sdp=snpanel-denyp4; sb=snpanel-block4
    icmp="icmp"
  fi

  "$ipt" -N "$FIREWALL_CHAIN" 2>/dev/null || true
  "$ipt" -F "$FIREWALL_CHAIN"

  "$ipt" -A "$FIREWALL_CHAIN" -i lo -j RETURN
  "$ipt" -A "$FIREWALL_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "$ipt" -A "$FIREWALL_CHAIN" -m conntrack --ctstate INVALID -j DROP

  "$ipt" -A "$FIREWALL_CHAIN" -m set --match-set "$sa" src -j RETURN
  "$ipt" -A "$FIREWALL_CHAIN" -p tcp -m set --match-set "$sap" src,dst -j RETURN
  "$ipt" -A "$FIREWALL_CHAIN" -p udp -m set --match-set "$sap" src,dst -j RETURN

  "$ipt" -A "$FIREWALL_CHAIN" -m set --match-set "$sd" src -j DROP
  "$ipt" -A "$FIREWALL_CHAIN" -p tcp -m set --match-set "$sdp" src,dst -j DROP
  "$ipt" -A "$FIREWALL_CHAIN" -p udp -m set --match-set "$sdp" src,dst -j DROP
  "$ipt" -A "$FIREWALL_CHAIN" -m set --match-set "$sb" src -j DROP

  # ICMPv6 carries neighbour discovery; dropping it breaks IPv6 entirely.
  "$ipt" -A "$FIREWALL_CHAIN" -p "$icmp" -j RETURN

  local port
  while read -r port; do
    [[ -n "$port" ]] || continue
    "$ipt" -A "$FIREWALL_CHAIN" -p tcp --dport "$port" -j RETURN
  done < <(firewall_protected_ports)

  local _id action ip proto
  # This is the branch the shifted columns silently disabled: with ip holding
  # the port number, `-z "$ip"` was never true and the port stayed closed.
  while IFS='|' read -r _id action ip port proto; do
    [[ "$action" == "allow" && -z "$ip" && -n "$port" ]] || continue
    "$ipt" -A "$FIREWALL_CHAIN" -p "${proto:-tcp}" --dport "$port" -j RETURN
  done < <(firewall_rules | firewall_read_tsv 5)

  if [[ "$state" == "enabled" ]]; then
    "$ipt" -A "$FIREWALL_CHAIN" -j DROP
    "$ipt" -C INPUT -j "$FIREWALL_CHAIN" 2>/dev/null || "$ipt" -I INPUT 1 -j "$FIREWALL_CHAIN"
  else
    # Keep the chain (and its counters) around but stop consulting it.
    while "$ipt" -C INPUT -j "$FIREWALL_CHAIN" 2>/dev/null; do
      "$ipt" -D INPUT -j "$FIREWALL_CHAIN" || break
    done
  fi
}

firewall_apply() {
  local state
  firewall_require_tools
  ensure_firewall_dir
  state="$(firewall_state)"
  firewall_sync_sets
  firewall_apply_family iptables 4 "$state"
  if firewall_has_ipv6; then
    firewall_apply_family ip6tables 6 "$state"
  fi
  firewall_write_boot_unit
  # Never let a Docker guard failure abort the main firewall apply.
  install_docker_firewall_guard || echo "WARNING: could not apply the Docker inbound guard" >&2
  echo "Firewall applied (${state})"
}

firewall_flush() {
  local ipt name
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    while "$ipt" -C INPUT -j "$FIREWALL_CHAIN" 2>/dev/null; do
      "$ipt" -D INPUT -j "$FIREWALL_CHAIN" || break
    done
    "$ipt" -F "$FIREWALL_CHAIN" 2>/dev/null || true
    "$ipt" -X "$FIREWALL_CHAIN" 2>/dev/null || true
  done
  if command -v ipset >/dev/null 2>&1; then
    for name in "${FW_SETS_V4[@]}" "${FW_SETS_V6[@]}"; do
      ipset destroy "$name" 2>/dev/null || true
    done
  fi
  echo "Firewall rules removed from the running kernel"
}

firewall_write_boot_unit() {
  local unit=/etc/systemd/system/snpanel-firewall.service tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'UNIT'
[Unit]
Description=SNPanel firewall (iptables + ipset)
After=network-pre.target
Wants=network-pre.target
Before=network.target nginx.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper firewall-apply
ExecStop=/usr/local/sbin/snpanel-helper firewall-flush

[Install]
WantedBy=multi-user.target
UNIT
  if ! cmp -s "$tmp" "$unit" 2>/dev/null; then
    install -m 0644 -o root -g root "$tmp" "$unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$tmp"
  systemctl is-enabled snpanel-firewall.service >/dev/null 2>&1 \
    || systemctl enable snpanel-firewall.service >/dev/null 2>&1 || true
}

# ---- status ---------------------------------------------------------------

firewall_set_count() {
  ipset list "$1" -t 2>/dev/null | awk -F': ' '/Number of entries/ { print $2; exit }'
}

firewall_status() {
  ensure_firewall_dir
  local state active="no" protected
  state="$(firewall_state)"
  if command -v iptables >/dev/null 2>&1 && iptables -C INPUT -j "$FIREWALL_CHAIN" 2>/dev/null; then
    active="yes"
  fi
  protected="$(firewall_protected_ports | tr '\n' ',' | sed 's/,$//')"

  echo "Status: ${state}"
  echo "Engine: iptables + ipset"
  echo "Chain active: ${active}"
  echo "IPv6: $(firewall_has_ipv6 && echo yes || echo no)"
  echo "Default incoming: deny (unlisted ports)"
  echo "Protected ports (tcp): ${protected}"
  echo ""
  echo "Rules:"
  if [[ -n "$(firewall_rules)" ]]; then
    firewall_rules | awk -F'\t' '{
      target = ($4 == "") ? "any port" : $4 "/" $5
      src = ($3 == "") ? "any" : $3
      printf "  [%s] %-5s %-22s from %s\n", $1, toupper($2), target, src
    }'
  else
    echo "  (none)"
  fi
  echo ""
  echo "Sets:"
  local name count
  for name in "${FW_SETS_V4[@]}"; do
    count="$(firewall_set_count "$name")"
    [[ -n "$count" ]] && printf '  %-18s %s entries\n' "$name" "$count"
  done
  if firewall_has_ipv6; then
    for name in "${FW_SETS_V6[@]}"; do
      count="$(firewall_set_count "$name")"
      [[ -n "$count" ]] && printf '  %-18s %s entries\n' "$name" "$count"
    done
  fi
}

firewall_list_json() {
  ensure_firewall_dir
  local protected state active="false"
  state="$(firewall_state)"
  protected="$(firewall_protected_ports | tr '\n' ' ')"
  if command -v iptables >/dev/null 2>&1 && iptables -C INPUT -j "$FIREWALL_CHAIN" 2>/dev/null; then
    active="true"
  fi
  firewall_rules | python3 -c '
import json, sys

rules = []
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5 or not parts[0].isdigit():
        continue
    rid, action, ip, port, proto = parts[:5]
    rules.append({
        "id": int(rid),
        "number": int(rid),
        "action": action.upper(),
        "to": f"{port}/{proto}" if port else "any",
        "from": ip or "any",
        "port": port or None,
        "protocol": proto or None,
        "ip": ip or None,
        "zone": "UserZone",
        "protected": False,
    })

protected = [p for p in sys.argv[1].split() if p.isdigit()]
for port in protected:
    rules.append({
        "id": 0,
        "number": 0,
        "action": "ALLOW",
        "to": f"{port}/tcp",
        "from": "any",
        "port": port,
        "protocol": "tcp",
        "ip": None,
        "zone": "PanelZone",
        "protected": True,
    })

print(json.dumps({
    "state": sys.argv[2],
    "active": sys.argv[3] == "true",
    "engine": "iptables+ipset",
    "rules": rules,
}))
' "$protected" "$state" "$active"
}

# ---- legacy cleanup -------------------------------------------------------

# Copy any surviving UFW user rules into the new rules file so an upgrade does
# not silently close ports the admin opened by hand.
firewall_import_ufw_rules() {
  command -v ufw >/dev/null 2>&1 || return 0
  local protected imported=0
  protected="$(firewall_protected_ports | tr '\n' ' ')"
  # A UFW rule for "Anywhere" has an empty source, so this reader has the same
  # requirement: an empty middle field must not shift the ones after it.
  while IFS='|' read -r action ip port proto; do
    [[ -n "$action" ]] || continue
    if [[ -z "$ip" && -n "$port" ]]; then
      case " $protected " in *" $port "*) continue ;; esac
    fi
    # Subshell: firewall_add_rule calls deny() on bad input, which exits.
    if ( firewall_add_rule "$action" "$ip" "$port" "$proto" ) >/dev/null 2>&1; then
      imported=$((imported + 1))
    fi
  done < <(ufw status numbered 2>/dev/null | python3 -c '
import re, sys

# "ufw status numbered" lines look like:
#   [ 1] 22/tcp        ALLOW IN    Anywhere        # snpanel:PanelZone
#   [ 3] 3306/tcp      ALLOW IN    10.0.0.5
# Application profiles ("Nginx Full"), v6 duplicates and OUT rules are skipped:
# the ports they cover are protected ports in the new chain.
LINE = re.compile(
    r"^(?:\[\s*\d+\]\s*)?(.+?)\s{2,}(ALLOW|DENY)(?:\s+(IN|OUT))?\s{2,}(.+?)\s*$",
    re.I,
)

for raw in sys.stdin:
    line = raw.rstrip()
    m = LINE.match(line)
    if not m:
        continue
    target, action, direction, source = m.group(1).strip(), m.group(2).lower(), (m.group(3) or "IN").upper(), m.group(4).strip()
    if direction != "IN":
        continue
    source = re.sub(r"\s*#.*$", "", source).strip()
    if "(v6)" in target or "(v6)" in source:
        continue
    if source.lower().startswith("anywhere"):
        source = ""
    port, proto = "", "tcp"
    pm = re.match(r"^(\d{1,5})(?:/(tcp|udp))?$", target)
    if pm:
        port, proto = pm.group(1), pm.group(2) or "tcp"
    elif target.lower() != "anywhere":
        # Application profile or port range: not portable to a single rule.
        continue
    if not port and not source:
        continue
    print("\t".join([action, source, port, proto]))
' | firewall_read_tsv 4)
  [[ "$imported" -gt 0 ]] && echo "Imported ${imported} rule(s) from UFW" || true
  return 0
}

firewall_purge_ufw() {
  command -v ufw >/dev/null 2>&1 || return 0
  echo "Removing UFW ..."
  ufw --force disable >/dev/null 2>&1 || true
  ufw --force reset >/dev/null 2>&1 || true
  systemctl disable --now ufw >/dev/null 2>&1 || true
  systemctl mask ufw >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y ufw >/dev/null 2>&1 || true
  rm -rf /etc/ufw /lib/ufw 2>/dev/null || true
  rm -f /etc/systemd/system/snpanel-firewall-blocklist.service \
        /etc/systemd/system/snpanel-firewall-blocklist.timer 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

# Strip the Nginx geo-map blocklist from every managed vhost. The
# ip-blocklist-server.conf stub is kept (emptied) so any hand-written vhost
# that still includes it does not break Nginx.
firewall_purge_nginx_blocklist() {
  install -d -o root -g root -m 0755 "$NGINX_SNPANEL_DIR"
  cat >"$NGINX_BLOCKLIST_SERVER_CONF" <<'CONF'
# Managed by SNPanel. IP blocking moved to iptables + ipset; this file is kept
# empty so older vhosts that still include it keep loading.
CONF
  chown root:root "$NGINX_BLOCKLIST_SERVER_CONF"
  chmod 0644 "$NGINX_BLOCKLIST_SERVER_CONF"

  local changed=0 conf
  for conf in "$NGINX_CONF_DIR"/*.conf; do
    [[ -f "$conf" ]] || continue
    if grep -q 'ip-blocklist-server\.conf' "$conf"; then
      sed -i '/ip-blocklist-server\.conf/d' "$conf"
      changed=1
    fi
  done
  [[ -f "$NGINX_BLOCKLIST_CONF" || -f "$NGINX_BLOCKLIST_RULES" ]] && changed=1
  rm -f "$NGINX_BLOCKLIST_CONF" "$NGINX_BLOCKLIST_RULES" 2>/dev/null || true
  if (( changed )) && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
  return 0
}

firewall_migrate() {
  firewall_require_tools
  local first_run=0
  [[ -f "$FIREWALL_STATE_FILE" ]] || first_run=1
  ensure_firewall_dir
  firewall_import_ufw_rules || true

  if (( first_run )); then
    # Inherit whatever was enforcing traffic before the migration. Switching a
    # box that had no active firewall to default-deny would cut off services
    # SNPanel does not know about (mail, game servers, custom daemons). A box
    # with blocklist URLs configured was relying on IP blocking through Nginx,
    # so that one is switched on.
    local was_enforcing=0
    if command -v ufw >/dev/null 2>&1 && grep -qi 'active' <<<"$(ufw status 2>/dev/null | head -n 1 || true)"; then
      was_enforcing=1
    fi
    if [[ -s "$FIREWALL_BLOCKLIST_URLS" ]]; then
      was_enforcing=1
    fi
    if (( was_enforcing )); then
      firewall_set_state enabled
    else
      firewall_set_state disabled
      echo "No active firewall detected; rules are staged but not enforced."
      echo "Turn them on from the panel Firewall page or: snpanel-helper firewall-enable"
    fi
  fi

  firewall_purge_ufw
  firewall_purge_nginx_blocklist
  firewall_apply
}

require_url() {
  local value="$1"
  [[ "$value" =~ ^https?://[^[:space:]]+$ ]] || deny "invalid URL: $value"
}

firewall_blocklist_urls() {
  ensure_snpanel_data_dir
  touch "$FIREWALL_BLOCKLIST_URLS"
  sed '/^[[:space:]]*$/d' "$FIREWALL_BLOCKLIST_URLS" | sort -u
}

firewall_blocklist_write_timer() {
  local changed=0 tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'SERVICE'
[Unit]
Description=Refresh SNPanel IP blocklists (iptables + ipset)
After=network-online.target snpanel-firewall.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper firewall-blocklist-run
SERVICE
  if ! cmp -s "$tmp" /etc/systemd/system/snpanel-blocklist.service 2>/dev/null; then
    install -m 0644 -o root -g root "$tmp" /etc/systemd/system/snpanel-blocklist.service
    changed=1
  fi
  cat >"$tmp" <<'TIMER'
[Unit]
Description=Refresh SNPanel IP blocklists daily

[Timer]
OnCalendar=*-*-* 01:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
TIMER
  if ! cmp -s "$tmp" /etc/systemd/system/snpanel-blocklist.timer 2>/dev/null; then
    install -m 0644 -o root -g root "$tmp" /etc/systemd/system/snpanel-blocklist.timer
    changed=1
  fi
  rm -f "$tmp"
  # Retire the Nginx-era units.
  if [[ -f /etc/systemd/system/snpanel-firewall-blocklist.timer ]]; then
    systemctl disable --now snpanel-firewall-blocklist.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/snpanel-firewall-blocklist.service \
          /etc/systemd/system/snpanel-firewall-blocklist.timer
    changed=1
  fi
  (( changed )) && systemctl daemon-reload >/dev/null 2>&1
  systemctl enable --now snpanel-blocklist.timer >/dev/null 2>&1 || true
  return 0
}

write_http_flood_nginx_conf() {
  ensure_nginx_conf_dir_writable
  if [[ ! -f "$NGINX_HTTP_FLOOD_ZONES" ]]; then
    cat >"$NGINX_HTTP_FLOOD_ZONES" <<'CONF'
# Managed by SNPanel. Shared zones for per-website HTTP flood protection.
map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key {
    default $binary_remote_addr;
    1 "";
}
limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;
CONF
  fi
  cat >"$NGINX_HTTP_FLOOD_CONF" <<'CONF'
# Managed by SNPanel. Shared zones for per-website HTTP flood protection.
include /etc/nginx/snpanel/http-flood-zones.conf;
CONF
  rm -f "$NGINX_HTTP_FLOOD_LEGACY_CONF" "$NGINX_HTTP_FLOOD_SERVER_CONF" 2>/dev/null || true
  chown root:root "$NGINX_HTTP_FLOOD_CONF" "$NGINX_HTTP_FLOOD_ZONES"
  chmod 0644 "$NGINX_HTTP_FLOOD_CONF" "$NGINX_HTTP_FLOOD_ZONES"
}

save_http_flood_zones() {
  local tmp backup=""
  ensure_nginx_conf_dir_writable
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ $(wc -c <"$tmp") -gt 131072 ]]; then
    rm -f "$tmp"
    deny "HTTP flood zones are too large"
  fi
  if file_has_nul "$tmp"; then
    rm -f "$tmp"
    deny "HTTP flood zones cannot contain NUL bytes"
  fi
  if [[ -f "$NGINX_HTTP_FLOOD_ZONES" ]]; then
    backup="${NGINX_HTTP_FLOOD_ZONES}.bak.$(date +%s)"
    cp "$NGINX_HTTP_FLOOD_ZONES" "$backup"
  fi
  install -m 0644 -o root -g root "$tmp" "$NGINX_HTTP_FLOOD_ZONES"
  rm -f "$tmp"
  write_http_flood_nginx_conf
  if ! nginx -t; then
    if [[ -n "$backup" && -f "$backup" ]]; then
      mv -f "$backup" "$NGINX_HTTP_FLOOD_ZONES"
    else
      cat >"$NGINX_HTTP_FLOOD_ZONES" <<'CONF'
# Managed by SNPanel. Shared zones for per-website HTTP flood protection.
map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key {
    default $binary_remote_addr;
    1 "";
}
limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;
CONF
    fi
    deny "Nginx rejected HTTP flood zones"
  fi
  rm -f "$backup" 2>/dev/null || true
  systemctl reload nginx
  echo "HTTP flood zones saved"
}

firewall_blocklist_status() {
  ensure_snpanel_data_dir
  touch "$FIREWALL_BLOCKLIST_URLS"
  echo "URLs:"
  if [[ -s "$FIREWALL_BLOCKLIST_URLS" ]]; then
    firewall_blocklist_urls | sed 's/^/  /'
  else
    echo "  (none)"
  fi
  echo ""
  echo "Engine:"
  echo "  iptables + ipset"
  echo "Sets:"
  printf '  snpanel-block4      %s entries\n' "$(firewall_set_count snpanel-block4)"
  if firewall_has_ipv6; then
    printf '  snpanel-block6      %s entries\n' "$(firewall_set_count snpanel-block6)"
  fi
  echo ""
  echo "Networks:"
  if [[ -s "$FIREWALL_BLOCKLIST_WORK" ]]; then
    local total shown
    total="$(sed '/^[[:space:]]*$/d' "$FIREWALL_BLOCKLIST_WORK" | wc -l | tr -d '[:space:]')"
    shown=50
    echo "  ${total} network(s), showing first ${shown}:"
    sed '/^[[:space:]]*$/d' "$FIREWALL_BLOCKLIST_WORK" | head -n "$shown" | sed 's/^/  /'
    if (( total > shown )); then
      echo "  ... $((total - shown)) more"
    fi
  else
    echo "  (none)"
  fi
  echo ""
  echo "Timer:"
  systemctl is-enabled snpanel-blocklist.timer 2>/dev/null || true
  systemctl list-timers snpanel-blocklist.timer --no-pager 2>/dev/null || true
}

firewall_blocklist_run() {
  ensure_snpanel_data_dir
  ensure_firewall_dir
  touch "$FIREWALL_BLOCKLIST_URLS"
  local tmp fetched count url
  tmp="$(mktemp)"
  fetched="$(mktemp)"
  while IFS= read -r url; do
    [[ -n "$url" ]] || continue
    require_url "$url"
    curl -fsSL --connect-timeout 10 --max-time 60 "$url" >>"$fetched" || echo "WARNING: could not fetch $url" >&2
    printf '\n' >>"$fetched"
  done < <(firewall_blocklist_urls)
  python3 - "$fetched" "$tmp" <<'PY'
import ipaddress
import re
import sys

seen = set()
networks = []
for raw in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    line = re.split(r"[\s#;,]+", raw.strip(), 1)[0]
    if not line:
        continue
    try:
        value = str(ipaddress.ip_network(line, strict=False))
    except ValueError:
        continue
    if value not in seen:
        seen.add(value)
        networks.append(value)

with open(sys.argv[2], "w", encoding="utf-8") as handle:
    for value in networks:
        handle.write(value + "\n")
PY
  install -m 0640 -o root -g root "$tmp" "$FIREWALL_BLOCKLIST_WORK"
  count="$(sed '/^[[:space:]]*$/d' "$FIREWALL_BLOCKLIST_WORK" | wc -l | tr -d '[:space:]')"
  rm -f "$tmp" "$fetched"
  firewall_apply >/dev/null
  firewall_blocklist_write_timer
  echo "IP blocklist refreshed: ${count} network(s) loaded into ipset"
}

firewall_blocklist_add_url() {
  local url="$1"
  require_url "$url"
  ensure_snpanel_data_dir
  touch "$FIREWALL_BLOCKLIST_URLS"
  if ! grep -Fxq -- "$url" "$FIREWALL_BLOCKLIST_URLS"; then
    printf '%s\n' "$url" >>"$FIREWALL_BLOCKLIST_URLS"
  fi
  sort -u -o "$FIREWALL_BLOCKLIST_URLS" "$FIREWALL_BLOCKLIST_URLS"
  firewall_blocklist_write_timer
  echo "IP blocklist URL added"
}

firewall_blocklist_delete_url() {
  local url="$1"
  require_url "$url"
  ensure_snpanel_data_dir
  touch "$FIREWALL_BLOCKLIST_URLS"
  grep -Fxv -- "$url" "$FIREWALL_BLOCKLIST_URLS" >"${FIREWALL_BLOCKLIST_URLS}.tmp" || true
  mv -f "${FIREWALL_BLOCKLIST_URLS}.tmp" "$FIREWALL_BLOCKLIST_URLS"
  firewall_blocklist_write_timer
  echo "IP blocklist URL removed"
}

write_ssl_auto_renew_timer() {
  cat >/etc/systemd/system/snpanel-ssl-auto-renew.service <<SERVICE
[Unit]
Description=Renew SNPanel SSL certificates that expire within 10 days
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper certbot-renew-soon 10
SERVICE
  cat >/etc/systemd/system/snpanel-ssl-auto-renew.timer <<TIMER
[Unit]
Description=Check SNPanel SSL certificates daily

[Timer]
OnCalendar=*-*-* 01:30:00
Persistent=true

[Install]
WantedBy=timers.target
TIMER
  systemctl daemon-reload
  systemctl enable --now snpanel-ssl-auto-renew.timer >/dev/null 2>&1 || true
}

copy_panel_live_certificate() {
  local domain="$1"
  [[ -n "$domain" ]] || return 0
  [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]] || return 0
  install -d -o root -g snpanel -m 0750 /etc/snpanel
  install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${domain}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
  install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${domain}/privkey.pem" /etc/snpanel/panel-privkey.pem
  if [[ -f "$ENV_FILE" ]]; then
    env_set PANEL_SSL_CERT "/etc/snpanel/panel-fullchain.pem"
    env_set PANEL_SSL_KEY "/etc/snpanel/panel-privkey.pem"
  fi
}

install_manual_ssl() {
  local domain="$1" base tmpdir
  require_domain "$domain"
  base="/etc/nginx/snpanel/ssl/sites/${domain}"
  tmpdir="$(mktemp -d /tmp/snpanel-manual-ssl.XXXXXX)"
  trap 'rm -rf "$tmpdir"' RETURN
  local payload_file="$tmpdir/payload.json"
  cat >"$payload_file"
  python3 - "$tmpdir" "$payload_file" <<'PY'
import json
import pathlib
import sys

tmpdir = pathlib.Path(sys.argv[1])
payload_file = pathlib.Path(sys.argv[2])
data = json.loads(payload_file.read_text(encoding="utf-8"))
parts = {
    "cert.crt": data.get("certificate", ""),
    "privkey.key": data.get("private_key", ""),
}
ca_bundle = data.get("ca_bundle", "")
if ca_bundle:
    parts["ca.crt"] = ca_bundle
for name, content in parts.items():
    if not content or "\x00" in content:
        raise SystemExit(f"invalid {name}")
    (tmpdir / name).write_text(content, encoding="utf-8")
PY
  install -d -o root -g snpanel -m 0750 "$base"
  install -m 0640 -o root -g snpanel "$tmpdir/cert.crt" "$base/cert.crt"
  install -m 0640 -o root -g snpanel "$tmpdir/privkey.key" "$base/privkey.key"
  if [[ -f "$tmpdir/ca.crt" ]]; then
    install -m 0640 -o root -g snpanel "$tmpdir/ca.crt" "$base/ca.crt"
    cat "$tmpdir/cert.crt" "$tmpdir/ca.crt" >"$tmpdir/fullchain.crt"
    install -m 0640 -o root -g snpanel "$tmpdir/fullchain.crt" "$base/fullchain.crt"
  else
    rm -f "$base/ca.crt"
    install -m 0640 -o root -g snpanel "$tmpdir/cert.crt" "$base/fullchain.crt"
  fi
  echo "Manual SSL installed for ${domain}"
}

remove_manual_ssl() {
  local domain="$1" base
  require_domain "$domain"
  base="/etc/nginx/snpanel/ssl/sites/${domain}"
  rm -f "$base/cert.crt" "$base/privkey.key" "$base/ca.crt" "$base/fullchain.crt"
  rmdir "$base" 2>/dev/null || true
  echo "Manual SSL removed for ${domain}"
}

install_certbot_dns_cloudflare() {
  export DEBIAN_FRONTEND=noninteractive
  if dpkg -s python3-certbot-dns-cloudflare >/dev/null 2>&1; then
    echo "certbot dns-cloudflare plugin already installed"
    return 0
  fi
  pkg_update_index
  pkg_install python3-certbot-dns-cloudflare
  echo "certbot dns-cloudflare plugin installed"
}

cloudflare_ssl_issue() {
  # Zone comes from argv (validated); the literal "*." is built here, never
  # taken from the caller. The token arrives on stdin so it never lands in a
  # process list or the sudo log.
  local zone="$1" email="${2:-}" ini token args
  require_domain "$zone"
  [[ -n "$email" ]] && require_email "$email"
  command -v certbot >/dev/null 2>&1 || deny "certbot is not installed"
  dpkg -s python3-certbot-dns-cloudflare >/dev/null 2>&1 \
    || deny "certbot dns-cloudflare plugin is not installed (run certbot-dns-cloudflare-install)"
  token="$(cat)"
  [[ "$token" =~ ^[A-Za-z0-9_.~-]{20,200}$ ]] || deny "cloudflare API token is missing or malformed"
  install -d -o root -g root -m 0700 /etc/snpanel /etc/snpanel/cloudflare
  ini="/etc/snpanel/cloudflare/${zone}.ini"
  ( umask 077; printf 'dns_cloudflare_api_token = %s\n' "$token" >"$ini" )
  chown root:root "$ini"; chmod 0600 "$ini"
  args=(certonly --dns-cloudflare --dns-cloudflare-credentials "$ini"
    --dns-cloudflare-propagation-seconds 30 --cert-name "$zone"
    -d "$zone" -d "*.${zone}" --non-interactive --agree-tos --keep-until-expiring)
  if [[ -n "$email" ]]; then
    args+=(--email "$email")
  else
    args+=(--register-unsafely-without-email)
  fi
  certbot "${args[@]}"
  # The panel may be reachable on this zone now, and renewals must keep the
  # per-hostname copies fresh.
  install_sni_renewal_hook
  sync_panel_sni_certificates >/dev/null
  echo "Wildcard certificate ready: ${zone} and *.${zone}"
}

ssl_cert_info() {
  # Read-only: the panel runs as 'snpanel' and cannot open /etc/letsencrypt/live,
  # so it asks the helper for a borrowed certificate's expiry and names.
  local name="$1" cert not_after sans
  require_domain "$name"
  if [[ -f "/etc/letsencrypt/live/${name}/cert.pem" ]]; then
    cert="/etc/letsencrypt/live/${name}/cert.pem"
  elif [[ -f "/etc/nginx/snpanel/ssl/sites/${name}/cert.crt" ]]; then
    cert="/etc/nginx/snpanel/ssl/sites/${name}/cert.crt"
  else
    deny "no certificate on this server for ${name}"
  fi
  not_after="$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2- || true)"
  sans="$( { openssl x509 -ext subjectAltName -noout -in "$cert" 2>/dev/null || true; } \
    | grep -oE 'DNS:[^,]+' | sed 's/DNS://g;s/ //g' | paste -sd, - || true)"
  if [[ -z "$sans" ]]; then
    sans="$( { openssl x509 -subject -noout -in "$cert" 2>/dev/null || true; } \
      | grep -oE 'CN ?= ?[^,/]+' | sed -E 's/CN ?= ?//' || true)"
  fi
  printf 'not_after=%s\n' "$not_after"
  printf 'sans=%s\n' "$sans"
}

delete_ssl_cert() {
  # A website that is gone should take its certificate with it. Left behind,
  # the renewal config still wakes certbot.timer twice a day and starts failing
  # the moment the domain stops pointing here - which is how a deleted site
  # turns into a permanently failed unit nobody can explain.
  local name="$1" panel_domain removed=0
  require_domain "$name"
  # The panel serves :2222 on a certificate that may well belong to a hosted
  # domain (panel-ssl-use-domain). Deleting that one drops every admin onto a
  # browser warning at the next login, so refuse even when asked directly.
  panel_domain="$(env_get PANEL_DOMAIN)"
  if [[ -n "$panel_domain" && "$panel_domain" == "$name" ]]; then
    deny "refusing to delete ${name}: the panel is served on this certificate"
  fi
  if [[ -d "/etc/letsencrypt/live/${name}" || -f "/etc/letsencrypt/renewal/${name}.conf" ]]; then
    certbot delete --cert-name "$name" --non-interactive >/dev/null 2>&1 \
      || deny "certbot could not delete the certificate for ${name}"
    echo "Deleted Let's Encrypt certificate ${name}"
    removed=1
  fi
  if [[ -d "/etc/nginx/snpanel/ssl/sites/${name}" ]]; then
    remove_manual_ssl "$name" >/dev/null
    echo "Removed uploaded certificate for ${name}"
    removed=1
  fi
  [[ "$removed" -eq 1 ]] || echo "No certificate on this server for ${name}"
  # Stop answering for the domain on :2222 as well; the sync drops SNI copies
  # whose source certificate no longer exists.
  sync_panel_sni_certificates >/dev/null
}

renew_ssl_soon() {
  local days="${1:-10}" seconds cert cert_name checked=0 renewed=0 panel_domain
  [[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 && "$days" -le 30 ]] || deny "usage: certbot-renew-soon [1-30 days]"
  write_ssl_auto_renew_timer
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot is not installed"
    return 0
  fi
  seconds=$((days * 86400))
  shopt -s nullglob
  for cert in /etc/letsencrypt/live/*/cert.pem; do
    [[ -f "$cert" ]] || continue
    cert_name="$(basename "$(dirname "$cert")")"
    [[ "$cert_name" == "README" ]] && continue
    checked=$((checked + 1))
    if ! openssl x509 -checkend "$seconds" -noout -in "$cert" >/dev/null 2>&1; then
      echo "Renewing certificate: ${cert_name}"
      if certbot renew --cert-name "$cert_name" --quiet --force-renewal \
        --deploy-hook "systemctl reload nginx || true; systemctl restart snpanel-api || true"; then
        renewed=$((renewed + 1))
      else
        echo "WARNING: could not renew ${cert_name}" >&2
      fi
    fi
  done
  shopt -u nullglob
  panel_domain="$(env_get PANEL_DOMAIN)"
  copy_panel_live_certificate "$panel_domain"
  if [[ "$renewed" -gt 0 ]]; then
    systemctl reload nginx >/dev/null 2>&1 || true
    systemctl restart snpanel-api >/dev/null 2>&1 || true
  fi
  echo "SSL auto-renew checked ${checked} certificate(s); renewed ${renewed} certificate(s) within ${days} day(s)."
}

# ---- managed application runtimes ------------------------------------------
# A site app runs as a systemd unit whose name the panel never gets to choose:
# it is derived here from the site user and site root, so a caller cannot aim
# start/stop/logs at nginx, mariadb, or another tenant's unit.

ensure_proxy_upgrade_map() {
  # `map` only works at http level, so a proxied vhost needs this file to exist
  # before nginx will even load. The installer writes it too, but the panel must
  # not depend on the installer having run since the feature shipped: without it
  # the first proxy vhost fails `nginx -t` and gets rolled back.
  local target=/etc/nginx/conf.d/00-snpanel-upgrade-map.conf
  [[ -s "$target" ]] && return 0
  cat >"$target" <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
NGINX
  chown root:root "$target"
  chmod 0644 "$target"
}

require_app_name() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?$ ]] || deny "invalid app name: $1"
}

app_unit_name() {
  local user="$1" name="$2"
  printf 'snpanel-app-%s-%s' "$user" "$name"
}

app_env_file() {
  # Deliberately outside the customer's home. Inside it the file was reachable
  # through the file manager, went into every site backup, and the permission
  # hardening pass in update.sh handed ownership back to the site user on the
  # next update. Nothing but root needs to read it: systemd loads
  # EnvironmentFile before dropping privileges, and the docker CLI runs as root.
  local user="$1" name="$2"
  printf '%s/apps/%s-%s.env' "$SNPANEL_DATA_DIR" "$user" "$name"
}

app_compose_file() {
  local user="$1" name="$2"
  printf '%s/apps/%s-%s.compose.yml' "$SNPANEL_DATA_DIR" "$user" "$name"
}

write_app_compose_file() {
  # The panel generates this from the customer's imported file, so it should
  # never contain any of the keys below. Checking anyway means a bug in the
  # generator cannot quietly hand a container the whole host.
  local target="$1" line tmp
  install -d -o root -g root -m 0700 "${SNPANEL_DATA_DIR}/apps"
  tmp="${target}.snpanel-tmp"
  install -m 0600 -o root -g root /dev/null "$tmp"
  cat >"$tmp"
  if grep -Eq '^[[:space:]]*(privileged|network_mode|pid|ipc|userns_mode|devices|cgroup_parent|volumes_from|build|env_file):' "$tmp"; then
    rm -f "$tmp"
    deny "generated compose contains a forbidden key"
  fi
  if grep -Eq '^[[:space:]]*-[[:space:]]*"?/' "$tmp"; then
    rm -f "$tmp"
    deny "generated compose mounts a host path"
  fi
  # The long form of the same thing: the panel only ever writes tmpfs this way.
  if grep -Eq '^[[:space:]]*(type:[[:space:]]*"?bind|source:[[:space:]]*"?/)' "$tmp"; then
    rm -f "$tmp"
    deny "generated compose mounts a host path"
  fi
  grep -q '^services:' "$tmp" || { rm -f "$tmp"; deny "generated compose has no services"; }
  mv -f "$tmp" "$target"
  chown root:root "$target"
  chmod 0600 "$target"
}

ensure_compose_bind_dirs() {
  local compose_file="$1" user="$2" app_dir="$3" line source target
  # The file was generated by the panel, so the shape is known: every bind mount
  # is a list entry "- ./path:/inside". Sources were already checked for `..` and
  # for absolute paths before they got here; check again rather than trust that.
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ "$line" == "- ./"*":/"* ]] || continue
    source="${line#- ./}"
    source="${source%%:*}"
    [[ -n "$source" && "$source" != *".."* ]] || continue
    target="${app_dir}/${source}"
    if [[ ! -e "$target" ]]; then
      install -d -m 0750 "$target"
      harden_site_dir "$target" "$user"
    elif [[ -d "$target" && "$(stat -c %U "$target")" == "root" ]]; then
      # Docker got there first on an earlier deploy and made it root-owned, so
      # the container could not write into its own mount. Take it back.
      harden_site_dir "$target" "$user"
    fi
  done < "$compose_file"
}

write_compose_app_unit() {
  local unit_path="$1" app_label="$2" user="$3" app_dir="$4" compose_file="$5" project="$6"
  local identifier
  identifier="$(basename "$unit_path" .service)"
  # Runs as root because it drives the Docker socket. Every container inside the
  # generated file is capped, capability-stripped and published on loopback only.
  cat >"$unit_path" <<UNIT
[Unit]
Description=SNPanel compose application ${app_label} (${user})
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=exec
WorkingDirectory=${app_dir}
ExecStartPre=-/usr/bin/docker compose -f ${compose_file} --project-directory ${app_dir} -p ${project} down --remove-orphans
ExecStart=/usr/bin/docker compose -f ${compose_file} --project-directory ${app_dir} -p ${project} up --remove-orphans
ExecStop=/usr/bin/docker compose -f ${compose_file} --project-directory ${app_dir} -p ${project} down
Restart=always
RestartSec=5
TimeoutStartSec=600
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${identifier}

[Install]
WantedBy=multi-user.target
UNIT
}

app_container_name() {
  local user="$1" name="$2"
  printf 'snpanel-%s-%s' "$user" "$name"
}

app_directory() {
  # Apps live side by side under the owner's home, one directory each. The
  # customer's SFTP is chrooted to that home, so they can upload code without
  # the app being tied to any website.
  local user="$1" name="$2"
  printf '%s/%s/apps/%s' "$HOME_ROOT" "$user" "$name"
}

ipv6_available() {
  # A global address, not the loopback and not a link-local one: those cannot
  # carry traffic from outside, so listening on them would prove nothing.
  #
  # Read it all before testing it. `ip | grep -q` looks equivalent and is not:
  # iproute2 flushes one line per address, so with two addresses grep can exit
  # on the first while ip is still writing the second, and under pipefail the
  # SIGPIPE that follows becomes the answer. A server with more than one IPv6
  # address was intermittently told it had none.
  local found
  found="$(ip -6 -o addr show scope global 2>/dev/null || true)"
  [[ -n "$found" ]]
}

ipv6_global_addresses() {
  ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
}

ipv6_is_enabled() {
  [[ -f "$PANEL_IPV6_MARKER" ]]
}

# Add or remove the IPv6 twin of every listen directive SNPanel manages. The
# 443 lines are written by certbot, not by the panel, so this works on the
# files as they are rather than re-rendering them.
nginx_ipv6_rewrite() {
  local mode="$1"
  python3 - "$mode" <<'PY'
import glob
import re
import sys

mode = sys.argv[1]
# SNPanel owns everything in conf.d; the distribution's own vhosts are not here.
# certbot writes "listen 443 ssl; # managed by Certbot", so the trailing
# comment has to be allowed or every HTTPS vhost would be skipped.
listen_v4 = re.compile(r"^(\s*)listen\s+((?:\d{1,3}\.){3}\d{1,3}:)?(\d+)([^;]*);\s*(#.*)?$")
listen_v6 = re.compile(r"^\s*listen\s+\[::\]:")
changed = []

for path in sorted(glob.glob("/etc/nginx/conf.d/*.conf")):
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    out = []
    for index, line in enumerate(lines):
        if listen_v6.match(line):
            # Drop the ones we added; "off" keeps nothing, "on" re-adds below.
            continue
        out.append(line)
        if mode != "on":
            continue
        match = listen_v4.match(line)
        if not match:
            continue
        indent, address, port, rest, _comment = match.groups()
        if address and not address.startswith("0.0.0.0"):
            # A vhost pinned to one IPv4 address has no IPv6 counterpart to
            # guess, so leave it exactly as the operator wrote it.
            continue
        out.append(f"{indent}listen [::]:{port}{rest};")
    if out != lines:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")
        changed.append(path)

for path in changed:
    print(path)
PY
}

# Apply whatever the marker says, with every touched file restored if nginx
# refuses the result. Silent no-op when the switch is off and nothing carries
# an IPv6 listen line already.
nginx_ipv6_apply() {
  local mode backup file
  mode="off"
  ipv6_is_enabled && mode="on"
  backup="$(mktemp -d /tmp/snpanel-ipv6-backup.XXXXXX)"
  for file in /etc/nginx/conf.d/*.conf; do
    [[ -f "$file" ]] || continue
    cp -a "$file" "${backup}/$(basename "$file")"
  done
  nginx_ipv6_rewrite "$mode" >/dev/null
  if ! nginx -t >/dev/null 2>&1; then
    for file in "$backup"/*.conf; do
      [[ -f "$file" ]] || continue
      cp -a "$file" "/etc/nginx/conf.d/$(basename "$file")"
    done
    rm -rf "$backup"
    return 1
  fi
  rm -rf "$backup"
  systemctl reload nginx
}

malware_scan_file_list() {
  # One find over the machine, with the noise pruned. Ten seconds on a normal
  # VPS, and it buys an exact total so the panel can show real progress.
  local args=() path
  for path in "${MALWARE_SCAN_PRUNE[@]}"; do
    args+=(-path "$path" -prune -o)
  done
  find / "${args[@]}" -type f -print 2>/dev/null
}

run_malware_server_scan() {
  local job="$1" list log total rc
  [[ "$job" =~ ^[0-9a-f]{8,64}$ ]] || deny "invalid scan job id"
  command -v clamdscan >/dev/null 2>&1 || deny "clamdscan is not installed"
  systemctl is-active --quiet clamav-daemon || deny "clamav-daemon is not running"
  install -d -o snpanel -g snpanel -m 0750 "$MALWARE_JOBS_DIR"
  list="${MALWARE_JOBS_DIR}/${job}.files"
  log="${MALWARE_JOBS_DIR}/${job}.scan.log"
  rm -f "$list" "$log"

  malware_scan_file_list >"$list"
  total="$(wc -l <"$list")"
  # The panel reads its progress out of this file while the scan runs, so the
  # total has to be in there rather than only in the exit output.
  printf 'total=%s\n' "$total" >"$log"
  chown snpanel:snpanel "$list" "$log"
  chmod 0640 "$list" "$log"

  # --fdpass hands clamd an open descriptor, which is the only way it reads
  # files its own user cannot. Niced hard: a scan must never be the reason a
  # website goes slow.
  rc=0
  nice -n 19 ionice -c3 clamdscan --fdpass --stdout --no-summary --file-list="$list" >>"$log" 2>&1 || rc=$?
  rm -f "$list"
  printf 'total=%s\n' "$total"
  printf 'exit=%s\n' "$rc"
}

install_sni_cert_pair() {
  local domain="$1" cert="$2" key="$3" target="${PANEL_SNI_DIR}/${domain}"
  install -d -o root -g snpanel -m 0750 "$target"
  install -m 0640 -o root -g snpanel "$cert" "${target}/fullchain.pem"
  install -m 0640 -o root -g snpanel "$key" "${target}/privkey.pem"
}

sync_panel_sni_certificates() {
  # Every certificate on this machine, copied where the panel can read it.
  # Manual uploads are written after Let's Encrypt on purpose: when a domain
  # has both, the uploaded one is what nginx serves, so it is what the panel
  # should serve too.
  local live_dir manual_dir domain target keep served_domain
  local -a served=()
  install -d -o root -g snpanel -m 0750 /etc/snpanel "$PANEL_SNI_DIR"
  for live_dir in /etc/letsencrypt/live/*/; do
    [[ -f "${live_dir}fullchain.pem" && -f "${live_dir}privkey.pem" ]] || continue
    domain="$(basename "$live_dir")"
    is_domain "$domain" || continue
    install_sni_cert_pair "$domain" "${live_dir}fullchain.pem" "${live_dir}privkey.pem"
    served+=("$domain")
  done
  for manual_dir in /etc/nginx/snpanel/ssl/sites/*/; do
    [[ -f "${manual_dir}fullchain.crt" && -f "${manual_dir}privkey.key" ]] || continue
    domain="$(basename "$manual_dir")"
    is_domain "$domain" || continue
    install_sni_cert_pair "$domain" "${manual_dir}fullchain.crt" "${manual_dir}privkey.key"
    served+=("$domain")
  done
  # A certificate that is gone must stop being served, or the panel would keep
  # answering for a domain this server no longer hosts.
  for target in "$PANEL_SNI_DIR"/*/; do
    [[ -d "$target" ]] || continue
    domain="$(basename "$target")"
    keep=0
    for served_domain in ${served[@]+"${served[@]}"}; do
      [[ "$served_domain" == "$domain" ]] && { keep=1; break; }
    done
    (( keep == 1 )) || rm -rf -- "$target"
  done
  printf '%s\n' ${served[@]+"${served[@]}"}
}

install_sni_renewal_hook() {
  # The panel reads these copies again whenever they change on disk, so a
  # renewal needs no restart - only a fresh copy.
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/snpanel-sni-certs <<'HOOK'
#!/usr/bin/env bash
# Installed by SNPanel. Keeps the panel's per-hostname certificate copies fresh.
set -euo pipefail
# RENEWED_LINEAGE is set by certbot to the live directory that just changed.
[[ -n "${RENEWED_LINEAGE:-}" ]] || exit 0
domain="$(basename "$RENEWED_LINEAGE")"
[[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || exit 0
[[ -f "${RENEWED_LINEAGE}/fullchain.pem" && -f "${RENEWED_LINEAGE}/privkey.pem" ]] || exit 0
install -d -o root -g snpanel -m 0750 /etc/snpanel /etc/snpanel/sni "/etc/snpanel/sni/${domain}"
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/fullchain.pem" "/etc/snpanel/sni/${domain}/fullchain.pem"
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/privkey.pem" "/etc/snpanel/sni/${domain}/privkey.pem"
HOOK
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/snpanel-sni-certs
}

install_panel_cert_renewal_hook() {
  # A certificate the panel borrowed from a website is a copy, and copies go
  # stale: certbot renews the website's lineage every couple of months and the
  # panel would keep serving the expired one until someone noticed.
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/snpanel-panel-cert <<'HOOK'
#!/usr/bin/env bash
# Installed by SNPanel. Refreshes the panel's copy of a website certificate.
set -euo pipefail
env_file="/opt/snpanel/backend/.env"
[[ -f "$env_file" ]] || exit 0
mode="$(sed -nE 's/^PANEL_SSL_MODE=//p' "$env_file" | tail -n1 | tr -d '"')"
domain="$(sed -nE 's/^PANEL_DOMAIN=//p' "$env_file" | tail -n1 | tr -d '"')"
[[ "$mode" == "domain" && -n "$domain" ]] || exit 0
# RENEWED_LINEAGE is set by certbot to the live directory that just changed.
[[ "${RENEWED_LINEAGE:-}" == "/etc/letsencrypt/live/${domain}" ]] || exit 0
install -d -o root -g snpanel -m 0750 /etc/snpanel
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/privkey.pem" /etc/snpanel/panel-privkey.pem
systemctl restart snpanel-api || true
HOOK
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/snpanel-panel-cert
}

require_backup_path() {
  # These commands write and read files as root at a path the panel chose, which
  # is only safe while that path cannot leave the backup tree — directly, through
  # .., or through a symlinked parent.
  local target="$1" parent real_parent
  [[ -n "$target" ]] || deny "empty backup path"
  [[ "$target" != *$'\n'* ]] || deny "invalid backup path"
  [[ "$target" != *".."* ]] || deny "backup path may not contain .."
  case "$target" in
    "${BACKUP_ROOT}"/*) : ;;
    *) deny "backup path must be under ${BACKUP_ROOT}" ;;
  esac
  install -d -m 0750 -o root -g snpanel "$BACKUP_ROOT"
  parent="$(dirname "$target")"
  [[ -d "$parent" ]] || deny "backup directory does not exist: $parent"
  real_parent="$(readlink -f "$parent")" || deny "cannot resolve $parent"
  case "$real_parent" in
    "${BACKUP_ROOT}"|"${BACKUP_ROOT}"/*) : ;;
    *) deny "backup directory escapes ${BACKUP_ROOT}" ;;
  esac
}

ensure_app_directory() {
  local user="$1" name="$2" apps_root target
  require_linux_user "$user"
  require_app_name "$name"
  apps_root="$(printf '%s/%s/apps' "$HOME_ROOT" "$user")"
  target="$(app_directory "$user" "$name")"
  [[ -d "${HOME_ROOT}/${user}" ]] || deny "home directory missing for $user"
  ensure_sites_group
  install -d -m 0750 "$apps_root"
  install -d -m 0750 "$target"
  harden_site_dir "$apps_root" "$user"
  harden_site_dir "$target" "$user"
  printf '%s' "$target"
}

remove_legacy_app_units() {
  # Units and containers from the release where an app was named after the
  # website it hung off. Nothing else would ever clean them up.
  local user="$1" name="$2" legacy unit stale
  for legacy in /etc/systemd/system/snpanel-app-"${user}"-*-"${name}".service; do
    [[ -f "$legacy" ]] || continue
    unit="$(basename "$legacy")"
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f "$legacy"
  done
  if command -v docker >/dev/null 2>&1; then
    # The trailing `|| true` matters: under `set -o pipefail` a grep that
    # matches nothing fails the pipeline, and `set -e` then kills the helper
    # without printing anything at all.
    stale="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E "^snpanel-${user}-[0-9a-f]{8}-${name}$" || true)"
    for legacy in $stale; do
      docker rm -f "$legacy" >/dev/null 2>&1 || true
    done
  fi
  rm -f "${SNPANEL_DATA_DIR}/apps/${user}"-*-"${name}.env"
}

require_app_port() {
  [[ "$1" =~ ^[0-9]{4,5}$ ]] || deny "invalid app port: $1"
  (( $1 >= 21000 && $1 <= 21999 )) || deny "app port outside the managed range: $1"
}

require_container_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || deny "invalid container port: $1"
  (( $1 >= 1 && $1 <= 65535 )) || deny "container port out of range: $1"
}

require_app_memory() {
  [[ "$1" =~ ^[0-9]{2,5}$ ]] || deny "invalid memory limit: $1"
  (( $1 >= 64 && $1 <= 16384 )) || deny "memory limit out of range: $1"
}

require_app_cpus() {
  [[ "$1" =~ ^[0-9]{1,2}(\.[0-9])?$ ]] || deny "invalid cpu limit: $1"
}

require_node_major() {
  [[ "$1" =~ ^[1-9][0-9]$ ]] || deny "invalid node major version: $1"
}

require_docker_image() {
  # Registry/name[:tag][@digest]. No whitespace and no leading dash, so the
  # reference can never be read by docker as a flag.
  [[ "$1" =~ ^[a-z0-9][a-z0-9._/-]{0,159}(:[A-Za-z0-9._-]{1,127})?(@sha256:[a-f0-9]{64})?$ ]] \
    || deny "invalid container image reference: $1"
  case "$1" in
    -*|*..*) deny "invalid container image reference: $1" ;;
  esac
}

resolve_node_bin_dir() {
  local major="$1" sys_major=""
  if [[ -x "/opt/snpanel/node/${major}/bin/node" ]]; then
    printf '/opt/snpanel/node/%s/bin' "$major"
    return 0
  fi
  if [[ -x /usr/bin/node ]]; then
    sys_major="$(/usr/bin/node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"
    if [[ "$sys_major" == "$major" ]]; then
      printf '/usr/bin'
      return 0
    fi
  fi
  return 1
}

write_app_env_file() {
  # Environment arrives on stdin as KEY=value lines, and only root ever reads
  # the result, so the site user cannot edit a value past validation.
  local target="$1" line tmp
  install -d -o root -g root -m 0700 "${SNPANEL_DATA_DIR}/apps"
  tmp="${target}.snpanel-tmp"
  install -m 0600 -o root -g root /dev/null "$tmp"
  while IFS= read -r line; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]] || deny "invalid environment line (expected KEY=value)"
    printf '%s\n' "$line" >>"$tmp"
  done
  mv -f "$tmp" "$target"
  chown root:root "$target"
  chmod 0600 "$target"
}

write_node_app_unit() {
  local unit_path="$1" app_label="$2" user="$3" app_dir="$4" env_file="$5"
  local port="$6" memory="$7" node_major="$8" app_exec="${9}" app_arg="${10}"
  local bin_dir exec_start identifier
  bin_dir="$(resolve_node_bin_dir "$node_major")" \
    || deny "Node ${node_major} is not installed; run node-install ${node_major} first"
  case "$app_exec" in
    node) exec_start="${bin_dir}/node ${app_arg}" ;;
    npm)  exec_start="${bin_dir}/npm run --silent ${app_arg}" ;;
    npx)  exec_start="${bin_dir}/npx --yes ${app_arg}" ;;
    yarn)
      if [[ -x "${bin_dir}/yarn" ]]; then
        exec_start="${bin_dir}/yarn ${app_arg}"
      elif [[ -x /usr/local/bin/yarn ]]; then
        exec_start="/usr/local/bin/yarn ${app_arg}"
      else
        deny "yarn is not installed; use npm instead"
      fi
      ;;
    *) deny "invalid start command: $app_exec" ;;
  esac
  identifier="$(basename "$unit_path" .service)"
  cat >"$unit_path" <<UNIT
[Unit]
Description=SNPanel application ${app_label} (${user})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${user}
Group=${user}
WorkingDirectory=${app_dir}
EnvironmentFile=-${env_file}
# HOST is forced so a misconfigured app cannot bind a public interface. The
# firewall is the second layer here, not the only one.
Environment=HOST=127.0.0.1
Environment=NODE_ENV=production
Environment=PORT=${port}
Environment=HOME=${HOME_ROOT}/${user}
Environment=PATH=${bin_dir}:/usr/local/bin:/usr/bin:/bin
ExecStart=${exec_start}
Restart=always
RestartSec=5
MemoryAccounting=yes
MemoryMax=${memory}M
TasksMax=256
LimitNOFILE=8192
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${app_dir}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${identifier}

[Install]
WantedBy=multi-user.target
UNIT
}

write_docker_app_unit() {
  local unit_path="$1" app_label="$2" user="$3" container="$4" app_dir="$5" env_file="$6"
  local port="$7" memory="$8" image="$9" container_port="${10}" cpus="${11}"
  local uid gid identifier
  uid="$(id -u "$user")" || deny "cannot resolve uid for $user"
  gid="$(id -g "$user")" || deny "cannot resolve gid for $user"
  identifier="$(basename "$unit_path" .service)"
  # The unit runs as root because it talks to the Docker socket, but the
  # container is the site user, has no capabilities, cannot gain privileges and
  # publishes only on loopback. The customer never gets socket access - that
  # would be equivalent to handing out root.
  cat >"$unit_path" <<UNIT
[Unit]
Description=SNPanel container ${app_label} (${user})
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=exec
ExecStartPre=-/usr/bin/docker rm -f ${container}
ExecStart=/usr/bin/docker run --rm --name ${container} \\
  --user ${uid}:${gid} \\
  --publish 127.0.0.1:${port}:${container_port} \\
  --env-file ${env_file} \\
  --env PORT=${container_port} \\
  --env HOST=0.0.0.0 \\
  --volume ${app_dir}:/app \\
  --workdir /app \\
  --memory ${memory}m \\
  --memory-swap ${memory}m \\
  --cpus ${cpus} \\
  --pids-limit 256 \\
  --cap-drop ALL \\
  --security-opt no-new-privileges \\
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \\
  ${image}
ExecStop=/usr/bin/docker stop --time 20 ${container}
Restart=always
RestartSec=5
TimeoutStartSec=300
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${identifier}

[Install]
WantedBy=multi-user.target
UNIT
}

write_docker_daemon_config() {
  install -d -m 0755 /etc/docker
  # Log rotation is not optional on a shared host: an unbounded container log
  # fills the disk and takes every other site down with it.
  cat >/etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "default-address-pool": [ { "base": "172.31.0.0/16", "size": 24 } ]
}
JSON
}

install_docker_firewall_guard() {
  # Docker publishes ports by DNAT in PREROUTING and allows them through its own
  # FORWARD chain, so a published port never passes through SNPANEL-INPUT. Panel
  # apps only ever publish on loopback, but a container started by hand could
  # publish on 0.0.0.0 and be reachable while the firewall looks enabled.
  # DOCKER-USER is the one chain Docker leaves to the operator.
  command -v iptables >/dev/null 2>&1 || return 0
  command -v docker >/dev/null 2>&1 || return 0
  local iface
  iface="$(ip route show default 2>/dev/null | awk '/^default/{print $5; exit}')"
  [[ -n "$iface" ]] || return 0
  iptables -w -N DOCKER-USER 2>/dev/null || true
  iptables -w -D DOCKER-USER -i "$iface" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
  iptables -w -D DOCKER-USER -i "$iface" -j DROP 2>/dev/null || true
  iptables -w -I DOCKER-USER 1 -i "$iface" -j DROP
  iptables -w -I DOCKER-USER 1 -i "$iface" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
}

install_docker_engine() {
  if command -v docker >/dev/null 2>&1; then
    write_docker_daemon_config
    systemctl restart docker >/dev/null 2>&1 || true
    install_docker_firewall_guard
    echo "Docker is already installed"
    return 0
  fi
  local distro codename arch
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu) distro=ubuntu ;;
    debian) distro=debian ;;
    *) deny "unsupported distribution for Docker install: ${ID:-unknown}" ;;
  esac
  codename="${VERSION_CODENAME:-}"
  [[ -n "$codename" ]] || deny "cannot determine distribution codename"
  arch="$(dpkg --print-architecture)"
  export DEBIAN_FRONTEND=noninteractive
  pkg_update_index
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${distro}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$arch" "$distro" "$codename" >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  write_docker_daemon_config
  systemctl enable --now docker
  install_docker_firewall_guard
  echo "Docker installed"
}

install_node_major() {
  local major="$1" arch tmp url latest
  require_node_major "$major"
  if [[ -x "/opt/snpanel/node/${major}/bin/node" ]]; then
    echo "Node ${major} is already installed"
    return 0
  fi
  case "$(dpkg --print-architecture)" in
    amd64) arch=x64 ;;
    arm64) arch=arm64 ;;
    *) deny "unsupported architecture for Node install" ;;
  esac
  latest="$(curl -fsSL https://nodejs.org/dist/index.json | SNPANEL_NODE_MAJOR="$major" python3 -c 'import json, os, sys
major = os.environ["SNPANEL_NODE_MAJOR"]
names = [item["version"] for item in json.load(sys.stdin) if item["version"].startswith("v" + major + ".")]
print(names[0] if names else "")' || true)"
  [[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || deny "no Node ${major} release found upstream"
  url="https://nodejs.org/dist/${latest}/node-${latest}-linux-${arch}.tar.xz"
  tmp="$(mktemp -d)"
  curl -fsSL "$url" -o "${tmp}/node.tar.xz" || { rm -rf "$tmp"; deny "cannot download ${url}"; }
  install -d -m 0755 /opt/snpanel/node
  rm -rf "/opt/snpanel/node/${major}.tmp"
  install -d -m 0755 "/opt/snpanel/node/${major}.tmp"
  tar -xJf "${tmp}/node.tar.xz" -C "/opt/snpanel/node/${major}.tmp" --strip-components=1
  rm -rf "$tmp"
  rm -rf "/opt/snpanel/node/${major}"
  mv "/opt/snpanel/node/${major}.tmp" "/opt/snpanel/node/${major}"
  chown -R root:root "/opt/snpanel/node/${major}"
  echo "Node ${latest} installed to /opt/snpanel/node/${major}"
}

list_installed_node_majors() {
  local dir
  [[ -d /opt/snpanel/node ]] || return 0
  for dir in /opt/snpanel/node/*; do
    [[ -x "$dir/bin/node" ]] || continue
    basename "$dir"
  done
}

is_in() {
  local needle="$1"; shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

is_allowed_service() {
  local service="$1" php_version=""
  if is_in "$service" "${ALLOWED_SERVICES[@]}"; then
    return 0
  fi
  if [[ "$service" =~ ^php([0-9]+\.[0-9]+)-fpm$ ]]; then
    php_version="${BASH_REMATCH[1]}"
    [[ -f "/etc/php/${php_version}/fpm/php-fpm.conf" ]] && return 0
  fi
  return 1
}

require_safe_path() {
  local prefix="$1" path="$2"
  # Reject path traversal components, newlines, and empty input. Bash strings
  # cannot carry NUL bytes, so there is no separate NUL pattern here.
  # Note: we cannot use `*..*` as a glob because that would also reject
  # legitimate filenames that just happen to contain a dot adjacent to a dot
  # via Bash's pattern matching quirks; instead we match the `..` only when
  # it actually forms a path component.
  case "$path" in
    *$'\n'*) deny "unsafe path: $path" ;;
    "") deny "empty path" ;;
    "..") deny "path traversal not allowed" ;;
    "../"*|*"/.."|*"/../"*) deny "path traversal not allowed" ;;
  esac
  local resolved
  resolved=$(readlink -m "$path") || deny "cannot resolve $path"
  case "$resolved/" in
    "$prefix"/*) ;;
    *) deny "path outside $prefix: $resolved" ;;
  esac
  echo "$resolved"
}

require_domain() {
  local d="$1"
  [[ "$d" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
    || deny "invalid domain: $d"
}

require_email() {
  local e="$1"
  [[ "$e" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] \
    || deny "invalid email: $e"
}

require_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || deny "invalid port: $1"
  (( $1 >= 1 && $1 <= 65535 )) || deny "port out of range: $1"
}

require_tail_lines() {
  [[ "$1" =~ ^[0-9]{1,4}$ ]] || deny "invalid log line count: $1"
  (( $1 >= 1 && $1 <= 5000 )) || deny "log line count out of range: $1"
}

require_proto() {
  [[ "$1" == "tcp" || "$1" == "udp" ]] || deny "invalid protocol: $1"
}

require_php_version() {
  [[ "$1" =~ ^(5\.6|7\.4|8\.0|8\.1|8\.2|8\.3|8\.4|8\.5)$ ]] || deny "invalid PHP version: $1"
}

require_linux_user() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]] || deny "invalid panel Linux user: $1"
  case "$1" in
    root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|_apt|nobody|snpanel|snpanel-sites|snpanel-sftp|mysql|redis|nginx)
      deny "reserved panel Linux user: $1" ;;
  esac
}

managed_root_depth() {
  # How many leading components of a path under a user's home make up a managed
  # root. A website root is <domain>; an application root is apps/<name>. Both
  # keep operations inside a named subtree instead of the bare home directory.
  local relative="$1" first second
  first="${relative%%/*}"
  if [[ "$first" == "apps" ]]; then
    [[ "$relative" == */* ]] || deny "application path is missing an application name"
    second="${relative#*/}"
    second="${second%%/*}"
    require_app_name "$second"
    printf '2'
    return 0
  fi
  require_site_domain_segment "$first"
  printf '1'
}

require_site_domain_segment() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
    || deny "invalid site domain path segment: $1"
}

read_site_logs_many() {
  # read_site_logs_many <access|error> <lines> <domain>...
  # One spawn for every site's log instead of one sudo round-trip each. Output
  # is per-domain, each block introduced by a US (0x1f) record separator so the
  # panel can split it without guessing.
  local kind="$1" lines="$2"; shift 2
  [[ "$kind" == "access" || "$kind" == "error" ]] || deny "invalid log kind: $kind"
  require_tail_lines "$lines"
  local domain path
  for domain in "$@"; do
    require_domain "$domain"
    path="/var/log/nginx/${domain}.${kind}.log"
    printf '\x1f%s\n' "$domain"
    if [[ -f "$path" && ! -L "$path" ]]; then
      tail -n "$lines" -- "$path" 2>/dev/null || true
    else
      printf 'SNPANEL_LOG_MISSING\n'
    fi
  done
}

read_site_log() {
  local domain="$1" kind="$2" lines="$3" path resolved
  require_domain "$domain"
  [[ "$kind" == "access" || "$kind" == "error" ]] || deny "invalid log kind: $kind"
  require_tail_lines "$lines"
  path="/var/log/nginx/${domain}.${kind}.log"
  resolved=$(readlink -m "$path") || deny "cannot resolve log path"
  case "$resolved" in
    /var/log/nginx/*) ;;
    *) deny "log path outside /var/log/nginx: $resolved" ;;
  esac
  echo "SNPANEL_LOG_PATH=$resolved" >&2
  if [[ ! -f "$resolved" ]]; then
    echo "SNPANEL_LOG_MISSING=1" >&2
    return 0
  fi
  tail -n "$lines" -- "$resolved"
}

require_managed_path() {
  local path="$1" user="${2:-}"
  local resolved first_part relative domain_part
  resolved=$(require_safe_path "$HOME_ROOT" "$path")
  if [[ -n "$user" ]]; then
    require_linux_user "$user"
    case "$resolved/" in
      "$HOME_ROOT/$user/"*)
        relative="${resolved#${HOME_ROOT}/${user}/}"
        managed_root_depth "$relative" >/dev/null
        ;;
      *) deny "path is not owned by panel Linux user $user: $resolved" ;;
    esac
  else
    case "$resolved/" in
      "$HOME_ROOT"/*/*)
        first_part="${resolved#${HOME_ROOT}/}"
        first_part="${first_part%%/*}"
        require_linux_user "$first_part"
        relative="${resolved#${HOME_ROOT}/${first_part}/}"
        managed_root_depth "$relative" >/dev/null
        ;;
      *) deny "path outside managed site roots: $resolved" ;;
    esac
  fi
  echo "$resolved"
}

require_bound_managed_path() {
  local user="$1" root="$2" path="$3"
  local normalized_root normalized target target_relative root_relative root_depth
  require_linux_user "$user"
  case "$root" in
    *$'\n'*) deny "unsafe root: $root" ;;
    "") deny "empty root" ;;
    "..") deny "root traversal not allowed" ;;
    "../"*|*"/.."|*"/../"*) deny "root traversal not allowed" ;;
  esac
  [[ "$root" == /* ]] || deny "root must be absolute: $root"
  normalized_root=$(python3 -c 'import os, sys; print(os.path.normpath(sys.argv[1]))' "$root") || deny "cannot normalize $root"
  case "$normalized_root/" in
    "$HOME_ROOT/$user/"*) ;;
    *) deny "root is not owned by panel Linux user $user: $normalized_root" ;;
  esac
  root_relative="${normalized_root#${HOME_ROOT}/${user}/}"
  root_depth="$(managed_root_depth "$root_relative")"
  if [[ "$root_depth" == "1" ]]; then
    [[ "$root_relative" == */* ]] && deny "site root must be a direct domain path: $normalized_root"
  else
    [[ "$root_relative" == */*/* ]] && deny "application root must be apps/<name>: $normalized_root"
  fi

  case "$path" in
    *$'\n'*) deny "unsafe path: $path" ;;
    "") deny "empty path" ;;
    "..") deny "path traversal not allowed" ;;
    "../"*|*"/.."|*"/../"*) deny "path traversal not allowed" ;;
  esac
  [[ "$path" == /* ]] || deny "path must be absolute: $path"
  normalized=$(python3 -c 'import os, sys; print(os.path.normpath(sys.argv[1]))' "$path") || deny "cannot normalize $path"
  case "$normalized/" in
    "$normalized_root"|"$normalized_root/"*) ;;
    *) deny "path outside expected site root: $normalized" ;;
  esac
  target="$normalized"
  target_relative="${target#${HOME_ROOT}/${user}/}"
  [[ "$target" == "$normalized_root" || "$target_relative" == */* ]] || deny "refusing to operate on a panel user home"
  echo "$target"
}

delete_no_follow() {
  local user="$1" root="$2" target="$3"
  python3 - "$user" "$root" "$target" <<'PY'
import os
import stat
import sys

user, root, target = sys.argv[1:4]
base = f"/home/{user}"
root = os.path.normpath(root)
target = os.path.normpath(target)

# A website root is /home/<user>/<domain>; an application root is one level
# deeper, /home/<user>/apps/<name>. Anything else is not a managed tree.
if os.path.dirname(root) not in (base, os.path.join(base, "apps")):
    raise SystemExit("invalid site root")
if target != root and not target.startswith(root + os.sep):
    raise SystemExit("target outside site root")

rel = os.path.relpath(target, base)
if rel.startswith("..") or rel == ".":
    raise SystemExit("target outside site root")

def open_child(parent_fd, name):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)

base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_fd = base_fd
    close_parent = False
    parts = rel.split(os.sep)
    for part in parts[:-1]:
        next_fd = open_child(parent_fd, part)
        if close_parent:
            os.close(parent_fd)
        parent_fd = next_fd
        close_parent = True

    leaf = parts[-1]

    def remove_entry(dir_fd, name):
        st = os.lstat(name, dir_fd=dir_fd)
        if stat.S_ISDIR(st.st_mode):
            child_fd = open_child(dir_fd, name)
            try:
                for entry in os.listdir(child_fd):
                    remove_entry(child_fd, entry)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=dir_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)

    remove_entry(parent_fd, leaf)
finally:
    try:
        if 'parent_fd' in locals() and parent_fd != base_fd:
            os.close(parent_fd)
    finally:
        os.close(base_fd)
PY
}

require_terminal_cwd() {
  local path="$1" user="$2" resolved
  require_linux_user "$user"
  resolved=$(require_safe_path "$HOME_ROOT" "$path")
  case "$resolved" in
    "$HOME_ROOT/$user"|"$HOME_ROOT/$user"/*) ;;
    *) deny "terminal cwd is not owned by panel Linux user $user: $resolved" ;;
  esac
  [[ -d "$resolved" ]] || deny "terminal cwd is not a directory: $resolved"
  echo "$resolved"
}

require_terminal_path_args() {
  local user="$1" cwd="$2" arg resolved
  shift 2
  require_linux_user "$user"
  for arg in "$@"; do
    case "$arg" in
      ""|"-"*|"--") continue ;;
      *$'\n'*|".."|"../"*|*"/.."|*"/../"*) deny "terminal path argument escapes user home: $arg" ;;
    esac
    if [[ "$arg" = /* ]]; then
      resolved=$(readlink -m -- "$arg") || deny "cannot resolve terminal path: $arg"
    else
      resolved=$(readlink -m -- "$cwd/$arg") || deny "cannot resolve terminal path: $arg"
    fi
    case "$resolved/" in
      "$HOME_ROOT/$user/"*) ;;
      *) deny "terminal path argument is outside panel user home: $arg" ;;
    esac
  done
}

require_terminal_download_args() {
  local user="$1" cwd="$2" arg value expect_output=0
  shift 2
  for arg in "$@"; do
    case "${arg,,}" in
      file://*) deny "terminal URL argument uses local file scheme: $arg" ;;
    esac
    if (( expect_output )); then
      require_terminal_path_args "$user" "$cwd" "$arg"
      expect_output=0
      continue
    fi
    case "$arg" in
      --output=*|--output-document=*|-O=*)
        value="${arg#*=}"
        require_terminal_path_args "$user" "$cwd" "$value"
        ;;
      -o|-O|--output|--output-document)
        expect_output=1
        ;;
      http://*|https://*|ftp://*|ftps://*|sftp://*)
        ;;
      -*|"")
        ;;
      *)
        require_terminal_path_args "$user" "$cwd" "$arg"
        ;;
    esac
  done
  (( expect_output == 0 )) || deny "terminal download output path is missing"
}

ensure_sites_group() {
  getent group "$SNPANEL_SITES_GROUP" >/dev/null || groupadd --system "$SNPANEL_SITES_GROUP"
  usermod -aG "$SNPANEL_SITES_GROUP" snpanel 2>/dev/null || true
  usermod -aG "$SNPANEL_SITES_GROUP" "$WEB_USER" 2>/dev/null || true
}

ensure_sftp_group() {
  getent group "$SNPANEL_SFTP_GROUP" >/dev/null || groupadd --system "$SNPANEL_SFTP_GROUP"
}

clear_path_acl() {
  local target="$1"
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -b -k "$target" 2>/dev/null || true
  fi
}

protect_site_secret_file() {
  local target="$1" name
  name="$(basename -- "$target")"
  local secret
  for secret in "${SITE_SECRET_FILES[@]}"; do
    if [[ "$name" == "$secret" ]]; then
      chmod 0640 "$target" 2>/dev/null || true
      return 0
    fi
  done
  return 0
}

protect_site_secret_tree() {
  local target="$1" secret
  for secret in "${SITE_SECRET_FILES[@]}"; do
    find "$target" -type f -name "$secret" -exec chmod 0640 {} + 2>/dev/null || true
  done
  return 0
}

harden_site_dir() {
  local target="$1" user="$2"
  chown "$user:$SNPANEL_SITES_GROUP" "$target"
  clear_path_acl "$target"
  chmod "$SITE_DIR_MODE" "$target"
  chmod a-s "$target" 2>/dev/null || true
  chmod -t "$target" 2>/dev/null || true
}

harden_site_file() {
  local target="$1" user="$2"
  chown "$user:$SNPANEL_SITES_GROUP" "$target"
  clear_path_acl "$target"
  chmod "$SITE_FILE_MODE" "$target"
  chmod a-s "$target" 2>/dev/null || true
  chmod -t "$target" 2>/dev/null || true
  protect_site_secret_file "$target"
}

harden_site_dir_path() {
  local root="$1" target="$2" user="$3" relative current part
  ensure_sites_group
  require_linux_user "$user"
  root=$(readlink -m "$root") || deny "cannot resolve $root"
  target=$(readlink -m "$target") || deny "cannot resolve $target"
  case "$target" in
    "$root"|"$root"/*) ;;
    *) deny "directory path outside site root: $target" ;;
  esac
  [[ -d "$target" ]] || deny "site directory does not exist: $target"
  harden_site_dir "$root" "$user"
  [[ "$target" == "$root" ]] && return 0
  relative="${target#${root}/}"
  current="$root"
  IFS='/' read -r -a root_parts <<< "$relative"
  for part in "${root_parts[@]}"; do
    current="$current/$part"
    [[ -d "$current" ]] || deny "site directory does not exist: $current"
    harden_site_dir "$current" "$user"
  done
}

ensure_panel_user_home() {
  local user="$1" home_dir="$HOME_ROOT/$1"
  ensure_sites_group
  ensure_sftp_group
  require_linux_user "$user"
  getent group "$user" >/dev/null || groupadd "$user"
  usermod -aG "$user" "$WEB_USER" 2>/dev/null || true
  chown root:root "$HOME_ROOT"
  chmod 0711 "$HOME_ROOT"
  chmod a-s "$HOME_ROOT" 2>/dev/null || true
  chmod -t "$HOME_ROOT" 2>/dev/null || true
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --create-home --home-dir "$home_dir" --shell /usr/sbin/nologin --gid "$user" "$user"
  fi
  usermod --home "$home_dir" --shell /usr/sbin/nologin --gid "$user" "$user" 2>/dev/null || true
  usermod -aG "$SNPANEL_SFTP_GROUP" "$user" 2>/dev/null || true
  mkdir -p "$home_dir"
  chown "root:$user" "$home_dir"
  chmod 0751 "$home_dir"
  chmod a-s "$home_dir" 2>/dev/null || true
  chmod -t "$home_dir" 2>/dev/null || true
  clear_path_acl "$home_dir"
}

set_panel_user_password() {
  local user="$1" password
  require_linux_user "$user"
  id -u "$user" >/dev/null 2>&1 || deny "panel Linux user does not exist: $user"
  password="$(cat)"
  password="${password%$'\n'}"
  [[ ${#password} -ge 12 && ${#password} -le 72 ]] || deny "password must be 12-72 characters"
  case "$password" in
    *:*|*$'\r'*|*$'\n'*) deny "password cannot contain ':', carriage returns or newlines" ;;
  esac
  printf '%s:%s\n' "$user" "$password" | chpasswd
  passwd -u "$user" >/dev/null 2>&1 || true
}

delete_panel_user_runtime() {
  local user="$1"
  require_linux_user "$user"
  for dir in /etc/php/*/fpm/pool.d; do
    [[ -d "$dir" ]] || continue
    for pool_file in "$dir"/snpanel-${user}.conf "$dir"/snpanel-${user}-*.conf; do
      [[ -f "$pool_file" ]] || continue
      rm -f "$pool_file"
      local php_version
      php_version="$(echo "$dir" | awk -F/ '{print $4}')"
      systemctl reload "php${php_version}-fpm" 2>/dev/null || true
    done
  done
  crontab -r -u "$user" 2>/dev/null || true
  pkill -u "$user" 2>/dev/null || true
  userdel "$user" 2>/dev/null || true
  groupdel "$user" 2>/dev/null || true
  rm -rf "$HOME_ROOT/$user" 2>/dev/null || true
  rm -rf "/var/lib/php/sessions/$user" 2>/dev/null || true
  rm -rf "/var/lib/php/uploads/$user" 2>/dev/null || true
}

site_php_pool_glob() {
  local user="$1" target="$2"
  require_linux_user "$user"
  target=$(readlink -m "$target") || deny "cannot resolve $target"
  local site_hash
  site_hash="$(printf '%s' "$target" | sha256sum | awk '{print substr($1, 1, 12)}')"
  printf 'snpanel-%s-%s-*' "$user" "$site_hash"
}

positive_int_or_default() {
  local value="${1:-}" default="$2" min="${3:-1}" max="${4:-}"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    value="$default"
  fi
  if (( value < min )); then
    value="$min"
  fi
  if [[ -n "$max" ]] && (( value > max )); then
    value="$max"
  fi
  printf '%s\n' "$value"
}

php_fpm_tuning_value() {
  local key="$1" default="$2" value=""
  if [[ -v "$key" ]]; then
    value="${!key}"
  fi
  if [[ -z "$value" ]]; then
    value="$(env_get "$key" 2>/dev/null || true)"
  fi
  printf '%s\n' "${value:-$default}"
}

php_fpm_total_memory_mb() {
  local total
  total="$(awk '/^MemTotal:/ { print int($2 / 1024); exit }' /proc/meminfo 2>/dev/null || true)"
  positive_int_or_default "$total" 1024 256 1048576
}

php_fpm_cpu_count() {
  local count
  count="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  positive_int_or_default "$count" 1 1 256
}

php_fpm_pool_count() {
  local current_pool="${1:-}" count=0 pool_file
  shopt -s nullglob
  for pool_file in /etc/php/*/fpm/pool.d/snpanel-*.conf; do
    [[ -f "$pool_file" ]] || continue
    count=$((count + 1))
  done
  shopt -u nullglob
  if [[ -n "$current_pool" && ! -f "$current_pool" ]]; then
    count=$((count + 1))
  fi
  if (( count < 1 )); then
    count=1
  fi
  printf '%s\n' "$count"
}

php_fpm_reserved_memory_mb() {
  local total="$1" reserve
  if (( total <= 1024 )); then
    reserve=$((total * 45 / 100))
    (( reserve >= 448 )) || reserve=448
  elif (( total <= 2048 )); then
    reserve=$((total * 35 / 100))
    (( reserve >= 640 )) || reserve=640
  elif (( total <= 4096 )); then
    reserve=$((total * 30 / 100))
    (( reserve >= 896 )) || reserve=896
  elif (( total <= 8192 )); then
    reserve=$((total * 25 / 100))
    (( reserve >= 1280 )) || reserve=1280
  else
    reserve=$((total * 20 / 100))
    (( reserve >= 2048 )) || reserve=2048
  fi
  if (( reserve > total - 128 )); then
    reserve=$((total - 128))
  fi
  if (( reserve < 128 )); then
    reserve=128
  fi
  printf '%s\n' "$reserve"
}

calculate_php_fpm_pool_tuning() {
  local current_pool="${1:-}" total_mb reserve_mb php_budget_mb cpu_count pool_count worker_mb
  local global_children pool_children cpu_cap profile_cap forced_children idle_default requests_default
  local active_pool_divisor pool_floor
  total_mb="$(php_fpm_total_memory_mb)"
  cpu_count="$(php_fpm_cpu_count)"
  pool_count="$(php_fpm_pool_count "$current_pool")"
  worker_mb="$(positive_int_or_default "$(php_fpm_tuning_value SNPANEL_PHP_FPM_WORKER_MB "$PHP_FPM_DEFAULT_WORKER_MB")" "$PHP_FPM_DEFAULT_WORKER_MB" 32 1024)"
  reserve_mb="$(php_fpm_reserved_memory_mb "$total_mb")"
  php_budget_mb=$((total_mb - reserve_mb))
  if (( php_budget_mb < worker_mb )); then
    php_budget_mb="$worker_mb"
  fi

  global_children=$((php_budget_mb / worker_mb))
  (( global_children >= 1 )) || global_children=1

  active_pool_divisor=1
  while (( active_pool_divisor * active_pool_divisor < pool_count )); do
    active_pool_divisor=$((active_pool_divisor + 1))
  done
  pool_children=$((global_children / active_pool_divisor))
  (( pool_children >= 1 )) || pool_children=1

  cpu_cap=$((cpu_count * 4))
  if (( total_mb >= 3072 )); then
    cpu_cap=$((cpu_count * 6))
  fi
  if (( total_mb >= 8192 )); then
    cpu_cap=$((cpu_count * 8))
  fi
  (( cpu_cap >= 2 )) || cpu_cap=2
  (( cpu_cap <= 96 )) || cpu_cap=96

  if (( total_mb <= 1024 )); then
    pool_floor=1
    profile_cap=4
    idle_default=10
    requests_default=300
  elif (( total_mb <= 2048 )); then
    pool_floor=2
    profile_cap=8
    idle_default=15
    requests_default=400
  elif (( total_mb <= 4096 )); then
    pool_floor=3
    profile_cap=14
    idle_default=20
    requests_default=500
  elif (( total_mb <= 8192 )); then
    pool_floor=4
    profile_cap=24
    idle_default=30
    requests_default=750
  else
    pool_floor=6
    profile_cap=48
    idle_default=45
    requests_default=1000
  fi

  (( pool_children >= pool_floor )) || pool_children="$pool_floor"
  (( pool_children <= cpu_cap )) || pool_children="$cpu_cap"
  (( pool_children <= profile_cap )) || pool_children="$profile_cap"
  forced_children="$(php_fpm_tuning_value SNPANEL_PHP_FPM_MAX_CHILDREN "")"
  if [[ -n "$forced_children" ]]; then
    pool_children="$(positive_int_or_default "$forced_children" "$pool_children" 1 512)"
  fi

  PHP_FPM_PM_MODE="ondemand"
  PHP_FPM_MAX_CHILDREN="$pool_children"
  PHP_FPM_PROCESS_IDLE_TIMEOUT="$(positive_int_or_default "$(php_fpm_tuning_value SNPANEL_PHP_FPM_IDLE_TIMEOUT "$idle_default")" "$idle_default" 5 300)"
  PHP_FPM_MAX_REQUESTS="$(positive_int_or_default "$(php_fpm_tuning_value SNPANEL_PHP_FPM_MAX_REQUESTS "$requests_default")" "$requests_default" 50 10000)"
  PHP_FPM_REQUEST_TERMINATE_TIMEOUT="$(positive_int_or_default "$(php_fpm_tuning_value SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT "$PHP_FPM_DEFAULT_REQUEST_TERMINATE_TIMEOUT")" "$PHP_FPM_DEFAULT_REQUEST_TERMINATE_TIMEOUT" 30 3600)"
}

php_fpm_set_directive() {
  local file="$1" key="$2" value="$3" key_re
  key_re="${key//./\\.}"
  if grep -Eq "^[;[:space:]]*${key_re}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[;[:space:]]*${key_re}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >>"$file"
  fi
}

apply_php_fpm_tuning_to_pool_file() {
  local pool_file="$1"
  php_fpm_set_directive "$pool_file" "pm" "$PHP_FPM_PM_MODE"
  php_fpm_set_directive "$pool_file" "pm.max_children" "$PHP_FPM_MAX_CHILDREN"
  php_fpm_set_directive "$pool_file" "pm.process_idle_timeout" "${PHP_FPM_PROCESS_IDLE_TIMEOUT}s"
  php_fpm_set_directive "$pool_file" "pm.max_requests" "$PHP_FPM_MAX_REQUESTS"
  php_fpm_set_directive "$pool_file" "request_terminate_timeout" "${PHP_FPM_REQUEST_TERMINATE_TIMEOUT}s"
}

retune_php_fpm_pools() {
  local pool_file php_version pool_user count=0 versions=""
  shopt -s nullglob
  for pool_file in /etc/php/*/fpm/pool.d/snpanel-*.conf; do
    [[ -f "$pool_file" ]] || continue
    calculate_php_fpm_pool_tuning "$pool_file"
    apply_php_fpm_tuning_to_pool_file "$pool_file"
    pool_user="$(awk -F= '/^[[:space:]]*user[[:space:]]*=/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }' "$pool_file")"
    if [[ -n "$pool_user" ]]; then
      ensure_php_runtime_dirs "$pool_user"
      usermod -aG "$pool_user" "$WEB_USER" 2>/dev/null || true
    fi
    count=$((count + 1))
    php_version="$(echo "$pool_file" | awk -F/ '{print $4}')"
    case " $versions " in
      *" $php_version "*) ;;
      *) versions="${versions} ${php_version}" ;;
    esac
  done
  shopt -u nullglob
  for php_version in $versions; do
    systemctl reload "php${php_version}-fpm" 2>/dev/null || true
  done
  echo "Retuned ${count} SNPanel PHP-FPM pool(s)."
}

mariadb_tuning_value() {
  local key="$1" default="$2" value=""
  if [[ -v "$key" ]]; then
    value="${!key}"
  fi
  if [[ -z "$value" ]]; then
    value="$(env_get "$key" 2>/dev/null || true)"
  fi
  printf '%s\n' "${value:-$default}"
}

mariadb_megabytes() {
  local value="${1:-}" default="$2" number unit
  if [[ "$value" =~ ^([0-9]+)([KkMmGg]?)$ ]]; then
    number="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    case "$unit" in
      [Kk]) printf '%s\n' $(((number + 1023) / 1024)) ;;
      [Gg]) printf '%s\n' $((number * 1024)) ;;
      *) printf '%s\n' "$number" ;;
    esac
    return 0
  fi
  printf '%s\n' "$default"
}

calculate_mariadb_tuning() {
  local total_mb cpu_count buffer_default buffer_mb log_file_mb tmp_mb max_connections thread_cache
  local table_open_cache open_files_limit packet_mb io_capacity
  total_mb="$(php_fpm_total_memory_mb)"
  cpu_count="$(php_fpm_cpu_count)"

  if (( total_mb <= 1024 )); then
    buffer_default=$((total_mb * 22 / 100))
    max_connections=35
    thread_cache=16
    table_open_cache=512
    tmp_mb=32
    packet_mb=64
  elif (( total_mb <= 2048 )); then
    buffer_default=$((total_mb * 25 / 100))
    max_connections=50
    thread_cache=24
    table_open_cache=512
    tmp_mb=48
    packet_mb=64
  elif (( total_mb <= 4096 )); then
    buffer_default=$((total_mb * 28 / 100))
    max_connections=80
    thread_cache=32
    table_open_cache=1024
    tmp_mb=64
    packet_mb=96
  elif (( total_mb <= 8192 )); then
    buffer_default=$((total_mb * 32 / 100))
    max_connections=120
    thread_cache=48
    table_open_cache=1024
    tmp_mb=96
    packet_mb=128
  else
    buffer_default=$((total_mb * 36 / 100))
    max_connections=180
    thread_cache=64
    table_open_cache=2048
    tmp_mb=128
    packet_mb=128
  fi

  (( buffer_default >= 128 )) || buffer_default=128
  (( buffer_default <= total_mb * 45 / 100 )) || buffer_default=$((total_mb * 45 / 100))
  buffer_mb="$(mariadb_megabytes "$(mariadb_tuning_value SNPANEL_MARIADB_BUFFER_POOL_SIZE "${buffer_default}M")" "$buffer_default")"
  buffer_mb="$(positive_int_or_default "$buffer_mb" "$buffer_default" 128 "$((total_mb * 60 / 100))")"

  max_connections="$(positive_int_or_default "$(mariadb_tuning_value SNPANEL_MARIADB_MAX_CONNECTIONS "$max_connections")" "$max_connections" 20 1000)"
  thread_cache="$(positive_int_or_default "$(mariadb_tuning_value SNPANEL_MARIADB_THREAD_CACHE_SIZE "$thread_cache")" "$thread_cache" 8 256)"
  table_open_cache="$(positive_int_or_default "$(mariadb_tuning_value SNPANEL_MARIADB_TABLE_OPEN_CACHE "$table_open_cache")" "$table_open_cache" 256 65535)"
  tmp_mb="$(mariadb_megabytes "$(mariadb_tuning_value SNPANEL_MARIADB_TMP_TABLE_SIZE "${tmp_mb}M")" "$tmp_mb")"
  tmp_mb="$(positive_int_or_default "$tmp_mb" 64 16 512)"
  packet_mb="$(mariadb_megabytes "$(mariadb_tuning_value SNPANEL_MARIADB_MAX_ALLOWED_PACKET "${packet_mb}M")" "$packet_mb")"
  packet_mb="$(positive_int_or_default "$packet_mb" 64 16 512)"
  log_file_mb=$((buffer_mb / 4))
  log_file_mb="$(positive_int_or_default "$(mariadb_megabytes "$(mariadb_tuning_value SNPANEL_MARIADB_LOG_FILE_SIZE "${log_file_mb}M")" "$log_file_mb")" "$log_file_mb" 64 1024)"
  io_capacity=$((cpu_count * 200))
  io_capacity="$(positive_int_or_default "$(mariadb_tuning_value SNPANEL_MARIADB_IO_CAPACITY "$io_capacity")" "$io_capacity" 200 4000)"
  open_files_limit=$((table_open_cache * 2 + max_connections + 512))
  open_files_limit="$(positive_int_or_default "$(mariadb_tuning_value SNPANEL_MARIADB_OPEN_FILES_LIMIT "$open_files_limit")" "$open_files_limit" 2048 200000)"

  MARIADB_INNODB_BUFFER_POOL_SIZE="${buffer_mb}M"
  MARIADB_INNODB_LOG_FILE_SIZE="${log_file_mb}M"
  MARIADB_MAX_CONNECTIONS="$max_connections"
  MARIADB_THREAD_CACHE_SIZE="$thread_cache"
  MARIADB_TABLE_OPEN_CACHE="$table_open_cache"
  MARIADB_TMP_TABLE_SIZE="${tmp_mb}M"
  MARIADB_MAX_ALLOWED_PACKET="${packet_mb}M"
  MARIADB_INNODB_IO_CAPACITY="$io_capacity"
  MARIADB_OPEN_FILES_LIMIT="$open_files_limit"
}

write_mariadb_tuning() {
  calculate_mariadb_tuning
  install -d -o root -g root -m 0755 "$(dirname "$MARIADB_TUNING_CONF")"
  cat >"$MARIADB_TUNING_CONF" <<MYSQL
# SNPanel auto-tunes MariaDB for small and medium VPS plans.
# Optional overrides in ${ENV_FILE}: SNPANEL_MARIADB_BUFFER_POOL_SIZE,
# SNPANEL_MARIADB_MAX_CONNECTIONS, SNPANEL_MARIADB_THREAD_CACHE_SIZE,
# SNPANEL_MARIADB_TABLE_OPEN_CACHE, SNPANEL_MARIADB_TMP_TABLE_SIZE,
# SNPANEL_MARIADB_MAX_ALLOWED_PACKET, SNPANEL_MARIADB_LOG_FILE_SIZE,
# SNPANEL_MARIADB_IO_CAPACITY, SNPANEL_MARIADB_OPEN_FILES_LIMIT.
[mysqld]
innodb_buffer_pool_size = ${MARIADB_INNODB_BUFFER_POOL_SIZE}
innodb_log_file_size = ${MARIADB_INNODB_LOG_FILE_SIZE}
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_io_capacity = ${MARIADB_INNODB_IO_CAPACITY}
max_connections = ${MARIADB_MAX_CONNECTIONS}
thread_cache_size = ${MARIADB_THREAD_CACHE_SIZE}
table_open_cache = ${MARIADB_TABLE_OPEN_CACHE}
tmp_table_size = ${MARIADB_TMP_TABLE_SIZE}
max_heap_table_size = ${MARIADB_TMP_TABLE_SIZE}
max_allowed_packet = ${MARIADB_MAX_ALLOWED_PACKET}
skip_name_resolve = 1
slow_query_log = 1
slow_query_log_file = /var/log/mysql/snpanel-slow.log
long_query_time = 2

[server]
open_files_limit = ${MARIADB_OPEN_FILES_LIMIT}
MYSQL
}

ensure_mariadb_slow_log() {
  local log_dir="/var/log/mysql" log_file="/var/log/mysql/snpanel-slow.log" log_group="mysql"
  getent group adm >/dev/null 2>&1 && log_group="adm"
  install -d -o mysql -g "$log_group" -m 0750 "$log_dir"
  touch "$log_file"
  chown mysql:"$log_group" "$log_file"
  chmod 0640 "$log_file"
}

retune_mariadb() {
  write_mariadb_tuning
  ensure_mariadb_slow_log
  mariadbd --help --verbose >/dev/null
  systemctl restart mariadb
  echo "Retuned MariaDB: innodb_buffer_pool_size=${MARIADB_INNODB_BUFFER_POOL_SIZE}, max_connections=${MARIADB_MAX_CONNECTIONS}, table_open_cache=${MARIADB_TABLE_OPEN_CACHE}."
}

# --- clock --------------------------------------------------------------------
# Cheap VPS hosts routinely block outbound UDP 123, so systemd-timesyncd and
# chrony never converge and the clock drifts until TOTP logins stop matching.
# When the kernel clock is not disciplined, read the time from an HTTPS Date
# header instead - it travels over the same 443 the panel already needs - and
# step the clock to it.
# See https://doc.bnix.vn/huong-dan-sua-nhanh-loi-vps-bi-sai-gio-loi-ntp/
TIME_HTTP_SOURCES=(https://time.google.com https://www.cloudflare.com https://www.google.com)
CLOCK_SKEW_THRESHOLD=2   # seconds; a smaller drift is left alone

clock_is_synchronized() {
  [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]
}

http_date_epoch() {
  # Print epoch seconds from the first reachable source's Date header.
  local url header
  for url in "$@"; do
    header="$(curl -sI --max-time 8 -H 'Cache-Control: no-cache' "$url" 2>/dev/null \
      | tr -d '\r' | awk -F': ' 'tolower($1) == "date" { print $2; exit }')"
    [[ -n "$header" ]] || continue
    date -u -d "$header" +%s 2>/dev/null && return 0
  done
  return 1
}

time_sync() {
  local before target skew
  if clock_is_synchronized; then
    echo "clock already disciplined by NTP; nothing to do"
    return 0
  fi
  target="$(http_date_epoch "${TIME_HTTP_SOURCES[@]}" || true)"
  if [[ -z "$target" ]]; then
    echo "no HTTPS time source was reachable; leaving the clock as is (the timer will retry)"
    return 0
  fi
  # Sample the local clock now, after the fetch, so curl round-trip latency
  # is not counted as skew.
  before="$(date -u +%s)"
  skew=$(( target - before ))
  if (( skew < 0 )); then skew=$(( -skew )); fi
  if (( skew < CLOCK_SKEW_THRESHOLD )); then
    echo "clock is within ${skew}s of the HTTPS time source; left as is"
    return 0
  fi
  date -u -s "@${target}" >/dev/null || deny "could not step the system clock"
  hwclock --systohc 2>/dev/null || true
  logger -t snpanel-helper -- "time-sync: stepped the clock by ${skew}s (HTTPS Date header)"
  echo "clock stepped by ${skew}s from an HTTPS Date header; now $(date -u +%FT%TZ)"
}

delete_site_php_pools() {
  local user="$1" target="$2" glob
  glob="$(site_php_pool_glob "$user" "$target")"
  for dir in /etc/php/*/fpm/pool.d; do
    [[ -d "$dir" ]] || continue
    for pool_file in "$dir"/$glob.conf; do
      [[ -f "$pool_file" ]] || continue
      rm -f "$pool_file"
      local php_version
      php_version="$(echo "$dir" | awk -F/ '{print $4}')"
      systemctl reload "php${php_version}-fpm" 2>/dev/null || true
    done
  done
}

ensure_php_pool() {
  local user="$1" target="$2" php_version="$3"
  [[ "$php_version" != "none" ]] || return 0
  require_linux_user "$user"
  require_php_version "$php_version"
  target=$(readlink -m "$target") || deny "cannot resolve $target"
  local pool_suffix="${php_version//./_}"
  local site_hash
  site_hash="$(printf '%s' "$target" | sha256sum | awk '{print substr($1, 1, 12)}')"
  local pool_name="snpanel-${user}-${site_hash}-${pool_suffix}"
  local pool_file="/etc/php/${php_version}/fpm/pool.d/${pool_name}.conf"
  # Per-user dirs for sessions/uploads. Sharing /tmp across pools lets one
  # site read another's session files (mode 0600 helps but only inside the
  # same uid; uploads land world-writable on tmpfs). Using 0700 dirs owned
  # by the pool's Linux user contains the data inside the site's trust
  # boundary.
  local sess_dir="/var/lib/php/sessions/${user}"
  local upload_dir="/var/lib/php/uploads/${user}"
  ensure_php_runtime_dirs "$user"
  calculate_php_fpm_pool_tuning "$pool_file"
  cat >"$pool_file" <<POOL
[${pool_name}]
user = ${user}
group = ${user}
listen = /run/php/${pool_name}.sock
listen.owner = ${WEB_USER}
listen.group = ${WEB_GROUP}
listen.mode = 0660
; SNPanel auto-tunes these values from RAM, CPU and managed pool count.
; Optional overrides: SNPANEL_PHP_FPM_WORKER_MB, SNPANEL_PHP_FPM_MAX_CHILDREN,
; SNPANEL_PHP_FPM_IDLE_TIMEOUT, SNPANEL_PHP_FPM_MAX_REQUESTS,
; SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT.
pm = ${PHP_FPM_PM_MODE}
pm.max_children = ${PHP_FPM_MAX_CHILDREN}
pm.process_idle_timeout = ${PHP_FPM_PROCESS_IDLE_TIMEOUT}s
pm.max_requests = ${PHP_FPM_MAX_REQUESTS}
request_terminate_timeout = ${PHP_FPM_REQUEST_TERMINATE_TIMEOUT}s
chdir = /
php_admin_value[open_basedir] = ${target}:${sess_dir}:${upload_dir}:/usr/share/php
php_admin_value[upload_tmp_dir] = ${upload_dir}
php_admin_value[session.save_path] = ${sess_dir}
POOL
  systemctl reload "php${php_version}-fpm"
}

ensure_php_runtime_dirs() {
  local user="$1"
  local sess_dir="/var/lib/php/sessions/${user}"
  local upload_dir="/var/lib/php/uploads/${user}"
  ensure_sites_group
  require_linux_user "$user"
  install -d -o "$user" -g "$user" -m 0700 "$sess_dir"
  # PHP keeps uploaded files in this directory before WordPress renames them
  # into wp-content/uploads. Keep the directory private to the site user, but
  # make it setgid snpanel-sites so moved uploads remain readable by nginx.
  install -d -o "$user" -g "$SNPANEL_SITES_GROUP" -m 2700 "$upload_dir"
  chmod g+s "$upload_dir" 2>/dev/null || true
}

fix_site_tree() {
  local target="$1" user="$2"
  ensure_sites_group
  require_linux_user "$user"
  chown -R "$user:$SNPANEL_SITES_GROUP" "$target"
  if [[ -d "$target" ]]; then
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -Rb "$target" 2>/dev/null || true
      find "$target" -type d -exec setfacl -k {} + 2>/dev/null || true
    fi
    find "$target" -type d -exec chmod 755 {} +
    find "$target" -type d -exec chmod a-s {} + 2>/dev/null || true
    find "$target" -type d -exec chmod -t {} + 2>/dev/null || true
    find "$target" -type f -exec chmod 644 {} +
    protect_site_secret_tree "$target"
  else
    harden_site_file "$target" "$user"
  fi
}

require_ip_or_cidr() {
  [[ "$1" =~ ^[0-9a-fA-F.:/]+$ ]] || deny "invalid IP/CIDR: $1"
}

# Validate and canonicalise an address/network before it reaches ipset. The
# value ends up in an `ipset restore` script, so nothing but a normalised
# network is ever allowed through.
require_ip_or_cidr_normalized() {
  local value="$1" normalized
  require_ip_or_cidr "$value"
  normalized="$(python3 - "$value" <<'PY' 2>/dev/null || true
import ipaddress
import sys

try:
    print(ipaddress.ip_network(sys.argv[1], strict=False))
except ValueError:
    sys.exit(1)
PY
)"
  [[ -n "$normalized" ]] || deny "invalid IP/CIDR: $value"
  [[ "$normalized" =~ ^[0-9a-fA-F.:]+/[0-9]{1,3}$ ]] || deny "invalid IP/CIDR: $value"
  printf '%s' "$normalized"
}

cmd="${1:-}"
shift || true
audit_log "$@"

case "$cmd" in

  # ---- systemctl --------------------------------------------------------
  systemctl)
    [[ $# -ge 2 ]] || deny "usage: systemctl <service> <action>"
    service="$1"; action="$2"
    is_allowed_service "$service" || deny "service not allowed: $service"
    is_in "$action" "${ALLOWED_ACTIONS[@]}" || deny "action not allowed: $action"
    if [[ "$action" == "stop" && ( "$service" == "snpanel-api" || "$service" == "redis-server" ) ]]; then
      deny "refusing to stop panel-critical service: $service"
    fi
    exec systemctl "$action" "$service"
    ;;

  daemon-reload)
    exec systemctl daemon-reload
    ;;

  # ---- nginx ------------------------------------------------------------
  nginx-test)
    exec nginx -t
    ;;

  nginx-reload)
    nginx -t
    exec systemctl reload nginx
    ;;
  nginx-custom-write)
    [[ $# -eq 1 ]] || deny "usage: nginx-custom-write <domain>"
    domain="$1"
    require_domain "$domain"
    ensure_nginx_conf_dir_writable
    target="${NGINX_CUSTOM_DIR}/${domain}.conf"
    tmp="${target}.tmp.$$"
    cat >"$tmp"
    if file_has_nul "$tmp"; then
      rm -f "$tmp"
      deny "custom nginx include contains NUL byte"
    fi
    install -m 0664 -o root -g snpanel "$tmp" "$target"
    rm -f "$tmp"
    ;;
  nginx-custom-delete)
    [[ $# -eq 1 ]] || deny "usage: nginx-custom-delete <domain>"
    domain="$1"
    require_domain "$domain"
    rm -f "${NGINX_CUSTOM_DIR}/${domain}.conf"
    ;;

  fastcgi-cache-clear)
    [[ $# -eq 0 ]] || deny "usage: fastcgi-cache-clear"
    install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0755 /var/cache/nginx/snpanel-fastcgi
    find /var/cache/nginx/snpanel-fastcgi -mindepth 1 -delete
    ;;

  # ---- updates ----------------------------------------------------------
  updates-status)
    echo "SNPanel release status:"
    if [[ -f "${SNPANEL_DATA_DIR}/update-status.json" ]]; then
      cat "${SNPANEL_DATA_DIR}/update-status.json"
    else
      echo "No update status file found."
    fi
    echo ""
    echo "APT upgradable packages:"
    apt list --upgradable 2>/dev/null | sed -n '1,60p' || true
    echo ""
    echo "Unattended upgrades:"
    systemctl is-enabled unattended-upgrades.service 2>/dev/null || true
    systemctl is-active unattended-upgrades.service 2>/dev/null || true
    echo ""
    echo "OS update service:"
    systemctl is-active snpanel-os-update.service 2>/dev/null | sed 's/^inactive$/idle/' || true
    journalctl -u snpanel-os-update.service -n 16 --no-pager 2>/dev/null | grep -v "Failed to open /run/systemd/transient" || true
    echo ""
    echo "Panel update service:"
    systemctl is-active snpanel-panel-update.service 2>/dev/null | sed 's/^inactive$/idle/' || true
    journalctl -u snpanel-panel-update.service -n 16 --no-pager 2>/dev/null | grep -v "Failed to open /run/systemd/transient" || true
    echo ""
    echo "Panel update log:"
    if command -v journalctl >/dev/null 2>&1 && systemctl cat snpanel-panel-update.service >/dev/null 2>&1; then
      journalctl -u snpanel-panel-update.service -n 60 --no-pager 2>/dev/null | grep -v "Failed to open /run/systemd/transient" || true
    fi
    if [[ ! -s /dev/stdin ]]; then :; fi
    if [[ -f /var/log/snpanel-panel-update.log ]]; then
      echo "--- /var/log/snpanel-panel-update.log (tail) ---"
      tail -n 60 /var/log/snpanel-panel-update.log 2>/dev/null || true
    fi
    ;;

  updates-os-run)
    run_os_update
    ;;

  updates-os-auto)
    [[ $# -eq 3 ]] || deny "usage: updates-os-auto <on|off> <security|all> <on|off>"
    configure_unattended_upgrades "$1" "$2" "$3"
    ;;

  updates-panel-run)
    run_panel_update
    ;;

  # ---- WAF --------------------------------------------------------------
  waf-status)
    waf_status
    ;;

  waf-install)
    install_waf_engine
    ;;

  # ---- ClamAV malware scanning (optional) -------------------------------
  clamav-install)
    install_clamav_engine
    ;;

  clamav-status)
    if command -v clamd >/dev/null 2>&1 || command -v clamscan >/dev/null 2>&1; then
      installed=1
    else
      installed=0
    fi
    if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
      running=1
    else
      running=0
    fi
    echo "installed=${installed} running=${running}"
    ;;

  clamav-start)
    install -d -o clamav -g clamav -m 0755 /run/clamav 2>/dev/null || true
    systemctl enable --now clamav-daemon
    echo "clamav-daemon started"
    ;;

  clamav-stop)
    systemctl disable --now clamav-daemon 2>/dev/null || systemctl stop clamav-daemon
    echo "clamav-daemon stopped"
    ;;

  # ---- Linux Malware Detect (LMD) --------------------------------------
  maldet-install)
    [[ $# -eq 0 ]] || deny "usage: maldet-install"
    install_maldet_engine
    ;;

  maldet-status)
    if [[ -x "$MALDET_BIN" ]]; then echo "installed=1"; else echo "installed=0"; fi
    if maldet_monitor_running; then echo "monitor=1"; else echo "monitor=0"; fi
    maldet_sig_file="${MALDET_HOME}/sigs/maldet.sigs.ver"
    if [[ -f "$maldet_sig_file" ]]; then
      echo "sig_version=$(cat "$maldet_sig_file" 2>/dev/null || echo unknown)"
      echo "sig_updated=$(date -u -r "$maldet_sig_file" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo '')"
    else
      echo "sig_version=unknown"
      echo "sig_updated="
    fi
    ;;

  maldet-update-sigs)
    [[ $# -eq 0 ]] || deny "usage: maldet-update-sigs"
    [[ -x "$MALDET_BIN" ]] || deny "maldet is not installed"
    "$MALDET_BIN" -u --force 2>&1 || true
    freshclam >/dev/null 2>&1 || true
    echo "signatures updated"
    ;;

  maldet-scan)
    # maldet-scan <job-id> <all|recent> <days> <path>...
    [[ $# -ge 4 ]] || deny "usage: maldet-scan <job-id> <all|recent> <days> <path>..."
    run_maldet_scan "$@"
    ;;

  maldet-report)
    [[ $# -eq 1 ]] || deny "usage: maldet-report <scanid>"
    [[ "$1" =~ ^[0-9]{6}-[0-9]{4}\.[0-9]+$ ]] || deny "invalid scanid"
    [[ -x "$MALDET_BIN" ]] || deny "maldet is not installed"
    [[ -f "${MALDET_HOME}/sess/session.${1}" ]] && cat "${MALDET_HOME}/sess/session.${1}" || true
    ;;

  maldet-monitor)
    [[ $# -eq 1 ]] || deny "usage: maldet-monitor <start|stop|status>"
    [[ -x "$MALDET_BIN" ]] || deny "maldet is not installed"
    case "$1" in
      start)
        # LMD's monitor mode shells out to both of these. It exits 0 when one
        # is missing, so systemd reports a bare protocol failure and the real
        # reason never surfaces - hence installing them here rather than
        # letting the start fail and guessing afterwards. `ed` is absent from
        # a minimal Debian.
        for _dep in "inotifywait:inotify-tools" "ed:ed"; do
          _cmd="${_dep%%:*}"; _pkg="${_dep##*:}"
          command -v "$_cmd" >/dev/null 2>&1 && continue
          pkg_install "$_pkg" >/dev/null 2>&1 || true
          command -v "$_cmd" >/dev/null 2>&1 || \
            deny "real-time protection needs ${_cmd} (package ${_pkg}), which could not be installed"
        done
        write_inotify_sysctl
        grep -qE '^default_monitor_mode=' "$MALDET_CONF" 2>/dev/null || printf 'default_monitor_mode="users"\n' >>"$MALDET_CONF"
        # Run the monitor through maldet.service: its children stay in the unit's
        # cgroup, so `systemctl stop` cleans them all up. A bare `maldet -b -m`
        # daemonises outside systemd and orphans its inotifywait.
        systemctl enable maldet >/dev/null 2>&1 || true
        systemctl restart maldet >/dev/null 2>&1 || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
          maldet_monitor_running && break
          sleep 1
        done
        if maldet_monitor_running; then
          echo "monitor started"
        else
          # Carry maldet's own sentence out to the panel. "monitor did not
          # start" on its own sent this into a journal-reading session that
          # the administrator cannot perform from the web interface.
          _why="$(journalctl -u maldet --no-pager -n 20 2>/dev/null \
                  | sed -n 's/.*{mon} //p' | tail -n 1)"
          [[ -n "$_why" ]] && deny "monitor did not start: ${_why}" \
                           || deny "monitor did not start"
        fi
        ;;
      stop)
        systemctl disable --now maldet >/dev/null 2>&1 || true
        systemctl reset-failed maldet >/dev/null 2>&1 || true
        "$MALDET_BIN" --kill-monitor >/dev/null 2>&1 || true
        # Kill the supervisor first (it respawns inotifywait), then the watcher.
        pkill -f 'maldet .*--monitor' >/dev/null 2>&1 || true
        sleep 1
        pkill -f 'inotifywait .*maldetect/sess/inotify' >/dev/null 2>&1 || true
        sleep 1
        pkill -9 -f 'inotifywait .*maldetect/sess/inotify' >/dev/null 2>&1 || true
        rm -f "${MALDET_HOME}/tmp/inotifywait.pid" 2>/dev/null || true
        maldet_monitor_running && deny "monitor still running after stop" || echo "monitor stopped"
        ;;
      status)
        if maldet_monitor_running; then echo "running=1"; else echo "running=0"; fi
        echo "watches=$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)"
        ;;
      *) deny "usage: maldet-monitor <start|stop|status>" ;;
    esac
    ;;

  waf-update)
    write_modsec_main_conf
    nginx -t
    systemctl reload nginx
    echo "SNPanel lightweight WAF rules refreshed"
    ;;

  waf-default-rules)
    write_waf_default_rules
    exec cat /etc/nginx/modsec/snpanel-default.conf
    ;;

  waf-custom-rules)
    touch /etc/nginx/modsec/snpanel-custom.conf
    exec cat /etc/nginx/modsec/snpanel-custom.conf
    ;;

  waf-custom-save)
    save_waf_custom_rules
    ;;
  waf-site-save)
    [[ $# -eq 1 ]] || deny "usage: waf-site-save <domain>"
    save_waf_site_rules "$1"
    ;;
  waf-site-delete)
    [[ $# -eq 1 ]] || deny "usage: waf-site-delete <domain>"
    delete_waf_site_rules "$1"
    ;;
  orphans-scan)
    [[ $# -eq 0 ]] || deny "usage: orphans-scan  (live domains on stdin)"
    cleanup_orphans scan
    ;;
  orphans-clean)
    [[ $# -eq 0 ]] || deny "usage: orphans-clean  (live domains on stdin)"
    cleanup_orphans clean
    ;;
  waf-crs-install)
    [[ $# -eq 0 ]] || deny "usage: waf-crs-install"
    install_waf_crs
    ;;
  waf-crs-mode)
    [[ $# -eq 1 ]] || deny "usage: waf-crs-mode <off|detect|block>"
    set_waf_crs_mode "$1"
    ;;
  waf-crs-status)
    [[ $# -eq 0 ]] || deny "usage: waf-crs-status"
    waf_crs_status
    ;;
  http-flood-zones-save)
    [[ $# -eq 0 ]] || deny "usage: http-flood-zones-save"
    save_http_flood_zones
    ;;

  # ---- PHP installation --------------------------------------------------
  php-install)
    [[ $# -eq 1 ]] || deny "usage: php-install <version>"
    install_php_version "$1"
    ;;

  php-opcache-set)
    [[ $# -eq 2 ]] || deny "usage: php-opcache-set <php-version> <0|1>"
    write_php_opcache_switch "$1" "$2"
    ;;

  php-tune-write)
    [[ $# -eq 1 ]] || deny "usage: php-tune-write <php-version>"
    write_php_tune "$1"
    ;;

  php-pools-retune)
    # Pool sizes are decided when a pool is written. A server that gained RAM
    # keeps the old numbers until every site happens to be touched; this walks
    # them all and rewrites each one against the machine as it is now.
    [[ $# -eq 0 ]] || deny "usage: php-pools-retune"
    shopt -s nullglob
    retuned=0
    for pool_file in /etc/php/*/fpm/pool.d/snpanel-*.conf; do
      [[ -f "$pool_file" ]] || continue
      calculate_php_fpm_pool_tuning "$pool_file"
      php_fpm_set_directive "$pool_file" "pm" "$PHP_FPM_PM_MODE"
      php_fpm_set_directive "$pool_file" "pm.max_children" "$PHP_FPM_MAX_CHILDREN"
      php_fpm_set_directive "$pool_file" "pm.process_idle_timeout" "${PHP_FPM_PROCESS_IDLE_TIMEOUT}s"
      php_fpm_set_directive "$pool_file" "pm.max_requests" "$PHP_FPM_MAX_REQUESTS"
      php_fpm_set_directive "$pool_file" "request_terminate_timeout" "${PHP_FPM_REQUEST_TERMINATE_TIMEOUT}s"
      echo "$(basename "$pool_file"): pm.max_children=${PHP_FPM_MAX_CHILDREN} idle=${PHP_FPM_PROCESS_IDLE_TIMEOUT}s max_requests=${PHP_FPM_MAX_REQUESTS}"
      retuned=$((retuned + 1))
    done
    for fpm_version_dir in /etc/php/*/fpm; do
      [[ -d "$fpm_version_dir" ]] || continue
      fpm_version="$(basename "$(dirname "$fpm_version_dir")")"
      systemctl reload "php${fpm_version}-fpm" 2>/dev/null || true
    done
    shopt -u nullglob
    echo "retuned ${retuned} pool(s)"
    ;;

  php-config-write)
    [[ $# -eq 1 ]] || deny "usage: php-config-write <version>"
    write_php_config "$1"
    ;;

  php-fpm-retune)
    [[ $# -eq 0 ]] || deny "usage: php-fpm-retune"
    retune_php_fpm_pools
    ;;

  mariadb-retune)
    [[ $# -eq 0 ]] || deny "usage: mariadb-retune"
    retune_mariadb
    ;;

  time-sync)
    [[ $# -eq 0 ]] || deny "usage: time-sync"
    time_sync
    ;;

  time-status)
    [[ $# -eq 0 ]] || deny "usage: time-status"
    if clock_is_synchronized; then echo "synchronized=yes"; else echo "synchronized=no"; fi
    echo "timezone=$(timedatectl show -p Timezone --value 2>/dev/null)"
    now="$(date -u +%s)"
    ref="$(http_date_epoch "${TIME_HTTP_SOURCES[@]}" || true)"
    if [[ -n "$ref" ]]; then
      echo "skew_seconds=$(( ref - now ))"
      echo "reference=https-date"
    else
      echo "skew_seconds="
      echo "reference=none"
    fi
    ;;

  # ---- panel runtime ----------------------------------------------------
  panel-url-set)
    [[ $# -eq 3 ]] || deny "usage: panel-url-set <http|https> <host> <port>"
    scheme="$1"; host="$2"; port="$3"
    require_panel_scheme "$scheme"
    require_panel_host "$host"
    require_port "$port"
    env_set PANEL_PORT "$port"
    env_set PANEL_URL "${scheme}://${host}:${port}"
    env_set ALLOWED_ORIGINS "${scheme}://${host}:${port}"
    if is_domain "$host"; then
      env_set PANEL_DOMAIN "$host"
    else
      env_set PANEL_DOMAIN ""
    fi
    if [[ "$scheme" == "http" ]]; then
      env_set PANEL_SSL_CERT ""
      env_set PANEL_SSL_KEY ""
    fi
    allow_panel_port "$port"
    refresh_tools_nginx
    schedule_panel_restart
    echo "Panel URL: ${scheme}://${host}:${port}"
    ;;

  malware-scan-server)
    # Scan the whole machine. The panel owns the job bookkeeping; this only
    # runs the scanner and leaves its output where the panel can read it.
    [[ $# -eq 1 ]] || deny "usage: malware-scan-server <job-id>"
    run_malware_server_scan "$1"
    ;;

  ipv6-status)
    [[ $# -eq 0 ]] || deny "usage: ipv6-status"
    if ipv6_available; then
      echo "available=yes"
    else
      echo "available=no"
    fi
    if ipv6_is_enabled; then
      echo "enabled=yes"
    else
      echo "enabled=no"
    fi
    echo "addresses=$(ipv6_global_addresses | paste -sd, -)"
    ;;

  ipv6-enable)
    [[ $# -eq 0 ]] || deny "usage: ipv6-enable"
    ipv6_available || deny "this server has no global IPv6 address"
    install -d -o root -g snpanel -m 0750 /etc/snpanel
    : >"$PANEL_IPV6_MARKER"
    chmod 0644 "$PANEL_IPV6_MARKER"
    if ! nginx_ipv6_apply; then
      # nginx_ipv6_apply already put every file back the way it found it.
      rm -f "$PANEL_IPV6_MARKER"
      deny "nginx refused the IPv6 configuration; nothing was changed"
    fi
    refresh_tools_nginx
    schedule_panel_restart
    echo "IPv6 enabled: $(ipv6_global_addresses | paste -sd, -)"
    ;;

  ipv6-disable)
    [[ $# -eq 0 ]] || deny "usage: ipv6-disable"
    rm -f "$PANEL_IPV6_MARKER"
    nginx_ipv6_apply || deny "nginx refused the configuration without IPv6"
    refresh_tools_nginx
    schedule_panel_restart
    echo "IPv6 disabled"
    ;;

  ipv6-apply)
    # Re-apply the switch after an update rewrote the vhosts. No-op when off.
    [[ $# -eq 0 ]] || deny "usage: ipv6-apply"
    if ipv6_is_enabled && ! ipv6_available; then
      # The address went away with the switch left on; do not hand nginx a
      # socket it cannot bind.
      rm -f "$PANEL_IPV6_MARKER"
      nginx_ipv6_apply || deny "nginx refused the configuration without IPv6"
      echo "IPv6 is no longer available on this server; the switch was turned off"
      exit 0
    fi
    nginx_ipv6_apply || deny "nginx refused the IPv6 configuration"
    ipv6_is_enabled && echo "IPv6 applied" || echo "IPv6 is off"
    ;;

  panel-sni-sync)
    # Refresh the certificates the panel can answer a handshake with. Safe to
    # run at any time: it only copies what is already on the machine.
    [[ $# -eq 0 ]] || deny "usage: panel-sni-sync"
    install_sni_renewal_hook
    sync_panel_sni_certificates
    ;;

  panel-ssl-domains)
    # /etc/letsencrypt/live is root-only, so the panel cannot see for itself
    # which of its websites already have a certificate it could borrow.
    [[ $# -eq 0 ]] || deny "usage: panel-ssl-domains"
    for live_dir in /etc/letsencrypt/live/*/; do
      [[ -f "${live_dir}fullchain.pem" && -f "${live_dir}privkey.pem" ]] || continue
      basename "$live_dir"
    done
    ;;

  panel-ssl-selfsigned)
    # The panel should never be reachable in the clear, and a brand new server
    # has no domain and no certificate authority that will vouch for its IP.
    # A self-signed certificate warns the browser once; plain HTTP does not warn
    # anybody while it hands over the admin password.
    [[ $# -ge 1 && $# -le 2 ]] || deny "usage: panel-ssl-selfsigned <hostname-or-ip> <port>"
    host="$1"; port="${2:-2222}"
    require_port "$port"
    [[ "$host" =~ ^[A-Za-z0-9.:_-]{1,253}$ ]] || deny "invalid panel hostname: $host"
    install -d -o root -g snpanel -m 0750 /etc/snpanel
    san="DNS:${host}"
    [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && san="IP:${host}"
    server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [[ -n "$server_ip" && "$server_ip" != "$host" ]] && san="${san},IP:${server_ip}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout /etc/snpanel/panel-selfsigned-privkey.pem \
      -out /etc/snpanel/panel-selfsigned-fullchain.pem \
      -subj "/CN=${host}" -addext "subjectAltName=${san}" >/dev/null 2>&1 \
      || deny "could not generate a self-signed certificate"
    chown root:snpanel /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
    chmod 0640 /etc/snpanel/panel-selfsigned-fullchain.pem /etc/snpanel/panel-selfsigned-privkey.pem
    env_set PANEL_SSL_CERT "/etc/snpanel/panel-selfsigned-fullchain.pem"
    env_set PANEL_SSL_KEY "/etc/snpanel/panel-selfsigned-privkey.pem"
    env_set PANEL_SSL_MODE "selfsigned"
    env_set PANEL_URL "https://${host}:${port}"
    env_set ALLOWED_ORIGINS "https://${host}:${port}"
    allow_panel_port "$port"
    refresh_tools_nginx
    schedule_panel_restart
    echo "Panel is on a self-signed certificate: https://${host}:${port}"
    ;;

  panel-ssl-use-domain)
    # A domain hosted here that already has a real certificate is a better
    # answer than a self-signed one, and than asking a certificate authority
    # for a second certificate covering the same name.
    [[ $# -eq 2 ]] || deny "usage: panel-ssl-use-domain <domain> <port>"
    domain="$1"; port="$2"
    require_domain "$domain"
    require_port "$port"
    live_dir="/etc/letsencrypt/live/${domain}"
    [[ -f "${live_dir}/fullchain.pem" && -f "${live_dir}/privkey.pem" ]] \
      || deny "no certificate for ${domain}; issue SSL for that website first"
    install -d -o root -g snpanel -m 0750 /etc/snpanel
    install -m 0640 -o root -g snpanel "${live_dir}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
    install -m 0640 -o root -g snpanel "${live_dir}/privkey.pem" /etc/snpanel/panel-privkey.pem
    env_set PANEL_DOMAIN "$domain"
    env_set PANEL_SSL_CERT "/etc/snpanel/panel-fullchain.pem"
    env_set PANEL_SSL_KEY "/etc/snpanel/panel-privkey.pem"
    env_set PANEL_SSL_MODE "domain"
    env_set PANEL_URL "https://${domain}:${port}"
    env_set ALLOWED_ORIGINS "https://${domain}:${port}"
    install_panel_cert_renewal_hook
    install_sni_renewal_hook
    sync_panel_sni_certificates >/dev/null
    allow_panel_port "$port"
    refresh_tools_nginx
    schedule_panel_restart
    echo "Panel now uses the certificate of ${domain}: https://${domain}:${port}"
    ;;

  panel-ssl-install)
    [[ $# -ge 2 && $# -le 3 ]] || deny "usage: panel-ssl-install <domain> <port> [email]"
    domain="$1"; port="$2"; email="${3:-}"
    require_domain "$domain"
    require_port "$port"
    # Webroot, not standalone: standalone needs port 80 to itself, which meant
    # stopping nginx — every website on the box went down for the ten seconds
    # certbot spent talking to Let's Encrypt, to issue a certificate for the
    # panel. The default vhost serves the challenge instead.
    install -d -o root -g snpanel -m 0755 /var/www/snpanel-acme/.well-known/acme-challenge
    certbot_args=(certonly --webroot -w /var/www/snpanel-acme
      -d "$domain" \
      --agree-tos \
      --non-interactive \
      --keep-until-expiring \
      --deploy-hook "install -d -o root -g snpanel -m 0750 /etc/snpanel && install -m 0640 -o root -g snpanel /etc/letsencrypt/live/${domain}/fullchain.pem /etc/snpanel/panel-fullchain.pem && install -m 0640 -o root -g snpanel /etc/letsencrypt/live/${domain}/privkey.pem /etc/snpanel/panel-privkey.pem")
    if [[ -n "$email" ]]; then
      require_email "$email"
      certbot_args+=(--email "$email")
    else
      certbot_args+=(--register-unsafely-without-email)
    fi
    # certbot exits 1 for "certificate not yet due for renewal" even with
    # --keep-until-expiring - that is certbot telling us it did nothing, not
    # that anything is wrong. Pressing the button a second time (or reinstalling
    # the panel) hits this every time after the first real issue. The only
    # thing that actually matters is whether a usable certificate exists on
    # disk afterwards; if certbot failed and there still isn't one, that is a
    # real failure and must propagate.
    certbot "${certbot_args[@]}" || {
      rc=$?
      [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]] || exit "$rc"
    }
    install -d -o root -g snpanel -m 0750 /etc/snpanel
    install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${domain}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
    install -m 0640 -o root -g snpanel "/etc/letsencrypt/live/${domain}/privkey.pem" /etc/snpanel/panel-privkey.pem
    env_set PANEL_DOMAIN "$domain"
    env_set PANEL_PORT "$port"
    env_set PANEL_SSL_CERT "/etc/snpanel/panel-fullchain.pem"
    env_set PANEL_SSL_KEY "/etc/snpanel/panel-privkey.pem"
    env_set PANEL_SSL_MODE letsencrypt
    env_set PANEL_URL "https://${domain}:${port}"
    env_set ALLOWED_ORIGINS "https://${domain}:${port}"
    if [[ -n "$email" ]]; then
      env_set SSL_EMAIL "$email"
    fi
    allow_panel_port "$port"
    refresh_tools_nginx
    schedule_panel_restart
    echo "Panel SSL enabled: https://${domain}:${port}"
    ;;

  # ---- certbot ----------------------------------------------------------
  certbot-issue)
    [[ $# -ge 1 ]] || deny "usage: certbot-issue <domain> [alias-domain ...] [email]"
    domain="$1"; shift
    email=""
    domains=("$domain")
    require_domain "$domain"
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == *@* ]]; then
        [[ $# -eq 1 ]] || deny "email must be the final certbot-issue argument"
        email="$1"
        shift
        break
      fi
      require_domain "$1"
      domains+=("$1")
      shift
    done
    install -d -o root -g snpanel -m 0755 /var/www/snpanel-acme/.well-known/acme-challenge
    if [[ -f "/etc/nginx/conf.d/${domain}.conf" ]]; then
      if grep -q "/var/lib/snpanel/acme-challenges" "/etc/nginx/conf.d/${domain}.conf"; then
        cp -a "/etc/nginx/conf.d/${domain}.conf" "/etc/nginx/conf.d/${domain}.conf.bak"
        sed -i 's#/var/lib/snpanel/acme-challenges#/var/www/snpanel-acme#g' "/etc/nginx/conf.d/${domain}.conf"
        nginx -t && systemctl reload nginx
      elif ! grep -q "well-known/acme-challenge" "/etc/nginx/conf.d/${domain}.conf"; then
        cp -a "/etc/nginx/conf.d/${domain}.conf" "/etc/nginx/conf.d/${domain}.conf.bak"
        python3 - "$domain" <<'PY'
from pathlib import Path
import sys

domain = sys.argv[1]
path = Path(f"/etc/nginx/conf.d/{domain}.conf")
content = path.read_text(encoding="utf-8")
block = """\

    # SNPANEL ACME CHALLENGE
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }
"""
marker = "    client_max_body_size"
if marker in content:
    line_end = content.find("\n", content.find(marker))
    content = content[: line_end + 1] + block + content[line_end + 1 :]
else:
    content = content.replace("\n    location / {", block + "\n    location / {", 1)
path.write_text(content, encoding="utf-8")
PY
        nginx -t && systemctl reload nginx
      fi
    fi
    # --allow-subset-of-names: the panel now always asks for www.<domain> too
    # (nginx always listens on it) - a domain with no working www DNS record
    # must not turn a working bare-domain issuance into a total failure.
    args=(certonly --webroot -w /var/www/snpanel-acme --cert-name "$domain" --non-interactive --agree-tos --expand --keep-until-expiring --allow-subset-of-names)
    for cert_domain in "${domains[@]}"; do
      args+=(-d "$cert_domain")
    done
    if [[ -n "$email" ]]; then
      require_email "$email"
      args+=(--email "$email")
    else
      args+=(--register-unsafely-without-email)
    fi
    # certbot exits 1 for "certificate not yet due for renewal" even with
    # --keep-until-expiring, even though nothing is wrong - it just means the
    # existing certificate is still good and it changed nothing. set -e would
    # otherwise abort here, before the nginx --install step ever runs, on
    # every re-issue request (a second click on "Cai SSL", --expand adding a
    # domain to an already-fresh cert, a panel reinstall). Only a call that
    # leaves no usable certificate on disk is a real failure.
    certbot "${args[@]}" || {
      rc=$?
      [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]] || exit "$rc"
    }
    # install --nginx is only ever pointed at the primary domain, never the
    # aliases/redirects. render_vhost() always puts both "$domain" and
    # "www.$domain" in the SAME server block's server_name line (see
    # nginx._server_names), so certbot's nginx plugin matching on "$domain"
    # already wires up www too - no need to ask for it separately. Asking for
    # a redirect-domain alias here is what broke: it has no server block of
    # its own (that is SNPanel's own job - see _append_certbot_redirect_vhosts,
    # which reuses this same certificate file once the panel re-renders the
    # vhost), so certbot's nginx plugin fell back to the first server block
    # it could find - the default_server tools vhost - and cloned it under
    # the alias's name, serving the wrong certificate and exposing whatever
    # that vhost has (phpMyAdmin) under an unrelated domain. Reproduced live,
    # twice: once for a redirect domain with no DNS here at all, and again
    # for one whose DNS was fixed and made it into the certificate - the
    # missing server block, not a missing SAN, was the actual cause both times.
    install_args=(install --nginx --cert-name "$domain" --non-interactive --redirect --expand -d "$domain")
    rc=0
    certbot "${install_args[@]}" || rc=$?
    # The panel can be opened on this domain now, so it needs the certificate.
    install_sni_renewal_hook
    sync_panel_sni_certificates >/dev/null
    exit "$rc"
    ;;

  certbot-renew)
    # certbot spreads scheduled renewals over up to eight minutes so every
    # server on earth does not call Let's Encrypt at midnight. That is right for
    # the timer and wrong here: somebody pressed a button and is watching.
    exec certbot renew --quiet --no-random-sleep-on-renew
    ;;
  certbot-renew-soon)
    [[ $# -le 1 ]] || deny "usage: certbot-renew-soon [days]"
    renew_ssl_soon "${1:-10}"
    ;;
  certbot-auto-renew-install)
    write_ssl_auto_renew_timer
    echo "SSL auto-renew timer installed"
    ;;
  manual-ssl-install)
    [[ $# -eq 1 ]] || deny "usage: manual-ssl-install <domain>"
    install_manual_ssl "$1"
    sync_panel_sni_certificates >/dev/null
    ;;
  manual-ssl-remove)
    [[ $# -eq 1 ]] || deny "usage: manual-ssl-remove <domain>"
    remove_manual_ssl "$1"
    sync_panel_sni_certificates >/dev/null
    ;;
  certbot-delete)
    [[ $# -eq 1 ]] || deny "usage: certbot-delete <domain>"
    delete_ssl_cert "$1"
    ;;
  certbot-dns-cloudflare-install)
    [[ $# -eq 0 ]] || deny "usage: certbot-dns-cloudflare-install"
    install_certbot_dns_cloudflare
    ;;
  cloudflare-ssl-issue)
    [[ $# -ge 1 && $# -le 2 ]] || deny "usage: cloudflare-ssl-issue <zone> [email]"
    cloudflare_ssl_issue "$1" "${2:-}"
    ;;
  ssl-cert-info)
    [[ $# -eq 1 ]] || deny "usage: ssl-cert-info <cert-name>"
    ssl_cert_info "$1"
    ;;

  # ---- firewall (iptables + ipset) ---------------------------------------
  # The ufw-* / nginx-blocklist-* names are kept as aliases so an API process
  # that has not been restarted yet keeps working during an update.
  firewall-status|ufw-status)
    firewall_status
    ;;
  firewall-list|ufw-list)
    firewall_list_json
    ;;
  firewall-enable|ufw-enable)
    firewall_set_state enabled
    firewall_apply
    ;;
  firewall-disable|ufw-disable)
    firewall_set_state disabled
    firewall_apply
    ;;
  firewall-reload|ufw-reload)
    firewall_apply
    ;;
  firewall-apply)
    firewall_apply
    ;;
  firewall-flush)
    firewall_flush
    ;;
  firewall-migrate)
    firewall_migrate
    ;;
  firewall-allow-port|ufw-allow-port)
    [[ $# -ge 1 && $# -le 2 ]] || deny "usage: firewall-allow-port <port> [proto]"
    firewall_add_rule allow "" "$1" "${2:-tcp}"
    ;;
  firewall-panel-allow-port|ufw-panel-allow-port)
    [[ $# -eq 1 ]] || deny "usage: firewall-panel-allow-port <port>"
    allow_panel_port "$1"
    echo "Panel port ${1} is open"
    ;;
  firewall-allow-ip|ufw-allow-ip)
    [[ $# -ge 1 && $# -le 3 ]] || deny "usage: firewall-allow-ip <ip> [port] [proto]"
    firewall_add_rule allow "$1" "${2:-}" "${3:-tcp}"
    ;;
  firewall-deny-ip|ufw-deny-ip)
    [[ $# -ge 1 && $# -le 3 ]] || deny "usage: firewall-deny-ip <ip> [port] [proto]"
    firewall_add_rule deny "$1" "${2:-}" "${3:-tcp}"
    ;;
  firewall-delete|ufw-delete)
    [[ $# -eq 1 && "$1" =~ ^[0-9]+$ ]] || deny "usage: firewall-delete <rule-id>"
    firewall_delete_rule "$1"
    ;;
  firewall-blocklist-status|nginx-blocklist-status|ufw-blocklist-status)
    firewall_blocklist_status
    ;;
  firewall-blocklist-timer-install|nginx-blocklist-timer-install|ufw-blocklist-timer-install)
    firewall_blocklist_write_timer
    echo "IP blocklist timer installed"
    ;;
  firewall-blocklist-add|nginx-blocklist-add|ufw-blocklist-add)
    [[ $# -eq 1 ]] || deny "usage: firewall-blocklist-add <url>"
    firewall_blocklist_add_url "$1"
    ;;
  firewall-blocklist-delete|nginx-blocklist-delete|ufw-blocklist-delete)
    [[ $# -eq 1 ]] || deny "usage: firewall-blocklist-delete <url>"
    firewall_blocklist_delete_url "$1"
    ;;
  firewall-blocklist-run|nginx-blocklist-run|ufw-blocklist-run)
    [[ $# -eq 0 ]] || deny "usage: firewall-blocklist-run"
    firewall_blocklist_run
    ;;

  # ---- filesystem -------------------------------------------------------
  fix-permissions)
    [[ $# -ge 1 && $# -le 2 ]] || deny "usage: fix-permissions <path> [site-user]"
    target=$(require_managed_path "$1" "${2:-}")
    if [[ $# -eq 2 ]]; then
      fix_site_tree "$target" "$2"
      exit 0
    fi
    chown -R "${WEB_USER}:${WEB_GROUP}" "$target"
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -Rb "$target" 2>/dev/null || true
      find "$target" -type d -exec setfacl -k {} + 2>/dev/null || true
    fi
    find "$target" -type d -exec chmod 755 {} +
    find "$target" -type d -exec chmod a-s {} + 2>/dev/null || true
    find "$target" -type d -exec chmod -t {} + 2>/dev/null || true
    find "$target" -type f -exec chmod 644 {} +
    protect_site_secret_tree "$target"
    ;;

  site-path-fix)
    [[ $# -eq 2 ]] || deny "usage: site-path-fix <path> <site-user>"
    target=$(require_managed_path "$1" "$2")
    fix_site_tree "$target" "$2"
    ;;

  site-chmod)
    # Apply an explicit mode to one entry inside a managed site tree.
    # Runs as root on purpose: the site user is not a member of the site group,
    # so a chmod performed as that user has its setgid bit cleared by the
    # kernel, which would silently break group inheritance on site folders.
    [[ $# -eq 4 ]] || deny "usage: site-chmod <site-user> <site-root> <absolute-path> <mode>"
    user="$1"; root_arg="$2"; path_arg="$3"; mode_arg="$4"
    require_linux_user "$user"
    # Five digits is the fully explicit form the panel sends, so chmod applies
    # the special digit on directories instead of preserving the existing one.
    [[ "$mode_arg" =~ ^[0-7]{3,5}$ ]] || deny "invalid mode: $mode_arg"
    target=$(require_bound_managed_path "$user" "$root_arg" "$path_arg")
    [[ -L "$target" ]] && deny "refusing to chmod a symlink: $target"
    [[ -e "$target" ]] || deny "path not found: $target"
    [[ "$(stat -c '%U' "$target")" == "$user" ]] || deny "path is not owned by $user: $target"
    chmod "$mode_arg" -- "$target"
    ;;

  site-document-root-ensure)
    [[ $# -eq 3 ]] || deny "usage: site-document-root-ensure <site-user> <site-root> <relative-path>"
    user="$1"; root_arg="$2"; rel_arg="$3"
    ensure_sites_group
    require_linux_user "$user"
    root_target=$(require_managed_path "$root_arg" "$user")
    [[ "$rel_arg" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || deny "unsafe relative path: $rel_arg"
    case "$rel_arg" in
      ""|"/"|/*|*$'\n'*|"."|".."|"./"*|"../"*|*"/."|*"/.."|*"/./"*|*"/../"*) deny "unsafe relative path: $rel_arg" ;;
    esac
    target=$(require_safe_path "$root_target" "$root_target/$rel_arg")
    mkdir -p -- "$target"
    harden_site_dir_path "$root_target" "$target" "$user"
    ;;

  site-file-write)
    [[ $# -eq 3 || $# -eq 4 ]] || deny "usage: site-file-write <site-user> <site-root> <relative-path> [0644|0640]"
    user="$1"; root_arg="$2"; rel_arg="$3"; mode_arg="${4:-0644}"
    require_linux_user "$user"
    [[ "$mode_arg" == "0644" || "$mode_arg" == "0640" ]] || deny "invalid file mode: $mode_arg"
    root_target=$(require_managed_path "$root_arg" "$user")
    case "$rel_arg" in
      ""|"/"|/*|*$'\n'*|".."|"../"*|*"/.."|*"/../"*) deny "unsafe relative path: $rel_arg" ;;
    esac
    target=$(require_safe_path "$root_target" "$root_target/$rel_arg")
    [[ -d "$target" ]] && deny "cannot write a directory: $target"
    [[ -L "$target" ]] && deny "refusing to write through a symlink: $target"
    parent=$(dirname -- "$target")
    runuser -u "$user" -- mkdir -p -- "$parent"
    harden_site_dir_path "$root_target" "$parent" "$user"
    existing_mode=""
    if [[ -e "$target" ]]; then
      existing_mode=$(stat -c '%a' -- "$target")
    fi
    base=$(basename -- "$target")
    tmp="$parent/.${base}.snpanel-write-$$"
    rm -f -- "$tmp"
    cat >"$tmp"
    chown "$user:$SNPANEL_SITES_GROUP" "$tmp"
    chmod "$mode_arg" "$tmp"
    mv -f -- "$tmp" "$target"
    ;;

  site-file-install)
    [[ $# -eq 4 ]] || deny "usage: site-file-install <site-user> <site-root> <relative-path> <staged-path>"
    user="$1"; root_arg="$2"; rel_arg="$3"; staged_arg="$4"
    require_linux_user "$user"
    root_target=$(require_managed_path "$root_arg" "$user")
    case "$rel_arg" in
      ""|"/"|/*|*$'\n'*|".."|"../"*|*"/.."|*"/../"*) deny "unsafe relative path: $rel_arg" ;;
    esac
    target=$(require_safe_path "$root_target" "$root_target/$rel_arg")
    [[ ! -L "$target" ]] || deny "refusing to write through a symlink: $target"
    [[ "$staged_arg" == /tmp/snpanel-upload-* ]] || deny "invalid staged upload path"
    [[ ! -L "$staged_arg" ]] || deny "staged upload cannot be a symlink"
    staged=$(readlink -e -- "$staged_arg") || deny "staged upload not found"
    [[ "$staged" == /tmp/snpanel-upload-* && -f "$staged" ]] || deny "invalid staged upload"
    [[ "$(stat -c '%U' -- "$staged")" == "snpanel" ]] || deny "staged upload must be owned by snpanel"
    parent=$(dirname -- "$target")
    runuser -u "$user" -- mkdir -p -- "$parent"
    harden_site_dir_path "$root_target" "$parent" "$user"
    base=$(basename -- "$target")
    tmp="$parent/.${base}.snpanel-install-$$"
    rm -f -- "$tmp"
    install -o "$user" -g "$SNPANEL_SITES_GROUP" -m 0644 -- "$staged" "$tmp"
    mv -f -- "$tmp" "$target"
    rm -f -- "$staged"
    ;;

  site-populate)
    # Replace a managed site's tree from a panel-staged copy, as root, because
    # the site directory belongs to its Linux user and the panel process
    # (snpanel) cannot write into it. Used by the DirectAdmin importer and the
    # full-user restore. The staged tree lives under the panel-owned import
    # staging area; symlinks and device nodes are dropped so a crafted backup
    # cannot smuggle one into the served tree.
    [[ $# -eq 3 ]] || deny "usage: site-populate <site-user> <site-root> <staged-source-dir>"
    user="$1"; root_arg="$2"; src_arg="$3"
    require_linux_user "$user"
    root_target=$(require_managed_path "$root_arg" "$user")
    case "$src_arg" in
      /var/lib/snpanel/import-stage/*|/var/lib/snpanel/da-import/*) : ;;
      *) deny "staged source must be under /var/lib/snpanel/import-stage" ;;
    esac
    [[ ! -L "$src_arg" ]] || deny "staged source cannot be a symlink"
    src=$(readlink -e -- "$src_arg") || deny "staged source not found"
    case "$src/" in
      /var/lib/snpanel/import-stage/*/|/var/lib/snpanel/da-import/*/) : ;;
      *) deny "staged source escaped the import staging area" ;;
    esac
    [[ -d "$src" ]] || deny "staged source is not a directory"
    [[ "$(stat -c '%U' -- "$src")" == "snpanel" ]] || deny "staged source must be owned by snpanel"
    runuser -u "$user" -- mkdir -p -- "$root_target"
    find "$root_target" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    cp -a --no-preserve=ownership -- "$src/." "$root_target/"
    find "$root_target" \( -type l -o -type b -o -type c -o -type p -o -type s \) -delete 2>/dev/null || true
    mkdir -p -- "$root_target/public_html"
    fix_site_tree "$root_target" "$user"
    ;;

  site-archive-extract)
    [[ $# -eq 7 ]] || deny "usage: site-archive-extract <site-user> <site-root> <archive-path> <destination-path> <zip|tar.gz> <max-items> <max-bytes>"
    user="$1"; root_arg="$2"; archive_rel="$3"; destination_rel="$4"; archive_kind="$5"
    max_items="$6"; max_bytes="$7"
    require_linux_user "$user"
    [[ "$archive_kind" == "zip" || "$archive_kind" == "tar.gz" ]] || deny "unsupported archive type"
    [[ "$max_items" =~ ^[0-9]+$ && "$max_bytes" =~ ^[0-9]+$ ]] || deny "invalid archive limits"
    root_target=$(require_managed_path "$root_arg" "$user")
    archive_target=$(require_safe_path "$root_target" "$root_target/$archive_rel")
    destination_target=$(require_safe_path "$root_target" "$root_target/$destination_rel")
    [[ -f "$archive_target" && ! -L "$archive_target" ]] || deny "archive not found"
    [[ -d "$destination_target" && ! -L "$destination_target" ]] || deny "archive destination not found"
    tmp_archive=$(mktemp "/tmp/snpanel-extract-XXXXXX")
    trap 'rm -f -- "$tmp_archive"' EXIT
    install -o "$user" -g "$user" -m 0600 -- "$archive_target" "$tmp_archive"
    runuser -u "$user" -- python3 - "$tmp_archive" "$archive_kind" "$destination_target" "$max_items" "$max_bytes" "$archive_target" <<'PY'
import os
import shutil
import stat
import sys
import tarfile
import zipfile

archive_path, archive_kind, destination = sys.argv[1:4]
max_items, max_bytes = int(sys.argv[4]), int(sys.argv[5])
source_archive = os.path.realpath(sys.argv[6])
destination = os.path.realpath(destination)


def safe_target(name):
    """Normalize backslash paths and resolve to a safe absolute path."""
    if "\x00" in name:
        raise ValueError("archive contains an unsafe path")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized.split("/", 1)[0]:
        raise ValueError("archive contains an absolute path")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("archive contains an unsafe path")
    target = os.path.abspath(os.path.join(destination, *parts))
    resolved = os.path.realpath(target)
    if os.path.commonpath((destination, resolved)) != destination:
        raise ValueError("archive path escapes destination")
    return target, resolved


def zip_implied_dirs(infos):
    implied = set()
    for info in infos:
        parts = [part for part in info.filename.replace("\\", "/").split("/") if part not in ("", ".")]
        for index in range(1, len(parts)):
            implied.add("/".join(parts[:index]))
    return implied


def _is_dir_entry(info, implied_dirs):
    """Return True if a ZipInfo represents a directory."""
    normalized = info.filename.replace("\\", "/")
    if info.is_dir() or normalized.endswith("/"):
        return True
    mode = (info.external_attr >> 16) & 0o170000
    if stat.S_ISDIR(mode) and info.file_size == 0:
        return True
    if info.file_size == 0 and normalized.rstrip("/") in implied_dirs:
        return True
    return False


def is_source_archive(resolved):
    return resolved == source_archive


def ensure_regular_target(target):
    if os.path.islink(target):
        raise ValueError("refusing to overwrite a symlink")
    if os.path.isdir(target):
        raise ValueError("archive file conflicts with an existing directory")


def ensure_directory_target(target):
    if os.path.islink(target):
        raise ValueError("refusing to overwrite a symlink")
    if os.path.exists(target) and not os.path.isdir(target):
        try:
            if os.path.getsize(target) == 0:
                return
        except OSError:
            pass
        raise ValueError("archive directory conflicts with an existing file")


def validate_zip():
    count = 0
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        implied_dirs = zip_implied_dirs(infos)
        for info in infos:
            count += 1
            if max_items and count > max_items:
                raise ValueError("archive has too many files")
            target, resolved = safe_target(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if stat.S_ISLNK(mode):
                raise ValueError("archive symlinks are not allowed")
            if is_source_archive(resolved):
                continue
            if _is_dir_entry(info, implied_dirs):
                ensure_directory_target(target)
                continue
            ensure_regular_target(target)
            total += info.file_size
            if max_bytes and total > max_bytes:
                raise ValueError("archive is too large")


def extract_zip():
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        implied_dirs = zip_implied_dirs(infos)
        for info in infos:
            target, resolved = safe_target(info.filename)
            if is_source_archive(resolved):
                continue
            if _is_dir_entry(info, implied_dirs):
                if os.path.exists(target) and not os.path.isdir(target):
                    os.unlink(target)
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            try:
                with archive.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            except RuntimeError as exc:
                raise ValueError("archive entry cannot be extracted") from exc


def validate_tar():
    count = 0
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            count += 1
            if max_items and count > max_items:
                raise ValueError("archive has too many files")
            target, resolved = safe_target(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive links and devices are not allowed")
            if is_source_archive(resolved):
                continue
            if not member.isdir() and not member.isfile():
                raise ValueError("archive contains unsupported entries")
            if member.isdir():
                ensure_directory_target(target)
                continue
            ensure_regular_target(target)
            total += member.size
            if max_bytes and total > max_bytes:
                raise ValueError("archive is too large")


def extract_tar():
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            target, resolved = safe_target(member.name)
            if is_source_archive(resolved):
                continue
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("archive entry cannot be extracted")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with source, open(target, "wb") as dst:
                shutil.copyfileobj(source, dst, length=1024 * 1024)


if archive_kind == "zip":
    validate_zip()
    extract_zip()
else:
    validate_tar()
    extract_tar()
PY
    # The archive may contain an entry with its own filename. Restore the
    # original source archive after extraction so it cannot overwrite itself.
    install -o "$user" -g "$SNPANEL_SITES_GROUP" -m 0644 -- "$tmp_archive" "$archive_target"
    fix_site_tree "$destination_target" "$user"
    rm -f -- "$tmp_archive"
    trap - EXIT
    ;;

  panel-user-ensure)
    [[ $# -eq 1 ]] || deny "usage: panel-user-ensure <panel-user>"
    ensure_panel_user_home "$1"
    ;;

  panel-user-password)
    [[ $# -eq 1 ]] || deny "usage: panel-user-password <panel-user>"
    set_panel_user_password "$1"
    ;;

  panel-user-delete)
    [[ $# -eq 1 ]] || deny "usage: panel-user-delete <panel-user>"
    delete_panel_user_runtime "$1"
    ;;

  site-runtime-ensure)
    [[ $# -eq 3 ]] || deny "usage: site-runtime-ensure <site-user> <path> <php-version|none>"
    user="$1"; path="$2"; php_version="$3"
    require_linux_user "$user"
    target=$(require_managed_path "$path" "$user")
    ensure_panel_user_home "$user"
    if [[ -d "$target/public" && ! -e "$target/public_html" ]]; then
      mv "$target/public" "$target/public_html"
    elif [[ -d "$target/public" && -d "$target/public_html" && -z "$(find "$target/public_html" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      rmdir "$target/public_html"
      mv "$target/public" "$target/public_html"
    fi
    mkdir -p "$target/public_html"
    harden_site_dir_path "$target" "$target/public_html" "$user"
    fix_site_tree "$target" "$user"
    ensure_php_pool "$user" "$target" "$php_version"
    ;;

  site-runtime-move)
    [[ $# -eq 4 ]] || deny "usage: site-runtime-move <site-user> <old-path> <new-path> <php-version|none>"
    user="$1"; old_path="$2"; new_path="$3"; php_version="$4"
    require_linux_user "$user"
    old_target=$(require_managed_path "$old_path")
    new_target=$(require_managed_path "$new_path" "$user")
    old_user="${old_target#${HOME_ROOT}/}"
    old_user="${old_user%%/*}"
    ensure_panel_user_home "$user"
    if [[ "$old_target" != "$new_target" ]]; then
      [[ ! -e "$new_target" ]] || deny "target path already exists: $new_target"
      delete_site_php_pools "$old_user" "$old_target"
      mkdir -p "$(dirname "$new_target")"
      mv "$old_target" "$new_target"
    fi
    if [[ -d "$new_target/public" && ! -e "$new_target/public_html" ]]; then
      mv "$new_target/public" "$new_target/public_html"
    fi
    mkdir -p "$new_target/public_html"
    harden_site_dir_path "$new_target" "$new_target/public_html" "$user"
    fix_site_tree "$new_target" "$user"
    ensure_php_pool "$user" "$new_target" "$php_version"
    ;;

  site-runtime-delete)
    [[ $# -eq 2 ]] || deny "usage: site-runtime-delete <site-user> <path>"
    user="$1"; path="$2"
    require_linux_user "$user"
    target=$(require_managed_path "$path" "$user")
    delete_site_php_pools "$user" "$target"
    exec rm -rf "$target"
    ;;

  rm-site)
    [[ $# -eq 3 ]] || deny "usage: rm-site <site-user> <site-root> <path>"
    user="$1"; root="$2"; path="$3"
    target=$(require_bound_managed_path "$user" "$root" "$path")
    delete_no_follow "$user" "$root" "$target"
    ;;

  mkdir-site)
    [[ $# -eq 1 ]] || deny "usage: mkdir-site <path>"
    target=$(require_managed_path "$1")
    install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0750 "$target"
    install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0750 "$target/public_html"
    ;;

  site-log-read)
    [[ $# -eq 3 ]] || deny "usage: site-log-read <domain> <access|error> <lines>"
    read_site_log "$1" "$2" "$3"
    ;;

  site-logs-read-many)
    [[ $# -ge 3 ]] || deny "usage: site-logs-read-many <access|error> <lines> <domain>..."
    read_site_logs_many "$@"
    ;;

  site-log-clear)
    [[ $# -eq 2 ]] || deny "usage: site-log-clear <domain> <access|error>"
    domain="$1"; kind="$2"
    require_domain "$domain"
    [[ "$kind" == "access" || "$kind" == "error" ]] || deny "invalid log kind: $kind"
    path="/var/log/nginx/${domain}.${kind}.log"
    resolved=$(readlink -m "$path") || deny "cannot resolve log path"
    case "$resolved" in
      /var/log/nginx/*) ;;
      *) deny "log path outside /var/log/nginx: $resolved" ;;
    esac
    if [[ -f "$resolved" ]]; then
      : > "$resolved"
    fi
    ;;

  # ---- WP-CLI as the web user ------------------------------------------
  wp)
    [[ $# -ge 1 ]] || deny "usage: wp <args...>"
    exec runuser -u "$WEB_USER" -- env HOME="$WEB_USER_HOME" WP_CLI_PHP_ARGS='-d pcre.jit=0' php -d pcre.jit=0 /usr/local/bin/wp "$@"
    ;;

  wp-site)
    # WP-CLI has to run under the same PHP the site runs, not whatever the
    # `php` alternative happens to point at. On a server with several PHP
    # versions installed those differ, and the difference is not cosmetic: a
    # site on 8.4 was updated by the 8.3 CLI, which had no mysqli, so every
    # `wp core update` failed with "Your PHP installation appears to be
    # missing the MySQL extension" - reported as a bare 500 in the panel.
    [[ $# -ge 2 ]] || deny "usage: wp-site <site-user> [--php-version=<version>] <args...>"
    user="$1"; shift
    require_linux_user "$user"
    wp_php="php"
    if [[ "${1:-}" == --php-version=* ]]; then
      wp_php_version="${1#--php-version=}"
      require_php_version "$wp_php_version"
      wp_php="php${wp_php_version}"
      command -v "$wp_php" >/dev/null 2>&1 || deny "PHP CLI is not installed: $wp_php"
      shift
    fi
    [[ $# -ge 1 ]] || deny "usage: wp-site <site-user> [--php-version=<version>] <args...>"
    exec runuser -u "$user" -- env HOME="$HOME_ROOT/$user" WP_CLI_PHP_ARGS='-d pcre.jit=0' "$wp_php" -d pcre.jit=0 /usr/local/bin/wp "$@"
    ;;

  # ---- crontab managed for the web user --------------------------------
  cron-list)
    user="${1:-$WEB_USER}"
    if [[ "$user" != "$WEB_USER" ]]; then require_linux_user "$user"; fi
    exec runuser -u "$user" -- crontab -l 2>/dev/null
    ;;
  cron-write)
    # crontab content is fed via stdin
    user="${1:-$WEB_USER}"
    if [[ "$user" != "$WEB_USER" ]]; then require_linux_user "$user"; fi
    exec runuser -u "$user" -- crontab -
    ;;

  # ---- service status (read-only, no privilege change needed but useful)
  service-status)
    [[ $# -eq 1 ]] || deny "usage: service-status <service>"
    is_allowed_service "$1" || deny "service not allowed: $1"
    exec systemctl status "$1" --no-pager
    ;;

  # ---- terminal command execution as panel Linux user ------------------
  terminal-exec)
    # Execute a whitelisted command as the panel Linux user
    # Args: <site-user> <cwd> [--timeout=<sec>] [--php-version=<version>] <command> [args...]
    [[ $# -ge 3 ]] || deny "usage: terminal-exec <site-user> <cwd> [--timeout=<sec>] [--php-version=<version>] <command> [args...]"
    user="$1"; cwd_arg="$2"; shift 2
    php_version=""
    terminal_timeout=""
    while [[ $# -gt 0 ]]; do
      case "${1:-}" in
        --php-version=*)
          php_version="${1#--php-version=}"
          require_php_version "$php_version"
          shift
          ;;
        --timeout=*)
          terminal_timeout="${1#--timeout=}"
          [[ "$terminal_timeout" =~ ^[0-9]{1,4}$ ]] || deny "invalid terminal timeout: $terminal_timeout"
          (( 10#$terminal_timeout >= 1 && 10#$terminal_timeout <= 1800 )) || deny "terminal timeout out of range"
          shift
          ;;
        *) break ;;
      esac
    done
    [[ $# -ge 1 ]] || deny "usage: terminal-exec <site-user> <cwd> [--timeout=<sec>] [--php-version=<version>] <command> [args...]"
    cmd="$1"; shift
    require_linux_user "$user"
    id -u "$user" >/dev/null 2>&1 || deny "panel Linux user does not exist: $user"
    target=$(require_terminal_cwd "$cwd_arg" "$user")

    install -d -o "$user" -g "$user" -m 0700 "$HOME_ROOT/$user/.composer" "$HOME_ROOT/$user/.npm"
    # Validate cwd exists immediately before cd to avoid TOCTOU
    [[ -d "$target" ]] || deny "working directory does not exist: $target"
    cd "$target" || deny "failed to change to working directory: $target"
    umask 022
    terminal_env=(
      "HOME=$HOME_ROOT/$user"
      "COMPOSER_HOME=$HOME_ROOT/$user/.composer"
      "npm_config_cache=$HOME_ROOT/$user/.npm"
      "PATH=/usr/local/bin:/usr/bin:/bin"
    )
    php_bin="php"
    if [[ -n "$php_version" ]]; then
      php_bin="php${php_version}"
      command -v "$php_bin" >/dev/null 2>&1 || deny "PHP CLI is not installed: $php_bin"
    fi

    # PHP started from the terminal was completely unconfined, while the same
    # site's PHP-FPM pool runs under open_basedir. That gap let one tenant read
    # another's files: the terminal runs as the site user, site files are
    # world-readable by design, and /home/<user> is 0751 - not listable, but
    # traversable if you know the name. `php -r "readfile('/home/other/...')"`
    # was enough. Verified on a live test server before the fix: it printed
    # /etc/passwd.
    #
    # The boundary is the tenant's own home, not one site root: a customer with
    # several sites still has to be able to work across them, and the leak
    # being closed is between customers.
    #
    # /var/lib/php/{sessions,uploads}/<user> match the pool. /tmp and
    # /usr/share/php are what composer and PEAR-era libraries expect. The
    # interpreter must also be able to read the phar it is being asked to run,
    # so the directory of each tool is appended at the call site.
    terminal_open_basedir="$HOME_ROOT/$user:/var/lib/php/sessions/$user:/var/lib/php/uploads/$user:/tmp:/usr/share/php"

    # Kill the whole process group when the budget runs out. Composer, npm and
    # WP-CLI can wedge on a slow network, and without this the API worker would
    # block on the pipe until the client gives up.
    terminal_runner=(runuser -u "$user" --)
    if [[ -n "$terminal_timeout" ]] && command -v timeout >/dev/null 2>&1; then
      terminal_runner=(timeout --signal=TERM --kill-after=10 "${terminal_timeout}" runuser -u "$user" --)
    fi

    # Whitelist of allowed commands for terminal access. Keep this in sync with
    # ALLOWED_COMMANDS in backend/app/services/terminal.py.
    case "$cmd" in
      php)
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$php_bin" -d open_basedir="$terminal_open_basedir" "$@"
        ;;
      composer)
        composer_bin="$(command -v composer || true)"
        [[ -n "$composer_bin" ]] || deny "composer not found"
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$php_bin" -d open_basedir="$terminal_open_basedir:$(dirname "$composer_bin")" "$composer_bin" "$@"
        ;;
      wp)
        [[ -f /usr/local/bin/wp ]] || deny "wp-cli not found"
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" WP_CLI_PHP_ARGS="-d pcre.jit=0 -d open_basedir=$terminal_open_basedir:/usr/local/bin" "$php_bin" -d pcre.jit=0 -d open_basedir="$terminal_open_basedir:/usr/local/bin" /usr/local/bin/wp "$@"
        ;;
      phpunit)
        phpunit_bin="$(command -v phpunit || true)"
        if [[ -z "$phpunit_bin" && -x "$target/vendor/bin/phpunit" ]]; then
          # Projects normally ship PHPUnit in vendor/bin instead of globally.
          phpunit_bin="$target/vendor/bin/phpunit"
        fi
        [[ -n "$phpunit_bin" ]] || deny "phpunit not found (install it globally or with composer)"
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$php_bin" -d open_basedir="$terminal_open_basedir:$(dirname "$phpunit_bin")" "$phpunit_bin" "$@"
        ;;
      node|npm|npx|yarn|git)
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$cmd" "$@"
        ;;
      ls|cat|mkdir|rmdir|rm|cp|mv|chmod|chown|grep|find|tar|zip|unzip|diff|head|tail|less|du|df|sed|awk|wc|sort|uniq|stat|file|touch)
        require_terminal_path_args "$user" "$target" "$@"
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$cmd" "$@"
        ;;
      pwd|echo|date|whoami|which|clear|id|uname|printenv|basename|dirname|realpath)
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$cmd" "$@"
        ;;
      curl|wget)
        require_terminal_download_args "$user" "$target" "$@"
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$cmd" "$@"
        ;;
      artisan)
        # Bare `artisan` is a convenience alias for `php artisan`. Laravel keeps
        # it at the project root, one level above public_html.
        if [[ ! -f artisan ]]; then
          deny "artisan not found in $target (Laravel keeps it in the site root; try 'cd ..' first)"
        fi
        exec "${terminal_runner[@]}" env "${terminal_env[@]}" "$php_bin" -d open_basedir="$terminal_open_basedir" artisan "$@"
        ;;
      *)
        echo "Command not allowed: $cmd" >&2
        echo "Allowed commands: php, composer, artisan, wp, phpunit, node, npm, npx, yarn, git," >&2
        echo "  ls, cat, mkdir, rmdir, rm, cp, mv, chmod, chown, touch, grep, find, tar, zip, unzip," >&2
        echo "  diff, head, tail, less, du, df, sed, awk, wc, sort, uniq, stat, file, curl, wget," >&2
        echo "  pwd, echo, date, whoami, which, clear, id, uname, printenv, basename, dirname, realpath" >&2
        exit 126
        ;;
    esac
    ;;

  nginx-upgrade-map-ensure)
    [[ $# -eq 0 ]] || deny "usage: nginx-upgrade-map-ensure"
    ensure_proxy_upgrade_map
    echo "websocket upgrade map present"
    ;;

  # ---- managed application runtimes (node / docker) --------------------
  site-app-write)
    [[ $# -ge 3 ]] || deny "usage: site-app-write <owner-user> <name> <node|docker> [--flags]"
    user="$1"; app_name="$2"; app_runtime="$3"; shift 3
    require_linux_user "$user"
    require_app_name "$app_name"
    is_in "$app_runtime" node docker compose || deny "invalid runtime: $app_runtime"
    app_port=""; app_memory="512"; app_node_major=""
    app_exec=""; app_arg=""; app_image=""; app_container_port="3000"; app_cpus="1"
    while [[ $# -gt 0 ]]; do
      case "${1:-}" in
        --port=*)           app_port="${1#*=}" ;;
        --memory=*)         app_memory="${1#*=}" ;;
        --node-major=*)     app_node_major="${1#*=}" ;;
        --exec=*)           app_exec="${1#*=}" ;;
        --arg=*)            app_arg="${1#*=}" ;;
        --image=*)          app_image="${1#*=}" ;;
        --container-port=*) app_container_port="${1#*=}" ;;
        --cpus=*)           app_cpus="${1#*=}" ;;
        *) deny "unknown site-app-write option: $1" ;;
      esac
      shift
    done
    require_app_port "$app_port"
    require_app_memory "$app_memory"
    require_app_cpus "$app_cpus"
    app_dir="$(ensure_app_directory "$user" "$app_name")"
    remove_legacy_app_units "$user" "$app_name"
    unit_name="$(app_unit_name "$user" "$app_name")"
    unit_path="/etc/systemd/system/${unit_name}.service"
    if [[ "$app_runtime" == "compose" ]]; then
      command -v docker >/dev/null 2>&1 || deny "Docker is not installed; run docker-install first"
      docker compose version >/dev/null 2>&1 || deny "the docker compose plugin is not installed"
      compose_file="$(app_compose_file "$user" "$app_name")"
      write_app_compose_file "$compose_file"
      ensure_compose_bind_dirs "$compose_file" "$user" "$app_dir"
      write_compose_app_unit "$unit_path" "$app_name" "$user" "$app_dir" "$compose_file" \
        "$(app_container_name "$user" "$app_name")"
      chown root:root "$unit_path"
      chmod 0644 "$unit_path"
      systemctl daemon-reload
      echo "$unit_name"
      exit 0
    fi
    env_file="$(app_env_file "$user" "$app_name")"
    write_app_env_file "$env_file"
    if [[ "$app_runtime" == "node" ]]; then
      require_node_major "$app_node_major"
      [[ "$app_arg" =~ ^[A-Za-z0-9._@/-]{1,120}$ ]] || deny "invalid start argument: $app_arg"
      write_node_app_unit "$unit_path" "$app_name" "$user" "$app_dir" "$env_file" \
        "$app_port" "$app_memory" "$app_node_major" "$app_exec" "$app_arg"
    else
      command -v docker >/dev/null 2>&1 || deny "Docker is not installed; run docker-install first"
      require_docker_image "$app_image"
      require_container_port "$app_container_port"
      container_name="$(app_container_name "$user" "$app_name")"
      write_docker_app_unit "$unit_path" "$app_name" "$user" "$container_name" "$app_dir" "$env_file" \
        "$app_port" "$app_memory" "$app_image" "$app_container_port" "$app_cpus"
    fi
    chown root:root "$unit_path"
    chmod 0644 "$unit_path"
    systemctl daemon-reload
    echo "$unit_name"
    ;;

  site-app-rename)
    # An app's directory is derived from its name, so a rename has to take the
    # customer's files with it or they are orphaned in the old path.
    [[ $# -eq 3 ]] || deny "usage: site-app-rename <owner-user> <old-name> <new-name>"
    user="$1"; app_name="$2"; app_new_name="$3"
    require_linux_user "$user"
    require_app_name "$app_name"
    require_app_name "$app_new_name"
    [[ "$app_name" != "$app_new_name" ]] || exit 0
    old_dir="$(app_directory "$user" "$app_name")"
    new_dir="$(app_directory "$user" "$app_new_name")"
    if [[ -d "$old_dir" ]]; then
      [[ -e "$new_dir" ]] && deny "a directory already exists at ${new_dir}"
      install -d -m 0750 "$(dirname "$new_dir")"
      mv -T -- "$old_dir" "$new_dir"
    fi
    ensure_app_directory "$user" "$app_new_name" >/dev/null
    old_env="$(app_env_file "$user" "$app_name")"
    [[ -f "$old_env" ]] && mv -f -- "$old_env" "$(app_env_file "$user" "$app_new_name")"
    old_compose="$(app_compose_file "$user" "$app_name")"
    [[ -f "$old_compose" ]] && mv -f -- "$old_compose" "$(app_compose_file "$user" "$app_new_name")"
    echo "$new_dir"
    ;;

  site-app-dir-ensure)
    [[ $# -eq 2 ]] || deny "usage: site-app-dir-ensure <owner-user> <name>"
    ensure_app_directory "$1" "$2"
    echo
    ;;

  site-app-export)
    # Everything an application owns, in one tar the panel can put in a backup:
    # its directory (parts of which containers own and the panel cannot read) and
    # each named volume (which live under /var/lib/docker, root's territory).
    [[ $# -eq 3 ]] || deny "usage: site-app-export <owner-user> <name> <dest-tar>"
    user="$1"; app_name="$2"; dest="$3"
    require_linux_user "$user"
    require_app_name "$app_name"
    require_backup_path "$dest"
    app_dir="$(app_directory "$user" "$app_name")"
    [[ -d "$app_dir" ]] || deny "application directory not found: $app_dir"
    stage="$(mktemp -d "${BACKUP_ROOT}/.app-export-XXXXXX")"
    trap 'rm -rf "$stage"' EXIT
    install -d -m 0700 "${stage}/volumes"
    tar -C "$app_dir" -cf "${stage}/files.tar" . 2>/dev/null || deny "could not read the application directory"
    if command -v docker >/dev/null 2>&1; then
      while IFS= read -r volume_name; do
        [[ -n "$volume_name" ]] || continue
        volume_path="/var/lib/docker/volumes/${volume_name}/_data"
        [[ -d "$volume_path" ]] || continue
        # Numeric owners: a database image expects its own uid inside the volume,
        # and that uid is the image's, not this machine's.
        tar -C "$volume_path" --numeric-owner -cf "${stage}/volumes/${volume_name}.tar" . 2>/dev/null || true
      done < <(docker volume ls --format '{{.Name}}' 2>/dev/null \
        | grep -E "^$(app_container_name "$user" "$app_name")_" || true)
    fi
    tar -C "$stage" --numeric-owner -cf "$dest" files.tar volumes
    chown snpanel:snpanel "$dest"
    chmod 0600 "$dest"
    rm -rf "$stage"
    trap - EXIT
    du -sb "$dest" | cut -f1
    ;;

  site-app-import)
    [[ $# -eq 3 ]] || deny "usage: site-app-import <owner-user> <name> <src-tar>"
    user="$1"; app_name="$2"; src="$3"
    require_linux_user "$user"
    require_app_name "$app_name"
    require_backup_path "$src"
    [[ -f "$src" && ! -L "$src" ]] || deny "no such export file: $src"
    app_dir="$(ensure_app_directory "$user" "$app_name")"
    stage="$(mktemp -d "${BACKUP_ROOT}/.app-import-XXXXXX")"
    trap 'rm -rf "$stage"' EXIT
    tar -C "$stage" -xf "$src" --no-same-owner
    [[ -f "${stage}/files.tar" ]] || deny "export file has no application directory"
    # No-same-owner then chown: the uid recorded in the archive may belong to a
    # different account on this machine, and a site tree is always owned by its
    # own user.
    tar -C "$app_dir" -xf "${stage}/files.tar" --no-same-owner
    chown -R "$user:$SNPANEL_SITES_GROUP" "$app_dir"
    harden_site_dir "$app_dir" "$user"
    restored=0
    if command -v docker >/dev/null 2>&1; then
      for volume_tar in "${stage}/volumes"/*.tar; do
        [[ -f "$volume_tar" ]] || continue
        volume_name="$(basename "$volume_tar" .tar)"
        [[ "$volume_name" == "$(app_container_name "$user" "$app_name")_"* ]] \
          || deny "export contains a volume for another application: $volume_name"
        docker volume create "$volume_name" >/dev/null
        volume_path="/var/lib/docker/volumes/${volume_name}/_data"
        [[ -d "$volume_path" ]] || continue
        tar -C "$volume_path" -xf "$volume_tar" --numeric-owner -p
        restored=$((restored + 1))
      done
    fi
    rm -rf "$stage"
    trap - EXIT
    echo "restored ${app_name}: directory + ${restored} volume(s)"
    ;;

  site-app-volume-usage)
    # Named volumes live under /var/lib/docker, which the panel user cannot read,
    # so a customer's container data was invisible to the disk quota.
    [[ $# -eq 1 ]] || deny "usage: site-app-volume-usage <owner-user>"
    user="$1"
    require_linux_user "$user"
    command -v docker >/dev/null 2>&1 || { echo 0; exit 0; }
    total=0
    while IFS= read -r volume_name; do
      [[ -n "$volume_name" ]] || continue
      volume_path="/var/lib/docker/volumes/${volume_name}/_data"
      [[ -d "$volume_path" ]] || continue
      size="$(du -sb --one-file-system "$volume_path" 2>/dev/null | cut -f1)"
      [[ "$size" =~ ^[0-9]+$ ]] && total=$((total + size))
    done < <(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E "^snpanel-${user}-" || true)
    echo "$total"
    ;;

  site-app-control)
    [[ $# -eq 3 ]] || deny "usage: site-app-control <owner-user> <name> <action>"
    user="$1"; app_name="$2"; app_action="$3"
    require_linux_user "$user"
    require_app_name "$app_name"
    is_in "$app_action" start stop restart status is-active is-enabled enable disable \
      || deny "action not allowed: $app_action"
    unit_name="$(app_unit_name "$user" "$app_name")"
    [[ -f "/etc/systemd/system/${unit_name}.service" ]] || deny "application unit not found: ${unit_name}"
    exec systemctl "$app_action" "${unit_name}.service" --no-pager
    ;;

  site-app-logs)
    [[ $# -eq 2 || $# -eq 3 ]] || deny "usage: site-app-logs <owner-user> <name> [lines]"
    user="$1"; app_name="$2"; log_lines="${3:-200}"
    require_linux_user "$user"
    require_app_name "$app_name"
    [[ "$log_lines" =~ ^[0-9]{1,4}$ ]] || deny "invalid line count: $log_lines"
    unit_name="$(app_unit_name "$user" "$app_name")"
    exec journalctl -u "${unit_name}.service" -n "$log_lines" --no-pager --output short-iso
    ;;

  site-app-delete)
    [[ $# -eq 2 ]] || deny "usage: site-app-delete <owner-user> <name>"
    user="$1"; app_name="$2"
    require_linux_user "$user"
    require_app_name "$app_name"
    unit_name="$(app_unit_name "$user" "$app_name")"
    systemctl disable --now "${unit_name}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${unit_name}.service"
    remove_legacy_app_units "$user" "$app_name"
    systemctl daemon-reload
    if command -v docker >/dev/null 2>&1; then
      compose_file="$(app_compose_file "$user" "$app_name")"
      if [[ -f "$compose_file" ]]; then
        docker compose -f "$compose_file" --project-directory "$(app_directory "$user" "$app_name")" \
          -p "$(app_container_name "$user" "$app_name")" down --volumes 2>/dev/null || true
      fi
      docker rm -f "$(app_container_name "$user" "$app_name")" 2>/dev/null || true
    fi
    rm -f "$(app_env_file "$user" "$app_name")" "$(app_compose_file "$user" "$app_name")"
    # The app's files stay put; deleting a customer's code is never implied by
    # removing its runtime.
    echo "removed ${unit_name}"
    ;;

  site-app-install-deps)
    # npm install for a node app, as the site user, with a hard timeout so a
    # runaway postinstall cannot hold a worker forever.
    [[ $# -eq 3 ]] || deny "usage: site-app-install-deps <owner-user> <name> <node-major>"
    user="$1"; app_name="$2"; app_node_major="$3"
    require_linux_user "$user"
    require_app_name "$app_name"
    require_node_major "$app_node_major"
    app_dir="$(ensure_app_directory "$user" "$app_name")"
    [[ -f "${app_dir}/package.json" ]] || deny "no package.json in ${app_name}"
    bin_dir="$(resolve_node_bin_dir "$app_node_major")" \
      || deny "Node ${app_node_major} is not installed; run node-install ${app_node_major} first"
    exec timeout 900 runuser -u "$user" -- env -i \
      HOME="${HOME_ROOT}/${user}" \
      PATH="${bin_dir}:/usr/local/bin:/usr/bin:/bin" \
      NODE_ENV=production \
      "${bin_dir}/npm" install --omit=dev --no-audit --no-fund --prefix "$app_dir"
    ;;

  site-app-compose-ps)
    [[ $# -eq 2 ]] || deny "usage: site-app-compose-ps <owner-user> <name>"
    user="$1"; app_name="$2"
    require_linux_user "$user"
    require_app_name "$app_name"
    command -v docker >/dev/null 2>&1 || deny "Docker is not installed; run docker-install first"
    compose_file="$(app_compose_file "$user" "$app_name")"
    [[ -f "$compose_file" ]] || deny "no compose file for ${app_name}; deploy it once first"
    app_dir="$(app_directory "$user" "$app_name")"
    project="$(app_container_name "$user" "$app_name")"
    container_ids="$(timeout 60 docker compose -f "$compose_file" --project-directory "$app_dir" \
      -p "$project" ps --all --quiet 2>/dev/null || true)"
    [[ -n "$container_ids" ]] || exit 0
    # A container that keeps dying is restarted by Docker, so at any moment it
    # reads as running; only the restart count tells the panel it is looping.
    exec timeout 60 docker inspect --format \
      '{"service":"{{index .Config.Labels "com.docker.compose.service"}}","state":"{{.State.Status}}","restarts":{{.RestartCount}},"exit":{{.State.ExitCode}},"oom":{{.State.OOMKilled}},"started":"{{.State.StartedAt}}"}' \
      $container_ids
    ;;

  site-app-compose-pull)
    [[ $# -eq 2 ]] || deny "usage: site-app-compose-pull <owner-user> <name>"
    user="$1"; app_name="$2"
    require_linux_user "$user"
    require_app_name "$app_name"
    command -v docker >/dev/null 2>&1 || deny "Docker is not installed; run docker-install first"
    compose_file="$(app_compose_file "$user" "$app_name")"
    [[ -f "$compose_file" ]] || deny "no compose file for ${app_name}; deploy it once first"
    app_dir="$(app_directory "$user" "$app_name")"
    exec timeout 1800 docker compose -f "$compose_file" --project-directory "$app_dir" \
      -p "$(app_container_name "$user" "$app_name")" pull
    ;;

  site-app-pull)
    [[ $# -eq 1 ]] || deny "usage: site-app-pull <image>"
    command -v docker >/dev/null 2>&1 || deny "Docker is not installed; run docker-install first"
    require_docker_image "$1"
    exec timeout 900 docker pull -- "$1"
    ;;

  docker-install)
    [[ $# -eq 0 ]] || deny "usage: docker-install"
    install_docker_engine
    ;;

  docker-status)
    [[ $# -eq 0 ]] || deny "usage: docker-status"
    if ! command -v docker >/dev/null 2>&1; then
      echo "installed=no"
      exit 0
    fi
    echo "installed=yes"
    echo "version=$(docker --version 2>/dev/null | head -n1)"
    echo "active=$(systemctl is-active docker 2>/dev/null)"
    # Images are shared by every tenant on the box, so they cannot be billed to
    # one customer's quota; an administrator still has to see what they cost.
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "df=$line"
    done < <(docker system df --format '{{.Type}}|{{.Size}}|{{.Reclaimable}}' 2>/dev/null || true)
    ;;

  docker-prune)
    # Dangling layers and build cache only: nothing that a tagged image, a
    # volume or a container still refers to is touched.
    [[ $# -eq 0 ]] || deny "usage: docker-prune"
    command -v docker >/dev/null 2>&1 || deny "Docker is not installed"
    docker image prune -f 2>&1 || true
    docker builder prune -f 2>&1 || true
    echo "--- remaining ---"
    docker system df --format '{{.Type}}|{{.Size}}|{{.Reclaimable}}' 2>/dev/null || true
    ;;

  node-install)
    [[ $# -eq 1 ]] || deny "usage: node-install <major>"
    install_node_major "$1"
    ;;

  node-list)
    [[ $# -eq 0 ]] || deny "usage: node-list"
    list_installed_node_majors
    ;;

  *)
    deny "unknown command: $cmd"
    ;;
esac
