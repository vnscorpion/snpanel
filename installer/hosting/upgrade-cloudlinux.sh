#!/usr/bin/env bash
# SNPanel Hosting Edition, stage 1: AlmaLinux 10 + SNPanel (nginx, PHP-FPM)
# -> CloudLinux 10, Apache + mod_lsapi + alt-php, CageFS, PHP Selector,
#    LVE, CloudLinux Manager inside the panel, MySQL Governor.
#
# One-way: cldeploy converts the operating system. Take a VPS snapshot first.
# The panel must already be the Hosting Edition build (apply-bundle.sh).
#
#   bash upgrade-cloudlinux.sh --check                 # report only, changes nothing
#   bash upgrade-cloudlinux.sh --key <CLOUDLINUX_KEY>  # runs until the reboot
#   systemctl reboot
#   bash upgrade-cloudlinux.sh                         # the rest, after the reboot
#
# Re-run it after any failure: every step looks at the machine and skips
# what is already done. Written from the CL-0 trial and the steps the test
# server was converted with (docs/hosting/CL-0-REPORT.md on the report branch).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

CL_KEY="${CL_KEY:-}"
CL_KEY_FILE="${CL_KEY_FILE:-/etc/snpanel/cloudlinux.key}"
DEFAULT_PHP="${DEFAULT_PHP:-8.4}"
EXTRA_PHP="${EXTRA_PHP:-8.1 8.2 8.3 8.4 8.5}"
GOVERNOR=1
GOVERNOR_MYSQL="${GOVERNOR_MYSQL:-}"
FORCE=0
BACKUP_ROOT="/root/snpanel-upgrade-backup"

usage() {
  cat <<'EOF'
Usage: bash upgrade-cloudlinux.sh [options]

  --check               Chỉ kiểm tra và liệt kê các bước còn thiếu; không đổi gì.
  --key KEY             Key kích hoạt CloudLinux (hoặc biến CL_KEY, hoặc file
                        /etc/snpanel/cloudlinux.key). Chỉ cần cho bước convert.
  --php "8.1 8.2 ..."   Các bản alt-php cài thêm (mặc định 8.1-8.5). Bản nào
                        website đang dùng luôn được cài.
  --default-php 8.4     Bản PHP mặc định của server (native và PHP Selector).
  --no-governor         Không cài MySQL Governor.
  --governor-mysql V    Tên bản cho mysqlgovernor.py (vd. mariadb1011); mặc
                        định đoán từ MariaDB đang chạy.
  --yes                 Không hỏi xác nhận.
  --force               Bỏ qua kết quả doctor --enterprise-readiness.

Biến môi trường SNPANEL_ADMIN_PASSWORD: mật khẩu admin panel, để script đặt
phiên bản PHP cho từng website qua API (nếu không có sẽ hỏi, bỏ trống thì bỏ qua).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1 ;;
    --key) CL_KEY="${2:?}"; shift ;;
    --key-file) CL_KEY_FILE="${2:?}"; shift ;;
    --php) EXTRA_PHP="${2:?}"; shift ;;
    --default-php) DEFAULT_PHP="${2:?}"; shift ;;
    --no-governor) GOVERNOR=0 ;;
    --governor-mysql) GOVERNOR_MYSQL="${2:?}"; shift ;;
    --yes|-y) ASSUME_YES=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Không hiểu tuỳ chọn: $1 (xem --help)" ;;
  esac
  shift
done

need_root
[[ "$DEFAULT_PHP" =~ ^[5-8]\.[0-9]$ ]] || die "--default-php phải có dạng 8.4"
DP="${DEFAULT_PHP/./}"

# --- which PHP versions ------------------------------------------------------
# What the operator asked for, the default, and every version a website uses
# today: a site must keep running the version it runs now.
php_versions() {
  local used
  used="$(sqlite_ro "SELECT DISTINCT php_version FROM websites WHERE app_type IN ('php','wordpress')" 2>/dev/null || true)"
  printf '%s\n' $EXTRA_PHP "$DEFAULT_PHP" $used \
    | grep -E '^[5-8]\.[0-9]$' | sort -t. -k1,1n -k2,2n -u
}
compact() { printf '%s' "${1/./}"; }

# =============================================================================
# 0. Preflight
# =============================================================================
preflight() {
  [[ "$(uname -m)" == x86_64 ]] || die "Chỉ hỗ trợ x86_64"
  if systemd-detect-virt -cq 2>/dev/null; then
    die "Máy đang chạy trong container ($(systemd-detect-virt -c)): LVE cần kernel thật (KVM/VMware/máy vật lý)"
  fi
  if ! is_cloudlinux; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == almalinux && "${VERSION_ID:-}" == 10* ]] \
      || die "Chỉ AlmaLinux 10 lên được CloudLinux 10 (máy này: ${PRETTY_NAME:-?}). Ubuntu/Debian: backup/restore sang một máy AlmaLinux 10 mới."
  fi
  [[ -x "$API_BIN" && -x "$HELPER" && -f "$ENV_FILE" && -f "$PANEL_DB" ]] \
    || die "Chưa thấy SNPanel ở $APP_DIR (cài SNPanel 1.1.0 trước)"
  grep -qa 'hosting/cloudlinux' "$API_BIN" \
    || die "Panel đang là bản Standard. Cài bản build Hosting Edition trước: bash apply-bundle.sh (README.md, bước 0)"
  if ! is_cloudlinux && grep -q enterprise-readiness <<<"$("$CLI_BIN" doctor --help 2>&1 || true)"; then
    log "${C_B}Kiểm tra máy (snpanel doctor --enterprise-readiness)${C_0}"
    if ! "$CLI_BIN" doctor --enterprise-readiness 2>&1 | tee -a "$LOG_FILE"; then
      [[ "$FORCE" == 1 ]] || die "Máy chưa đạt điều kiện ở trên. Sửa rồi chạy lại, hoặc --force nếu chắc chắn."
      warn "Bỏ qua kết quả kiểm tra (--force)"
    fi
  fi
}

# =============================================================================
# 1. Backup
# =============================================================================
backup_done() { [[ -f "$STATE_DIR/backup.done" ]]; }
backup_run() {
  local dir; dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  install -d -m 700 "$dir"
  python3 - "$PANEL_DB" "$dir/snpanel.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
PY
  install -m 600 "$ENV_FILE" "$dir/backend.env"
  [[ -d /etc/nginx ]] && tar czf "$dir/etc-nginx.tgz" -C / etc/nginx
  compgen -G '/etc/opt/remi/php*/php-fpm.d' >/dev/null && tar czf "$dir/remi-fpm-pools.tgz" /etc/opt/remi/php*/php-fpm.d 2>/dev/null
  nft list ruleset >"$dir/nft-ruleset.txt" 2>/dev/null || true
  rpm -qa | sort >"$dir/rpm-qa.txt"
  systemctl list-unit-files --no-legend >"$dir/unit-files.txt"
  cp -a /etc/os-release "$dir/os-release"
  sqlite_ro "SELECT id, domain, app_type, php_version, linux_user FROM websites ORDER BY id" >"$dir/websites.tsv"
  echo "$dir" >"$STATE_DIR/backup.done"
  info "Sao lưu ở $dir"
}

# =============================================================================
# 2. cldeploy: AlmaLinux 10 -> CloudLinux 10 (about 5 minutes, sites stay up)
# =============================================================================
convert_done() { is_cloudlinux; }
convert_run() {
  local key="$CL_KEY"
  [[ -z "$key" && -f "$CL_KEY_FILE" ]] && key="$(tr -d '[:space:]' <"$CL_KEY_FILE")"
  [[ -n "$key" ]] || die "Cần key CloudLinux: --key KEY (hoặc CL_KEY=..., hoặc file $CL_KEY_FILE)"
  confirm CLOUDLINUX "Chuyển máy sang CloudLinux 10 là MỘT CHIỀU (cldeploy đổi cả hệ điều hành). Hãy chắc là đã có snapshot VPS."
  curl -fsSLo "$STATE_DIR/cldeploy" https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy
  # The key goes through the environment, not argv: /proc/<pid>/cmdline is
  # world-readable.
  CLDEPLOY_ACTIVATION_KEY="$key" run bash "$STATE_DIR/cldeploy" --precheck
  CLDEPLOY_ACTIVATION_KEY="$key" run bash "$STATE_DIR/cldeploy" -y --conversion-only
}

# =============================================================================
# 3. LVE loaded (after the reboot)
# =============================================================================
lve_done() { lve_loaded && lvectl list >/dev/null 2>&1; }
lve_run() {
  log ""
  log "${C_B}Đã convert sang CloudLinux. Khởi động lại máy rồi chạy lại đúng lệnh này:${C_0}"
  log "    systemctl reboot"
  log "    bash $0"
  exit 0
}

# =============================================================================
# 4. Packages: Apache, mod_lsapi, ModSecurity, CageFS, alt-php, CloudLinux Manager
# =============================================================================
EXTS="bcmath cli common gd intl mbstring mysqlnd opcache pdo process soap xml zip sodium pecl-imagick"
packages_done() {
  rpm -q httpd mod_ssl mod_security cagefs liblsapi mod_lsapi lvemanager lve-stats lve-utils >/dev/null 2>&1 || return 1
  local v; for v in $(php_versions); do rpm -q "alt-php$(compact "$v")" >/dev/null 2>&1 || return 1; done
}
packages_run() {
  # The package scriptlet starts httpd, which dies on :80 while nginx holds it.
  systemctl is-active --quiet httpd || systemctl mask httpd
  local v base="" ext=""
  for v in $(php_versions); do
    base="$base alt-php$(compact "$v")"
    for e in $EXTS; do ext="$ext alt-php$(compact "$v")-$e"; done
  done
  # shellcheck disable=SC2086
  run dnf -y install httpd mod_ssl mod_security cagefs liblsapi mod_lsapi lvemanager lve-stats lve-utils $base
  # shellcheck disable=SC2086
  run dnf -y --setopt=strict=0 install $ext
}

# =============================================================================
# 5. PHP: CageFS skeleton, PHP Selector, native PHP (outside CageFS)
# =============================================================================
php_done() {
  local E="/opt/alt/php$DP/etc"
  [[ -d /usr/share/cagefs-skeleton/bin ]] || return 1
  for f in /usr/local/bin/lsphp /usr/bin/php /usr/bin/php-cgi /etc/php.ini; do
    [[ -f "$f" && ! -L "$f" ]] || return 1
  done
  cmp -s /usr/local/bin/lsphp "/opt/alt/php$DP/usr/bin/lsphp" || return 1
  same_file snpanel-mysql.ini "$E/php.d/snpanel-mysql.ini"
}
php_run() {
  local E="/opt/alt/php$DP/etc" v x tz bdir
  bdir="$(cat "$STATE_DIR/backup.done" 2>/dev/null || echo "$BACKUP_ROOT")"
  [[ -d /usr/share/cagefs-skeleton/bin ]] || run cagefsctl --init
  run cloudlinux-selector set --json --interpreter php --default-version "$DEFAULT_PHP"
  # mod_lsapi's setup copies the lowest alt-php into /usr/local/bin/lsphp;
  # the copies below come after it.
  run switch_mod_lsapi --setup || warn "switch_mod_lsapi --setup báo lỗi; tiếp tục, các file native được đặt ngay sau đây"
  # Native PHP = the default alt-php, as real files: CageFS copies a symlink
  # as a symlink and the Selector then stops working in every cage (F8, F9).
  for f in /usr/bin/php /usr/bin/php-cgi /etc/php.ini; do
    [[ -e "$f" && ! -e "$bdir/native$(basename "$f").orig" ]] && cp -aP "$f" "$bdir/native$(basename "$f").orig" 2>/dev/null || true
  done
  rm -f /usr/local/bin/lsphp /usr/bin/php /usr/bin/php-cgi /etc/php.ini
  install -m 0755 "/opt/alt/php$DP/usr/bin/lsphp" /usr/local/bin/lsphp
  install -m 0755 "/opt/alt/php$DP/usr/bin/php" /usr/bin/php
  install -m 0755 "/opt/alt/php$DP/usr/bin/php-cgi" /usr/bin/php-cgi
  install -m 0644 "$E/php.ini" /etc/php.ini
  [[ -f /etc/cl.selector/native.conf ]] || printf 'lsphp=/usr/local/bin/lsphp\n' >/etc/cl.selector/native.conf
  # php8.4 / php84 on the PATH, as the Standard edition had them.
  for v in $(php_versions); do
    [[ -x "/opt/alt/php$(compact "$v")/usr/bin/php" ]] || continue
    ln -sfn "/opt/alt/php$(compact "$v")/usr/bin/php" "/usr/local/bin/php$v"
    ln -sfn "/opt/alt/php$(compact "$v")/usr/bin/php" "/usr/bin/php$(compact "$v")"
  done
  # Native PHP runs phpMyAdmin, WP-CLI and composer for the panel.
  for x in phar mbstring zip xmlreader xmlwriter intl gd bcmath fileinfo opcache; do
    [[ -f "$E/php.d.all/$x.ini" ]] && ln -sfn "$E/php.d.all/$x.ini" "$E/php.d/$x.ini"
  done
  install_file snpanel-mysql.ini "$E/php.d/snpanel-mysql.ini" 0644
  tz="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
  sed -i "s#^;\?date.timezone =.*#date.timezone = $tz#" "$E/php.ini" /etc/php.ini
  run cagefsctl --setup-cl-selector
  run selectorctl --apply-global-php-ini
  # WordPress needs these in every version, set BEFORE any account gets a
  # version: an account's defaults are a snapshot taken then (F10).
  for v in $(php_versions); do
    [[ -d "/opt/alt/php$(compact "$v")" ]] || continue
    run selectorctl --enable-extensions=nd_mysqli,nd_pdo_mysql,opcache --version="$v" || warn "PHP $v: không bật được nd_mysqli/nd_pdo_mysql/opcache"
  done
}

# =============================================================================
# 6. Apache on 8080/8443, beside nginx (nothing public changes yet)
# =============================================================================
tools_bootstrap() {
  # The tools vhost the helper keeps up to date (ops/panel.rs,
  # render_tools_apache) needs to exist before the helper will write it.
  local cert key
  cert="$(env_get PANEL_SSL_CERT)"; key="$(env_get PANEL_SSL_KEY)"
  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    cert=/etc/snpanel/panel-selfsigned-fullchain.pem; key=/etc/snpanel/panel-selfsigned-privkey.pem
  fi
  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    cert=/etc/httpd/snpanel/bootstrap.crt; key=/etc/httpd/snpanel/bootstrap.key
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=snpanel-default.invalid" \
      -keyout "$key" -out "$cert" >/dev/null 2>&1
    chmod 600 "$key"
  fi
  local block='    ErrorLog /var/log/httpd/snpanel-tools.error.log
    CustomLog /var/log/httpd/snpanel-tools.access.log combined
    LimitRequestBody 1153433600

    Alias /.well-known/acme-challenge/ /var/www/snpanel-acme/.well-known/acme-challenge/

    # phpMyAdmin runs as its own system user, outside CageFS, never as a customer
    SuexecUserGroup snpanel-pma snpanel-pma
    RedirectMatch 301 ^/phpmyadmin$ /phpmyadmin/
    Alias /phpmyadmin/ /usr/share/phpMyAdmin/
    <Directory /usr/share/phpMyAdmin/>
        Options -Indexes
        AllowOverride None
        DirectoryIndex index.php
        Require all granted
        <FilesMatch "\.php$">
            SetHandler application/x-httpd-lsphp
        </FilesMatch>
    </Directory>
    <Directory /usr/share/phpMyAdmin/setup/>
        Require all denied
    </Directory>
    <Directory /var/www/snpanel-acme/>
        Options None
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>'
  {
    echo "# SNPANEL MANAGED - default vhost: ACME + phpMyAdmin. Written by the panel."
    echo "# First vhost loaded, so it answers any Host no site claims (nginx: default_server)."
    printf '<VirtualHost *:8080>\n    ServerName snpanel-default.invalid\n    DocumentRoot /var/www/snpanel-acme\n%s\n\n' "$block"
    printf '<VirtualHost *:8443>\n    ServerName snpanel-default.invalid\n    DocumentRoot /var/www/snpanel-acme\n    SSLEngine on\n    SSLCertificateFile %s\n    SSLCertificateKeyFile %s\n%s\n' "$cert" "$key" "$block"
  } >/etc/httpd/snpanel/00-tools.conf
}
apache_done() {
  [[ -f /etc/httpd/snpanel/00-tools.conf ]] || return 1
  same_file 00-snpanel.conf /etc/httpd/conf.d/00-snpanel.conf || return 1
  same_file httpd-snpanel.conf /etc/systemd/system/httpd.service.d/snpanel.conf || return 1
  same_file snpanel-weblogs.conf /etc/systemd/system/httpd.service.d/snpanel-weblogs.conf || return 1
  ! grep -q '^Listen 80$' /etc/httpd/conf/httpd.conf || return 1
  [[ -f /var/www/snpanel-acme/.well-known/acme-challenge/snpanel-health ]] || return 1
  systemctl is-active --quiet httpd
}
apache_run() {
  local bdir f
  bdir="$(cat "$STATE_DIR/backup.done" 2>/dev/null || echo "$BACKUP_ROOT")"
  # The stock conf.d files: Remi's PHP-FPM handlers, the EPEL phpMyAdmin
  # alias, the welcome page, and ssl.conf's _default_:443 (LiteSpeed reads
  # this configuration too and would open listeners from it) (F5).
  install -d /etc/httpd/conf.d.disabled-by-snpanel
  for f in /etc/httpd/conf.d/{php.conf,php*-php.conf,phpMyAdmin.conf,welcome.conf,userdir.conf,autoindex.conf,ssl.conf}; do
    [[ -f "$f" ]] && mv "$f" /etc/httpd/conf.d.disabled-by-snpanel/
  done
  [[ -f "$bdir/httpd.conf.orig" ]] || cp -a /etc/httpd/conf/httpd.conf "$bdir/httpd.conf.orig"
  sed -i 's/^Listen 80$/#Listen 80  # SNPanel: see conf.d\/00-snpanel.conf/' /etc/httpd/conf/httpd.conf
  install_file 00-snpanel.conf /etc/httpd/conf.d/00-snpanel.conf 0644
  [[ -f /etc/httpd/conf.d/00-snpanel-listen.inc ]] || install_file 00-snpanel-listen.inc /etc/httpd/conf.d/00-snpanel-listen.inc 0644
  install -d -m 0755 /etc/httpd/snpanel /etc/httpd/snpanel/sites /etc/httpd/snpanel/waf
  install_file httpd-snpanel.conf /etc/systemd/system/httpd.service.d/snpanel.conf 0644
  install_file snpanel-weblogs.conf /etc/systemd/system/httpd.service.d/snpanel-weblogs.conf 0644
  install_file snpanel-weblogs.conf /etc/systemd/system/lshttpd.service.d/snpanel-weblogs.conf 0644
  # The watchdog's and web-status's probe: a static file, never PHP (F22).
  install -d -m 0755 /var/www/snpanel-acme/.well-known/acme-challenge
  echo ok >/var/www/snpanel-acme/.well-known/acme-challenge/snpanel-health
  chmod 644 /var/www/snpanel-acme/.well-known/acme-challenge/snpanel-health
  id -u snpanel-pma >/dev/null 2>&1 \
    || useradd --system --no-create-home --home-dir /var/lib/phpMyAdmin --shell /sbin/nologin snpanel-pma
  [[ -f /etc/httpd/snpanel/00-tools.conf ]] || tools_bootstrap
  systemctl daemon-reload
  run httpd -t
  systemctl unmask httpd
  systemctl reset-failed httpd 2>/dev/null || true
  run systemctl enable --now httpd
}

# =============================================================================
# 7. CloudLinux integration: CPAPI, CageFS config, D-Bus, CloudLinux Manager UI
# =============================================================================
integration_done() {
  same_file snpanel-cpapi /usr/local/lib/snpanel/snpanel-cpapi || return 1
  same_file snpanel-ui-user-info /usr/local/lib/snpanel/snpanel-ui-user-info || return 1
  same_file cloudlinux-ui-router.php /usr/local/lib/snpanel/cloudlinux-ui-router.php || return 1
  same_file snpanel-lvemanager.sudoers /etc/sudoers.d/snpanel-lvemanager || return 1
  same_file snpanel-systemd-read.conf /etc/dbus-1/system.d/snpanel-systemd-read.conf || return 1
  grep -q '^\[lvemanager_config\]' /opt/cpvendor/etc/integration.ini 2>/dev/null || return 1
  grep -qx '!/var/lib/snpanel-cpapi' /etc/cagefs/cagefs.mp 2>/dev/null || return 1
  [[ -f /var/lib/snpanel-lvemanager/index.php || -d /var/lib/snpanel-lvemanager/assets ]] || return 1
  systemctl is-active --quiet snpanel-cloudlinux-ui
}
integration_run() {
  install_file snpanel-cpapi /usr/local/lib/snpanel/snpanel-cpapi 0755
  install_file snpanel-ui-user-info /usr/local/lib/snpanel/snpanel-ui-user-info 0755
  install_file cloudlinux-ui-router.php /usr/local/lib/snpanel/cloudlinux-ui-router.php 0644
  install -d -m 0755 /opt/cpvendor/etc
  cat >/opt/cpvendor/etc/integration.ini <<'EOF'
; SNPANEL MANAGED - CloudLinux control panel integration
[integration_scripts]
panel_info = /usr/local/lib/snpanel/snpanel-cpapi panel_info
db_info = /usr/local/lib/snpanel/snpanel-cpapi db_info
packages = /usr/local/lib/snpanel/snpanel-cpapi packages
users = /usr/local/lib/snpanel/snpanel-cpapi users
domains = /usr/local/lib/snpanel/snpanel-cpapi domains
resellers = /usr/local/lib/snpanel/snpanel-cpapi resellers
admins = /usr/local/lib/snpanel/snpanel-cpapi admins
php = /usr/local/lib/snpanel/snpanel-cpapi php

[lvemanager_config]
ui_user_info = /usr/local/lib/snpanel/snpanel-ui-user-info
base_path = /var/lib/snpanel-lvemanager
base_uri = /cloudlinux/
run_service = 0
EOF
  chmod 644 /opt/cpvendor/etc/integration.ini
  # The CPAPI script runs inside every customer's cage; its snapshot is
  # mounted read-only there (F11).
  install_file snpanel.cagefs.cfg /etc/cagefs/conf.d/snpanel.cfg 0644
  grep -qx '!/var/lib/snpanel-cpapi' /etc/cagefs/cagefs.mp || echo '!/var/lib/snpanel-cpapi' >>/etc/cagefs/cagefs.mp
  install -d -m 0755 /var/lib/snpanel-cpapi
  # CLOS-5813: isolatectl is missing from the CageFS skeleton.
  echo /usr/sbin/isolatectl | run cagefsctl --wait-lock --update-list || true
  # CageFS's D-Bus hardening hides systemd from every non-root account; the
  # panel reads service state as "snpanel".
  install_file snpanel-systemd-read.conf /etc/dbus-1/system.d/snpanel-systemd-read.conf 0644
  busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || systemctl reload dbus-broker 2>/dev/null || true
  # CloudLinux Manager's own UI, served on the loopback outside LVE and
  # proxied by the panel at /cloudlinux/.
  id -u snpanel-lvem >/dev/null 2>&1 \
    || useradd --system --home-dir /var/lib/snpanel-lvemanager --shell /sbin/nologin snpanel-lvem
  install -d -o root -g snpanel-lvem -m 0755 /var/lib/snpanel-lvemanager
  visudo -cf "$FILES/snpanel-lvemanager.sudoers" >/dev/null
  install_file snpanel-lvemanager.sudoers /etc/sudoers.d/snpanel-lvemanager 0440
  run /usr/share/l.v.e-manager/install-lvemanager-plugin.py --install
  install_file snpanel-cloudlinux-ui.service /etc/systemd/system/snpanel-cloudlinux-ui.service 0644
  systemctl daemon-reload
  run systemctl enable --now snpanel-cloudlinux-ui
  # The Resource Usage charts are drawn in the cage: a stale font cache
  # puts fontconfig warnings into the JSON CloudLinux Manager parses.
  fc-cache -f >/dev/null 2>&1 || true
  run cagefsctl --force-update
  run cagefsctl --remount-all
  # The panel starts its CloudLinux side (CPAPI snapshot, LVE) at start-up.
  run systemctl restart snpanel-api
}

# =============================================================================
# 8. Accounts: CageFS, PHP Selector version per account
# =============================================================================
accounts_done() {
  local u enabled
  enabled="$(cagefsctl --list-enabled 2>/dev/null || true)"
  for u in $(panel_linux_users); do
    grep -qx "$u" <<<"$enabled" || return 1
  done
}
account_version() {
  # The version most of the account's PHP sites use; a tie goes to the default.
  sqlite_ro "SELECT w.php_version FROM websites w JOIN users u ON u.id = w.owner_id
             WHERE u.username = '$1' AND w.app_type IN ('php','wordpress')" \
    | python3 -c '
import collections, sys
default = sys.argv[1]
c = collections.Counter(v.strip() for v in sys.stdin if v.strip())
if not c:
    print(default); sys.exit()
top = max(c.values())
w = sorted(v for v, n in c.items() if n == top)
print(default if default in w else w[-1])' "$DEFAULT_PHP"
}
accounts_run() {
  local u v
  for u in $(panel_linux_users); do
    [[ "$u" =~ ^[a-z_][a-z0-9_-]*$ ]] || { warn "Bỏ qua tài khoản tên lạ: $u"; continue; }
    # CageFS, ~/.lve, ~/.lvestats, ~/.wp-cli: the helper does this for
    # every account it ensures on CloudLinux.
    run "$HELPER" panel-user-ensure "$u"
    install -d -o "$u" -g "$u" -m 0771 "/home/$u/.cagefs" "/home/$u/.cagefs/websites" 2>/dev/null || true
    v="$(account_version "$u")"
    [[ -d "/opt/alt/php$(compact "$v")" ]] || v="$DEFAULT_PHP"
    run cloudlinux-selector set --json --interpreter php --user "$u" --current-version "$v"
    info "$u: PHP $v"
  done
}

# =============================================================================
# 9. Cutover: nginx off, Apache takes 80/443 through the nft redirect
# =============================================================================
webscripts_done() {
  same_file snpanel-webswitch /usr/local/sbin/snpanel-webswitch || return 1
  same_file snpanel-webswitch-restore /usr/local/sbin/snpanel-webswitch-restore || return 1
  same_file snpanel-webswitch-restore.service /etc/systemd/system/snpanel-webswitch-restore.service || return 1
  same_file snpanel-webswitch-restore.timer /etc/systemd/system/snpanel-webswitch-restore.timer
}
webscripts_run() {
  # Only the files: which server answers 80/443 is not touched here.
  install_file snpanel-webswitch /usr/local/sbin/snpanel-webswitch 0755
  install_file snpanel-webswitch-restore /usr/local/sbin/snpanel-webswitch-restore 0755
  install_file snpanel-webswitch-restore.service /etc/systemd/system/snpanel-webswitch-restore.service 0644
  install_file snpanel-webswitch-restore.timer /etc/systemd/system/snpanel-webswitch-restore.timer 0644
  systemctl daemon-reload
  # The timer re-fires only while the oneshot is not left "active".
  if [[ -s /var/lib/snpanel/webserver ]]; then
    systemctl enable snpanel-webswitch-restore.service >/dev/null 2>&1 || true
    run systemctl enable --now snpanel-webswitch-restore.timer
  fi
}

cutover_done() {
  [[ ! -e /usr/sbin/nginx ]] && ! unit_file_exists nginx || return 1
  [[ -s /var/lib/snpanel/webserver ]] || return 1
  nft list table inet snpanel_webfailover >/dev/null 2>&1
}
site_codes() {
  # site_codes <port>: "<domain> <HTTP status>" per website, asked on <port>.
  local d
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    printf '%s %s\n' "$d" "$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Host: $d" "http://127.0.0.1:$1/" || true)"
  done < <(sqlite_ro "SELECT domain FROM websites ORDER BY id")
}
cutover_run() {
  local before after f scheme host port live
  # Units from 1.1.0 name /etc/nginx in ReadWritePaths without the "-" that
  # makes it optional; without nginx the panel then fails (226/NAMESPACE).
  for f in /etc/systemd/system/snpanel-*.service; do
    grep -qE '[ =]/etc/nginx' "$f" 2>/dev/null && sed -i -E 's#([ =])(/etc/nginx[^ ]*)#\1-\2#g; s#--/etc#-/etc#g' "$f"
  done
  systemctl daemon-reload
  # The firewall must let redirected 80/443 through before the switch; the
  # helper renders that rule on every rebuild.
  run "$HELPER" firewall-reload || warn "firewall-reload báo lỗi (firewall có thể đang tắt)"
  before="$(site_codes 80)"
  confirm APACHE "Chuyển web từ nginx sang Apache: các site gián đoạn trong lúc gỡ nginx và ghi lại vhost (thường dưới một phút)."
  systemctl disable --now nginx 2>/dev/null || true
  # nginx-filesystem stays: the EPEL phpMyAdmin package needs it.
  run dnf -y --setopt=clean_requirements_on_remove=False remove nginx nginx-core
  [[ ! -e /usr/sbin/nginx ]] || die "/usr/sbin/nginx vẫn còn sau khi gỡ nginx"
  systemctl daemon-reload
  run systemctl restart snpanel-helper.socket snpanel-helper.service
  run systemctl restart snpanel-api
  sleep 3
  # Every site's vhost, now as Apache's (the panel sees no nginx), and its
  # WAF rules in ModSecurity 2 form.
  run runuser -u snpanel -- env HOME="$APP_DIR" SNPANEL_USE_HELPER=true \
    "$API_BIN" --env "$ENV_FILE" --refresh-sites || warn "--refresh-sites báo lỗi ở vài site; xem log"
  run httpd -t
  run systemctl reload httpd
  # A machine already live on a web server keeps it; a fresh one goes to Apache.
  live="$(cat /var/lib/snpanel/webserver 2>/dev/null || true)"
  run /usr/local/sbin/snpanel-webswitch "${live:-apache}"
  systemctl enable snpanel-webswitch-restore.service >/dev/null 2>&1 || true
  run systemctl enable --now snpanel-webswitch-restore.timer
  # The tools vhost and phpMyAdmin's address, from the panel's own URL.
  read -r scheme host port < <(panel_url_parts)
  [[ -n "$host" ]] && run "$HELPER" panel-url-set "$scheme" "$host" "$port" || warn "Không đọc được PANEL_URL; vào panel đặt lại URL panel một lần"
  # PHP-FPM (Remi) is no longer what serves PHP.
  for f in $(systemctl list-unit-files --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$f" >/dev/null 2>&1 || true
    systemctl mask "$f" >/dev/null 2>&1 || true
  done
  sleep 2
  after="$(site_codes 80)"
  log "Mã HTTP từng site (trước -> sau):"
  join <(sort <<<"$before") <(sort <<<"$after") | awk '{flag = ($2 == $3) ? "" : "   <- khác"; printf "    %-40s %s -> %s%s\n", $1, $2, $3, flag}' | tee -a "$LOG_FILE"
}

# =============================================================================
# 10. Each website's PHP version: the account's, or its own (MultiPHP)
# =============================================================================
sitephp_done() { [[ -f "$STATE_DIR/site-php.done" ]]; }
sitephp_run() {
  if ! api_login; then
    warn "Bỏ qua bước này. Chạy lại với SNPANEL_ADMIN_PASSWORD=... khi sẵn sàng, hoặc vào Websites đặt PHP cho từng site."
    return 0
  fi
  local sites="$STATE_DIR/websites.json"
  ( umask 077; api GET /websites >"$sites" )
  python3 - "$sites" <<'PY' | while IFS=$'\t' read -r id domain user target; do
import json, subprocess, sys
sites = json.load(open(sys.argv[1]))
cache = {}
def account(u):
    if u not in cache:
        out = subprocess.run(["cloudlinux-selector", "get", "--json", "--interpreter", "php", "--user", u],
                             capture_output=True, text=True).stdout
        try:
            cache[u] = json.loads(out).get("selected_version")
        except Exception:
            cache[u] = None
    return cache[u]
for s in sites:
    if s.get("app_type") not in ("php", "wordpress") or not s.get("linux_user"):
        continue
    own = s.get("php_version") or ""
    target = "inherit" if own in ("", account(s["linux_user"])) else own
    print(f'{s["id"]}\t{s["domain"]}\t{s["linux_user"]}\t{target}')
PY
    local got
    got="$(api PATCH "/websites/$id" "{\"php_version\": \"$target\"}" | python3 -c 'import json,sys
try: d=json.load(sys.stdin); print(d.get("php_version", d.get("detail","?")))
except Exception: print("?")')"
    info "$domain ($user): $target -> ${got:-?}"
  done
  rm -f "$sites"
  touch "$STATE_DIR/site-php.done"
}

# =============================================================================
# 11. MySQL Governor (observe only), and its database-user map
# =============================================================================
governor_done() {
  [[ "$GOVERNOR" == 0 ]] && return 0
  rpm -q governor-mysql >/dev/null 2>&1 && systemctl is-active --quiet db_governor || return 1
  same_file snpanel-dbuser-map /usr/local/sbin/snpanel-dbuser-map || return 1
  systemctl is-enabled --quiet snpanel-dbuser-map.timer
}
governor_run() {
  local bdir ver
  bdir="$(cat "$STATE_DIR/backup.done" 2>/dev/null || echo "$BACKUP_ROOT")"
  if ! rpm -q governor-mysql >/dev/null 2>&1 || ! systemctl is-active --quiet db_governor; then
    if [[ -z "$GOVERNOR_MYSQL" ]]; then
      ver="$(mariadb -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-MariaDB' | head -n1 | cut -d. -f1,2)"
      [[ -n "$ver" ]] || die "Không đọc được phiên bản MariaDB; dùng --governor-mysql mariadbXXYY"
      GOVERNOR_MYSQL="mariadb${ver/./}"
    fi
    confirm GOVERNOR "Cài MySQL Governor thay MariaDB bằng bản của CloudLinux ($GOVERNOR_MYSQL): site dùng database lỗi khoảng 1-2 phút."
    info "Dump toàn bộ database vào $bdir/pre-governor.sql"
    mysqldump --all-databases --single-transaction --routines --events >"$bdir/pre-governor.sql"
    chmod 600 "$bdir/pre-governor.sql"
    run dnf -y install governor-mysql
    run /usr/share/lve/dbgovernor/mysqlgovernor.py --mysql-version="$GOVERNOR_MYSQL"
    run /usr/share/lve/dbgovernor/mysqlgovernor.py --install --yes
  fi
  install_file snpanel-dbuser-map /usr/local/sbin/snpanel-dbuser-map 0755
  install_file snpanel-dbuser-map.service /etc/systemd/system/snpanel-dbuser-map.service 0644
  install_file snpanel-dbuser-map.timer /etc/systemd/system/snpanel-dbuser-map.timer 0644
  systemctl daemon-reload
  run /usr/local/sbin/snpanel-dbuser-map
  run systemctl enable --now snpanel-dbuser-map.timer
  # Installed, it restricts "abusers" at once; observe until limits are set.
  run dbctl --lve-mode off
}

# =============================================================================
main() {
  log "${C_B}SNPanel Hosting Edition - bước 1: CloudLinux$([[ "$CHECK" == 1 ]] && echo ' (chỉ kiểm tra)')${C_0}"
  preflight
  step backup      "Sao lưu cấu hình và database panel"
  step convert     "Convert AlmaLinux 10 -> CloudLinux 10 (cldeploy)"
  if [[ "$CHECK" == 0 ]] || lve_loaded; then
    step lve       "Kernel LVE đã nạp (sau khi khởi động lại)"
  fi
  step packages    "Cài Apache, mod_lsapi, ModSecurity, CageFS, alt-php $(php_versions | tr '\n' ' ')"
  step php         "PHP Selector, CageFS và PHP native $DEFAULT_PHP"
  step apache      "Apache trên 8080/8443 (chạy song song nginx)"
  step integration "Tích hợp CloudLinux: CPAPI, D-Bus, CloudLinux Manager trong panel"
  step accounts    "Đưa tài khoản vào CageFS, đặt phiên bản PHP cho từng tài khoản"
  step webscripts  "Script chuyển web server (snpanel-webswitch) và timer giữ chuyển hướng 80/443"
  step cutover     "Chuyển web từ nginx sang Apache (80/443)"
  step sitephp     "Phiên bản PHP riêng cho từng website (MultiPHP)"
  step governor    "MySQL Governor (chế độ quan sát) và dbuser-map"
  if [[ "$CHECK" == 1 ]]; then
    log ""
    [[ "$PENDING" == 0 ]] && log "${C_OK}Máy đã ở bước 1 (CloudLinux) đầy đủ.${C_0}" || log "Còn $PENDING bước chưa làm."
    return 0
  fi
  log ""
  log "${C_OK}${C_B}Xong bước 1.${C_0} Máy chạy CloudLinux + Apache; nginx và PHP-FPM đã tắt."
  log "  - Vào panel: Services, Websites, Settings > CloudLinux Manager."
  log "  - Bước 2 (LiteSpeed Enterprise): bash $(dirname "$0")/install-litespeed.sh --serial <SERIAL> (hoặc --trial)"
  log "  - Sao lưu trước khi nâng cấp: $(cat "$STATE_DIR/backup.done" 2>/dev/null)"
}
main
