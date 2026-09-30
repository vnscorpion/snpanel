#!/usr/bin/env bash
# SNPanel Hosting Edition, stage 2: LiteSpeed Enterprise in front, Apache as
# the hot standby.
#
#   Apache     Listen 8080/8443                      always running
#   LiteSpeed  reads Apache's config, offset +1000 -> 9080/9443, always running
#   nftables   inet snpanel_webfailover: 80/443 -> the live one
#   snpanel-webwatch: LiteSpeed down 3 s or its licence gone -> Apache
#
#   bash install-litespeed.sh --check
#   bash install-litespeed.sh --serial XXXX-XXXX-XXXX-XXXX   (or --trial)
#   bash install-litespeed.sh --remove        # back to Apache only (stage 1)
#
# Needs stage 1 (upgrade-cloudlinux.sh). Re-run it after any failure.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

LSWS_DIR=/usr/local/lsws
LSWS_CONF="$LSWS_DIR/conf/httpd_config.xml"
SERIAL="${LSWS_SERIAL:-}"
TRIAL=0
LSWS_VERSION="${LSWS_VERSION:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
REMOVE=0
FORCE=0
WORK="$STATE_DIR/lsws"

usage() {
  cat <<'EOF'
Usage: bash install-litespeed.sh [options]

  --check            Chỉ kiểm tra; không đổi gì.
  --serial SERIAL    Serial license LiteSpeed Enterprise (hoặc biến LSWS_SERIAL).
  --trial            Dùng license dùng thử 14 ngày thay cho serial.
  --version X.Y.Z    Bản LiteSpeed (mặc định: bản mới nhất).
  --email ADDR       Email quản trị cho LiteSpeed WebAdmin.
  --force            Vẫn chuyển 80/443 sang LiteSpeed khi có site trả mã khác Apache.
  --remove           Trả 80/443 về Apache, tắt LiteSpeed và watchdog (giữ file cài).
  --yes              Không hỏi xác nhận.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1 ;;
    --serial) SERIAL="${2:?}"; shift ;;
    --trial) TRIAL=1 ;;
    --version) LSWS_VERSION="${2:?}"; shift ;;
    --email) ADMIN_EMAIL="${2:?}"; shift ;;
    --force) FORCE=1 ;;
    --remove) REMOVE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Không hiểu tuỳ chọn: $1 (xem --help)" ;;
  esac
  shift
done

need_root

preflight() {
  is_cloudlinux && lve_loaded || die "Cần làm bước 1 trước (upgrade-cloudlinux.sh): máy chưa chạy CloudLinux"
  [[ -x /usr/sbin/httpd && ! -e /usr/sbin/nginx ]] || die "Cần làm xong bước 1 trước: Apache phải đang phục vụ, nginx đã gỡ"
  [[ -x /usr/local/sbin/snpanel-webswitch && -s /var/lib/snpanel/webserver ]] \
    || die "Thiếu snpanel-webswitch hoặc /var/lib/snpanel/webserver: chạy lại upgrade-cloudlinux.sh"
  systemctl is-active --quiet httpd || die "Apache (httpd) đang không chạy"
  curl -s -o /dev/null -m 5 -H 'Host: snpanel-default.invalid' \
    http://127.0.0.1:8080/.well-known/acme-challenge/snpanel-health \
    || die "Apache không trả lời trên 8080"
}

setting() { sed -n "s:.*<$1>\(.*\)</$1>.*:\1:p" "$LSWS_CONF" 2>/dev/null | head -n1; }

# =============================================================================
# 1. Install LiteSpeed Enterprise, reading Apache's configuration
# =============================================================================
install_done() { [[ -x "$LSWS_DIR/bin/lshttpd" && -f "$LSWS_CONF" ]]; }
install_run() {
  local v dir pass email
  [[ -n "$SERIAL" || "$TRIAL" == 1 ]] || die "Cần --serial SERIAL hoặc --trial"
  install -d -m 700 "$WORK"
  v="$LSWS_VERSION"
  if [[ -z "$v" ]]; then
    v="$(curl -fsS https://update.litespeedtech.com/ws/latest.php | head -n 1 | sed -nE 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')"
  fi
  [[ "$v" =~ ^[0-9]+(\.[0-9]+)+$ ]] || die "Không lấy được số phiên bản LiteSpeed (dùng --version)"
  info "LiteSpeed Enterprise $v"
  run curl -fsSLo "$WORK/lsws.tar.gz" "https://www.litespeedtech.com/packages/${v%%.*}.0/lsws-$v-ent-x86_64-linux.tar.gz"
  rm -rf "$WORK/lsws-$v"
  tar -xzf "$WORK/lsws.tar.gz" -C "$WORK"
  dir="$WORK/lsws-$v"
  [[ -f "$dir/install.sh" ]] || die "Gói LiteSpeed không có install.sh"
  if [[ "$TRIAL" == 1 ]]; then
    run curl -fsSLo "$dir/trial.key" https://license.litespeedtech.com/reseller/trial.key
  else
    ( umask 077; printf '%s\n' "$SERIAL" >"$dir/serial.no" )
  fi
  # The installer asks its questions on stdin, and its `more ./LICENSE` eats
  # the answers: a `more` that is just `cat` goes first on the PATH.
  install -d -m 700 "$WORK/fakebin"
  printf '#!/bin/sh\ncat "$@"\n' >"$WORK/fakebin/more"; chmod 700 "$WORK/fakebin/more"
  pass="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
  email="${ADMIN_EMAIL:-root@$(hostname -f 2>/dev/null || hostname)}"
  # Licence, destination (default), admin user, password x2, email,
  # control panel 2 (DirectAdmin: read Apache's config), port offset 1000,
  # PHP suEXEC 2 (in the user's home only), then "Y" for the rest.
  ( umask 077; printf 'Yes\n\nadmin\n%s\n%s\n%s\n2\n1000\n2\nY\nY\nY\nY\n' "$pass" "$pass" "$email" >"$WORK/answers" )
  ( cd "$dir" && PATH="$WORK/fakebin:$PATH" bash ./install.sh <"$WORK/answers" ) 2>&1 | tee -a "$LOG_FILE" \
    | grep -v -i password || true
  shred -u "$WORK/answers" 2>/dev/null || rm -f "$WORK/answers"
  [[ -x "$LSWS_DIR/bin/lshttpd" ]] || die "Cài LiteSpeed không thành công (xem $LOG_FILE)"
  # Under systemd, never in some other process's cgroup: started from the
  # helper, it died with the helper's next restart (d921b28).
  "$LSWS_DIR/bin/lswsctrl" stop >/dev/null 2>&1 || true
  systemctl daemon-reload
  # On the terminal only, never into the log.
  printf '  Mật khẩu LiteSpeed WebAdmin (user admin), chỉ hiện một lần: %s\n' "$pass"
  log "  Đổi lại bất cứ lúc nào: panel > Services > Web server > mật khẩu mới."
}

# =============================================================================
# 2. Configuration: Apache mode, offset 1000, LVE, CageFS
# =============================================================================
config_done() {
  [[ "$(setting loadApacheConf)" == 1 && "$(setting apachePortOffset)" == 1000 ]] || return 1
  [[ "$(setting apacheConfFile)" == /etc/httpd/conf/httpd.conf ]] || return 1
  grep -q '<enableLVE>2</enableLVE>' "$LSWS_CONF" || return 1
  grep -qx '/usr/local/lsws' /etc/cagefs/cagefs.mp || return 1
  same_file snpanel-weblogs.conf /etc/systemd/system/lshttpd.service.d/snpanel-weblogs.conf || return 1
  systemctl is-active --quiet lshttpd
}
config_run() {
  cp -a "$LSWS_CONF" "$LSWS_CONF.snpanel-orig" 2>/dev/null || true
  sed -i -E 's#<loadApacheConf>[^<]*</loadApacheConf>#<loadApacheConf>1</loadApacheConf>#;
             s#<apachePortOffset>[^<]*</apachePortOffset>#<apachePortOffset>1000</apachePortOffset>#;
             s#<apacheConfFile>[^<]*</apacheConfFile>#<apacheConfFile>/etc/httpd/conf/httpd.conf</apacheConfFile>#' "$LSWS_CONF"
  # LVE for LiteSpeed's PHP processes; CloudLinux's own reconfigure sets
  # phpSuExec itself (to 1) whenever CageFS updates.
  grep -q '<enableLVE>' "$LSWS_CONF" \
    || sed -i 's#</httpServerConfig>#<enableLVE>2</enableLVE></httpServerConfig>#' "$LSWS_CONF"
  grep -qx '/usr/local/lsws' /etc/cagefs/cagefs.mp || echo '/usr/local/lsws' >>/etc/cagefs/cagefs.mp
  install_file snpanel-weblogs.conf /etc/systemd/system/lshttpd.service.d/snpanel-weblogs.conf 0644
  systemctl daemon-reload
  run cagefsctl --remount-all
  run systemctl enable lshttpd
  run systemctl restart lshttpd
  local i
  for i in $(seq 1 30); do
    curl -fs -o /dev/null -m 2 -H 'Host: snpanel-default.invalid' \
      http://127.0.0.1:9080/.well-known/acme-challenge/snpanel-health && break
    sleep 1
  done
}

# =============================================================================
# 3. Go live: 80/443 -> LiteSpeed, the watchdog on
# =============================================================================
site_codes() {
  local d
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    printf '%s %s\n' "$d" "$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Host: $d" "http://127.0.0.1:$1/" || true)"
  done < <(sqlite_ro "SELECT domain FROM websites ORDER BY id")
}
live_done() {
  [[ "$(cat /var/lib/snpanel/webserver 2>/dev/null)" == lsws ]] || return 1
  same_file snpanel-webwatch /usr/local/sbin/snpanel-webwatch || return 1
  systemctl is-active --quiet snpanel-webwatch
}
live_run() {
  local apache lsws diff scheme host port
  apache="$(site_codes 8080)"; lsws="$(site_codes 9080)"
  diff="$(join <(sort <<<"$apache") <(sort <<<"$lsws") | awk '$2 != $3')"
  if [[ -n "$diff" ]]; then
    log "Các site trả mã khác nhau (Apache 8080 / LiteSpeed 9080):"
    awk '{printf "    %-40s %s / %s\n", $1, $2, $3}' <<<"$diff" | tee -a "$LOG_FILE"
    [[ "$FORCE" == 1 ]] || die "Chưa chuyển 80/443. LiteSpeed vẫn chạy trên 9080 để kiểm tra; sửa rồi chạy lại, hoặc --force."
  fi
  curl -fs -o /dev/null -m 5 -H 'Host: snpanel-default.invalid' \
    http://127.0.0.1:9080/.well-known/acme-challenge/snpanel-health || die "LiteSpeed không trả lời trên 9080"
  install_file snpanel-webwatch /usr/local/sbin/snpanel-webwatch 0755
  install_file snpanel-webwatch.service /etc/systemd/system/snpanel-webwatch.service 0644
  systemctl daemon-reload
  run /usr/local/sbin/snpanel-webswitch lsws
  run systemctl enable --now snpanel-webwatch
  run systemctl enable httpd lshttpd
  # WebAdmin gets the panel's certificate (the helper copies it on this call).
  read -r scheme host port < <(panel_url_parts)
  [[ -n "$host" ]] && run "$HELPER" panel-url-set "$scheme" "$host" "$port" || true
}

remove() {
  log "${C_B}Trả 80/443 về Apache${C_0}"
  confirm APACHE "Tắt LiteSpeed và watchdog, Apache nhận lại 80/443 (không gián đoạn)."
  run /usr/local/sbin/snpanel-webswitch apache
  systemctl disable --now snpanel-webwatch lshttpd 2>&1 | tee -a "$LOG_FILE" || true
  log "${C_OK}Xong.${C_0} LiteSpeed vẫn cài ở $LSWS_DIR; chạy lại lệnh này không kèm --remove để bật lại."
}

main() {
  if [[ "$REMOVE" == 1 ]]; then remove; return; fi
  log "${C_B}SNPanel Hosting Edition - bước 2: LiteSpeed Enterprise$([[ "$CHECK" == 1 ]] && echo ' (chỉ kiểm tra)')${C_0}"
  preflight
  step install "Cài LiteSpeed Enterprise ($LSWS_DIR)"
  step config  "Cấu hình: đọc cấu hình Apache, offset 1000 (9080/9443), LVE, CageFS"
  step live    "LiteSpeed nhận 80/443, bật watchdog tự chuyển sang Apache"
  if [[ "$CHECK" == 1 ]]; then
    log ""
    [[ "$PENDING" == 0 ]] && log "${C_OK}LiteSpeed đang live, Apache dự phòng.${C_0}" || log "Còn $PENDING bước chưa làm."
    return 0
  fi
  log ""
  log "${C_OK}${C_B}Xong bước 2.${C_0} LiteSpeed nhận 80/443; Apache chạy dự phòng trên 8080/8443."
  log "  - Panel > Services: trạng thái web server, license, chuyển về Apache khi cần bảo trì."
  log "  - WebAdmin: https://<máy chủ>:7080 (mở cổng 7080 trong panel khi cần)."
}
main
