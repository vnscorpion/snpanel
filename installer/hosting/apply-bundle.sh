#!/usr/bin/env bash
# Put a Hosting Edition bundle (make-bundle.sh) on this server.
#
#   tar -xzf snpanel-hosting-*.tar.gz -C /root
#   bash /root/snpanel-hosting/installer/hosting/apply-bundle.sh
#
# A Standard machine (nginx, SNPanel 1.1.0 or later) is updated the way every
# release is: installer/update.sh from the bundle's source, with the bundle's
# binaries. A machine already on the Hosting Edition (no nginx) gets the
# binaries and the frontend only, because update.sh still assumes nginx.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

BUNDLE="$(cd "$HOSTING_DIR/../.." && pwd)"
SRC=/opt/snpanel-hosting-src
BIN="$BUNDLE/target/x86_64-unknown-linux-musl/release"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n 2,10p "$0"; exit 0 ;;
    *) die "Không hiểu tuỳ chọn: $1" ;;
  esac
  shift
done

need_root
[[ -f "$BUNDLE/SHA256SUMS" && -f "$BUNDLE/HOSTING_BUILD" ]] || die "$BUNDLE không phải một bundle Hosting Edition (thiếu SHA256SUMS)"
( cd "$BUNDLE" && sha256sum --quiet -c SHA256SUMS ) || die "Bundle không khớp SHA256SUMS: tải lại"
for b in snpanel-helper snpanel-extract snpanel-api snpanel snpanel-install; do
  [[ -x "$BIN/$b" ]] || die "Bundle thiếu binary $b"
done
[[ -f "$ENV_FILE" ]] || die "Chưa thấy SNPanel ở $APP_DIR: cài SNPanel 1.1.0 trước"
build="$(cat "$BUNDLE/HOSTING_BUILD")"

if [[ -x /usr/sbin/nginx ]]; then
  log "${C_B}Cập nhật SNPanel lên bản Hosting Edition ${build:0:10} (update.sh)${C_0}"
  [[ "$CHECK" == 1 ]] && { log "Máy Standard: sẽ chạy installer/update.sh --skip-pull từ $SRC"; exit 0; }
  confirm UPDATE "Cập nhật panel từ bundle này (panel khởi động lại vài lần, site không bị ảnh hưởng)."
  if [[ "$BUNDLE" != "$SRC" ]]; then
    rm -rf "$SRC.new"
    cp -a "$BUNDLE" "$SRC.new"
    rm -rf "$SRC"
    mv "$SRC.new" "$SRC"
  fi
  SOURCE_DIR="$SRC" run bash "$SRC/installer/update.sh" --skip-pull
else
  log "${C_B}Thay binary và frontend: bản Hosting Edition ${build:0:10}${C_0}"
  [[ "$CHECK" == 1 ]] && { log "Máy Hosting Edition: sẽ thay binary và build lại frontend"; exit 0; }
  confirm UPDATE "Thay binary panel và build lại frontend (panel khởi động lại, site không bị ảnh hưởng)."
  install -m 0755 -o root -g root "$BIN/snpanel-api" /usr/local/bin/snpanel-api-rust
  install -m 0750 -o root -g snpanel "$BIN/snpanel-helper" /usr/local/sbin/snpanel-helper
  install -m 0755 -o root -g root "$BIN/snpanel-extract" /usr/local/sbin/snpanel-extract
  install -m 0750 -o root -g root "$BIN/snpanel-install" /usr/local/sbin/snpanel-install
  install -m 0755 -o root -g root "$BIN/snpanel" /usr/local/sbin/snpanel
  ln -sfn /usr/local/sbin/snpanel /usr/local/sbin/snpanelctl
  ln -sfn /usr/local/sbin/snpanel /usr/local/sbin/snpanel-cli
  install -m 0644 "$BUNDLE/VERSION" "$APP_DIR/VERSION"
  # The frontend's source, then its build, as update.sh does.
  command -v rsync >/dev/null || run dnf -y install rsync
  run rsync -a --delete --exclude node_modules --exclude dist --exclude .vite \
    "$BUNDLE/frontend/" "$APP_DIR/frontend/"
  chown -R snpanel:snpanel "$APP_DIR/frontend"
  ( cd "$APP_DIR/frontend"
    [[ -d node_modules ]] || run runuser -u snpanel -- env HOME="$APP_DIR" npm install --no-audit --no-fund
    run runuser -u snpanel -- env HOME="$APP_DIR" VITE_API_URL=/api npm run build )
  chmod o+rX "$APP_DIR/frontend"; chmod -R o+rX "$APP_DIR/frontend/dist"
  run systemctl restart snpanel-helper.socket snpanel-helper.service
  run systemctl restart snpanel-api
fi
printf '%s\n' "$build" >"$STATE_DIR/hosting-build"
log "${C_OK}Panel đang chạy bản Hosting Edition ${build:0:10}.${C_0}"
log "  Tiếp theo: bash $HOSTING_DIR/upgrade-cloudlinux.sh --check"
