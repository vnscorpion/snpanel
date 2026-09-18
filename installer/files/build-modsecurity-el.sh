#!/bin/bash
# Build the nginx ModSecurity module from source on AlmaLinux 10.
#
# This is the trial the user asked for: on this container only, not in the
# installer. It is written to be reversible and to fail safe - the load_module
# directive is only written after the module builds, and it is removed again if
# `nginx -t` rejects it, because an nginx that will not start is a worse
# outcome than an nginx with no WAF.
#
# Version matching matters: a dynamic module is tied to the nginx it was built
# against. The distribution nginx is built --with-compat, which is what makes a
# third-party module loadable at all, and the source used here is the same
# version. An nginx update to a different version will need a rebuild - which
# is exactly the risk that kept this out of the installer.
set -uo pipefail

LOG=/root/modsec-build.log
exec > >(tee -a "$LOG") 2>&1
echo "=== started $(date -Is) ==="

NGINX_VER="$(nginx -v 2>&1 | sed 's#.*/##')"
MODSEC_VER=3.0.14
WORK=/root/modsec-build
mkdir -p "$WORK"
cd "$WORK"

echo
echo "=== 1. build dependencies ==="
# zlib is zlib-ng on EL10, under a compat name; yajl is only needed for the
# JSON audit log, which the panel does not use, so it is not required here.
deps=(gcc gcc-c++ make automake autoconf libtool pkgconf-pkg-config
      pcre2-devel openssl-devel libxml2-devel libcurl-devel lmdb-devel
      git wget tar)
for candidate in zlib-ng-compat-devel zlib-devel; do
  if dnf -q info "$candidate" >/dev/null 2>&1; then deps+=("$candidate"); break; fi
done
dnf -y install "${deps[@]}" >/dev/null 2>&1 || { echo "FAILED: build dependencies"; exit 1; }
echo "  installed: ${deps[*]}"

echo
echo "=== 2. libmodsecurity ${MODSEC_VER} ==="
if [[ ! -f /usr/local/modsecurity/lib/libmodsecurity.so ]]; then
  url="https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${MODSEC_VER}/modsecurity-v${MODSEC_VER}.tar.gz"
  [[ -f "modsecurity-v${MODSEC_VER}.tar.gz" ]] || curl -fsSL --max-time 600 -o "modsecurity-v${MODSEC_VER}.tar.gz" "$url" \
    || { echo "FAILED: download libmodsecurity"; exit 1; }
  rm -rf "modsecurity-v${MODSEC_VER}"
  tar xzf "modsecurity-v${MODSEC_VER}.tar.gz"
  cd "modsecurity-v${MODSEC_VER}"
  # --without-lmdb and friends keep the dependency surface small; the panel
  # uses none of the optional back ends.
  ./configure --prefix=/usr/local/modsecurity --with-pcre2 --without-lmdb >/dev/null 2>&1 \
    || { echo "FAILED: configure libmodsecurity"; tail -20 config.log; exit 1; }
  echo "  configured; compiling (this is the slow part)"
  make -j"$(nproc)" >/dev/null 2>&1 || { echo "FAILED: make libmodsecurity"; exit 1; }
  make install >/dev/null 2>&1 || { echo "FAILED: make install libmodsecurity"; exit 1; }
  cd "$WORK"
fi
ls -la /usr/local/modsecurity/lib/libmodsecurity.so* | head -3 | sed 's/^/  /'

echo
echo "=== 3. nginx ${NGINX_VER} source and the connector ==="
[[ -f "nginx-${NGINX_VER}.tar.gz" ]] || curl -fsSL --max-time 300 -o "nginx-${NGINX_VER}.tar.gz" \
  "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" || { echo "FAILED: download nginx source"; exit 1; }
rm -rf "nginx-${NGINX_VER}" ModSecurity-nginx
tar xzf "nginx-${NGINX_VER}.tar.gz"
git clone -q --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git \
  || { echo "FAILED: clone the connector"; exit 1; }
echo "  nginx-${NGINX_VER} and ModSecurity-nginx ready"

echo
echo "=== 4. building the dynamic module ==="
cd "nginx-${NGINX_VER}"
# --with-compat is what makes the module loadable by the distribution's nginx.
# Nothing else from its configure line matters for a dynamic module.
./configure --with-compat --add-dynamic-module=../ModSecurity-nginx \
  --with-cc-opt="-I/usr/local/modsecurity/include" \
  --with-ld-opt="-L/usr/local/modsecurity/lib" >/dev/null 2>&1 \
  || { echo "FAILED: configure nginx module"; tail -20 objs/autoconf.err 2>/dev/null; exit 1; }
make modules >/dev/null 2>&1 || { echo "FAILED: make modules"; exit 1; }
ls -la objs/ngx_http_modsecurity_module.so | sed 's/^/  /'

echo
echo "=== 5. installing it, reversibly ==="
install -m 0755 objs/ngx_http_modsecurity_module.so /usr/lib64/nginx/modules/
# The library lives outside the default search path, so tell the loader.
echo /usr/local/modsecurity/lib >/etc/ld.so.conf.d/modsecurity.conf
ldconfig

conf=/usr/share/nginx/modules/50-mod-http-modsecurity.conf
echo 'load_module "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so";' >"$conf"
if nginx -t >/dev/null 2>&1; then
  echo "  nginx accepts the module"
else
  echo "  nginx REJECTED it - removing the directive so nginx still starts:"
  nginx -t 2>&1 | tail -3 | sed 's/^/    /'
  rm -f "$conf"
  exit 1
fi

echo
echo "=== 6. the base configuration the rules need ==="
install -d -m 0755 /etc/modsecurity
if [[ ! -f /etc/modsecurity/modsecurity.conf ]]; then
  cp "$WORK/modsecurity-v${MODSEC_VER}/modsecurity.conf-recommended" /etc/modsecurity/modsecurity.conf
  cp "$WORK/modsecurity-v${MODSEC_VER}/unicode.mapping" /etc/modsecurity/ 2>/dev/null || true
  sed -i -E 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
fi
echo "  /etc/modsecurity/modsecurity.conf: SecRuleEngine $(sed -n 's/^SecRuleEngine //p' /etc/modsecurity/modsecurity.conf)"

echo
echo "=== 7. the OWASP Core Rule Set ==="
CRS_VER=4.10.0
if [[ ! -d /usr/share/modsecurity-crs/rules ]]; then
  curl -fsSL --max-time 300 -o crs.tar.gz \
    "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VER}.tar.gz" \
    || { echo "  WARNING: could not download CRS; the engine still works with the panel's own rules"; }
  if [[ -f crs.tar.gz ]]; then
    rm -rf "coreruleset-${CRS_VER}"
    tar xzf crs.tar.gz
    install -d -m 0755 /usr/share/modsecurity-crs
    cp -a "coreruleset-${CRS_VER}/rules" /usr/share/modsecurity-crs/
    cp -a "coreruleset-${CRS_VER}/crs-setup.conf.example" /usr/share/modsecurity-crs/crs-setup.conf
    # The CRS ships two data files the rules include by name.
    cp -a "coreruleset-${CRS_VER}"/rules/*.data /usr/share/modsecurity-crs/rules/ 2>/dev/null || true
  fi
fi
if [[ -d /usr/share/modsecurity-crs/rules ]]; then
  echo "  CRS rules: $(ls /usr/share/modsecurity-crs/rules/*.conf 2>/dev/null | wc -l) files"
else
  echo "  CRS not installed"
fi

echo
echo "=== 8. reloading nginx ==="
nginx -t 2>&1 | tail -2 | sed 's/^/  /'
systemctl reload nginx && echo "  reloaded"
echo
echo "=== finished $(date -Is) ==="
