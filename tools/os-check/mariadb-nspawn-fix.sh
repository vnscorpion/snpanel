#!/bin/bash
# The container limit RUST_MIGRATION_STATUS.md records twice: under
# systemd-nspawn, mariadb-install-db run as root cannot drop to `mysql`, so the
# package's postinst leaves no system tables and the server aborts with
# "Table 'mysql.db' doesn't exist". Running the same tool already as `mysql`
# is the documented workaround. A real host never needs this.
#
# Then what the package's own postinst would have left: no anonymous accounts
# and no `test` database. mariadb-install-db's defaults create both, and an
# anonymous ''@localhost outranks 'site_user'@'%' for every local connection,
# which refuses every site's database login.
set -uo pipefail
if ! systemctl is-active --quiet mariadb; then
  if [ ! -f /var/lib/mysql/mysql/db.frm ] && [ ! -f /var/lib/mysql/mysql/db.MAD ]; then
    runuser -u mysql -- mariadb-install-db --datadir=/var/lib/mysql \
      --auth-root-authentication-method=socket --skip-test-db > /tmp/mariadb-install-db.log 2>&1
    echo "mariadb-install-db as mysql: rc=$?"
  fi
  systemctl start mariadb
fi
mariadb -e "DELETE FROM mysql.global_priv WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;"
echo "anonymous accounts left: $(mariadb -N -e "SELECT COUNT(*) FROM mysql.global_priv WHERE User=''")"
systemctl is-active mariadb
mariadb -e 'SELECT VERSION()' 2>&1 | tail -1
