# SNPanel

**English** | [Tiếng Việt](README.vi.md)

SNPanel is a lightweight hosting control panel for Ubuntu, Debian and
AlmaLinux. It runs WordPress and PHP websites from one clean web interface -
accounts and packages, quotas, backups, SSL, a firewall and a WAF built in.
It is written in Rust: one binary serves the panel, and a small root helper
does the privileged work behind it.

## Features

**Websites**

- WordPress one-click installer with WP-CLI; PHP 8.4 by default with 8.3
  beside it, and more versions installable from the panel
- WordPress and PHP sites, each with an editable nginx vhost
- Let's Encrypt SSL through certbot
- A file manager: upload, edit, archive and extract
- MariaDB databases with phpMyAdmin single sign-on (60-second tokens); a
  database belongs to a panel user and travels with them in their backups
- A cron manager with whitelisted WP-CLI commands
- A terminal per site, running allowlisted commands as the site's own Linux
  user

**Accounts**

- Two roles: administrator and end user (customer)
- Every panel user is a Linux user with an SFTP login chrooted to their home;
  websites live in `/home/<user>/<domain>/public_html`
- Website limits, storage quotas and reusable packages per user
- Administrators can sign in as a customer to create sites for them, and move
  a website to another owner
- Two-step sign-in with a passkey, an authenticator-app code (TOTP), or both

**Backups**

- Site files and their databases; scheduled full-user backups; restore,
  upload and download
- Copies off the server to SFTP servers and S3 buckets - AWS S3, Cloudflare
  R2, Backblaze B2, Wasabi, MinIO or any S3-compatible store
- Archives named by date and time, by user name, by weekday or by date, each
  kept as long as its schedule says

**Security**

- An nftables firewall: the panel, web and mail ports always open, allow and
  deny rules per address, and URL blocklists loaded into nftables sets
- An nginx ModSecurity WAF with the panel's WordPress, Laravel and PHP rules
  and the OWASP Core Rule Set, switched per site; HTTP flood limits and bot
  blocking
- Malware scanning: ClamAV checks uploads as they arrive, and Linux Malware
  Detect scans a site, every site or the whole machine, on demand or on a
  schedule, moving what it finds to quarantine

**Server**

- A dashboard: CPU, RAM, disk and network; a card for each area, green, amber
  or red; and what needs attention, worst first, with the way to fix it
- PHP settings per version, and PHP extensions installed or removed from the
  page - redis, imagick, memcached, mongodb, apcu, xdebug and more
- PHP-FPM and MariaDB tuned to the machine's RAM and CPU
- Services at a glance, with restart; OS updates through apt or dnf, now or
  automatically; SNPanel updates from its releases
- English and Vietnamese, switched from the header - pages and server
  messages alike

**Addons**, installed from Settings > Addons

- **Applications**: Node.js apps, Docker containers and Compose projects, each
  on its own port with its own memory limit, served on a domain through nginx
- **Fail2ban**: SSH, panel sign-ins, WordPress sign-ins, password-protected
  folders and repeat offenders, banned in nftables; Cloudflare's addresses are
  never banned from a site's log
- **AI assistants (MCP)**: 32 tools for Claude Code, Cursor, VS Code and any
  other MCP client at `/api/mcp`, over the websites, files, logs, backups,
  firewall and WAF. Each assistant has a token of the account it acts for,
  read-only unless allowed to act, and every action is in the audit log
- **Notifications**, for administrators: e-mail through your SMTP server and
  Telegram through your bot - failed backups, malware, expiring certificates,
  a filling disk, a stopped service, a new release, and sign-ins and changes
  to administrator accounts

## Requirements

- A clean server running Ubuntu 24.04 LTS, Debian 13 or AlmaLinux 10, with
  root access
  - Debian 13 has the most PHP versions: 7.4 to 8.5, from packages.sury.org
  - On AlmaLinux the installer enables EPEL and Remi, and PHP comes from Remi.
    The nginx ModSecurity engine is not packaged there, so the WAF page offers
    HTTP flood limits and bot blocking only. SELinux is not configured by the
    installer.
  - Ubuntu 26.04 is not supported yet: the PHP repository for Ubuntu does not
    publish for it, which leaves only the distribution's PHP 8.5
  - Debian 12 is accepted by the installer, but not tested as thoroughly
- 1 vCPU and 1 GB RAM at least; 2 vCPU and 2 GB RAM recommended
- Optional: a domain pointing at the server, for the panel's own SSL

## Installation

Run as root on a fresh server:

```bash
curl -fsSL https://raw.githubusercontent.com/vnscorpion/snpanel/refs/heads/main/install.sh | bash
```

The script installs the newest release. It asks for:

- the panel hostname - optional; left blank, the panel uses the server's IP
- the panel port - `2222` by default; the firewall opens only that port for
  the panel
- whether to issue Let's Encrypt SSL for the panel hostname, and an e-mail
  address for it

It installs nginx, MariaDB, Redis, OpenSSH/SFTP, PHP 8.4 and 8.3, Node.js,
certbot, phpMyAdmin, WP-CLI and nftables; creates the `snpanel` service
account, the `admin` account and the `snpanel-api` service; tunes PHP-FPM
and MariaDB to the machine; and prints the panel's address, user and
password, which are also saved to `/root/login.txt`. Keep the password in a
password manager.

The panel answers on every domain hosted on the server: it keeps a
certificate for each and picks one per connection, so
`https://<any hosted domain>:<panel port>` opens it with a certificate the
browser accepts. `snpanel login` lists those addresses.

To check an installation, run `xtask acceptance` as root on the server: it
creates a throwaway website, checks that PHP runs through nginx and that the
WAF reports honestly, and removes the site again.

## Updating

From the panel's **Updates** page, or over SSH:

```bash
snpanel-update --release      # the newest release
snpanel-update --tag v1.0.0   # a particular release
```

If the browser still shows the old interface afterwards, reload with
Ctrl + Shift + R.

## Rescue over SSH

`snpanel`, run as root, opens a menu for when the web panel cannot be
reached: the saved login, recent logs, restarting the panel, reopening the
firewall's ports, resetting the panel's address and port, repairing its SSL,
fixing permissions, changing the admin password and updating.

```bash
snpanel change-ip OLD_IP NEW_IP      # the server's IP address changed
snpanel change-admin-password
snpanel sync-admin-root-password     # the admin password becomes root's
snpanel reset-admin-2fa              # the authenticator or passkey is lost
snpanel-rescue-firewall              # locked out: back up the rules, rebuild with the protected ports only
```

## Where things are

| | |
|---|---|
| Program | `/opt/snpanel` |
| Configuration | `/opt/snpanel/backend/.env`, `/etc/snpanel` |
| State | `/var/lib/snpanel` |
| Backups | `/var/backups/snpanel` |
| Websites | `/home/<user>/<domain>/public_html` |
| System user | `snpanel` |
| Services | `snpanel-api`, `snpanel-helper` |
| Logs | `journalctl -u snpanel-api` |

```bash
systemctl restart snpanel-api
systemctl status snpanel-api nginx mariadb redis-server php8.3-fpm php8.4-fpm
nginx -t && systemctl reload nginx
```

## Firewall

Filtering runs on nftables, in a table of the panel's own (`inet snpanel`).
`/var/lib/snpanel/firewall/rules.tsv` holds the rules; every change renders
the whole table, checks it with `nft --check` and loads it at once, and
`snpanel-firewall.service` loads it again at boot, before the network and
nginx.

- The SSH port, the panel port and 80, 443, 465 and 587 are always open, and
  cannot be closed from the panel.
- Allow and deny rules, with or without a port, are elements of nftables
  sets; allow rules are checked first.
- URL blocklists are fetched daily into sets of their own, IPv4 and IPv6: a
  list of a million addresses costs one lookup per packet.
- Allowed traffic leaves the table with `return`, not `accept`, so fail2ban
  and any other rules on the machine still see it.
- Turning the firewall off removes the panel's table and nothing else.

An older install that filtered with UFW, iptables or an nginx `geo`
blocklist has its rules carried over when it updates. If no firewall was
active there, the rules are staged but not enforced until it is turned on
from the Firewall page.

## Accounts, ownership and quotas

| Role | Can |
|------|-----|
| `admin` | Everything: websites, users and their packages, ownership, services, the firewall, PHP, backups and the panel's settings |
| `end_user` | Its own websites and their files, databases, SSL, WordPress tools and cron, and its own backups |

- A panel user's Linux account has the same name, and is its SFTP login,
  chrooted to its home - `admin` is `/home/admin`. The SFTP password follows
  the panel password, unless an administrator turns SFTP off for the user or
  gives it a password of its own; users see their SFTP details, and can
  change the password, on their Account security page.
- These accounts are in the `snpanel-sftp` group: SFTP only - no shell, no
  terminal, no forwarding.
- Every database has an owner. An administrator can create one for any user,
  and change its owner and website; moving a website to another user takes
  its databases along, and moves its files and its PHP-FPM and nginx
  configuration.
- Deleting a user deletes everything it owns: websites, files, databases,
  cron jobs, PHP-FPM pools and its Linux account.
- An end user has a website limit and a storage limit in MB, counted over all
  its websites and checked before anything that writes - creating a site,
  uploading, editing, archiving, extracting, taking over a site. It is the
  panel's own quota, not a disk quota; administrators have none.

## Configuration

The installer writes `/opt/snpanel/backend/.env`:

```ini
APP_ENV=production
SECRET_KEY=<random, 32 bytes or more>
COMMAND_DRY_RUN=false
DATABASE_URL=sqlite:////opt/snpanel/backend/snpanel.db
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_BACKEND=redis
ALLOWED_ORIGINS=https://panel.example.com
BACKUP_ROOT=/var/backups/snpanel
SSL_EMAIL=admin@example.com
PANEL_URL=http://SERVER_IP:2222
PANEL_DOMAIN=
PANEL_PORT=2222
PANEL_SSL_CERT=                   # the certificate for names that have none of their own
PANEL_SSL_KEY=
PANEL_SNI_DIR=/etc/snpanel/sni    # one certificate per hostname
FRONTEND_DIST=/opt/snpanel/frontend/dist
```

In production the panel refuses to start with `COMMAND_DRY_RUN=true`,
`ALLOWED_ORIGINS=*` or a `SECRET_KEY` shorter than 32 characters.

**PHP-FPM and MariaDB tuning.** Every PHP site has a PHP-FPM pool of its own
(`ondemand`), sized from the machine's RAM, CPU count and number of pools;
MariaDB gets `/etc/mysql/mariadb.conf.d/90-snpanel-tuning.cnf`, sized from RAM
and CPU, leaving room for nginx, PHP-FPM, Redis and the panel. To override,
add any of these to `.env`, then retune:

```ini
SNPANEL_PHP_FPM_WORKER_MB=128
SNPANEL_PHP_FPM_MAX_CHILDREN=
SNPANEL_PHP_FPM_IDLE_TIMEOUT=
SNPANEL_PHP_FPM_MAX_REQUESTS=
SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT=300
SNPANEL_MARIADB_BUFFER_POOL_SIZE=
SNPANEL_MARIADB_MAX_CONNECTIONS=
SNPANEL_MARIADB_THREAD_CACHE_SIZE=
SNPANEL_MARIADB_TABLE_OPEN_CACHE=
SNPANEL_MARIADB_TMP_TABLE_SIZE=
SNPANEL_MARIADB_MAX_ALLOWED_PACKET=
SNPANEL_MARIADB_LOG_FILE_SIZE=
SNPANEL_MARIADB_IO_CAPACITY=
SNPANEL_MARIADB_OPEN_FILES_LIMIT=
```

```bash
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper php-fpm-retune
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper mariadb-retune
```

## Security model

The panel does not run as root. `snpanel-api` runs as the `snpanel` system
user in a hardened systemd unit, and asks a root helper for everything
privileged:

```
snpanel-api      (user snpanel, hardened systemd unit)
   |  /run/snpanel/helper.sock - typed requests; the caller checked by SO_PEERCRED
   v
snpanel-helper   (root; answers its own list of operations, and nothing else)
```

The helper validates every domain, port, address and path before it runs
anything: services from a whitelist, `nginx -t` and reload, certbot for one
checked domain, panel users and their PHP-FPM pools, firewall rules, the
ownership of site paths under `/home`, WP-CLI and cron as the site's user,
and the terminal's allowlisted commands. Were the API itself compromised, it
could write only to nginx's `conf.d`, managed site paths and the backups
folder, and ask the helper for those operations - there is no way from it to
root.

The terminal runs commands without a shell - `;`, `|`, backticks and globs are
plain arguments - checks that every path stays in the user's home, runs PHP
tools with the site's PHP version, and stops a command at 60 seconds, or 900
for installers such as `composer`, `npm`, `wp` and `git`. Its allowlist is a
guardrail rather than a boundary: sites are kept apart by their own Linux
users, chrooted homes, PHP-FPM `open_basedir` and the helper's path checks.

- Sign-in is rate-limited in Redis - 8 attempts a minute, locked after 20
  failures - and takes the same time whether the user exists or not.
- Sessions are HttpOnly cookies (`snpanel_session`) with a CSRF token
  (`snpanel_csrf`) echoed in the `X-CSRF-Token` header; the token is never
  exposed to JavaScript. A password, role or two-step change, disabling an
  account or signing out revokes the sessions issued before it.
- A strict Content-Security-Policy (`script-src 'self'`,
  `frame-ancestors 'none'`).
- Database and WordPress passwords reach commands on stdin, never on the
  command line; database passwords are encrypted at rest.
- Custom nginx blocks are checked: balanced braces, at most 16 KB, and no
  `server`, `http`, `include`, `load_module`, `proxy_pass`, `alias`, log or
  `ssl_*` directives.
- The file manager refuses symlinks anywhere in a path, and paths that leave
  the site.
- In a site, files are `644` and folders `755`; `wp-config.php`, `.env` and
  `.my.cnf` are kept at `640`.

## Provisioning API (WHMCS)

The WHMCS server module in `modules/servers/snpanel/` creates and manages
panel accounts over the provisioning API, with a Bearer token made on the
API tokens tab of Panel settings and pasted into the server's Access Hash.
The module is shared with OPanel, so SNPanel answers the way the module
expects.

| WHMCS | Endpoint |
|---|---|
| `TestConnection`, `PackageLoader` | `GET /plans` |
| `CreateAccount` | `POST /accounts` |
| `SuspendAccount` | `POST /accounts/{external_id}/suspend` |
| `UnsuspendAccount` | `POST /accounts/{external_id}/unsuspend` |
| `TerminateAccount` | `DELETE /accounts/{external_id}` |
| `ChangePassword` | `PATCH /accounts/{external_id}/password` |
| `ChangePackage` | `PATCH /accounts/{external_id}/package` |
| `UsageUpdate` | `GET /accounts/{external_id}/usage` |
| `LoginLink`, `ClientArea` | `POST /accounts/{external_id}/login` |

- `external_id` is `whmcs:<serviceid>`, so a service is one panel account
  across renames.
- SNPanel answers with bare objects - never one carrying both `success` and
  `data`, which the module would unwrap.
- Single sign-on returns `login_url`, an absolute address on the hostname the
  call came to (or `PANEL_URL`), good once for 5 minutes. A suspended account
  lands on `/?error=account_suspended` instead.
- Suspending disables the panel login, ends the account's sessions, serves
  each of its websites as a "suspended" page and locks their Linux users;
  unsuspending puts everything back.
- Terminating takes no backup unless asked with `?backup=true`, which writes a
  full backup to `/var/backups/snpanel` first; a failed backup never blocks
  the termination. The billing row stays, emptied, so the client area can
  still show the service.

## Development

- **Panel**: Rust - axum, rustls, sqlx (SQLite), tokio; one static binary
  serves the API and the interface over TLS on the panel port
- **Helper**: Rust, root, behind a Unix socket that checks its caller
- **Interface**: React 18, Vite, lucide-react
- **Server**: nginx, OpenSSH/SFTP, ModSecurity, nftables, systemd, MariaDB,
  Redis (Valkey on AlmaLinux), PHP-FPM, certbot

```
snpanel/
|-- crates/
|   |-- snpanel-api/         the HTTP API and the panel's jobs
|   |-- snpanel-helper/      the privileged operations
|   |-- snpanel-ipc/         the protocol between the two
|   |-- snpanel-core/        configuration, cryptography, roles
|   |-- snpanel-db/          the database schema and queries
|   |-- snpanel-nginx/       vhost templates
|   |-- snpanel-osabi/       what differs between distributions
|   |-- snpanel-installer/   what the install and update scripts call
|   `-- snpanel-cli/         the `snpanel` command
|-- frontend/                the React interface
|-- installer/               install, update and firewall rescue scripts
|-- modules/servers/snpanel/ the WHMCS module
|-- xtask/                   build and verification tasks
`-- backend/                 on a server: `.env` and the SQLite database
```

## Versioning

SNPanel uses semantic versioning (`major.minor.patch`). The current release
is `1.0.0`.

## License

MIT.
