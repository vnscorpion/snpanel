# SNPanel

Lightweight hosting management panel for Ubuntu, Debian and AlmaLinux. SNPanel helps you run
WordPress and PHP websites from a single clean web UI with user
ownership, quotas, backups, SSL, services, and firewall tools built in.

> **SNPanel is a fork of [BPanel](https://github.com/BNIX-VN/bpanel), being
> rewritten in Rust, and it is not an upgrade of it.**
>
> A server running BPanel cannot update into SNPanel. The two install to
> different places, run under different system users and service names, and
> set different session cookies, so they share no file on disk:
>
> | | BPanel | SNPanel |
> |---|---|---|
> | install root | `/opt/bpanel` | `/opt/snpanel` |
> | configuration | `/etc/bpanel` | `/etc/snpanel` |
> | state | `/var/lib/bpanel` | `/var/lib/snpanel` |
> | system user | `bpanel` | `snpanel` |
> | services | `bpanel-api`, `bpanel-helper` | `snpanel-api`, `snpanel-helper` |
> | session cookie | `bpanel_session` | `snpanel_session` |
>
> The separation is deliberate: the two can sit on one machine without
> touching each other, and a BPanel server pointed at this repository by
> mistake cannot "update" itself into a layout it knows nothing about. There
> is no migration path today - moving an existing server means a fresh install
> and carrying the data across by hand.
>
> Version numbering restarts at `1.0.0` for the same reason. BPanel is at
> 1.0.134, so a BPanel machine that did somehow read this repository's tags
> would see a *lower* number and offer no update at all, which is the safe
> direction for that mistake to fail in.

- Dashboard resource monitoring for CPU, RAM, disk, and network throughput
- WordPress one-click installer (PHP 8.4 default, 8.3/8.4 supported) with WP-CLI
- WordPress and PHP sites with editable full Nginx vhosts
- Panel users map to Linux/SFTP users; website source lives in `/home/<panel-user>/<domain>/public_html`
- Admin quick-login for creating sites as a selected user, plus one-owner assignment per website
- Website count limits and SNPanel soft storage quotas per end user
- User packages for reusable website/storage limits on panel accounts
- MariaDB database creation and management with phpMyAdmin SSO (60s tokens)
- Let's Encrypt SSL via certbot
- Native SNPanel file manager with upload, edit, archive, and extract support
- Backups: archive site files + SQL, scheduled full-user backups, restore, upload, download
- Off-server copies to SFTP servers and to S3 buckets - AWS S3, Cloudflare R2,
  Backblaze B2, Wasabi, MinIO or any other S3-compatible store
- A schedule names its archives by date and time (every run kept, pruned to
  its retention), by the user name alone (each run replaces the last), by
  the day of the week (a week of copies) or by the date (one a day, pruned)
- An S3 bucket keeps as many of a schedule's archives as the server does; an
  SFTP server keeps every copy
- iptables + ipset firewall with protected panel/web/mail ports, per-IP allow/deny rules,
  and URL blocklists loaded straight into an ipset
- Update controls for apt-based OS packages and SNPanel source updates
- Nginx ModSecurity/WAF engine installed by default, using lightweight WordPress/Laravel/PHP rules, per-site toggles, and HTTP Flood limits
- PHP-FPM config editor per version
- Cron job manager with whitelisted WP-CLI commands
- Role-based access: Admin / End user
- An MCP addon for AI assistants - Claude Code, Cursor, VS Code - at `/api/mcp`:
  32 tools over the websites, files, logs, backups, firewall and WAF, each
  assistant with a token of the account it acts for (read-only unless made to
  allow actions), every action in the audit log
- Google Authenticator compatible 2FA
- English and Vietnamese, switched from the header - the pages and the server's
  messages alike; English is the source, Vietnamese its translation

## Tech stack

- Front door: Rust - axum, rustls, sqlx, tokio. Terminates TLS on the panel
  port, serves the routers it has ported, and forwards the rest to the Python
  process on loopback (the strangler pattern; see `RUST_MIGRATION_STATUS.md`)
- Backend: FastAPI, SQLAlchemy, SQLite (default), Pydantic v2
- Frontend: React 18, Vite, lucide-react
- Server: Nginx, OpenSSH/SFTP, ModSecurity/WAF, systemd, MariaDB, Redis, PHP-FPM, certbot

Both implementations share one SQLite file, one Redis, and one `SECRET_KEY`,
so a session started through either is valid through the other. The Rust side
is being grown router by router; nothing is switched over until it answers
byte-for-byte the same as the Python it replaces.

## Versioning

Current release: `1.0.0`.

SNPanel versions use semantic versioning: `major.minor.patch`, and the count
restarts at the fork rather than continuing BPanel's - see the note at the top
of this file for why that matters.

## System requirements

- Ubuntu 24.04 LTS, Debian 12 / 13, or AlmaLinux 10 (clean install recommended)
  - **Debian 13 carries the most PHP versions.** Its packages come from
    packages.sury.org, which publishes 7.4 through 8.5 for trixie, so the panel
    can offer more versions there than anywhere else.
  - **Ubuntu 26.04 is not supported.** It was ported and then withdrawn:
    Ondrej's PPA publishes no `resolute` suite, so the only PHP available on
    it is the distribution's 8.5. A panel that cannot install the PHP version
    a customer's site runs on is not support, and claiming it would mean the
    first honest test happened on somebody's server. This will be revisited
    when the PPA publishes for the release.
  - On AlmaLinux the installer enables EPEL and Remi, and PHP comes from
    Remi's `php83`/`php84` packages. Two panel features are unavailable
    there and say so rather than failing quietly: the nginx ModSecurity
    rule engine, which the distribution does not package at all, and
    installing an additional PHP version from the panel.
- Root access
- Optional: a domain pointing to the server's public IP (for SSL on the panel)
- 1 vCPU / 1 GB RAM minimum, 2 vCPU / 2 GB RAM recommended

## Fresh install

Run as root on a fresh Ubuntu, Debian or AlmaLinux server.

Single-command install:

```bash
curl -fsSL https://raw.githubusercontent.com/vnscorpion/snpanel/refs/heads/main/install.sh | bash
```

The bootstrap script downloads the newest semantic release tag from GitHub,
then runs the installer from that tag. It also copies `VERSION` into the
runtime root so the panel shows the installed release, not the fallback.

The installer will:

1. Install git, Nginx, MariaDB, Redis, OpenSSH/SFTP, PHP 8.4 default (8.3/8.4 supported), Node.js 22,
   certbot, phpMyAdmin, WP-CLI, iptables, ipset.
2. Copy source to `/opt/snpanel`, build the frontend, set up the Python venv.
3. Create the `snpanel` service account and the `admin` Linux/SFTP account.
4. Create the systemd service `snpanel-api`.
5. Configure phpMyAdmin SSO.
6. Auto-tune PHP-FPM and MariaDB from VPS RAM/CPU and keep that tuning on reboot.
7. Start the panel directly on the configured panel port without relying on Nginx for login.
8. Issue Let's Encrypt SSL for the panel domain (optional).
9. Install `/usr/local/sbin/snpanel-update` and `/usr/local/sbin/snpanel-rescue-firewall`.
10. Remove the extracted release source.
11. Print only the panel URL, user, and password; save the same fields to
   `/root/login.txt`.

You will be prompted for:

- Panel hostname (optional; blank uses the server IP)
- Panel port (default `2222`; the firewall opens only the selected panel port)
- Whether to enable Let's Encrypt SSL for the panel domain
- An email for SSL registration

After install, open the `Panel URL` printed at the end of the installer. The
admin password is shown there and saved to `/root/login.txt`; store it in a
password manager.

The panel is not tied to that one hostname. It holds a copy of every
certificate on the machine and picks one per TLS handshake (SNI), so
`https://<any domain hosted here>:<panel port>` opens the same panel with a
certificate the browser accepts. `snpanel login` and the Panel settings page
both list the hostnames that work. `PANEL_URL` only decides which certificate
a browser gets when it asks for a name that has none of its own, and which
address the installer prints.

## The Rust front door

SNPanel is being rewritten in Rust one router at a time, using the strangler
pattern: a Rust process holds the panel port and the TLS certificate, answers
the routes it has ported, and forwards everything else to the Python process
on loopback. Both share one SQLite file, one Redis and one `SECRET_KEY`, so a
session started through either is valid through the other.

**`installer/install.sh` sets up the Python panel only.** Turning the Rust
front door on is a second, deliberate step - it is not done for you, and the
panel is fully functional without it.

```bash
# Build the static binaries (on a build host, not the server)
cargo build --release --target x86_64-unknown-linux-musl -p snpanel-api -p xtask

# Copy them to the server, then switch the front door over
install -m755 snpanel-api /usr/local/bin/snpanel-api-rust
install -m755 xtask       /usr/local/bin/xtask-rust
bash installer/files/api-cutover.sh
```

The cutover moves Python to `127.0.0.1:8000`, starts `snpanel-rust` on the
panel port, and checks that the new front door answers before it returns. If
anything fails it rolls back to the Python front door by itself, and
`api-cutover.sh rollback` does the same on demand.

Two checks come with it and are worth running after any change:

```bash
bash installer/files/api-shadow-check.sh    # both implementations, same requests
bash installer/files/api-browser-check.sh   # the flow a browser actually performs
```

The shadow check sends the same request to the Rust and the Python side and
compares the answers. Any difference is a bug in the Rust side, never a new
API: the frontend cannot tell which one served it, and it must not be able to.

`RUST_MIGRATION_STATUS.md` records which routers have moved, which have moved
only in part, and why the remaining ones are waiting.

## SSH rescue menu

Run as root:

```bash
snpanel
```

Use this menu when the web panel is unavailable. It can show the saved login,
show rescue status, print recent logs, restart panel services, reopen required
firewall ports, reset the panel URL/port, repair panel SSL, fix runtime
permissions, change the `admin` password, and update SNPanel from the latest
release tag. Website and user management stays in the web panel.

Common SSH rescue commands:

```bash
# Change the server IP without prompts
snpanel change-ip OLD_IP NEW_IP

# Make the SNPanel admin password match the current Linux root password
snpanel sync-admin-root-password

# Last resort when a firewall rule locked you out: back up the current state,
# drop every SNPanel/UFW filter rule, and rebuild with protected ports only
snpanel-rescue-firewall
```

## Firewall

IP filtering runs on **iptables + ipset**. The panel never writes rules by
hand at request time: `/var/lib/snpanel/firewall/rules.tsv` is the source of
truth, and every change rebuilds the `SNPANEL-INPUT` chain and reloads the
ipsets from disk. `snpanel-firewall.service` replays the same apply at boot, so
no `iptables-save` state can drift.

- **Protected ports** (SSH from `sshd -T`, the panel port, 80/443/465/587) are
  always allowed and cannot be deleted from the panel.
- **Allow/deny IP** rules go into `hash:net` sets; rules with a port go into
  `hash:net,port` sets. Allow rules are evaluated before deny rules.
- **URL blocklists** are fetched daily into `snpanel-block4` / `snpanel-block6`.
  A million-entry list costs one hash lookup per packet instead of a million
  Nginx `geo` entries or UFW rules.
- The chain uses `RETURN` (not `ACCEPT`) for allowed traffic, so fail2ban and
  any other `INPUT` rules still see the packet.
- Disabling the firewall removes the jump from `INPUT`; it does not change the
  `INPUT` policy, so nothing else on the box is affected.

Upgrades from a SNPanel release that used UFW/Nginx run `snpanel-helper
firewall-migrate`, which imports surviving UFW user rules, purges UFW and its
config, removes the Nginx `geo` blocklist (`snpanel-ip-blocklist.conf`,
`ip-blocklist-geo.conf`, and the per-vhost `include`), then applies the new
chain.

The migration inherits the previous enforcement state rather than assuming it:
if UFW was active, or blocklist URLs were configured, the new firewall is
enabled; on a box that had no active firewall the rules are staged but not
enforced, so nothing the panel does not know about gets cut off. Turn it on
from the Firewall page when you are ready. Fresh installs always enforce.

## Updates

SNPanel can update itself from the latest stable GitHub release tag. Run it from
SSH:

```bash
snpanel-update --release
```

The same action is available in the panel's **Updates** page. The update script
checks release tags, downloads the selected release zip to a temporary
directory, syncs source to `/opt/snpanel`, rebuilds the frontend, refreshes
helper scripts, restarts the API, reloads Nginx, and removes the temporary
source. `/opt/snpanel-source` is not kept for normal release updates; it is only a
developer `--branch` or `--skip-pull` source directory.

The panel stores release check and update progress in
`/var/lib/snpanel/update-status.json`. The Updates page compares the installed
version with the newest release tag and enables the panel update button only
when a newer release is available.

To stay on a specific release:

```bash
snpanel-update --tag v1.0.0
```

If the browser still shows the old UI, do a hard refresh (Ctrl + Shift + R) or
open in incognito.

## Project layout

```
snpanel/
|-- backend/                    The panel's runtime directory on a box: `.env`
|                               and the SQLite database. No code lives here
|                               any more - the FastAPI application it is named
|                               after was deleted when the port finished.
|-- frontend/                   React + Vite SPA
|   `-- src/
|-- crates/                     The panel
|   |-- snpanel-core/             config, crypto (bcrypt, Fernet, JWT, TOTP), roles
|   |-- snpanel-osabi/            per-distro differences, nftables rendering
|   |-- snpanel-ipc/              the helper protocol
|   |-- snpanel-db/               the schema, and the queries over it
|   |-- snpanel-helper/           the privileged operations, behind SO_PEERCRED
|   |-- snpanel-nginx/            the vhost templates and their renderer
|   |-- snpanel-installer/        what install.sh and update.sh call into
|   |-- snpanel-cli/              the `snpanel` command
|   `-- snpanel-api/              the HTTP front door
|-- xtask/                      build and verification tasks
|-- installer/
|   |-- files/                   sudoers, the helper's socket units
|   |-- install.sh               Full first-time install
|   |-- rescue-firewall.sh       Emergency firewall reset (locked-out recovery)
|   `-- update.sh                Pull from GitHub and redeploy
|-- RUST_MIGRATION_STATUS.md    What has moved to Rust, and what has not
|-- IMPROVEMENTS.md             Things the port deliberately did not fix
`-- README.md
```

## Provisioning API and the shared billing module

`modules/servers/snpanel/` is a single WHMCS server module used against **both
SNPanel and OPanel**. The module is the fixed side of this contract: SNPanel
matches what the module already expects, rather than the module being adapted
per panel. `backend/app/tests/test_provisioning_module_contract.py` pins the
response keys it reads.

It authenticates with a Bearer token (created under **API Tokens**, pasted into
the server's Access Hash). Every hook maps to one endpoint:

| WHMCS hook | Endpoint |
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

`external_id` is `whmcs:<serviceid>`, so a service maps to exactly one panel
account across renames.

Cross-panel notes:

- **Response envelope**: OPanel replies with `{"success": ..., "data": ...}`;
  SNPanel replies with bare objects. The module unwraps a body only when it
  carries *both* keys, so no SNPanel response may use that pair together.
- **SSO**: the module reads `data.login_url` only. SNPanel returns it as an
  absolute URL built from the hostname the API call arrived on - so the
  customer lands on the domain the billing system already uses - falling back
  to `PANEL_URL` when that hostname is not one this panel serves, and to a
  relative path the module prefixes itself. `url` and `path` come along too. The token is single-use
  and expires after 5 minutes; `/api/auth/sso/<token>` sets the session cookie
  and redirects. A suspended account is redirected to
  `/?error=account_suspended` instead of being logged in.
- **Suspend** disables the panel login, bumps `token_version` (killing live
  sessions), rewrites each vhost as a static "suspended" site, and locks the
  site Linux users. **Unsuspend** restores the real vhost, aliases, WAF and
  flood settings from the database.
- **Terminate** takes no query string from the module, so `backup` defaults to
  off. Pass `?backup=true` to write a full user backup to `/var/backups/snpanel`
  before the account is deleted; it runs inline, so only use it from a caller
  that can wait. A failed backup is recorded on the account and never blocks
  the termination.
- A terminated account keeps its billing row with empty `username`/`email`, so
  the client area can still render the service.

## Roles

| Role | Capabilities |
|------|--------------|
| `admin` | Full control: websites, users, ownership assignment, services, firewall, PHP config, backups, and security settings. |
| `end_user` | Manage only websites assigned to the account, including files, databases, SSL, WordPress tools, cron, and own backups. |

## User and website ownership

- Each panel user also has a Linux user with the same normalized username,
  and that account is their SFTP login, chrooted to their home - for example
  `admin` -> `/home/admin`.
- By default the SFTP login uses the panel password and follows it when it
  changes. On the Users page an administrator can switch a user's SFTP off, or
  give it a password of its own - typed, or generated and shown once - after
  which a panel password change no longer reaches it. Each user sees their
  SFTP details on the Account security page and can change their own SFTP
  password there, after their current panel password and authenticator code.
- Panel Linux users are members of `snpanel-sftp`; the installer adds an SSHD
  `Match Group snpanel-sftp` block for password-based SFTP access. SSH shells,
  TTYs and forwarding are disabled for these users.
- New websites are created under `/home/<panel-user>/<domain>/public_html`.
- Every database has an owner, and a full user backup holds every database
  its user owns - on one of their sites or on none - and a restore brings them
  back. On the Databases page an administrator can make a database for any
  user and change a database's owner and site; moving a site to another user
  takes its databases with it.
- If an admin creates a website without impersonating another user, the website
  belongs to the admin account.
- Admins can quick-login as another panel user before creating websites for
  that account.
- Admins can assign a website to exactly one panel user. Moving ownership also
  moves the site path to the new Linux user and rewrites the PHP-FPM/Nginx
  runtime configuration.
- Deleting a panel user permanently deletes all websites, files, databases,
  backup schedule links, cron entries, PHP-FPM pools, and Linux-user data owned
  by that user.

## Quotas

- End users have a website count limit and a storage limit in MB.
- Admin users are not storage-limited.
- Storage usage is calculated from all websites owned by the user.
- SNPanel enforces the storage limit before site creation, upload, edit, archive,
  extract, and ownership assignment operations.
- This is an application-level soft quota, not an OS disk quota.

## Configuration

`/opt/snpanel/backend/.env` is generated by the installer and contains:

```ini
APP_ENV=production
SECRET_KEY=<random-32-bytes>
COMMAND_DRY_RUN=false
DATABASE_URL=sqlite:////opt/snpanel/backend/snpanel.db
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_BACKEND=redis
ALLOWED_ORIGINS=https://panel.example.com
BACKUP_ROOT=/var/backups/snpanel
SSL_EMAIL=admin@example.com
PANEL_URL=http://SERVER_IP:2222  # uses the selected panel port
PANEL_DOMAIN=
PANEL_PORT=2222                  # default; installer can set another port
PANEL_SSL_CERT=                  # default certificate, for hostnames with none
PANEL_SSL_KEY=
PANEL_SNI_DIR=/etc/snpanel/sni    # one certificate per hostname, kept by the helper
FRONTEND_DIST=/opt/snpanel/frontend/dist
```

### PHP-FPM auto tuning

SNPanel creates one PHP-FPM pool per managed PHP site. Pool sizing is tuned when
a site runtime is created or refreshed: the helper reads total RAM, CPU count,
and the number of managed PHP-FPM pools, then sets conservative `ondemand`
values for `pm.max_children`, idle timeout, request recycling, and hard request
timeout. Small VPS plans keep fewer children alive and recycle sooner; larger
plans receive a higher per-pool cap without using the same static values as a
1 GB server.

Optional overrides can be added to `/opt/snpanel/backend/.env`:

```ini
SNPANEL_PHP_FPM_WORKER_MB=128
SNPANEL_PHP_FPM_MAX_CHILDREN=
SNPANEL_PHP_FPM_IDLE_TIMEOUT=
SNPANEL_PHP_FPM_MAX_REQUESTS=
SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT=300
```

After changing overrides, retune existing pools:

```bash
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper php-fpm-retune
```

### MariaDB auto tuning

SNPanel also writes `/etc/mysql/mariadb.conf.d/90-snpanel-tuning.cnf` with VPS
sized MariaDB defaults. The helper tunes InnoDB buffer pool, connection count,
thread/table caches, temporary table limits, packet size, and slow-query logging
from total RAM and CPU count. The defaults leave memory for Nginx, PHP-FPM,
Redis, and the panel process instead of giving MariaDB a fixed oversized cache.

Optional overrides can be added to `/opt/snpanel/backend/.env`:

```ini
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

After changing overrides, retune MariaDB:

```bash
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper mariadb-retune
```

The backend refuses to start in production with `COMMAND_DRY_RUN=true` or
`ALLOWED_ORIGINS=*`. SECRET_KEY must be at least 32 chars in production.

## Service commands

```bash
# API logs
journalctl -u snpanel-api -f

# Restart the API after backend changes
systemctl restart snpanel-api

# Reload Nginx after vhost edits
nginx -t && systemctl reload nginx

# Service status
systemctl status snpanel-api nginx mariadb redis-server php8.3-fpm php8.4-fpm

# SSH rescue menu
snpanel

# Change the server IP
snpanel change-ip
snpanel change-ip OLD_IP NEW_IP

# Change the SNPanel admin login password
snpanel change-admin-password

# Make SNPanel admin use the current root password
snpanel sync-admin-root-password
```

## Security model

The panel daemon does **not** run as root. The installer creates a system user
`snpanel` and a single root-owned helper script that does all privileged work.

```
snpanel-api  (uvicorn, user=snpanel, hardened systemd unit)
   |
   |  sudo -n /usr/local/sbin/snpanel-helper <subcommand> ...
   v
snpanel-helper  (root, runs only whitelisted operations)
```

What the helper allows:

- `systemctl start/stop/restart/reload <whitelisted service>`
- `nginx -t`, `nginx reload`
- `certbot --nginx ...` for a single validated domain
- create/delete panel Linux users, sync their SFTP password, and manage per-user PHP-FPM pools
- `firewall-status/enable/disable/allow-port/allow-ip/deny-ip/delete` (iptables + ipset)
- fix ownership/ACLs for managed site paths under `/home/<panel-user>/<domain>`
- `rm -rf <managed site path>`
- WP-CLI and crontab management as the website's Linux user
- `terminal-exec`: an allowlisted command as the website's Linux user

### Website terminal

The per-site terminal runs commands as the website's own Linux user through
`snpanel-helper terminal-exec`. Commands are split into argv in Python (no shell
is involved, so `;`, `|`, backticks and globs are ordinary arguments) and the
executable must be on the allowlist, which covers the PHP toolchain
(`php`, `composer`, `artisan`, `wp`, `phpunit`), the JS toolchain
(`node`, `npm`, `npx`, `yarn`), `git`, and the usual file/text utilities
(`ls`, `cat`, `sed`, `awk`, `grep`, `find`, `tar`, `wc`, `stat`, …).

- Every path argument to a file utility must resolve inside
  `/home/<panel-user>/`; `curl`/`wget` additionally reject `file://` and any
  output path outside that home.
- `php`/`composer`/`wp` run against the site's configured PHP version
  (`php8.4`, not the system default), so Composer platform checks pass.
- Each command gets a wall-clock budget enforced by `timeout` inside the
  helper: 60s for quick utilities, 900s for installers and updaters
  (`composer`, `npm`, `wp`, `git`, `php`, …). The API adds a slightly longer
  backstop so a wedged helper cannot pin a worker.
- The allowlist is a guardrail, not a privilege boundary: `php -r` can already
  run arbitrary code **as that site's Linux user**. Isolation comes from the
  per-site Unix user, the chrooted home, and the helper's path checks.

Anything else is rejected. The helper validates domains, ports, IPs, and
filesystem paths before invoking the real binary.

The installer also creates a local MariaDB `snpanel` account used by the API to
create per-site databases and users for WordPress installs.

Additional hardening on the systemd unit:

- Runs as `snpanel` with only the `www-data` and `snpanel-sites` supplementary groups.
  `snpanel` is the service account for the API, not a panel login user; fresh
  installs do not create `/home/snpanel` or `/home/snpanel-sites`.
- Panel login users are Linux users in the `snpanel-sftp` group. Their
  home directories live directly under `/home/<username>`, are root-owned
  SFTP chroots, and contain user-owned site directories. `/home` is
  executable-only for non-root users, so panel users cannot list other
  usernames.
- Malware scanning is a page of its own, not a toggle on the Security page.
  It scans one website, every website, or every file on the machine, and can do
  the last one on a weekly schedule the admin sets. A whole-machine scan runs
  through the helper so clamd can read files its own user cannot, skips the
  kernel filesystems and the signature database, and is niced to the floor so a
  scan is never the reason a website goes slow.
- A fresh install turns IPv6 on by itself when the machine already holds a
  global IPv6 address, and says so in the summary it prints. A server that
  updates into this release is left as its admin set it. Neither can conjure
  an address a provider assigned but never configured: on most VPS the
  metadata service publishes no network data at all.
- Otherwise IPv6 is off until an admin turns it on in Panel settings. Turning it on
  checks for a global IPv6 address first and refuses on a server without one:
  nginx cannot bind an address family the machine does not have, and it would
  refuse to start, taking every website with it. When it is on, the helper adds
  the IPv6 twin of every listen directive it manages - including the
  certbot-written `listen 443 ssl` lines - runs `nginx -t`, and restores every
  file it touched if nginx refuses. `/etc/snpanel/ipv6-enabled` is the switch;
  an update re-applies it, and it turns itself off if the address ever goes
  away. The firewall was already dual-stack.
- Inside a site tree the defaults are `644` for files and `755` for folders,
  the same modes every hosting panel and every PHP application expects.
  `wp-config.php`, `.env` and `.my.cnf` are put back to `640` after any bulk
  permission pass. Sites are kept apart by the per-pool PHP-FPM `open_basedir`,
  by the SFTP chroot, by `nologin` shells and by the panel terminal's path
  checks - not by the mode bits.
- Uses `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`,
  `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
  `ProtectClock`, `ProtectHostname`, and `ProtectProc=invisible`.
- Uses `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, and
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
- Drops ambient capabilities with `CapabilityBoundingSet=~`.

`NoNewPrivileges=false`, `ProtectSystem=false`, `ProtectHome=false`, and
`RestrictSUIDSGID=false` are intentional because the API must invoke the sudo
helper and manage website files under `/home`. Privileged operations stay
constrained by the root-owned helper and sudoers allowlist.

If the API itself were ever compromised, the attacker would be limited to:
- writing into `/etc/nginx/conf.d/`, managed site paths under `/home`, and `/var/backups/snpanel/`
- running the helper subcommands above (no arbitrary code execution as root)

There is no path back to root via the API process.

## Security notes

- Login is rate-limited in Redis (8 attempts / minute, lockout after 20 fails),
  so counters are shared across uvicorn workers.
- Google Authenticator compatible TOTP 2FA can be enabled per account.
- Constant-time login path: bcrypt is verified even when the user does not
  exist, to avoid username enumeration via timing.
- DB and WordPress passwords are passed via stdin / `--prompt`, never as
  command-line args, so they don't appear in `ps`.
- DB passwords are encrypted at rest (Fernet, key derived from SECRET_KEY).
- Custom Nginx blocks are validated: braces must balance, dangerous directives
  (`server {`, `http {`, `events {`, `include`, `load_module`, `user`, `lua_*`,
  `proxy_pass`, `alias`, `*_log`, `ssl_*`) are rejected, max 16 KB.
- File manager rejects symlinks anywhere in the path. Website owners can manage
  their own deploy sources, including PHP, `.htaccess`, `.env`, and
  `wp-config.php`, with quota and ownership checks enforced by SNPanel.
- Path traversal is blocked at every layer that touches the filesystem.
- Auth uses HttpOnly cookies (`snpanel_session`) plus a CSRF token cookie
  (`snpanel_csrf`) echoed in the `X-CSRF-Token` header. The JWT is never
  exposed to JavaScript, mitigating token theft via XSS.
- Strict `Content-Security-Policy` (`script-src 'self'`, `frame-ancestors 'none'`).
- JWTs include a `jti`; revoked session IDs are stored server-side, and
  `token_version` invalidates previously issued JWTs on password change, role
  change, account disable, 2FA changes, or explicit logout.
- Production installs require `RATE_LIMIT_BACKEND=redis`, reject
  `ALLOWED_ORIGINS=*`, enforce `COMMAND_DRY_RUN=false`, and return generic
  500 responses for unhandled errors.

## License

MIT - see LICENSE.
