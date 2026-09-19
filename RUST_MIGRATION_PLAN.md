# Rust migration — plan

**Measured 19 September 2026.** Every number here was counted from the code,
not carried over from an earlier estimate. `RUST_MIGRATION_STATUS.md` records
what has been done and what it cost; this records what is left, in what order,
and how each step is judged finished.

`Cargo.toml` and about thirty source comments cite this document by section —
§4.1, §4.2, §4.3, §5.1, §6.1, §6.3, §6.4, §6.5, §8, §9.1, §9.2, Appendix B.
Those citations were pointing at a file that was not in the repository. The
numbering below is the one the code already uses, so a reader following a
reference lands where the author meant. A test
(`backend/app/tests/test_migration_plan.py`) fails if a citation stops
resolving.

---

## 1. Where this actually stands

| | measured | |
|---|---|---|
| API endpoints answered by Rust | **95 of 211** | 45% |
| Routers served whole | 6 of 17 | `addons`, `auth`, `firewall`, `packages`, `terminal`, `updates` |
| Routers served in part | 8 | the strangler proxies the rest of each |
| Routers untouched | 3 | `provisioning`, `site_apps`, `deps` |
| Privileged helper | **deployed** | 63 of the 105 verbs Python calls are answered over the socket |
| Installer | 0% | 9,944 lines of bash across four files |
| Rust CLI | **in production** | `snpanel 0.1.0`, and Rust holds :2222 |

Two of those lines are easy to misread.

**"14 of 17 routers have a Rust module" is not 82% done.** It is 43%. Most
routers have a module that answers some of their endpoints and hands the rest
to Python. `maintenance` alone is 67 endpoints — 32% of the whole surface —
and 38 of them are still Python's.

**The helper is deployed, and that is not the same as finished.** Stage B put
`snpanel-helper` on a live Debian 13 behind a socket-activated unit and proved
it carries real traffic: all 31 site verbs answered by Rust, two power cycles
identical, a rollback run and re-install restored, and an A/B that took the
panel from 2 `sudo` invocations to **0**. What is not finished is the surface:
of the 105 verbs the panel's Python calls, 63 are answered over the socket and
42 still fall through to 5,993 lines of bash. Falling through is the design,
not a fault — but it is why a router can be "ported" and still be standing on
bash underneath, and `terminal-exec` is the newest example.

A third line is worth stating because it is easy to over-read in the other
direction: `snpanel-ipc` defines 133 request variants and the argv layer maps
83 verb names, which is more than the 63 above. Three of those names
(`firewall-migrate-nft`, `selinux-port-add`, `selinux-restore-site`) have no
caller in Python and no arm in the bash helper. They are Rust-side surface
running ahead of its callers, not coverage.

---

## 2. The ordering constraint

This is what an endpoint count hides, and it decides everything in §8.

**The helper leads the routers that sit on it.** `users` and `databases` are
each half-ported and stuck exactly there: their read halves are in Rust and
their write halves end at a helper verb with no Rust equivalent. `websites`
(20 endpoints left, 1,374 lines) and `maintenance` (67 endpoints, 1,670 lines)
are almost entirely helper calls — render a vhost, issue a certificate, take a
backup, restore one.

Porting those routers first would mean a Rust router shelling out to bash,
which is the arrangement being removed. So:

> Finish a helper domain, deploy it, then port the routers that call it.
> Never the other way round.

The corollary: **§8 Stage B is the critical path**, and it is the stage that
looks least impressive in a status report.

---

## 3. What is not being ported

**Five verbs had no caller and have been removed**: `chown-www`,
`docker-firewall-guard`, `malware-scan-server-estimate`,
`site-app-volume-list`, `waf-site-rules`. The helper went from 6,030 to 5,993
lines, and **112 live verbs** remain.

An earlier version of this section listed eight, and getting that wrong is the
part worth keeping:

- **`certbot-renew-soon` is alive and load-bearing.** It is invoked daily by
  `snpanel-ssl-auto-renew.service`, a unit the helper writes itself inside a
  heredoc, so no search for a *caller* finds it. Deleting it would have
  stopped certificate renewal on every installed server, silently, and shown
  up months later as an expired certificate.
- **`maldet-report` and `waf-crs-install`** have no caller either, but a test
  asserts each one exists. Removing a feature a test deliberately pins is a
  product decision rather than cleanup, so they are left alone and named here.

The rule this produced: before deleting anything, look for its name inside
generated text - units, timers, cron entries, heredocs - and on a running
server, not only in the source.

---

## 4. The privileged helper

### 4.1 Crate layout

Workspace members today: `snpanel-core`, `snpanel-osabi`, `snpanel-ipc`,
`snpanel-cli`, `snpanel-db`, `snpanel-helper`, `snpanel-nginx`, `snpanel-api`,
`xtask`.

`snpanel-nginx` was added when Stage C started, because twelve of the twenty
`websites` write endpoints do nothing but rewrite a vhost, and the rendering
is the same work each time. It is its own crate rather than a module in
`snpanel-api` so that C19 - the contract that says the bytes must match - has
somewhere to live that does not depend on an HTTP framework.

Added when its stage starts, so CI never builds an empty shell:

- `crates/snpanel-installer` — §8 Stage F
- `crates/snpanel-daimport` — §8 Stage G

### 4.2 The trust boundary

The bash helper's first line of defence is `sudo` plus a verb allowlist. The
Rust helper replaces it with peer credentials read from the socket
(`snpanel-helper/src/peercred.rs`): the kernel says who connected, and the
caller cannot lie about it.

This is the one item in this plan that warrants review by somebody who did not
write it. A mistake here is not a bug, it is a privilege escalation. It lands
before any operation does.

### 4.3 The protocol

`snpanel-ipc` is the wire contract: one request enum, one response enum,
arguments already parsed. Three properties it exists to guarantee, and each
is a defect in the bash it replaces:

- every argument arrives parsed, so no handler re-validates;
- no handler builds a shell string;
- every handler returns a response rather than exiting. The bash `exec`s for
  most operations, so the process *becomes* nginx or systemctl and its exit
  status is the only channel back — which is why the panel could not tell
  "nginx says the config is bad" from "nginx is not installed" without
  parsing English out of stderr.

93 variants are defined; 112 live verbs need one.

---

## 5. Operations

### 5.1 The audit trail

Every privileged operation is logged to journald natively, not through an
inherited stderr that the caller could redirect. The record of who asked for
what has to survive the caller.

---

## 6. The OS abstraction

The governing rule: there is no `if cfg!(debian)` scattered through the code.
One trait, one implementation per distribution, and everything else asks the
trait.

### 6.1 Detection and the per-distribution table

`snpanel-osabi::platform::Platform` is the table: package names, service
names, web user, PHP repository, paths. `detect.rs` picks the implementation
from `/etc/os-release`.

**There are three copies of this table** — Rust, `installer/platform.sh`
(308 lines), and `backend/app/core/platform.py`. They are pinned together by
`backend/app/tests/test_platform_matches_installer.py`, and those tests are
the only thing standing between the three and a silent divergence. Keep them
passing at every step. §8 Stage F removes one copy rather than adding a
fourth.

Supported: Ubuntu 24.04, Debian 12/13, AlmaLinux 10 (and the EL10 rebuilds —
Rocky, RHEL, Oracle — which share the layout exactly). Ubuntu 26.04 was
implemented and withdrawn; see `RUST_MIGRATION_STATUS.md`.

### 6.2 Services and paths

What each distribution calls the same thing: `redis` vs `valkey`,
`mariadb` vs `mysql`, `www-data` vs `nginx`, where phpMyAdmin lives. Measured
per distribution rather than assumed from a related one — doing that corrected
four EL entries, the load-bearing one being that EL10 ships no `redis` package
at all.

### 6.3 The firewall

`rules.tsv` is the source of truth (contract C13) and every apply is derived
from it. The backend moves from iptables/ipset to nftables, because ipset is
deprecated on RHEL 10 — but the reason to do it carefully is narrower than
that: the file is parsed in three places, and parsing it wrongly once already
opened a port in the panel's display while leaving it shut on the machine.

Anything reading `rules.tsv` uses the shared parser. Not `IFS=$'\t' read`,
which collapses runs of tabs.

### 6.4 SELinux

The item most likely to be skipped and most likely to be missed when it is.
Contexts for site directories, ports for the panel. It is not optional on the
RHEL family, and a site that works until the first `restorecon` is worse than
one that never worked.

### 6.5 The RHEL family

Every path differs from the Debian family; the Remi layout in particular is
not a variant of the Ondrej one. This is why the trait exists rather than a
set of conditionals.

---

## 7. Risks, named

- **C3, the Fernet key derivation (R1).** The highest-rated risk and
  unchanged: Python and Rust must derive the same key from the same
  `SECRET_KEY`, or every stored credential becomes unreadable. Covered by a
  fixture today; it stays covered at every stage.
- **The helper is a trust boundary.** See §4.2.
- **Three copies of the platform table.** See §6.1.
- **`maintenance` is underestimated by its endpoint count.** 67 endpoints over
  1,670 lines, most ending in backup and restore — where a mistake destroys
  customer data rather than returning the wrong JSON. It deserves the most
  conservative treatment here, not the fastest.
- **Ported audit entries are missing their detail.** `packages::audit_action`
  is the only audit helper the routers use, and it hardcodes an empty detail
  and always appends `ip=` and `ua=`. The Python has two shapes and they are
  not interchangeable: `log_action(db, user.id, action, target, detail)` with
  no `request=`, which is what every file-manager endpoint calls, and
  `log_action(..., request=request)` with no detail. So a ported `delete_files`
  records ip and user-agent where the Python records *which files were
  deleted*, which is the entry an administrator goes looking for after an
  incident. Found while porting the file-manager writes; the new endpoints use
  `maintenance::audit_detail`, which has the Python's shape. **19 existing call
  sites across `maintenance`, `users`, `packages` and `websites` have not been
  checked yet** — each has to be read against its Python counterpart, because
  which of the two shapes is right differs per endpoint.

- **Nothing in Stage F is reversible on a customer's machine.** An installer
  that half-runs leaves a box in a state no rollback was written for. Every
  step of it must be idempotent and re-runnable, which the bash learned the
  hard way: `CREATE USER IF NOT EXISTS` does not change a password, so
  re-running the installer locked the panel out of MariaDB.
- **A check that asks the machine instead of the question.** This has now
  caused four separate failures — golden fixtures that differed by whether
  nginx had a module, a test that passed only where ModSecurity was installed,
  a helper that called a valid download corrupt because `file` was absent, and
  a test suite that needed an undeclared `httpx2`. Any new check gets asked:
  *would this answer differently on a clean machine?*

---

## 8. Order of work

```
A (helper: site domain)
   └─> B (deploy the Rust helper)      <-- critical path
          ├─> C (websites, maintenance)
          └─> D (remaining domains) ──> E (remaining routers)
F (installer) runs alongside; shares nothing with A-E
                                          └─> G (remove Python)
```

Each stage states an **exit** that is a measurement, not an opinion. A stage
is not finished because the code is written; it is finished when the number is
reached.

### Stage A - the helper's `site` domain — **complete**

**31 of 31 verbs are answered by Rust.** Measured from `op_name()` and the
dispatch table, not counted by hand.

Two things the work itself corrected in this plan:

**The 27-verb figure counted `site-app-*` as part of this domain**, because
the names share a prefix. They are Docker orchestration and nothing in
`websites` or `maintenance` waited on them, so the critical path was shorter
than it looked.

**`site-path-fix` needed no work at all.** It is byte-for-byte the
two-argument form of `fix-permissions`. Checking before implementing is worth
more here than anywhere else: the verbs are named as though they were all
distinct.

Two pieces deliberately still fall through to the bash, and are not counted
as done:

- **`site-app-write`'s `compose` runtime.** It writes a second file and
  resolves bind mounts; the node and docker runtimes are here.
- **nothing else.**

`site-archive-extract` needed a second binary. An archive is
attacker-controlled input, so the bash drops to the site's own user with
`runuser` before touching it, and keeping that property ruled out three
easier options: re-executing the helper needs it world-executable (it is
0750 root:snpanel, and widening that to avoid shipping a small binary is the
wrong trade); `fork` plus `setuid` is not safe from a threaded process when
what follows allocates; and extracting as root then chowning gives up the
containment entirely. So `snpanel-extract` is a program that needs no
privileges, does one thing, and is run as the site user by the helper. It
must be installed to `/usr/local/sbin/snpanel-extract` alongside the Rust
helper in Stage B; until then the verb reports that it is missing and the
bash answers.

**A correction, found while starting Stage B.** That exit was measured from
`op_name()` and the dispatch table, and both said 31 of 31. Neither is what
the panel calls. Every call site invokes `snpanel-helper <verb> <args>`, and
the mapping from *that* to a request had 7 of the 31 - so 24 site verbs,
including every `site-app-*`, `site-archive-extract`, `wp` and `wp-site`, were
answered over a socket nothing used and handed straight back to the bash over
the command line that everything uses. The measurement was true and the
conclusion drawn from it was not: a verb is answered by Rust when the shape
the caller uses reaches Rust, not when a variant exists for it.

The mapping now covers all 31, and lives in `snpanel-ipc` rather than in the
helper binary, because Stage B needs the identical one on the API side. What
the two copies would have drifted about is which arguments are accepted for an
operation that runs as root.

**Exit:** reached. Every site verb has an IPC variant, an implementation, and
a mapping from the command line the panel actually uses.

### Stage B — deploy the Rust helper *(critical path)*

The cutover mechanism, modelled on `installer/files/api-cutover.sh` but
per-verb rather than all-or-nothing: an allowlist decides which verbs the Rust
helper answers and which fall through to bash, so the remaining domains can
land one at a time on machines already serving customers.

§4.2 lands first. The API's `sudo -n /usr/local/sbin/snpanel-helper <verb>`
call site becomes a socket call with the shell path kept as fallback.

**The cutover must set what boots, not only what runs.** The API cutover called
`start`/`stop` and never `enable`/`disable`; a reboot silently reverted it, and
a stray `systemctl start` put the old unit into a three-second restart loop
that ran 71 times before anyone noticed. Do not repeat that shape.

**What the cutover does**, in `installer/files/helper-cutover.sh`:

- moves the bash helper to `snpanel-helper.sh` and puts the Rust binary in its
  place, so the panel calls the same path through the same sudoers rule and
  every unported verb `exec`s the bash;
- installs `snpanel-extract` to `/usr/local/sbin/`, without which
  `site-archive-extract` reports itself missing and the bash answers;
- installs `snpanel-helper.socket` and `snpanel-helper.service` and runs
  `enable --now` on the **socket**, not the service: systemd owns the socket,
  starts the helper on the first connection, and holds the socket across a
  helper restart so an update never shows the API a connection refused;
- proves the round trip before declaring success, by connecting **as the
  `snpanel` user** and reading an answer. A socket that exists and does not
  answer is worse than no socket, because the API tries it first on every
  call. If it does not answer, everything is rolled back.

**The per-verb control is `SNPANEL_HELPER_VERBS`**, written as a systemd
drop-in rather than into `.env`, because `.env` is also read by the Python and
C18 is a contract. An entry ending in `*` matches a prefix, so
`site-*,wp,wp-site` is a first deployment that moves the site domain and
leaves everything else on the path it has been using. Unset means every verb
the mapping answers.

**Three outcomes, deliberately not alike**, in `shell.rs`:

| what happened | what the panel does |
| --- | --- |
| the mapping does not know the verb | sudo, which reaches the bash. This is the cutover. |
| the transport failed | sudo. A helper that is not listening is an operational problem, not a security one, and a customer should not see an error for it. |
| the helper answered, ok or refused | that answer is returned, and **never retried through sudo**. Retrying a refusal would make failing the one check this transport adds a way around it. |
| the mapping knows the verb and refuses the arguments | refused, 2, no transport. An argument rejected here must not get a second hearing from a looser parser. |

Each of those four was checked by breaking the code and watching the test
fail, not by reading it.

**`snpanel doctor` does not exist.** `snpanelctl` is an interactive rescue
menu with no such subcommand, so the exit criterion named a command that was
never written. The report is `helper-cutover.sh status`, and it prints what a
reboot comes back to - `is-enabled`, not `is-active` - because that is the
distinction the API cutover got wrong.

**Exit:** reached, on a Debian 13 installed from the published `main` and cut
over with the shipped script. Measured on the box, not inferred:

| what the exit asks | what was measured |
| --- | --- |
| a live installation answers site verbs from Rust | `--help` through the panel's own `sudo` path reports 73 of the bash helper's 112, and all 31 site verbs answer without being handed back |
| the bash is installed but not called for them | a site verb writes an audit line from the Rust helper; `docker-status` logs "not ported yet; delegating to the bash helper" |
| **a reboot comes back in the same state** | the container was powered off and started: helper, fallback, extractor, `enabled=enabled active=active`, the allowlist, and a round trip that answers - all identical |
| the status command says so | `helper-cutover.sh status`, which prints `is-enabled` rather than `is-active` |

The panel served HTTP 200 throughout, including on the bash during a rollback.

**Rollback was run, not just printed.** A rollback nobody has executed is a
promise nobody has checked, and the machine it gets run on is one that is
already going wrong. It put the bash back, the panel kept serving, and a
re-install restored the cutover. It also left the socket file behind, which
cost a refused connection on every privileged call until the next install -
correct behaviour, pure waste - so it removes it now.

**The socket was demonstrated end to end**, with the Rust front door in place
and sudo's own journal as the witness - it is written by sudo, not by anything
this change touches. The same request, the same box, one line of configuration
different:

| allowlist | `GET /api/firewall/status` | sudo invocations for `firewall-*` |
| --- | --- | --- |
| `site-*,wp,wp-site` | HTTP 200 | 2 |
| `site-*,wp,wp-site,firewall-*` | HTTP 200 | **0** |

The helper answered both times. That is the per-verb cutover working: an
operation moves from sudo to a socket that checks the caller's credentials,
the response does not change, and the move is one line and a restart to undo.

The first attempt at this reported the opposite, and the reason is worth
keeping. It deployed a `snpanel-api` built the previous day, before the socket
transport existed, and correctly observed that the socket was not being used -
there was no socket code in the binary. The differential was sound and the
artefact was wrong, which is not something a test can tell you. The deploy
script now refuses a binary older than the sources.

Three things this stage found that had nothing to do with it, each recorded in
its own commit: a minimal Debian has no `sudo` and the installer's package
list did not ask for one; an update wrote the bash helper over the Rust one on
every run; and `PanelUsername::parse` normalised where the Python validates,
so `site-runtime-ensure UPPER /home/UPPER/x` created a directory outside the
home of the account that owned it.

### Stage C — the routers that sit on `site`

`websites` write half (20 endpoints, 1,374 lines), then `maintenance` (67
endpoints, 1,670 lines). Split `maintenance` by sub-area — backup, restore,
cron, logs — rather than attempting it whole.

**Exit:** shadow diff green for both; endpoint coverage ≥ **60%**.

### Stage D — the remaining helper domains

Runs in parallel with C. The domains with no Rust module: `panel` (9 verbs),
`certbot` (6), `maldet` (6), `clamav` (4), `docker` (4), `ipv6` (4), `updates`
(4), `cron` (2), `time` (2), `node` (2), and the singletons. The five dead verbs in §3 are already gone.

**Exit:** 112 live verbs answered by Rust; the bash helper is no longer
installed on new installations.

### Stage E — the remaining routers

`waf` (16 left), `malware` (11), `panel_settings` (8), `users` (4),
`databases` (4), `addons` (2), `services` (1), `terminal` (1), then
`provisioning` (13) and `site_apps` (10), which need the `docker` domain.

**Exit:** endpoint coverage **100%**; the proxy path is never taken in normal
operation.

### Stage F — the installer

9,944 lines of bash, and the part a customer meets first: `install.sh`
(1,857), `update.sh` (1,749), `platform.sh` (308), `snpanel-helper.sh` (6,030
— retired by Stage D). Built on `snpanel-osabi`, which already carries the
table.

**Exit:** a fresh install on each supported distribution performed entirely by
the Rust installer, and `installer/files/platform-check.sh` passing at the
count the bash reaches today (Debian 13: 31/31).

### Stage G — remove Python

Three known gaps, each small alone:

- **the dual-stack socket.** `serve.py` builds an `AF_INET6` socket with
  `IPV6_V6ONLY` cleared and falls back to IPv4 on failure; Rust binds IPv4
  only. Identical behaviour where IPv6 is off, which is why it has not bitten.
- **site-app storage accounting.** `storage_quota` counts an application's own
  directory and its container volumes; Rust counts websites only, so it
  understates usage for an account with site apps.
- **the frontend**, still served by Python through the proxy. `rust-embed`
  replaces that.

**Exit:** `snpanel-upstream` is not installed and no Python process serves the
panel. At that point the shadow diff has nothing left to compare against, so
the golden fixtures and the suite become the only gate — which is the moment
to confirm both still have teeth.

### Phase 7 — extensions

Beyond removing Python: the EL10 rebuilds already accepted by §6.1, Debian 12
parity, and DA import (`snpanel-daimport`).

---

## 9. The strangler

The mechanism that makes Stage C possible at all: 211 endpoints do not move in
one release. Rust holds the port, answers what it has, and forwards the rest
to Python on loopback. Moving one router changes one file.

Its correctness rests on two shared things, and both are contracts rather than
conveniences.

### 9.1 Shared configuration

Both processes read the same `.env`. Contract C18: every variable name stays
exactly as it is, including the PHP-FPM and MariaDB overrides, because `.env`
is written by the installer and rewritten by every update — a rename strands
existing boxes. The same `SECRET_KEY` reaches both, which is what makes a
session minted by either side valid on the other (C4), and what makes C3
(§7) load-bearing.

### 9.2 Shared database

Both implementations open the *same* SQLite file. There is no data to
synchronise and no window in which the two disagree; a request can be served
by either side. The price is that schema changes belong to whichever side owns
migrations until Stage G, and that SQLite's locking behaviour is now a
two-process concern rather than a one-process one.

---

## Appendix B — the bash surface, by domain

112 verbs, after the five removed in §3. Ordered by size; "rust" means the
`ops` module exists, not that the verbs are implemented.

| domain | verbs | rust module |
|---|---|---|
| `site` | 26 | yes |
| `waf` | 11 | yes |
| `panel` | 9 | — |
| `certbot` | 6 | — |
| `maldet` | 6 | — |
| `php` | 6 | yes |
| `nginx` | 5 | yes |
| `clamav` | 4 | — |
| `docker` | 4 | — |
| `ipv6` | 4 | — |
| `updates` | 4 | — |
| `firewall` | 3 | yes |
| `cron`, `malware`, `manual`, `node`, `orphans`, `time`, `wp` | 2 each | — |
| `chown`, `cloudflare`, `daemon`, `fastcgi`, `fix`, `http`, `mariadb`, `mkdir`, `rm`, `service` | 1 each | — |
| `ssl` | 1 | yes |

The shortest honest statement of the distance: **124 of 211 endpoints and
9,944 lines of bash remain**, the helper is the gate on most of it, and the
mechanism that makes each step ordinary is already built and serving real
traffic.
