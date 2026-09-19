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
| API endpoints answered by Rust | **54 of 211** | 25% |
| Routers served whole | 4 of 17 | `auth`, `firewall`, `packages`, `updates` |
| Routers served in part | 9 | the strangler proxies the rest of each |
| Routers untouched | 4 | `maintenance`, `provisioning`, `site_apps`, `deps` |
| Privileged helper | **0% deployed** | 93 IPC variants defined, 117 shell verbs still serving |
| Installer | 0% | 9,944 lines of bash across four files |
| Rust CLI | **in production** | `snpanel 0.1.0`, and Rust holds :2222 |

Two of those lines are easy to misread.

**"13 of 17 routers have a Rust module" is not 76% done.** It is 25%. Most
routers have a module that answers a handful of their endpoints and hands the
rest to Python. `maintenance` alone is 67 endpoints — 32% of the whole
surface — with no Rust at all.

**The helper is designed but not deployed.** `snpanel-ipc` defines 93 request
variants and `snpanel-helper` implements six domains, but what runs on a live
server is 6,030 lines of bash, and nothing in the API talks to the Rust helper
yet. This is the largest gap between what the repository looks like and what a
customer's machine runs.

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

Eight verbs have no caller anywhere — not the Python backend, not the Rust
crates, not `update.sh`:

`certbot-renew-soon`, `chown-www`, `docker-firewall-guard`, `maldet-report`,
`malware-scan-server-estimate`, `site-app-volume-list`, `waf-crs-install`,
`waf-site-rules`.

Porting dead code is how dead code survives. Delete them from the bash in a
change of their own, so the deletion is reviewable separately from any port.
That leaves **109 live verbs**.

---

## 4. The privileged helper

### 4.1 Crate layout

Workspace members today: `snpanel-core`, `snpanel-osabi`, `snpanel-ipc`,
`snpanel-cli`, `snpanel-db`, `snpanel-helper`, `snpanel-api`, `xtask`.

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

93 variants are defined; 109 live verbs need one.

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

### Stage A — the helper's `site` domain

27 verbs, the largest domain, and the one everything waits on. The Rust module
exists (`ops/site.rs`); the verbs do not.

**Exit:** every `site-*` verb has an IPC variant and an implementation, and
each shadow-diffs clean against the bash version.

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

**Exit:** a live installation answers site verbs from Rust, the bash helper is
installed but not called for them, **a reboot comes back in the same state**,
and `snpanel doctor` says so.

### Stage C — the routers that sit on `site`

`websites` write half (20 endpoints, 1,374 lines), then `maintenance` (67
endpoints, 1,670 lines). Split `maintenance` by sub-area — backup, restore,
cron, logs — rather than attempting it whole.

**Exit:** shadow diff green for both; endpoint coverage ≥ **60%**.

### Stage D — the remaining helper domains

Runs in parallel with C. The domains with no Rust module: `panel` (9 verbs),
`certbot` (6), `maldet` (6), `clamav` (4), `docker` (4), `ipv6` (4), `updates`
(4), `cron` (2), `time` (2), `node` (2), and the singletons. Delete the eight
dead verbs in §3 rather than porting them.

**Exit:** 109 live verbs answered by Rust; the bash helper is no longer
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

117 verbs, of which 109 are live (§3). Ordered by size; "rust" means the
`ops` module exists, not that the verbs are implemented.

| domain | verbs | rust module |
|---|---|---|
| `site` | 27 | yes |
| `waf` | 12 | yes |
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

The shortest honest statement of the distance: **157 of 211 endpoints and
9,944 lines of bash remain**, the helper is the gate on most of it, and the
mechanism that makes each step ordinary is already built and serving real
traffic.
