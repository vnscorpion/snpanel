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
| API endpoints answered by Rust | **127 of 211** | 60% |
| Routers served whole | 7 of 17 | `addons`, `auth`, `firewall`, `packages`, `services`, `terminal`, `updates` |
| Routers served in part | 8 | the strangler proxies the rest of each |
| Routers untouched | 3 | `provisioning`, `site_apps`, `deps` |
| Privileged helper | **complete** | all 106 verbs Python calls are answered over the socket |
| Installer | 0% | 9,944 lines of bash across four files |
| Rust CLI | **in production** | `snpanel 0.1.0`, and Rust holds :2222 |

Two of those lines are easy to misread.

**"14 of 17 routers have a Rust module" is not 82% done.** It is 60%. Most
routers have a module that answers some of their endpoints and hands the rest
to Python. `maintenance` alone is 67 endpoints — 32% of the whole surface —
and 38 of them are still Python's.

**The helper is deployed, and that is not the same as finished.** Stage B put
`snpanel-helper` on a live Debian 13 behind a socket-activated unit and proved
it carries real traffic: all 31 site verbs answered by Rust, two power cycles
identical, a rollback run and re-install restored, and an A/B that took the
panel from 2 `sudo` invocations to **0**. What is not finished is the surface:
**all 106** verbs the panel's Python calls are answered over the socket, and
nothing the panel does falls through to `snpanel-helper.sh` any more. (105 until this week.
The scratch survey that produced that figure looks for
`shell.privileged("<verb>"`, and `backend/app/services/orphans.py` calls
through a local `_run()` wrapper, so `orphans-scan` and `orphans-clean` were
counted as having no caller for most of the migration. An in-tree test replaces
the survey now.) Falling through is the design,
not a fault — but it is why a router can be "ported" and still be standing on
bash underneath, and `terminal-exec` is the newest example.

A third line is worth stating because it is easy to over-read in the other
direction: `snpanel-ipc` defines 118 request variants and the argv layer maps
136 verb names, which is more than the 106 above. (An earlier draft said 133
variants. Counted two ways — the variants in the `enum HelperRequest` body, and
the distinct `Self::` arms in its `name()` table — it is 109; more names than
variants because several verbs are aliases sharing one.) Three of those names
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
lines, and **147 verb names** remain across its arms — 112 of them
distinct arms, the rest legacy aliases sharing an implementation
(`ufw-*` and `nginx-*` names from before the feature moved). The
smaller figure was what an extractor that skipped `a|b|c)` arms
measured, and it is the count Stage D's exit used to be phrased in.

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

133 variants are defined; the 105 verbs the panel's Python calls need one.

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

### The same test rotted twice, in two files

`a_verb_this_build_does_not_answer_is_unmapped_so_the_bash_gets_it` named a
real unported verb as its example, and its own comment predicted the problem:
*"`panel-url-set` is the next one to go, and this has to be changed again when
it does"*. It was right — and that is the argument against the pattern, not
for it. The example had already moved from `docker-install` once.

This is the second test in `argv.rs` with that shape; the first,
`an_unmapped_verb_does_not_read_stdin`, was fixed one commit earlier. The test
directly above both of them already used `no-such-verb`, so the right idiom
was in the file the whole time.

Both now name something that cannot ever be mapped. The rule, stated once:
**when a test has to be edited every time unrelated work lands, the thing it
names is not the thing it is testing.**

### `is_domain` accepts an IP address, and the orphan sweep depends on it

`orphan_live_domains` normalises the panel's list with `tr -d '[:space:]'`
and then checks it with `is_domain`. Two answers there are easy to read past
and were measured against the bash on Debian 13 rather than inferred:

- whitespace is removed **anywhere**, not trimmed, so `exa mple.com` becomes
  `example.com` and two names on one line are glued into one;
- `is_domain`'s regex allows all-digit labels, so `192.0.2.1` passes and
  stays on the live list.

The second matters. A port that "fixed" it by rejecting IP addresses would
drop that name from the live set, and the orphan sweep would then see a
certificate for it as unreferenced and archive-and-delete it. The Rust port
keeps the behaviour, and the fixture that pins it is 20 inputs replayed
against the bash.

Everything the sweep removes is copied to `/root/snpanel-removed` first, and
an empty live list is refused outright at both ends - Python will not ask, and
the helper will not act. "Unreferenced" is a strong inference, not a
certainty.

### A refusal exits 1, and the code said 2 for most of the migration

`REFUSED_EXIT_CODE` was 2, justified by "the bash's `deny` exits 2". It does
not:

```sh
deny() { echo "snpanel-helper: $*" >&2; exit 1; }
```

The `exit 2` that reading picked up is fifteen lines above `deny` and belongs
to the `SUDO_USER` guard, which is a different answer: not "no, and here is
why" but "you may not call me at all". Checked against the installed helper on
Debian 13 rather than read a second time — a bad domain, a wrong argument
count and an unknown verb all exit 1; only `SUDO_USER=nobody` exits 2.

The test that pinned 2 carried the counter-evidence in its own doc comment:
*"Found live: `php-tune-write` with a directive outside the allowlist refused
with the right message and exit 1."* The observation was correct and the
number was set against it.

Nothing behaved differently, because every caller tests `!= 0`. It matters
from here because `terminal-exec` passes a command's own status through, and a
helper that reported refusals as 2 would make every command that legitimately
exits 2 look like one. Both codes are now mapped the way the bash means them:
`NotAuthorised` → 2, everything else → 1.

The mapping also existed **twice** — once in the API, once copied into the
helper's test with a comment reading "Repeated *and* compared: if the two ever
drift, this is the test that says so." A copy cannot detect drift; it is the
drift. It now lives in `snpanel-ipc`, which both crates already depend on.

### Two mutants that could not be caught, and were not tests failing

Proving the terminal tests had teeth turned up two mutations that no test
could catch because neither changes a verdict:

- removing the flag-skip in `check_path_args`: `-la` resolves to `<cwd>/-la`,
  inside the home, with or without it;
- making the absolute-path branch unreachable: Rust's `Path::join` with an
  absolute argument discards the base, so `cwd.join("/etc/passwd")` is already
  `/etc/passwd`.

Both are equivalent mutants. Reporting them as gaps would have sent someone
looking for a missing test; the second is now noted in the code, because a
reader could otherwise take that branch for the check itself.

### The consumer is not always Python

`firewall-blocklist-status` looked like the safe kind: its Python service
hands `CommandResult.__dict__` straight to the API, which hands it to the
browser, so nothing parses it. Nothing in *Python* parses it.
`parseFirewallBlocklistUrls` in `frontend/src/App.jsx` does — it starts
collecting at a line that is exactly `URLs:`, stops at exactly `Networks:` or
`Timer:`, and keeps what begins with `http` in between. Rename a header and
the panel's URL table empties while the verb still looks like it answered.

So the rule from the entry above needs widening. "Displayed verbatim" is not
the end of the search; it is the point at which the search moves to the
browser. Every `.stdout` use in `frontend/src/App.jsx` was read — there are
13 — and **two** of them are reads, not renders:

- `parseFirewallBlocklistUrls`, above.
- The Services page, which decides each card's badge with
  `text.includes('active (running)')` and
  `text.includes('inactive') || text.includes('failed')` over
  `service-status`. Rust passes `systemctl status` through unchanged, so this
  one already agreed — checked rather than assumed.

The same sweep turned up a third problem in a verb nobody parses at all.
`updates-status` answered with `with_data(update-status.json)`; the Updates
page renders that verb's stdout verbatim, and the bash writes **six** labelled
sections. What the administrator saw was the release blob alone — no
upgradable package list, no unattended-upgrades state, neither service state,
neither journal. Not a parse failure, an information loss, and invisible for
the same reason as the rest: nothing errored.

### A test whose example keeps being ported is testing the wrong thing

`an_unmapped_verb_does_not_read_stdin` checks that a verb the argv layer does
not map is delegated to bash **without** reading stdin first — reading it
would consume the payload the fallthrough needs. It named a real unported verb
as its example, and that example had to be changed three times:
`docker-install`, then `panel-url-set`, then `php-install`, each time because
that verb had just been ported.

None of those edits said anything about the mechanism. `from_argv` does not
know which names the bash helper carries, so any unmapped name exercises the
same path — and one of the moves hid a real problem, because a substring guard
had matched this test's example rather than the argv arm it was meant to find.
The example is now a name that cannot ever be mapped.

The general form: when a test has to be edited every time unrelated work
lands, the thing it names is not the thing it is testing.

### A test can pass because it never ran

Three mutations in this session were reported as caught when nothing had run:
the mutation runner filtered on `ops::waf::tests::…` while the tests had
landed in `conf_tests`, cargo matched no test, exited 0, and exit 0 was read
as "the test still passes". A mutation runner must assert that exactly one
test ran, not merely that the run failed.

Two tests were also toothless for reasons of their own, and both are the same
mistake in different clothes — **asserting against something the test itself
produced**:

- `the_rule_set_is_looked_for_where_distributions_put_it` probed the
  filesystem, so on any machine without CRS installed it was true whatever
  the search list said.
- `the_blocklist_status_headers_are_what_the_browser_parses` parsed a sample
  string written in the test, so renaming the real header changed nothing it
  looked at.

Both now assert against the constant or the formatter the production path
uses.

### A ported verb can answer in a shape its caller cannot read

`shell.privileged` runs `sudo snpanel-helper <verb>` and captures **stdout as
text**. `HelperResponse::data` is printed as pretty JSON. So any verb whose
Python consumer parses stdout is wrong unless the helper writes the bash's
text — and six did not. All six were on `main`, all six were silent, because
every one of those call sites passes `check=False`.

| verb | what Python parses | what Rust wrote | what the panel showed |
|---|---|---|---|
| `maldet-status` | `installed=` `monitor=` `sig_version=` `sig_updated=` | JSON | scanner and real-time monitor always "off" |
| `ipv6-status` | `available=yes` `enabled=yes` `addresses=a,b` | JSON, no `addresses` at all | every server "no IPv6, disabled" |
| `ssl-cert-info` | `not_after=` `sans=` | JSON, no `sans` at all | no expiry, no covered names |
| `panel-ssl-domains` | one bare domain per line | JSON `{"hostnames":[…]}`, and read the panel's own copies rather than `/etc/letsencrypt/live` | "borrow an existing certificate" list always empty |
| `waf-crs-status` | eight keys | JSON with two | CRS "not installed", every memory figure 0 |
| `clamav-status` | (no caller yet) | JSON | — |

`ssl-cert-info` is the one with teeth beyond display. `cert_covers(sans,
domain)` decides whether a certificate already covers a name; an empty `sans`
answers "no" for every domain, which sends the panel to certbot for a
certificate it already holds — against an issuer with rate limits.

Two more divergences surfaced in the same reading, neither about JSON:

- **The CRS mode lived in two files.** Rust wrote `/etc/nginx/modsec/crs-mode`;
  the bash reads and writes `/etc/nginx/modsec/snpanel-crs-mode`. Each
  implementation wrote a file the other never opened, so a mode set before the
  cutover read as `off` after it and vice versa. Both directions silently
  disarm a WAF an administrator believes is on.
- **The rule set was looked for in the wrong place.** Rust checked
  `/etc/nginx/modsec/crs`; no distribution puts the rules there. The bash
  checks the three paths Debian and EL actually use.

Two verbs answer in JSON and are *not* bugs: `waf-status` and `updates-status`
hand `CommandResult.__dict__` straight to the UI, so stdout is displayed, not
parsed. Recorded so the next reader does not "fix" them.

**What generalises.** A verb counted as "ported" is counted on its signature.
When its consumer parses text, the contract lives in the parser, not the type
— and `check=False` turns a wrong answer into a silent one at **83** call
sites. Each of the six now has a test that applies the consumer's own parsing
to the helper's own output, and separately asserts that pretty JSON parses to
nothing. All 21 remaining `with_data` sites were read against their Python
consumers; the rest either have no caller yet or are displayed verbatim.

The test that let `maldet-status` through asserted `r.ok`. That is true of
both shapes. A status verb needs its output asserted, not its success.


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

### Stage C — the routers that sit on `site` — **met**

`websites` write half (20 endpoints, 1,374 lines), then `maintenance` (67
endpoints, 1,670 lines). Split `maintenance` by sub-area — backup, restore,
cron, logs — rather than attempting it whole.

**Exit:** shadow diff green for both; endpoint coverage ≥ **60%**.

**Both met.** Coverage is 127 of 211 (60%), and the shadow diff is
**109 of 109 requests identical**, run twice back to back on Debian 13 with
the Rust front door on :2222 and Python on loopback. The corpus grew from 90
requests to 109 for this: nineteen reads across `websites`, `waf` and
`maintenance`, including the whole per-site WAF page and a file-manager path
that climbs out of the site root, where agreeing on the *message* matters as
much as agreeing on the status.

Only reads were added. A shadow diff calls both sides with the same request,
so a write would run twice and the second call would be compared against a
world the first had already changed. Every Stage C write is covered by a
golden corpus instead, where what is compared is the bytes it would produce.

**The live run found two bugs that every test had passed over.**

*The Rust API could not start.* `/websites/{website_id}/nginx-custom` was
registered twice — once for `GET`, once for `PUT` — each `.route()` attaching
its own `.fallback()`. axum merges two `MethodRouter`s for one path and
panics when both carry a fallback:

```text
thread 'main' panicked at routes/websites.rs:89:10:
Cannot merge two `MethodRouter`s that both have a fallback
```

It had been on `main` since at least `f802d07c` and nothing noticed, because a
router is only assembled at startup and no test assembled one. The deployed
binary predated the commit that introduced it, so the running panel was fine
and the repository was not. A deploy found it in four seconds.
`routes::tests::the_api_router_can_be_built` now builds it, and the test's
only assertion is that the call returns.

*`POST /users/{id}/password` checked in the wrong order.* A short password
against a non-existent id answered 404 from Rust and 422 from Python:
`UserPasswordUpdate` declares `password: str = Field(min_length=12)`, and
FastAPI validates the model before the handler runs. Not only a status code —
the Rust order told a caller whether a user id existed before it had looked at
what they sent.

One difference is declared rather than fixed. `GET /firewall/status` returns a
`CommandResult` whose `command` field is what actually ran, and since the
Stage B cutover the Rust side answers over the helper socket and reports
`firewall-status` while Python shells out and reports the `sudo` line. Both
are truthful about their own process. It is marked volatile *at that case*
with the distinction spelled out — it is a transition artefact, not a moving
reading — and it has to come back out when Python goes.

### Stage D — the remaining helper domains

Runs in parallel with C. The domains with no Rust module: `panel` (9 verbs),
`certbot` (6), `maldet` (6), `clamav` (4), `docker` (4), `ipv6` (4), `updates`
(4), `cron` (2), `time` (2), `node` (2), and the singletons. The five dead verbs in §3 are already gone.

**Exit:** every verb the panel's Python calls answered by Rust.

**Done.** All **106** of them — the figure was 105 until
`every_bash_verb_is_mapped_or_listed_as_unported` found two the hand-kept
survey had never seen. The test owns the list now and it is empty; a verb
added to the bash and called from Python without an arm here fails that
assertion rather than falling through and working.

What remains of the bash helper is **16 verbs no caller reaches**: aliases it
keeps "so an API process that has not been restarted yet keeps working during
an update" (`ufw-*`, `nginx-blocklist-*`), and installer-time operations the
panel never invokes. Removing the file is a Stage G question — either those
aliases go with it, or they need arms here first.

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
