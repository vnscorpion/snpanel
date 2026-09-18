# IMPROVEMENTS.md

NT1 of `RUST_MIGRATION_PLAN.md` says: port 1:1, do not improve. Bugs get
ported as bugs. This file is the pressure valve — every "while we are in here
we could also…" goes here instead of into the port, and gets revisited after
Phase 6.

The plan calls NT1 the rule most likely to be broken and the number one reason
rewrites fail. Writing the idea down is what makes it cheap to not do it now.

---

## Deferred

### I1 — `ratatui` rescue menu
Phase 1 suggests a full-screen TUI. Shipped as plain text instead, matching the
bash exactly. Reasons: the current menu is plain text, so plain text is the
1:1 port; this is the screen an operator reaches when the box is already
broken, and a full-screen TUI needs terminal capabilities a serial console or
a degraded SSH session may not have. `menu.rs` keeps the dispatch table
separate from the rendering, so a `ratatui` front end can be added over it
without touching behaviour.

### I2 — Unknown-field rejection inside a helper request
`#[serde(deny_unknown_fields)]` does not work on an internally tagged enum, so
an unexpected field inside `request` is ignored rather than refused. The
`Envelope`'s `version` covers the case that actually matters (version skew
between API and helper). Fixing it properly means adjacently tagging the enum
and giving every variant its own struct — a large mechanical change, worth
doing when the remaining ~110 variants are written in Phase 2 rather than
twice.

### I3 — Per-rule counters in the firewall
nftables can attach a `counter` to each rule, which would make "why was this
packet dropped" answerable from `nft list ruleset`. The iptables version has no
such thing, so adding it now would be an improvement, not a port. Cheap to add
later; the renderer is one function.

### I4 — `rules.tsv` is rewritten whole on every change
Fine at the current scale and unchanged from the bash. If a customer ever
accumulates tens of thousands of rules this becomes the bottleneck. Do not
touch it during the port: it is also what makes the backend swap safe.

### I4b — route vhost writes through the helper
`/etc/nginx/conf.d` is `root:snpanel 2775`, so the unprivileged API writes
vhosts into nginx's configuration directory itself
(`services/nginx.py::write_vhost` calls `target.write_text`). No helper is
involved, and therefore none of the helper's checks apply to the most
security-relevant file the panel generates.

`HelperRequest::NginxWriteSite` already exists for this and is implemented -
it writes atomically, runs `nginx -t`, and **restores the previous file if the
new one is rejected**, which the direct write does not. It has no bash
counterpart and so no CLI name; it is reachable only over the socket, which is
the transport the ported API will use.

Closing this means the `snpanel` account no longer needs write access to
`/etc/nginx`, which is a real narrowing of the privilege boundary. Deliberately
not done during the port: NT1, and changing it now would mean changing
`nginx.py` while it is still the thing serving traffic.

### I5 — `snpanel doctor` could check more
Currently: OS, CPU baseline, config, firewall backend, SELinux, key paths.
Obvious additions once the API is ported — certificate expiry, disk space per
site, PHP-FPM pool health, whether the panel port is actually listening,
whether `rules.tsv` and the loaded ruleset agree. Deliberately left out for
now so `doctor` stays read-only and dependency-free.

### I6 — Fernet tokens carry a timestamp nobody reads
`secrets.decrypt` never passes a TTL, so the timestamp in every stored
ciphertext is written and ignored. Keeping it (we must — it is part of the
format), but a future rekey could record real rotation metadata instead.

---

## Done differently on purpose, with reasons

These are not deferred — they are decisions where following the plan's text
literally would have been wrong. Each is recorded so the divergence is a
choice on the record rather than a mistake nobody noticed.

### D1 — The nft ruleset is fuller than the plan's sketch
`RUST_MIGRATION_PLAN.md` §6.3 shows a sample ruleset. Compared against
`firewall_apply_family` in the bash helper, the sketch omits three things, all
of which are implemented:

1. `ct state invalid drop`.
2. An ICMP `return`. The bash has a comment noting that dropping ICMPv6 breaks
   neighbour discovery, i.e. breaks IPv6 entirely.
3. The `denyp4`/`denyp6` sets — deny a source *and* a port. The sketch has only
   the whole-host deny sets, so every port-scoped deny rule would have silently
   widened into a whole-host deny.

The sketch is illustrative; the bash is the specification. Covered by tests in
`crates/snpanel-osabi/src/firewall/nft.rs`.

### D2 — IPv6 rules are always rendered
An earlier revision gated the v6 sets on the host having a global IPv6 address.
That silently dropped an existing `deny 2001:db8::/32` rule from `rules.tsv`
during migration — the rule would vanish from the firewall while still being
listed in the panel UI. The bash gate (`firewall_has_ipv6`) tests whether
`ip6tables` can filter at all, which is a different question, and one that
`table inet` makes moot. Regression test:
`v6_rules_are_rendered_even_on_a_v4_only_host`.

### D3 — TOTP accepts secrets shorter than the RFC minimum
`totp-rs` refuses a secret under 128 bits; pyotp does not. SNPanel's own
enrolments are 160-bit, but a secret imported from another panel or issued by
an older version can be shorter, and refusing it would lock that user out of
their account with no recovery path but a support ticket. `TOTP::new_unchecked`
matches pyotp. New secrets are still generated at 160 bits.

### D4 — EL rebuilds share the AlmaLinux implementation
Rocky, RHEL and Oracle 10 have byte-identical layouts to AlmaLinux 10, so
`detect` accepts them. The plan lists this under Phase 7; refusing a system
that is already handled correctly would be an arbitrary "unsupported".

### D5 — `Settings` has a hand-written `Debug`
A derived one puts `SECRET_KEY` and `GITHUB_TOKEN` into any log line or panic
message that formats the settings — which is exactly the output that gets
pasted into a support ticket. Both fields render as `<redacted>`.

### D6 — Default SIGPIPE is restored in the CLI
Rust sets `SIGPIPE` to `SIG_IGN` at startup, which turns `snpanel status | head`
into a panic with a backtrace. Every other tool on the box exits quietly there.
