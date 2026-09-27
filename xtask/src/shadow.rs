//! `cargo xtask shadow-diff` - plan §9.3.
//!
//! Send the same request to both implementations and compare the answers. Any
//! difference is a bug in the Rust side (NT7), so the tool's job is to make
//! differences impossible to miss and easy to read.
//!
//! What is compared, and what is deliberately not:
//!
//! - **status code** - always.
//! - **body** - as JSON, with object keys ordered, so a serialiser that emits
//!   fields in a different order does not read as a difference. Key *order* is
//!   not part of any JSON contract; key *presence* and values are.
//! - **headers** - only the ones that carry meaning to the frontend.
//!   `Date`, `Server` and `Content-Length` differ by construction and comparing
//!   them would bury the real differences in noise.
//!
//! Some values cannot match and saying so is part of the tool: a timestamp, a
//! CPU percentage or a free-memory figure read microseconds apart will differ
//! between the two calls no matter how correct both are. Those paths are
//! declared volatile and compared structurally - same keys, same types - rather
//! than by value.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Values that legitimately differ between two calls, by **full path**.
///
/// Full paths, not leaf names, and the distinction earns its keep: `cpu.percent`
/// is a live sample and must be allowed to vary, while `disk.total` and
/// `memory.total` must not - those are exactly where a unit mistake shows up,
/// and marking a bare `percent` or `total` volatile would have hidden the
/// bytes-versus-megabytes bug this tool was written to catch.
///
/// Each entry is a claim that the value is a reading of a moving thing, not a
/// licence to silence a difference that is inconvenient.
const VOLATILE: &[&str] = &[
    // Two independent 0.2-second samples taken moments apart.
    "cpu.percent",
    "cpu.load",
    // Memory moves continuously; the totals do not and are still compared.
    "memory.used",
    "memory.available",
    "memory.percent",
    // Counters that only go up.
    "network.rx_per_sec",
    "network.tx_per_sec",
    "network.rx_total",
    "network.tx_total",
    // A busy box writes between the two calls.
    "disk.used",
    "disk.free",
    "disk.percent",
    // /api/services/system-info returns raw `free -m` and `df -h` output.
    "memory",
    "disk",
    "uptime",
    "timestamp",
    // A CSRF token is freshly minted on any call that has no cookie to reuse,
    // so two calls can never agree on the value. Its presence and type are
    // still compared.
    "csrf_token",
    // A one-shot SSO link carries a fresh 256-bit token. The *status* is what
    // this case is for - a failed decrypt is a 500 here and a 200 there, which
    // the comparison catches - and the password behind it is checked directly
    // by the C3 cross-check in api-shadow-check.sh.
    "url",
];

struct Case {
    method: &'static str,
    path: &'static str,
    body: Option<&'static str>,
    /// Send the body as a form rather than JSON.
    ///
    /// `/auth/login` reads an OAuth2 form. Posting JSON to it earns a 422 from
    /// both implementations - which would compare as "same" while testing
    /// nothing at all.
    form: bool,
    /// Paths that vary for *this endpoint only*.
    ///
    /// The global VOLATILE list is a claim about a field wherever it appears;
    /// this is a claim about one endpoint. `stdout` is the example that forced
    /// the distinction: `updates-os-auto` runs `apt-get update`, whose "Hit:"
    /// lines come back in whatever order the mirrors answer, while `stdout` on
    /// the firewall endpoints is exactly what has to be compared.
    volatile: &'static [&'static str],
}

/// The requests to compare. Grows as routers are ported.
const CASES: &[Case] = &[
    Case {
        method: "GET",
        path: "/api/health",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/services/list",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/services/system-info",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/services/resource-usage",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/services/action",
        body: Some(r#"{"name":"nginx","action":"status"}"#),
        form: false,
        volatile: &[],
    },
    // The refusals matter as much as the successes: a port that accepts what
    // the original refused is a security regression, not a cosmetic one.
    Case {
        method: "POST",
        path: "/api/services/action",
        body: Some(r#"{"name":"sshd","action":"restart"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/services/action",
        body: Some(r#"{"name":"snpanel-api","action":"stop"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/services/action",
        body: Some(r#"{"name":"nginx","action":"mask"}"#),
        form: false,
        volatile: &[],
    },
    // ---- auth -----------------------------------------------------------
    //
    // `/session` is the SPA's bootstrap: every field it returns is rendered
    // somewhere, and `storage_used_bytes` is the one that catches a unit
    // mistake, because it is a real walk of a real website tree on both sides.
    Case {
        method: "GET",
        path: "/api/auth/session",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/auth/csrf",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/auth/2fa/status",
        body: None,
        form: false,
        volatile: &[],
    },
    // A wrong password. Compared for the *message* as much as the status: a
    // reply that distinguishes "no such user" from "wrong password" is a
    // username oracle, and this case is what would catch one appearing.
    Case {
        method: "POST",
        path: "/api/auth/login",
        body: Some("username=admin&password=definitely-not-the-password"),
        form: true,
        volatile: &[],
    },
    // A user that does not exist has to look identical to the case above.
    Case {
        method: "POST",
        path: "/api/auth/login",
        body: Some("username=nobody-at-all&password=definitely-not-the-password"),
        form: true,
        volatile: &[],
    },
    // Over the 72-byte cap: refused before bcrypt ever sees it.
    Case {
        method: "POST",
        path: "/api/auth/login",
        body: Some(
            "username=admin&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        form: true,
        volatile: &[],
    },
    // Missing fields: FastAPI's 422 is a list under `detail`, not a string,
    // and each entry carries `input` as well as `type`, `loc` and `msg`.
    Case {
        method: "POST",
        path: "/api/auth/login",
        body: Some("username=admin"),
        form: true,
        volatile: &[],
    },
    // Both fields missing: Pydantic reports *both*, not the first. A port that
    // stopped at the first would send the user round the loop twice.
    Case {
        method: "POST",
        path: "/api/auth/login",
        body: Some(""),
        form: true,
        volatile: &[],
    },
    // A body that is valid JSON but not an object.
    Case {
        method: "POST",
        path: "/api/auth/2fa/enable",
        body: Some(r#""just-a-string""#),
        form: false,
        volatile: &[],
    },
    // Too short for the field's min_length, which carries `ctx` as well.
    Case {
        method: "POST",
        path: "/api/auth/2fa/enable",
        body: Some(r#"{"code":"123"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/auth/2fa/enable",
        body: Some("{}"),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/auth/2fa/enable",
        body: Some(r#"{"code":"000000"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/auth/2fa/disable",
        body: Some(r#"{"current_password":"wrong-password"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/auth/sso/nosuchtokenatall",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/auth/impersonate/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- packages -------------------------------------------------------
    //
    // Read-only and refusal cases only. A create through both sides would
    // leave two packages behind on a live panel, and a diff tool that mutates
    // the system it is comparing is one nobody will run twice.
    Case {
        method: "GET",
        path: "/api/packages",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "PATCH",
        path: "/api/packages/99999",
        body: Some(r#"{"website_limit":10}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "DELETE",
        path: "/api/packages/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    // The bounds, which are what stop a storage limit overflowing when it is
    // multiplied into bytes.
    Case {
        method: "POST",
        path: "/api/packages",
        body: Some(r#"{"name":"shadow-diff","website_limit":99999}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/packages",
        body: Some(r#"{"name":"shadow-diff","node_app_memory_mb":8}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/packages",
        body: Some(r#"{"name":"   "}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/packages",
        body: Some(r#"{"website_limit":5}"#),
        form: false,
        volatile: &[],
    },
    // The name of the package the installer creates, so both sides must
    // answer 409 rather than making a second one.
    Case {
        method: "POST",
        path: "/api/packages",
        body: Some(r#"{"name":"Default"}"#),
        form: false,
        volatile: &[],
    },
    // ---- users ----------------------------------------------------------
    Case {
        method: "GET",
        path: "/api/users",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/me",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/audit/log?limit=5",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/audit/log?limit=5&action=update_package",
        body: None,
        form: false,
        volatile: &[],
    },
    // The query-parameter bounds, whose 422s carry `loc: ["query", ...]`
    // rather than `["body", ...]`.
    Case {
        method: "GET",
        path: "/api/users/audit/log?limit=0",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/audit/log?limit=9999",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/audit/log?offset=-1",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/users/audit/log?limit=abc",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "PATCH",
        path: "/api/users/99999",
        body: Some(r#"{"website_limit":10}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/users/99999/2fa/reset",
        body: None,
        form: false,
        volatile: &[],
    },
    // The two self-lockout guards. User 1 is the admin the token belongs to,
    // so these are the real refusals rather than a 404 on the way past them.
    Case {
        method: "PATCH",
        path: "/api/users/1",
        body: Some(r#"{"role":"end_user"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "PATCH",
        path: "/api/users/1",
        body: Some(r#"{"is_active":false}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/users/1/2fa/reset",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "PATCH",
        path: "/api/users/1",
        body: Some(r#"{"role":"root"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "PATCH",
        path: "/api/users/1",
        body: Some(r#"{"package_id":99999}"#),
        form: false,
        volatile: &[],
    },
    // A method this router has *not* ported: it must reach Python through the
    // method-level fallback rather than coming back 405.
    Case {
        method: "DELETE",
        path: "/api/users/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/users/99999/password",
        body: Some(r#"{"password":"short"}"#),
        form: false,
        volatile: &[],
    },
    // ---- firewall -------------------------------------------------------
    //
    // Reads and refusals. Nothing here opens or closes a port: a diff tool
    // that changes the firewall of the machine it is comparing is one nobody
    // should run twice.
    Case {
        method: "GET",
        path: "/api/firewall/status",
        body: None,
        form: false,
        // **Not a moving reading**, unlike every other entry here, and the
        // difference is worth stating rather than hiding.
        //
        // `command` is what actually ran. Since the Stage B cutover the Rust
        // side answers this over the helper socket and reports the verb -
        // `firewall-status` - while Python still shells out and reports
        // `sudo -n /usr/local/sbin/snpanel-helper firewall-status`. Each is
        // truthful about its own process; they are different processes.
        //
        // It disappears when Python does, and at that point this entry has to
        // come back out rather than quietly keep covering something else.
        // Every other field of the result, `returncode` and both streams
        // included, is still compared.
        volatile: &["command"],
    },
    Case {
        method: "GET",
        path: "/api/firewall/blocklists",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "DELETE",
        path: "/api/firewall/rules/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "DELETE",
        path: "/api/firewall/rules/0",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/allow-port",
        body: Some(r#"{"port":"70000"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/allow-port",
        body: Some(r#"{"port":"80","protocol":"icmp"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/allow-port",
        body: Some("{}"),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/allow-ip",
        body: Some(r#"{"ip":"not-an-address"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/block-ip",
        body: Some(r#"{"ip":"10.0.0.0/33"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/blocklists",
        body: Some(r#"{"url":"ftp://example.com/list.txt"}"#),
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/firewall/blocklists",
        body: Some(r#"{"url":"short"}"#),
        form: false,
        volatile: &[],
    },
    // ---- databases ------------------------------------------------------
    Case {
        method: "GET",
        path: "/api/databases",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/databases?q=wp",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/databases?q=nothing-matches-this",
        body: None,
        form: false,
        volatile: &[],
    },
    // A one-shot hand-off on a real database: the token differs every time and
    // is volatile, but a Fernet key derivation that disagreed with Python's
    // fails here as a 500 against a 200 (C3, risk R1).
    Case {
        method: "POST",
        path: "/api/databases/1/phpmyadmin-sso",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/databases/99999/phpmyadmin-sso",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/databases/phpmyadmin-sso/nosuchtoken",
        body: None,
        form: false,
        volatile: &[],
    },
    // Not ported: must reach Python rather than 405.
    Case {
        method: "DELETE",
        path: "/api/databases/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- updates --------------------------------------------------------
    //
    // `status` is a read, and the release check behind it is cached in a state
    // file *both* implementations share - so whichever one refreshes writes
    // the answer and the other reads it. That sharing is what makes this case
    // comparable at all.
    Case {
        method: "GET",
        path: "/api/updates/status",
        body: None,
        form: false,
        volatile: &[],
    },
    // The mode guard. Nothing is configured: the value is refused before the
    // helper is reached.
    Case {
        method: "POST",
        path: "/api/updates/os/auto",
        body: Some(r#"{"enabled":true,"mode":"everything"}"#),
        form: false,
        volatile: &[],
    },
    // Both of these reach the helper, and both are *idempotent*: each writes
    // the same unattended-upgrades configuration (security updates on, no
    // automatic reboot), which is the panel's own default. They are here
    // because every field of SystemAutoUpdateConfig has a default, so `{}` is
    // a valid body - and reading the service's ValueError instead of the
    // schema made this a 422 where the panel answers 200.
    Case {
        method: "POST",
        path: "/api/updates/os/auto",
        body: Some(r#"{"enabled":true}"#),
        form: false,
        volatile: &["stdout", "stderr"],
    },
    // ---- websites -------------------------------------------------------
    //
    // The listing is the busiest page in the panel, and the one endpoint here
    // that *writes*: a certificate found on disk turns `ssl_enabled` on. Both
    // sides see the same filesystem, so they agree - and if they did not, the
    // second call would be comparing against a row the first had corrected.
    Case {
        method: "GET",
        path: "/api/websites",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites?q=sgd",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites?q=nothing-matches-this",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/1/aliases",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/1/nginx-custom",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/1/nginx-config",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/99999/aliases",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/99999/nginx-config",
        body: None,
        form: false,
        volatile: &[],
    },
    // Not ported: creating a site makes a Linux account and renders a vhost.
    Case {
        method: "DELETE",
        path: "/api/websites/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- panel settings -------------------------------------------------
    //
    // `/public` is the only unauthenticated endpoint in the panel, and the
    // three fields it projects are a security boundary: everything else in
    // the settings describes the server and its customers.
    Case {
        method: "GET",
        path: "/api/panel-settings/public",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/panel-settings",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- malware --------------------------------------------------------
    //
    // Four sources in one reply: the clamd socket, the maldet binary, the
    // settings file and /proc/meminfo. `memory_available_mb` moves between
    // two calls; the total does not, and it is the one that catches a
    // kilobytes-for-megabytes mistake.
    Case {
        method: "GET",
        path: "/api/malware/status",
        body: None,
        form: false,
        volatile: &["memory_available_mb"],
    },
    // Not ported: starting a scan drives the helper.
    Case {
        method: "POST",
        path: "/api/malware/run",
        body: Some(r#"{"target":"nonsense"}"#),
        form: false,
        volatile: &[],
    },
    // ---- waf and terminal -----------------------------------------------
    Case {
        method: "GET",
        path: "/api/waf/status",
        body: None,
        form: false,
        volatile: &[],
    },
    // Three helper calls and a catalogue the panel holds in code. The
    // catalogue was generated from the Python's own list, so a difference here
    // would be a transcription error in eight strings of prose.
    Case {
        method: "GET",
        path: "/api/waf/rules",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/terminal/allowed-commands",
        body: None,
        form: false,
        volatile: &[],
    },
    // Not ported: both run through the helper's terminal trampoline.
    Case {
        method: "POST",
        path: "/api/terminal/exec/99999",
        body: Some(r#"{"command":"ls"}"#),
        form: false,
        volatile: &[],
    },
    // ---- Stage C: the site routers ---------------------------------------
    //
    // Reads only, and deliberately so. A shadow diff calls both sides with the
    // same request, so a *write* would run twice: the first call changes the
    // machine and the second is then compared against a world the first
    // already altered. Every write ported in Stage C is covered by a golden
    // corpus instead, where the comparison is of the bytes it would produce
    // rather than of the effect of producing them twice.
    Case {
        method: "GET",
        path: "/api/websites/1/ssl/sources",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/99999/ssl/sources",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/1/ssl/cloudflare-zone",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/websites/99999/ssl/cloudflare-zone",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- the WAF page ----------------------------------------------------
    //
    // `waf/websites/{id}` is the whole per-site page: the rule selection, the
    // CRS state, the flood limits and the three bot lists. It is the single
    // richest read Stage C added, which makes it the one most worth comparing
    // against the real thing.
    Case {
        method: "GET",
        path: "/api/waf/websites/1",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/waf/websites/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/waf/bots",
        body: None,
        form: false,
        volatile: &[],
    },
    // `/waf/crs` reports what nginx has loaded *and* a memory estimate. The
    // measured figures move between two calls; the estimate and the opt-in
    // count do not, and those are what the page acts on.
    Case {
        method: "GET",
        path: "/api/waf/crs",
        body: None,
        form: false,
        volatile: &["nginx_pss_mb", "ram_available_mb"],
    },
    // Scanning for orphans touches nothing - that is the endpoint's whole
    // claim, and running it twice is how the claim gets tested.
    Case {
        method: "GET",
        path: "/api/waf/orphans",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- maintenance -----------------------------------------------------
    Case {
        method: "GET",
        path: "/api/maintenance/cron/1",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/cron/99999",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/da-import/backups",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/files/1",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/files/1?path=public_html",
        body: None,
        form: false,
        volatile: &[],
    },
    // A path that climbs out of the site root. Both sides must refuse it, and
    // with the same words: this is the one comparison where agreeing on the
    // *message* matters as much as agreeing on the status.
    Case {
        method: "GET",
        path: "/api/maintenance/files/1?path=../../etc",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/backups/1",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/user-backups",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/backup-schedules",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/sftp-targets",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "GET",
        path: "/api/maintenance/php-config",
        body: None,
        form: false,
        volatile: &[],
    },
    // ---- the panel settings write half -----------------------------------
    //
    // Not called: `PATCH /panel-settings` can run `panel-url-set`, which
    // rewrites the panel's own nginx server block. A shadow diff would do it
    // twice and the second call would be comparing against a panel the first
    // had already moved.
    // ---- addons ---------------------------------------------------------
    Case {
        method: "GET",
        path: "/api/addons",
        body: None,
        form: false,
        volatile: &[],
    },
    // Not ported: installing one stops every site app first.
    Case {
        method: "POST",
        path: "/api/addons/nosuchaddon/install",
        body: None,
        form: false,
        volatile: &[],
    },
    Case {
        method: "POST",
        path: "/api/updates/os/auto",
        body: Some(r#"{"mode":"security"}"#),
        form: false,
        // `apt-get update` lists its repositories in whatever order the
        // mirrors answer, so two runs a second apart disagree on the order of
        // the "Hit:" lines. stderr is the same kind of thing on a freshly
        // installed machine: "Deferring configuration of apt-listchanges"
        // appears on the first run and never again, so the second caller sees
        // a shorter message. The status and every other field are still
        // compared, and both streams stay compared on every other endpoint.
        volatile: &["stdout", "stderr"],
    },
];

pub fn run(args: &[String]) -> Result<()> {
    let rust = flag(args, "--rust").unwrap_or_else(|| "http://127.0.0.1:2223".into());
    let python = flag(args, "--python").unwrap_or_else(|| "http://127.0.0.1:8000".into());
    let token = flag(args, "--token").context(
        "--token is required: both sides need an authenticated request, and the \
         point of the exercise is that the *same* token works against both",
    )?;

    println!("rust:   {rust}");
    println!("python: {python}\n");

    let mut differences = 0usize;
    for case in CASES {
        let label = format!("{} {}", case.method, case.path);
        let a = call(&rust, case, &token).with_context(|| format!("calling rust: {label}"))?;
        let b = call(&python, case, &token).with_context(|| format!("calling python: {label}"))?;

        match compare(&a, &b, case) {
            Ok(()) => println!("  same   {label}  [{}]", a.status),
            Err(reason) => {
                differences += 1;
                println!("  DIFF   {label}");
                for line in reason.lines() {
                    println!("           {line}");
                }
            }
        }
    }

    println!();
    if differences > 0 {
        bail!(
            "{differences} of {} requests differ; every one is a bug in the Rust side (NT7)",
            CASES.len()
        );
    }
    println!("all {} requests match", CASES.len());
    Ok(())
}

struct Reply {
    status: u16,
    body: String,
}

fn call(base: &str, case: &Case, token: &str) -> Result<Reply> {
    let url = format!("{}{}", base.trim_end_matches('/'), case.path);
    let mut argv: Vec<String> = vec![
        "curl".into(),
        "-sk".into(),
        "--max-time".into(),
        "30".into(),
        "-X".into(),
        case.method.into(),
        "-H".into(),
        format!("Authorization: Bearer {token}"),
        "-w".into(),
        "\n%{http_code}".into(),
    ];
    if let Some(body) = case.body {
        argv.push("-H".into());
        argv.push(if case.form {
            "Content-Type: application/x-www-form-urlencoded".to_string()
        } else {
            "Content-Type: application/json".to_string()
        });
        argv.push("-d".into());
        argv.push(body.into());
    }
    argv.push(url);

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, status) = text
        .rsplit_once('\n')
        .map(|(b, s)| (b.to_string(), s.trim().parse::<u16>().unwrap_or(0)))
        .unwrap_or((text.clone(), 0));
    Ok(Reply { status, body })
}

fn compare(rust: &Reply, python: &Reply, case: &Case) -> Result<(), String> {
    if rust.status != python.status {
        return Err(format!(
            "status: rust {} vs python {}\nrust body:   {}\npython body: {}",
            rust.status,
            python.status,
            truncate(&rust.body),
            truncate(&python.body)
        ));
    }

    let a: Value = serde_json::from_str(&rust.body)
        .map_err(|e| format!("rust body is not JSON: {e}\n{}", truncate(&rust.body)))?;
    let b: Value = serde_json::from_str(&python.body)
        .map_err(|e| format!("python body is not JSON: {e}\n{}", truncate(&python.body)))?;

    let mut differences = Vec::new();
    diff(&a, &b, "", case.volatile, &mut differences);
    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences.join("\n"))
    }
}

/// Walk both values together, reporting each place they disagree.
///
/// Reporting *every* difference rather than the first: a port usually gets a
/// field name wrong in several places at once, and fixing them one round trip
/// at a time is slow.
fn diff(a: &Value, b: &Value, path: &str, case_volatile: &[&str], out: &mut Vec<String>) {
    // Array indices are stripped so `services[3]` is matched as `services`;
    // the path is otherwise compared whole.
    let key = path.split('[').next().unwrap_or(path);
    let volatile = VOLATILE.contains(&key) || case_volatile.contains(&key);

    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let xk: BTreeMap<_, _> = x.iter().collect();
            let yk: BTreeMap<_, _> = y.iter().collect();
            for key in xk
                .keys()
                .chain(yk.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                let child = if path.is_empty() {
                    (*key).clone()
                } else {
                    format!("{path}.{key}")
                };
                match (xk.get(*key), yk.get(*key)) {
                    (Some(av), Some(bv)) => diff(av, bv, &child, case_volatile, out),
                    (Some(_), None) => out.push(format!("{child}: only rust has it")),
                    (None, Some(_)) => out.push(format!("{child}: only python has it")),
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                out.push(format!(
                    "{path}: rust has {} items, python has {}",
                    x.len(),
                    y.len()
                ));
                return;
            }
            // Order matters: the service list's order is part of its contract.
            for (i, (av, bv)) in x.iter().zip(y.iter()).enumerate() {
                diff(av, bv, &format!("{path}[{i}]"), case_volatile, out);
            }
        }
        _ => {
            if volatile {
                // Same shape is all that can be asked of a live reading.
                if std::mem::discriminant(a) != std::mem::discriminant(b) {
                    out.push(format!(
                        "{path}: type differs ({} vs {})",
                        type_of(a),
                        type_of(b)
                    ));
                }
            } else if a != b {
                out.push(format!(
                    "{path}: rust {} vs python {}",
                    truncate(&a.to_string()),
                    truncate(&b.to_string())
                ));
            }
        }
    }
}

fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn truncate(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s.to_string()
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn differences(a: Value, b: Value) -> Vec<String> {
        let mut out = Vec::new();
        diff(&a, &b, "", &[], &mut out);
        out
    }

    /// A case with no per-endpoint volatiles, for the comparison tests.
    const PLAIN: Case = Case {
        method: "GET",
        path: "/api/test",
        body: None,
        form: false,
        volatile: &[],
    };

    #[test]
    fn identical_bodies_have_no_differences() {
        let v = serde_json::json!({"status":"ok","name":"SNPanel","version":"1.0.134"});
        assert!(differences(v.clone(), v).is_empty());
    }

    #[test]
    fn key_order_is_not_a_difference() {
        // Key order carries no meaning in JSON; reporting it would bury the
        // differences that do.
        let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert!(differences(a, b).is_empty());
    }

    #[test]
    fn a_missing_field_is_reported_with_which_side_has_it() {
        let a = serde_json::json!({"status":"ok"});
        let b = serde_json::json!({"status":"ok","name":"SNPanel"});
        let d = differences(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("name"));
        assert!(d[0].contains("only python"));
    }

    #[test]
    fn array_order_is_a_difference_because_the_service_list_depends_on_it() {
        let a = serde_json::json!({"services":["snpanel-api","nginx","mariadb"]});
        let b = serde_json::json!({"services":["nginx","snpanel-api","mariadb"]});
        let d = differences(a, b);
        assert!(!d.is_empty(), "order must be compared");
        assert!(d[0].contains("services[0]"));
    }

    #[test]
    fn a_length_difference_is_reported_once_not_per_element() {
        let a = serde_json::json!({"services":["a","b","c"]});
        let b = serde_json::json!({"services":["a"]});
        let d = differences(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("3 items"));
    }

    #[test]
    fn volatile_readings_are_compared_by_type_not_by_value() {
        // Two calls moments apart legitimately see different CPU figures.
        let a = serde_json::json!({"cpu": {"percent": 12.5, "cores": 4}});
        let b = serde_json::json!({"cpu": {"percent": 13.1, "cores": 4}});
        assert!(differences(a, b).is_empty());
    }

    #[test]
    fn a_total_is_not_volatile_just_because_a_percent_is() {
        // This is the distinction full-path matching buys. A bare `percent`
        // or `total` in the list would have hidden the bytes-versus-megabytes
        // bug that this tool was written to catch.
        let a = serde_json::json!({"memory": {"total": 8_000_000_000u64, "percent": 41.0}});
        let b = serde_json::json!({"memory": {"total": 7800u64, "percent": 42.0}});
        let d = differences(a, b);
        assert_eq!(d.len(), 1, "the total must still be compared: {d:?}");
        assert!(d[0].contains("memory.total"));
    }

    #[test]
    fn a_volatile_field_of_the_wrong_type_is_still_a_difference() {
        // Being allowed to vary is not being allowed to change shape: the
        // Dashboard does arithmetic on cpu.percent.
        let a = serde_json::json!({"cpu": {"percent": "12.5"}});
        let b = serde_json::json!({"cpu": {"percent": 13.1}});
        let d = differences(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("type differs"));
    }

    #[test]
    fn a_volatile_path_does_not_silence_a_same_named_key_elsewhere() {
        // `disk` is volatile in system-info, where it is raw `df -h` text.
        // `disk.mount` in resource-usage is not.
        let a = serde_json::json!({"disk": {"mount": "/"}});
        let b = serde_json::json!({"disk": {"mount": "/srv"}});
        let d = differences(a, b);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("disk.mount"));
    }

    #[test]
    fn a_non_volatile_value_difference_is_reported() {
        let a = serde_json::json!({"name":"snpanel"});
        let b = serde_json::json!({"name":"SNPanel"});
        let d = differences(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("name"));
    }

    #[test]
    fn every_difference_is_reported_not_just_the_first() {
        let a = serde_json::json!({"one":1,"two":2,"three":3});
        let b = serde_json::json!({"one":9,"two":8,"three":7});
        assert_eq!(differences(a, b).len(), 3);
    }

    #[test]
    fn the_case_list_covers_refusals_as_well_as_successes() {
        // A port that accepts what the original refused is a security
        // regression, so the refusals have to be in the comparison set.
        let refusals = CASES
            .iter()
            .filter(|c| {
                c.body
                    .map(|b| b.contains("sshd") || b.contains("mask") || b.contains("\"stop\""))
                    .unwrap_or(false)
            })
            .count();
        assert!(refusals >= 3, "expected the refusal cases to be present");
    }

    #[test]
    fn a_case_volatile_silences_that_field_and_only_that_field() {
        let a = serde_json::json!({"stdout": "one", "returncode": 0});
        let b = serde_json::json!({"stdout": "two", "returncode": 0});

        // Without the per-case entry this is a difference, as it should be on
        // every other endpoint that returns a command's output.
        let mut plain = Vec::new();
        diff(&a, &b, "", &[], &mut plain);
        assert_eq!(plain.len(), 1, "{plain:?}");

        let mut with_volatile = Vec::new();
        diff(&a, &b, "", &["stdout"], &mut with_volatile);
        assert!(with_volatile.is_empty(), "{with_volatile:?}");
    }

    #[test]
    fn a_case_volatile_does_not_excuse_a_different_type() {
        // Being allowed to vary is not being allowed to change shape: a string
        // where the other side sends a number is still a difference.
        let a = serde_json::json!({"stdout": "text"});
        let b = serde_json::json!({"stdout": 7});
        let mut out = Vec::new();
        diff(&a, &b, "", &["stdout"], &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("type differs"), "{}", out[0]);
    }

    #[test]
    fn a_case_volatile_does_not_excuse_a_missing_field() {
        let a = serde_json::json!({"stdout": "text", "returncode": 0});
        let b = serde_json::json!({"returncode": 0});
        let mut out = Vec::new();
        diff(&a, &b, "", &["stdout"], &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("only rust has it"), "{}", out[0]);
    }

    #[test]
    fn a_status_mismatch_is_reported_before_the_body_is_parsed() {
        let rust = Reply {
            status: 200,
            body: "{}".into(),
        };
        let python = Reply {
            status: 403,
            body: "{}".into(),
        };
        let err = compare(&rust, &python, &PLAIN).unwrap_err();
        assert!(err.contains("status"));
        assert!(err.contains("403"));
    }
}
