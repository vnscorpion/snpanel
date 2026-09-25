//! The MCP tools: thirty-two, as OPanel's addon has them.
//!
//! Twenty for every account, on its own resources - an administrator's on
//! everybody's - and twelve for administrators. A tool that changes
//! something goes through the panel's own endpoint ([`Context::call`]); one
//! that only reads may read the database directly, which is also how what it
//! shows is chosen field by field rather than passed through: a website's
//! row carries its panel password, and no assistant needs that.

use std::sync::Arc;

use axum::http::Method;
use serde_json::{json, Map, Value};
use snpanel_core::crypto::sigv4::uri_encode;

use super::guards::{self, RuleMatch};
use super::{iso, Arguments, Context, Param, Tool, ToolError, ToolFuture, ToolResult};

const DOMAIN: Param = Param::text("domain", "The website's domain, such as example.com.");
const OWNER: Param = Param::text(
    "owner",
    "Administrators only: just this account's, by username. Leave it out for all.",
);
const USERNAME: Param = Param::text(
    "username",
    "Administrators only: another account, by username. Leave it out for your own.",
);
const PATH: Param = Param::text(
    "path",
    "A path inside the website's folder, such as public_html/wp-config.php.",
);

pub static ALL: &[Tool] = &[
    // ------------------------------------------------------------ everyone
    Tool {
        name: "whoami",
        title: "Who am I",
        description: "The account this token acts for: its name, role and limits, and what the token may do.",
        params: &[],
        admin_only: false,
        writes: false,
        destructive: false,
        run: whoami,
    },
    Tool {
        name: "list_websites",
        title: "List websites",
        description: "The websites this account may work on, with their PHP version, type, status, SSL and WAF.",
        params: &[OWNER],
        admin_only: false,
        writes: false,
        destructive: false,
        run: list_websites,
    },
    Tool {
        name: "get_website",
        title: "Website details",
        description: "One website: its runtime, folder, aliases and redirects, databases, and when its certificate expires.",
        params: &[DOMAIN.required()],
        admin_only: false,
        writes: false,
        destructive: false,
        run: get_website,
    },
    Tool {
        name: "list_databases",
        title: "List databases",
        description: "The MariaDB databases this account may work on, with their owner and website. Passwords are never shown.",
        params: &[OWNER],
        admin_only: false,
        writes: false,
        destructive: false,
        run: list_databases,
    },
    Tool {
        name: "read_site_log",
        title: "Read a website's log",
        description: "The last lines of a website's nginx access or error log.",
        params: &[
            DOMAIN.required(),
            Param::one_of("kind", "access (the default) or error.", &["access", "error"]),
            Param::number("lines", "How many lines from the end; 100 when left out.", 1, 500),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: read_site_log,
    },
    Tool {
        name: "read_waf_access_log",
        title: "Read the WAF access log",
        description: "Requests from the access logs, newest first, each with its address, path, status, user agent and the WAF's verdict. Narrow it with a verdict or a search; use traffic_summary first to see what to look for.",
        params: &[
            Param::text("domain", "One website's log; every website this account may read when left out."),
            Param::one_of("verdict", "Only requests the WAF allowed, or blocked.", &["allow", "block"]),
            Param::text("search", "Only requests whose address, path, user agent or line contains this text."),
            Param::number("limit", "How many requests to return; 50 when left out.", 1, 200),
            Param::number("lines", "How many lines of each log to read; 2000 when left out.", 1, 20_000),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: read_waf_access_log,
    },
    Tool {
        name: "traffic_summary",
        title: "Traffic summary",
        description: "What the access logs add up to: requests and blocked requests, status classes, and the top addresses (each with its most requested path), paths and user agents. The place to start looking into traffic or an attack.",
        params: &[
            Param::text("domain", "One website; every website this account may read when left out."),
            Param::number("lines", "How many lines of each log to read; 3000 when left out.", 1, 20_000),
            Param::number("top", "How many of each top list; 10 when left out.", 1, 50),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: traffic_summary,
    },
    Tool {
        name: "list_backups",
        title: "List backups",
        description: "The full-account backups kept on this server for an account.",
        params: &[USERNAME],
        admin_only: false,
        writes: false,
        destructive: false,
        run: list_backups,
    },
    Tool {
        name: "list_backup_jobs",
        title: "List backup jobs",
        description: "Recent backup and restore jobs and how they ended - where create_backup's job is followed.",
        params: &[],
        admin_only: false,
        writes: false,
        destructive: false,
        run: list_backup_jobs,
    },
    Tool {
        name: "server_resources",
        title: "Server resources",
        description: "The server's CPU, memory, disk and load.",
        params: &[],
        admin_only: false,
        writes: false,
        destructive: false,
        run: server_resources,
    },
    Tool {
        name: "list_files",
        title: "List files",
        description: "The files and folders in a folder of a website.",
        params: &[
            DOMAIN.required(),
            Param::text("path", "The folder, inside the website's folder; public_html when left out."),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: list_files,
    },
    Tool {
        name: "read_file",
        title: "Read a file",
        description: "A text file of a website, a stretch of lines at a time (files up to 2 MB). total_lines says how far there is to go.",
        params: &[
            DOMAIN.required(),
            PATH.required(),
            Param::number("start_line", "The first line, from 1; 1 when left out.", 1, 10_000_000),
            Param::number("line_count", "How many lines; 400 when left out.", 1, 2000),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: read_file,
    },
    Tool {
        name: "search_files",
        title: "Search files",
        description: "Plain text - not a pattern - in a website's files. Skips .git, node_modules, caches, uploads and binary files; reads files up to 512 KB and returns at most 100 matches.",
        params: &[
            DOMAIN.required(),
            Param::text("text", "The text to find.").required(),
            Param::text("path", "The folder to search, inside the website's folder; public_html when left out."),
            Param::text("file_suffix", "Only files whose names end with this, such as .php."),
            Param::flag("case_sensitive", "Match upper and lower case exactly; false when left out."),
        ],
        admin_only: false,
        writes: false,
        destructive: false,
        run: search_files,
    },
    Tool {
        name: "create_backup",
        title: "Back up an account",
        description: "Starts a full backup of an account - its websites, files, databases and applications - kept on this server. It runs in the background: follow it with list_backup_jobs.",
        params: &[USERNAME],
        admin_only: false,
        writes: true,
        destructive: false,
        run: create_backup,
    },
    Tool {
        name: "issue_ssl_certificate",
        title: "Issue an SSL certificate",
        description: "Issues or renews a Let's Encrypt certificate for a website and its aliases. The domain has to point at this server already.",
        params: &[DOMAIN.required()],
        admin_only: false,
        writes: true,
        destructive: false,
        run: issue_ssl_certificate,
    },
    Tool {
        name: "set_website_waf",
        title: "Turn a website's WAF on or off",
        description: "Turns the web application firewall of one website on or off.",
        params: &[
            DOMAIN.required(),
            Param::flag("enabled", "true to turn it on, false to turn it off.").required(),
        ],
        admin_only: false,
        writes: true,
        destructive: false,
        run: set_website_waf,
    },
    Tool {
        name: "write_file",
        title: "Write a file",
        description: "Creates a file of a website or replaces it whole, making the folders it needs. Read a file with read_file before replacing it.",
        params: &[
            DOMAIN.required(),
            PATH.required(),
            Param::text("content", "The whole new content of the file.").required(),
        ],
        admin_only: false,
        writes: true,
        destructive: false,
        run: write_file,
    },
    Tool {
        name: "create_directory",
        title: "Create a folder",
        description: "Creates a folder in a website, with any folders above it that are missing.",
        params: &[DOMAIN.required(), PATH.required()],
        admin_only: false,
        writes: true,
        destructive: false,
        run: create_directory,
    },
    Tool {
        name: "move_file",
        title: "Move or rename",
        description: "Moves a file or folder of a website to another path, renaming it, or both.",
        params: &[
            DOMAIN.required(),
            PATH.required(),
            Param::text("new_path", "Where it goes, inside the website's folder.").required(),
        ],
        admin_only: false,
        writes: true,
        destructive: false,
        run: move_file,
    },
    Tool {
        name: "delete_file",
        title: "Delete a file or folder",
        description: "Deletes a file, or a folder with everything in it, from a website. It cannot be undone: ask the user first. The website's folder and web root are never deleted.",
        params: &[DOMAIN.required(), PATH.required()],
        admin_only: false,
        writes: true,
        destructive: true,
        run: delete_file,
    },
    // --------------------------------------------------------- administrators
    Tool {
        name: "list_users",
        title: "List accounts",
        description: "Every panel account, with its role, limits and whether it is active.",
        params: &[],
        admin_only: true,
        writes: false,
        destructive: false,
        run: list_users,
    },
    Tool {
        name: "list_services",
        title: "List services",
        description: "The server's services - nginx, PHP-FPM, MariaDB and the rest - and whether each is running.",
        params: &[],
        admin_only: true,
        writes: false,
        destructive: false,
        run: list_services,
    },
    Tool {
        name: "list_backup_schedules",
        title: "List backup schedules",
        description: "The scheduled backups: whose, when, where they are copied, how they are named and how the last run went.",
        params: &[],
        admin_only: true,
        writes: false,
        destructive: false,
        run: list_backup_schedules,
    },
    Tool {
        name: "recent_audit_log",
        title: "Recent audit log",
        description: "The latest entries of the panel's audit log: who did what, and when.",
        params: &[Param::number("limit", "How many entries; 50 when left out.", 1, 100)],
        admin_only: true,
        writes: false,
        destructive: false,
        run: recent_audit_log,
    },
    Tool {
        name: "panel_update_status",
        title: "Panel update status",
        description: "The panel's version, and whether a newer release is out.",
        params: &[],
        admin_only: true,
        writes: false,
        destructive: false,
        run: panel_update_status,
    },
    Tool {
        name: "list_firewall_rules",
        title: "List firewall rules",
        description: "The server firewall's state and rules - open ports, allowed and blocked addresses.",
        params: &[],
        admin_only: true,
        writes: false,
        destructive: false,
        run: list_firewall_rules,
    },
    Tool {
        name: "list_waf_rules",
        title: "List WAF rules",
        description: "The server-wide custom WAF rules, and a website's own custom rules and rule selection when a domain is given.",
        params: &[Param::text("domain", "Also this website's rules.")],
        admin_only: true,
        writes: false,
        destructive: false,
        run: list_waf_rules,
    },
    Tool {
        name: "block_ip",
        title: "Block an address",
        description: "Blocks an address, or a network no wider than a /16, from the whole server in the firewall. Refuses private and reserved ranges, this server's own addresses and the address this assistant calls from. Prefer add_waf_rule on one website; never block a CDN's or proxy's address.",
        params: &[
            Param::text("ip", "The address or network, such as 203.0.113.7 or 203.0.113.0/24.").required(),
            Param::text("reason", "Why, for the audit log."),
        ],
        admin_only: true,
        writes: true,
        destructive: false,
        run: block_ip,
    },
    Tool {
        name: "unblock_ip",
        title: "Unblock an address",
        description: "Removes the panel firewall's rules that block an address. Nothing else is touched.",
        params: &[Param::text("ip", "The address or network that was blocked.").required()],
        admin_only: true,
        writes: true,
        destructive: false,
        run: unblock_ip,
    },
    Tool {
        name: "add_waf_rule",
        title: "Add a WAF rule",
        description: "Adds a rule that refuses matching requests with a 403, to one website or - without a domain - to every website. It matches the client address (ip, an address or network), the path's start (path), or text in the user agent or query (user_agent, query, case-insensitive). No raw ModSecurity is accepted.",
        params: &[
            Param::one_of("match", "What the rule looks at.", RuleMatch::NAMES).required(),
            Param::text("value", "The address or network, the path's start, or the text to look for.").required(),
            Param::text("domain", "One website; every website when left out."),
            Param::text("note", "Why the rule is there, kept beside it and in the log."),
        ],
        admin_only: true,
        writes: true,
        destructive: false,
        run: add_waf_rule,
    },
    Tool {
        name: "restart_service",
        title: "Restart a service",
        description: "Restarts or reloads one of the server's services. Stopping one is not offered.",
        params: &[
            Param::text("service", "The service, as list_services names it.").required(),
            Param::one_of("action", "restart (the default) or reload.", &["restart", "reload"]),
        ],
        admin_only: true,
        writes: true,
        destructive: false,
        run: restart_service,
    },
    Tool {
        name: "run_backup_schedule",
        title: "Run a backup schedule now",
        description: "Runs a backup schedule now, as its timer would, in the background. Its result shows in list_backup_schedules.",
        params: &[Param::number("schedule_id", "The schedule's id, from list_backup_schedules.", 1, i64::MAX).required()],
        admin_only: true,
        writes: true,
        destructive: false,
        run: run_backup_schedule,
    },
];

/// A tool by name, whoever may see it.
pub fn find(name: &str) -> Option<&'static Tool> {
    ALL.iter().find(|tool| tool.name == name)
}

fn text<'a>(args: &'a Arguments, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

fn number(args: &Arguments, name: &str) -> Option<i64> {
    args.get(name).and_then(Value::as_i64)
}

fn flag(args: &Arguments, name: &str) -> Option<bool> {
    args.get(name).and_then(Value::as_bool)
}

fn db_error(e: impl std::fmt::Display) -> ToolError {
    ToolError::new(format!("Cannot read the panel's database: {e}"))
}

/// A path inside a website, as the file manager takes it: no `..`, no
/// leading slash.
fn site_path(raw: &str) -> Result<String, ToolError> {
    crate::files::clean_relative_path(raw).map_err(|e| ToolError::new(e.to_string()))
}

fn parent_and_name(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => (String::new(), path.to_string()),
    }
}

async fn owner_names(
    ctx: &Context,
    ids: impl Iterator<Item = i64>,
) -> std::collections::HashMap<i64, String> {
    let mut names = std::collections::HashMap::new();
    for id in ids {
        if names.contains_key(&id) {
            continue;
        }
        if let Ok(Some(user)) = ctx.state.db.users().by_id(id).await {
            names.insert(id, user.username);
        }
    }
    names
}

fn site_summary(site: &snpanel_db::Website, owner: &str) -> Value {
    json!({
        "domain": site.domain,
        "owner": owner,
        "status": site.status,
        "type": if site.app_type.is_empty() { "wordpress" } else { &site.app_type },
        "php_version": site.php_version,
        "document_root": site.document_root,
        "ssl": {
            "enabled": site.ssl_enabled,
            "mode": site.ssl_mode,
            "shared_from": site.ssl_source_domain,
        },
        "waf_enabled": site.waf_enabled,
        "owasp_crs": site.crs_enabled,
        "http_flood_protection": site.http_flood_enabled,
    })
}

// ------------------------------------------------------------------ everyone

fn whoami(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let user = ctx.user();
        Ok(json!({
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_admin": ctx.is_admin(),
            "website_limit": user.website_limit,
            "storage_limit_mb": user.storage_limit_mb,
            "token": {
                "name": ctx.token.name,
                "prefix": ctx.token.prefix,
                "allows_actions": ctx.token.can_write,
                "expires_at": iso(&ctx.token.expires_at),
            },
            "tools_available": super::list_tools(ctx.is_admin(), ctx.token.can_write).len(),
        }))
    })
}

fn list_websites(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let owner = match text(&args, "owner") {
            Some(name) => Some(ctx.account(Some(name)).await?),
            None => None,
        };
        let filter = if ctx.is_admin() {
            owner.as_ref().map(|u| u.id)
        } else {
            Some(ctx.user().id)
        };
        let sites = ctx
            .state
            .db
            .websites()
            .list(filter, "")
            .await
            .map_err(db_error)?;
        let names = owner_names(&ctx, sites.iter().map(|s| s.owner_id)).await;
        let items: Vec<Value> = sites
            .iter()
            .map(|site| site_summary(site, names.get(&site.owner_id).map_or("", String::as_str)))
            .collect();
        Ok(json!({ "count": items.len(), "websites": items }))
    })
}

fn get_website(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let db = &ctx.state.db;
        let owner = owner_names(&ctx, std::iter::once(site.owner_id)).await;
        let aliases: Vec<Value> = db
            .websites()
            .aliases(site.id)
            .await
            .unwrap_or_default()
            .iter()
            .map(|alias| json!({ "domain": alias.domain, "mode": alias.mode, "ssl_enabled": alias.ssl_enabled }))
            .collect();
        let databases: Vec<Value> = db
            .databases()
            .for_website(site.id)
            .await
            .unwrap_or_default()
            .iter()
            .map(|account| json!({ "name": account.db_name, "user": account.db_user }))
            .collect();
        let certificate = if site.ssl_enabled {
            let source = site
                .ssl_source_domain
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| site.domain.clone());
            let (expires, names) = crate::routes::websites::cert_info(&ctx.state, &source).await;
            json!({ "expires": expires, "names": names, "certificate_of": source })
        } else {
            Value::Null
        };
        let mut summary = site_summary(&site, owner.get(&site.owner_id).map_or("", String::as_str));
        summary["folder"] = json!(site.root_path);
        summary["linux_user"] = json!(site.linux_user);
        summary["nginx_rewrite_mode"] = json!(site.nginx_rewrite_mode);
        summary["aliases"] = json!(aliases);
        summary["databases"] = json!(databases);
        summary["certificate"] = certificate;
        Ok(summary)
    })
}

fn list_databases(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let owner = match text(&args, "owner") {
            Some(name) => Some(ctx.account(Some(name)).await?),
            None => None,
        };
        let listed = ctx.call(Method::GET, "/databases", None).await?;
        let rows = listed
            .as_array()
            .cloned()
            .or_else(|| listed.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let items: Vec<Value> = rows
            .into_iter()
            .filter(|row| {
                owner
                    .as_ref()
                    .is_none_or(|u| row.get("owner_id").and_then(Value::as_i64) == Some(u.id))
            })
            .map(|row| {
                let mut kept = Map::new();
                if let Value::Object(map) = row {
                    for (key, value) in map {
                        if !key.contains("password") {
                            kept.insert(key, value);
                        }
                    }
                }
                Value::Object(kept)
            })
            .collect();
        Ok(json!({ "count": items.len(), "databases": items }))
    })
}

fn read_site_log(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let kind = text(&args, "kind").unwrap_or("access");
        let lines = number(&args, "lines").unwrap_or(100);
        let path = format!("/websites/{}/logs?kind={kind}&lines={lines}", site.id);
        let mut log = ctx.call(Method::GET, &path, None).await?;
        if let Value::Object(map) = &mut log {
            map.insert("domain".to_string(), json!(site.domain));
            map.insert("kind".to_string(), json!(kind));
        }
        Ok(log)
    })
}

/// The access-log entries a call may read: one website's, or every one the
/// caller may read. Newest first.
async fn access_entries(
    ctx: &Context,
    domain: Option<&str>,
    lines: usize,
) -> Result<(Vec<Value>, Vec<String>), ToolError> {
    let website_id = match domain {
        Some(domain) => Some(ctx.website(domain).await?.id),
        None => None,
    };
    match crate::routes::waf::access_entries(&ctx.state, &ctx.current, website_id, lines).await {
        Ok(found) => Ok(found),
        Err(response) => Err(super::response_error(response).await),
    }
}

fn read_waf_access_log(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let lines = number(&args, "lines").unwrap_or(2000) as usize;
        let limit = number(&args, "limit").unwrap_or(50) as usize;
        let verdict = text(&args, "verdict").unwrap_or("");
        let search = text(&args, "search").unwrap_or("");
        let (entries, missing) = access_entries(&ctx, text(&args, "domain"), lines).await?;
        let scanned = entries.len();
        let matching: Vec<Value> = entries
            .into_iter()
            .filter(|entry| crate::access_log::matches_access_filter(entry, verdict, search))
            .collect();
        let shown: Vec<Value> = matching
            .iter()
            .take(limit)
            .map(|entry| {
                json!({
                    "time": entry["timestamp"],
                    "domain": entry["domain"],
                    "ip": entry["ip"],
                    "method": entry["method"],
                    "path": entry["path"],
                    "status": entry["status"],
                    "verdict": entry["verdict"],
                    "reason": entry["reason"],
                    "user_agent": entry["user_agent"],
                    "referer": entry["referer"],
                })
            })
            .collect();
        Ok(json!({
            "requests": shown,
            "matching": matching.len(),
            "scanned": scanned,
            "sites_without_a_log": missing,
        }))
    })
}

/// What a set of access-log entries adds up to.
pub fn summarize(entries: &[Value], top: usize) -> Value {
    use std::collections::HashMap;

    #[derive(Default)]
    struct Tally {
        requests: usize,
        blocked: usize,
    }
    let mut statuses: HashMap<&'static str, usize> = HashMap::new();
    let mut by_ip: HashMap<String, (Tally, HashMap<String, usize>)> = HashMap::new();
    let mut by_path: HashMap<String, Tally> = HashMap::new();
    let mut by_agent: HashMap<String, usize> = HashMap::new();
    let mut by_domain: HashMap<String, usize> = HashMap::new();
    let mut blocked = 0;
    for entry in entries {
        let is_blocked = entry["verdict"].as_str() == Some("block");
        if is_blocked {
            blocked += 1;
        }
        let class = match entry["status"].as_u64().unwrap_or(0) {
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "other",
        };
        *statuses.entry(class).or_default() += 1;
        let ip = entry["ip"].as_str().unwrap_or("").to_string();
        let path = entry["path"].as_str().unwrap_or("").to_string();
        let (tally, paths) = by_ip.entry(ip).or_default();
        tally.requests += 1;
        tally.blocked += usize::from(is_blocked);
        *paths.entry(path.clone()).or_default() += 1;
        let tally = by_path.entry(path).or_default();
        tally.requests += 1;
        tally.blocked += usize::from(is_blocked);
        *by_agent
            .entry(entry["user_agent"].as_str().unwrap_or("").to_string())
            .or_default() += 1;
        *by_domain
            .entry(entry["domain"].as_str().unwrap_or("").to_string())
            .or_default() += 1;
    }
    // Most first; a tie by name, so the same log gives the same list.
    fn ranked<T>(
        map: HashMap<String, T>,
        count: impl Fn(&T) -> usize,
        top: usize,
    ) -> Vec<(String, T)> {
        let mut items: Vec<(String, T)> = map.into_iter().collect();
        items.sort_by(|a, b| count(&b.1).cmp(&count(&a.1)).then_with(|| a.0.cmp(&b.0)));
        items.truncate(top);
        items
    }
    let top_ips: Vec<Value> = ranked(by_ip, |(t, _)| t.requests, top)
        .into_iter()
        .map(|(ip, (tally, paths))| {
            let (top_path, hits) = ranked(paths, |n| *n, 1)
                .into_iter()
                .next()
                .unwrap_or_default();
            json!({
                "ip": ip,
                "requests": tally.requests,
                "blocked": tally.blocked,
                "top_path": top_path,
                "top_path_requests": hits,
            })
        })
        .collect();
    let top_paths: Vec<Value> = ranked(by_path, |t| t.requests, top)
        .into_iter()
        .map(|(path, tally)| json!({ "path": path, "requests": tally.requests, "blocked": tally.blocked }))
        .collect();
    let top_agents: Vec<Value> = ranked(by_agent, |n| *n, top)
        .into_iter()
        .map(|(agent, requests)| json!({ "user_agent": agent, "requests": requests }))
        .collect();
    let domains: Vec<Value> = ranked(by_domain, |n| *n, usize::MAX)
        .into_iter()
        .map(|(domain, requests)| json!({ "domain": domain, "requests": requests }))
        .collect();
    let classes: Map<String, Value> = ["2xx", "3xx", "4xx", "5xx", "other"]
        .iter()
        .map(|class| {
            (
                class.to_string(),
                json!(statuses.get(class).copied().unwrap_or(0)),
            )
        })
        .collect();
    json!({
        "requests": entries.len(),
        "blocked": blocked,
        "status_classes": classes,
        "top_ips": top_ips,
        "top_paths": top_paths,
        "top_user_agents": top_agents,
        "websites": domains,
        "from": entries.last().map(|e| e["timestamp"].clone()),
        "to": entries.first().map(|e| e["timestamp"].clone()),
    })
}

fn traffic_summary(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let lines = number(&args, "lines").unwrap_or(3000) as usize;
        let top = number(&args, "top").unwrap_or(10) as usize;
        let (entries, missing) = access_entries(&ctx, text(&args, "domain"), lines).await?;
        let mut summary = summarize(&entries, top);
        summary["lines_read_per_site"] = json!(lines);
        summary["sites_without_a_log"] = json!(missing);
        Ok(summary)
    })
}

fn list_backups(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let account = ctx.account(text(&args, "username")).await?;
        let listed = ctx
            .call(
                Method::GET,
                &format!("/maintenance/user-backups/{}", account.id),
                None,
            )
            .await?;
        let backups: Vec<Value> = listed["items"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(|path| {
                let meta = std::fs::metadata(path).ok();
                json!({
                    "file": path.rsplit('/').next().unwrap_or(path),
                    "path": path,
                    "size_bytes": meta.as_ref().map(std::fs::Metadata::len),
                    "modified": meta
                        .and_then(|m| m.modified().ok())
                        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                })
            })
            .collect();
        Ok(json!({ "username": account.username, "count": backups.len(), "backups": backups }))
    })
}

fn list_backup_jobs(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        ctx.call(Method::GET, "/maintenance/backup-jobs", None)
            .await
    })
}

fn server_resources(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        ctx.call(Method::GET, "/services/resource-usage", None)
            .await
    })
}

fn list_files(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or("public_html"))?;
        let listed = ctx
            .call(
                Method::GET,
                &format!(
                    "/maintenance/files/{}?path={}",
                    site.id,
                    uri_encode(&path, true)
                ),
                None,
            )
            .await?;
        Ok(json!({ "domain": site.domain, "path": path, "items": listed["items"] }))
    })
}

fn read_file(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or(""))?;
        let read = ctx
            .call(
                Method::GET,
                &format!(
                    "/maintenance/files/{}/read?path={}",
                    site.id,
                    uri_encode(&path, true)
                ),
                None,
            )
            .await?;
        let content = read["content"].as_str().unwrap_or("");
        slice_lines(
            &path,
            content,
            number(&args, "start_line").unwrap_or(1) as usize,
            number(&args, "line_count").unwrap_or(400) as usize,
        )
    })
}

/// A stretch of a file's lines, and how many it has.
pub fn slice_lines(path: &str, content: &str, start: usize, count: usize) -> ToolResult {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let start = start.max(1);
    if total > 0 && start > total {
        return Err(ToolError::new(format!(
            "{path} has {total} lines; start_line is past the end"
        )));
    }
    let from = (start - 1).min(total);
    let to = (from + count).min(total);
    Ok(json!({
        "path": path,
        "start_line": start,
        "line_count": to - from,
        "total_lines": total,
        "more": to < total,
        "content": lines[from..to].join("\n"),
    }))
}

fn search_files(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or("public_html"))?;
        let needle = text(&args, "text").unwrap_or("");
        let suffix = text(&args, "file_suffix").unwrap_or("").trim();
        // Checked here as the file manager checks a folder it lists; the
        // helper checks again, and walks without following a link.
        crate::files::safe_path(&site.root_path, &path, false)
            .map_err(|e| ToolError::new(e.to_string()))?;
        let user = site
            .linux_user
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| site.root_path.split('/').nth(2).map(str::to_string))
            .unwrap_or_default();
        let case = if flag(&args, "case_sensitive").unwrap_or(false) {
            "1"
        } else {
            "0"
        };
        let secrets = if ctx.is_admin() { "1" } else { "0" };
        let result = crate::shell::privileged(
            ctx.state.settings.command_dry_run,
            "site-file-search",
            &[&user, &site.root_path, &path, needle, suffix, case, secrets],
            None,
            None,
        )
        .await;
        if !result.ok() {
            return Err(ToolError::new(
                result.failure_detail("Cannot search the files").trim(),
            ));
        }
        let mut found: Value =
            serde_json::from_str(result.stdout.trim()).unwrap_or_else(|_| json!({ "matches": [] }));
        // The helper's paths are the folder's; the assistant's are the site's.
        if let Some(matches) = found.get_mut("matches").and_then(Value::as_array_mut) {
            for entry in matches {
                if let Some(relative) = entry["path"].as_str() {
                    let full = if path.is_empty() {
                        relative.to_string()
                    } else {
                        format!("{path}/{relative}")
                    };
                    entry["path"] = json!(full);
                }
            }
        }
        found["domain"] = json!(site.domain);
        found["searched"] = json!(if path.is_empty() { "." } else { &path });
        Ok(found)
    })
}

fn create_backup(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let account = ctx.account(text(&args, "username")).await?;
        let job = ctx
            .call(
                Method::POST,
                "/maintenance/user-backup",
                Some(json!({ "user_id": account.id })),
            )
            .await?;
        Ok(json!({
            "username": account.username,
            "job": job,
            "note": "The backup runs in the background; list_backup_jobs shows how it ends.",
        }))
    })
}

fn issue_ssl_certificate(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        ctx.call(
            Method::POST,
            &format!("/websites/{}/ssl", site.id),
            Some(json!({})),
        )
        .await
    })
}

fn set_website_waf(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let enabled = flag(&args, "enabled").unwrap_or(false);
        ctx.call(
            Method::PATCH,
            &format!("/websites/{}/waf", site.id),
            Some(json!({ "waf_enabled": enabled })),
        )
        .await?;
        Ok(json!({ "domain": site.domain, "waf_enabled": enabled }))
    })
}

/// A folder of a website and the ones above it, made where missing - each
/// through the file manager, so each belongs to the site's user.
async fn ensure_folder(
    ctx: &Context,
    site: &snpanel_db::Website,
    folder: &str,
) -> Result<Vec<String>, ToolError> {
    let mut made = Vec::new();
    let mut so_far = String::new();
    for part in folder.split('/').filter(|p| !p.is_empty()) {
        let parent = so_far.clone();
        so_far = if so_far.is_empty() {
            part.to_string()
        } else {
            format!("{so_far}/{part}")
        };
        let existing = crate::files::safe_path(&site.root_path, &so_far, false)
            .map_err(|e| ToolError::new(e.to_string()))?;
        if existing.is_dir() {
            continue;
        }
        if existing.exists() {
            return Err(ToolError::new(format!("{so_far} is a file, not a folder")));
        }
        ctx.call(
            Method::POST,
            "/maintenance/files/mkdir",
            Some(json!({ "website_id": site.id, "path": parent, "name": part })),
        )
        .await?;
        made.push(so_far.clone());
    }
    Ok(made)
}

fn write_file(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or(""))?;
        let (parent, name) = parent_and_name(&path);
        if name.is_empty() {
            return Err(ToolError::new("Name the file to write"));
        }
        let content = text(&args, "content").unwrap_or("");
        let made = ensure_folder(&ctx, &site, &parent).await?;
        ctx.call(
            Method::POST,
            "/maintenance/files/write",
            Some(json!({ "website_id": site.id, "path": path, "content": content })),
        )
        .await?;
        Ok(json!({
            "domain": site.domain,
            "path": path,
            "bytes": content.len(),
            "folders_created": made,
        }))
    })
}

fn create_directory(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or(""))?;
        if path.is_empty() {
            return Err(ToolError::new("Name the folder to create"));
        }
        let made = ensure_folder(&ctx, &site, &path).await?;
        Ok(
            json!({ "domain": site.domain, "path": path, "created": made, "existed": made.is_empty() }),
        )
    })
}

fn move_file(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let from = site_path(text(&args, "path").unwrap_or(""))?;
        let to = site_path(text(&args, "new_path").unwrap_or(""))?;
        if from.is_empty() || to.is_empty() {
            return Err(ToolError::new("Name both the file and where it goes"));
        }
        if from == to {
            return Err(ToolError::new("The new path is the same as the old one"));
        }
        let (from_parent, from_name) = parent_and_name(&from);
        let (to_parent, to_name) = parent_and_name(&to);
        if from_parent != to_parent {
            ensure_folder(&ctx, &site, &to_parent).await?;
            ctx.call(
                Method::POST,
                "/maintenance/files/move",
                Some(json!({ "website_id": site.id, "paths": [from], "destination_path": to_parent })),
            )
            .await?;
        }
        if from_name != to_name {
            let now_at = if to_parent.is_empty() {
                from_name.clone()
            } else {
                format!("{to_parent}/{from_name}")
            };
            ctx.call(
                Method::POST,
                "/maintenance/files/rename",
                Some(json!({ "website_id": site.id, "path": now_at, "new_name": to_name })),
            )
            .await
            .map_err(|e| {
                if from_parent == to_parent {
                    e
                } else {
                    ToolError::new(format!("Moved to {now_at}, but the rename failed: {}", e.0))
                }
            })?;
        }
        Ok(json!({ "domain": site.domain, "from": from, "to": to }))
    })
}

fn delete_file(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let site = ctx.website(text(&args, "domain").unwrap_or("")).await?;
        let path = site_path(text(&args, "path").unwrap_or(""))?;
        if let Some(refusal) = guards::delete_refusal(&path, &site.document_root) {
            return Err(ToolError::new(refusal));
        }
        ctx.call(
            Method::POST,
            "/maintenance/files/delete",
            Some(json!({ "website_id": site.id, "paths": [path] })),
        )
        .await?;
        Ok(json!({ "domain": site.domain, "deleted": path }))
    })
}

// ------------------------------------------------------------ administrators

fn list_users(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let listed = ctx.call(Method::GET, "/users?usage=0", None).await?;
        let rows = listed.as_array().cloned().unwrap_or_default();
        let users: Vec<Value> = rows
            .iter()
            .map(|row| {
                let mut kept = Map::new();
                for key in [
                    "id",
                    "username",
                    "email",
                    "role",
                    "is_active",
                    "website_limit",
                    "storage_limit_mb",
                    "package",
                    "totp_enabled",
                    "created_at",
                ] {
                    if let Some(value) = row.get(key) {
                        kept.insert(key.to_string(), value.clone());
                    }
                }
                Value::Object(kept)
            })
            .collect();
        Ok(json!({ "count": users.len(), "users": users }))
    })
}

fn list_services(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let names = ctx.call(Method::GET, "/services/list", None).await?;
        let names: Vec<String> = names
            .as_array()
            .or_else(|| names.get("services").and_then(Value::as_array))
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|n| n.as_str().map(str::to_string))
            .collect();
        let mut services = Vec::new();
        for name in names {
            let state = ctx
                .call(
                    Method::POST,
                    "/services/action",
                    Some(json!({ "name": name, "action": "status" })),
                )
                .await;
            let (running, detail) = match state {
                Ok(result) => (
                    result.get("returncode").and_then(Value::as_i64) == Some(0),
                    result["stdout"]
                        .as_str()
                        .unwrap_or("")
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                ),
                Err(e) => (false, e.0),
            };
            services.push(json!({ "name": name, "running": running, "detail": detail }));
        }
        Ok(json!({ "services": services }))
    })
}

fn list_backup_schedules(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let schedules = ctx
            .call(Method::GET, "/maintenance/backup-schedules", None)
            .await?;
        Ok(json!({ "schedules": schedules }))
    })
}

fn recent_audit_log(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let limit = number(&args, "limit").unwrap_or(50);
        ctx.call(
            Method::GET,
            &format!("/users/audit/log?limit={limit}"),
            None,
        )
        .await
    })
}

fn panel_update_status(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move { ctx.call(Method::GET, "/updates/status", None).await })
}

fn list_firewall_rules(ctx: Arc<Context>, _args: Arguments) -> ToolFuture {
    Box::pin(async move { ctx.call(Method::GET, "/firewall/status", None).await })
}

fn list_waf_rules(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let server = ctx.call(Method::GET, "/waf/rules", None).await?;
        let mut answer = json!({
            "server_custom_rules": server["custom_rules"],
            "engine": server["status"],
        });
        if let Some(domain) = text(&args, "domain") {
            let site = ctx.website(domain).await?;
            let config = ctx
                .call(Method::GET, &format!("/waf/websites/{}", site.id), None)
                .await?;
            answer["website"] = json!({
                "domain": site.domain,
                "waf_enabled": site.waf_enabled,
                "custom_rules": config.get("custom_rules").cloned().unwrap_or_else(|| json!(site.waf_custom_rules)),
                "enabled_rule_ids": config.get("enabled_rule_ids").cloned().unwrap_or(Value::Null),
            });
        }
        Ok(answer)
    })
}

/// The addresses this server answers on: never blocked.
async fn server_addresses() -> Vec<std::net::IpAddr> {
    let output = tokio::process::Command::new("hostname")
        .arg("-I")
        .output()
        .await;
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The firewall rules that block a network, by their numbers.
fn blocking_rules(status: &Value, net: &str) -> Vec<i64> {
    status["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|rule| {
            let action = rule["action"].as_str().unwrap_or("").to_ascii_lowercase();
            let blocks = matches!(action.as_str(), "deny" | "drop" | "reject" | "block");
            let port = rule
                .get("port")
                .filter(|p| !p.is_null() && p.as_str() != Some(""));
            blocks
                && port.is_none()
                && rule["ip"]
                    .as_str()
                    .is_some_and(|ip| guards::same_network(ip, net))
        })
        .filter_map(|rule| rule["id"].as_i64())
        .collect()
}

fn block_ip(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let wanted = text(&args, "ip").unwrap_or("");
        let client = ctx.client_ip.parse().ok();
        let net =
            guards::block_target(wanted, &server_addresses().await, client).map_err(ToolError)?;
        let target = if net.prefix == if net.addr.is_ipv4() { 32 } else { 128 } {
            net.addr.to_string()
        } else {
            net.to_string()
        };
        let status = ctx.call(Method::GET, "/firewall/status", None).await?;
        if !blocking_rules(&status, &target).is_empty() {
            return Ok(json!({ "ip": target, "blocked": true, "already": true }));
        }
        ctx.call(
            Method::POST,
            "/firewall/block-ip",
            Some(json!({ "ip": target })),
        )
        .await?;
        Ok(
            json!({ "ip": target, "blocked": true, "already": false, "reason": text(&args, "reason").unwrap_or("") }),
        )
    })
}

fn unblock_ip(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let wanted = text(&args, "ip").unwrap_or("").trim().to_string();
        if guards::Network::parse(&wanted).is_none() {
            return Err(ToolError::new(format!(
                "{wanted} is not an IP address or a network"
            )));
        }
        let status = ctx.call(Method::GET, "/firewall/status", None).await?;
        let rules = blocking_rules(&status, &wanted);
        if rules.is_empty() {
            return Err(ToolError::new(format!(
                "No firewall rule of the panel blocks {wanted}"
            )));
        }
        // Highest number first: removing a rule renumbers the ones after it.
        let mut rules = rules;
        rules.sort_unstable_by(|a, b| b.cmp(a));
        for number in &rules {
            ctx.call(Method::DELETE, &format!("/firewall/rules/{number}"), None)
                .await?;
        }
        Ok(json!({ "ip": wanted, "rules_removed": rules.len() }))
    })
}

fn add_waf_rule(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let kind = RuleMatch::parse(text(&args, "match").unwrap_or(""))
            .ok_or_else(|| ToolError::new("Unknown match"))?;
        let value =
            guards::rule_value(kind, text(&args, "value").unwrap_or("")).map_err(ToolError)?;
        let note = guards::rule_note(text(&args, "note").unwrap_or(""));
        // Every id in use, the server's custom rules and every site's.
        let server = ctx.call(Method::GET, "/waf/rules", None).await?;
        let server_rules = server["custom_rules"].as_str().unwrap_or("").to_string();
        let sites = ctx
            .state
            .db
            .websites()
            .list(None, "")
            .await
            .map_err(db_error)?;
        let mut texts: Vec<&str> = sites.iter().map(|s| s.waf_custom_rules.as_str()).collect();
        texts.push(&server_rules);
        let id = guards::next_rule_id(&texts).ok_or_else(|| {
            ToolError::new(
                "Every WAF rule id kept for assistants is in use; remove some of their rules first",
            )
        })?;
        let when = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        let rule = guards::render_rule(kind, &value, id, &note, &when, &ctx.user().username);
        let joined = |existing: &str| {
            let existing = existing.trim_end();
            if existing.is_empty() {
                rule.clone()
            } else {
                format!("{existing}\n\n{rule}")
            }
        };
        let scope = match text(&args, "domain") {
            None => {
                ctx.call(
                    Method::PUT,
                    "/waf/rules/custom",
                    Some(json!({ "content": joined(&server_rules) })),
                )
                .await?;
                "every website".to_string()
            }
            Some(domain) => {
                let site = ctx.website(domain).await?;
                let config = ctx
                    .call(Method::GET, &format!("/waf/websites/{}", site.id), None)
                    .await?;
                let current = config["custom_rules"]
                    .as_str()
                    .unwrap_or(&site.waf_custom_rules)
                    .to_string();
                let enabled = config.get("enabled_rule_ids").cloned().unwrap_or_else(|| {
                    json!(crate::waf::parse_enabled_rule_ids(&site.waf_default_rules))
                });
                ctx.call(
                    Method::PUT,
                    &format!("/waf/websites/{}", site.id),
                    Some(json!({ "custom_rules": joined(&current), "enabled_rule_ids": enabled })),
                )
                .await?;
                site.domain
            }
        };
        Ok(json!({ "id": id, "applies_to": scope, "rule": rule }))
    })
}

fn restart_service(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let service = text(&args, "service").unwrap_or("").trim().to_string();
        let action = text(&args, "action").unwrap_or("restart");
        let result = ctx
            .call(
                Method::POST,
                "/services/action",
                Some(json!({ "name": service, "action": action })),
            )
            .await?;
        if result
            .get("returncode")
            .and_then(Value::as_i64)
            .is_some_and(|code| code != 0)
        {
            let detail = result["stderr"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| result["stdout"].as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            return Err(ToolError::new(format!(
                "{action} of {service} failed: {detail}"
            )));
        }
        Ok(json!({ "service": service, "action": action, "done": true }))
    })
}

fn run_backup_schedule(ctx: Arc<Context>, args: Arguments) -> ToolFuture {
    Box::pin(async move {
        let id = number(&args, "schedule_id").unwrap_or(0);
        ctx.call(
            Method::POST,
            &format!("/maintenance/backup-schedules/{id}/run"),
            Some(json!({})),
        )
        .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ip: &str, path: &str, status: u64, verdict: &str, agent: &str, when: &str) -> Value {
        json!({ "ip": ip, "path": path, "status": status, "verdict": verdict, "user_agent": agent, "domain": "a.com", "timestamp": when })
    }

    #[test]
    fn traffic_adds_up_by_address_path_and_agent() {
        // Newest first, as the logs are read.
        let entries = vec![
            entry("1.1.1.1", "/wp-login.php", 403, "block", "bot", "t5"),
            entry("1.1.1.1", "/wp-login.php", 403, "block", "bot", "t4"),
            entry("1.1.1.1", "/", 200, "allow", "bot", "t3"),
            entry("2.2.2.2", "/", 200, "allow", "browser", "t2"),
            entry("3.3.3.3", "/x", 502, "allow", "browser", "t1"),
        ];
        let s = summarize(&entries, 2);
        assert_eq!(s["requests"], 5);
        assert_eq!(s["blocked"], 2);
        assert_eq!(
            s["status_classes"],
            json!({"2xx": 2, "3xx": 0, "4xx": 2, "5xx": 1, "other": 0})
        );
        assert_eq!(
            s["top_ips"],
            json!([
                {"ip": "1.1.1.1", "requests": 3, "blocked": 2, "top_path": "/wp-login.php", "top_path_requests": 2},
                {"ip": "2.2.2.2", "requests": 1, "blocked": 0, "top_path": "/", "top_path_requests": 1},
            ])
        );
        assert_eq!(
            s["top_paths"][0],
            json!({"path": "/", "requests": 2, "blocked": 0})
        );
        assert_eq!(
            s["top_user_agents"][0],
            json!({"user_agent": "bot", "requests": 3})
        );
        assert_eq!(
            (s["from"].as_str(), s["to"].as_str()),
            (Some("t1"), Some("t5"))
        );
        assert_eq!(summarize(&[], 5)["requests"], 0);
    }

    #[test]
    fn a_file_is_read_a_stretch_at_a_time() {
        let content = "one\ntwo\nthree\nfour\n";
        let first = slice_lines("a.txt", content, 1, 2).unwrap();
        assert_eq!(
            (
                first["content"].as_str(),
                first["total_lines"].as_u64(),
                first["more"].as_bool()
            ),
            (Some("one\ntwo"), Some(4), Some(true))
        );
        let rest = slice_lines("a.txt", content, 3, 400).unwrap();
        assert_eq!(
            (
                rest["content"].as_str(),
                rest["line_count"].as_u64(),
                rest["more"].as_bool()
            ),
            (Some("three\nfour"), Some(2), Some(false))
        );
        assert!(slice_lines("a.txt", content, 5, 1)
            .unwrap_err()
            .0
            .contains("has 4 lines"));
        let empty = slice_lines("e.txt", "", 1, 10).unwrap();
        assert_eq!(empty["total_lines"], 0);
    }

    #[test]
    fn only_a_rule_that_blocks_the_whole_address_is_unblocked() {
        let status = json!({ "rules": [
            {"id": 1, "action": "ALLOW", "port": "22"},
            {"id": 2, "action": "DENY", "ip": "1.2.3.4"},
            {"id": 3, "action": "deny", "ip": "1.2.3.4/32"},
            {"id": 4, "action": "deny", "ip": "1.2.3.4", "port": "80"},
            {"id": 5, "action": "allow", "ip": "1.2.3.4"},
            {"id": 6, "action": "deny", "ip": "1.2.3.5"},
        ]});
        assert_eq!(blocking_rules(&status, "1.2.3.4"), [2, 3]);
        assert!(blocking_rules(&status, "9.9.9.9").is_empty());
    }

    #[test]
    fn a_path_splits_into_its_folder_and_name() {
        assert_eq!(
            parent_and_name("a/b/c.txt"),
            ("a/b".to_string(), "c.txt".to_string())
        );
        assert_eq!(
            parent_and_name("c.txt"),
            (String::new(), "c.txt".to_string())
        );
    }
}
