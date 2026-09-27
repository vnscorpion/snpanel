//! Putting every site back the way the panel says it should be.
//!
//! Source: the two inline Python blocks that do the same sweep —
//! `snpanelctl fix-permissions` and `update.sh`'s site-refresh. Both walk
//! every website and, for each, ensure the runtime directory and document
//! root, fix ownership, resync the WAF rules, take the vhost back under
//! management and rewrite it; with the shared HTTP-flood zone file written
//! once before and once after.
//!
//! A flag on the binary rather than a route, because `snpanelctl` and
//! `update.sh` both run while the panel may be stopped, and a request to it
//! would have nowhere to go.
//!
//! # Two deliberate divergences, both measured
//!
//! Neither Python block calls the panel's own `_rewrite_website_vhost`. Both
//! call `nginx.rewrite_vhost` with a hand-written keyword list, and what the
//! list leaves out is the problem.
//!
//! **Aliases.** Neither block passes `aliases`, and `aliases=None` means "no
//! aliases" rather than "keep what is there" — `_server_names` builds
//! `[domain, www.domain]` and stops. Measured on a site with one alias: the
//! panel's own rewrite produced `server_name probe.example www.probe.example
//! alias.example;` and both sweeps produced `server_name probe.example
//! www.probe.example;`. So every update silently deletes every alias from
//! every vhost until somebody next edits that site in the panel, and the
//! alias stops resolving in the meantime.
//!
//! **The rewrite mode.** `fix-permissions` alone also omits `rewrite_mode`,
//! which defaults through `_check_rewrite_mode(None)` to `"none"`. On the
//! same probe site, set to `laravel`, the document root came back as
//! `/home/probeuser/probe.example/public_html` instead of
//! `.../public_html/public`. So `fix-permissions` breaks every Laravel and
//! CodeIgniter site it touches.
//!
//! This reproduces **neither**. It goes through
//! [`super::websites::rewrite_website_vhost`] — the path the panel itself
//! uses — which reads the aliases from the database and the rewrite mode
//! from the row. NT1 asks for behaviour to be reproduced rather than
//! improved, and that is right for behaviour somebody might depend on;
//! nobody depends on their aliases being deleted by an update. The
//! divergence is named here, recorded in the status document, and is a
//! one-line change to undo if it turns out to be load-bearing.

use crate::state::AppState;

/// What a failing site does to the rest of the sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnFailure {
    /// Source: `snpanelctl fix-permissions`, which lets the `RuntimeError`
    /// out and stops. An operator ran this by hand and is reading the
    /// output; finishing quietly over a broken site would hide the thing
    /// they asked about.
    Stop,
    /// Source: `update.sh`, whose loop body is wrapped in
    /// `except Exception as exc: print(f"WARNING: ...")`. An update that
    /// stopped at the first bad site would leave every site after it
    /// un-refreshed and the panel half-updated.
    Warn,
}

/// What the sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Swept {
    pub(crate) sites: usize,
    /// One line per problem, in the order they happened. Empty on a clean
    /// run.
    pub(crate) warnings: Vec<String>,
}

impl Swept {
    /// The lines the caller prints. The count goes last so it is the final
    /// thing on screen after any warnings.
    pub(crate) fn report(&self) -> String {
        let mut lines = self.warnings.clone();
        lines.push(match self.sites {
            1 => "Refreshed 1 site.".to_string(),
            n => format!("Refreshed {n} sites."),
        });
        lines.join("\n")
    }
}

/// Walk every website.
///
/// The flood-zone file is written **before and after**, which is the
/// Python's shape and not redundancy: the file is shared by every vhost, so
/// writing it first means the vhosts rendered below can name a zone that
/// exists, and writing it again afterwards picks up anything the loop
/// changed.
pub(crate) async fn all_sites(state: &AppState, on_failure: OnFailure) -> Result<Swept, String> {
    let mut swept = Swept::default();

    // Oldest first, as `db.query(Website).all()` comes back. Not the
    // listing endpoint's `list()`, which is newest-first for the UI: on a
    // strict sweep the order decides which sites were already refreshed when
    // it stopped, and that should be the Python's set and not a different
    // one.
    let websites = state
        .db
        .websites()
        .all_by_id()
        .await
        .map_err(|e| format!("could not list the websites: {e}"))?;

    zones(state, on_failure, &mut swept).await?;

    for website in &websites {
        match one_site(state, website).await {
            Ok(()) => swept.sites += 1,
            Err(why) => match on_failure {
                OnFailure::Stop => return Err(why),
                // Source: `WARNING: could not refresh permissions for
                // {website.domain}: {exc}`.
                OnFailure::Warn => swept.warnings.push(format!(
                    "WARNING: could not refresh permissions for {}: {why}",
                    website.domain
                )),
            },
        }
    }

    zones(state, on_failure, &mut swept).await?;
    Ok(swept)
}

/// Source: `nginx.sync_http_flood_zones(websites)`, and the two different
/// things the two blocks do when it fails.
async fn zones(state: &AppState, on_failure: OnFailure, swept: &mut Swept) -> Result<(), String> {
    let Err(why) = super::websites::sync_flood_zones(state).await else {
        return Ok(());
    };
    match on_failure {
        // Source: `raise RuntimeError(... "Unable to sync HTTP flood zones")`.
        OnFailure::Stop => Err(why),
        // Source: `WARNING: could not refresh HTTP flood zones: {...}`.
        OnFailure::Warn => {
            swept.warnings.push(format!(
                "WARNING: could not refresh HTTP flood zones: {why}"
            ));
            Ok(())
        }
    }
}

/// One website, in the Python's order.
///
/// The order is load-bearing in two places. The document root has to exist
/// before a vhost whose `root` points at it is written, or the config test
/// fails on a directory nothing has made yet. And the WAF rule file has to
/// be there before a vhost that includes it, for the same reason.
async fn one_site(state: &AppState, website: &snpanel_db::Website) -> Result<(), String> {
    let linux_user = website.linux_user.clone().unwrap_or_default();

    if !linux_user.is_empty() {
        let user = snpanel_core::types::PanelUsername::parse(&linux_user)
            .map_err(|e| format!("{linux_user} is not a usable Linux account name: {e}"))?;

        // Source: `runtime_php_version` - a static or proxied site gets no
        // pool, so it gets no PHP version here either.
        let app_type = if website.app_type.is_empty() {
            "wordpress"
        } else {
            &website.app_type
        };
        let runtime_php = matches!(app_type, "wordpress" | "php")
            .then_some(website.php_version.as_str())
            .filter(|v| !v.is_empty())
            // Source: `php_version or "none"`. The helper reads "" and
            // "none" the same way, and "none" is what the Python sends.
            .unwrap_or("none");

        let ensured = crate::shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[user.as_str(), &website.root_path, runtime_php],
            None,
            Some(&["mkdir", "-p", &website.root_path]),
        )
        .await;
        if !ensured.ok() {
            return Err(ensured
                .failure_detail("Could not prepare the site directory")
                .trim()
                .to_string());
        }

        let document_root = document_root_of(website);
        let target = format!("{}/{}", website.root_path, document_root);
        let made = crate::shell::privileged(
            state.settings.command_dry_run,
            "site-document-root-ensure",
            &[user.as_str(), &website.root_path, document_root],
            None,
            Some(&["mkdir", "-p", &target]),
        )
        .await;
        if !made.ok() {
            return Err(made
                .failure_detail("Could not prepare the document root")
                .trim()
                .to_string());
        }
    }

    // Source: `site_users.fix_site_permissions`, whose two calls are both
    // `check=False`. The result is **ignored on purpose**: ownership that
    // could not be corrected is not a reason to leave the vhost stale, and
    // the Python does not treat it as one.
    let owner = if linux_user.is_empty() {
        format!(
            "{}:{}",
            super::maintenance::web_user(),
            super::maintenance::web_group()
        )
    } else {
        format!("{linux_user}:{linux_user}")
    };
    let mut args: Vec<&str> = vec![&website.root_path];
    if !linux_user.is_empty() {
        args.push(&linux_user);
    }
    let _ = crate::shell::privileged(
        state.settings.command_dry_run,
        "fix-permissions",
        &args,
        None,
        Some(&["chown", "-R", &owner, &website.root_path]),
    )
    .await;

    // Source: `result = waf.sync_website_rules(website)` and the
    // `RuntimeError` on a non-zero return.
    let synced = crate::waf::sync_website_rules(
        state.settings.command_dry_run,
        website,
        &super::waf::server_crs_mode(),
    )
    .await
    .map_err(|e| format!("Unable to sync WAF rules: {e}"))?;
    if !synced.ok() {
        return Err(synced
            .failure_detail("Unable to sync WAF rules")
            .trim()
            .to_string());
    }

    // Source: `if website.nginx_config_mode != "managed": ... db.commit()`.
    // The sweep is the panel taking the file back, and the row has to say so
    // or the next edit will refuse to touch a vhost it thinks is hand-written.
    if website.nginx_config_mode != "managed" {
        state
            .db
            .websites()
            .set_config_mode_managed(website.id)
            .await
            .map_err(|e| format!("could not mark the vhost as managed: {e}"))?;
    }

    // The panel's own rewrite, not the Python's hand-written keyword list.
    // See the module docs: the list omits the aliases, and on the
    // `fix-permissions` path the rewrite mode too.
    super::websites::rewrite_owned_vhost(state, website, Default::default()).await?;
    Ok(())
}

/// Source: `getattr(website, "document_root", "public_html") or "public_html"`.
fn document_root_of(website: &snpanel_db::Website) -> &str {
    if website.document_root.is_empty() {
        "public_html"
    } else {
        &website.document_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The report ends with the count, after any warnings.**
    ///
    /// An operator watching `update.sh` scroll past sees the last line. A
    /// count printed before the warnings is a count that scrolls away.
    #[test]
    fn the_count_is_the_last_line() {
        let swept = Swept {
            sites: 3,
            warnings: vec!["WARNING: a".into(), "WARNING: b".into()],
        };
        let report = swept.report();
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(
            lines,
            vec!["WARNING: a", "WARNING: b", "Refreshed 3 sites."]
        );
    }

    #[test]
    fn one_site_is_not_one_sites() {
        assert_eq!(
            Swept {
                sites: 1,
                ..Default::default()
            }
            .report(),
            "Refreshed 1 site."
        );
        assert_eq!(Swept::default().report(), "Refreshed 0 sites.");
    }

    /// **An empty document root falls back to the Python's default.**
    ///
    /// `getattr(..., "public_html") or "public_html"` — the `or` is the
    /// operative half, because the column exists and holds `""` on rows that
    /// predate it. A blank passed on would make the helper's target the site
    /// root itself, and `fix-permissions` would then be handed a path one
    /// level up from the one it was meant to own.
    #[test]
    fn a_blank_document_root_becomes_public_html() {
        let mut website = crate::testenv::website_row();
        website.document_root = String::new();
        assert_eq!(document_root_of(&website), "public_html");
        website.document_root = "public".to_string();
        assert_eq!(document_root_of(&website), "public");
    }

    /// **A panel with no sites sweeps cleanly rather than refusing.**
    ///
    /// Unlike the orphan sweep, where an empty list is a delete request and
    /// has to be refused, an empty site list here means there is nothing to
    /// do. An install that has not had a site added yet runs `update.sh`
    /// like any other.
    #[tokio::test]
    async fn no_sites_is_not_a_failure() {
        let Some(state) = crate::testenv::panel("refresh-empty").await else {
            eprintln!("skipped: could not build a test panel here");
            return;
        };
        for mode in [OnFailure::Stop, OnFailure::Warn] {
            let swept = all_sites(&state, mode)
                .await
                .expect("an empty panel sweeps");
            assert_eq!(swept.sites, 0);
            assert_eq!(swept.warnings, Vec::<String>::new(), "{mode:?}");
            assert_eq!(swept.report(), "Refreshed 0 sites.");
        }
    }
}
