//! `/api/addons` - ported from `api/addons.py`.
//!
//! The note here used to say install and uninstall were waiting on the helper,
//! because uninstalling the Application addon stops every site app first.
//! `site-app-control` has been answered by the Rust helper since Stage B, so
//! they are here now.
//!
//! The listing is readable by **every** role, and that is deliberate: the
//! sections a customer cannot see are the ones an addon has not been installed
//! for, and a blank panel with no explanation is worse than one that names the
//! missing feature. What a customer does *not* get is `notes` - those describe
//! how the server is put together, which is nobody's business but the
//! administrator's - or `can_manage`, which is false for them.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/addons", get(list).fallback(crate::fallback))
        .route(
            "/addons/{slug}/install",
            post(install).fallback(crate::fallback),
        )
        .route(
            "/addons/{slug}/uninstall",
            post(uninstall).fallback(crate::fallback),
        )
}

/// Source: `addons.APPLICATION`.
const APPLICATION: &str = "application";

/// Source: `addons.CATALOGUE`.
///
/// Held here rather than read from a file because it is the Python's own
/// constant: what the panel *can* do is a property of the release, and only
/// what has been *installed* lives on disk. The Vietnamese strings are the
/// panel's own and are copied byte for byte - they are what an administrator
/// reads on the Addons page.
fn catalogue() -> Vec<(&'static str, Value)> {
    vec![(
        APPLICATION,
        json!({
            "name": "Application",
            "version": "1.0.0",
            "summary": "Chạy ứng dụng Node.js, container và Docker Compose, đưa ra domain qua Nginx.",
            "details": [
                "Cài Docker và các bản Node.js khi cần, không nằm trong bản cài mặc định.",
                "Mỗi ứng dụng có cổng nội bộ riêng, giới hạn RAM/CPU và chạy dưới user của khách.",
                "Website chọn mode Application để Nginx trỏ vào ứng dụng đã cài.",
            ],
            "notes": [
                "Backup hiện chưa bao gồm dữ liệu ứng dụng (thư mục apps và named volume).",
                "Dung lượng image và volume Docker chưa được tính vào quota đĩa của khách.",
            ],
            "keeps_data_on_uninstall": true,
        }),
    )]
}

/// Source: `addons.ADDONS_FILE`.
fn addons_file() -> std::path::PathBuf {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".to_string());
    std::path::Path::new(&dir).join("addons.json")
}

fn stored() -> Value {
    std::fs::read_to_string(addons_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// Source: `addons.state()` - the catalogue with each addon's record folded
/// in, sorted by slug.
fn addon_state() -> Vec<Value> {
    let stored = stored();
    let mut entries: Vec<(&str, Value)> = catalogue();
    entries.sort_by_key(|(slug, _)| *slug);

    entries
        .into_iter()
        .map(|(slug, entry)| {
            let record = stored.get(slug).cloned().unwrap_or_else(|| json!({}));
            let mut out = json!({ "slug": slug });
            if let (Some(out_map), Some(entry_map)) = (out.as_object_mut(), entry.as_object()) {
                for (k, v) in entry_map {
                    out_map.insert(k.clone(), v.clone());
                }
                out_map.insert(
                    "installed".into(),
                    json!(record
                        .get("installed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)),
                );
                out_map.insert(
                    "installed_version".into(),
                    json!(record
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or_default()),
                );
                out_map.insert(
                    "installed_at".into(),
                    json!(record
                        .get("installed_at")
                        .and_then(Value::as_str)
                        .unwrap_or_default()),
                );
            }
            out
        })
        .collect()
}

async fn list(State(_state): State<AppState>, current: CurrentUser) -> Response {
    // `ensure_role(current_user.role, Role.end_user)` - every authenticated
    // role passes, but an unrecognised one does not.
    if permissions::normalize_role(&current.user.role).is_none() {
        return crate::errors::error(axum::http::StatusCode::FORBIDDEN, "Invalid role");
    }
    let can_manage = permissions::is_admin_role(&current.user.role);

    let mut items = addon_state();
    if !can_manage {
        for item in &mut items {
            if let Some(map) = item.as_object_mut() {
                map.remove("notes");
            }
        }
    }

    axum::Json(json!({ "items": items, "can_manage": can_manage })).into_response()
}

// ---------------------------------------------------------------------------
// turning an addon on and off
// ---------------------------------------------------------------------------

/// Source: `addons._write` - a temporary file in the same directory, then a
/// rename. Losing power halfway through leaves the old file, not half of a
/// new one, and every caller of `is_installed` reads this.
fn write_addons(data: &Value) -> std::io::Result<()> {
    let path = addons_file();
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;

    // `json.dump(..., ensure_ascii=True, indent=2, sort_keys=True)` followed
    // by a newline. serde_json's pretty printer is two-space indented and its
    // maps are sorted, which is the same file for the three ASCII keys this
    // ever writes.
    let mut text = serde_json::to_string_pretty(data)?;
    text.push('\n');

    let temp = dir.join(format!(".addons.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, &path)
}

/// Source: `addons.known` - a slug outside the catalogue is a 404, not a
/// silently created entry.
fn known(slug: &str) -> Option<Value> {
    catalogue()
        .into_iter()
        .find(|(name, _)| *name == slug)
        .map(|(_, entry)| entry)
}

/// Source: `datetime.now(timezone.utc).isoformat(timespec="seconds")`.
///
/// `+00:00`, not `Z`. Python's `isoformat` writes the offset out, and the
/// listing hands this string straight to the frontend.
fn now_utc() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// Source: `addons.install` - the record it puts in the file.
fn install_record(data: &mut Value, slug: &str, version: &str, when: &str) {
    let map = data.as_object_mut().expect("stored() returns an object");
    map.insert(
        slug.to_string(),
        json!({
            "installed": true,
            "version": version,
            "installed_at": when,
        }),
    );
}

/// Source: `addons.uninstall` - `record = data.get(slug) or {}` and then only
/// `installed` is changed.
///
/// The version and the install date are **kept**, which is what lets the
/// listing still name the version sitting there switched off, and what makes
/// installing again pick up where it left off.
fn uninstall_record(data: &mut Value, slug: &str) {
    let map = data.as_object_mut().expect("stored() returns an object");
    let mut record = map
        .get(slug)
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    record["installed"] = json!(false);
    map.insert(slug.to_string(), record);
}

/// Source: `install_addon`.
async fn install(
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    current: CurrentUser,
) -> Response {
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let Some(entry) = known(&slug) else {
        return crate::errors::not_found(&format!("No such addon: {slug}"));
    };

    let version = entry["version"].as_str().unwrap_or("").to_string();
    let mut data = stored();
    install_record(&mut data, &slug, &version, &now_utc());
    if let Err(e) = write_addons(&data) {
        tracing::error!("writing addons.json failed: {e}");
        return crate::errors::internal_error();
    }

    let _ = state
        .db
        .audits()
        .log(Some(current.user.id), "install_addon", &slug, &version)
        .await;

    axum::Json(json!({
        "slug": slug,
        "name": entry["name"],
        "installed": true,
        "version": version,
        // The runtimes an application needs are installed from the Application
        // page itself, which can report progress; saying so here saves someone
        // wondering why Docker did not appear.
        "next_step": if slug == APPLICATION {
            "Vào mục Application để cài Docker hoặc bản Node.js cần dùng."
        } else {
            ""
        },
    }))
    .into_response()
}

/// Source: `uninstall_addon`.
///
/// Nothing the addon created is deleted. The units are stopped, because a
/// panel that no longer shows a feature should not keep running it where
/// nobody can see or manage it; the files, the volumes and the rows stay
/// exactly where they are, so installing it again brings it all back.
async fn uninstall(
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    current: CurrentUser,
) -> Response {
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let Some(entry) = known(&slug) else {
        return crate::errors::not_found(&format!("No such addon: {slug}"));
    };

    let mut stopped: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    if slug == APPLICATION {
        let apps = match state.db.site_apps().all().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("listing site apps failed: {e}");
                return crate::errors::internal_error();
            }
        };
        for app in apps {
            // Source: the `except (RuntimeError, ValueError)` around
            // `site_apps.control`. An app that is already gone, or was never
            // deployed, is not a reason to refuse the uninstall - it is
            // reported in `could_not_stop` and the rest carry on.
            match stop_app(state.settings.command_dry_run, &app).await {
                Ok(()) => stopped.push(app.name),
                Err(()) => failed.push(app.name),
            }
        }
    }

    let mut data = stored();
    uninstall_record(&mut data, &slug);
    if let Err(e) = write_addons(&data) {
        tracing::error!("writing addons.json failed: {e}");
        return crate::errors::internal_error();
    }

    let _ = state
        .db
        .audits()
        .log(
            Some(current.user.id),
            "uninstall_addon",
            &slug,
            &format!("stopped {}", stopped.len()),
        )
        .await;

    axum::Json(json!({
        "slug": slug,
        "name": entry["name"],
        "installed": false,
        "stopped": stopped,
        "could_not_stop": failed,
        "kept": "Thư mục ứng dụng, volume và dữ liệu trong panel được giữ nguyên.",
    }))
    .into_response()
}

/// Source: `site_apps.control(app, "stop")`, with the two `ValueError`s that
/// wrap it: `owner_linux_user` when the owner row is gone, and
/// `validate_name` on the app's own name.
///
/// `control` itself passes `check=False`, so a helper that fails is not an
/// exception in Python and is not an error here either - only the two
/// validation failures are. That is why a stopped-but-unhappy unit still
/// counts as stopped.
async fn stop_app(dry_run: bool, app: &snpanel_db::SiteAppRow) -> Result<(), ()> {
    let username = app
        .owner_username
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    // Source: `linux_user_for_panel_username` - lower and strip, then
    // `validate_linux_user` on the result.
    let owner = snpanel_core::types::PanelUsername::parse(&username).map_err(|_| ())?;
    let name = validate_app_name(&app.name).ok_or(())?;

    crate::shell::privileged(
        dry_run,
        "site-app-control",
        &[owner.as_str(), &name, "stop"],
        None,
        Some(&["bash", "-lc", "echo dry-run"]),
    )
    .await;
    Ok(())
}

/// Source: `site_apps.validate_name` - `^[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]$` or
/// a single `[a-z0-9]`, matched against the stripped, lowercased name.
fn validate_app_name(name: &str) -> Option<String> {
    let value = name.trim().to_lowercase();
    let bytes = value.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = match bytes.len() {
        0 => false,
        1 => alnum(bytes[0]),
        // The first alternative needs a first and a last character plus up to
        // 31 in between, so 2 to 33 characters in total.
        2..=32 => {
            alnum(bytes[0])
                && alnum(bytes[bytes.len() - 1])
                && bytes[1..bytes.len() - 1]
                    .iter()
                    .all(|&b| alnum(b) || b == b'_' || b == b'-')
        }
        _ => false,
    };
    ok.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `addons.json` after each write, byte for byte, against the real
    /// Python's. It is the whole state of the feature - `require()` reads it
    /// on every Application request - so a file shaped differently turns the
    /// addon off for everybody, and one that drops an unrelated entry takes a
    /// second addon with it.
    #[test]
    fn the_state_file_is_written_the_way_python_writes_it() {
        let dir = std::env::temp_dir().join(format!("addons-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the temp data dir");
        let _env = crate::testenv::EnvGuard::set(&[(
            "SNPANEL_DATA_DIR",
            dir.to_str().expect("a utf-8 temp path"),
        )]);

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/addons_state.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the addons corpus"))
                .expect("the corpus parses");
        let writes = corpus["writes"].as_array().expect("the writes");

        // The date moves every run, so the comparison uses the corpus's own
        // normalised form with the value blanked. The format itself is pinned
        // by `an_install_date_is_written_the_way_python_writes_it`.
        let normalise = |text: &str| -> String {
            let mut parsed: serde_json::Value =
                serde_json::from_str(text).expect("the file we just wrote parses");
            for (_, record) in parsed.as_object_mut().expect("an object").iter_mut() {
                if record
                    .get("installed_at")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                {
                    record["installed_at"] = json!("<when>");
                }
            }
            serde_json::to_string_pretty(&parsed).expect("pretty") + "\n"
        };

        let mut failures: Vec<String> = Vec::new();
        let mut check = |label: &str| {
            let Some(case) = writes.iter().find(|w| w["label"] == label) else {
                failures.push(format!("{label}: not in the corpus"));
                return;
            };
            let got = std::fs::read_to_string(addons_file()).expect("the file we wrote");
            let want = case["normalised"].as_str().unwrap_or("");
            let got = normalise(&got);
            if got != want {
                failures.push(format!("{label}:\n  python {want:?}\n  rust   {got:?}"));
            }
        };

        let mut data = stored();
        install_record(&mut data, "application", "1.0.0", &now_utc());
        write_addons(&data).expect("install");
        check("install");

        let mut data = stored();
        uninstall_record(&mut data, "application");
        write_addons(&data).expect("uninstall");
        check("uninstall");

        let mut data = stored();
        install_record(&mut data, "application", "1.0.0", &now_utc());
        write_addons(&data).expect("reinstall");
        check("reinstall");

        // An unrelated entry already in the file has to survive.
        let mut data = stored();
        data.as_object_mut().unwrap().insert(
            "something-else".to_string(),
            json!({
                "installed": true,
                "version": "9.9.9",
                "installed_at": "2020-01-01T00:00:00+00:00",
            }),
        );
        write_addons(&data).expect("the stranger");
        let mut data = stored();
        uninstall_record(&mut data, "application");
        write_addons(&data).expect("uninstall again");
        check("uninstall-with-a-stranger-present");

        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn an_install_date_is_written_the_way_python_writes_it() {
        // `isoformat(timespec="seconds")` on an aware UTC datetime: no
        // fractional seconds, and the offset spelled out rather than `Z`.
        let now = now_utc();
        assert_eq!(now.len(), "2026-01-02T03:04:05+00:00".len(), "{now}");
        assert!(now.ends_with("+00:00"), "{now}");
        assert_eq!(now.as_bytes()[10], b'T', "{now}");
        assert!(!now.contains('.'), "{now}");
    }

    /// `validate_name` runs over every app's name during an uninstall, and a
    /// name it refuses is an app the panel reports it could not stop. The
    /// boundaries are where the pattern's two alternatives meet.
    #[test]
    fn an_app_name_is_validated_the_way_python_validates_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/addons_state.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the addons corpus"))
                .expect("the corpus parses");

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["names"].as_array().expect("the name cases") {
            let name = case["name"].as_str().unwrap_or("");
            let got = validate_app_name(name);
            match case.get("result").and_then(Value::as_str) {
                Some(want) => {
                    if got.as_deref() != Some(want) {
                        failures.push(format!("{name:?}: python {want:?}, rust {got:?}"));
                    }
                }
                None => {
                    if got.is_some() {
                        failures.push(format!("{name:?}: python refused, rust {got:?}"));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn a_slug_outside_the_catalogue_is_not_installable() {
        // `known()` is what makes an unknown slug a 404 rather than a new
        // entry in the file that nothing can ever uninstall.
        assert!(known("application").is_some());
        for bad in [
            "",
            "Application",
            "docker",
            "../application",
            "application ",
        ] {
            assert!(known(bad).is_none(), "{bad:?} must not be a known addon");
        }
    }

    #[test]
    fn an_entry_carries_the_catalogue_and_the_stored_record() {
        let items = addon_state();
        assert_eq!(items.len(), 1, "one addon in the catalogue");
        let app = &items[0];
        assert_eq!(app["slug"], json!(APPLICATION));
        for key in [
            "name",
            "version",
            "summary",
            "details",
            "notes",
            "keeps_data_on_uninstall",
            "installed",
            "installed_version",
            "installed_at",
        ] {
            assert!(app.get(key).is_some(), "{key} is missing");
        }
        // Absent from the store means not installed, with empty strings rather
        // than nulls - the frontend renders these directly.
        assert!(app["installed"].is_boolean());
        assert!(app["installed_version"].is_string());
        assert!(app["installed_at"].is_string());
    }

    #[test]
    fn the_notes_are_for_administrators_only() {
        // They describe how the server is put together. A customer sees the
        // feature exists, not how it is built.
        let mut items = addon_state();
        assert!(items[0].get("notes").is_some());
        if let Some(map) = items[0].as_object_mut() {
            map.remove("notes");
        }
        assert!(items[0].get("notes").is_none());
        // Everything else survives the removal.
        assert!(items[0].get("summary").is_some());
    }

    #[test]
    fn the_catalogue_text_is_the_panels_own() {
        // These strings are what an administrator reads on the Addons page, so
        // they are copied rather than translated or tidied (NT1).
        let items = addon_state();
        assert_eq!(items[0]["name"], json!("Application"));
        assert!(items[0]["summary"]
            .as_str()
            .unwrap()
            .starts_with("Chạy ứng dụng Node.js"));
        assert_eq!(items[0]["details"].as_array().unwrap().len(), 3);
        assert_eq!(items[0]["notes"].as_array().unwrap().len(), 2);
    }
}
