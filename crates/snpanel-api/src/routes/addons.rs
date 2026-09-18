//! `/api/addons` - ported from `api/addons.py`, the listing.
//!
//! Install and uninstall stay with Python: uninstalling the Application addon
//! stops every site app first, which is `site_apps.control`, which is the
//! helper surface Phase 2 has not finished.
//!
//! The listing is readable by **every** role, and that is deliberate: the
//! sections a customer cannot see are the ones an addon has not been installed
//! for, and a blank panel with no explanation is worse than one that names the
//! missing feature. What a customer does *not* get is `notes` - those describe
//! how the server is put together, which is nobody's business but the
//! administrator's - or `can_manage`, which is false for them.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/addons", get(list).fallback(crate::fallback))
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

#[cfg(test)]
mod tests {
    use super::*;

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
