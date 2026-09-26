//! `/api/users/{user_id}/sftp/accounts` - a user's own SFTP accounts: extra
//! logins, each shut into one folder of their home. DirectAdmin's FTP
//! accounts, over SFTP, for a panel that has no FTP.
//!
//! Not in the Python. The helper makes the Linux account, its jail and its
//! mount (see `ops/sftp_sub.rs`); this is who may ask, and the list. An
//! administrator for anyone; a user for themselves - proving it is them, as
//! for their own SFTP password, before making a login or changing one: an
//! SFTP account is a key to their files.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::sftp_subaccounts::SftpSubaccount;
use snpanel_db::User;

use crate::auth::CurrentUser;
use crate::errors::{
    bad_request, conflict, error, internal_error, not_enough_permissions, not_found,
};
use crate::state::AppState;

/// How many SFTP accounts one user may have.
pub const MAX_ACCOUNTS: usize = 20;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/users/{user_id}/sftp/accounts",
            get(list).post(create).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/sftp/accounts/{account_id}",
            axum::routing::delete(remove).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/sftp/accounts/{account_id}/password",
            post(set_password).fallback(crate::fallback),
        )
}

fn is_admin(current: &CurrentUser) -> bool {
    permissions::has_role(&current.user.role, Role::Admin)
}

async fn owner(state: &AppState, current: &CurrentUser, user_id: i64) -> Result<User, Response> {
    if current.user.id != user_id && !is_admin(current) {
        return Err(not_enough_permissions());
    }
    match state.db.users().by_id(user_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(not_found("User not found")),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            Err(internal_error())
        }
    }
}

/// The name after `<owner>_`: 1-16 lowercase letters and digits.
pub fn name_ok(name: &str) -> bool {
    (1..=16).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A folder below the home, as the helper takes it: `.` for all of it,
/// else plain names joined by `/`.
pub fn directory_of(raw: &str) -> Option<String> {
    let text = raw.trim().trim_matches('/');
    if text.is_empty() || text == "." {
        return Some(".".to_string());
    }
    let plain = text.len() <= 1024
        && text.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    plain.then(|| text.to_string())
}

fn account_json(account: &SftpSubaccount, owner: &str) -> Value {
    json!({
        "id": account.id,
        "username": account.username,
        "directory": account.directory,
        // What the account sees: the folder, by its own name, at the top.
        "home": format!(
            "/{}",
            if account.directory == "." {
                owner.to_string()
            } else {
                account.directory.rsplit('/').next().unwrap_or_default().to_string()
            }
        ),
        "created_at": account.created_at,
    })
}

/// The password a request asks for: typed, or generated and shown once.
fn requested_password(body: &Value) -> Result<(String, bool), Response> {
    if body.get("generate").and_then(Value::as_bool) == Some(true) {
        return Ok((crate::sftp_access::generated_password(), true));
    }
    match body.get("password") {
        Some(Value::String(typed)) => {
            crate::sftp_access::check_password(typed)
                .map_err(|message| error(StatusCode::UNPROCESSABLE_ENTITY, message))?;
            Ok((typed.clone(), false))
        }
        _ => Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Type an SFTP password, or ask for one to be generated.",
        )),
    }
}

/// `GET /api/users/{user_id}/sftp/accounts`.
async fn list(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let user = match owner(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let linux = match crate::sftp_access::linux_account(&user.username) {
        Ok(a) => a,
        Err(message) => return bad_request(&message),
    };
    match state.db.sftp_subaccounts().list_for(user.id).await {
        Ok(rows) => axum::Json(json!({
            "owner": linux.as_str(),
            "max": MAX_ACCOUNTS,
            "ports": crate::sftp_access::ssh_ports(state.settings.command_dry_run).await,
            "items": rows.iter().map(|a| account_json(a, linux.as_str())).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("listing SFTP accounts failed: {e}");
            internal_error()
        }
    }
}

/// `POST /api/users/{user_id}/sftp/accounts` `{name, directory, password? |
/// generate}` - the account `<owner>_<name>`, shut into `directory`.
async fn create(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let user = match owner(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    if user.id == current.user.id {
        if let Err(r) = super::users::require_step_up(&state, &current, &body) {
            return r;
        }
    }
    if !user.is_active {
        return conflict("This user is suspended.");
    }
    let linux = match crate::sftp_access::linux_account(&user.username) {
        Ok(a) => a,
        Err(message) => return bad_request(&message),
    };
    let name = body["name"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if !name_ok(&name) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "The account name is 1-16 lowercase letters and digits.",
        );
    }
    let username = format!("{}_{name}", linux.as_str());
    if snpanel_core::types::PanelUsername::parse(&username).is_err() {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "That name makes an account name longer than 32 characters.",
        );
    }
    let Some(directory) = directory_of(body["directory"].as_str().unwrap_or(".")) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "The folder is plain names below the home: letters, digits, '.', '_' and '-'.",
        );
    };
    let (password, generated) = match requested_password(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let existing = match state.db.sftp_subaccounts().list_for(user.id).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing SFTP accounts failed: {e}");
            return internal_error();
        }
    };
    if existing.len() >= MAX_ACCOUNTS {
        return conflict(&format!("A user has at most {MAX_ACCOUNTS} SFTP accounts."));
    }
    // A panel user of that name, or anyone's account: a Linux name is one.
    let taken = matches!(state.db.users().by_username(&username).await, Ok(Some(_)))
        || matches!(
            state.db.sftp_subaccounts().username_taken(&username).await,
            Ok(true)
        );
    if taken {
        return conflict(&format!("The name {username} is taken."));
    }

    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "sftp-sub-create",
        &[linux.as_str(), &username, &directory],
        Some(&format!("{password}\n")),
        None,
    )
    .await;
    if !result.ok() {
        return bad_request(
            result
                .failure_detail("The SFTP account could not be made.")
                .trim(),
        );
    }
    let row = match state
        .db
        .sftp_subaccounts()
        .create(
            user.id,
            &username,
            &directory,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("recording SFTP account {username} failed: {e}");
            // Not listed, it could not be deleted from the page: undone.
            let _ = crate::shell::privileged(
                state.settings.command_dry_run,
                "sftp-sub-delete",
                &[linux.as_str(), &username],
                None,
                None,
            )
            .await;
            return internal_error();
        }
    };
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "sftp_account_create",
        &username,
    )
    .await;
    let mut body = account_json(&row, linux.as_str());
    if generated {
        body["password"] = json!(password);
    }
    axum::Json(body).into_response()
}

async fn account(
    state: &AppState,
    user: &User,
    account_id: i64,
) -> Result<SftpSubaccount, Response> {
    match state.db.sftp_subaccounts().by_id(user.id, account_id).await {
        Ok(Some(row)) => Ok(row),
        Ok(None) => Err(not_found("SFTP account not found")),
        Err(e) => {
            tracing::error!("reading SFTP account {account_id} failed: {e}");
            Err(internal_error())
        }
    }
}

/// `POST /api/users/{user_id}/sftp/accounts/{id}/password` `{password? |
/// generate}`.
async fn set_password(
    State(state): State<AppState>,
    Path((user_id, account_id)): Path<(i64, i64)>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let user = match owner(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    if user.id == current.user.id {
        if let Err(r) = super::users::require_step_up(&state, &current, &body) {
            return r;
        }
    }
    let row = match account(&state, &user, account_id).await {
        Ok(row) => row,
        Err(r) => return r,
    };
    let linux = match crate::sftp_access::linux_account(&user.username) {
        Ok(a) => a,
        Err(message) => return bad_request(&message),
    };
    let (password, generated) = match requested_password(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "sftp-sub-password",
        &[linux.as_str(), &row.username],
        Some(&format!("{password}\n")),
        None,
    )
    .await;
    if !result.ok() {
        return bad_request(
            result
                .failure_detail("The SFTP password could not be set.")
                .trim(),
        );
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "sftp_account_password",
        &row.username,
    )
    .await;
    let mut body = account_json(&row, linux.as_str());
    if generated {
        body["password"] = json!(password);
    }
    axum::Json(body).into_response()
}

/// `DELETE /api/users/{user_id}/sftp/accounts/{id}`.
async fn remove(
    State(state): State<AppState>,
    Path((user_id, account_id)): Path<(i64, i64)>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let user = match owner(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let row = match account(&state, &user, account_id).await {
        Ok(row) => row,
        Err(r) => return r,
    };
    if let Err(message) = drop_account(&state, &user.username, &row).await {
        return bad_request(&message);
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "sftp_account_delete",
        &row.username,
    )
    .await;
    axum::Json(json!({ "ok": true })).into_response()
}

/// An account gone - the helper's half, then the row.
async fn drop_account(state: &AppState, owner: &str, row: &SftpSubaccount) -> Result<(), String> {
    let linux = crate::sftp_access::linux_account(owner)?;
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "sftp-sub-delete",
        &[linux.as_str(), &row.username],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return Err(result
            .failure_detail("The SFTP account could not be removed.")
            .trim()
            .to_string());
    }
    state
        .db
        .sftp_subaccounts()
        .delete(row.user_id, row.id)
        .await
        .map_err(|e| format!("The SFTP account was removed but not its record: {e}"))?;
    Ok(())
}

/// A site going: the owner's SFTP accounts shut into its folder go with it,
/// whose mount would be of a folder no longer there.
pub(crate) async fn drop_for_site(state: &AppState, owner_id: i64, site_root: &str) {
    let Ok(Some(user)) = state.db.users().by_id(owner_id).await else {
        return;
    };
    let Ok(linux) = crate::sftp_access::linux_account(&user.username) else {
        return;
    };
    let home = format!("/home/{}/", linux.as_str());
    let Some(folder) = site_root
        .strip_prefix(&home)
        .map(|f| f.trim_end_matches('/').to_string())
    else {
        return;
    };
    if folder.is_empty() {
        return;
    }
    let Ok(rows) = state.db.sftp_subaccounts().list_for(user.id).await else {
        return;
    };
    for row in rows {
        let inside = row.directory == folder || row.directory.starts_with(&format!("{folder}/"));
        if inside {
            if let Err(message) = drop_account(state, &user.username, &row).await {
                tracing::warn!("SFTP account {} of a deleted site: {message}", row.username);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_short_lowercase_letters_and_digits() {
        for good in ["dev", "a", "web2", "abcdefghijklmnop"] {
            assert!(name_ok(good), "{good}");
        }
        for bad in ["", "Dev", "dev-1", "dev_1", "abcdefghijklmnopq", "dév"] {
            assert!(!name_ok(bad), "{bad}");
        }
    }

    #[test]
    fn a_folder_is_plain_names_below_the_home() {
        assert_eq!(directory_of("").as_deref(), Some("."));
        assert_eq!(directory_of("/").as_deref(), Some("."));
        assert_eq!(directory_of(".").as_deref(), Some("."));
        assert_eq!(
            directory_of("example.com/public_html/").as_deref(),
            Some("example.com/public_html")
        );
        assert_eq!(directory_of("/example.com").as_deref(), Some("example.com"));
        for bad in ["../bob", "example.com/../..", "a//b", "a b", "a;b", "x/./y"] {
            assert!(directory_of(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn an_account_shows_the_folder_it_starts_in() {
        let row = SftpSubaccount {
            id: 1,
            user_id: 2,
            username: "alice_dev".into(),
            directory: "example.com/public_html".into(),
            created_at: "2026-09-26 10:00:00".into(),
        };
        assert_eq!(account_json(&row, "alice")["home"], "/public_html");
        let all = SftpSubaccount {
            directory: ".".into(),
            ..row
        };
        assert_eq!(account_json(&all, "alice")["home"], "/alice");
    }

    #[test]
    fn the_router_can_be_built() {
        let _ = router();
    }
}
