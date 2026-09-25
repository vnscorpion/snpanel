//! `/api/users/{user_id}/sftp` - not in the Python: a user's SFTP login.
//!
//! An administrator switches it on and off for anyone. A user sees their own
//! and changes its password while it is on, proving it is them first - the
//! current panel password, and the authenticator code when they have one - as
//! a panel password change does: an SFTP password is every file they have.
//!
//! Switching SFTP on always sets a password, typed or generated and shown
//! once, and from then on the login keeps a password of its own. Unlocking
//! whatever was there would bring back the one the panel last copied in,
//! from before it was switched off, which nobody may remember.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::sftp_accounts::SftpAccess;
use snpanel_db::User;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, internal_error, not_enough_permissions, not_found};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/users/{user_id}/sftp",
            get(read).put(switch).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/sftp/password",
            post(set_password).fallback(crate::fallback),
        )
}

fn is_admin(current: &CurrentUser) -> bool {
    permissions::has_role(&current.user.role, Role::Admin)
}

/// The user, when the caller may see their SFTP login: an administrator, or
/// the user themself.
async fn target(state: &AppState, current: &CurrentUser, user_id: i64) -> Result<User, Response> {
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

/// What the page shows: the decision, and what to connect with.
async fn describe(state: &AppState, user: &User, generated: Option<String>) -> Response {
    let access = match crate::sftp_access::access(&state.db, user.id, &user.username).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return internal_error();
        }
    };
    let account = match crate::sftp_access::linux_account(&user.username) {
        Ok(a) => a,
        Err(message) => return bad_request(&message),
    };
    let mut body = json!({
        "user_id": user.id,
        "username": account.as_str(),
        "enabled": access.enabled,
        "own_password": access.own_password,
        "active": user.is_active,
        "home": format!("/home/{}", account.as_str()),
        "ports": crate::sftp_access::ssh_ports(state.settings.command_dry_run).await,
    });
    if let Some(password) = generated {
        body["password"] = json!(password);
    }
    axum::Json(body).into_response()
}

/// The password a request asks for: typed, or generated when `generate` is
/// true. `Ok(None)` when it asks for neither.
fn requested_password(body: &Value) -> Result<Option<(String, bool)>, Response> {
    if body.get("generate").and_then(Value::as_bool) == Some(true) {
        return Ok(Some((crate::sftp_access::generated_password(), true)));
    }
    match body.get("password") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(typed)) => {
            crate::sftp_access::check_password(typed)
                .map_err(|message| error(StatusCode::UNPROCESSABLE_ENTITY, message))?;
            Ok(Some((typed.clone(), false)))
        }
        Some(_) => Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "The SFTP password must be text.",
        )),
    }
}

/// The Linux account's password, set - which also unlocks it.
async fn set_linux_password(state: &AppState, user: &User, password: &str) -> Result<(), Response> {
    let account = crate::sftp_access::linux_account(&user.username).map_err(|m| bad_request(&m))?;
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "panel-user-password",
        &[account.as_str()],
        Some(&format!("{password}\n")),
        None,
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        tracing::error!(
            "setting the SFTP password failed: {}",
            result.failure_detail("panel-user-password")
        );
        Err(bad_request(
            result
                .failure_detail("The SFTP password could not be set.")
                .trim(),
        ))
    }
}

async fn record(state: &AppState, user: &User, access: SftpAccess) -> Result<(), Response> {
    state
        .db
        .sftp_accounts()
        .set(
            user.id,
            &user.username,
            access,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
        .map_err(|e| {
            tracing::error!("storing the SFTP settings failed: {e}");
            internal_error()
        })
}

/// `GET /api/users/{user_id}/sftp`.
async fn read(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(user_id): Path<i64>,
) -> Response {
    match target(&state, &current, user_id).await {
        Ok(user) => describe(&state, &user, None).await,
        Err(r) => r,
    }
}

/// `PUT /api/users/{user_id}/sftp` `{enabled, password?, generate?}` -
/// administrators only.
async fn switch(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !is_admin(&current) {
        return not_enough_permissions();
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "enabled must be true or false",
        );
    };
    let user = match target(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let now = match crate::sftp_access::access(&state.db, user.id, &user.username).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return internal_error();
        }
    };

    let mut generated = None;
    if enabled {
        let requested = match requested_password(&body) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let Some((password, was_generated)) = requested else {
            if now.enabled {
                return describe(&state, &user, None).await;
            }
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Set an SFTP password to switch SFTP on.",
            );
        };
        // A suspended user's account is locked; a password would unlock it.
        if !user.is_active {
            return crate::errors::conflict(
                "This user is suspended. Let them back in before switching SFTP on.",
            );
        }
        if let Err(r) = set_linux_password(&state, &user, &password).await {
            return r;
        }
        if let Err(r) = record(
            &state,
            &user,
            SftpAccess {
                enabled: true,
                own_password: true,
            },
        )
        .await
        {
            return r;
        }
        if was_generated {
            generated = Some(password);
        }
    } else {
        crate::sftp_access::set_locked(
            &state.db,
            state.settings.command_dry_run,
            user.id,
            &user.username,
            &[],
            true,
        )
        .await;
        if let Err(r) = record(
            &state,
            &user,
            SftpAccess {
                enabled: false,
                ..now
            },
        )
        .await
        {
            return r;
        }
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        if enabled {
            "sftp_enable"
        } else {
            "sftp_disable"
        },
        &user.username,
    )
    .await;
    describe(&state, &user, generated).await
}

/// `POST /api/users/{user_id}/sftp/password` `{password?, generate?}`.
///
/// An administrator for anyone; a user for themselves, with the current
/// panel password and their authenticator code.
async fn set_password(
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
    let user = match target(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    if user.id == current.user.id {
        if let Err(r) = super::users::require_step_up(&state, &current, &body) {
            return r;
        }
    }
    let access = match crate::sftp_access::access(&state.db, user.id, &user.username).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return internal_error();
        }
    };
    if !access.enabled {
        return crate::errors::conflict("SFTP is off for this user.");
    }
    if !user.is_active {
        return crate::errors::conflict("This user is suspended.");
    }
    let (password, was_generated) = match requested_password(&body) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Type an SFTP password, or ask for one to be generated.",
            )
        }
        Err(r) => return r,
    };
    if let Err(r) = set_linux_password(&state, &user, &password).await {
        return r;
    }
    if let Err(r) = record(
        &state,
        &user,
        SftpAccess {
            enabled: true,
            own_password: true,
        },
    )
    .await
    {
        return r;
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "sftp_password",
        &user.username,
    )
    .await;
    describe(&state, &user, was_generated.then_some(password)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_asks_for_a_typed_password_a_generated_one_or_neither() {
        assert!(matches!(requested_password(&json!({})), Ok(None)));
        assert!(matches!(
            requested_password(&json!({ "password": null })),
            Ok(None)
        ));
        let Ok(Some((typed, false))) =
            requested_password(&json!({ "password": "correct horse battery" }))
        else {
            panic!("a typed password");
        };
        assert_eq!(typed, "correct horse battery");
        // Asking for one to be generated wins over anything typed beside it.
        let Ok(Some((generated, true))) =
            requested_password(&json!({ "generate": true, "password": "correct horse battery" }))
        else {
            panic!("a generated password");
        };
        assert_eq!(generated.len(), 20);
        assert!(requested_password(&json!({ "password": "short" })).is_err());
        assert!(requested_password(&json!({ "password": 123456789012u64 })).is_err());
        assert!(requested_password(&json!({ "password": "correct:horse battery" })).is_err());
    }
}
