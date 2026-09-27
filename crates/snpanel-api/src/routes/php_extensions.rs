//! `/api/maintenance/php-versions/{php_version}/extensions*` - the
//! extensions of one PHP version: what it loads, and the panel's catalogue
//! to install from and remove.
//!
//! Not in the Python. Administrators only: a PHP version is the server's,
//! and every website on it gets what it loads. "Installed" is what PHP says
//! it loads with FPM's own ini files (`php -m`), not what a package manager
//! says is on disk - a package installed and switched off is not an
//! extension a site can use. The installing and removing are the helper's
//! (`php-ext-install`, `php-ext-remove`), which restarts that FPM.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use snpanel_core::php_ext::{self, PHP_EXTENSIONS};
use snpanel_core::PhpVersion;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_enough_permissions, not_found};
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/maintenance/php-versions/{php_version}/extensions",
            get(list).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-versions/{php_version}/extensions/{extension}/install",
            post(install).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-versions/{php_version}/extensions/{extension}/remove",
            post(remove).fallback(crate::fallback),
        )
}

/// The version, when it is one the panel supports and this server has.
fn installed_version(raw: &str) -> Result<PhpVersion, Response> {
    let version = PhpVersion::parse(raw).map_err(|_| bad_request("Unsupported PHP version"))?;
    if !crate::php::list_installed_php().contains(&version.dotted()) {
        return Err(not_found(&format!("PHP {version} is not installed")));
    }
    Ok(version)
}

/// What the page shows: the catalogue, each entry installed or not by what
/// PHP loads, and everything it loads.
async fn view(version: PhpVersion) -> Value {
    let loaded = crate::php_tune::loaded_modules(&version.dotted())
        .await
        .unwrap_or_default();
    json!({
        "version": version.dotted(),
        // Whether PHP answered at all: with nothing loaded the page says it
        // cannot tell, rather than that nothing is installed.
        "read": !loaded.is_empty(),
        "loaded": loaded,
        "extensions": PHP_EXTENSIONS.iter().map(|e| json!({
            "key": e.key,
            "base": e.base,
            "installed": e.loaded_in(&loaded),
        })).collect::<Vec<_>>(),
    })
}

async fn list(Path(php_version): Path<String>, current: CurrentUser) -> Response {
    if !current.user.is_admin() {
        return not_enough_permissions();
    }
    match installed_version(&php_version) {
        Ok(version) => Json(view(version).await).into_response(),
        Err(r) => r,
    }
}

async fn install(
    State(state): State<AppState>,
    Path((php_version, extension)): Path<(String, String)>,
    req: Request,
) -> Response {
    change(state, php_version, extension, req, true).await
}

async fn remove(
    State(state): State<AppState>,
    Path((php_version, extension)): Path<(String, String)>,
    req: Request,
) -> Response {
    change(state, php_version, extension, req, false).await
}

async fn change(
    state: AppState,
    php_version: String,
    extension: String,
    req: Request,
    installing: bool,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !current.user.is_admin() {
        return not_enough_permissions();
    }
    let version = match installed_version(&php_version) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(ext) = php_ext::find(&extension) else {
        return not_found("There is no such PHP extension in the panel's list");
    };
    if !installing && ext.base {
        return bad_request(&format!(
            "{} comes with every PHP version the panel installs, and the panel does not remove it",
            ext.key
        ));
    }
    let dotted = version.dotted();
    if state.settings.command_dry_run {
        let mut answer = view(version).await;
        answer["message"] = json!(format!(
            "Would {} {} for PHP {dotted}",
            if installing { "install" } else { "remove" },
            ext.key
        ));
        return Json(answer).into_response();
    }
    // Literal verbs, one call each: the helper's own test reads them here.
    let result = if installing {
        shell::privileged(false, "php-ext-install", &[&dotted, ext.key], None, None).await
    } else {
        shell::privileged(false, "php-ext-remove", &[&dotted, ext.key], None, None).await
    };
    if !result.ok() {
        let detail = result.failure_detail(if installing {
            "The extension could not be installed"
        } else {
            "The extension could not be removed"
        });
        tracing::warn!(
            "PHP {dotted} extension {} {} failed: {}",
            ext.key,
            if installing { "install" } else { "removal" },
            detail.trim()
        );
        return error(StatusCode::BAD_REQUEST, detail.trim());
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        if installing {
            "php_extension_install"
        } else {
            "php_extension_remove"
        },
        &format!("php{dotted}"),
        ext.key,
    )
    .await;
    let mut answer = view(version).await;
    answer["message"] = json!(if installing {
        format!(
            "{} is installed for PHP {dotted}. PHP-FPM {dotted} restarted.",
            ext.key
        )
    } else {
        format!(
            "{} is removed from PHP {dotted}. PHP-FPM {dotted} restarted.",
            ext.key
        )
    });
    answer["output"] = json!(result.stdout);
    Json(answer).into_response()
}
