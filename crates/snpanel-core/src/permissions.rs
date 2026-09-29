//! Roles, ported from `core/permissions.py`.
//!
//! Two roles and three legacy aliases. The aliases are the reason this is a
//! module rather than a string comparison: a database installed before the
//! rename still holds `super_admin`, and reading that as "not an admin" would
//! quietly demote the owner of the panel. `deps.py` compares against the
//! *normalised* role everywhere, so Rust has to as well.
//!
//! An unrecognised role is not `end_user`. The Python raises 403 "Invalid
//! role", and that difference matters: defaulting a typo'd role to the lower
//! privilege sounds safe, but it turns a data problem into a silent permission
//! change nobody notices until an admin cannot reach their own settings.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Level 1.
    EndUser,
    /// Level 2: an end user with hosting of their own who also manages the
    /// accounts they created - never the server. Not in the Python.
    Reseller,
    /// Level 3.
    Admin,
}

impl Role {
    /// The string the database stores.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::EndUser => "end_user",
            Role::Reseller => "reseller",
            Role::Admin => "admin",
        }
    }

    /// Source: `ROLE_LEVEL`.
    pub fn level(self) -> u8 {
        match self {
            Role::EndUser => 1,
            Role::Reseller => 2,
            Role::Admin => 3,
        }
    }
}

/// Source: `normalize_role`. `None` is the Python's 403 "Invalid role".
pub fn normalize_role(role: &str) -> Option<Role> {
    match role {
        // LEGACY_ROLE_ALIASES, checked before the enum exactly as Python does.
        "super_admin" => Some(Role::Admin),
        "user" | "readonly" => Some(Role::EndUser),
        "admin" => Some(Role::Admin),
        "end_user" => Some(Role::EndUser),
        "reseller" => Some(Role::Reseller),
        _ => None,
    }
}

/// Source: `is_admin_role`.
pub fn is_admin_role(role: &str) -> bool {
    normalize_role(role) == Some(Role::Admin)
}

/// Whether `role` is a reseller's.
pub fn is_reseller_role(role: &str) -> bool {
    normalize_role(role) == Some(Role::Reseller)
}

/// Source: `ensure_role` - true when `role` is at least `minimum`.
///
/// An invalid role is false, which is the Python's 403 either way: it raises
/// on the normalisation before it ever compares levels.
pub fn has_role(role: &str, minimum: Role) -> bool {
    normalize_role(role).is_some_and(|r| r.level() >= minimum.level())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_legacy_aliases_still_resolve() {
        // A panel installed before the rename holds super_admin, and reading
        // that as "not an admin" would demote the owner of the machine.
        assert_eq!(normalize_role("super_admin"), Some(Role::Admin));
        assert_eq!(normalize_role("user"), Some(Role::EndUser));
        assert_eq!(normalize_role("readonly"), Some(Role::EndUser));
        assert!(is_admin_role("super_admin"));
    }

    #[test]
    fn the_current_names_resolve() {
        assert_eq!(normalize_role("admin"), Some(Role::Admin));
        assert_eq!(normalize_role("end_user"), Some(Role::EndUser));
        assert!(is_admin_role("admin"));
        assert!(!is_admin_role("end_user"));
    }

    #[test]
    fn an_unknown_role_is_refused_rather_than_downgraded() {
        // Python raises 403 "Invalid role"; quietly treating it as end_user
        // would turn a data problem into a permission change nobody notices.
        for bad in ["", "root", "administrator", "ADMIN", "Admin"] {
            assert_eq!(normalize_role(bad), None, "{bad:?}");
            assert!(!is_admin_role(bad), "{bad:?}");
            assert!(!has_role(bad, Role::EndUser), "{bad:?}");
        }
    }

    #[test]
    fn role_levels_order_the_way_ensure_role_compares_them() {
        assert!(has_role("admin", Role::EndUser));
        assert!(has_role("admin", Role::Admin));
        assert!(has_role("end_user", Role::EndUser));
        assert!(!has_role("end_user", Role::Admin));
        // A reseller is above a customer and below the server's owner: every
        // admin-only check stays closed to it.
        assert!(has_role("reseller", Role::EndUser));
        assert!(has_role("reseller", Role::Reseller));
        assert!(!has_role("reseller", Role::Admin));
        assert!(!is_admin_role("reseller"));
        assert!(is_reseller_role("reseller"));
        assert!(!has_role("end_user", Role::Reseller));
    }
}
