//! Environment loading for the Sondera hook clients and harness server.
//!
//! Configuration is layered so an organization can manage it centrally while users fill in the
//! rest. Files load in this order:
//!
//! 1. the system file at [`DEFAULT_SYSTEM_ENV`] (or the path in `SONDERA_SYSTEM_ENV`), managed by
//!    the organization;
//! 2. the user file at `~/.sondera/env`.
//!
//! `dotenvy` does not overwrite a variable that is already set in the process environment, so the
//! first source to define a value wins. The effective precedence is therefore: process
//! environment, then system file, then user file. An organization can pin security-relevant
//! settings (`SONDERA_PROVIDER`, `SONDERA_FAIL_MODE`, `SONDERA_BASE_URL`) and a user cannot relax
//! them, while still supplying their own values for anything the organization left unset (a
//! personal API key, for example).

use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Default system environment file, owned by the organization.
pub const DEFAULT_SYSTEM_ENV: &str = "/etc/sondera/env";

/// Path to the system environment file. Honors `SONDERA_SYSTEM_ENV` when set, otherwise
/// [`DEFAULT_SYSTEM_ENV`]. Read from the process environment, not from either env file.
pub fn system_env_path() -> PathBuf {
    std::env::var("SONDERA_SYSTEM_ENV")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SYSTEM_ENV))
}

/// Path to the per-user environment file (`~/.sondera/env`), or `None` if the home directory
/// cannot be determined.
pub fn user_env_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sondera").join("env"))
}

/// Load the system file, then the user file, with organization-enforced precedence. See the
/// crate docs for the precedence rules.
pub fn load() {
    load_from(Some(&system_env_path()), user_env_path().as_deref());
}

/// Load explicit system and user files. Pass `None` to skip a layer. Exposed so callers that
/// resolve paths themselves (and tests) can reuse the same precedence logic.
pub fn load_from(system: Option<&Path>, user: Option<&Path>) {
    if let Some(path) = system {
        load_file(path, "system");
    }
    if let Some(path) = user {
        load_file(path, "user");
    }
}

fn load_file(path: &Path, layer: &str) {
    if !path.exists() {
        debug!(layer, path = ?path, "no env file present, skipping");
        return;
    }
    match dotenvy::from_path(path) {
        Ok(()) => debug!(layer, path = ?path, "loaded env file"),
        Err(error) => warn!(layer, path = ?path, %error, "failed to load env file"),
    }
}
