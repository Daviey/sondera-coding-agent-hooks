//! Precedence tests for the layered env loader. Uses unique variable names so the process-global
//! environment is not corrupted for parallel tests.

use std::fs;
use tempfile::tempdir;

/// A value set in the system file must not be overwritten by the user file.
#[test]
fn system_value_beats_user_value() {
    let dir = tempdir().unwrap();
    let system = dir.path().join("system.env");
    let user = dir.path().join("user.env");

    let shared = "SONDERA_CFG_TEST_SYS_BEATS_USER";
    let user_only = "SONDERA_CFG_TEST_USER_ONLY_GAP";
    unsafe { std::env::remove_var(shared); };
    unsafe { std::env::remove_var(user_only); };

    fs::write(&system, format!("{shared}=from-system\n")).unwrap();
    fs::write(&user, format!("{shared}=from-user\n{user_only}=filled-by-user\n")).unwrap();

    sondera_config::load_from(Some(&system), Some(&user));

    assert_eq!(
        std::env::var(shared).unwrap(),
        "from-system",
        "system value must win over user value"
    );
    assert_eq!(
        std::env::var(user_only).unwrap(),
        "filled-by-user",
        "user file must still fill vars the system file left unset"
    );
}

/// A value already in the process environment beats both files.
#[test]
fn process_env_beats_files() {
    let dir = tempdir().unwrap();
    let system = dir.path().join("system.env");

    let key = "SONDERA_CFG_TEST_PROC_WINS";
    unsafe { std::env::set_var(key, "from-process"); };
    fs::write(&system, format!("{key}=from-system\n")).unwrap();

    sondera_config::load_from(Some(&system), None);

    assert_eq!(
        std::env::var(key).unwrap(),
        "from-process",
        "process environment must win over the system file"
    );
    unsafe { std::env::remove_var(key); };
}

/// A missing system file is fine; the user file still loads.
#[test]
fn missing_system_file_falls_back_to_user() {
    let dir = tempdir().unwrap();
    let missing_system = dir.path().join("does-not-exist.env");
    let user = dir.path().join("user.env");

    let key = "SONDERA_CFG_TEST_MISSING_SYS";
    unsafe { std::env::remove_var(key); };
    fs::write(&user, format!("{key}=from-user\n")).unwrap();

    sondera_config::load_from(Some(&missing_system), Some(&user));

    assert_eq!(std::env::var(key).unwrap(), "from-user");
}
