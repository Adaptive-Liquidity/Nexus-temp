//! Crate-wide test-only helpers for the process-global egress environment.
//!
//! `NEXUS_EGRESS_ALLOWLIST` and `NEXUS_EGRESS_ALLOW_PRIVATE` are read by
//! `EgressPolicy::from_env`, which every AEON client construction goes through.
//! Tests in more than one module mutate them, and `cargo test` runs the unit tests
//! of every module as threads of a *single* process — so the mutex governing them
//! has to be one crate-wide mutex.
//!
//! TEST-1: previously `src/aeon.rs` and `src/hypervisor/mod.rs` each declared their
//! own module-local `EGRESS_ENV_LOCK`. Two distinct mutexes over one process-global
//! resource provide no mutual exclusion against each other, so a `hypervisor::tests`
//! writer setting `NEXUS_EGRESS_ALLOW_PRIVATE="not-a-bool"` could be observed by a
//! concurrent reader, which then panicked with
//! `ConfigError("NEXUS_EGRESS_ALLOW_PRIVATE must be one of: 0, 1, true, false")`.
//! Reproduced at 12/20 runs under default test parallelism, 0/5 single-threaded.

use std::ffi::OsString;
use std::sync::Mutex;

/// The single mutex governing [`EGRESS_ENV_VARS`] for the whole crate's tests.
///
/// Do not add a second lock over these variables in any module — that is the exact
/// defect this replaces.
pub(crate) static EGRESS_ENV_LOCK: Mutex<()> = Mutex::new(());

/// The process-global variables read by `EgressPolicy::from_env`.
pub(crate) const EGRESS_ENV_VARS: [&str; 2] =
    ["NEXUS_EGRESS_ALLOWLIST", "NEXUS_EGRESS_ALLOW_PRIVATE"];

/// Run `test` with both egress variables removed, restoring the originals after,
/// while holding [`EGRESS_ENV_LOCK`] so no other test observes the mutation.
///
/// Hold this only around **synchronous** environment mutation and config/client
/// construction. It takes a `std::sync::Mutex`, so it must never wrap an `.await`;
/// build the client inside the closure and await outside it.
///
/// Not reentrant: never call a helper that acquires [`EGRESS_ENV_LOCK`] from inside
/// this closure.
pub(crate) fn with_clean_egress_env<R>(test: impl FnOnce() -> R + std::panic::UnwindSafe) -> R {
    let _guard = EGRESS_ENV_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());

    let saved: [(&str, Option<OsString>); 2] =
        EGRESS_ENV_VARS.map(|name| (name, std::env::var_os(name)));

    for name in EGRESS_ENV_VARS {
        std::env::remove_var(name);
    }

    let result = std::panic::catch_unwind(test);

    for (name, value) in saved {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    match result {
        Ok(value) => value,
        Err(payload) => {
            std::panic::resume_unwind(payload);
        }
    }
}
