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

/// RAII restoration guard: puts [`EGRESS_ENV_VARS`] back to their captured values when
/// dropped, including while unwinding from a panic.
///
/// This is deliberately `Drop`-based rather than a `catch_unwind` + restore sequence.
/// With an explicit restore path the guarantee depends on that path being reached; with
/// `Drop` the restoration is performed by unwinding itself, so a panic anywhere inside
/// the closure — or any future early return — still restores the environment.
struct EgressEnvRestore {
    saved: [(&'static str, Option<OsString>); 2],
}

impl Drop for EgressEnvRestore {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// Run `test` with both egress variables removed, restoring the originals afterward,
/// while holding [`EGRESS_ENV_LOCK`] so no other test observes the mutation.
///
/// Panic-safe: restoration is performed by [`EgressEnvRestore`]'s `Drop`, so the
/// original values are put back even if `test` panics, and the panic propagates
/// unchanged. The guard is declared *after* the lock, so drop order restores the
/// environment first and releases the mutex second.
///
/// A panic escaping `test` poisons [`EGRESS_ENV_LOCK`] (the `MutexGuard` is dropped
/// while unwinding). That is recovered on every acquisition via
/// `unwrap_or_else(|poisoned| poisoned.into_inner())`, so one panicking test cannot
/// cascade into failures in unrelated tests.
///
/// Hold this only around **synchronous** environment mutation and config/client
/// construction. It takes a `std::sync::Mutex`, so it must never wrap an `.await`;
/// build the client inside the closure and await outside it.
///
/// Not reentrant: never call a helper that acquires [`EGRESS_ENV_LOCK`] from inside
/// this closure.
pub(crate) fn with_clean_egress_env<R>(test: impl FnOnce() -> R) -> R {
    let _lock = EGRESS_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Declared after `_lock`: on drop (including during unwind) the environment is
    // restored while the mutex is still held, then the mutex is released.
    let _restore = EgressEnvRestore {
        saved: EGRESS_ENV_VARS.map(|name| (name, std::env::var_os(name))),
    };

    for name in EGRESS_ENV_VARS {
        std::env::remove_var(name);
    }

    test()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Panic-safety of the restoration guard, and non-cascading poison recovery.
    ///
    /// Known values are established *while holding* [`EGRESS_ENV_LOCK`] so this cannot
    /// race a concurrent helper call: the lock is exclusive, so no other test can be
    /// mid save/restore when we write, and every other writer restores what it found —
    /// so our values survive until we read them back.
    #[test]
    fn restores_env_after_panic_and_recovers_from_poisoned_lock() {
        const KNOWN_ALLOWLIST: &str = "test-env-panic-safety.invalid";
        const KNOWN_ALLOW_PRIVATE: &str = "true";

        // (a) start from known values.
        {
            let _lock = EGRESS_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::env::set_var(EGRESS_ENV_VARS[0], KNOWN_ALLOWLIST);
            std::env::set_var(EGRESS_ENV_VARS[1], KNOWN_ALLOW_PRIVATE);
        }

        // (b) the closure mutates both variables and then panics.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_clean_egress_env(|| {
                std::env::set_var(EGRESS_ENV_VARS[0], "clobbered-by-panicking-closure");
                std::env::set_var(EGRESS_ENV_VARS[1], "not-a-bool");
                panic!("intentional panic inside with_clean_egress_env");
            })
        }));
        assert!(
            outcome.is_err(),
            "the closure's panic must propagate out of with_clean_egress_env"
        );

        // (c) both variables were restored despite the panic — proving Drop ran while
        // unwinding, not merely on the success path.
        {
            let _lock = EGRESS_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(
                std::env::var(EGRESS_ENV_VARS[0]).ok().as_deref(),
                Some(KNOWN_ALLOWLIST),
                "{} must be restored after a panicking closure",
                EGRESS_ENV_VARS[0]
            );
            assert_eq!(
                std::env::var(EGRESS_ENV_VARS[1]).ok().as_deref(),
                Some(KNOWN_ALLOW_PRIVATE),
                "{} must be restored after a panicking closure",
                EGRESS_ENV_VARS[1]
            );
        }

        // (d) the helper is still usable after the panic poisoned the mutex — no
        // cascading failure — and still presents a clean environment.
        let observed = with_clean_egress_env(|| {
            (
                std::env::var_os(EGRESS_ENV_VARS[0]),
                std::env::var_os(EGRESS_ENV_VARS[1]),
            )
        });
        assert_eq!(
            observed,
            (None, None),
            "helper must still clear both variables after recovering a poisoned lock"
        );

        // Leave the process environment as the rest of the suite expects: absent.
        {
            let _lock = EGRESS_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for name in EGRESS_ENV_VARS {
                std::env::remove_var(name);
            }
        }
    }
}
