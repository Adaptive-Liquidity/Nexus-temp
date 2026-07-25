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
use std::sync::{Mutex, MutexGuard};

/// The single mutex governing [`EGRESS_ENV_VARS`] for the whole crate's tests.
///
/// Do not add a second lock over these variables in any module — that is the exact
/// defect this replaces.
pub(crate) static EGRESS_ENV_LOCK: Mutex<()> = Mutex::new(());

/// The process-global variables read by `EgressPolicy::from_env`.
pub(crate) const EGRESS_ENV_VARS: [&str; 2] =
    ["NEXUS_EGRESS_ALLOWLIST", "NEXUS_EGRESS_ALLOW_PRIVATE"];

/// Proof that the current thread holds [`EGRESS_ENV_LOCK`], by owning the real
/// `MutexGuard`.
///
/// This is deliberately **not** a zero-sized marker. A marker could be constructed by
/// any crate-internal code that merely claims to hold the lock, which makes the
/// obligation a convention. Owning the `MutexGuard` makes it a fact: the only way to
/// obtain one of these is to actually acquire the mutex, so a function taking
/// `&EgressEnvGuard<'_>` cannot be called without the lock being held.
pub(crate) struct EgressEnvGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl EgressEnvGuard<'static> {
    /// Acquire the crate-wide egress lock, recovering from poisoning.
    ///
    /// A test that panics while holding this lock poisons it; that is expected and
    /// non-fatal, so every acquisition recovers via `into_inner`.
    pub(crate) fn acquire() -> Self {
        Self {
            _guard: EGRESS_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        }
    }
}

/// Hold [`EGRESS_ENV_LOCK`] for the duration of `f`, **without** clearing the
/// environment.
///
/// Serialisation alone is sufficient for readers: an invalid value only ever exists
/// while a writer holds this lock, so a reader that holds it cannot observe one.
/// Deliberately not clearing means a test that intentionally configures an allowlist
/// before constructing a client still sees its own configuration.
pub(crate) fn with_egress_lock<R>(f: impl FnOnce(&EgressEnvGuard<'_>) -> R) -> R {
    let held = EgressEnvGuard::acquire();
    f(&held)
}

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

    /// Deterministic proof that the choke point serialises a reader against a writer
    /// holding an invalid egress value — the exact TEST-1 race, driven by channel
    /// handshakes rather than sleeps.
    ///
    /// What this proves deterministically: the reader never observes the invalid value
    /// (construction would panic on `ConfigError` if it did), and it completes only
    /// after the writer releases. What it cannot prove without a bounded wait is the
    /// instantaneous claim "the reader is blocked *right now*" — that is a negative
    /// about a blocking mutex, so the `recv_timeout` below is an observation, not a
    /// proof, and it is deliberately not the assertion the test rests on.
    fn choke_point_serialises_reader(
        construct: fn() -> (),
    ) -> (bool, std::sync::mpsc::Receiver<()>) {
        use std::sync::mpsc;
        use std::thread;

        let (reader_started_tx, reader_started_rx) = mpsc::channel::<()>();
        let (reader_done_tx, reader_done_rx) = mpsc::channel::<()>();
        let (writer_may_release_tx, writer_may_release_rx) = mpsc::channel::<()>();

        let writer = thread::spawn(move || {
            with_clean_egress_env(|| {
                // Invalid value is live for as long as this closure holds the lock.
                std::env::set_var(EGRESS_ENV_VARS[1], "not-a-bool");
                // Hand control to the test body, which starts the reader.
                writer_may_release_rx
                    .recv()
                    .expect("test body must signal release");
            });
        });

        let reader = thread::spawn(move || {
            reader_started_tx.send(()).expect("signal reader start");
            // Blocks until the writer releases; must never observe "not-a-bool".
            construct();
            reader_done_tx.send(()).expect("signal reader done");
        });

        reader_started_rx.recv().expect("reader must start");
        // Observation (not the load-bearing assertion): the reader should still be
        // blocked while the writer holds the lock.
        let blocked_while_writer_held = reader_done_rx
            .recv_timeout(std::time::Duration::from_millis(150))
            .is_err();

        writer_may_release_tx.send(()).expect("release writer");
        writer.join().expect("writer thread");
        reader.join().expect("reader thread");

        (blocked_while_writer_held, reader_done_rx)
    }

    #[test]
    fn memory_client_responder_is_serialised_against_invalid_egress_writer() {
        let (blocked, _rx) = choke_point_serialises_reader(|| {
            let _ = crate::aeon::AeonMemoryClient::with_test_responder(
                &crate::aeon::AeonConfig {
                    enabled: true,
                    base_url: "http://aeon.test".to_string(),
                    agent_id: "agent-1".to_string(),
                    session_id: None,
                    timeout_ms: 30_000,
                    management_key: Some("mgmt-key".to_string()),
                    hmac_key: None,
                    verifying_key: None,
                },
                std::sync::Arc::new(|_req| crate::aeon::TestHttpResponse {
                    status: 200,
                    body: "{}".to_string(),
                }),
            );
        });
        // Reaching here at all means construction succeeded: had the reader observed
        // "not-a-bool", `from_config` would have returned ConfigError and the
        // `.expect()` inside the constructor would have panicked in the reader thread,
        // failing the join above.
        assert!(
            blocked,
            "reader completed while the writer still held the lock — the choke point \
             did not serialise construction"
        );
    }

    #[test]
    fn timeline_sink_responder_is_serialised_against_invalid_egress_writer() {
        let (blocked, _rx) = choke_point_serialises_reader(|| {
            let _ = crate::aeon::AeonTimelineSink::with_test_responder(
                &crate::aeon::AeonConfig {
                    enabled: true,
                    base_url: "http://aeon.test".to_string(),
                    agent_id: "agent-1".to_string(),
                    session_id: None,
                    timeout_ms: 30_000,
                    management_key: Some("mgmt-key".to_string()),
                    hmac_key: None,
                    verifying_key: None,
                },
                std::sync::Arc::new(|_req| crate::aeon::TestHttpResponse {
                    status: 200,
                    body: "{}".to_string(),
                }),
            );
        });
        assert!(
            blocked,
            "reader completed while the writer still held the lock — the choke point \
             did not serialise construction"
        );
    }
}
