//! PostgreSQL-backed shared replay consumption for RecallEnvelopeV2.
//!
//! This module provides storage and migrations only. It does not wire recall
//! verification into a runtime path, select database configuration, or make
//! runtime replay resistance active.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use aeon_nexus_bridge::v2::RECALL_NONCE_HEX_LEN;
use async_trait::async_trait;
use sqlx::PgPool;

use super::recall_v2::{ReplayConsumeResult, ReplayNamespace, ReplayStore, ReplayStoreError};

pub const POSTGRES_REPLAY_SCHEMA_VERSION: i32 = 1;
pub const POSTGRES_REPLAY_TABLE: &str = "nexus_recall_replay_nonces";
pub const POSTGRES_REPLAY_SCHEMA_TABLE: &str = "nexus_recall_replay_schema";
pub const MAX_PURGE_BATCH_SIZE: u32 = 10_000;

const MIGRATION_SQL: &str = include_str!("../../migrations/0001_recall_replay_store.sql");
const CONSUME_CLEANUP_LOCK_KEY: i64 = 5_640_004_627_203_514_945;

const CONSUME_SQL: &str = "
WITH replay_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock_shared($4)
),
inserted AS (
    INSERT INTO public.nexus_recall_replay_nonces
        (replay_namespace, nonce, expires_at_unix_ms)
    SELECT $1, $2, $3
    FROM replay_guard
    ON CONFLICT (replay_namespace, nonce) DO NOTHING
    RETURNING TRUE
)
SELECT TRUE FROM inserted
";

const PURGE_SQL: &str = "
WITH replay_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock($3)
),
expired AS MATERIALIZED (
    SELECT replay.replay_namespace, replay.nonce
    FROM public.nexus_recall_replay_nonces AS replay
    CROSS JOIN replay_guard
    WHERE replay.expires_at_unix_ms < $1
    ORDER BY replay.expires_at_unix_ms, replay.replay_namespace, replay.nonce
    LIMIT $2
    FOR UPDATE OF replay SKIP LOCKED
),
deleted AS (
    DELETE FROM public.nexus_recall_replay_nonces AS replay
    USING expired
    WHERE replay.replay_namespace = expired.replay_namespace
      AND replay.nonce = expired.nonce
    RETURNING 1
)
SELECT COUNT(*)::BIGINT FROM deleted
";

#[derive(Clone)]
pub struct PostgresReplayStore {
    pool: PgPool,
    operation_timeout: Duration,
}

impl PostgresReplayStore {
    /// Constructs a store only after proving the expected schema is available.
    ///
    /// This method never applies migrations and never falls back to memory.
    pub async fn new(
        pool: PgPool,
        operation_timeout: Duration,
    ) -> Result<Self, PostgresReplayStoreError> {
        validate_operation_timeout(operation_timeout)?;
        validate_schema(&pool, operation_timeout).await?;
        Ok(Self {
            pool,
            operation_timeout,
        })
    }

    /// Applies the additive version-one migration and validates its result.
    ///
    /// The embedded migration is idempotent and serialized with a
    /// transaction-scoped PostgreSQL advisory lock.
    pub async fn apply_migrations(
        pool: &PgPool,
        operation_timeout: Duration,
    ) -> Result<(), PostgresReplayStoreError> {
        validate_operation_timeout(operation_timeout)?;
        timeout_sqlx(
            operation_timeout,
            "apply replay-store migration",
            sqlx::raw_sql(MIGRATION_SQL).execute(pool),
        )
        .await?;
        validate_schema(pool, operation_timeout).await
    }

    /// Deletes at most batch_size rows whose expiry is strictly before the
    /// caller-supplied safe cutoff.
    ///
    /// No database clock participates in the decision. The caller must derive
    /// the cutoff conservatively from the accepted validity and skew policy.
    /// An exclusive advisory lock serializes cleanup against the shared lock
    /// held by each atomic consume statement.
    pub async fn purge_expired_before(
        &self,
        safe_cutoff_unix_ms: i64,
        batch_size: u32,
    ) -> Result<u64, PostgresReplayStoreError> {
        validate_safe_cutoff(safe_cutoff_unix_ms)?;
        validate_batch_size(batch_size)?;

        let deleted: i64 = timeout_sqlx(
            self.operation_timeout,
            "purge expired replay rows",
            sqlx::query_scalar(PURGE_SQL)
                .bind(safe_cutoff_unix_ms)
                .bind(i64::from(batch_size))
                .bind(CONSUME_CLEANUP_LOCK_KEY)
                .fetch_one(&self.pool),
        )
        .await?;
        u64::try_from(deleted).map_err(|_| {
            PostgresReplayStoreError::SchemaContract(
                "PostgreSQL returned a negative replay cleanup count",
            )
        })
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

#[async_trait]
impl ReplayStore for PostgresReplayStore {
    async fn consume_once(
        &self,
        replay_namespace: ReplayNamespace,
        nonce: &str,
        expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        validate_nonce(nonce).map_err(ReplayStoreError::new)?;
        validate_expires_at(expires_at_unix_ms).map_err(ReplayStoreError::new)?;

        let inserted: Option<bool> = timeout_sqlx(
            self.operation_timeout,
            "consume replay nonce",
            sqlx::query_scalar(CONSUME_SQL)
                .bind(replay_namespace.as_bytes().as_slice())
                .bind(nonce)
                .bind(expires_at_unix_ms)
                .bind(CONSUME_CLEANUP_LOCK_KEY)
                .fetch_optional(&self.pool),
        )
        .await
        .map_err(ReplayStoreError::new)?;

        Ok(if inserted.is_some() {
            ReplayConsumeResult::Fresh
        } else {
            ReplayConsumeResult::Replayed
        })
    }
}

#[derive(Debug)]
pub enum PostgresReplayStoreError {
    InvalidOperationTimeout,
    InvalidNonce,
    InvalidExpiresAt(i64),
    InvalidSafeCutoff(i64),
    InvalidBatchSize(u32),
    TimedOut {
        operation: &'static str,
    },
    Database {
        operation: &'static str,
        source: sqlx::Error,
    },
    SchemaVersion {
        expected: i32,
        found: Option<i32>,
    },
    SchemaContract(&'static str),
}

impl fmt::Display for PostgresReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperationTimeout => {
                formatter.write_str("PostgreSQL replay operation timeout must be non-zero")
            }
            Self::InvalidNonce => formatter.write_str(
                "replay nonce must be the exact lowercase-hex protocol representation",
            ),
            Self::InvalidExpiresAt(value) => {
                write!(formatter, "replay expiry must be non-negative, found {value}")
            }
            Self::InvalidSafeCutoff(value) => {
                write!(formatter, "replay cleanup cutoff must be non-negative, found {value}")
            }
            Self::InvalidBatchSize(value) => write!(
                formatter,
                "replay cleanup batch size must be between 1 and {MAX_PURGE_BATCH_SIZE}, found {value}"
            ),
            Self::TimedOut { operation } => {
                write!(formatter, "PostgreSQL replay operation timed out: {operation}")
            }
            Self::Database { operation, .. } => {
                write!(formatter, "PostgreSQL replay operation failed: {operation}")
            }
            Self::SchemaVersion { expected, found } => match found {
                Some(found) => write!(
                    formatter,
                    "unsupported PostgreSQL replay schema version {found}; expected {expected}"
                ),
                None => write!(
                    formatter,
                    "PostgreSQL replay schema version is missing; expected {expected}"
                ),
            },
            Self::SchemaContract(problem) => {
                write!(formatter, "invalid PostgreSQL replay schema: {problem}")
            }
        }
    }
}

impl Error for PostgresReplayStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_operation_timeout(timeout: Duration) -> Result<(), PostgresReplayStoreError> {
    if timeout.is_zero() {
        Err(PostgresReplayStoreError::InvalidOperationTimeout)
    } else {
        Ok(())
    }
}

fn validate_nonce(nonce: &str) -> Result<(), PostgresReplayStoreError> {
    if nonce.len() == RECALL_NONCE_HEX_LEN
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PostgresReplayStoreError::InvalidNonce)
    }
}

fn validate_expires_at(expires_at_unix_ms: i64) -> Result<(), PostgresReplayStoreError> {
    if expires_at_unix_ms >= 0 {
        Ok(())
    } else {
        Err(PostgresReplayStoreError::InvalidExpiresAt(
            expires_at_unix_ms,
        ))
    }
}

fn validate_safe_cutoff(safe_cutoff_unix_ms: i64) -> Result<(), PostgresReplayStoreError> {
    if safe_cutoff_unix_ms >= 0 {
        Ok(())
    } else {
        Err(PostgresReplayStoreError::InvalidSafeCutoff(
            safe_cutoff_unix_ms,
        ))
    }
}

fn validate_batch_size(batch_size: u32) -> Result<(), PostgresReplayStoreError> {
    if (1..=MAX_PURGE_BATCH_SIZE).contains(&batch_size) {
        Ok(())
    } else {
        Err(PostgresReplayStoreError::InvalidBatchSize(batch_size))
    }
}

async fn timeout_sqlx<T>(
    timeout: Duration,
    operation: &'static str,
    future: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, PostgresReplayStoreError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| PostgresReplayStoreError::TimedOut { operation })?
        .map_err(|source| PostgresReplayStoreError::Database { operation, source })
}

async fn validate_schema(
    pool: &PgPool,
    operation_timeout: Duration,
) -> Result<(), PostgresReplayStoreError> {
    let version: Option<i32> = timeout_sqlx(
        operation_timeout,
        "read replay schema version",
        sqlx::query_scalar(
            "SELECT schema_version
             FROM public.nexus_recall_replay_schema
             WHERE schema_name = 'nexus.recall.replay'",
        )
        .fetch_optional(pool),
    )
    .await?;
    if version != Some(POSTGRES_REPLAY_SCHEMA_VERSION) {
        return Err(PostgresReplayStoreError::SchemaVersion {
            expected: POSTGRES_REPLAY_SCHEMA_VERSION,
            found: version,
        });
    }

    let columns: Vec<(String, String, String, Option<String>)> = timeout_sqlx(
        operation_timeout,
        "inspect replay table columns",
        sqlx::query_as(
            "SELECT column_name, data_type, is_nullable, column_default
             FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(POSTGRES_REPLAY_TABLE)
        .fetch_all(pool),
    )
    .await?;
    for (name, data_type) in [
        ("replay_namespace", "bytea"),
        ("nonce", "text"),
        ("expires_at_unix_ms", "bigint"),
        ("first_consumed_at", "timestamp with time zone"),
    ] {
        if !columns
            .iter()
            .any(|column| column.0 == name && column.1 == data_type && column.2 == "NO")
        {
            return Err(PostgresReplayStoreError::SchemaContract(
                "required replay column is absent, nullable, or has the wrong type",
            ));
        }
    }
    if !columns.iter().any(|column| {
        column.0 == "first_consumed_at"
            && column
                .3
                .as_deref()
                .is_some_and(|default| default.contains("clock_timestamp()"))
    }) {
        return Err(PostgresReplayStoreError::SchemaContract(
            "first_consumed_at must use the database consumption timestamp default",
        ));
    }

    let constraints: Vec<(String, String, bool, String)> = timeout_sqlx(
        operation_timeout,
        "inspect replay table constraints",
        sqlx::query_as(
            "SELECT conname, contype::text, convalidated, pg_get_constraintdef(oid)
             FROM pg_constraint
             WHERE conrelid = 'public.nexus_recall_replay_nonces'::regclass",
        )
        .fetch_all(pool),
    )
    .await?;
    for (name, kind, definition_fragment) in [
        (
            "nexus_recall_replay_nonces_pkey",
            "p",
            "PRIMARY KEY (replay_namespace, nonce)",
        ),
        (
            "nexus_recall_replay_namespace_length",
            "c",
            "octet_length(replay_namespace) = 32",
        ),
        (
            "nexus_recall_replay_nonce_shape",
            "c",
            "octet_length(nonce) = 64",
        ),
        (
            "nexus_recall_replay_expiry_nonnegative",
            "c",
            "expires_at_unix_ms >= 0",
        ),
    ] {
        if !constraints.iter().any(|constraint| {
            constraint.0 == name
                && constraint.1 == kind
                && constraint.2
                && constraint.3.contains(definition_fragment)
        }) {
            return Err(PostgresReplayStoreError::SchemaContract(
                "required replay constraint is absent, malformed, or unvalidated",
            ));
        }
    }
    if !constraints.iter().any(|constraint| {
        constraint.0 == "nexus_recall_replay_nonce_shape" && constraint.3.contains("^[0-9a-f]{64}$")
    }) {
        return Err(PostgresReplayStoreError::SchemaContract(
            "replay nonce constraint does not enforce lowercase hexadecimal",
        ));
    }

    let expiry_index: Option<String> = timeout_sqlx(
        operation_timeout,
        "inspect replay cleanup index",
        sqlx::query_scalar(
            "SELECT indexdef
             FROM pg_indexes
             WHERE schemaname = 'public'
               AND tablename = 'nexus_recall_replay_nonces'
               AND indexname = 'nexus_recall_replay_expiry_idx'",
        )
        .fetch_optional(pool),
    )
    .await?;
    if !expiry_index.as_deref().is_some_and(|definition| {
        definition.contains("(expires_at_unix_ms, replay_namespace, nonce)")
    }) {
        return Err(PostgresReplayStoreError::SchemaContract(
            "required replay cleanup index is absent or malformed",
        ));
    }

    let privileges: bool = timeout_sqlx(
        operation_timeout,
        "inspect replay table privileges",
        sqlx::query_scalar(
            "SELECT has_table_privilege(
                        current_user,
                        'public.nexus_recall_replay_nonces',
                        'SELECT,INSERT,DELETE'
                    )",
        )
        .fetch_one(pool),
    )
    .await?;
    if !privileges {
        return Err(PostgresReplayStoreError::SchemaContract(
            "current database role lacks SELECT, INSERT, or DELETE",
        ));
    }

    let malformed_rows: bool = timeout_sqlx(
        operation_timeout,
        "validate stored replay rows",
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                 FROM public.nexus_recall_replay_nonces
                 WHERE octet_length(replay_namespace) <> 32
                    OR octet_length(nonce) <> 64
                    OR nonce !~ '^[0-9a-f]{64}$'
                    OR expires_at_unix_ms < 0
             )",
        )
        .fetch_one(pool),
    )
    .await?;
    if malformed_rows {
        return Err(PostgresReplayStoreError::SchemaContract(
            "replay table contains malformed stored values",
        ));
    }

    Ok(())
}
