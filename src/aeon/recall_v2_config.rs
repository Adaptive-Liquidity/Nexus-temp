//! Production component configuration for RecallEnvelopeV2 verification.
//!
//! This module constructs pinned AEON trust roots and a schema-validated
//! PostgreSQL replay store. It deliberately does not call AEON, wire the
//! verifier into a recall path, consume context-assertion replays, or make any
//! runtime replay-resistance claim.

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::recall_v2::{TrustedKey, TrustedKeyBundle, TrustedKeyBundleError};
use super::recall_v2_postgres::{PostgresReplayStore, PostgresReplayStoreError};

pub const RECALL_V2_MODE_ENV: &str = "NEXUS_RECALL_V2_MODE";
pub const RECALL_V2_TRUSTED_KEYS_ENV: &str = "NEXUS_RECALL_V2_TRUSTED_KEYS";
pub const RECALL_V2_REPLAY_DATABASE_URL_ENV: &str = "NEXUS_RECALL_V2_REPLAY_DATABASE_URL";
pub const RECALL_V2_POOL_MAX_CONNECTIONS_ENV: &str = "NEXUS_RECALL_V2_POOL_MAX_CONNECTIONS";
pub const RECALL_V2_CONNECT_TIMEOUT_MS_ENV: &str = "NEXUS_RECALL_V2_CONNECT_TIMEOUT_MS";
pub const RECALL_V2_OPERATION_TIMEOUT_MS_ENV: &str = "NEXUS_RECALL_V2_OPERATION_TIMEOUT_MS";

const TRUSTED_KEY_DOCUMENT_VERSION: u32 = 1;
const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 8;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_OPERATION_TIMEOUT_MS: u64 = 5_000;

/// Explicit runtime selection for the V2 verifier components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallV2RuntimeMode {
    Disabled,
    Enforced,
}

/// Raw configuration values before validation.
///
/// Keeping this separate from environment access makes startup policy tests
/// deterministic and prevents tests from racing on process-global variables.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RecallV2ConfigValues {
    pub mode: Option<String>,
    pub trusted_keys_json: Option<String>,
    pub replay_database_url: Option<String>,
    pub pool_max_connections: Option<String>,
    pub connect_timeout_ms: Option<String>,
    pub operation_timeout_ms: Option<String>,
}

impl RecallV2ConfigValues {
    /// Read the production component variables without interpreting them.
    pub fn from_env() -> Result<Self, RecallV2ComponentConfigError> {
        Ok(Self {
            mode: read_optional_env(RECALL_V2_MODE_ENV)?,
            trusted_keys_json: read_optional_env(RECALL_V2_TRUSTED_KEYS_ENV)?,
            replay_database_url: read_optional_env(RECALL_V2_REPLAY_DATABASE_URL_ENV)?,
            pool_max_connections: read_optional_env(RECALL_V2_POOL_MAX_CONNECTIONS_ENV)?,
            connect_timeout_ms: read_optional_env(RECALL_V2_CONNECT_TIMEOUT_MS_ENV)?,
            operation_timeout_ms: read_optional_env(RECALL_V2_OPERATION_TIMEOUT_MS_ENV)?,
        })
    }
}

impl fmt::Debug for RecallV2ConfigValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecallV2ConfigValues")
            .field("mode", &self.mode)
            .field(
                "trusted_keys_json",
                &self.trusted_keys_json.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "replay_database_url",
                &self.replay_database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("pool_max_connections", &self.pool_max_connections)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("operation_timeout_ms", &self.operation_timeout_ms)
            .finish()
    }
}

/// Validated component configuration.
#[derive(Clone)]
pub enum RecallV2ComponentConfig {
    Disabled,
    Enforced(EnforcedRecallV2ComponentConfig),
}

impl RecallV2ComponentConfig {
    pub fn from_env() -> Result<Self, RecallV2ComponentConfigError> {
        Self::from_values(RecallV2ConfigValues::from_env()?)
    }

    pub fn from_values(values: RecallV2ConfigValues) -> Result<Self, RecallV2ComponentConfigError> {
        let mode = parse_runtime_mode(values.mode.as_deref())?;
        if mode == RecallV2RuntimeMode::Disabled {
            return Ok(Self::Disabled);
        }

        let trusted_keys_json = require_nonempty(
            values.trusted_keys_json,
            RecallV2ComponentConfigError::MissingTrustedKeys,
        )?;
        let trusted_key_provider = PinnedTrustedAeonKeyProvider::from_json(&trusted_keys_json)?;

        let replay_database_url = require_nonempty(
            values.replay_database_url,
            RecallV2ComponentConfigError::MissingReplayDatabaseUrl,
        )?;
        let pool_max_connections = parse_nonzero_u32(
            values.pool_max_connections.as_deref(),
            DEFAULT_POOL_MAX_CONNECTIONS,
            RecallV2ComponentConfigError::InvalidPoolMaxConnections,
        )?;
        let connect_timeout = Duration::from_millis(parse_nonzero_u64(
            values.connect_timeout_ms.as_deref(),
            DEFAULT_CONNECT_TIMEOUT_MS,
            RecallV2ComponentConfigError::InvalidConnectTimeout,
        )?);
        let operation_timeout = Duration::from_millis(parse_nonzero_u64(
            values.operation_timeout_ms.as_deref(),
            DEFAULT_OPERATION_TIMEOUT_MS,
            RecallV2ComponentConfigError::InvalidOperationTimeout,
        )?);

        Ok(Self::Enforced(EnforcedRecallV2ComponentConfig {
            trusted_key_provider,
            replay_database_url: ReplayDatabaseUrl(replay_database_url),
            pool_max_connections,
            connect_timeout,
            operation_timeout,
        }))
    }

    pub fn mode(&self) -> RecallV2RuntimeMode {
        match self {
            Self::Disabled => RecallV2RuntimeMode::Disabled,
            Self::Enforced(_) => RecallV2RuntimeMode::Enforced,
        }
    }

    pub fn enforced(&self) -> Option<&EnforcedRecallV2ComponentConfig> {
        match self {
            Self::Disabled => None,
            Self::Enforced(config) => Some(config),
        }
    }
}

impl fmt::Debug for RecallV2ComponentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("RecallV2ComponentConfig::Disabled"),
            Self::Enforced(config) => formatter
                .debug_tuple("RecallV2ComponentConfig::Enforced")
                .field(config)
                .finish(),
        }
    }
}

/// Validated enforced-mode settings.
#[derive(Clone)]
pub struct EnforcedRecallV2ComponentConfig {
    trusted_key_provider: PinnedTrustedAeonKeyProvider,
    replay_database_url: ReplayDatabaseUrl,
    pool_max_connections: u32,
    connect_timeout: Duration,
    operation_timeout: Duration,
}

impl EnforcedRecallV2ComponentConfig {
    pub fn trusted_key_provider(&self) -> &PinnedTrustedAeonKeyProvider {
        &self.trusted_key_provider
    }

    pub fn pool_max_connections(&self) -> u32 {
        self.pool_max_connections
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

impl fmt::Debug for EnforcedRecallV2ComponentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnforcedRecallV2ComponentConfig")
            .field("trusted_key_provider", &self.trusted_key_provider)
            .field("replay_database_url", &self.replay_database_url)
            .field("pool_max_connections", &self.pool_max_connections)
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ReplayDatabaseUrl(String);

impl fmt::Debug for ReplayDatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Lifecycle state for a pinned AEON verification key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedAeonKeyState {
    Active,
    Retired,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedAeonKeyDocument {
    version: u32,
    keys: Vec<PinnedAeonKeyRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedAeonKeyRecord {
    key_id: String,
    public_key_hex: String,
    state: PinnedAeonKeyState,
}

/// Provider that trusts only keys present in an operator-supplied pinned
/// document. No response or network discovery source exists in this type.
#[derive(Clone)]
pub struct PinnedTrustedAeonKeyProvider {
    trusted_keys: TrustedAeonKeySet,
}

impl PinnedTrustedAeonKeyProvider {
    pub fn from_json(document: &str) -> Result<Self, TrustedAeonKeyProviderError> {
        let document: PinnedAeonKeyDocument = serde_json::from_str(document)
            .map_err(|_| TrustedAeonKeyProviderError::InvalidDocument)?;
        if document.version != TRUSTED_KEY_DOCUMENT_VERSION {
            return Err(TrustedAeonKeyProviderError::UnsupportedDocumentVersion(
                document.version,
            ));
        }
        if document.keys.is_empty() {
            return Err(TrustedAeonKeyProviderError::EmptyBundle);
        }

        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let mut active_key_ids = Vec::new();
        let mut retired_key_ids = Vec::new();
        let mut keys = Vec::with_capacity(document.keys.len());

        for record in document.keys {
            if record.key_id.is_empty() {
                return Err(TrustedAeonKeyProviderError::EmptyKeyId);
            }
            if !key_ids.insert(record.key_id.clone()) {
                return Err(TrustedAeonKeyProviderError::DuplicateKeyId(record.key_id));
            }
            let public_key = decode_public_key(&record.key_id, &record.public_key_hex)?;
            if !public_keys.insert(public_key) {
                return Err(TrustedAeonKeyProviderError::DuplicatePublicKey);
            }
            let trusted_key = TrustedKey::from_bytes(record.key_id.clone(), public_key)
                .map_err(|error| map_trusted_key_error(record.key_id.clone(), error))?;
            match record.state {
                PinnedAeonKeyState::Active => active_key_ids.push(record.key_id),
                PinnedAeonKeyState::Retired => retired_key_ids.push(record.key_id),
            }
            keys.push(trusted_key);
        }

        if active_key_ids.is_empty() {
            return Err(TrustedAeonKeyProviderError::MissingActiveKey);
        }
        active_key_ids.sort();
        retired_key_ids.sort();
        let bundle = TrustedKeyBundle::new(keys)
            .map_err(|error| map_trusted_key_error(String::new(), error))?;

        Ok(Self {
            trusted_keys: TrustedAeonKeySet {
                bundle,
                active_key_ids,
                retired_key_ids,
            },
        })
    }
}

impl fmt::Debug for PinnedTrustedAeonKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedTrustedAeonKeyProvider")
            .field("active_key_ids", &self.trusted_keys.active_key_ids)
            .field("retired_key_ids", &self.trusted_keys.retired_key_ids)
            .finish()
    }
}

/// Trusted-key provider boundary used by production component construction.
pub trait TrustedAeonKeyProvider: Send + Sync {
    fn load(&self) -> Result<TrustedAeonKeySet, TrustedAeonKeyProviderError>;
}

impl TrustedAeonKeyProvider for PinnedTrustedAeonKeyProvider {
    fn load(&self) -> Result<TrustedAeonKeySet, TrustedAeonKeyProviderError> {
        Ok(self.trusted_keys.clone())
    }
}

/// Immutable trusted verification keys plus their rotation-overlap state.
#[derive(Debug, Clone)]
pub struct TrustedAeonKeySet {
    bundle: TrustedKeyBundle,
    active_key_ids: Vec<String>,
    retired_key_ids: Vec<String>,
}

impl TrustedAeonKeySet {
    pub fn trusted_key_bundle(&self) -> &TrustedKeyBundle {
        &self.bundle
    }

    pub fn into_trusted_key_bundle(self) -> TrustedKeyBundle {
        self.bundle
    }

    pub fn active_key_ids(&self) -> &[String] {
        &self.active_key_ids
    }

    pub fn retired_key_ids(&self) -> &[String] {
        &self.retired_key_ids
    }

    pub fn len(&self) -> usize {
        self.active_key_ids.len() + self.retired_key_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_key(&self, key_id: &str) -> bool {
        self.active_key_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(key_id))
            .is_ok()
            || self
                .retired_key_ids
                .binary_search_by(|candidate| candidate.as_str().cmp(key_id))
                .is_ok()
    }
}

/// Constructed production components. Enforced mode has no in-memory variant.
pub enum RecallV2Components {
    Disabled,
    Enforced(EnforcedRecallV2Components),
}

/// Pinned trust roots and the only allowed production replay backend.
pub struct EnforcedRecallV2Components {
    trusted_keys: TrustedAeonKeySet,
    replay_store: Arc<PostgresReplayStore>,
}

impl EnforcedRecallV2Components {
    pub fn trusted_keys(&self) -> &TrustedAeonKeySet {
        &self.trusted_keys
    }

    pub fn replay_store(&self) -> &Arc<PostgresReplayStore> {
        &self.replay_store
    }
}

/// Construct components from already-validated configuration.
///
/// PostgreSQL migrations are never applied here. A missing or incompatible
/// schema is a startup error, and enforced mode never degrades to memory.
pub async fn construct_recall_v2_components(
    config: RecallV2ComponentConfig,
) -> Result<RecallV2Components, RecallV2StartupError> {
    let RecallV2ComponentConfig::Enforced(config) = config else {
        return Ok(RecallV2Components::Disabled);
    };

    let trusted_keys = config.trusted_key_provider.load()?;
    let connect_options = PgConnectOptions::from_str(&config.replay_database_url.0)
        .map_err(|_| RecallV2StartupError::InvalidReplayDatabaseUrl)?;
    let connect = PgPoolOptions::new()
        .max_connections(config.pool_max_connections)
        .acquire_timeout(config.connect_timeout)
        .connect_with(connect_options);
    let pool = tokio::time::timeout(config.connect_timeout, connect)
        .await
        .map_err(|_| RecallV2StartupError::ReplayDatabaseConnectTimedOut)?
        .map_err(RecallV2StartupError::ReplayDatabaseUnavailable)?;
    let replay_store = PostgresReplayStore::new(pool, config.operation_timeout).await?;

    Ok(RecallV2Components::Enforced(EnforcedRecallV2Components {
        trusted_keys,
        replay_store: Arc::new(replay_store),
    }))
}

/// Parse and construct from deterministic raw values.
pub async fn construct_recall_v2_components_from_values(
    values: RecallV2ConfigValues,
) -> Result<RecallV2Components, RecallV2StartupError> {
    construct_recall_v2_components(RecallV2ComponentConfig::from_values(values)?).await
}

/// Parse and construct from the production environment.
///
/// This function is intentionally not called by any runtime path in this PR.
pub async fn construct_recall_v2_components_from_env(
) -> Result<RecallV2Components, RecallV2StartupError> {
    construct_recall_v2_components(RecallV2ComponentConfig::from_env()?).await
}

#[derive(Debug, thiserror::Error)]
pub enum RecallV2ComponentConfigError {
    #[error("environment variable {0} is not valid Unicode")]
    NonUnicodeEnvironment(&'static str),
    #[error("NEXUS_RECALL_V2_MODE must be exactly 'disabled' or 'enforced'")]
    InvalidMode,
    #[error("enforced Recall V2 mode requires an explicit trusted-key document")]
    MissingTrustedKeys,
    #[error("invalid pinned AEON trusted-key configuration")]
    TrustedKeys(#[from] TrustedAeonKeyProviderError),
    #[error("enforced Recall V2 mode requires a PostgreSQL replay database URL")]
    MissingReplayDatabaseUrl,
    #[error("Recall V2 pool max connections must be a non-zero decimal integer")]
    InvalidPoolMaxConnections,
    #[error("Recall V2 database connect timeout must be a non-zero decimal millisecond value")]
    InvalidConnectTimeout,
    #[error("Recall V2 replay operation timeout must be a non-zero decimal millisecond value")]
    InvalidOperationTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustedAeonKeyProviderError {
    #[error("pinned AEON trusted-key document is invalid or contains unknown fields")]
    InvalidDocument,
    #[error("unsupported pinned AEON trusted-key document version {0}")]
    UnsupportedDocumentVersion(u32),
    #[error("pinned AEON trusted-key document must contain at least one key")]
    EmptyBundle,
    #[error("pinned AEON key id must not be empty")]
    EmptyKeyId,
    #[error("pinned AEON key id is duplicated")]
    DuplicateKeyId(String),
    #[error("one Ed25519 public key must not be configured under multiple key ids")]
    DuplicatePublicKey,
    #[error("pinned AEON public key must be exactly 64 lowercase hexadecimal characters")]
    InvalidPublicKeyHex { key_id: String },
    #[error("pinned AEON public key is not a valid Ed25519 verification key")]
    InvalidPublicKey { key_id: String },
    #[error("pinned AEON trust roots must include at least one active key")]
    MissingActiveKey,
}

#[derive(Debug, thiserror::Error)]
pub enum RecallV2StartupError {
    #[error("Recall V2 component configuration is invalid")]
    Config(#[from] RecallV2ComponentConfigError),
    #[error("pinned AEON trusted keys are unavailable")]
    TrustedKeys(#[from] TrustedAeonKeyProviderError),
    #[error("Recall V2 replay database URL is invalid")]
    InvalidReplayDatabaseUrl,
    #[error("Recall V2 replay database connection timed out")]
    ReplayDatabaseConnectTimedOut,
    #[error("Recall V2 replay database is unavailable")]
    ReplayDatabaseUnavailable(#[source] sqlx::Error),
    #[error("Recall V2 PostgreSQL replay store failed startup validation")]
    ReplayStore(#[from] PostgresReplayStoreError),
}

fn read_optional_env(name: &'static str) -> Result<Option<String>, RecallV2ComponentConfigError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(RecallV2ComponentConfigError::NonUnicodeEnvironment(name))
        }
    }
}

fn parse_runtime_mode(
    value: Option<&str>,
) -> Result<RecallV2RuntimeMode, RecallV2ComponentConfigError> {
    match value {
        None | Some("disabled") => Ok(RecallV2RuntimeMode::Disabled),
        Some("enforced") => Ok(RecallV2RuntimeMode::Enforced),
        Some(_) => Err(RecallV2ComponentConfigError::InvalidMode),
    }
}

fn require_nonempty<T>(value: Option<String>, error: T) -> Result<String, T> {
    match value {
        Some(value) if !value.is_empty() && value.trim() == value => Ok(value),
        _ => Err(error),
    }
}

fn parse_nonzero_u32(
    value: Option<&str>,
    default: u32,
    error: RecallV2ComponentConfigError,
) -> Result<u32, RecallV2ComponentConfigError> {
    match value {
        None => Ok(default),
        Some(value) if is_decimal(value) => value
            .parse::<u32>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or(error),
        Some(_) => Err(error),
    }
}

fn parse_nonzero_u64(
    value: Option<&str>,
    default: u64,
    error: RecallV2ComponentConfigError,
) -> Result<u64, RecallV2ComponentConfigError> {
    match value {
        None => Ok(default),
        Some(value) if is_decimal(value) => value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or(error),
        Some(_) => Err(error),
    }
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn decode_public_key(key_id: &str, encoded: &str) -> Result<[u8; 32], TrustedAeonKeyProviderError> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustedAeonKeyProviderError::InvalidPublicKeyHex {
            key_id: key_id.to_owned(),
        });
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    Ok(decoded)
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("public key hexadecimal was validated before decoding"),
    }
}

fn map_trusted_key_error(
    key_id: String,
    error: TrustedKeyBundleError,
) -> TrustedAeonKeyProviderError {
    match error {
        TrustedKeyBundleError::EmptyKeyId => TrustedAeonKeyProviderError::EmptyKeyId,
        TrustedKeyBundleError::InvalidPublicKey => {
            TrustedAeonKeyProviderError::InvalidPublicKey { key_id }
        }
        TrustedKeyBundleError::EmptyBundle => TrustedAeonKeyProviderError::EmptyBundle,
        TrustedKeyBundleError::DuplicateKeyId(key_id) => {
            TrustedAeonKeyProviderError::DuplicateKeyId(key_id)
        }
    }
}
