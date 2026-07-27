//! Pure verification for the frozen `RecallEnvelopeV2` contract.
//!
//! This module deliberately contains no HTTP client, runtime wiring, or
//! production replay-store selection. Runtime replay resistance is not active
//! merely because this verifier and its storage contract exist.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use aeon_nexus_bridge::v2::{
    recall_signing_bytes, CanonicalUuid, RecallDigestV2, RecallEnvelopeV2, RecallError,
    RECALL_CANONICALIZATION_VERSION, RECALL_PROTOCOL_VERSION, RECALL_SIGNATURE_ALGORITHM,
    RECALL_SIGNING_DOMAIN_LABEL,
};
use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const REPLAY_NAMESPACE_DOMAIN: &[u8] = b"NEXUS_RECALL_V2_REPLAY_NAMESPACE_V1\0";

/// Clock used for deterministic timestamp validation.
pub trait Clock: Send + Sync {
    fn now_unix_ms(&self) -> i64;
}

/// Context Nexus expected when it made the recall request.
///
/// The raw query is retained so the verifier can hash its exact UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRecallContext {
    pub tenant_id: String,
    pub workspace_id: Option<String>,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub mission_id: Option<String>,
    pub run_id: CanonicalUuid,
    pub request_id: CanonicalUuid,
    pub query: String,
}

/// Context component that did not match the signed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextField {
    TenantId,
    WorkspaceId,
    AgentId,
    SessionId,
    MissionId,
    RunId,
    RequestId,
    QueryDigest,
}

impl fmt::Display for ContextField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TenantId => "tenant_id",
            Self::WorkspaceId => "workspace_id",
            Self::AgentId => "agent_id",
            Self::SessionId => "session_id",
            Self::MissionId => "mission_id",
            Self::RunId => "run_id",
            Self::RequestId => "request_id",
            Self::QueryDigest => "query_digest",
        };
        formatter.write_str(name)
    }
}

/// Verification-time policy that is local to Nexus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecallVerificationPolicy {
    max_future_skew_ms: i64,
}

impl RecallVerificationPolicy {
    pub fn new(max_future_skew_ms: i64) -> Result<Self, RecallPolicyError> {
        if max_future_skew_ms < 0 {
            return Err(RecallPolicyError { max_future_skew_ms });
        }
        Ok(Self { max_future_skew_ms })
    }

    pub fn max_future_skew_ms(self) -> i64 {
        self.max_future_skew_ms
    }
}

/// Invalid verifier policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecallPolicyError {
    max_future_skew_ms: i64,
}

impl RecallPolicyError {
    pub fn max_future_skew_ms(self) -> i64 {
        self.max_future_skew_ms
    }
}

impl fmt::Display for RecallPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "maximum future skew must be non-negative, found {}",
            self.max_future_skew_ms
        )
    }
}

impl Error for RecallPolicyError {}

/// A public key trusted by local configuration, never by response discovery.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    key_id: String,
    verifying_key: VerifyingKey,
    fingerprint: [u8; 32],
}

impl TrustedKey {
    pub fn from_bytes(
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, TrustedKeyBundleError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(TrustedKeyBundleError::EmptyKeyId);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| TrustedKeyBundleError::InvalidPublicKey)?;
        let fingerprint = Sha256::digest(public_key).into();
        Ok(Self {
            key_id,
            verifying_key,
            fingerprint,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// Explicit immutable bundle of trusted signing keys.
#[derive(Debug, Clone)]
pub struct TrustedKeyBundle {
    keys: BTreeMap<String, TrustedKey>,
}

impl TrustedKeyBundle {
    pub fn new(keys: impl IntoIterator<Item = TrustedKey>) -> Result<Self, TrustedKeyBundleError> {
        let mut configured = BTreeMap::new();
        for key in keys {
            let key_id = key.key_id.clone();
            if configured.insert(key_id.clone(), key).is_some() {
                return Err(TrustedKeyBundleError::DuplicateKeyId(key_id));
            }
        }
        if configured.is_empty() {
            return Err(TrustedKeyBundleError::EmptyBundle);
        }
        Ok(Self { keys: configured })
    }

    fn get(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedKeyBundleError {
    EmptyKeyId,
    InvalidPublicKey,
    EmptyBundle,
    DuplicateKeyId(String),
}

impl fmt::Display for TrustedKeyBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKeyId => formatter.write_str("trusted key id must not be empty"),
            Self::InvalidPublicKey => formatter.write_str("invalid Ed25519 public key"),
            Self::EmptyBundle => {
                formatter.write_str("trusted key bundle must contain at least one key")
            }
            Self::DuplicateKeyId(key_id) => {
                write!(formatter, "duplicate trusted key id: {key_id}")
            }
        }
    }
}

impl Error for TrustedKeyBundleError {}

/// Opaque collision-resistant replay partition.
///
/// The namespace commits to frozen protocol metadata, tenant/workspace, and
/// the verified public-key fingerprint. It intentionally does not use the
/// unsigned key id, so aliases for one physical key cannot evade replay
/// detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayNamespace([u8; 32]);

impl ReplayNamespace {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayConsumeResult {
    Fresh,
    Replayed,
}

/// Storage-layer failure while consuming a nonce.
#[derive(Debug)]
pub struct ReplayStoreError {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl ReplayStoreError {
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("replay store operation failed")
    }
}

impl Error for ReplayStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Atomic replay-consumption boundary.
///
/// Implementations must atomically return `Fresh` only when `(namespace,
/// nonce)` has not already been consumed, retain it through
/// `expires_at_unix_ms`, and return `Replayed` otherwise. Errors fail closed.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    async fn consume_once(
        &self,
        replay_namespace: ReplayNamespace,
        nonce: &str,
        expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError>;
}

/// A successfully authenticated, context-bound, fresh recall envelope.
#[derive(Debug)]
pub struct VerifiedRecallEnvelope {
    envelope: RecallEnvelopeV2,
    verified_at_unix_ms: i64,
    replay_namespace: ReplayNamespace,
}

impl VerifiedRecallEnvelope {
    pub fn envelope(&self) -> &RecallEnvelopeV2 {
        &self.envelope
    }

    pub fn verified_at_unix_ms(&self) -> i64 {
        self.verified_at_unix_ms
    }

    pub fn replay_namespace(&self) -> ReplayNamespace {
        self.replay_namespace
    }
}

#[derive(Debug)]
pub enum RecallVerificationError {
    Parse(serde_json::Error),
    UnsupportedProtocolVersion,
    UnsupportedCanonicalizationVersion,
    InvalidEnvelope(RecallError),
    UnknownSigningKey,
    InvalidSignatureEncoding,
    InvalidSignature,
    ContextMismatch { field: ContextField },
    InvalidClock,
    Expired,
    IssuedTooFarInFuture,
    Replayed,
    ReplayStore(ReplayStoreError),
}

impl fmt::Display for RecallVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(_) => formatter.write_str("invalid RecallEnvelopeV2 JSON"),
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("unsupported recall protocol version")
            }
            Self::UnsupportedCanonicalizationVersion => {
                formatter.write_str("unsupported recall canonicalization version")
            }
            Self::InvalidEnvelope(_) => formatter.write_str("invalid RecallEnvelopeV2"),
            Self::UnknownSigningKey => formatter.write_str("unknown recall signing key"),
            Self::InvalidSignatureEncoding => {
                formatter.write_str("invalid Ed25519 signature encoding")
            }
            Self::InvalidSignature => formatter.write_str("invalid Ed25519 signature"),
            Self::ContextMismatch { field } => {
                write!(formatter, "recall context mismatch: {field}")
            }
            Self::InvalidClock => formatter.write_str("clock returned a negative Unix timestamp"),
            Self::Expired => formatter.write_str("recall envelope has expired"),
            Self::IssuedTooFarInFuture => {
                formatter.write_str("recall envelope was issued too far in the future")
            }
            Self::Replayed => formatter.write_str("recall nonce has already been consumed"),
            Self::ReplayStore(_) => formatter.write_str("replay store failed"),
        }
    }
}

impl Error for RecallVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::InvalidEnvelope(error) => Some(error),
            Self::ReplayStore(error) => Some(error),
            _ => None,
        }
    }
}

/// Pure verifier parameterized by trusted keys, clock, and replay store.
pub struct RecallVerifier<C, R> {
    trusted_keys: TrustedKeyBundle,
    policy: RecallVerificationPolicy,
    clock: C,
    replay_store: Arc<R>,
}

impl<C, R> RecallVerifier<C, R>
where
    C: Clock,
    R: ReplayStore,
{
    pub fn new(
        trusted_keys: TrustedKeyBundle,
        policy: RecallVerificationPolicy,
        clock: C,
        replay_store: Arc<R>,
    ) -> Self {
        Self {
            trusted_keys,
            policy,
            clock,
            replay_store,
        }
    }

    /// Strictly parse, authenticate, bind, time-check, and consume one envelope.
    pub async fn verify_json(
        &self,
        envelope_json: &str,
        expected: &ExpectedRecallContext,
    ) -> Result<VerifiedRecallEnvelope, RecallVerificationError> {
        let envelope: RecallEnvelopeV2 =
            serde_json::from_str(envelope_json).map_err(RecallVerificationError::Parse)?;
        validate_envelope(&envelope)?;

        let trusted_key = self
            .trusted_keys
            .get(&envelope.signature.key_id)
            .ok_or(RecallVerificationError::UnknownSigningKey)?;
        verify_signature(&envelope, trusted_key)?;
        verify_context(&envelope, expected)?;

        let now_unix_ms = self.clock.now_unix_ms();
        verify_time(&envelope, now_unix_ms, self.policy)?;

        let replay_namespace = derive_replay_namespace(&envelope, trusted_key);
        let consume_result = self
            .replay_store
            .consume_once(
                replay_namespace,
                &envelope.payload.nonce,
                envelope.payload.expires_at_unix_ms,
            )
            .await
            .map_err(RecallVerificationError::ReplayStore)?;
        if consume_result == ReplayConsumeResult::Replayed {
            return Err(RecallVerificationError::Replayed);
        }

        Ok(VerifiedRecallEnvelope {
            envelope,
            verified_at_unix_ms: now_unix_ms,
            replay_namespace,
        })
    }
}

fn validate_envelope(envelope: &RecallEnvelopeV2) -> Result<(), RecallVerificationError> {
    envelope.validate().map_err(|error| match error {
        RecallError::ProtocolVersion(_) => RecallVerificationError::UnsupportedProtocolVersion,
        RecallError::CanonicalizationVersion(_) => {
            RecallVerificationError::UnsupportedCanonicalizationVersion
        }
        other => RecallVerificationError::InvalidEnvelope(other),
    })
}

fn verify_signature(
    envelope: &RecallEnvelopeV2,
    trusted_key: &TrustedKey,
) -> Result<(), RecallVerificationError> {
    let signature_bytes = decode_signature(&envelope.signature.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let signing_bytes = recall_signing_bytes(&envelope.payload)
        .map_err(RecallVerificationError::InvalidEnvelope)?;
    trusted_key
        .verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| RecallVerificationError::InvalidSignature)
}

fn decode_signature(encoded: &str) -> Result<[u8; 64], RecallVerificationError> {
    let mut decoded = [0_u8; 64];
    if encoded.len() != decoded.len() * 2 {
        return Err(RecallVerificationError::InvalidSignatureEncoding);
    }
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn decode_nibble(byte: u8) -> Result<u8, RecallVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RecallVerificationError::InvalidSignatureEncoding),
    }
}

fn verify_context(
    envelope: &RecallEnvelopeV2,
    expected: &ExpectedRecallContext,
) -> Result<(), RecallVerificationError> {
    let payload = &envelope.payload;
    require_context(
        payload.tenant_id == expected.tenant_id,
        ContextField::TenantId,
    )?;
    require_context(
        payload.workspace_id.as_option().map(String::as_str) == expected.workspace_id.as_deref(),
        ContextField::WorkspaceId,
    )?;
    require_context(payload.agent_id == expected.agent_id, ContextField::AgentId)?;
    require_context(
        payload.session_id.as_option().map(String::as_str) == expected.session_id.as_deref(),
        ContextField::SessionId,
    )?;
    require_context(
        payload.mission_id.as_option().map(String::as_str) == expected.mission_id.as_deref(),
        ContextField::MissionId,
    )?;
    require_context(payload.run_id == expected.run_id, ContextField::RunId)?;
    require_context(
        payload.request_id == expected.request_id,
        ContextField::RequestId,
    )?;
    let expected_query_digest = RecallDigestV2::sha256(expected.query.as_bytes(), true);
    require_context(
        payload.query_digest == expected_query_digest,
        ContextField::QueryDigest,
    )
}

fn require_context(matches: bool, field: ContextField) -> Result<(), RecallVerificationError> {
    if matches {
        Ok(())
    } else {
        Err(RecallVerificationError::ContextMismatch { field })
    }
}

fn verify_time(
    envelope: &RecallEnvelopeV2,
    now_unix_ms: i64,
    policy: RecallVerificationPolicy,
) -> Result<(), RecallVerificationError> {
    if now_unix_ms < 0 {
        return Err(RecallVerificationError::InvalidClock);
    }
    if now_unix_ms >= envelope.payload.expires_at_unix_ms {
        return Err(RecallVerificationError::Expired);
    }
    let latest_acceptable_issue = now_unix_ms.saturating_add(policy.max_future_skew_ms());
    if envelope.payload.issued_at_unix_ms > latest_acceptable_issue {
        return Err(RecallVerificationError::IssuedTooFarInFuture);
    }
    Ok(())
}

fn derive_replay_namespace(
    envelope: &RecallEnvelopeV2,
    trusted_key: &TrustedKey,
) -> ReplayNamespace {
    let mut digest = Sha256::new();
    append_namespace_part(&mut digest, REPLAY_NAMESPACE_DOMAIN);
    append_namespace_part(&mut digest, RECALL_PROTOCOL_VERSION.as_bytes());
    append_namespace_part(&mut digest, RECALL_CANONICALIZATION_VERSION.as_bytes());
    append_namespace_part(&mut digest, RECALL_SIGNING_DOMAIN_LABEL.as_bytes());
    append_namespace_part(&mut digest, RECALL_SIGNATURE_ALGORITHM.as_bytes());
    append_namespace_part(&mut digest, &trusted_key.fingerprint);
    append_namespace_part(&mut digest, envelope.payload.tenant_id.as_bytes());
    append_optional_namespace_part(
        &mut digest,
        envelope
            .payload
            .workspace_id
            .as_option()
            .map(String::as_bytes),
    );
    ReplayNamespace(digest.finalize().into())
}

fn append_namespace_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn append_optional_namespace_part(digest: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            digest.update([1]);
            append_namespace_part(digest, value);
        }
        None => digest.update([0]),
    }
}
