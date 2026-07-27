#![cfg(feature = "aeon-memory")]

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use nexus::aeon::recall_v2::{
    Clock, ContextField, ExpectedRecallContext, RecallVerificationError, RecallVerificationPolicy,
    RecallVerifier, ReplayConsumeResult, ReplayNamespace, ReplayStore, ReplayStoreError,
    TrustedKey, TrustedKeyBundle,
};
use sha2::{Digest, Sha256};

const KEY_ID: &str = "test-key-0001";
const VECTOR_PUBLIC_KEY: [u8; 32] = [
    0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
    0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12,
];
const QUERY: &str = "what did we decide about retries?";
const NOW_MS: i64 = 1_760_000_001_000;

fn envelope_json() -> &'static str {
    include_str!("../crates/aeon_nexus_bridge/vectors/recall_envelope_v2/envelope.json")
}

fn expected_context() -> ExpectedRecallContext {
    ExpectedRecallContext {
        tenant_id: "tenant-0001".to_owned(),
        workspace_id: None,
        agent_id: "agent-0001".to_owned(),
        session_id: Some("session-0001".to_owned()),
        mission_id: None,
        run_id: "9f1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"
            .parse()
            .expect("canonical run id"),
        request_id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
            .parse()
            .expect("canonical request id"),
        query: QUERY.to_owned(),
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        NOW_MS
    }
}

struct FreshStore;

#[async_trait]
impl ReplayStore for FreshStore {
    async fn consume_once(
        &self,
        _namespace: ReplayNamespace,
        _nonce: &str,
        _expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        Ok(ReplayConsumeResult::Fresh)
    }
}

#[derive(Debug)]
struct BackendUnavailable;

impl fmt::Display for BackendUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backend unavailable")
    }
}

impl Error for BackendUnavailable {}

struct FailingStore;

#[async_trait]
impl ReplayStore for FailingStore {
    async fn consume_once(
        &self,
        _namespace: ReplayNamespace,
        _nonce: &str,
        _expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        Err(ReplayStoreError::new(BackendUnavailable))
    }
}

fn trusted_key() -> TrustedKey {
    TrustedKey::from_bytes(KEY_ID, VECTOR_PUBLIC_KEY).expect("valid vector key")
}

fn policy() -> RecallVerificationPolicy {
    RecallVerificationPolicy::new(5_000).expect("valid policy")
}

#[tokio::test]
async fn verified_result_and_configuration_accessors_are_stable() {
    let key = trusted_key();
    assert_eq!(key.key_id(), KEY_ID);
    assert_eq!(
        key.public_key_fingerprint(),
        <[u8; 32]>::from(Sha256::digest(VECTOR_PUBLIC_KEY))
    );
    assert_eq!(policy().max_future_skew_ms(), 5_000);

    let verifier = RecallVerifier::new(
        TrustedKeyBundle::new([key]).expect("trusted bundle"),
        policy(),
        FixedClock,
        Arc::new(FreshStore),
    );
    let verified = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("vector verifies");

    assert_eq!(verified.verified_at_unix_ms(), NOW_MS);
    assert_eq!(verified.envelope().signature.key_id, KEY_ID);
    assert_ne!(verified.replay_namespace().as_bytes(), &[0_u8; 32]);
}

#[tokio::test]
async fn replay_store_errors_fail_closed_and_preserve_the_source() {
    let verifier = RecallVerifier::new(
        TrustedKeyBundle::new([trusted_key()]).expect("trusted bundle"),
        policy(),
        FixedClock,
        Arc::new(FailingStore),
    );

    let error = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect_err("backend failure must fail closed");

    assert_eq!(error.to_string(), "replay store failed");
    let RecallVerificationError::ReplayStore(store_error) = error else {
        panic!("expected replay store error");
    };
    assert_eq!(store_error.to_string(), "replay store operation failed");
    assert_eq!(
        store_error.source().expect("backend source").to_string(),
        "backend unavailable"
    );
}

#[test]
fn public_error_messages_are_non_sensitive_and_specific() {
    let fields = [
        (ContextField::TenantId, "tenant_id"),
        (ContextField::WorkspaceId, "workspace_id"),
        (ContextField::AgentId, "agent_id"),
        (ContextField::SessionId, "session_id"),
        (ContextField::MissionId, "mission_id"),
        (ContextField::RunId, "run_id"),
        (ContextField::RequestId, "request_id"),
        (ContextField::QueryDigest, "query_digest"),
    ];
    for (field, name) in fields {
        assert_eq!(field.to_string(), name);
        assert_eq!(
            RecallVerificationError::ContextMismatch { field }.to_string(),
            format!("recall context mismatch: {name}")
        );
    }

    assert!(RecallVerificationPolicy::new(-1)
        .expect_err("negative skew")
        .to_string()
        .contains("non-negative"));
    assert!(TrustedKey::from_bytes("", VECTOR_PUBLIC_KEY)
        .expect_err("empty key id")
        .to_string()
        .contains("must not be empty"));
}
