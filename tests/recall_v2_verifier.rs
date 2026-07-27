#![cfg(feature = "aeon-memory")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aeon_nexus_bridge::v2::{
    recall_signed_payload_digest, RecallEnvelopeV2, RecallEnvelopeV2Payload,
};
use async_trait::async_trait;
use nexus::aeon::recall_v2::{
    Clock, ContextField, ExpectedRecallContext, RecallVerificationError, RecallVerificationPolicy,
    RecallVerifier, ReplayConsumeResult, ReplayNamespace, ReplayStore, ReplayStoreError,
    TrustedKey, TrustedKeyBundle,
};
use serde_json::Value;
use tokio::sync::Barrier;

const KEY_ID: &str = "test-key-0001";
const VECTOR_PUBLIC_KEY_HEX: &str =
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const QUERY: &str = "what did we decide about retries?";
const ISSUED_AT_MS: i64 = 1_760_000_000_000;
const EXPIRES_AT_MS: i64 = 1_760_000_030_000;
const MAX_FUTURE_SKEW_MS: i64 = 5_000;

fn envelope_json() -> &'static str {
    include_str!("../crates/aeon_nexus_bridge/vectors/recall_envelope_v2/envelope.json")
}

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

#[derive(Default)]
struct InMemoryReplayStore {
    entries: Mutex<HashMap<(ReplayNamespace, String), i64>>,
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn consume_once(
        &self,
        namespace: ReplayNamespace,
        nonce: &str,
        expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        let mut entries = self.entries.lock().expect("test replay mutex poisoned");
        let key = (namespace, nonce.to_owned());
        if entries.contains_key(&key) {
            return Ok(ReplayConsumeResult::Replayed);
        }
        entries.insert(key, expires_at_unix_ms);
        Ok(ReplayConsumeResult::Fresh)
    }
}

fn decode_public_key() -> [u8; 32] {
    let mut decoded = [0_u8; 32];
    for (index, pair) in VECTOR_PUBLIC_KEY_HEX.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    decoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture contains non-hex byte"),
    }
}

fn trusted_keys() -> TrustedKeyBundle {
    let key = TrustedKey::from_bytes(KEY_ID, decode_public_key()).expect("valid vector key");
    TrustedKeyBundle::new([key]).expect("non-empty trusted key bundle")
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

fn policy() -> RecallVerificationPolicy {
    RecallVerificationPolicy::new(MAX_FUTURE_SKEW_MS).expect("valid policy")
}

fn verifier(
    now_unix_ms: i64,
    replay_store: Arc<InMemoryReplayStore>,
) -> RecallVerifier<FixedClock, InMemoryReplayStore> {
    RecallVerifier::new(
        trusted_keys(),
        policy(),
        FixedClock(now_unix_ms),
        replay_store,
    )
}

fn mutate_envelope(mutator: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(envelope_json()).expect("vector JSON");
    mutator(&mut value);
    serde_json::to_string(&value).expect("mutated envelope serializes")
}

fn assert_context_mismatch(error: RecallVerificationError, field: ContextField) {
    assert!(
        matches!(
            error,
            RecallVerificationError::ContextMismatch { field: actual } if actual == field
        ),
        "expected context mismatch for {field:?}, got {error:?}"
    );
}

#[tokio::test]
async fn frozen_vector_verifies_with_explicitly_trusted_key() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );

    let verified = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("frozen vector must verify");

    assert_eq!(verified.envelope().signature.key_id, KEY_ID);
    assert_eq!(verified.verified_at_unix_ms(), ISSUED_AT_MS + 1_000);
}

#[tokio::test]
async fn bad_signature_is_rejected_without_consuming_nonce() {
    let store = Arc::new(InMemoryReplayStore::default());
    let verifier = verifier(ISSUED_AT_MS + 1_000, Arc::clone(&store));
    let bad = mutate_envelope(|value| {
        let signature = value["signature"]["signature"]
            .as_str()
            .expect("signature string");
        value["signature"]["signature"] = format!("0{}", &signature[1..]).into();
    });

    let error = verifier
        .verify_json(&bad, &expected_context())
        .await
        .expect_err("bad signature must fail");
    assert!(matches!(error, RecallVerificationError::InvalidSignature));

    verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("invalid signature must not burn the nonce");
}

#[tokio::test]
async fn unknown_key_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let unknown = mutate_envelope(|value| {
        value["signature"]["key_id"] = "untrusted-key".into();
    });

    let error = verifier
        .verify_json(&unknown, &expected_context())
        .await
        .expect_err("unknown key must fail");

    assert!(matches!(error, RecallVerificationError::UnknownSigningKey));
}

#[tokio::test]
async fn altered_payload_is_rejected_by_signature_after_digest_recomputation() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let altered = mutate_envelope(|value| {
        value["payload"]["hits"][0]["memory_id"] = "altered-memory".into();
        let parsed: RecallEnvelopeV2 = serde_json::from_value(value.clone())
            .expect("altered envelope remains structurally valid");
        value["signature"]["signed_payload_digest"] =
            serde_json::to_value(recall_signed_payload_digest(&parsed.payload).expect("digest"))
                .expect("digest serializes");
    });

    let error = verifier
        .verify_json(&altered, &expected_context())
        .await
        .expect_err("altered payload must fail signature verification");

    assert!(matches!(error, RecallVerificationError::InvalidSignature));
}

#[tokio::test]
async fn wrong_tenant_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.tenant_id = "tenant-wrong".to_owned();

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong tenant must fail");
    assert_context_mismatch(error, ContextField::TenantId);
}

#[tokio::test]
async fn wrong_workspace_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.workspace_id = Some("workspace-wrong".to_owned());

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong workspace must fail");
    assert_context_mismatch(error, ContextField::WorkspaceId);
}

#[tokio::test]
async fn wrong_agent_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.agent_id = "agent-wrong".to_owned();

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong agent must fail");
    assert_context_mismatch(error, ContextField::AgentId);
}

#[tokio::test]
async fn wrong_session_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.session_id = None;

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong session must fail");
    assert_context_mismatch(error, ContextField::SessionId);
}

#[tokio::test]
async fn wrong_mission_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.mission_id = Some("mission-wrong".to_owned());

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong mission must fail");
    assert_context_mismatch(error, ContextField::MissionId);
}

#[tokio::test]
async fn wrong_run_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.run_id = "00000000-0000-4000-8000-000000000001"
        .parse()
        .expect("canonical run id");

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong run must fail");
    assert_context_mismatch(error, ContextField::RunId);
}

#[tokio::test]
async fn wrong_request_id_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.request_id = "00000000-0000-4000-8000-000000000002"
        .parse()
        .expect("canonical request id");

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong request id must fail");
    assert_context_mismatch(error, ContextField::RequestId);
}

#[tokio::test]
async fn wrong_query_digest_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let mut expected = expected_context();
    expected.query = "what did we decide about timeouts?".to_owned();

    let error = verifier
        .verify_json(envelope_json(), &expected)
        .await
        .expect_err("wrong query must fail");
    assert_context_mismatch(error, ContextField::QueryDigest);
}

#[tokio::test]
async fn envelope_is_expired_at_exact_expiry_boundary() {
    let verifier = verifier(EXPIRES_AT_MS, Arc::new(InMemoryReplayStore::default()));

    let error = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect_err("now == expires_at must be expired");

    assert!(matches!(error, RecallVerificationError::Expired));
}

#[tokio::test]
async fn issued_too_far_in_the_future_is_rejected() {
    let now = ISSUED_AT_MS - MAX_FUTURE_SKEW_MS - 1;
    let verifier = verifier(now, Arc::new(InMemoryReplayStore::default()));

    let error = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect_err("issuance beyond configured skew must fail");

    assert!(matches!(
        error,
        RecallVerificationError::IssuedTooFarInFuture
    ));
}

#[tokio::test]
async fn exact_future_skew_boundary_is_accepted() {
    let now = ISSUED_AT_MS - MAX_FUTURE_SKEW_MS;
    let verifier = verifier(now, Arc::new(InMemoryReplayStore::default()));

    verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("issuance at exact skew boundary must pass");
}

#[tokio::test]
async fn unsupported_protocol_version_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let unsupported = mutate_envelope(|value| {
        value["payload"]["protocol_version"] = "aeon-recall-envelope-v999".into();
    });

    let error = verifier
        .verify_json(&unsupported, &expected_context())
        .await
        .expect_err("unsupported protocol must fail");

    assert!(matches!(
        error,
        RecallVerificationError::UnsupportedProtocolVersion
    ));
}

#[tokio::test]
async fn unsupported_canonicalization_version_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );
    let unsupported = mutate_envelope(|value| {
        value["payload"]["canonicalization_version"] = "aeon-canonical-json-v999".into();
    });

    let error = verifier
        .verify_json(&unsupported, &expected_context())
        .await
        .expect_err("unsupported canonicalization must fail");

    assert!(matches!(
        error,
        RecallVerificationError::UnsupportedCanonicalizationVersion
    ));
}

#[tokio::test]
async fn duplicate_nonce_is_rejected() {
    let verifier = verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    );

    verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("first consumption must be fresh");
    let error = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect_err("second consumption must be replayed");

    assert!(matches!(error, RecallVerificationError::Replayed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_duplicate_consumption_allows_exactly_one_success() {
    const ATTEMPTS: usize = 16;

    let verifier = Arc::new(verifier(
        ISSUED_AT_MS + 1_000,
        Arc::new(InMemoryReplayStore::default()),
    ));
    let barrier = Arc::new(Barrier::new(ATTEMPTS));
    let mut tasks = Vec::with_capacity(ATTEMPTS);

    for _ in 0..ATTEMPTS {
        let verifier = Arc::clone(&verifier);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            verifier
                .verify_json(envelope_json(), &expected_context())
                .await
        }));
    }

    let mut successes = 0;
    let mut replays = 0;
    for task in tasks {
        match task.await.expect("verification task must not panic") {
            Ok(_) => successes += 1,
            Err(RecallVerificationError::Replayed) => replays += 1,
            Err(error) => panic!("unexpected verification result: {error:?}"),
        }
    }

    assert_eq!(successes, 1);
    assert_eq!(replays, ATTEMPTS - 1);
}

#[test]
fn negative_future_skew_policy_is_rejected() {
    let error = RecallVerificationPolicy::new(-1).expect_err("negative skew must fail");
    assert_eq!(error.max_future_skew_ms(), -1);
}

#[test]
fn empty_trusted_key_bundle_is_rejected() {
    let error = TrustedKeyBundle::new([]).expect_err("empty bundle must fail");
    assert!(error.to_string().contains("at least one"));
}

#[test]
fn duplicate_trusted_key_id_is_rejected() {
    let first = TrustedKey::from_bytes(KEY_ID, decode_public_key()).expect("valid key");
    let second = TrustedKey::from_bytes(KEY_ID, decode_public_key()).expect("valid key");
    let error = TrustedKeyBundle::new([first, second]).expect_err("duplicate id must fail");
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn expected_context_uses_exact_query_bytes() {
    let expected = expected_context();
    let payload: RecallEnvelopeV2Payload = serde_json::from_str(include_str!(
        "../crates/aeon_nexus_bridge/vectors/recall_envelope_v2/payload.json"
    ))
    .expect("frozen payload");

    assert_eq!(
        aeon_nexus_bridge::v2::sha256_hex(expected.query.as_bytes()),
        payload.query_digest.value()
    );
}
