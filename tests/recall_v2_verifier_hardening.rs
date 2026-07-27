#![cfg(feature = "aeon-memory")]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use aeon_nexus_bridge::v2::{
    recall_signed_payload_digest, recall_signing_bytes, to_lowercase_hex, RecallEnvelopeV2,
    RecallEnvelopeV2Payload, RecallError, RECALL_MAX_TTL_MS,
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use nexus::aeon::recall_v2::{
    Clock, ExpectedRecallContext, RecallVerificationError, RecallVerificationPolicy,
    RecallVerifier, ReplayConsumeResult, ReplayNamespace, ReplayStore, ReplayStoreError,
    TrustedKey, TrustedKeyBundle,
};
use serde_json::Value;

const KEY_ID: &str = "test-key-0001";
const VECTOR_PUBLIC_KEY: [u8; 32] = [
    0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
    0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12,
];
const QUERY: &str = "what did we decide about retries?";
const ISSUED_AT_MS: i64 = 1_760_000_000_000;

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
    entries: Mutex<HashSet<(ReplayNamespace, String)>>,
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn consume_once(
        &self,
        namespace: ReplayNamespace,
        nonce: &str,
        _expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        let mut entries = self.entries.lock().expect("test replay mutex poisoned");
        if entries.insert((namespace, nonce.to_owned())) {
            Ok(ReplayConsumeResult::Fresh)
        } else {
            Ok(ReplayConsumeResult::Replayed)
        }
    }
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
    RecallVerificationPolicy::new(5_000).expect("valid policy")
}

fn vector_key(key_id: &str) -> TrustedKey {
    TrustedKey::from_bytes(key_id, VECTOR_PUBLIC_KEY).expect("valid vector key")
}

fn verifier_with_keys(
    keys: impl IntoIterator<Item = TrustedKey>,
) -> RecallVerifier<FixedClock, InMemoryReplayStore> {
    RecallVerifier::new(
        TrustedKeyBundle::new(keys).expect("valid trusted key bundle"),
        policy(),
        FixedClock(ISSUED_AT_MS + 1_000),
        Arc::new(InMemoryReplayStore::default()),
    )
}

fn mutate_envelope(mutator: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(envelope_json()).expect("vector JSON");
    mutator(&mut value);
    serde_json::to_string(&value).expect("mutated envelope serializes")
}

fn resign_envelope(
    key_id: &str,
    signing_seed: [u8; 32],
    mutate_payload: impl FnOnce(&mut RecallEnvelopeV2Payload),
) -> String {
    let mut envelope: RecallEnvelopeV2 =
        serde_json::from_str(envelope_json()).expect("vector envelope");
    mutate_payload(&mut envelope.payload);
    envelope.signature.key_id = key_id.to_owned();
    envelope.signature.signed_payload_digest =
        recall_signed_payload_digest(&envelope.payload).expect("payload digest");

    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signing_bytes = recall_signing_bytes(&envelope.payload).expect("signing bytes");
    envelope.signature.signature = to_lowercase_hex(&signing_key.sign(&signing_bytes).to_bytes());

    serde_json::to_string(&envelope).expect("re-signed envelope serializes")
}

#[tokio::test]
async fn unknown_wire_field_is_strictly_rejected() {
    let verifier = verifier_with_keys([vector_key(KEY_ID)]);
    let unknown_field = mutate_envelope(|value| {
        value["unexpected"] = true.into();
    });

    let error = verifier
        .verify_json(&unknown_field, &expected_context())
        .await
        .expect_err("unknown envelope member must fail");

    assert!(matches!(error, RecallVerificationError::Parse(_)));
}

#[tokio::test]
async fn protocol_maximum_validity_window_is_enforced() {
    let verifier = verifier_with_keys([vector_key(KEY_ID)]);
    let too_long = mutate_envelope(|value| {
        value["payload"]["expires_at_unix_ms"] = (ISSUED_AT_MS + RECALL_MAX_TTL_MS + 1).into();
    });

    let error = verifier
        .verify_json(&too_long, &expected_context())
        .await
        .expect_err("overlong validity window must fail");

    assert!(matches!(
        error,
        RecallVerificationError::InvalidEnvelope(RecallError::TtlTooLong { .. })
    ));
}

#[tokio::test]
async fn negative_clock_value_fails_closed() {
    let verifier = RecallVerifier::new(
        TrustedKeyBundle::new([vector_key(KEY_ID)]).expect("valid key bundle"),
        policy(),
        FixedClock(-1),
        Arc::new(InMemoryReplayStore::default()),
    );

    let error = verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect_err("negative Unix clock must fail");

    assert!(matches!(error, RecallVerificationError::InvalidClock));
}

#[tokio::test]
async fn aliases_for_same_physical_key_share_replay_namespace() {
    let verifier = verifier_with_keys([vector_key("alias-a"), vector_key("alias-b")]);
    let envelope_a = mutate_envelope(|value| {
        value["signature"]["key_id"] = "alias-a".into();
    });
    let envelope_b = mutate_envelope(|value| {
        value["signature"]["key_id"] = "alias-b".into();
    });

    verifier
        .verify_json(&envelope_a, &expected_context())
        .await
        .expect("first key alias must be fresh");
    let error = verifier
        .verify_json(&envelope_b, &expected_context())
        .await
        .expect_err("unsigned key-id alias must not bypass replay detection");

    assert!(matches!(error, RecallVerificationError::Replayed));
}

#[tokio::test]
async fn different_signers_have_distinct_replay_namespaces() {
    let second_seed = [0x24; 32];
    let second_signing_key = SigningKey::from_bytes(&second_seed);
    let second_key =
        TrustedKey::from_bytes("second-key", second_signing_key.verifying_key().to_bytes())
            .expect("valid second key");
    let verifier = verifier_with_keys([vector_key(KEY_ID), second_key]);

    verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("vector signer must be fresh");
    let second_envelope = resign_envelope("second-key", second_seed, |_| {});
    verifier
        .verify_json(&second_envelope, &expected_context())
        .await
        .expect("same nonce under a different signer namespace must be fresh");
}

#[tokio::test]
async fn tenants_have_distinct_replay_namespaces() {
    let verifier = verifier_with_keys([vector_key(KEY_ID)]);
    verifier
        .verify_json(envelope_json(), &expected_context())
        .await
        .expect("first tenant must be fresh");

    let second_envelope = resign_envelope(KEY_ID, [0x42; 32], |payload| {
        payload.tenant_id = "tenant-0002".to_owned();
    });
    let mut second_context = expected_context();
    second_context.tenant_id = "tenant-0002".to_owned();

    verifier
        .verify_json(&second_envelope, &second_context)
        .await
        .expect("same nonce under a different tenant namespace must be fresh");
}
