#![cfg(feature = "aeon-replay-postgres")]

use std::sync::Arc;

use aeon_nexus_bridge::v2::{
    recall_signed_payload_digest, recall_signing_bytes, to_lowercase_hex, RecallEnvelopeV2,
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use nexus::aeon::recall_v2::{
    Clock, ExpectedRecallContext, RecallVerificationError, RecallVerificationPolicy,
    RecallVerifier, ReplayConsumeResult, ReplayNamespace, ReplayStore, ReplayStoreError,
};
use nexus::aeon::recall_v2_config::{PinnedTrustedAeonKeyProvider, TrustedAeonKeyProvider};
use serde_json::json;
use sha2::{Digest, Sha256};

const ISSUED_AT_MS: i64 = 1_760_000_000_000;
const CANONICAL_KEY_ID_PREFIX: &str = "ed25519-sha256:";

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

struct AlwaysFreshStore;

#[async_trait]
impl ReplayStore for AlwaysFreshStore {
    async fn consume_once(
        &self,
        _namespace: ReplayNamespace,
        _nonce: &str,
        _expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        Ok(ReplayConsumeResult::Fresh)
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(seed: u8) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

fn canonical_key_id(public_key: &[u8; 32]) -> String {
    let fingerprint: [u8; 32] = Sha256::digest(public_key).into();
    format!(
        "{CANONICAL_KEY_ID_PREFIX}{}",
        to_lowercase_hex(&fingerprint)
    )
}

fn key_record(seed: u8, state: &str) -> serde_json::Value {
    let public_key = public_key(seed);
    json!({
        "key_id": canonical_key_id(&public_key),
        "public_key_hex": to_lowercase_hex(&public_key),
        "state": state
    })
}

fn key_document(keys: Vec<serde_json::Value>) -> String {
    json!({"version": 1, "keys": keys}).to_string()
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
        query: "what did we decide about retries?".to_owned(),
    }
}

fn signed_vector_envelope(signing_key: &SigningKey, key_id: &str) -> String {
    let vector_json =
        include_str!("../crates/aeon_nexus_bridge/vectors/recall_envelope_v2/envelope.json");
    let mut envelope: RecallEnvelopeV2 =
        serde_json::from_str(vector_json).expect("vector envelope");
    envelope.signature.key_id = key_id.to_owned();
    envelope.signature.signed_payload_digest =
        recall_signed_payload_digest(&envelope.payload).expect("payload digest");
    let signing_bytes = recall_signing_bytes(&envelope.payload).expect("canonical signing bytes");
    envelope.signature.signature = to_lowercase_hex(&signing_key.sign(&signing_bytes).to_bytes());
    serde_json::to_string(&envelope).expect("signed envelope JSON")
}

fn verifier(document: &str) -> RecallVerifier<FixedClock, AlwaysFreshStore> {
    let trusted_keys = PinnedTrustedAeonKeyProvider::from_json(document)
        .expect("valid pinned trust roots")
        .load()
        .expect("pinned provider loads")
        .into_trusted_key_bundle();
    RecallVerifier::new(
        trusted_keys,
        RecallVerificationPolicy::new(5_000).expect("valid policy"),
        FixedClock(ISSUED_AT_MS + 1_000),
        Arc::new(AlwaysFreshStore),
    )
}

#[test]
fn canonical_key_id_is_accepted() {
    let public_key = public_key(0x51);
    let key_id = canonical_key_id(&public_key);
    let provider =
        PinnedTrustedAeonKeyProvider::from_json(&key_document(vec![key_record(0x51, "active")]))
            .expect("canonical key id is accepted");
    let trusted = provider.load().expect("provider loads");

    assert_eq!(trusted.active_key_ids(), &[key_id]);
}

#[test]
fn arbitrary_operator_alias_is_rejected() {
    let public_key = public_key(0x52);
    let document = key_document(vec![json!({
        "key_id": "aeon-primary",
        "public_key_hex": to_lowercase_hex(&public_key),
        "state": "active"
    })]);

    assert!(
        PinnedTrustedAeonKeyProvider::from_json(&document).is_err(),
        "operator aliases must not become trust roots"
    );
}

#[test]
fn fingerprint_for_a_different_public_key_is_rejected() {
    let supplied_key_id = canonical_key_id(&public_key(0x53));
    let different_public_key = public_key(0x54);
    let document = key_document(vec![json!({
        "key_id": supplied_key_id,
        "public_key_hex": to_lowercase_hex(&different_public_key),
        "state": "active"
    })]);

    assert!(
        PinnedTrustedAeonKeyProvider::from_json(&document).is_err(),
        "a key id must commit to the configured public key"
    );
}

#[test]
fn changing_public_key_without_changing_key_id_is_rejected() {
    let original_public_key = public_key(0x55);
    let mut record = key_record(0x55, "active");
    record["public_key_hex"] = json!(to_lowercase_hex(&public_key(0x56)));
    let document = key_document(vec![record]);

    assert!(
        PinnedTrustedAeonKeyProvider::from_json(&document).is_err(),
        "changing key bytes must invalidate the pinned identifier"
    );
    assert_ne!(
        canonical_key_id(&original_public_key),
        canonical_key_id(&public_key(0x56))
    );
}

#[tokio::test]
async fn active_and_retired_canonical_keys_verify_during_overlap() {
    let active_key = signing_key(0x42);
    let retired_key = signing_key(0x57);
    let active_id = canonical_key_id(&active_key.verifying_key().to_bytes());
    let retired_id = canonical_key_id(&retired_key.verifying_key().to_bytes());
    let verifier = verifier(&key_document(vec![
        key_record(0x42, "active"),
        key_record(0x57, "retired"),
    ]));

    verifier
        .verify_json(
            &signed_vector_envelope(&active_key, &active_id),
            &expected_context(),
        )
        .await
        .expect("canonical active key verifies");
    verifier
        .verify_json(
            &signed_vector_envelope(&retired_key, &retired_id),
            &expected_context(),
        )
        .await
        .expect("canonical retired key verifies during overlap");
}

#[tokio::test]
async fn removing_retired_key_ends_its_trust() {
    let retired_key = signing_key(0x58);
    let retired_id = canonical_key_id(&retired_key.verifying_key().to_bytes());
    let verifier = verifier(&key_document(vec![key_record(0x42, "active")]));

    let error = verifier
        .verify_json(
            &signed_vector_envelope(&retired_key, &retired_id),
            &expected_context(),
        )
        .await
        .expect_err("removed retired key must no longer verify");

    assert!(matches!(error, RecallVerificationError::UnknownSigningKey));
}
