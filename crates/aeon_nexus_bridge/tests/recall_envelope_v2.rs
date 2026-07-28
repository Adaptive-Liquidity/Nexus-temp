//! RecallEnvelopeV2 (S0.1) conformance tests.
//!
//! The checked-in vector under `vectors/recall_envelope_v2/` is the normative
//! artifact: AEON-IQ vendors it in S0.2 and must reproduce it byte for byte.
//! These tests prove the Rust implementation agrees with it, and that every
//! rule in the contract fails closed.

use std::collections::BTreeSet;

use aeon_nexus_bridge::v2::{
    canonical_json_v1_bytes, recall_payload_digest_for_diagnostics, recall_signed_payload_digest,
    recall_signing_bytes, sha256_hex, to_lowercase_hex, Nullable, RecallEnvelopeV2,
    RecallEnvelopeV2Payload, RecallHitV2, RecallSignatureV2, RECALL_CANONICALIZATION_VERSION,
    RECALL_MAX_HITS, RECALL_MAX_TTL_MS, RECALL_PROTOCOL_VERSION, RECALL_SIGNING_DOMAIN_BYTES,
    RECALL_SIGNING_DOMAIN_LABEL,
};
use aeon_nexus_bridge::{MemoryScore, TypedDigest};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

// ── Fixture ──────────────────────────────────────────────────────────────────

const REQUEST_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const RUN_ID: &str = "9f1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";
const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ISSUED_AT_MS: i64 = 1_760_000_000_000;
const EXPIRES_AT_MS: i64 = 1_760_000_030_000; // +30_000 ms = RECALL_DEFAULT_TTL_MS
const ED25519_SEED: [u8; 32] = [0x42; 32];
const KEY_ID: &str = "test-key-0001";
const ALGORITHM: &str = "ed25519";

fn digest_of(bytes: &[u8]) -> TypedDigest {
    TypedDigest::sha256_public(bytes)
}

/// The normative fixture payload.
///
/// Hit 0 populates both reserved fields; hit 1 leaves both `null` alongside a
/// `null` score, so one vector exercises populated *and* AUTH_0 forms.
fn fixture_payload() -> RecallEnvelopeV2Payload {
    RecallEnvelopeV2Payload {
        protocol_version: RECALL_PROTOCOL_VERSION.to_owned(),
        canonicalization_version: RECALL_CANONICALIZATION_VERSION.to_owned(),
        request_id: REQUEST_ID
            .parse()
            .expect("fixture request_id is a valid uuid"),
        nonce: NONCE.to_owned(),
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
        tenant_id: "tenant-0001".to_owned(),
        workspace_id: Nullable::null(),
        agent_id: "agent-0001".to_owned(),
        session_id: Nullable::some("session-0001".to_owned()),
        mission_id: Nullable::null(),
        run_id: RUN_ID.parse().expect("fixture run_id is a valid uuid"),
        query_digest: digest_of(b"what did we decide about retries?"),
        limit: 10,
        retrieval_policy_digest: digest_of(b"retrieval-policy-v1"),
        embedding_config_digest: digest_of(b"embedding-config-v1"),
        hits: vec![
            RecallHitV2 {
                memory_id: "mem-0001".to_owned(),
                memory_version_id: "mev-0001".to_owned(),
                content_digest: digest_of(b"first memory content"),
                rank: 0,
                score_micros: Nullable::some(MemoryScore::from_micros(875_000)),
                provenance_digest: Nullable::some(digest_of(b"provenance-0001")),
                authority_label: Nullable::some("AUTH_2".to_owned()),
            },
            RecallHitV2 {
                memory_id: "mem-0002".to_owned(),
                memory_version_id: "mev-0002".to_owned(),
                content_digest: digest_of(b"second memory content"),
                rank: 1,
                score_micros: Nullable::null(),
                provenance_digest: Nullable::null(),
                authority_label: Nullable::null(),
            },
        ],
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&ED25519_SEED)
}

fn fixture_signature(payload: &RecallEnvelopeV2Payload) -> RecallSignatureV2 {
    let bytes = recall_signing_bytes(payload).expect("signing bytes");
    let signature = signing_key().sign(&bytes);
    RecallSignatureV2 {
        algorithm: ALGORITHM.to_owned(),
        key_id: KEY_ID.to_owned(),
        signature: to_lowercase_hex(&signature.to_bytes()),
        signed_payload_digest: recall_signed_payload_digest(payload).expect("digest"),
        signing_domain: RECALL_SIGNING_DOMAIN_LABEL.to_owned(),
    }
}

fn fixture_envelope() -> RecallEnvelopeV2 {
    let payload = fixture_payload();
    let signature = fixture_signature(&payload);
    RecallEnvelopeV2 { payload, signature }
}

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/vector.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("missing normative vector at {path}: {error}"));
    serde_json::from_str(&raw).expect("vector.json is valid JSON")
}

fn vector_str(key: &str) -> String {
    vector()[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector.json missing string field {key}"))
        .to_owned()
}

fn canonical_string(payload: &RecallEnvelopeV2Payload) -> String {
    String::from_utf8(canonical_json_v1_bytes(payload).expect("canonical bytes"))
        .expect("canonical bytes are UTF-8")
}

fn payload_json_value() -> Value {
    serde_json::to_value(fixture_payload()).expect("payload serializes")
}

// ── Vector conformance ───────────────────────────────────────────────────────

/// Diagnostic aid: `cargo test -p aeon_nexus_bridge -- --nocapture emit_vector`
/// prints every value the vector file must contain.
#[test]
fn emit_vector() {
    let payload = fixture_payload();
    let canonical = canonical_json_v1_bytes(&payload).expect("canonical bytes");
    let signing = recall_signing_bytes(&payload).expect("signing bytes");
    let key = signing_key();

    println!("canonical_json            = {}", canonical_string(&payload));
    println!("canonical_sha256          = {}", sha256_hex(&canonical));
    println!("signing_bytes_hex         = {}", to_lowercase_hex(&signing));
    println!(
        "signed_payload_digest     = {}",
        recall_signed_payload_digest(&payload)
            .expect("digest")
            .value
    );
    println!(
        "payload_digest_diagnostic = {}",
        recall_payload_digest_for_diagnostics(&payload)
            .expect("digest")
            .value
    );
    println!(
        "ed25519_seed_hex          = {}",
        to_lowercase_hex(&ED25519_SEED)
    );
    println!(
        "ed25519_public_key_hex    = {}",
        to_lowercase_hex(key.verifying_key().as_bytes())
    );
    println!(
        "signature_hex             = {}",
        to_lowercase_hex(&key.sign(&signing).to_bytes())
    );
}

#[test]
fn canonical_bytes_match_the_checked_in_vector() {
    assert_eq!(
        canonical_string(&fixture_payload()),
        vector_str("canonical_json")
    );
}

#[test]
fn signing_bytes_match_the_checked_in_vector() {
    let signing = recall_signing_bytes(&fixture_payload()).expect("signing bytes");
    assert_eq!(to_lowercase_hex(&signing), vector_str("signing_bytes_hex"));
}

#[test]
fn signing_bytes_are_domain_prefixed_canonical_bytes() {
    let payload = fixture_payload();
    let canonical = canonical_json_v1_bytes(&payload).expect("canonical bytes");
    let signing = recall_signing_bytes(&payload).expect("signing bytes");

    let mut expected = Vec::from(RECALL_SIGNING_DOMAIN_BYTES);
    expected.extend_from_slice(&canonical);
    assert_eq!(signing, expected);
    // The NUL separator is load-bearing and must actually be present.
    assert_eq!(
        &signing[..RECALL_SIGNING_DOMAIN_BYTES.len()],
        b"AEON_RECALL_ENVELOPE_V2\0"
    );
    assert_eq!(signing[RECALL_SIGNING_DOMAIN_BYTES.len() - 1], 0u8);
}

#[test]
fn signed_payload_digest_is_sha256_of_signing_bytes_not_of_payload() {
    let payload = fixture_payload();
    let signing = recall_signing_bytes(&payload).expect("signing bytes");
    let digest = recall_signed_payload_digest(&payload).expect("digest");

    assert_eq!(digest.value, sha256_hex(&signing));
    assert_eq!(digest.value, vector_str("signed_payload_digest"));

    // ...and is emphatically NOT the digest of the bare canonical payload.
    let diagnostic = recall_payload_digest_for_diagnostics(&payload).expect("digest");
    assert_ne!(digest.value, diagnostic.value);
    assert_eq!(diagnostic.value, vector_str("payload_digest_diagnostic"));
}

#[test]
fn deterministic_ed25519_signature_matches_the_vector() {
    let key = signing_key();
    assert_eq!(
        to_lowercase_hex(key.verifying_key().as_bytes()),
        vector_str("ed25519_public_key_hex")
    );

    let signing = recall_signing_bytes(&fixture_payload()).expect("signing bytes");
    assert_eq!(
        to_lowercase_hex(&key.sign(&signing).to_bytes()),
        vector_str("signature_hex")
    );
}

#[test]
fn fixture_payload_matches_the_checked_in_payload_json() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/payload.json"
    );
    let raw = std::fs::read_to_string(path).expect("payload.json present");
    let from_file: RecallEnvelopeV2Payload =
        serde_json::from_str(&raw).expect("payload.json deserializes");
    assert_eq!(from_file, fixture_payload());
    from_file.validate().expect("fixture payload is valid");
}

#[test]
fn fixture_envelope_validates() {
    fixture_envelope()
        .validate()
        .expect("fixture envelope is valid");
}

// ── Every signed field is actually covered ───────────────────────────────────

/// Mutating any signed field must change the signing bytes, so the vector's
/// signature no longer applies. This is what makes the envelope tamper-evident.
#[test]
fn every_signed_field_mutation_changes_signing_bytes() {
    let base = recall_signing_bytes(&fixture_payload()).expect("signing bytes");
    let base_hex = to_lowercase_hex(&base);

    type Mutation = (&'static str, Box<dyn Fn(&mut RecallEnvelopeV2Payload)>);
    let mutations: Vec<Mutation> = vec![
        (
            "protocol_version",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.protocol_version.push('x')),
        ),
        (
            "canonicalization_version",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.canonicalization_version.push('x')),
        ),
        (
            "request_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.request_id = RUN_ID.parse().unwrap()),
        ),
        (
            "nonce",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.nonce.replace_range(0..1, "f")),
        ),
        (
            "issued_at_unix_ms",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.issued_at_unix_ms += 1),
        ),
        (
            "expires_at_unix_ms",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.expires_at_unix_ms += 1),
        ),
        (
            "tenant_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.tenant_id.push('x')),
        ),
        (
            "workspace_id null -> set",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.workspace_id = Nullable::some("workspace-0001".to_owned())
            }),
        ),
        (
            "agent_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.agent_id.push('x')),
        ),
        (
            "session_id set -> null",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.session_id = Nullable::null()),
        ),
        (
            "mission_id null -> set",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.mission_id = Nullable::some("mission-0001".to_owned())
            }),
        ),
        (
            "run_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.run_id = REQUEST_ID.parse().unwrap()),
        ),
        (
            "query_digest",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.query_digest = digest_of(b"different query")
            }),
        ),
        (
            "limit",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.limit += 1),
        ),
        (
            "retrieval_policy_digest",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.retrieval_policy_digest = digest_of(b"other-policy")
            }),
        ),
        (
            "embedding_config_digest",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.embedding_config_digest = digest_of(b"other-embedding")
            }),
        ),
        (
            "hit.memory_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.hits[0].memory_id.push('x')),
        ),
        (
            "hit.memory_version_id",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.hits[0].memory_version_id.push('x')),
        ),
        (
            "hit.content_digest",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[0].content_digest = digest_of(b"tampered content")
            }),
        ),
        (
            "hit.rank",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.hits[0].rank = 7),
        ),
        (
            "hit.score_micros value",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[0].score_micros = Nullable::some(MemoryScore::from_micros(1))
            }),
        ),
        (
            "hit.score_micros -> null",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.hits[0].score_micros = Nullable::null()),
        ),
        (
            "hit.provenance_digest -> null",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[0].provenance_digest = Nullable::null()
            }),
        ),
        (
            "hit.authority_label -> null",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[0].authority_label = Nullable::null()
            }),
        ),
        (
            "hit1.provenance_digest -> populated",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[1].provenance_digest = Nullable::some(digest_of(b"late provenance"))
            }),
        ),
        (
            "hit1.authority_label -> populated",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits[1].authority_label = Nullable::some("AUTH_1".to_owned())
            }),
        ),
        (
            "hits order",
            Box::new(|p: &mut RecallEnvelopeV2Payload| p.hits.swap(0, 1)),
        ),
        (
            "hits truncated",
            Box::new(|p: &mut RecallEnvelopeV2Payload| {
                p.hits.pop();
            }),
        ),
    ];

    let mut seen = BTreeSet::new();
    for (name, mutate) in mutations {
        let mut payload = fixture_payload();
        mutate(&mut payload);
        let mutated = to_lowercase_hex(&recall_signing_bytes(&payload).expect("signing bytes"));
        assert_ne!(
            mutated, base_hex,
            "mutation `{name}` did not change signing bytes"
        );
        assert!(
            seen.insert(mutated),
            "mutation `{name}` collided with another mutation"
        );
    }
}

/// Populating a reserved field on a hit that had `null` must change the signed
/// bytes. If it did not, provenance/authority claims could be added later
/// without invalidating an existing signature.
#[test]
fn reserved_field_population_changes_signed_bytes() {
    let base = recall_signed_payload_digest(&fixture_payload()).expect("digest");

    let mut with_provenance = fixture_payload();
    with_provenance.hits[1].provenance_digest = Nullable::some(digest_of(b"added later"));
    assert_ne!(
        recall_signed_payload_digest(&with_provenance)
            .expect("digest")
            .value,
        base.value
    );

    let mut with_authority = fixture_payload();
    with_authority.hits[1].authority_label = Nullable::some("AUTH_3".to_owned());
    assert_ne!(
        recall_signed_payload_digest(&with_authority)
            .expect("digest")
            .value,
        base.value
    );
}

// ── Optional-field wire rule (D1) ────────────────────────────────────────────

#[test]
fn optional_keys_are_always_serialized_even_when_null() {
    let value = payload_json_value();
    for key in ["workspace_id", "session_id", "mission_id"] {
        assert!(
            value.get(key).is_some(),
            "optional key {key} must be present"
        );
    }
    assert!(value["workspace_id"].is_null());
    assert!(value["mission_id"].is_null());

    let hit = &value["hits"][1];
    for key in ["score_micros", "provenance_digest", "authority_label"] {
        assert!(
            hit.get(key).is_some(),
            "optional hit key {key} must be present"
        );
        assert!(hit[key].is_null(), "hit key {key} must be explicit null");
    }
}

#[test]
fn explicit_null_is_accepted_for_optional_fields() {
    let raw = serde_json::to_string(&fixture_payload()).expect("serialize");
    let parsed: RecallEnvelopeV2Payload = serde_json::from_str(&raw).expect("explicit nulls parse");
    assert_eq!(parsed, fixture_payload());
    parsed.validate().expect("valid");
}

#[test]
fn absent_optional_keys_are_rejected() {
    for key in ["workspace_id", "session_id", "mission_id"] {
        let mut value = payload_json_value();
        value.as_object_mut().unwrap().remove(key);
        let raw = serde_json::to_string(&value).unwrap();
        assert!(
            serde_json::from_str::<RecallEnvelopeV2Payload>(&raw).is_err(),
            "absent optional key `{key}` must be rejected, not defaulted to null"
        );
    }

    for key in ["score_micros", "provenance_digest", "authority_label"] {
        let mut value = payload_json_value();
        value["hits"][0].as_object_mut().unwrap().remove(key);
        let raw = serde_json::to_string(&value).unwrap();
        assert!(
            serde_json::from_str::<RecallEnvelopeV2Payload>(&raw).is_err(),
            "absent optional hit key `{key}` must be rejected"
        );
    }
}

#[test]
fn score_null_is_accepted_and_never_becomes_zero() {
    let payload = fixture_payload();
    assert!(payload.hits[1].score_micros.is_null());
    payload.validate().expect("null score is valid");

    let round_tripped: RecallEnvelopeV2Payload =
        serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
    assert!(round_tripped.hits[1].score_micros.is_null());
    assert_ne!(
        round_tripped.hits[1].score_micros,
        Nullable::some(MemoryScore::from_micros(0)),
        "an absent score must never collapse to zero"
    );
}

// ── Fail-closed parsing ──────────────────────────────────────────────────────

#[test]
fn unknown_fields_fail_closed() {
    let mut value = payload_json_value();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(serde_json::from_str::<RecallEnvelopeV2Payload>(&value.to_string()).is_err());

    let mut value = payload_json_value();
    value["hits"][0]
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(serde_json::from_str::<RecallEnvelopeV2Payload>(&value.to_string()).is_err());

    let envelope = serde_json::to_value(fixture_envelope()).unwrap();
    let mut value = envelope.clone();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(serde_json::from_str::<RecallEnvelopeV2>(&value.to_string()).is_err());

    let mut value = envelope;
    value["signature"]
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(serde_json::from_str::<RecallEnvelopeV2>(&value.to_string()).is_err());
}

#[test]
fn wrong_protocol_version_fails_closed() {
    let mut payload = fixture_payload();
    payload.protocol_version = "aeon-recall-envelope-v1".to_owned();
    assert!(payload.validate().is_err());
}

#[test]
fn wrong_canonicalization_version_fails_closed() {
    let mut payload = fixture_payload();
    payload.canonicalization_version = "rfc8785".to_owned();
    assert!(payload.validate().is_err());
}

#[test]
fn wrong_signing_domain_fails_closed() {
    let mut envelope = fixture_envelope();
    envelope.signature.signing_domain = "AEON_RECALL_ENVELOPE_V1".to_owned();
    assert!(envelope.validate().is_err());
}

#[test]
fn mismatched_signed_payload_digest_fails_closed() {
    let mut envelope = fixture_envelope();
    envelope.payload.tenant_id = "tenant-0002".to_owned();
    assert!(
        envelope.validate().is_err(),
        "swapping the payload must invalidate signed_payload_digest"
    );
}

// ── Validation rules ─────────────────────────────────────────────────────────

#[test]
fn nonce_must_be_64_lowercase_hex_characters() {
    let mut short = fixture_payload();
    short.nonce = NONCE[..62].to_owned();
    assert!(short.validate().is_err(), "62-char nonce must be rejected");

    let mut long = fixture_payload();
    long.nonce = format!("{NONCE}ab");
    assert!(long.validate().is_err(), "66-char nonce must be rejected");

    let mut upper = fixture_payload();
    upper.nonce = NONCE.to_uppercase();
    assert!(
        upper.validate().is_err(),
        "uppercase nonce must be rejected"
    );

    let mut non_hex = fixture_payload();
    non_hex.nonce = "g".repeat(64);
    assert!(
        non_hex.validate().is_err(),
        "non-hex nonce must be rejected"
    );

    assert_eq!(NONCE.len(), 64);
    fixture_payload()
        .validate()
        .expect("64-char lowercase hex nonce is valid");
}

#[test]
fn ttl_over_the_maximum_is_rejected() {
    let mut ok = fixture_payload();
    ok.expires_at_unix_ms = ok.issued_at_unix_ms + RECALL_MAX_TTL_MS;
    ok.validate().expect("TTL exactly at the maximum is valid");

    let mut too_long = fixture_payload();
    too_long.expires_at_unix_ms = too_long.issued_at_unix_ms + RECALL_MAX_TTL_MS + 1;
    assert!(
        too_long.validate().is_err(),
        "TTL over 120s must be rejected"
    );
}

#[test]
fn expiry_must_be_strictly_after_issue_and_issue_non_negative() {
    let mut equal = fixture_payload();
    equal.expires_at_unix_ms = equal.issued_at_unix_ms;
    assert!(equal.validate().is_err());

    let mut inverted = fixture_payload();
    inverted.expires_at_unix_ms = inverted.issued_at_unix_ms - 1;
    assert!(inverted.validate().is_err());

    let mut negative = fixture_payload();
    negative.issued_at_unix_ms = -1;
    negative.expires_at_unix_ms = 1;
    assert!(negative.validate().is_err());
}

fn hit(index: u32) -> RecallHitV2 {
    RecallHitV2 {
        memory_id: format!("mem-{index:04}"),
        memory_version_id: format!("mev-{index:04}"),
        content_digest: digest_of(format!("content-{index}").as_bytes()),
        rank: index,
        score_micros: Nullable::null(),
        provenance_digest: Nullable::null(),
        authority_label: Nullable::null(),
    }
}

#[test]
fn hit_count_bounds_are_enforced() {
    let mut at_max = fixture_payload();
    at_max.limit = 100;
    at_max.hits = (0..RECALL_MAX_HITS as u32).map(hit).collect();
    at_max.validate().expect("exactly 100 hits is valid");

    let mut over_max = fixture_payload();
    over_max.limit = 100;
    over_max.hits = (0..=RECALL_MAX_HITS as u32).map(hit).collect();
    assert_eq!(over_max.hits.len(), 101);
    assert!(over_max.validate().is_err(), "101 hits must be rejected");
}

#[test]
fn empty_hits_are_valid_and_signable() {
    let mut payload = fixture_payload();
    payload.hits = Vec::new();
    payload
        .validate()
        .expect("a recall that returned nothing is attestable");

    let signature = fixture_signature(&payload);
    RecallEnvelopeV2 { payload, signature }
        .validate()
        .expect("empty-hit envelope validates");
}

#[test]
fn hits_exceeding_limit_are_rejected() {
    let mut payload = fixture_payload();
    payload.limit = 1;
    assert_eq!(payload.hits.len(), 2);
    assert!(
        payload.validate().is_err(),
        "hits.len() > limit must be rejected"
    );

    payload.limit = 2;
    payload.validate().expect("hits.len() == limit is valid");
}

#[test]
fn duplicate_memory_ids_are_rejected() {
    let mut payload = fixture_payload();
    payload.hits[1].memory_id = payload.hits[0].memory_id.clone();
    assert!(payload.validate().is_err());
}

#[test]
fn duplicate_memory_version_ids_are_rejected() {
    let mut payload = fixture_payload();
    payload.hits[1].memory_version_id = payload.hits[0].memory_version_id.clone();
    assert!(payload.validate().is_err());
}

#[test]
fn rank_gaps_and_reordering_are_rejected() {
    let mut gap = fixture_payload();
    gap.hits[1].rank = 2;
    assert!(gap.validate().is_err(), "rank gap must be rejected");

    let mut swapped = fixture_payload();
    swapped.hits[0].rank = 1;
    swapped.hits[1].rank = 0;
    assert!(
        swapped.validate().is_err(),
        "ranks not matching array order must be rejected"
    );

    let mut not_zero_based = fixture_payload();
    not_zero_based.hits[0].rank = 1;
    not_zero_based.hits[1].rank = 2;
    assert!(
        not_zero_based.validate().is_err(),
        "ranks must be zero-based"
    );
}

#[test]
fn empty_required_identifiers_are_rejected() {
    let mut tenant = fixture_payload();
    tenant.tenant_id = String::new();
    assert!(tenant.validate().is_err());

    let mut agent = fixture_payload();
    agent.agent_id = String::new();
    assert!(agent.validate().is_err());

    let mut memory = fixture_payload();
    memory.hits[0].memory_id = String::new();
    assert!(memory.validate().is_err());

    let mut version = fixture_payload();
    version.hits[0].memory_version_id = String::new();
    assert!(version.validate().is_err());

    // A present-but-empty optional is also invalid; `null` is how you say absent.
    let mut workspace = fixture_payload();
    workspace.workspace_id = Nullable::some(String::new());
    assert!(workspace.validate().is_err());
}

// ── Canonicalization properties ──────────────────────────────────────────────

#[test]
fn canonical_json_sorts_object_keys_and_preserves_array_order() {
    let canonical = canonical_string(&fixture_payload());

    // Top-level keys ascend by byte order.
    let agent_at = canonical.find("\"agent_id\"").expect("agent_id present");
    let tenant_at = canonical.find("\"tenant_id\"").expect("tenant_id present");
    assert!(agent_at < tenant_at, "keys must be sorted ascending");

    // Array order is preserved: mem-0001 precedes mem-0002.
    let first = canonical.find("mem-0001").expect("first hit present");
    let second = canonical.find("mem-0002").expect("second hit present");
    assert!(first < second, "array order must be preserved, not sorted");

    // No insignificant whitespace.
    assert!(!canonical.contains(": "));
    assert!(!canonical.contains(", "));
    assert!(!canonical.contains('\n'));
}

#[test]
fn canonical_json_is_independent_of_input_key_order() {
    let payload = fixture_payload();
    let canonical = canonical_json_v1_bytes(&payload).expect("canonical bytes");

    // Round-trip through a Value whose keys were re-emitted in another order.
    let reparsed: Value = serde_json::from_slice(&canonical).expect("valid JSON");
    let shuffled = serde_json::to_string(&reparsed).expect("reserialize");
    let reparsed_payload: RecallEnvelopeV2Payload =
        serde_json::from_str(&shuffled).expect("reparse");

    assert_eq!(
        canonical_json_v1_bytes(&reparsed_payload).expect("canonical bytes"),
        canonical
    );
}

#[test]
fn score_is_fixed_point_on_the_wire_never_a_float() {
    let canonical = canonical_string(&fixture_payload());
    assert!(canonical.contains("\"score_micros\":875000"));
    assert!(!canonical.contains("875000.0"));
    assert!(!canonical.contains("0.875"));
}

// ── V1 / V2 separation ───────────────────────────────────────────────────────

#[test]
fn v1_and_v2_cannot_be_confused() {
    use aeon_nexus_bridge::{hmac_agent_id, MemoryEvidence, MemoryEvidenceHit};

    let v1 = MemoryEvidence::new(
        hmac_agent_id(b"test-key", "agent-a"),
        Some("session-a".to_owned()),
        vec![MemoryEvidenceHit::new("mem-1", b"content one", Some(0.5)).expect("hit")],
    );
    let v1_json = serde_json::to_string(&v1).expect("v1 serializes");
    let v2_json = serde_json::to_string(&fixture_payload()).expect("v2 serializes");

    assert!(
        serde_json::from_str::<RecallEnvelopeV2Payload>(&v1_json).is_err(),
        "V1 evidence must not deserialize as a V2 payload"
    );
    assert!(
        serde_json::from_str::<MemoryEvidence>(&v2_json).is_err(),
        "V2 payload must not deserialize as V1 evidence"
    );

    assert_eq!(v1.version, "aeon-nexus-memory-evidence-v1");
    assert_eq!(
        fixture_payload().protocol_version,
        "aeon-recall-envelope-v2"
    );
}

/// V1 canonical bytes and digest must be exactly what they were before V2
/// existed. If this changes, evidence produced before this PR stops verifying.
#[test]
fn v1_digests_remain_byte_identical() {
    use aeon_nexus_bridge::{
        canonical_bytes, memory_evidence_digest, MemoryEvidence, MemoryEvidenceHit, TypedDigest,
    };

    let evidence = MemoryEvidence::new(
        TypedDigest {
            algorithm: "hmac-sha256".to_owned(),
            value: "a".repeat(64),
            public_recomputable: false,
        },
        Some("session-a".to_owned()),
        vec![MemoryEvidenceHit::new("mem-1", b"content one", Some(0.5)).expect("hit")],
    );

    let canonical = canonical_bytes(&evidence).expect("v1 canonical bytes");
    let expected = concat!(
        r#"{"agent_handle":{"algorithm":"hmac-sha256","public_recomputable":false,"#,
        r#""value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
        r#""injected_hits":[{"content_digest":{"algorithm":"sha256","public_recomputable":true,"#,
        r#""value":"cdaf242e2e139dd255fbb56a691a9d0943a916a3235ee8d3cd73810d9d0b1ea2"},"#,
        r#""memory_id":"mem-1","score":500000}],"session_id":"session-a","#,
        r#""version":"aeon-nexus-memory-evidence-v1"}"#
    );
    assert_eq!(
        String::from_utf8(canonical).expect("utf8"),
        expected,
        "V1 canonical bytes changed"
    );

    let digest = memory_evidence_digest(&evidence).expect("v1 digest");
    assert_eq!(digest.algorithm, "sha256");
    assert!(digest.public_recomputable);
    assert_eq!(digest.value, sha256_hex(expected.as_bytes()));
}
