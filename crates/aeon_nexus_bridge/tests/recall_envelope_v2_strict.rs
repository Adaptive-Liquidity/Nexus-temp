//! RecallEnvelopeV2 strictness tests: limit bounds, duplicate-key rejection,
//! JSON Schema conformance, signature-envelope freezing, and the V1 baseline
//! taken from untouched Nexus-temp main.

use aeon_nexus_bridge::v2::{
    recall_signed_payload_digest, recall_signing_bytes, to_lowercase_hex, CanonicalUuid, Nullable,
    RecallDigestV2, RecallEnvelopeV2, RecallEnvelopeV2Payload, RecallHitV2, RecallSignatureV2,
    RECALL_CANONICALIZATION_VERSION, RECALL_MAX_LIMIT, RECALL_MIN_LIMIT, RECALL_PROTOCOL_VERSION,
    RECALL_SIGNATURE_ALGORITHM, RECALL_SIGNATURE_HEX_LEN, RECALL_SIGNING_DOMAIN_LABEL,
};
use aeon_nexus_bridge::{MemoryScore, TypedDigest};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const REQUEST_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const RUN_ID: &str = "9f1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";
const ED25519_SEED: [u8; 32] = [0x42; 32];

fn digest_of(bytes: &[u8]) -> RecallDigestV2 {
    RecallDigestV2::sha256(bytes, true)
}

fn base_payload() -> RecallEnvelopeV2Payload {
    RecallEnvelopeV2Payload {
        protocol_version: RECALL_PROTOCOL_VERSION.to_owned(),
        canonicalization_version: RECALL_CANONICALIZATION_VERSION.to_owned(),
        request_id: REQUEST_ID.parse().unwrap(),
        nonce: NONCE.to_owned(),
        issued_at_unix_ms: 1_760_000_000_000,
        expires_at_unix_ms: 1_760_000_030_000,
        tenant_id: "tenant-0001".to_owned(),
        workspace_id: Nullable::null(),
        agent_id: "agent-0001".to_owned(),
        session_id: Nullable::some("session-0001".to_owned()),
        mission_id: Nullable::null(),
        run_id: RUN_ID.parse().unwrap(),
        query_digest: digest_of(b"what did we decide about retries?"),
        limit: 10,
        retrieval_policy_digest: digest_of(b"retrieval-policy-v1"),
        embedding_config_digest: digest_of(b"embedding-config-v1"),
        hits: vec![RecallHitV2 {
            memory_id: "mem-0001".to_owned(),
            memory_version_id: "mev-0001".to_owned(),
            content_digest: digest_of(b"first memory content"),
            rank: 0,
            score_micros: Nullable::some(MemoryScore::from_micros(875_000)),
            provenance_digest: Nullable::null(),
            authority_label: Nullable::null(),
        }],
    }
}

fn sign(payload: &RecallEnvelopeV2Payload) -> RecallSignatureV2 {
    let key = SigningKey::from_bytes(&ED25519_SEED);
    let bytes = recall_signing_bytes(payload).expect("signing bytes");
    RecallSignatureV2 {
        algorithm: RECALL_SIGNATURE_ALGORITHM.to_owned(),
        key_id: "test-key-0001".to_owned(),
        signature: to_lowercase_hex(&key.sign(&bytes).to_bytes()),
        signed_payload_digest: recall_signed_payload_digest(payload).expect("digest"),
        signing_domain: RECALL_SIGNING_DOMAIN_LABEL.to_owned(),
    }
}

fn envelope(payload: RecallEnvelopeV2Payload) -> RecallEnvelopeV2 {
    let signature = sign(&payload);
    RecallEnvelopeV2 { payload, signature }
}

// ── 2. limit bounds ──────────────────────────────────────────────────────────

#[test]
fn limit_zero_is_rejected() {
    let mut payload = base_payload();
    payload.limit = 0;
    payload.hits.clear();
    assert!(
        payload.validate().is_err(),
        "limit 0 must be rejected even with empty hits"
    );
}

#[test]
fn limit_one_with_empty_hits_is_accepted() {
    let mut payload = base_payload();
    payload.limit = RECALL_MIN_LIMIT;
    payload.hits.clear();
    payload
        .validate()
        .expect("limit 1 with zero hits is a valid, signable no-result recall");
    envelope(payload).validate().expect("envelope validates");
}

#[test]
fn limit_one_with_one_hit_is_accepted() {
    let mut payload = base_payload();
    payload.limit = 1;
    assert_eq!(payload.hits.len(), 1);
    payload.validate().expect("limit 1 with one hit is valid");
}

#[test]
fn hits_exceeding_limit_is_rejected_at_the_boundary() {
    let mut payload = base_payload();
    payload.limit = 1;
    payload.hits.push(RecallHitV2 {
        memory_id: "mem-0002".to_owned(),
        memory_version_id: "mev-0002".to_owned(),
        content_digest: digest_of(b"second memory content"),
        rank: 1,
        score_micros: Nullable::null(),
        provenance_digest: Nullable::null(),
        authority_label: Nullable::null(),
    });
    assert!(payload.validate().is_err(), "2 hits with limit 1 must fail");

    payload.limit = 2;
    payload.validate().expect("2 hits with limit 2 is valid");
}

#[test]
fn limit_above_maximum_is_rejected() {
    let mut payload = base_payload();
    payload.limit = RECALL_MAX_LIMIT + 1;
    assert!(payload.validate().is_err());
}

// ── 3. duplicate JSON keys ───────────────────────────────────────────────────
//
// These fixtures are built as raw strings on purpose. A duplicate key cannot be
// expressed through `serde_json::Value`: its `Map` keeps only the last
// occurrence, so a Value-based test would silently pass while proving nothing.

fn payload_json_string() -> String {
    serde_json::to_string(&base_payload()).expect("serialize")
}

fn envelope_json_with_populated_provenance() -> String {
    let mut payload = base_payload();
    payload.hits[0].provenance_digest = Nullable::some(digest_of(b"provenance"));
    serde_json::to_string(&envelope(payload)).expect("serialize")
}

/// Insert a second copy of `"key":<value>` immediately after the opening brace
/// of the object starting at `object_start`.
fn duplicate_key_at(json: &str, object_start: usize, key: &str, value: &str) -> String {
    let mut out = String::with_capacity(json.len() + key.len() + value.len() + 4);
    out.push_str(&json[..=object_start]);
    out.push_str(&format!("\"{key}\":{value},"));
    out.push_str(&json[object_start + 1..]);
    out
}

fn digest_object_start(json: &str, field: &str) -> usize {
    let marker = format!("\"{field}\":{{");
    json.find(&marker).expect("digest field present") + marker.len() - 1
}

fn digest_object_mut<'a>(
    value: &'a mut Value,
    field: &str,
) -> &'a mut serde_json::Map<String, Value> {
    fn find<'a>(
        value: &'a mut Value,
        field: &str,
    ) -> Option<&'a mut serde_json::Map<String, Value>> {
        match value {
            Value::Object(object) => {
                if object.get(field).is_some_and(Value::is_object) {
                    return object.get_mut(field).and_then(Value::as_object_mut);
                }
                object.values_mut().find_map(|child| find(child, field))
            }
            Value::Array(items) => items.iter_mut().find_map(|child| find(child, field)),
            _ => None,
        }
    }

    find(value, field).expect("digest object present")
}

const DIGEST_FIELDS: [&str; 6] = [
    "provenance_digest",
    "query_digest",
    "retrieval_policy_digest",
    "embedding_config_digest",
    "content_digest",
    "signed_payload_digest",
];

#[test]
fn duplicate_top_level_payload_key_is_rejected() {
    let json = payload_json_string();
    let raw = duplicate_key_at(&json, 0, "tenant_id", "\"tenant-9999\"");
    assert_eq!(
        raw.matches("\"tenant_id\"").count(),
        2,
        "fixture must duplicate"
    );

    let error = serde_json::from_str::<RecallEnvelopeV2Payload>(&raw)
        .expect_err("duplicate top-level key must be rejected");
    assert!(
        error.to_string().contains("duplicate field"),
        "expected a duplicate-field error, got: {error}"
    );
}

#[test]
fn duplicate_hit_key_is_rejected() {
    let json = payload_json_string();
    let hits_at = json.find("\"hits\":[{").expect("hits present");
    let object_start = hits_at + "\"hits\":[".len();
    let raw = duplicate_key_at(&json, object_start, "memory_id", "\"mem-9999\"");
    assert_eq!(
        raw.matches("\"memory_id\"").count(),
        2,
        "fixture must duplicate"
    );

    let error = serde_json::from_str::<RecallEnvelopeV2Payload>(&raw)
        .expect_err("duplicate hit key must be rejected");
    assert!(
        error.to_string().contains("duplicate field"),
        "expected a duplicate-field error, got: {error}"
    );
}

#[test]
fn duplicate_signature_envelope_key_is_rejected() {
    let json = serde_json::to_string(&envelope(base_payload())).expect("serialize");
    let sig_at = json
        .find("\"signature\":{")
        .expect("signature object present");
    let object_start = sig_at + "\"signature\":".len();
    let raw = duplicate_key_at(&json, object_start, "key_id", "\"attacker-key\"");
    assert_eq!(
        raw.matches("\"key_id\"").count(),
        2,
        "fixture must duplicate"
    );

    let error = serde_json::from_str::<RecallEnvelopeV2>(&raw)
        .expect_err("duplicate signature key must be rejected");
    assert!(
        error.to_string().contains("duplicate field"),
        "expected a duplicate-field error, got: {error}"
    );
}

#[test]
fn nullable_digest_rejects_duplicate_and_unknown_members() {
    let json = envelope_json_with_populated_provenance();
    let object_start = digest_object_start(&json, "provenance_digest");

    let duplicate = duplicate_key_at(&json, object_start, "algorithm", "\"sha256\"");
    let error = serde_json::from_str::<RecallEnvelopeV2>(&duplicate)
        .expect_err("duplicate member inside nullable digest must be rejected");
    assert!(
        error.to_string().contains("duplicate field"),
        "expected a duplicate-field error, got: {error}"
    );

    let unknown = duplicate_key_at(&json, object_start, "attacker", "true");
    serde_json::from_str::<RecallEnvelopeV2>(&unknown)
        .expect_err("unknown member inside nullable digest must be rejected");
}

#[test]
fn every_v2_digest_rejects_duplicate_known_and_unknown_members() {
    for field in DIGEST_FIELDS {
        for (member, value) in [
            ("algorithm", "\"sha256\""),
            (
                "value",
                "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
            ),
            ("public_recomputable", "false"),
        ] {
            let json = envelope_json_with_populated_provenance();
            let raw = duplicate_key_at(&json, digest_object_start(&json, field), member, value);
            let error = serde_json::from_str::<RecallEnvelopeV2>(&raw).expect_err(
                "every duplicate known member in every nested V2 digest must be rejected",
            );
            assert!(
                error.to_string().contains("duplicate field"),
                "{field}.{member} returned the wrong error: {error}"
            );
        }

        let json = envelope_json_with_populated_provenance();
        let raw = duplicate_key_at(
            &json,
            digest_object_start(&json, field),
            "unexpected",
            "\"value\"",
        );
        assert!(
            serde_json::from_str::<RecallEnvelopeV2>(&raw).is_err(),
            "{field} accepted an unknown member"
        );
    }
}

#[test]
fn every_v2_digest_rejects_invalid_or_incomplete_wire_values() {
    for field in DIGEST_FIELDS {
        for invalid_algorithm in ["SHA256", "sha-256", "hmac-sha256", ""] {
            let mut value: Value =
                serde_json::from_str(&envelope_json_with_populated_provenance()).unwrap();
            digest_object_mut(&mut value, field)["algorithm"] = Value::from(invalid_algorithm);
            let raw = serde_json::to_string(&value).unwrap();
            assert!(
                serde_json::from_str::<RecallEnvelopeV2>(&raw).is_err(),
                "{field} accepted invalid algorithm {invalid_algorithm:?}"
            );
        }

        for invalid_value in [
            "0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            "00000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let mut value: Value =
                serde_json::from_str(&envelope_json_with_populated_provenance()).unwrap();
            digest_object_mut(&mut value, field)["value"] = Value::from(invalid_value);
            let raw = serde_json::to_string(&value).unwrap();
            assert!(
                serde_json::from_str::<RecallEnvelopeV2>(&raw).is_err(),
                "{field} accepted invalid digest value"
            );
        }

        for missing in ["algorithm", "value", "public_recomputable"] {
            let mut value: Value =
                serde_json::from_str(&envelope_json_with_populated_provenance()).unwrap();
            digest_object_mut(&mut value, field).remove(missing);
            let raw = serde_json::to_string(&value).unwrap();
            assert!(
                serde_json::from_str::<RecallEnvelopeV2>(&raw).is_err(),
                "{field} accepted missing member {missing}"
            );
        }

        let mut value: Value =
            serde_json::from_str(&envelope_json_with_populated_provenance()).unwrap();
        digest_object_mut(&mut value, field)["public_recomputable"] = Value::from("true");
        let raw = serde_json::to_string(&value).unwrap();
        assert!(
            serde_json::from_str::<RecallEnvelopeV2>(&raw).is_err(),
            "{field} accepted a non-boolean flag"
        );
    }
}

#[test]
fn nullable_digest_accepts_null_and_a_populated_object() {
    let null_json = serde_json::to_string(&envelope(base_payload())).unwrap();
    let null_parsed: RecallEnvelopeV2 = serde_json::from_str(&null_json).expect("null accepted");
    assert!(null_parsed.payload.hits[0].provenance_digest.is_null());

    let populated_json = envelope_json_with_populated_provenance();
    let populated: RecallEnvelopeV2 =
        serde_json::from_str(&populated_json).expect("populated digest accepted");
    assert!(populated.payload.hits[0]
        .provenance_digest
        .as_option()
        .is_some());
}

/// Documents *why* the tests above pass, so the guarantee is not accidental.
///
/// serde_derive generates a `Deserialize` impl that tracks each field in a
/// local `Option<T>` and calls `serde::de::Error::duplicate_field` when a key
/// arrives twice. It is the derive, not `deny_unknown_fields`, that provides
/// this: `deny_unknown_fields` only rejects *unrecognised* names and would
/// happily accept a repeated known one.
#[test]
fn duplicate_key_rejection_comes_from_the_derive_not_deny_unknown_fields() {
    // A duplicate of a KNOWN field: `deny_unknown_fields` cannot be what
    // rejects this, because the name is recognised.
    let json = payload_json_string();
    let raw = duplicate_key_at(&json, 0, "limit", "99");
    let error = serde_json::from_str::<RecallEnvelopeV2Payload>(&raw).expect_err("must reject");
    assert!(error.to_string().contains("duplicate field `limit`"));

    // And a Value-based parse would NOT have caught it -- last-wins.
    let as_value: Value = serde_json::from_str(&raw).expect("Value parse tolerates duplicates");
    assert_eq!(
        as_value["limit"], 10,
        "serde_json::Value silently keeps the LAST duplicate; this is why the \
         raw-string fixtures above matter"
    );
}

// ── 4. JSON Schema conformance ───────────────────────────────────────────────

fn compiled_schema() -> (boon::Schemas, boon::SchemaIndex) {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schema/recall_envelope_v2.schema.json"
    );
    let raw = std::fs::read_to_string(schema_path).expect("schema present");
    let value: Value = serde_json::from_str(&raw).expect("schema is valid JSON");

    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource("recall_envelope_v2.json", value)
        .expect("schema resource");
    let index = compiler
        .compile("recall_envelope_v2.json", &mut schemas)
        .expect("schema compiles");
    (schemas, index)
}

fn schema_accepts(instance: &Value) -> bool {
    let (schemas, index) = compiled_schema();
    schemas.validate(instance, index).is_ok()
}

fn valid_envelope_value() -> Value {
    serde_json::to_value(envelope(base_payload())).expect("serialize")
}

#[test]
fn schema_accepts_the_checked_in_fixtures() {
    assert!(
        schema_accepts(&valid_envelope_value()),
        "the fixture envelope must satisfy the published schema"
    );

    let payload_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/payload.json"
    );
    let raw = std::fs::read_to_string(payload_path).expect("payload.json present");
    let payload: RecallEnvelopeV2Payload = serde_json::from_str(&raw).expect("parses");
    let checked_in = envelope(payload);
    assert!(
        schema_accepts(&serde_json::to_value(checked_in).expect("serialize")),
        "the checked-in payload fixture must satisfy the published schema"
    );
}

#[test]
fn schema_rejects_absent_nullable_key() {
    let mut value = valid_envelope_value();
    value["payload"]
        .as_object_mut()
        .unwrap()
        .remove("workspace_id");
    assert!(
        !schema_accepts(&value),
        "an absent nullable key must fail the schema, mirroring the Rust rule"
    );
}

#[test]
fn schema_accepts_explicit_null() {
    let value = valid_envelope_value();
    assert!(value["payload"]["workspace_id"].is_null());
    assert!(value["payload"]["mission_id"].is_null());
    assert!(
        schema_accepts(&value),
        "explicit null must satisfy the schema"
    );
}

#[test]
fn schema_bounds_score_micros_to_the_signed_64_bit_wire_range() {
    for boundary in [i64::MIN, i64::MAX] {
        let mut value = valid_envelope_value();
        value["payload"]["hits"][0]["score_micros"] = Value::from(boundary);
        assert!(
            schema_accepts(&value),
            "score_micros boundary {boundary} must satisfy the schema"
        );
        serde_json::from_value::<RecallEnvelopeV2>(value)
            .expect("the Rust wire type must accept both signed 64-bit boundaries");
    }

    let mut above_max = valid_envelope_value();
    above_max["payload"]["hits"][0]["score_micros"] =
        serde_json::from_str("9223372036854777856").expect("valid JSON integer");
    assert!(
        !schema_accepts(&above_max),
        "the schema must reject score_micros above i64::MAX"
    );

    let mut exactly_one_above = valid_envelope_value();
    exactly_one_above["payload"]["hits"][0]["score_micros"] =
        serde_json::from_str("9223372036854775808").expect("valid JSON integer");
    assert!(
        serde_json::from_value::<RecallEnvelopeV2>(exactly_one_above).is_err(),
        "the Rust wire type must reject score_micros above i64::MAX"
    );

    let schema_json: Value =
        serde_json::from_str(include_str!("../schema/recall_envelope_v2.schema.json"))
            .expect("schema JSON parses");
    let integer_branch = &schema_json["$defs"]["hit"]["properties"]["score_micros"]["oneOf"][0];
    assert_eq!(integer_branch["minimum"], Value::from(i64::MIN));
    assert_eq!(integer_branch["maximum"], Value::from(i64::MAX));
}

#[test]
fn schema_bounds_timestamps_to_the_signed_64_bit_wire_range() {
    let schema_json: Value =
        serde_json::from_str(include_str!("../schema/recall_envelope_v2.schema.json"))
            .expect("schema JSON parses");
    let properties = &schema_json["$defs"]["payload"]["properties"];

    for (field, minimum) in [("issued_at_unix_ms", 0_i64), ("expires_at_unix_ms", 1_i64)] {
        assert_eq!(properties[field]["minimum"], Value::from(minimum));
        assert_eq!(properties[field]["maximum"], Value::from(i64::MAX));

        let mut boundary = valid_envelope_value();
        boundary["payload"][field] = Value::from(i64::MAX);
        assert!(
            schema_accepts(&boundary),
            "{field} at i64::MAX must satisfy the schema"
        );
        serde_json::from_value::<RecallEnvelopeV2>(boundary)
            .expect("the Rust wire type must deserialize i64::MAX");

        let mut above_max = valid_envelope_value();
        above_max["payload"][field] =
            serde_json::from_str("9223372036854777856").expect("valid JSON integer");
        assert!(
            !schema_accepts(&above_max),
            "the schema must reject {field} above i64::MAX"
        );

        let mut exactly_one_above = valid_envelope_value();
        exactly_one_above["payload"][field] =
            serde_json::from_str("9223372036854775808").expect("valid JSON integer");
        assert!(
            serde_json::from_value::<RecallEnvelopeV2>(exactly_one_above).is_err(),
            "the Rust wire type must reject {field} above i64::MAX"
        );
    }
}

#[test]
fn schema_rejects_unknown_fields() {
    let mut value = valid_envelope_value();
    value["payload"]
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(!schema_accepts(&value));

    let mut value = valid_envelope_value();
    value["payload"]["hits"][0]
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), Value::from(1));
    assert!(!schema_accepts(&value));
}

#[test]
fn schema_rejects_invalid_nonce() {
    for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"0".repeat(63)] {
        let mut value = valid_envelope_value();
        value["payload"]["nonce"] = Value::from(bad);
        assert!(!schema_accepts(&value), "nonce {bad:?} must be rejected");
    }
}

#[test]
fn invalid_uuid_is_rejected() {
    let mut value = valid_envelope_value();
    value["payload"]["request_id"] = Value::from("not-a-uuid");

    // `format: uuid` is annotation-only in many validators, so the binding
    // guarantee is the Rust type. Assert that explicitly rather than assuming
    // the schema catches it.
    let rust_rejected = serde_json::from_value::<RecallEnvelopeV2>(value.clone()).is_err();
    assert!(rust_rejected, "the Rust types must reject an invalid UUID");
}

#[test]
fn schema_rejects_101_hits() {
    let mut value = valid_envelope_value();
    let hits: Vec<Value> = (0..101)
        .map(|index| {
            serde_json::json!({
                "memory_id": format!("mem-{index:04}"),
                "memory_version_id": format!("mev-{index:04}"),
                "content_digest": serde_json::to_value(
                    digest_of(format!("c{index}").as_bytes())
                ).unwrap(),
                "rank": index,
                "score_micros": Value::Null,
                "provenance_digest": Value::Null,
                "authority_label": Value::Null
            })
        })
        .collect();
    value["payload"]["hits"] = Value::Array(hits);
    assert!(!schema_accepts(&value), "101 hits must exceed maxItems");
}

#[test]
fn schema_rejects_invalid_signature_envelope_shape() {
    // Wrong algorithm.
    let mut value = valid_envelope_value();
    value["signature"]["algorithm"] = Value::from("hmac-sha256");
    assert!(!schema_accepts(&value), "algorithm is frozen to ed25519");

    // Signature not 128 hex chars.
    let mut value = valid_envelope_value();
    value["signature"]["signature"] = Value::from("abcd");
    assert!(!schema_accepts(&value), "short signature must be rejected");

    // Wrong signing domain.
    let mut value = valid_envelope_value();
    value["signature"]["signing_domain"] = Value::from("AEON_RECALL_ENVELOPE_V1");
    assert!(!schema_accepts(&value), "signing_domain is frozen");

    // Missing key_id.
    let mut value = valid_envelope_value();
    value["signature"].as_object_mut().unwrap().remove("key_id");
    assert!(!schema_accepts(&value), "key_id is required");

    // The signed payload digest is always recomputable from the public payload
    // and frozen signing domain.
    let mut value = valid_envelope_value();
    value["signature"]["signed_payload_digest"]["public_recomputable"] = Value::from(false);
    assert!(
        !schema_accepts(&value),
        "signed_payload_digest must declare public_recomputable=true"
    );
}

// ── 5. signature envelope strictness ─────────────────────────────────────────

#[test]
fn algorithm_is_frozen_to_a_single_constant() {
    assert_eq!(RECALL_SIGNATURE_ALGORITHM, "ed25519");
    for bad in ["", "ED25519", "ed25519ph", "hmac-sha256", "none", "rsa"] {
        let mut env = envelope(base_payload());
        env.signature.algorithm = bad.to_owned();
        assert!(
            env.validate().is_err(),
            "algorithm {bad:?} must be rejected; only an exact match is allowed"
        );
    }
}

#[test]
fn key_id_must_be_non_empty() {
    let mut env = envelope(base_payload());
    env.signature.key_id = String::new();
    assert!(env.validate().is_err());
}

#[test]
fn signed_payload_digest_must_be_publicly_recomputable() {
    let mut value = valid_envelope_value();
    value["signature"]["signed_payload_digest"]["public_recomputable"] = Value::from(false);
    let env: RecallEnvelopeV2 =
        serde_json::from_value(value).expect("false remains valid for other V2 digest positions");
    assert!(
        env.validate().is_err(),
        "signed_payload_digest is always publicly recomputable"
    );
}

#[test]
fn signature_must_be_lowercase_hex_of_exact_ed25519_length() {
    assert_eq!(RECALL_SIGNATURE_HEX_LEN, 128);

    let good = envelope(base_payload());
    assert_eq!(good.signature.signature.len(), RECALL_SIGNATURE_HEX_LEN);
    good.validate().expect("well-formed signature validates");

    let mut env = envelope(base_payload());
    env.signature.signature = env.signature.signature.to_uppercase();
    assert!(env.validate().is_err(), "uppercase hex must be rejected");

    let mut env = envelope(base_payload());
    env.signature.signature = "z".repeat(RECALL_SIGNATURE_HEX_LEN);
    assert!(env.validate().is_err(), "non-hex must be rejected");

    let mut env = envelope(base_payload());
    env.signature.signature = "ab".repeat(63);
    assert!(env.validate().is_err(), "126 chars must be rejected");

    let mut env = envelope(base_payload());
    env.signature.signature = "ab".repeat(65);
    assert!(env.validate().is_err(), "130 chars must be rejected");
}

#[test]
fn signed_payload_digest_must_be_lowercase_sha256_hex() {
    let mut value = serde_json::to_value(envelope(base_payload())).unwrap();
    value["signature"]["signed_payload_digest"]["algorithm"] = Value::from("hmac-sha256");
    assert!(
        serde_json::from_value::<RecallEnvelopeV2>(value).is_err(),
        "digest algorithm must be sha256"
    );

    let mut value = serde_json::to_value(envelope(base_payload())).unwrap();
    let uppercase = value["signature"]["signed_payload_digest"]["value"]
        .as_str()
        .unwrap()
        .to_uppercase();
    value["signature"]["signed_payload_digest"]["value"] = Value::from(uppercase);
    assert!(serde_json::from_value::<RecallEnvelopeV2>(value).is_err());

    let mut value = serde_json::to_value(envelope(base_payload())).unwrap();
    value["signature"]["signed_payload_digest"]["value"] = Value::from("ab".repeat(31));
    assert!(serde_json::from_value::<RecallEnvelopeV2>(value).is_err());
}

#[test]
fn signed_payload_digest_is_recomputed_from_full_signing_bytes() {
    let payload = base_payload();
    let env = envelope(payload.clone());

    let expected = recall_signed_payload_digest(&payload).expect("digest");
    assert_eq!(env.signature.signed_payload_digest, expected);

    // Substituting the digest of the bare canonical payload must fail.
    let mut tampered = envelope(payload.clone());
    let canonical = aeon_nexus_bridge::v2::canonical_json_v1_bytes(&payload).expect("canonical");
    tampered.signature.signed_payload_digest = RecallDigestV2::sha256(&canonical, true);
    assert!(
        tampered.validate().is_err(),
        "the un-domain-separated payload digest must not be accepted"
    );

    let mut swapped = envelope(payload);
    swapped.payload.agent_id = "agent-9999".to_owned();
    assert!(swapped.validate().is_err());
}

// ── 6. V1 baseline from untouched Nexus-temp main ────────────────────────────

/// Baseline generated by compiling `crates/aeon_nexus_bridge/src/lib.rs` as
/// fetched from Nexus-temp main at commit
/// 971fdfcd9b242ac69404d3c27b1821f971ab10b4 (file SHA-256
/// ef2c40f6559246ff3f9042f9465aaa6b52e21bbdeebc2c48d354456ed638dd90, verified
/// to contain no `pub mod v2`) in a separate crate, then running the identical
/// construction below. These constants come from that pristine build, not from
/// this working tree.
const V1_MAIN_COMMIT: &str = "971fdfcd9b242ac69404d3c27b1821f971ab10b4";
const V1_MAIN_CANONICAL: &str = concat!(
    r#"{"agent_handle":{"algorithm":"hmac-sha256","public_recomputable":false,"#,
    r#""value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
    r#""injected_hits":[{"content_digest":{"algorithm":"sha256","public_recomputable":true,"#,
    r#""value":"cdaf242e2e139dd255fbb56a691a9d0943a916a3235ee8d3cd73810d9d0b1ea2"},"#,
    r#""memory_id":"mem-1","score":500000}],"session_id":"session-a","#,
    r#""version":"aeon-nexus-memory-evidence-v1"}"#
);
const V1_MAIN_DIGEST: &str = "f8b8a4be520e6aba6e53b024410c72c4ba12de05139676a957199cd37b2e9f19";

#[test]
fn v1_matches_untouched_main_baseline() {
    use aeon_nexus_bridge::{
        canonical_bytes, memory_evidence_digest, MemoryEvidence, MemoryEvidenceHit,
    };

    assert_eq!(
        V1_MAIN_COMMIT.len(),
        40,
        "baseline records a full commit sha"
    );

    let evidence = MemoryEvidence::new(
        TypedDigest {
            algorithm: "hmac-sha256".to_owned(),
            value: "a".repeat(64),
            public_recomputable: false,
        },
        Some("session-a".to_owned()),
        vec![MemoryEvidenceHit::new("mem-1", b"content one", Some(0.5)).expect("hit")],
    );

    let canonical =
        String::from_utf8(canonical_bytes(&evidence).expect("canonical")).expect("utf8");
    assert_eq!(
        canonical, V1_MAIN_CANONICAL,
        "V1 canonical bytes diverged from untouched main @ {V1_MAIN_COMMIT}"
    );

    let digest = memory_evidence_digest(&evidence).expect("digest");
    assert_eq!(
        digest.value, V1_MAIN_DIGEST,
        "V1 digest diverged from untouched main @ {V1_MAIN_COMMIT}"
    );
    assert_eq!(digest.algorithm, "sha256");
    assert!(digest.public_recomputable);
}

// ── 2b. canonical UUID wire format ───────────────────────────────────────────

/// The same 128-bit value in every representation RFC 4122 tolerates. All but
/// the first must be rejected: they parse to an identical UUID but serialize to
/// different canonical bytes, so accepting them would let two parties agree on
/// the identifier while disagreeing on the signature.
const UUID_SAME_VALUE_VARIANTS: [(&str, &str); 5] = [
    ("uppercase", "3F2504E0-4F89-41D3-9A0C-0305E82C3301"),
    ("mixed case", "3f2504E0-4f89-41d3-9a0c-0305e82c3301"),
    ("simple (unhyphenated)", "3f2504e04f8941d39a0c0305e82c3301"),
    ("braced", "{3f2504e0-4f89-41d3-9a0c-0305e82c3301}"),
    ("urn:uuid", "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
];

#[test]
fn canonical_uuid_accepts_only_lowercase_hyphenated_36_chars() {
    let good = CanonicalUuid::parse(REQUEST_ID).expect("canonical form is accepted");
    assert_eq!(good.to_canonical_string(), REQUEST_ID);
    assert_eq!(REQUEST_ID.len(), 36);

    for (label, variant) in UUID_SAME_VALUE_VARIANTS {
        // Every variant is a *valid* UUID as far as the uuid crate is concerned...
        assert!(
            uuid::Uuid::parse_str(variant).is_ok(),
            "{label} should parse as a UUID; the test is only meaningful if it does"
        );
        // ...and every one of them must still be rejected here.
        assert!(
            CanonicalUuid::parse(variant).is_err(),
            "{label} form must be rejected: {variant}"
        );
    }
}

#[test]
fn canonical_uuid_rejects_malformed_shapes() {
    for bad in [
        "",
        "3f2504e0-4f89-41d3-9a0c-0305e82c330",   // 35 chars
        "3f2504e0-4f89-41d3-9a0c-0305e82c33011", // 37 chars
        "3f2504e0_4f89_41d3_9a0c_0305e82c3301",  // underscores
        "3g2504e0-4f89-41d3-9a0c-0305e82c3301",  // non-hex
        "3f2504e04-f89-41d3-9a0c-0305e82c3301",  // hyphens misplaced
    ] {
        assert!(CanonicalUuid::parse(bad).is_err(), "must reject {bad:?}");
    }
}

#[test]
fn non_canonical_uuid_is_rejected_at_deserialization() {
    for (label, variant) in UUID_SAME_VALUE_VARIANTS {
        let mut value = valid_envelope_value();
        value["payload"]["request_id"] = Value::from(variant);
        assert!(
            serde_json::from_value::<RecallEnvelopeV2>(value.clone()).is_err(),
            "{label} request_id must be rejected by the Rust types"
        );

        let mut value = valid_envelope_value();
        value["payload"]["run_id"] = Value::from(variant);
        assert!(
            serde_json::from_value::<RecallEnvelopeV2>(value).is_err(),
            "{label} run_id must be rejected by the Rust types"
        );
    }
}

#[test]
fn schema_rejects_non_canonical_uuid() {
    for (label, variant) in UUID_SAME_VALUE_VARIANTS {
        let mut value = valid_envelope_value();
        value["payload"]["request_id"] = Value::from(variant);
        assert!(
            !schema_accepts(&value),
            "{label} request_id must be rejected by the JSON Schema too"
        );
    }

    // And the canonical form still passes, so the pattern is not simply
    // rejecting everything.
    assert!(schema_accepts(&valid_envelope_value()));
}

// ── 3b. complete envelope fixture ────────────────────────────────────────────

fn envelope_fixture_path() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/envelope.json"
    )
}

/// Diagnostic: prints the exact bytes `envelope.json` must contain.
#[test]
fn emit_envelope_fixture() {
    let payload_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/payload.json"
    );
    let raw = std::fs::read_to_string(payload_path).expect("payload.json present");
    let payload: RecallEnvelopeV2Payload = serde_json::from_str(&raw).expect("parses");
    let env = envelope(payload);
    println!(
        "ENVELOPE_JSON={}",
        serde_json::to_string(&env).expect("serialize")
    );
}

fn checked_in_envelope() -> RecallEnvelopeV2 {
    let raw = std::fs::read_to_string(envelope_fixture_path()).expect("envelope.json present");
    serde_json::from_str(&raw).expect("envelope.json deserializes")
}

#[test]
fn envelope_fixture_satisfies_the_schema() {
    let raw = std::fs::read_to_string(envelope_fixture_path()).expect("envelope.json present");
    let value: Value = serde_json::from_str(&raw).expect("valid JSON");
    assert!(
        schema_accepts(&value),
        "the checked-in envelope must satisfy the published schema"
    );
}

#[test]
fn envelope_fixture_deserializes_and_validates() {
    checked_in_envelope()
        .validate()
        .expect("checked-in envelope validates");
}

#[test]
fn envelope_fixture_payload_matches_payload_and_vector_files() {
    let env = checked_in_envelope();

    let payload_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/payload.json"
    );
    let payload_raw = std::fs::read_to_string(payload_path).expect("payload.json present");
    let standalone: RecallEnvelopeV2Payload =
        serde_json::from_str(&payload_raw).expect("payload.json parses");
    assert_eq!(
        env.payload, standalone,
        "envelope.json payload must equal payload.json"
    );

    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/vector.json"
    );
    let vector: Value =
        serde_json::from_str(&std::fs::read_to_string(vector_path).expect("vector.json"))
            .expect("valid JSON");

    let canonical = String::from_utf8(
        aeon_nexus_bridge::v2::canonical_json_v1_bytes(&env.payload).expect("canonical"),
    )
    .expect("utf8");
    assert_eq!(
        canonical,
        vector["canonical_json"].as_str().expect("canonical_json"),
        "envelope payload canonical bytes must match vector.json"
    );
}

#[test]
fn envelope_fixture_digest_matches_sha256_of_signing_bytes() {
    let env = checked_in_envelope();
    let signing = recall_signing_bytes(&env.payload).expect("signing bytes");
    assert_eq!(
        env.signature.signed_payload_digest.value(),
        aeon_nexus_bridge::v2::sha256_hex(&signing)
    );
    assert_eq!(
        env.signature.signed_payload_digest,
        recall_signed_payload_digest(&env.payload).expect("digest")
    );
}

/// The one place this crate touches a public key: proving the checked-in
/// signature actually verifies. This is vector validation, not a runtime
/// verification path -- S0.3 owns that.
#[test]
fn envelope_fixture_signature_verifies_with_the_checked_in_public_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/vector.json"
    );
    let vector: Value =
        serde_json::from_str(&std::fs::read_to_string(vector_path).expect("vector.json"))
            .expect("valid JSON");

    let pk_hex = vector["ed25519_public_key_hex"]
        .as_str()
        .expect("public key");
    let pk_bytes: [u8; 32] = decode_hex(pk_hex).try_into().expect("32-byte public key");
    let verifying = VerifyingKey::from_bytes(&pk_bytes).expect("valid public key");

    let env = checked_in_envelope();
    let sig_bytes: [u8; 64] = decode_hex(&env.signature.signature)
        .try_into()
        .expect("64-byte signature");
    let signature = Signature::from_bytes(&sig_bytes);

    let signing = recall_signing_bytes(&env.payload).expect("signing bytes");
    verifying
        .verify(&signing, &signature)
        .expect("checked-in signature must verify over the checked-in signing bytes");

    // And must NOT verify over tampered bytes.
    let mut tampered = env.payload.clone();
    tampered.agent_id = "agent-9999".to_owned();
    let tampered_bytes = recall_signing_bytes(&tampered).expect("signing bytes");
    assert!(
        verifying.verify(&tampered_bytes, &signature).is_err(),
        "signature must not verify over a modified payload"
    );
}

// ── Artifact manifest enforcement ────────────────────────────────────────────

/// Every artifact AEON-IQ vendors in S0.2 is hashed here. Editing a fixture or
/// the schema without deliberately updating `MANIFEST.sha256` fails this test.
///
/// The manifest -- not this file, and not PROTOCOL.md -- is the single source
/// of truth for artifact hashes, so there is exactly one place to update and
/// nothing that can silently drift out of agreement with it.
#[test]
fn artifact_manifest_matches_checked_in_files() {
    use sha2::{Digest, Sha256};

    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = crate_root.join("vectors/recall_envelope_v2/MANIFEST.sha256");
    let manifest = std::fs::read_to_string(&manifest_path).expect("MANIFEST.sha256 present");

    let mut checked = 0usize;
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (expected, relative) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("malformed manifest line: {line}"));

        let bytes = std::fs::read(crate_root.join(relative))
            .unwrap_or_else(|error| panic!("manifest lists missing file {relative}: {error}"));
        let actual = to_lowercase_hex(&Sha256::digest(&bytes));

        assert_eq!(
            actual, expected,
            "\n{relative} does not match MANIFEST.sha256.\n  expected {expected}\n  actual   {actual}\n\
             If the change was intentional, update vectors/recall_envelope_v2/MANIFEST.sha256."
        );
        checked += 1;
    }

    assert_eq!(
        checked, 6,
        "manifest must cover exactly the schema, PROTOCOL.md and the four \
         vector fixtures -- and must never list itself"
    );
    assert!(
        !manifest.contains("MANIFEST.sha256"),
        "the manifest must not list itself; that hash could never be satisfied"
    );
}

/// The manifest is worthless if it can pass while listing nothing, or while
/// pointing at files that do not exist. Prove it actually discriminates.
#[test]
fn artifact_manifest_detects_a_modified_file() {
    use sha2::{Digest, Sha256};

    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let payload = std::fs::read(crate_root.join("vectors/recall_envelope_v2/payload.json"))
        .expect("payload.json present");

    let mut tampered = payload.clone();
    tampered.extend_from_slice(b" ");
    assert_ne!(
        to_lowercase_hex(&Sha256::digest(&tampered)),
        to_lowercase_hex(&Sha256::digest(&payload)),
        "a one-byte change must change the digest"
    );

    let manifest =
        std::fs::read_to_string(crate_root.join("vectors/recall_envelope_v2/MANIFEST.sha256"))
            .expect("MANIFEST.sha256 present");
    assert!(
        !manifest.contains(&to_lowercase_hex(&Sha256::digest(&tampered))),
        "the tampered digest must not appear in the manifest"
    );
    for relative in [
        "schema/recall_envelope_v2.schema.json",
        "schema/recall_envelope_v2/PROTOCOL.md",
        "vectors/recall_envelope_v2/payload.json",
        "vectors/recall_envelope_v2/vector.json",
        "vectors/recall_envelope_v2/envelope.json",
        "vectors/recall_envelope_v2/canonicalization_strings.json",
    ] {
        assert!(manifest.contains(relative), "manifest must list {relative}");
    }
}

// ── preserve_order conformance ───────────────────────────────────────────────

/// `aeon-canonical-json-v1` must not depend on serde_json's `preserve_order`
/// feature remaining disabled -- any transitive dependency in the workspace can
/// enable it, silently flipping `serde_json::Map` from sorted `BTreeMap` to
/// insertion-ordered `IndexMap`.
///
/// The canonicaliser sorts keys explicitly rather than inheriting `Map` order,
/// so these values must hold under either setting. This test pins them; the
/// companion isolated build with `preserve_order` on runs the same assertions.
#[test]
fn canonical_values_are_independent_of_map_ordering() {
    let payload_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/payload.json"
    );
    let raw = std::fs::read_to_string(payload_path).expect("payload.json present");
    let payload: RecallEnvelopeV2Payload = serde_json::from_str(&raw).expect("parses");

    let canonical = String::from_utf8(
        aeon_nexus_bridge::v2::canonical_json_v1_bytes(&payload).expect("canonical"),
    )
    .expect("utf8");
    let signing = recall_signing_bytes(&payload).expect("signing bytes");
    let digest = recall_signed_payload_digest(&payload).expect("digest");

    // Keys ascend by byte order regardless of how the Map stores them.
    let agent_at = canonical.find("\"agent_id\"").expect("agent_id");
    let canon_at = canonical
        .find("\"canonicalization_version\"")
        .expect("canonicalization_version");
    let tenant_at = canonical.find("\"tenant_id\"").expect("tenant_id");
    assert!(
        agent_at < canon_at && canon_at < tenant_at,
        "keys must be sorted"
    );

    assert_eq!(
        aeon_nexus_bridge::v2::sha256_hex(canonical.as_bytes()),
        "b7ac1d6ad86259f6e7ea32895721f8445a4c31a82b77f99edf18a6eacdd21db7",
        "canonical payload bytes changed"
    );
    // SHA-256 over the signing bytes IS signed_payload_digest, so both the
    // computed value and the stored one must equal the pinned constant.
    assert_eq!(
        aeon_nexus_bridge::v2::sha256_hex(&signing),
        "f3f326513b66184fbd349b62696373fe469659bda379fb3b773b032b8f85d71a",
        "signing bytes changed"
    );
    assert_eq!(
        digest.value(),
        "f3f326513b66184fbd349b62696373fe469659bda379fb3b773b032b8f85d71a",
        "signed_payload_digest changed"
    );
    assert_eq!(
        to_lowercase_hex(&signing[..24]),
        "41454f4e5f524543414c4c5f454e56454c4f50455f563200",
        "domain prefix changed"
    );

    // And the checked-in Ed25519 signature still verifies over these bytes.
    let key = SigningKey::from_bytes(&ED25519_SEED);
    assert_eq!(
        to_lowercase_hex(&key.sign(&signing).to_bytes()),
        "389c6b6b32956dc5aa8b9f72e0abdeb2c095a5c83db1b74ee4e2ebcd757741c5\
         c408ff77d0c011e31e3810f4e859098fecf331ca7a1efc20457ce580d9848905",
        "Ed25519 signature over the signing bytes changed"
    );
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2), "hex must have even length");
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn envelope_fixture_reserializes_byte_exactly() {
    let raw = std::fs::read_to_string(envelope_fixture_path()).expect("envelope.json present");
    let expected = raw.trim_end_matches('\n');
    let env: RecallEnvelopeV2 = serde_json::from_str(expected).expect("parses");
    let reserialized = serde_json::to_string(&env).expect("serialize");
    assert_eq!(
        reserialized, expected,
        "envelope.json must round-trip byte-exactly"
    );
}

#[test]
fn canonical_string_escaping_is_frozen() {
    let input = serde_json::json!({
        "composed": "\u{00e9}",
        "decomposed": "e\u{0301}",
        "emoji": "\u{1f600}",
        "quote": "\"",
        "backslash": "\\",
        "newline": "\n",
        "tab": "\t",
        "control": "\u{0001}",
        "slash": "/",
        "line_separator": "\u{2028}",
        "paragraph_separator": "\u{2029}"
    });
    let actual = aeon_nexus_bridge::v2::canonical_json_v1_bytes(&input).unwrap();
    let expected = concat!(
        "{\"backslash\":\"\\\\\",\"composed\":\"",
        "\u{00e9}",
        "\",\"control\":\"\\u0001\",\"decomposed\":\"e",
        "\u{0301}",
        "\",\"emoji\":\"",
        "\u{1f600}",
        "\",\"line_separator\":\"",
        "\u{2028}",
        "\",\"newline\":\"\\n\",\"paragraph_separator\":\"",
        "\u{2029}",
        "\",\"quote\":\"\\\"\",\"slash\":\"/\",\"tab\":\"\\t\"}"
    );
    assert_eq!(actual, expected.as_bytes());

    let composed =
        aeon_nexus_bridge::v2::canonical_json_v1_bytes(&serde_json::json!("\u{00e9}")).unwrap();
    let decomposed =
        aeon_nexus_bridge::v2::canonical_json_v1_bytes(&serde_json::json!("e\u{0301}")).unwrap();
    assert_ne!(
        composed, decomposed,
        "canonicalization must not normalize Unicode"
    );
}

#[test]
fn invalid_lone_surrogate_is_rejected_before_canonicalization() {
    assert!(serde_json::from_str::<Value>(r#""\uD800""#).is_err());
    assert!(serde_json::from_str::<Value>(r#""\uDC00""#).is_err());
}

#[test]
fn every_control_character_uses_the_frozen_escape() {
    for codepoint in 0_u32..=0x1f {
        let scalar = char::from_u32(codepoint).unwrap().to_string();
        let actual = aeon_nexus_bridge::v2::canonical_json_v1_bytes(&scalar).unwrap();
        let expected = match codepoint {
            0x08 => r#""\b""#.to_owned(),
            0x09 => r#""\t""#.to_owned(),
            0x0a => r#""\n""#.to_owned(),
            0x0c => r#""\f""#.to_owned(),
            0x0d => r#""\r""#.to_owned(),
            other => format!(r#""\u00{other:02x}""#),
        };
        assert_eq!(
            actual,
            expected.as_bytes(),
            "wrong escape for U+{codepoint:04X}"
        );
    }
}

#[test]
fn language_neutral_canonicalization_string_vector_matches() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/recall_envelope_v2/canonicalization_strings.json"
    );
    let raw = std::fs::read_to_string(path).expect("canonicalization vector present");
    let vector: Value = serde_json::from_str(&raw).expect("canonicalization vector is JSON");
    let cases = vector["cases"].as_array().expect("cases array");

    let mut encodings = std::collections::BTreeMap::new();
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let value = case["value"].as_str().expect("case value");
        let expected = case["canonical_utf8_hex"].as_str().expect("canonical hex");
        let actual = aeon_nexus_bridge::v2::canonical_json_v1_bytes(value).unwrap();
        assert_eq!(to_lowercase_hex(&actual), expected, "case {name}");
        encodings.insert(name, actual);
    }

    for pair in vector["distinct_pairs"].as_array().expect("distinct pairs") {
        let left = pair["left"].as_str().expect("left case");
        let right = pair["right"].as_str().expect("right case");
        assert_ne!(
            encodings.get(left).expect("left encoding"),
            encodings.get(right).expect("right encoding"),
            "{left} and {right} must remain byte-distinct"
        );
    }
}
