//! RecallEnvelopeV2 — the replay-resistant recall attestation contract (S0.1).
//!
//! This module defines wire shape, canonical bytes, signing bytes and strict
//! validation. It deliberately does **not** sign or verify: producing and
//! checking Ed25519 signatures is S0.2/S0.3 work. The only place a real
//! signature appears is the checked-in test vector.
//!
//! V1 (`crate::MemoryEvidence`) is untouched, undeprecated, and there is no
//! conversion in either direction. The two contracts are mutually unparseable
//! by construction and there are tests that prove it.
//!
//! # Replay resistance
//!
//! The payload carries a `nonce` and an `issued_at`/`expires_at` window, and
//! both are covered by the signature. This module validates their *shape* only.
//! It does not track nonce reuse and does not compare timestamps to a clock —
//! that is a verifier concern (S0.3). Shape validity here is necessary for
//! replay resistance, not sufficient for it.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Write as _};

use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{MemoryScore, SHA256_ALGORITHM};

// ── Frozen constants ─────────────────────────────────────────────────────────

/// Exact `protocol_version` value. Any other value fails closed.
pub const RECALL_PROTOCOL_VERSION: &str = "aeon-recall-envelope-v2";

/// Exact `canonicalization_version` value.
///
/// Named for what it is: a recursive sorted-key JSON encoding defined by this
/// crate. It is deliberately **not** claimed to implement RFC 8785 / JCS.
pub const RECALL_CANONICALIZATION_VERSION: &str = "aeon-canonical-json-v1";

/// Human-readable domain label carried in the signature envelope.
pub const RECALL_SIGNING_DOMAIN_LABEL: &str = "AEON_RECALL_ENVELOPE_V2";

/// The exact byte prefix hashed and signed, including the NUL separator.
///
/// Signing bytes are `RECALL_SIGNING_DOMAIN_BYTES || canonical(payload)`.
/// The label above is what travels on the wire; these bytes are what the
/// cryptography actually commits to. They must never diverge.
pub const RECALL_SIGNING_DOMAIN_BYTES: &[u8] = b"AEON_RECALL_ENVELOPE_V2\0";

/// Recommended envelope lifetime when a producer has no reason to choose.
pub const RECALL_DEFAULT_TTL_MS: i64 = 30_000;
/// Hard upper bound on `expires_at - issued_at`.
pub const RECALL_MAX_TTL_MS: i64 = 120_000;

/// Lower bound on the requested `limit`. A recall asking for zero results is
/// not a meaningful thing to attest, so it is rejected rather than tolerated.
pub const RECALL_MIN_LIMIT: u32 = 1;
/// Hard upper bound on the requested `limit`.
pub const RECALL_MAX_LIMIT: u32 = 100;
/// Hard upper bound on `hits.len()`.
pub const RECALL_MAX_HITS: usize = 100;

/// Nonce is exactly 32 random bytes, lowercase-hex encoded.
pub const RECALL_NONCE_BYTES: usize = 32;
/// Therefore exactly 64 hex characters.
pub const RECALL_NONCE_HEX_LEN: usize = RECALL_NONCE_BYTES * 2;

/// The only signature algorithm this contract accepts.
///
/// Deliberately a single frozen constant rather than an open string: an
/// attacker-chosen `algorithm` is how signature schemes get downgraded, and a
/// verifier that trusts the envelope to name its own algorithm has no way to
/// refuse a weaker one.
pub const RECALL_SIGNATURE_ALGORITHM: &str = "ed25519";

/// Ed25519 signatures are exactly 64 bytes, so exactly 128 lowercase-hex chars.
pub const RECALL_SIGNATURE_BYTES: usize = 64;
/// Therefore exactly 128 hex characters.
pub const RECALL_SIGNATURE_HEX_LEN: usize = RECALL_SIGNATURE_BYTES * 2;

/// Length of a lowercase-hex SHA-256 digest value.
const SHA256_HEX_LEN: usize = 64;

/// A canonical UUID is exactly 36 characters: 32 lowercase hex plus 4 hyphens.
pub const UUID_CANONICAL_LEN: usize = 36;
/// Byte offsets at which a canonical UUID carries a hyphen.
const UUID_HYPHEN_OFFSETS: [usize; 4] = [8, 13, 18, 23];

// ── Canonical UUID ───────────────────────────────────────────────────────────

/// A UUID restricted to exactly one wire representation.
///
/// `Uuid::parse_str` is deliberately **not** sufficient here. It accepts every
/// form RFC 4122 tolerates -- uppercase, unhyphenated "simple", braced, and
/// `urn:uuid:` -- all of which parse to the *same* 128-bit value but produce
/// *different* canonical JSON bytes and therefore different signatures. Two
/// parties could then agree on the identifier while disagreeing on the digest.
///
/// So the input string is validated character by character before parsing:
/// exactly 36 characters, lowercase hex, hyphens only at offsets 8/13/18/23.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalUuid(Uuid);

impl CanonicalUuid {
    /// Parse a UUID in canonical lowercase hyphenated form, rejecting all
    /// other representations.
    pub fn parse(input: &str) -> Result<Self, RecallError> {
        if input.len() != UUID_CANONICAL_LEN {
            return Err(RecallError::NonCanonicalUuid(input.to_owned()));
        }
        for (offset, byte) in input.bytes().enumerate() {
            let ok = if UUID_HYPHEN_OFFSETS.contains(&offset) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            };
            if !ok {
                return Err(RecallError::NonCanonicalUuid(input.to_owned()));
            }
        }
        // Shape is already proven; this cannot fail, but never unwrap on input.
        let uuid =
            Uuid::parse_str(input).map_err(|_| RecallError::NonCanonicalUuid(input.to_owned()))?;
        Ok(Self(uuid))
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    /// The single permitted wire form.
    pub fn to_canonical_string(self) -> String {
        self.0.hyphenated().to_string()
    }
}

impl std::str::FromStr for CanonicalUuid {
    type Err = RecallError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl fmt::Display for CanonicalUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}

impl Serialize for CanonicalUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `Uuid::hyphenated` is lowercase by definition, so what goes out is
        // exactly what `parse` would accept back in.
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

/// The strict SHA-256 digest used only by RecallEnvelopeV2.
///
/// Unlike the frozen V1 [`crate::TypedDigest`], this type cannot represent an
/// unsupported algorithm or malformed value. Its custom deserializer also
/// rejects unknown and duplicate members before canonicalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecallDigestV2 {
    algorithm: String,
    value: String,
    public_recomputable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallDigestV2Wire {
    algorithm: String,
    value: String,
    public_recomputable: bool,
}

impl RecallDigestV2 {
    /// Compute a valid V2 SHA-256 digest.
    pub fn sha256(bytes: &[u8], public_recomputable: bool) -> Self {
        Self {
            algorithm: SHA256_ALGORITHM.to_owned(),
            value: sha256_hex(bytes),
            public_recomputable,
        }
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn public_recomputable(&self) -> bool {
        self.public_recomputable
    }

    fn from_wire(wire: RecallDigestV2Wire) -> Result<Self, String> {
        if wire.algorithm != SHA256_ALGORITHM {
            return Err(format!(
                "digest algorithm must be exactly {SHA256_ALGORITHM}"
            ));
        }
        if wire.value.len() != SHA256_HEX_LEN
            || !wire
                .value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "digest value must be exactly {SHA256_HEX_LEN} lowercase hexadecimal characters"
            ));
        }
        Ok(Self {
            algorithm: wire.algorithm,
            value: wire.value,
            public_recomputable: wire.public_recomputable,
        })
    }
}

impl<'de> Deserialize<'de> for RecallDigestV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RecallDigestV2Wire::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ── Present-but-nullable optional fields ─────────────────────────────────────

/// An optional value whose key is **always** present on the wire.
///
/// `None` encodes as explicit JSON `null`; an absent key is a hard error.
///
/// This exists because `Option<T>` cannot express that rule: serde's derive
/// silently treats a missing field of type `Option<T>` as `None`, so `{...}`
/// and `{"session_id":null,...}` would both parse while producing *different*
/// canonical bytes and therefore different signatures. Each wire field uses a
/// field-level deserializer without `default`, making a missing key fail as a
/// missing field. Present values deserialize directly from the original Serde
/// stream, preserving nested duplicate-key detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nullable<T>(Option<T>);

impl<T> Nullable<T> {
    /// A present, non-null value.
    pub fn some(value: T) -> Self {
        Self(Some(value))
    }

    /// A present key with an explicit `null` value.
    ///
    /// For `provenance_digest` this means "no authenticated provenance claim";
    /// for `authority_label` it means "no authenticated authority claim",
    /// semantically AUTH_0. It never means "unknown" or "zero".
    pub fn null() -> Self {
        Self(None)
    }

    pub fn as_option(&self) -> Option<&T> {
        self.0.as_ref()
    }

    pub fn is_null(&self) -> bool {
        self.0.is_none()
    }

    pub fn into_option(self) -> Option<T> {
        self.0
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<T: Serialize> Serialize for Nullable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(value) => value.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Nullable<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Nullable)
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// One ranked memory returned by a recall, as attested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallHitV2 {
    pub memory_id: String,
    pub memory_version_id: String,
    pub content_digest: RecallDigestV2,
    /// Zero-based, contiguous, and equal to this hit's index in `hits`.
    pub rank: u32,
    /// Fixed-point score in micros. Never a float, never zero-substituted:
    /// an absent score is explicit `null`.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub score_micros: Nullable<MemoryScore>,
    /// `null` = no authenticated provenance claim.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provenance_digest: Nullable<RecallDigestV2>,
    /// `null` = no authenticated authority claim (AUTH_0).
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub authority_label: Nullable<String>,
}

/// The signed body of a recall attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallEnvelopeV2Payload {
    pub protocol_version: String,
    pub canonicalization_version: String,
    pub request_id: CanonicalUuid,
    /// 32 random bytes, lowercase hex (64 chars).
    pub nonce: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    /// Required. Must be a stable **opaque** identifier — never a display
    /// name, email address, or other human-readable identity data.
    pub tenant_id: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub workspace_id: Nullable<String>,
    /// Required, and opaque on the same terms as `tenant_id`.
    pub agent_id: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub session_id: Nullable<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub mission_id: Nullable<String>,
    pub run_id: CanonicalUuid,
    /// SHA-256 over the exact UTF-8 query bytes, with no normalization.
    pub query_digest: RecallDigestV2,
    /// The requested cap. This is a *request parameter*, not a result count:
    /// `hits.len()` is the count, and no redundant count field exists that
    /// could contradict it while signed.
    pub limit: u32,
    pub retrieval_policy_digest: RecallDigestV2,
    pub embedding_config_digest: RecallDigestV2,
    /// Ordered. JSON arrays preserve order under canonicalization; only object
    /// keys are sorted.
    pub hits: Vec<RecallHitV2>,
}

/// Detached signature over `RECALL_SIGNING_DOMAIN_BYTES || canonical(payload)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallSignatureV2 {
    pub algorithm: String,
    pub key_id: String,
    /// Lowercase hex.
    pub signature: String,
    /// `SHA256(RECALL_SIGNING_DOMAIN_BYTES || canonical(payload))` — the digest
    /// of the *signing bytes*, not of the bare canonical payload, so it
    /// inherits domain separation.
    pub signed_payload_digest: RecallDigestV2,
    /// Must equal [`RECALL_SIGNING_DOMAIN_LABEL`]. Never caller-selectable.
    pub signing_domain: String,
}

/// A recall attestation: signed payload plus its detached signature.
///
/// `payload.protocol_version` is authoritative and is deliberately not
/// duplicated at this level, so there is no second copy to disagree with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallEnvelopeV2 {
    pub payload: RecallEnvelopeV2Payload,
    pub signature: RecallSignatureV2,
}

// ── aeon-canonical-json-v1 ───────────────────────────────────────────────────

/// Serialize `value` to canonical JSON bytes.
///
/// Rules: preserve Unicode scalars without normalization; emit ordinary
/// non-ASCII, slash, U+2028 and U+2029 directly as UTF-8; escape quote,
/// backslash and the five short control escapes; encode other U+0000 through
/// U+001F scalars as lowercase `\u00xx`; sort object keys by raw UTF-8 bytes;
/// preserve array order; emit no insignificant whitespace; reject floats.
/// Invalid lone surrogates are rejected by the JSON parser because Rust strings
/// contain only Unicode scalar values.
///
/// Keys are sorted explicitly here rather than relying on `serde_json::Map`
/// iteration order. That order depends on serde_json's `preserve_order`
/// feature, which any transitive dependency in the workspace can turn on —
/// flipping `Map` from `BTreeMap` (sorted) to `IndexMap` (insertion-ordered)
/// and silently changing every signature this crate produces. Canonical output
/// must not be hostage to a feature flag nobody is watching, so this function
/// is correct under either setting, and the golden vectors prove it.
pub fn canonical_json_v1_bytes<T>(value: &T) -> Result<Vec<u8>, RecallError>
where
    T: Serialize + ?Sized,
{
    let value = serde_json::to_value(value).map_err(RecallError::Serialization)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), RecallError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            // No float may enter canonical bytes: formatting is not stable
            // across implementations and NaN/Infinity have no JSON encoding.
            if number.is_f64() {
                return Err(RecallError::FloatInCanonicalBytes(number.to_string()));
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => write_json_string(string, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_canonical(&map[key.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_json_string(value: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    out.push(b'"');
    for scalar in value.chars() {
        match scalar {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{0009}' => out.extend_from_slice(br#"\t"#),
            '\u{000a}' => out.extend_from_slice(br#"\n"#),
            '\u{000c}' => out.extend_from_slice(br#"\f"#),
            '\u{000d}' => out.extend_from_slice(br#"\r"#),
            control if control <= '\u{001f}' => {
                let byte = control as u8;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(byte >> 4) as usize]);
                out.push(HEX[(byte & 0x0f) as usize]);
            }
            ordinary => {
                let mut encoded = [0_u8; 4];
                out.extend_from_slice(ordinary.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ── Signing bytes and digest ─────────────────────────────────────────────────

/// The exact bytes an AEON signer signs and a Nexus verifier re-derives.
pub fn recall_signing_bytes(payload: &RecallEnvelopeV2Payload) -> Result<Vec<u8>, RecallError> {
    let canonical = canonical_json_v1_bytes(payload)?;
    let mut bytes = Vec::with_capacity(RECALL_SIGNING_DOMAIN_BYTES.len() + canonical.len());
    bytes.extend_from_slice(RECALL_SIGNING_DOMAIN_BYTES);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

/// `SHA256(signing bytes)` — the value that belongs in
/// [`RecallSignatureV2::signed_payload_digest`].
pub fn recall_signed_payload_digest(
    payload: &RecallEnvelopeV2Payload,
) -> Result<RecallDigestV2, RecallError> {
    Ok(RecallDigestV2::sha256(
        &recall_signing_bytes(payload)?,
        true,
    ))
}

// ── Validation ───────────────────────────────────────────────────────────────

impl RecallEnvelopeV2Payload {
    /// Validate payload shape. Fails closed on every rule.
    ///
    /// Does not consult a clock: `issued_at`/`expires_at` are checked for
    /// internal consistency and TTL bound only. Skew is verifier policy (S0.3).
    pub fn validate(&self) -> Result<(), RecallError> {
        if self.protocol_version != RECALL_PROTOCOL_VERSION {
            return Err(RecallError::ProtocolVersion(self.protocol_version.clone()));
        }
        if self.canonicalization_version != RECALL_CANONICALIZATION_VERSION {
            return Err(RecallError::CanonicalizationVersion(
                self.canonicalization_version.clone(),
            ));
        }

        validate_nonce(&self.nonce)?;

        if self.issued_at_unix_ms < 0 {
            return Err(RecallError::NegativeIssuedAt(self.issued_at_unix_ms));
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(RecallError::ExpiryNotAfterIssue {
                issued_at_unix_ms: self.issued_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
            });
        }
        let ttl_ms = self.expires_at_unix_ms - self.issued_at_unix_ms;
        if ttl_ms > RECALL_MAX_TTL_MS {
            return Err(RecallError::TtlTooLong {
                ttl_ms,
                max_ttl_ms: RECALL_MAX_TTL_MS,
            });
        }

        require_non_empty("tenant_id", &self.tenant_id)?;
        require_non_empty("agent_id", &self.agent_id)?;
        require_non_empty_nullable("workspace_id", &self.workspace_id)?;
        require_non_empty_nullable("session_id", &self.session_id)?;
        require_non_empty_nullable("mission_id", &self.mission_id)?;

        require_sha256_digest("query_digest", &self.query_digest)?;
        require_sha256_digest("retrieval_policy_digest", &self.retrieval_policy_digest)?;
        require_sha256_digest("embedding_config_digest", &self.embedding_config_digest)?;

        if self.limit < RECALL_MIN_LIMIT || self.limit > RECALL_MAX_LIMIT {
            return Err(RecallError::LimitOutOfRange {
                limit: self.limit,
                min_limit: RECALL_MIN_LIMIT,
                max_limit: RECALL_MAX_LIMIT,
            });
        }
        if self.hits.len() > RECALL_MAX_HITS {
            return Err(RecallError::TooManyHits {
                hits: self.hits.len(),
                max_hits: RECALL_MAX_HITS,
            });
        }
        if self.hits.len() > self.limit as usize {
            return Err(RecallError::HitsExceedLimit {
                hits: self.hits.len(),
                limit: self.limit,
            });
        }

        let mut memory_ids = BTreeSet::new();
        let mut memory_version_ids = BTreeSet::new();
        for (index, hit) in self.hits.iter().enumerate() {
            if hit.rank as usize != index {
                return Err(RecallError::RankMismatch {
                    index,
                    rank: hit.rank,
                });
            }
            require_non_empty("memory_id", &hit.memory_id)?;
            require_non_empty("memory_version_id", &hit.memory_version_id)?;
            require_sha256_digest("content_digest", &hit.content_digest)?;
            if let Some(digest) = hit.provenance_digest.as_option() {
                require_sha256_digest("provenance_digest", digest)?;
            }
            if let Some(label) = hit.authority_label.as_option() {
                require_non_empty("authority_label", label)?;
            }
            if !memory_ids.insert(hit.memory_id.as_str()) {
                return Err(RecallError::DuplicateMemoryId(hit.memory_id.clone()));
            }
            if !memory_version_ids.insert(hit.memory_version_id.as_str()) {
                return Err(RecallError::DuplicateMemoryVersionId(
                    hit.memory_version_id.clone(),
                ));
            }
        }

        Ok(())
    }
}

impl RecallEnvelopeV2 {
    /// Validate the payload, the signing domain, and the digest binding.
    ///
    /// This does **not** verify the signature itself — no key material enters
    /// this crate. It proves the envelope is well-formed and that
    /// `signed_payload_digest` really is the digest of this payload's signing
    /// bytes, so a mismatched or swapped payload cannot pass unnoticed.
    pub fn validate(&self) -> Result<(), RecallError> {
        self.payload.validate()?;

        if self.signature.signing_domain != RECALL_SIGNING_DOMAIN_LABEL {
            return Err(RecallError::SigningDomain(
                self.signature.signing_domain.clone(),
            ));
        }
        // Exact match, not "non-empty". An envelope does not get to nominate
        // its own algorithm: that is the classic downgrade vector.
        if self.signature.algorithm != RECALL_SIGNATURE_ALGORITHM {
            return Err(RecallError::UnsupportedAlgorithm(
                self.signature.algorithm.clone(),
            ));
        }
        require_non_empty("key_id", &self.signature.key_id)?;
        require_lowercase_hex("signature", &self.signature.signature)?;
        if self.signature.signature.len() != RECALL_SIGNATURE_HEX_LEN {
            return Err(RecallError::SignatureLength(self.signature.signature.len()));
        }
        require_sha256_digest(
            "signed_payload_digest",
            &self.signature.signed_payload_digest,
        )?;

        let expected = recall_signed_payload_digest(&self.payload)?;
        if self.signature.signed_payload_digest != expected {
            return Err(RecallError::SignedPayloadDigestMismatch {
                expected: expected.value().to_owned(),
                found: self.signature.signed_payload_digest.value().to_owned(),
            });
        }

        Ok(())
    }
}

fn validate_nonce(nonce: &str) -> Result<(), RecallError> {
    if nonce.len() != RECALL_NONCE_HEX_LEN {
        return Err(RecallError::NonceLength(nonce.len()));
    }
    if !nonce
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecallError::NonceCharset(nonce.to_owned()));
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), RecallError> {
    if value.is_empty() {
        return Err(RecallError::EmptyIdentifier(field));
    }
    Ok(())
}

fn require_non_empty_nullable(
    field: &'static str,
    value: &Nullable<String>,
) -> Result<(), RecallError> {
    match value.as_option() {
        Some(inner) => require_non_empty(field, inner),
        None => Ok(()),
    }
}

fn require_lowercase_hex(field: &'static str, value: &str) -> Result<(), RecallError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(RecallError::MalformedHex(field));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecallError::MalformedHex(field));
    }
    Ok(())
}

fn require_sha256_digest(field: &'static str, digest: &RecallDigestV2) -> Result<(), RecallError> {
    if digest.algorithm() != SHA256_ALGORITHM {
        return Err(RecallError::DigestAlgorithm {
            field,
            algorithm: digest.algorithm().to_owned(),
        });
    }
    if digest.value().len() != SHA256_HEX_LEN {
        return Err(RecallError::MalformedHex(field));
    }
    require_lowercase_hex(field, digest.value())
}

/// Lowercase-hex helper for building fixtures and test vectors.
pub fn to_lowercase_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

/// SHA-256 of arbitrary bytes, lowercase hex. Used by fixture generators.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_lowercase_hex(&Sha256::digest(bytes))
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RecallError {
    Serialization(serde_json::Error),
    FloatInCanonicalBytes(String),
    ProtocolVersion(String),
    CanonicalizationVersion(String),
    NonceLength(usize),
    NonceCharset(String),
    NegativeIssuedAt(i64),
    ExpiryNotAfterIssue {
        issued_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    },
    TtlTooLong {
        ttl_ms: i64,
        max_ttl_ms: i64,
    },
    LimitOutOfRange {
        limit: u32,
        min_limit: u32,
        max_limit: u32,
    },
    UnsupportedAlgorithm(String),
    SignatureLength(usize),
    NonCanonicalUuid(String),
    TooManyHits {
        hits: usize,
        max_hits: usize,
    },
    HitsExceedLimit {
        hits: usize,
        limit: u32,
    },
    RankMismatch {
        index: usize,
        rank: u32,
    },
    DuplicateMemoryId(String),
    DuplicateMemoryVersionId(String),
    EmptyIdentifier(&'static str),
    MalformedHex(&'static str),
    DigestAlgorithm {
        field: &'static str,
        algorithm: String,
    },
    SigningDomain(String),
    SignedPayloadDigestMismatch {
        expected: String,
        found: String,
    },
}

impl fmt::Display for RecallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => write!(f, "failed to serialize recall payload: {error}"),
            Self::FloatInCanonicalBytes(value) => write!(
                f,
                "floating-point value {value} may not enter canonical bytes"
            ),
            Self::ProtocolVersion(found) => write!(
                f,
                "protocol_version must be {RECALL_PROTOCOL_VERSION}, found {found}"
            ),
            Self::CanonicalizationVersion(found) => write!(
                f,
                "canonicalization_version must be {RECALL_CANONICALIZATION_VERSION}, found {found}"
            ),
            Self::NonceLength(len) => write!(
                f,
                "nonce must be exactly {RECALL_NONCE_HEX_LEN} hex characters ({RECALL_NONCE_BYTES} bytes), found {len}"
            ),
            Self::NonceCharset(_) => write!(f, "nonce must be lowercase hexadecimal"),
            Self::NegativeIssuedAt(value) => {
                write!(f, "issued_at_unix_ms must be >= 0, found {value}")
            }
            Self::ExpiryNotAfterIssue {
                issued_at_unix_ms,
                expires_at_unix_ms,
            } => write!(
                f,
                "expires_at_unix_ms ({expires_at_unix_ms}) must be strictly greater than issued_at_unix_ms ({issued_at_unix_ms})"
            ),
            Self::TtlTooLong { ttl_ms, max_ttl_ms } => {
                write!(f, "TTL {ttl_ms}ms exceeds maximum {max_ttl_ms}ms")
            }
            Self::LimitOutOfRange {
                limit,
                min_limit,
                max_limit,
            } => write!(f, "limit {limit} must be between {min_limit} and {max_limit}"),
            Self::UnsupportedAlgorithm(found) => write!(
                f,
                "algorithm must be exactly {RECALL_SIGNATURE_ALGORITHM}, found {found}"
            ),
            Self::NonCanonicalUuid(found) => write!(
                f,
                "uuid must be canonical lowercase hyphenated form ({UUID_CANONICAL_LEN} chars); \
                 uppercase, simple, braced and urn:uuid forms are rejected: {found}"
            ),
            Self::SignatureLength(len) => write!(
                f,
                "signature must be exactly {RECALL_SIGNATURE_HEX_LEN} hex characters ({RECALL_SIGNATURE_BYTES} bytes), found {len}"
            ),
            Self::TooManyHits { hits, max_hits } => {
                write!(f, "{hits} hits exceeds maximum {max_hits}")
            }
            Self::HitsExceedLimit { hits, limit } => {
                write!(f, "{hits} hits exceeds requested limit {limit}")
            }
            Self::RankMismatch { index, rank } => write!(
                f,
                "hit at index {index} declares rank {rank}; ranks must be zero-based and contiguous in array order"
            ),
            Self::DuplicateMemoryId(id) => write!(f, "duplicate memory_id: {id}"),
            Self::DuplicateMemoryVersionId(id) => write!(f, "duplicate memory_version_id: {id}"),
            Self::EmptyIdentifier(field) => write!(f, "{field} must not be empty"),
            Self::MalformedHex(field) => {
                write!(f, "{field} must be non-empty lowercase hexadecimal")
            }
            Self::DigestAlgorithm { field, algorithm } => write!(
                f,
                "{field} must use algorithm {SHA256_ALGORITHM}, found {algorithm}"
            ),
            Self::SigningDomain(found) => write!(
                f,
                "signing_domain must be {RECALL_SIGNING_DOMAIN_LABEL}, found {found}"
            ),
            Self::SignedPayloadDigestMismatch { expected, found } => write!(
                f,
                "signed_payload_digest mismatch: expected {expected}, found {found}"
            ),
        }
    }
}

impl Error for RecallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}
