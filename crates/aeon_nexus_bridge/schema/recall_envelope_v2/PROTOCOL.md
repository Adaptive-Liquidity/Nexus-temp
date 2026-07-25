# RecallEnvelopeV2 — normative protocol (S0.1)

Language-neutral specification of the AEON-IQ recall attestation contract.
The Rust implementation in `crates/aeon_nexus_bridge` is **one conforming
implementation**, not the definition. Where prose and code disagree, this
document and the checked-in vectors are authoritative.

- `protocol_version` — `aeon-recall-envelope-v2`
- `canonicalization_version` — `aeon-canonical-json-v1`

---

## 1. Structures

### 1.1 Envelope

```
RecallEnvelopeV2 {
  payload:   RecallEnvelopeV2Payload
  signature: RecallSignatureV2
}
```

`payload.protocol_version` is authoritative and is **not** duplicated at
envelope level. There is deliberately no second copy that could disagree with
it.

### 1.2 Payload

| Field | Type | Notes |
| --- | --- | --- |
| `protocol_version` | string | exactly `aeon-recall-envelope-v2` |
| `canonicalization_version` | string | exactly `aeon-canonical-json-v1` |
| `request_id` | canonical UUID | §3 |
| `nonce` | string | 64 lowercase hex chars = 32 random bytes |
| `issued_at_unix_ms` | integer | ≥ 0, milliseconds since Unix epoch |
| `expires_at_unix_ms` | integer | > `issued_at_unix_ms` |
| `tenant_id` | opaque id | required, non-empty, §10 |
| `workspace_id` | opaque id \| null | nullable |
| `agent_id` | opaque id | required, non-empty, §10 |
| `session_id` | opaque id \| null | nullable |
| `mission_id` | opaque id \| null | nullable |
| `run_id` | canonical UUID | §3 |
| `query_digest` | digest | §6 |
| `limit` | integer | 1 ≤ limit ≤ 100 |
| `retrieval_policy_digest` | digest | SHA-256, caller-defined preimage |
| `embedding_config_digest` | digest | SHA-256, caller-defined preimage |
| `hits` | array | ordered, 0–100 entries |

### 1.3 Hit

| Field | Type | Notes |
| --- | --- | --- |
| `memory_id` | opaque id | non-empty, unique within the envelope |
| `memory_version_id` | opaque id | non-empty, unique within the envelope |
| `content_digest` | digest | SHA-256 over the memory content bytes |
| `rank` | integer | zero-based; equals the hit's array index |
| `score_micros` | integer \| null | fixed point; §11 |
| `provenance_digest` | digest \| null | §12 |
| `authority_label` | string \| null | §12 |

### 1.4 Digest

```
{ "algorithm": "sha256", "value": <64 lowercase hex>, "public_recomputable": <bool> }
```

### 1.5 Signature

| Field | Type | Notes |
| --- | --- | --- |
| `algorithm` | string | exactly `ed25519` |
| `key_id` | string | non-empty |
| `signature` | string | exactly 128 lowercase hex chars (64 bytes) |
| `signed_payload_digest` | digest | §7 |
| `signing_domain` | string | exactly `AEON_RECALL_ENVELOPE_V2` |

`signing_domain` is a declarative echo of the frozen label, never
caller-selectable. A mismatch MUST fail closed.

---

## 2. Optional fields: null, never absent

**Every optional key MUST be present.** Absence of the value is encoded as
explicit JSON `null`. An absent key is invalid and MUST be rejected.

Applies to: `workspace_id`, `session_id`, `mission_id`, `score_micros`,
`provenance_digest`, `authority_label`.

Rationale: `{...}` and `{"session_id":null,...}` are different byte strings and
therefore produce different signatures. Permitting both would let two
implementations agree on the meaning while disagreeing on the digest.

> Implementation note. In Rust this is *not* expressible with `Option<T>`:
> serde's derive silently maps a missing field to `None`. The reference
> implementation uses a distinct `Nullable<T>` whose deserializer routes through
> `deserialize_any`, which serde's missing-field deserializer rejects. Other
> languages must apply an equivalent explicit presence check.

---

## 3. Canonical UUID

`request_id` and `run_id` MUST be **canonical lowercase hyphenated** form:
exactly 36 characters, lowercase hex, hyphens at offsets 8, 13, 18, 23.

The following MUST be rejected even though they parse to the same 128-bit
value:

| Form | Example |
| --- | --- |
| uppercase | `3F2504E0-4F89-41D3-9A0C-0305E82C3301` |
| mixed case | `3f2504E0-4f89-41d3-9a0c-0305e82c3301` |
| simple | `3f2504e04f8941d39a0c0305e82c3301` |
| braced | `{3f2504e0-...-0305e82c3301}` |
| urn:uuid | `urn:uuid:3f2504e0-...-0305e82c3301` |

A permissive UUID parser is **not** sufficient. Validate the string form before
parsing. JSON Schema uses an explicit `pattern`, not `format: uuid`, which is
annotation-only in most validators.

---

## 4. Canonicalization — `aeon-canonical-json-v1`

Defined by this document. It is **not** RFC 8785 / JCS and MUST NOT be
described as such.

1. Serialize the payload to a JSON value.
2. Object keys are emitted in ascending order of their **raw UTF-8 key bytes**.
3. Array order is preserved. Arrays are never sorted.
4. No insignificant whitespace: no space after `:` or `,`, no newlines.
5. Strings are UTF-8, escaped per RFC 8259.
6. **Numbers MUST be integers.** A floating-point value anywhere in the payload
   is an error, not a rounding opportunity.
7. Duplicate object keys MUST be rejected before canonicalization.

Key ordering MUST be performed explicitly, not inherited from a language's map
type. (In Rust, `serde_json::Map` ordering depends on the `preserve_order`
feature, which any transitive dependency can enable.)

---

## 5. Duplicate keys

A JSON object containing the same key twice MUST be rejected at parse time,
including when both occurrences are *known* fields. Rejecting only unknown
fields is insufficient. Note that parsing into a generic JSON value type
typically keeps the last occurrence silently — the check must happen during
strict deserialization.

---

## 6. Query digest preimage

```
query_digest = SHA-256( <exact UTF-8 bytes of the query string> )
```

No trimming, case folding, Unicode normalization, or whitespace collapsing.
The raw query bytes as issued.

---

## 7. Signing bytes and `signed_payload_digest`

Two frozen constants:

```
RECALL_SIGNING_DOMAIN_LABEL = "AEON_RECALL_ENVELOPE_V2"
RECALL_SIGNING_DOMAIN_BYTES = 41 45 4f 4e 5f 52 45 43 41 4c 4c 5f 45 4e 56 45
                              4c 4f 50 45 5f 56 32 00
```

The label is what travels on the wire. The bytes — **including the trailing
`0x00`** — are what the cryptography commits to.

```
signing_bytes         = RECALL_SIGNING_DOMAIN_BYTES || canonical(payload)
signed_payload_digest = SHA-256( signing_bytes )
```

`signed_payload_digest` is the digest of the **signing bytes**, not of
`canonical(payload)` alone, so it inherits domain separation. The digest of the
bare canonical payload MUST NOT be placed in a signature envelope. (The test
vector publishes it as `payload_digest_diagnostic` purely so the two values can
be compared; it is not part of the contract.)

### 7.1 What is and is not signed

**Only `canonical(payload)` is included in the signing bytes.** The outer
`RecallEnvelopeV2` object — the `payload` / `signature` wrapper — is *not*
canonicalized and *not* signed. Nothing in the `signature` object is covered by
its own signature.

Consequently:

- **The outer envelope's JSON object-key order is NOT security-significant.**
  `{"payload":…,"signature":…}` and `{"signature":…,"payload":…}` are equally
  valid and carry identical security properties. Do not infer meaning from it,
  do not canonicalize the outer object, and do not hash the transmitted envelope
  bytes as a substitute for the procedure in §8.
- The same holds for whitespace and formatting of the transmitted envelope: it
  is transport representation, not signed content.

**Consumers MUST parse the envelope structurally and independently
re-canonicalize the payload before verifying the digest or the signature.**
Concretely: deserialize the envelope into typed fields, take the `payload`
*value*, run §4 canonicalization over it yourself, prepend the domain bytes per
§7, and verify against that. A verifier MUST NOT:

- extract the payload as a raw substring of the received JSON and hash those
  bytes;
- reuse the sender's byte framing in any form;
- trust `signed_payload_digest` in place of recomputation.

The payload's canonical form is a function of its *values*, not of how the
sender happened to serialize them. Any conforming implementation re-deriving it
from parsed values arrives at identical bytes — that is the entire point of §4,
and it is why an intermediary may reformat the envelope in transit without
invalidating the signature.

---

## 8. Signature procedure

**Producer**

1. Build and validate the payload (§9).
2. `canonical(payload)` per §4.
3. `signing_bytes` per §7.
4. Ed25519-sign `signing_bytes`. Encode lowercase hex.
5. Emit `signature` with `algorithm = "ed25519"`,
   `signing_domain = "AEON_RECALL_ENVELOPE_V2"`,
   `signed_payload_digest = SHA-256(signing_bytes)`.

**Verifier**

1. Parse strictly; reject unknown fields, duplicate keys, absent optional keys.
2. Validate payload shape (§9) and signature shape (§1.5).
3. Recompute `canonical(payload)` and `signing_bytes` from the received payload.
4. Recompute `SHA-256(signing_bytes)`; reject on mismatch with
   `signed_payload_digest`.
5. Verify the Ed25519 signature over the **recomputed** signing bytes, using a
   key selected by `key_id` from a trusted keyring — never from the envelope.

A verifier MUST NOT trust `signed_payload_digest` in place of recomputation, and
MUST NOT accept an `algorithm` other than `ed25519`.

---

## 9. Validation rules

| Rule | Requirement |
| --- | --- |
| versions | `protocol_version` and `canonicalization_version` exact match |
| nonce | exactly 64 lowercase hex chars |
| time | `issued_at_unix_ms ≥ 0`; `expires_at_unix_ms > issued_at_unix_ms` |
| TTL | `expires_at − issued_at ≤ 120000 ms`; default 30000 ms |
| limit | `1 ≤ limit ≤ 100` |
| hits | `0 ≤ len(hits) ≤ 100` and `len(hits) ≤ limit` |
| rank | `hits[i].rank == i`, zero-based and contiguous |
| uniqueness | all `memory_id` unique; all `memory_version_id` unique |
| identifiers | required ids non-empty; a present optional id must be non-empty |
| digests | `algorithm = "sha256"`, 64 lowercase hex chars |
| unknown fields | rejected |
| numbers | integers only |

Empty `hits` is valid and signable: a recall that returned nothing is a real,
attestable event.

**Clock skew is NOT validated here.** `issued_at`/`expires_at` are checked only
for internal consistency and TTL bound. Comparing them to a wall clock is
verifier policy (S0.3).

---

## 10. Identifier privacy

`tenant_id` and `agent_id` are **stable opaque identifiers**. They MUST NOT
contain display names, email addresses, or other unnecessary personal data.
They appear in signed bytes that may be shared outside the issuing system.

Note that V1 (`aeon-nexus-memory-evidence-v1`) carried an HMAC'd
`agent_handle` rather than a raw identifier. V2 carries the identifier
directly; producers SHOULD keep supplying pseudonymous values so the practical
privacy posture is preserved.

---

## 11. Scores

`score_micros` is a fixed-point integer in millionths. `0.875` is `875000`.

`null` means **no score**. It MUST NOT be replaced with `0`, and no
floating-point value may enter canonical bytes.

---

## 12. Per-hit provenance and authority

`provenance_digest` and `authority_label` are **per hit**, not per envelope, and
are covered by canonical bytes and the signature.

`null` means:

- no authenticated provenance claim, and
- no authenticated authority claim — semantically **AUTH_0**.

`null` never means "unknown" or "not yet computed". Populating either field on a
hit that previously carried `null` changes the signing bytes and invalidates any
existing signature. That is intentional: an authority claim cannot be added
after the fact without re-signing.

---

## 13. What S0.1 does NOT provide

- **No replay protection.** The nonce and validity window are carried and
  format-checked, but nonce reuse is not tracked and timestamps are not compared
  to a clock. V2 provides the *contract* a replay guard enforces; it is not
  itself a replay guard.
- **No signing.** The reference implementation defines the signature envelope
  and computes signing bytes. It holds no key material and performs no runtime
  signing.
- **No verification.** It checks internal consistency —
  `signed_payload_digest == SHA-256(signing_bytes)` — which is not signature
  verification.
- **No key management**: no keyring, rotation, distribution, or `key_id`
  resolution.
- **No transport, storage, or persistence.**

## 14. Deferred

**S0.2 (AEON-IQ producer)** — populate real values; sign with a managed key;
vendor the schema and vectors below and pass byte-for-byte conformance;
preserve pseudonymous identifiers (§10).

**S0.3 (Nexus verifier)** — resolve `key_id` against a trusted keyring; verify
signatures; enforce clock skew and the validity window; enforce nonce
uniqueness (replay storage); define failure and audit behaviour.

---

## 15. Source artifacts

The authoritative hashes live in **one machine-readable file**:

```
vectors/recall_envelope_v2/MANIFEST.sha256
```

standard `sha256sum` format, paths relative to the crate root, covering:

- `schema/recall_envelope_v2.schema.json`
- `vectors/recall_envelope_v2/payload.json`
- `vectors/recall_envelope_v2/vector.json`
- `vectors/recall_envelope_v2/envelope.json`

They are deliberately **not** duplicated in this document. A second copy would
drift, and a stale hash in a normative spec is worse than none. The test
`artifact_manifest_matches_checked_in_files` recomputes every entry, so editing
a fixture or the schema fails the build until the manifest is deliberately
updated.

Vendoring parties MUST record, alongside the copied files:

1. the source Nexus commit SHA,
2. the contents of `MANIFEST.sha256`,

and MUST re-verify those hashes after copying.

`.gitattributes` in the crate pins `eol=lf` for `schema/**` and `vectors/**`.
These files are hashed byte-for-byte, so a CRLF checkout would invalidate every
entry without changing any content.

The Ed25519 key in the vectors is a fixed all-`0x42` test seed. It protects
nothing and MUST NOT appear in any real system.

**V1 compatibility baseline.** `aeon-nexus-memory-evidence-v1` is unchanged by
this contract: not deprecated, not converted, byte-identical on the wire.
Verified against untouched `Nexus-temp` main at commit
`971fdfcd9b242ac69404d3c27b1821f971ab10b4`.
