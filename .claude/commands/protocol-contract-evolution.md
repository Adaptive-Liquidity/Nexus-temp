---
name: protocol-contract-evolution
description: Workflow command scaffold for protocol-contract-evolution in Nexus-temp.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /protocol-contract-evolution

Use this workflow when working on **protocol-contract-evolution** in `Nexus-temp`.

## Goal

Evolve or refine a protocol contract and its conformance suite, including schema, implementation, protocol documentation, test vectors, and manifest hashes.

## Common Files

- `crates/aeon_nexus_bridge/schema/recall_envelope_v2.schema.json`
- `crates/aeon_nexus_bridge/schema/recall_envelope_v2/PROTOCOL.md`
- `crates/aeon_nexus_bridge/src/v2.rs`
- `crates/aeon_nexus_bridge/src/v2/canonical_preflight.rs`
- `crates/aeon_nexus_bridge/tests/recall_envelope_v2.rs`
- `crates/aeon_nexus_bridge/tests/recall_envelope_v2_strict.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit or add to the schema definition (JSON schema file).
- Edit or add to the protocol documentation (PROTOCOL.md).
- Update or implement Rust source files for the contract logic (src/v2.rs, canonicalization helpers, etc).
- Update or add test files for the contract (tests/recall_envelope_v2*.rs).
- Update test vectors (vectors/recall_envelope_v2/*.json).

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.