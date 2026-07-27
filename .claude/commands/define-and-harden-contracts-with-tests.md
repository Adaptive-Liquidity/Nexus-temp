---
name: define-and-harden-contracts-with-tests
description: Workflow command scaffold for define-and-harden-contracts-with-tests in Nexus-temp.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /define-and-harden-contracts-with-tests

Use this workflow when working on **define-and-harden-contracts-with-tests** in `Nexus-temp`.

## Goal

Defines or hardens contracts (interfaces/boundaries) for Aeon components, updating implementation and corresponding tests.

## Common Files

- `Cargo.toml`
- `src/aeon.rs`
- `src/aeon/recall_v2_postgres.rs`
- `tests/recall_v2_postgres.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Update Cargo.toml for dependencies
- Modify or define contract in src/aeon.rs or src/aeon/recall_v2_postgres.rs
- Update or add tests in tests/recall_v2_postgres.rs

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.