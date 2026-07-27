---
name: add-or-update-postgres-replay-store-backend
description: Workflow command scaffold for add-or-update-postgres-replay-store-backend in Nexus-temp.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-postgres-replay-store-backend

Use this workflow when working on **add-or-update-postgres-replay-store-backend** in `Nexus-temp`.

## Goal

Implements or modifies the Postgres replay store backend for the Aeon module, including schema changes, backend logic, and corresponding tests.

## Common Files

- `migrations/0001_recall_replay_store.sql`
- `src/aeon/recall_v2_postgres.rs`
- `tests/recall_v2_postgres.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update SQL migration for replay store
- Implement or modify backend logic in src/aeon/recall_v2_postgres.rs
- Update or add tests in tests/recall_v2_postgres.rs

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.