# Nexus-IQ Roadmap

**Last updated**: 2026-07-25

This is the public roadmap: what Nexus-IQ is, what has shipped, what is being built, and — just as
importantly — what it does **not** prove. Detailed implementation sequencing is maintained
internally.

---

## What Nexus-IQ is

**AI agents can act. Nexus-IQ makes their actions transactional.**

An agent **proposes** a change. The runtime **stages** it in an isolated workspace, runs
**deterministic validators**, requires **human approval** where policy demands it, and only then
**commits**. Every committed change emits a portable, signed evidence receipt that a third party can
verify offline.

A guiding rule runs through the whole system:

> Recalled memory may inform an agent's reasoning. It may never silently increase the agent's
> authority to act.

## Product stages

| Stage | Product | Status |
|---|---|---|
| 1 | **Transactional Change Gate** — wraps an existing coding agent, stages its work in a Git worktree, validates it, and opens a branch/PR with a signed receipt | In development |
| 2 | **Proof-Carrying Runtime** — generalizes the model to broader agent actions, with effect journaling, commit barriers, compensation, and origin-bound memory authority | Planned |
| 3 | **Cognitive Hypervisor** — long-running multi-agent missions, continuity, isolated candidate branches, recovery orchestration | Research / long-term |

First supported workflows are **dependency updates**, then **infrastructure-as-code changes**
(plan-only to begin with — no automatic apply). Nexus-IQ governs and validates changes rather than
competing with tools that generate them.

## Shipped today

- **Nexus** — WebAssembly execution with Ed25519 capability tokens (expiry, revocation, delegation
  chains, subset-only attenuation), guest-state snapshots, typed failure classification, and signed
  Proof Capsules with DSSE export.
- **AEON-IQ** — persistent agent memory (working / factual / archival tiers) with importance- and
  utility-aware retention, retrieval audit records, and signed memory-hit evidence.
- **Nexus-IQ self-host kit** — Docker Compose stack packaging both, with MCP integration for
  Claude, Cursor, and other MCP-compatible clients.
- Current release: **v1.1.0** across all three components, with published container images.

## In development

- **Evidence integrity hardening** — query- and run-bound recall attestation, a tamper-evident
  signed event chain, consistent execution-state capture, and durable operator-controlled signing
  identities so receipts remain verifiable across restarts.
- **Transactional Change Gate** — transaction state machine, effect journal, Git-worktree workspace
  backend, commit barrier, dependency-update and IaC validator packs, an in-toto/DSSE-compatible
  Agent Transaction Receipt, and an offline verifier.

## Research

- **Adaptive Memory Pressure (AMP)** — a preregistered five-seed study measuring retention of
  designated high-value memories under memory pressure. Publication of the paper and its full
  artifact package is in progress and independent of the product releases above.
- **Memory provenance and authority** — source evidence, derivation graphs, origin-bound authority
  ceilings, quarantine, and revocation of memories derived from compromised sources.

## Acceptance targets

A release is not considered ready until, at minimum:

- An aborted transaction leaves the protected repository unchanged.
- Modifications outside the declared scope are rejected.
- Every validator result is bound to the exact tree/diff digest it examined.
- An approval cannot be reused for a different change.
- Receipts verify offline, and still verify after a service restart.
- A failed validator produces an abort — never a partial commit.
- At least two independent parties can reproduce the workflow.

## What Nexus-IQ does not prove

We publish limitations alongside every capsule, and we hold the same standard here. Nexus-IQ does
**not**:

- prove that the executed program was correct;
- guarantee full deterministic replay of an execution;
- roll back arbitrary external side effects;
- demonstrate that recalled memory *caused* a model's decision;
- remove the need to trust the runtime and host boundary.

Rollback and recovery guarantees are scoped to the documented execution paths, not to arbitrary
agent tooling. Claims of production or enterprise readiness await an external security audit.

## Deliberately out of scope

A general agent framework · a coding model · a hosted multi-tenant execution cloud · a generic
identity platform · a marketplace · billing infrastructure.

---

Security issues should be reported privately via the process in `SECURITY.md`. Findings are
disclosed after fixes ship.
