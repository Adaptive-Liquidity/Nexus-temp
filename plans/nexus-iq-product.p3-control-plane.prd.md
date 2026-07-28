# PRD: Nexus-IQ Control Plane — P3a + P2.5

**Status**: draft
**Owner**: contact@adaptiveliquidity.com
**Created**: 2026-06-29
**Format**: problem-first PRD (ecc:plan-prd)
**Parent**: [nexus-iq-product.prd.md](nexus-iq-product.prd.md) (phase P3)

> Scope of THIS PRD: **P2.5** (dynamic tenant/API-key registry in the Rust gateway) +
> **P3a** (the first control-plane slice). Later P3 slices (memory/proof viewers, demo,
> billing stubs) and P4–P6 are out of scope here and tracked in the parent PRD.

---

## Locked Decisions (do not re-litigate)

| Area | Decision |
|---|---|
| Framework | **Next.js App Router + TypeScript**, deployed on **Vercel** |
| Auth | **Clerk** (Organizations = workspaces; Clerk owns sign-in UI, sessions, org switching) |
| Data | **Neon Postgres + Drizzle ORM** (typed schema + migrations) |
| Repo | **new `nexus-iq-platform` monorepo** (pnpm + Turborepo), separate from the Rust `Nexus` repo |
| Runtime boundary | **Rust P2 gateway stays separate** — the web app is a *client* of `mcp.nexusiq.ai`, never embeds the runtime |
| P3a exclusions | **no** provider-key vault, **no** memory mutation, **no** billing engine, **no** web execution |

---

## Problem

P0–P2 made Nexus-IQ remotely reachable and per-tenant authenticated — but the tenant/API-key
store is a **static JSON file** (`NEXUS_MCP_HTTP_TENANTS`) loaded at Rust-gateway startup. There is
no way for a human to sign up, create a workspace, mint or revoke an API key, or get a copy-paste
MCP connector config. A key "created" by a future web app would be inert until the gateway is
manually re-deployed. There is no front door and no self-serve credential lifecycle.

## Hypothesis

If we (P2.5) make the gateway read its tenant/key registry **dynamically from Neon** with
revocation, and (P3a) ship a Clerk-authenticated control plane that mints/revokes those keys and
emits ready-to-paste MCP connector configs, then a non-technical user can go from signup → working
MCP connection in minutes, and key lifecycle becomes self-serve and auditable — without exposing
execution or secrets (those stay P5/later).

## Why now

P3a is the first surface that turns the P0–P2 plumbing into a usable product, and it is the
natural consumer of P2's per-tenant auth. P2.5 is the hard dependency that makes key management
real rather than cosmetic.

---

## Goals (P3a)

- Sign up / sign in / workspace (org) management via Clerk.
- Create, name, scope, **revoke** API keys; secret shown once, only SHA-256 + prefix persisted.
- `/connect` page: per-client (Claude / Cursor / ChatGPT / OpenHands) copy-paste MCP config using
  the user's key + `mcp.nexusiq.ai`.
- Runtime status: show whether the workspace's runtime endpoint is reachable/online.
- Dashboard shell: navigation, workspace switcher, responsive layout, real design system.
- Audit skeleton: append-only `audit_log` table + write path on key/member/connect events + a
  minimal viewer.

## Goals (P2.5)

- Replace the static `NEXUS_MCP_HTTP_TENANTS` file with a **Neon-backed dynamic registry**.
- Honor **revocation** within a bounded TTL (short cache, e.g. ≤30s) without a gateway restart.
- **Preserve every P2 security property**: SHA-256 key hashing, constant-time compare, per-tenant
  rate limit, fail-closed on lookup/DB error, no plaintext keys ever stored or logged.

## Non-Goals (P3a)

- Provider-key vault (OpenAI/Anthropic keys) — later slice.
- Any memory **write/edit/delete/import**; memory/proof **viewers** are a later P3 slice.
- Billing engine / plans / seats enforcement (stub UI only if unavoidable, no engine).
- Web-triggered execution (stays gated to P5).

## Users

| User | P3a value |
|---|---|
| New individual / prospect | signup → mint key → connect Claude/Cursor in minutes |
| Team admin | workspace + members + per-key revocation + audit trail |
| Power user | multiple scoped keys, runtime-online visibility |

---

## Architecture

```
Browser ── Clerk (auth UI/session) ──┐
                                      ▼
app.nexusiq.ai (Next.js App Router on Vercel)
  - RSC for data reads (server components hit Neon via Drizzle)
  - server actions / route handlers for mutations (mint/revoke key, audit writes)
  - Clerk Org = Workspace (tenant boundary)
                                      │ writes/reads
                                      ▼
                            Neon Postgres (Drizzle)
        api_keys (sha256+prefix), workspaces, members, runtime_connections, audit_log
                                      ▲
                                      │ P2.5: dynamic read (short-TTL cache, revocation)
                            Rust mcp-http gateway (mcp.nexusiq.ai)
                            validates Bearer key → tenant → read-only MCP (P1/P2)
```

**Key lifecycle (security-critical path):** web app generates a high-entropy key
(`niq_<workspace>_<random>`), shows it **once**, persists `{ key_sha256, key_prefix, workspace_id,
scopes, rate_limit_rpm, status, created_by, created_at }`. The Rust gateway (P2.5) looks up by
SHA-256 (constant-time) against a cached view of `api_keys WHERE status='active'`. Revoke = set
`status='revoked'`, `revoked_at=now()`; gateway drops it within the cache TTL.

---

## Monorepo layout (`nexus-iq-platform`)

```
nexus-iq-platform/            # pnpm workspace + Turborepo
  apps/web/                   # Next.js App Router (Vercel)
  packages/db/                # Drizzle schema, migrations, Neon client (single source of truth)
  packages/core/              # domain logic: key minting/hashing, audit writer, tenant mapping
  packages/ui/                # design-system components (NOT a raw shadcn dump — see anti-slop)
  packages/config/            # shared tsconfig / eslint / tailwind / prettier presets
```
No business logic in `apps/web` route files beyond wiring; mintable/hashable/auditable logic lives
in `packages/core` and is unit-tested independent of Next.js.

---

## Drizzle schema (P3a — synthetic)

```
workspaces        ( id pk, clerk_org_id unique, name, created_at )
workspace_members ( workspace_id fk, clerk_user_id, role enum(owner,admin,member), created_at )
api_keys          ( id pk, workspace_id fk, name, key_prefix, key_sha256 unique, scopes text[],
                    rate_limit_rpm int, status enum(active,revoked), created_by, created_at,
                    last_used_at nullable, revoked_at nullable )
runtime_connections ( id pk, workspace_id fk, kind enum(cloud,local), status enum(online,offline),
                    last_seen_at )
audit_log         ( id pk, workspace_id fk, actor_clerk_user_id, action, target_type, target_id,
                    metadata jsonb, created_at )   -- append-only
```
Migrations via `drizzle-kit`; Neon branch per preview deployment.

---

## Skills & Agents to use (anti-slop is a requirement, not a nicety)

| Task | Skill / Agent | Why |
|---|---|---|
| Design direction + dashboard shell | **ccg:frontend-design** skill + `design:design-system` | opinionated type/spacing/color, anti-AI-slop patterns — NOT a generic admin template |
| Feature architecture / build order | **ecc:code-architect** agent; **ecc:nextjs-turbopack** + **ecc:react-patterns** skills | App-Router RSC/client boundaries, server actions, caching done right |
| DB schema + queries | **ecc:database-reviewer** agent; **ecc:postgres-patterns** skill | indexing, constraints, Drizzle idioms, migration safety |
| Key minting/hashing + audit path | **ecc:security-reviewer** agent | high-entropy keys, SHA-256, no plaintext/log leakage, IDOR/workspace-scoping |
| Accessibility | **ecc:a11y-architect** agent | WCAG 2.2 on shell + forms from day one |
| Per-change review | **ecc:react-reviewer** + **ecc:typescript-reviewer** agents | hook correctness, type safety, RSC boundary bugs |
| Tests | **ecc:react-testing** / **ecc:tdd-workflow** skills | behavioral coverage on core + key flows |
| P2.5 (Rust) | **codex dispatch lane** + **ecc:rust-reviewer** + **ecc:security-reviewer** | consistent with P0–P2; preserve security invariants |

**Anti-slop guardrails (enforced in review):**
- No dumping a component kit and calling it a design. `packages/ui` is a deliberate, minimal system
  (tokens → primitives → composites) with real empty/loading/error states.
- RSC by default; client components only where interaction demands. No `"use client"` at the root.
- No business logic in page files; no `any`; no fetch-in-`useEffect` waterfalls; typed end-to-end.
- Every list/table has designed empty, loading, error, and permission-denied states.
- Copy is product copy, not lorem/AI filler. One typographic scale, one spacing scale.

---

## Delivery Milestones

| Milestone | Repo(s) | Status | Plan |
|---|---|---|---|
| **P2.5** — Neon-backed dynamic tenant/API-key registry (revocation + TTL cache) | `Nexus` (Rust gateway) | pending | — |
| **P3a-1** — monorepo scaffold + design system + dashboard shell | `nexus-iq-platform` (NEW) | pending | — |
| **P3a-2** — Clerk auth + workspace (org) model + members | `nexus-iq-platform` | pending | — |
| **P3a-3** — Drizzle schema + migrations on Neon | `nexus-iq-platform` (+`packages/db`) | pending | — |
| **P3a-4** — API-key management (mint/scope/revoke; show-once) | `nexus-iq-platform` + Neon | pending | — |
| **P3a-5** — `/connect` MCP config generator (Claude/Cursor/ChatGPT/OpenHands) | `nexus-iq-platform` | pending | — |
| **P3a-6** — runtime status + audit skeleton (table, write path, viewer) | both | pending | — |

**Sequencing:** P3a-3 (schema) and **P2.5** are co-dependent — the `api_keys` table is the shared
contract. Land schema first, then P2.5 points the Rust gateway at it, then P3a-4 key management is
end-to-end real. P3a-1/-2 can proceed in parallel.

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Gateway coupling to the web app's DB (P2.5 reads Neon directly) | High | Read-only gateway DB role, dedicated `api_keys` view, short-TTL cache, fail-closed on DB error |
| API key leakage (logged, stored plaintext, shown twice) | High | Show-once UI, persist only SHA-256+prefix, security-reviewer gate on the mint/audit path |
| Workspace cross-tenant access (IDOR) | High | Every query scoped by workspace from Clerk org; security-reviewer + tests |
| Revocation lag | Medium | Bounded cache TTL (≤30s) documented; explicit invalidation if cheap |
| AI-slop UI | Medium | frontend-design skill + design-review gate; guardrails above |
| Clerk ↔ Neon user/org drift | Medium | Clerk webhooks (or lazy upsert) to sync org/user; treat Clerk as source of truth for identity |

## Success Metrics

- New user: signup → minted key → working MCP connection in < 5 min, no docs.
- Revoking a key blocks the gateway within the cache TTL (proven by test).
- Zero plaintext keys in DB or logs (security-review + grep gate).
- Dashboard shell passes a11y (WCAG 2.2 AA) and a design-review with no slop findings.

## Resolved Decisions (2026-06-29)

- **P2.5 access pattern**: gateway reads Neon **directly** via a **locked-down read-only DB role**
  + **short-TTL refresh-ahead cache**; **fails closed on cache miss + DB failure**. Web app is the
  only writer of tenant/API-key records; gateway only ever reads **active, hashed** keys.
- **Clerk→DB sync**: **lazy upsert** of user/workspace on first authenticated request, **plus
  verified Clerk webhooks** for deletes / deactivation / membership changes (signature-verified).

## Open Questions (remaining)

- Key format/prefix scheme and per-key scope vocabulary (start: `read` only, matching P1/P2).
- Where this PRD + platform docs live long-term (Nexus `plans/` vs `nexus-iq-platform/docs/`).

## Required external setup (user-provisioned — blocks live wiring, not the build)

- **Neon**: project + database; a **read-only role** for the gateway (SELECT on `api_keys`/a view
  only); two connection strings — app role (RW) for the web app, read-only role for the gateway.
- **Clerk**: application; publishable + secret keys; a **webhook signing secret**; Organizations on.
- **Vercel**: project linked to `apps/web`; env vars (Clerk keys, Neon app URL).
- Until provided, P2.5 builds/tests against a trait + in-memory mock (Postgres impl gated by env/feature).

## Acceptance (P2.5 + P3a)

- [ ] P2.5: gateway honors keys minted in Neon and revocations within TTL; P2 security tests still green; fail-closed on DB error.
- [ ] P3a: Clerk auth + workspace switching; mint/revoke key (show-once); `/connect` emits valid per-client config; runtime status renders; audit rows written for key/member/connect events.
- [ ] Reviews pass: security-reviewer (key path), database-reviewer (schema), react/typescript reviewers, a11y, and a design-review with no slop findings.
- [ ] No provider-key vault, no memory mutation, no billing engine, no web execution introduced.
