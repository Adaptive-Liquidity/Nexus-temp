---
name: ci-workflow-update
description: Workflow command scaffold for ci-workflow-update in Nexus-temp.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /ci-workflow-update

Use this workflow when working on **ci-workflow-update** in `Nexus-temp`.

## Goal

Update or add continuous integration workflows, such as building images, running benchmarks, or verifying protocol manifest changes.

## Common Files

- `.github/workflows/ci.yml`
- `.github/workflows/benchmarks.yml`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit or add GitHub Actions workflow YAML files.
- Commit changes to workflow files.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.