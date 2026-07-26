```markdown
# Nexus-temp Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and workflows of the Nexus-temp Rust codebase. You'll learn the project's coding conventions, how to evolve protocol contracts, update CI workflows, and write effective tests. This guide is based on real repository analysis and is designed to help contributors quickly become productive.

## Coding Conventions

- **File Naming:**  
  Use `camelCase` for file names.  
  _Example:_  
  ```
  recallEnvelopeV2.rs
  canonicalPreflight.rs
  ```

- **Import Style:**  
  Use relative imports within modules.  
  _Example:_  
  ```rust
  mod canonicalPreflight;
  use super::canonicalPreflight::preflight_check;
  ```

- **Export Style:**  
  Use named exports for functions, structs, and modules.  
  _Example:_  
  ```rust
  pub fn validate_envelope(...) { ... }
  pub struct RecallEnvelopeV2 { ... }
  ```

- **Commit Messages:**  
  Follow [Conventional Commits](https://www.conventionalcommits.org/).  
  Prefixes: `fix`, `ci`, `test`, `feat`  
  _Example:_  
  ```
  feat: add canonical preflight checks for v2 envelopes
  fix: correct schema validation for recall envelope
  ```

## Workflows

### Protocol Contract Evolution
**Trigger:** When you need to add, update, or fix a protocol contract and ensure all artifacts and tests are consistent.  
**Command:** `/update-protocol-contract`

1. **Edit or add to the schema definition**  
   - Update the relevant JSON schema file:  
     ```
     crates/aeon_nexus_bridge/schema/recall_envelope_v2.schema.json
     ```
2. **Edit or add to the protocol documentation**  
   - Update `PROTOCOL.md`:  
     ```
     crates/aeon_nexus_bridge/schema/recall_envelope_v2/PROTOCOL.md
     ```
3. **Update or implement Rust source files**  
   - Edit contract logic or helpers:  
     ```
     crates/aeon_nexus_bridge/src/v2.rs
     crates/aeon_nexus_bridge/src/v2/canonical_preflight.rs
     ```
4. **Update or add test files**  
   - Add or modify tests:  
     ```
     crates/aeon_nexus_bridge/tests/recall_envelope_v2.rs
     crates/aeon_nexus_bridge/tests/recall_envelope_v2_strict.rs
     ```
5. **Update test vectors**  
   - Add or update JSON test vectors:  
     ```
     crates/aeon_nexus_bridge/vectors/recall_envelope_v2/*.json
     ```
6. **Update the manifest hash**  
   - Regenerate the manifest to reflect artifact changes:  
     ```
     crates/aeon_nexus_bridge/vectors/recall_envelope_v2/MANIFEST.sha256
     ```

_Example:_  
```bash
# After making changes, update the manifest
sha256sum *.json > MANIFEST.sha256
```

---

### CI Workflow Update
**Trigger:** When you want to add or modify CI/CD automation for building, testing, or verifying the project.  
**Command:** `/update-ci`

1. **Edit or add GitHub Actions workflow YAML files**  
   - For CI:  
     ```
     .github/workflows/ci.yml
     ```
   - For benchmarks:  
     ```
     .github/workflows/benchmarks.yml
     ```
2. **Commit changes to workflow files**  
   - Use a conventional commit message, e.g.:  
     ```
     ci: add benchmark workflow for protocol v2
     ```

---

## Testing Patterns

- **Test File Naming:**  
  Test files use the pattern `*.test.*` or are named to match the feature under test.  
  _Example:_  
  ```
  recall_envelope_v2.test.rs
  recall_envelope_v2_strict.rs
  ```

- **Test Placement:**  
  Tests are placed in the `tests/` directory, often alongside the feature or protocol version.

- **Test Example:**  
  ```rust
  #[test]
  fn test_recall_envelope_v2_valid() {
      let envelope = RecallEnvelopeV2::new(...);
      assert!(envelope.is_valid());
  }
  ```

- **Framework:**  
  No specific test framework detected; uses Rust's built-in test harness.

## Commands

| Command                   | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| /update-protocol-contract | Evolve or refine a protocol contract and its conformance   |
| /update-ci                | Update or add CI/CD automation workflows                   |
```
