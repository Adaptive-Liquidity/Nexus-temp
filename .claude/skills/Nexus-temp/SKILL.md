```markdown
# Nexus-temp Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill teaches the core development patterns and workflows for the Nexus-temp Rust codebase. It covers coding conventions, commit styles, file organization, and step-by-step guides for the most common development tasks—especially around the Aeon module's Postgres replay store backend and contract management. Use this as a reference for contributing code, writing tests, and maintaining consistency across the repository.

## Coding Conventions

### File Naming

- Use `snake_case` for all file and module names.

  **Example:**
  ```
  src/aeon/recall_v2_postgres.rs
  tests/recall_v2_postgres.rs
  ```

### Import Style

- Prefer **relative imports** within modules.

  **Example:**
  ```rust
  mod recall_v2_postgres;
  use self::recall_v2_postgres::ReplayStore;
  ```

### Export Style

- Use **named exports** for module interfaces.

  **Example:**
  ```rust
  pub struct ReplayStore { /* ... */ }
  pub fn new_store() -> ReplayStore { /* ... */ }
  ```

### Commit Patterns

- Follow **conventional commits**.
- Prefixes: `test`, `feat`, `ci`, `fix`
- Keep commit messages concise (average ~47 characters).

  **Example:**
  ```
  feat: add initial Postgres replay store backend
  fix: correct recall logic in recall_v2_postgres.rs
  test: add tests for replay store migrations
  ```

## Workflows

### Add or Update Postgres Replay Store Backend

**Trigger:** When someone wants to add or update the Postgres replay store backend in Aeon.  
**Command:** `/add-replay-store-backend`

1. **Create or update SQL migration for replay store**
   - Edit or add migration files, e.g. `migrations/0001_recall_replay_store.sql`.
2. **Implement or modify backend logic**
   - Update or create `src/aeon/recall_v2_postgres.rs` with new logic or schema changes.
   - Ensure code follows import/export conventions.
3. **Update or add tests**
   - Write or modify tests in `tests/recall_v2_postgres.rs` to cover new or changed functionality.

**Example:**
```rust
// src/aeon/recall_v2_postgres.rs
pub struct ReplayStore { /* fields */ }

impl ReplayStore {
    pub fn new(/* params */) -> Self { /* ... */ }
    pub fn replay(&self, /* ... */) -> Result<(), Error> { /* ... */ }
}
```

### Define and Harden Contracts with Tests

**Trigger:** When someone wants to define or strengthen the contract for a component, ensuring tests and dependencies are updated.  
**Command:** `/define-contract`

1. **Update dependencies**
   - Modify `Cargo.toml` to add or update dependencies as needed.
2. **Modify or define contract**
   - Edit `src/aeon.rs` or `src/aeon/recall_v2_postgres.rs` to define or update public interfaces.
   - Ensure all contract changes are reflected in the implementation.
3. **Update or add tests**
   - Add or update tests in `tests/recall_v2_postgres.rs` to validate the contract.

**Example:**
```rust
// src/aeon.rs
pub trait RecallContract {
    fn recall(&self, id: Uuid) -> Option<Event>;
}
```

## Testing Patterns

- Test files follow the pattern `*.test.*` (e.g., `recall_v2_postgres.test.rs`).
- Testing framework is not explicitly specified; use Rust's built-in test framework unless otherwise noted.

**Example:**
```rust
// tests/recall_v2_postgres.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_store_insert() {
        // Arrange
        let store = ReplayStore::new(/* ... */);

        // Act
        let result = store.insert(/* ... */);

        // Assert
        assert!(result.is_ok());
    }
}
```

## Commands

| Command                    | Purpose                                                            |
|----------------------------|--------------------------------------------------------------------|
| /add-replay-store-backend  | Add or update the Postgres replay store backend in Aeon            |
| /define-contract           | Define or harden contracts for Aeon components and update tests     |
```
