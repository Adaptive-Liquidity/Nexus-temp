```markdown
# Nexus-temp Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill introduces the core development patterns and conventions used in the Nexus-temp Rust repository. You'll learn how to structure files, write imports and exports, follow commit message guidelines, and implement and run tests in line with the project's standards.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `my_module.rs`, `user_profile.rs`

### Import Style
- Use **relative imports** within modules.
  - Example:
    ```rust
    mod utils;
    use crate::utils::helper_function;
    ```

### Export Style
- Use **named exports** to expose functions, structs, or modules.
  - Example:
    ```rust
    pub fn calculate_sum(a: i32, b: i32) -> i32 {
        a + b
    }
    ```

### Commit Messages
- Follow **conventional commits** with prefixes such as `feat` and `test`.
  - Example:
    ```
    feat: add user authentication module
    test: add tests for login functionality
    ```

## Workflows

### Add a New Feature
**Trigger:** When implementing a new piece of functionality  
**Command:** `/add-feature`

1. Create a new Rust file using snake_case (e.g., `new_feature.rs`).
2. Implement the feature with named exports.
3. Use relative imports to include dependencies.
4. Write a commit message starting with `feat:`.
5. Push your changes.

### Write and Run Tests
**Trigger:** When adding or updating tests  
**Command:** `/run-tests`

1. Create or update test files matching the `*.test.*` pattern (e.g., `math.test.rs`).
2. Write tests using Rust's built-in testing framework.
3. Run tests using `cargo test` or your preferred test runner.
4. Commit with a message starting with `test:`.

## Testing Patterns

- Test files are named with the pattern `*.test.*` (e.g., `utils.test.rs`).
- Testing framework is not explicitly defined, but Rust's built-in test framework is assumed.
- Example test:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_add() {
          assert_eq!(add(2, 3), 5);
      }
  }
  ```

## Commands
| Command        | Purpose                                   |
|----------------|-------------------------------------------|
| /add-feature   | Scaffold and commit a new feature module  |
| /run-tests     | Run all tests in the repository           |
```
