```markdown
# Nexus-temp Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches best practices and conventions for contributing to the Nexus-temp TypeScript codebase. It covers file naming, import/export styles, commit message conventions, and testing patterns. By following these guidelines, contributors ensure consistency, readability, and maintainability across the project.

## Coding Conventions

### File Naming
- Use **camelCase** for all file names.
  - Example: `myComponent.ts`, `userService.test.ts`

### Import Style
- Use **relative imports** for referencing other modules.
  - Example:
    ```typescript
    import { fetchData } from './apiClient';
    ```

### Export Style
- Use **named exports** for all modules.
  - Example:
    ```typescript
    // In userService.ts
    export function getUser(id: string) { ... }
    export const USER_ROLE = 'admin';
    ```

### Commit Messages
- Follow **Conventional Commits** format.
- Use prefixes such as `ci` for continuous integration changes.
- Keep commit messages concise (average ~45 characters).
  - Example:
    ```
    ci: update build pipeline for node 18
    ```

## Workflows

### Commit Changes
**Trigger:** When making any change to the codebase  
**Command:** `/commit`

1. Stage your changes with `git add`.
2. Write a commit message following the Conventional Commits format (e.g., `ci: update dependency versions`).
3. Commit your changes with `git commit -m "type: short description"`.

### Add a New Module
**Trigger:** When adding new functionality  
**Command:** `/add-module`

1. Create a new file using camelCase naming (e.g., `newFeature.ts`).
2. Implement your functionality using named exports.
3. Import dependencies using relative paths.
4. Add tests in a corresponding `*.test.ts` file.
5. Commit your changes following the commit conventions.

### Write and Run Tests
**Trigger:** When adding or updating code  
**Command:** `/test`

1. Create or update test files matching the `*.test.*` pattern (e.g., `userService.test.ts`).
2. Write tests for your exported functions or constants.
3. Run the test suite using the project's test runner (framework not specified; check project documentation or `package.json` for details).

## Testing Patterns

- Test files follow the `*.test.*` naming pattern (e.g., `apiClient.test.ts`).
- Place tests alongside the modules they test or in a dedicated test directory.
- Testing framework is not specified; refer to project documentation for setup and execution.
- Example test file:
  ```typescript
  import { getUser } from './userService';

  describe('getUser', () => {
    it('returns user data for valid id', () => {
      // test implementation
    });
  });
  ```

## Commands
| Command      | Purpose                                      |
|--------------|----------------------------------------------|
| /commit      | Commit changes using conventional messages    |
| /add-module  | Add a new module following code conventions  |
| /test        | Write and run tests for your code            |
```