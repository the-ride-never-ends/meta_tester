# Change Log

## Unreleased

- Exclude pytest fixtures with a test prefix, including aliases and async fixtures.
- Exclude fixture assertions from duplicate checks and use one fixture collector.
- Check async tests for an asyncio marker on the test, class, or module.
- Accept pytest entry points with import aliases and exit calls.
- Detect conditional expressions and all comprehension types in test methods.
- Add regression tests for test collection, async markers, and entry points.

- Add project data and all dependencies from requirements.txt to pyproject.toml.
- Added ci.yaml for CI/CD
- Changed ci.yaml to ci.yml
