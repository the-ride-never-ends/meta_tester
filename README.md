# Meta-Tester
## Author: Kyle Rose, Claude 4.5, Gemini 2.5 Pro
## Version: 1.0.0

## Overview

Meta-Tester acts as a quality gate for a pytest suite, automatically detecting common testing anti-patterns and enforcing consistent unit tests standards. Allows for the vibe-coding of tests in pytest with confidence that best practices are being followed.

Inspired by the horror of debugging vibe-coded tests at scale.

Informed by: https://testsmells.org/index.html, https://pure.tudelft.nl/ws/portalfiles/portal/137994226/s10664_022_10207_5.pdf, and https://bytedev.medium.com/things-ive-learned-from-writing-a-lot-of-unit-tests-2d234d0cfccf

## Usage

### CLI

```bash
python main.py <test_file.py>
```

Returns analysis results including failed tests, return code, and pytests regular and error output.

### As Pytest Tests

Run meta-tests directly:

```bash
pytest meta_test.py
```

## Enforced Rules

### Test Method Requirements

- Maximum 10 lines per test (excluding docstrings)
- Exactly one assertion per test
- No constructor calls (use fixtures)
- No empty test bodies
- F-string assertion messages with dynamic content
- At most one production method call
- No mocking of the method under test
- No skip/ignore decorators
- No magic numbers or strings in assertions
- No external resource access (e.g., files, network)
- No print/logging statements
- No redundant assertions (assert True/False)
- No str/repr comparisons
- Must follow `test_when_x_then_y` naming convention
- Must have GIVEN/WHEN/THEN docstring structure
- Must use whole fixtures, not parts
- No resource optimism (check availability)
- No conditional logic (if/for/while/match/try)
- Must only test through public API

### File-Level Requirements

- Must start with shebang
- Must end with `pytest.main([__file__])`
- No duplicate assertions across file

### Class Requirements

- Docstrings must mention production class/function being tested

## Configuration

Set `META_TESTER_TARGET_FILE` environment variable to analyze a specific file:

```bash
export META_TESTER_TARGET_FILE=/path/to/test_file.py
pytest meta_test.py
```

## Excluded Directories

`.venv`, `venv`, `node_modules`, `.git`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `site-packages`

## Roadmap
- Add more test smell detections
- Integrate with CI/CD pipelines
- Write test smells for fixtures
