# Changelog

All notable changes to the true_negatives test suite will be documented in this file.

## [1.0.0] - 2025-10-03

### Added
- Initial creation of true_negatives test suite with 29 individual test files
- Created directory structure under tests/meta_tester/test_smells/true_negatives/
- Added __init__.py files for proper Python package structure
- Created test_method_length_violation.py - Tests method length limits
- Created test_multiple_assertions_violation.py - Tests multiple assertions rule
- Created test_constructor_call_violation.py - Tests constructor call restrictions
- Created test_empty_method_violation.py - Tests empty method detection
- Created test_missing_assertion_message_violation.py - Tests assertion message requirements
- Created test_multiple_production_calls_violation.py - Tests single production call rule
- Created test_multiple_production_classs_violation.py - Tests multiple production method calls
- Created test_no_production_calls_violation.py - Tests production call requirements
- Created test_mocking_method_under_test_violation.py - Tests mocking restrictions
- Created test_skip_decorator_violation.py - Tests skip decorator usage
- Created test_magic_numbers_violation.py - Tests magic number detection
- Created test_external_resources_violation.py - Tests external resource usage
- Created test_print_statement_violation.py - Tests print statement detection
- Created test_always_true_assertion_violation.py - Tests redundant assertions
- Created test_always_false_assertion_violation.py - Tests redundant assertions
- Created test_string_repr_violation.py - Tests str/repr usage
- Created test_bad_docstring_format_violation.py - Tests docstring format
- Created test_bad_naming_convention_violation.py - Tests naming conventions
- Created test_fixture_usage_violation.py - Tests fixture usage patterns
- Created test_private_access_violation.py - Tests private method access
- Created test_resource_assumption_violation.py - Tests resource assumptions
- Created test_if_statement_violation.py - Tests control flow restrictions
- Created test_for_loop_violation.py - Tests loop usage
- Created test_while_loop_violation.py - Tests loop usage
- Created test_try_except_violation.py - Tests exception handling
- Created test_class_docstring_violation.py - Tests class docstring requirements
- Created test_first_duplicate_assertion.py - Tests duplicate assertion patterns
- Created test_second_duplicate_assertion.py - Tests duplicate assertion patterns
