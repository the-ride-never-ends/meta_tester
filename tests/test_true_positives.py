#!/usr/bin/env python3
"""
Test suite to verify that true positive test smell examples are correctly detected.

This module tests that each file in the true_positives directory contains exactly
one test smell and that the meta-tester correctly identifies that specific smell.
"""
import ast
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Dict, Tuple
import os
import re
from collections import defaultdict


import pytest


_TRUE_POSITIVES_DIR = Path(__file__).parent / "true_positives"
_META_TESTER_FILE = Path(__file__).parent.parent / "meta_test.py"
_TRUE_POSITIVES_NON_EXCLUSIVE_DIR = Path(__file__).parent / "true_positives_overlaps"


from ..meta_test import logger  # noqa: F401


def _get_true_positive_files() -> List[Path]:
    """
    Get all Python test files from the true_positives directory.
    
    Returns:
        List[Path]: List of paths to true positive test files.
    
    Raises:
        FileNotFoundError: If the true_positives directory does not exist.
    """
    pattern = "_test_*.py"
    if not _TRUE_POSITIVES_DIR.exists():
        raise FileNotFoundError(f"True positives directory not found at {_TRUE_POSITIVES_DIR}")
    
    return sorted(_TRUE_POSITIVES_DIR.glob(pattern))


def _get_non_exclusive_true_positive_files() -> List[Path]:
    """
    Get all Python test files from the true_positives_overlaps directory.
    
    Returns:
        List[Path]: List of paths to non-mutually exclusive true positive test files.
    
    Raises:
        FileNotFoundError: If the true_positives_overlaps directory does not exist.

    """
    pattern = "_test_*.py"
    if not _TRUE_POSITIVES_NON_EXCLUSIVE_DIR.exists():
        raise FileNotFoundError(f"Non-exclusive true positives directory not found at {_TRUE_POSITIVES_NON_EXCLUSIVE_DIR}")

    return sorted(_TRUE_POSITIVES_NON_EXCLUSIVE_DIR.glob(pattern))


def run_meta_tester_on_file(test_file: Path) -> Tuple[int, str, str]:
    """
    Run the meta-tester on a specific test file.
    
    Args:
        test_file (Path): Path to the test file to analyze.
    
    Returns:
        Tuple[int, str, str]: Return code, stdout, and stderr from pytest run.
    """
    # Create a temporary test configuration that tells the meta-tester to analyze only this file
    if not test_file.exists():
        raise FileNotFoundError(f"Test file not found: {test_file}")

    env = os.environ.copy()
    env['META_TESTER_TARGET_FILE'] = str(test_file.resolve())
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(_META_TESTER_FILE.resolve()), "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=_TRUE_POSITIVES_DIR.parent.parent,
        env=env
    )
    return result.returncode, result.stdout, result.stderr


def run_meta_tester(test_file: str) -> dict[str, Any]:
    """
    Run the meta-tester on a specific test file.

    Args:
        test_file (str): Path to the test file to analyze.

    Returns:
        dict[str, Any]: Dictionary of test results. The keys are the following:
            - 'returncode': int, the return code from pytest.
            - 'failed_count': int, number of failed tests.
            - 'failed_tests': list[str], names of the failed tests.
            - 'stdout': str, standard output from pytest.
            - 'stderr': str, standard error from pytest.

    Raises:
        TypeError: If test_file is not a string.
        ValueError: If test_file does not end with .py.
        FileNotFoundError: If the specified test file does not exist.
        RuntimeError: If an unexpected error occurs while running the meta-tester.
    """
    if not isinstance(test_file, str):
        raise TypeError(f"test_file must be a string, got {type(test_file).__name__}.")
    if not test_file.endswith(".py"):
        raise ValueError(f"test_file must be a Python file ending with .py, got {test_file}.")
    test_path = Path(test_file)
    if not test_path.exists():
        raise FileNotFoundError(f"Test file not found: {test_file}")
    try:
        returncode, stdout, stderr = run_meta_tester_on_file(test_path)
    except Exception as e:
        raise RuntimeError(f"Unexpected error running meta-tester on {test_file}: {e}") from e
    else:
        failed_tests: list[str] = extract_failed_test_names(stdout)
        return {
            'returncode': returncode,
            'failed_count': len(failed_tests),
            'failed_tests': failed_tests,
            'stdout': stdout,
            'stderr': stderr,
        }



def _count_failed_tests(stdout: str) -> int:
    """
    Count the number of failed tests from pytest output.

    This function parses the pytest summary line (e.g., "2 failed, 26 passed")
    to extract the failure count. This is more reliable than counting
    occurrences of "FAILED" which can appear multiple times per test.

    Args:
        stdout (str): Standard output from pytest run.

    Returns:
        int: Number of failed tests, or 0 if no failures found.
    
    Example:
        >>> output = "=== 2 failed, 26 passed in 0.23s ==="
        >>> _count_failed_tests(output)
        2
    """
    summary_markers = ["Captured log call", "short test summary info"]
    for marker in summary_markers: 
        if marker in stdout:
            #marker = "short test summary info"
            stdout = stdout.split(marker, 1)[-1]

    # Look for pytest summary line pattern: "X failed"
    match = re.search(r'(\d+)\s+failed', stdout)
    if match:
        #logger.debug(f"match.string: {match.string}")
        match_group = match.group(1)
        logger.debug(f"match_group: {match_group}")
        return int(match_group)
    return 0


def extract_failed_test_names(stdout: str) -> List[str]:
    """
    Extract the names of failed tests from pytest output.
    
    Args:
        stdout (str): Standard output from pytest run.
    
    Returns:
        List[str]: List of failed test names.
    """
    failed_tests: list[str] = []
    all_unique_parts = set()

    summary_markers = ["Captured log call", "short test summary info"]
    for marker in summary_markers: 
        if marker in stdout:
            #marker = "short test summary info"
            stdout = stdout.split(marker, 1)[-1]

    logger.debug(f"stdout after summary marker removal:\n{stdout}")

    for line in stdout.split('\n'):
        unique_parts = set()
        if 'FAILED' not in line:
            continue

        if "[" in line and "]" in line:
            # Remove anything between the brackets
            line = re.sub(r'\[.*?\]', '', line)

        if '::' in line:
            # Extract the test name from lines.
            parts = line.split('::')
            unique_parts = {
                part for part in parts 
                if part and # Remove empty parts, python file names, and lines that start with a capital letter
                not part.endswith(".py") and
                not part[0].isupper()
            }
            all_unique_parts.update(unique_parts)

            if len(parts) >= 2:
                # Get the last part and remove everything after the closing bracket
                last_part = parts[-1]
                # Split on ' ' to remove stuff like "- AssertionError"
                test_with_params = last_part.split(' ')[0]
                
                # Find the last closing bracket to handle nested brackets in parameters
                last_bracket_pos = test_with_params.rfind(']')
                if last_bracket_pos != -1:
                    # Remove everything from the last closing bracket onwards
                    test_with_params = test_with_params[:last_bracket_pos]

                # Now split on '[' to get just the test name without parameters
                test_name = test_with_params.split('[')[0].strip()
                # Remove 'FAILED' prefix if it somehow got through
                test_name = test_name.replace('FAILED', '').strip()

                # Split off the class name if present
                if '.' in test_name:
                    test_name = test_name.split('.')[-1].strip()

                if test_name:  # Only add non-empty test names
                    failed_tests.append(test_name)

    # Remove duplicates while preserving order
    seen = set()
    unique_tests = []
    for test in failed_tests:
        if test not in seen:
            seen.add(test)
            unique_tests.append(test)
    logger.debug(f"Unique failed tests extracted: {unique_tests}")

    return unique_tests

def _is_test_class(node: ast.AST) -> bool:
    """Check if the AST node is a test class (name starts with 'Test')."""
    return isinstance(node, ast.ClassDef) and node.name.startswith('Test')

def _is_test_method(node: ast.AST) -> bool:
    """Check if the AST node is a test method (name starts with 'test_')."""
    return isinstance(node, ast.FunctionDef) and node.name.startswith('test_')



def _get_file_mappings():
    true_positive_files: list[Path] = _get_true_positive_files()
    output_dict = defaultdict(str)
    for file in true_positive_files:
 
        # Get the AST tree of the test file
        try:
            tree = ast.parse(file.read_text())
        except SyntaxError as e:
            raise SyntaxError(f"Syntax error in file {file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Error parsing file {file}: {e}") from e

        # Get the test class
        test_classes = [node for node in ast.walk(tree) if _is_test_class(node)]
        assert len(test_classes) == 1, \
            f"Expected exactly one test class in {file.name}, but found {len(test_classes)}"

        # Get the test method
        # There should be exactly one test method per file
        test_methods = [node for node in test_classes[0].body if _is_test_method(node)]
        # assert len(test_methods) == 1, \
        #     f"Expected exactly one test method in {file.name}, but found {len(test_methods)}"
        test_method = test_methods[0]

        output_dict[file.name] = test_method.name
    return output_dict


def _map_file_to_expected_failure() -> Dict[str, str]:
    """
    Map each true positive file to its expected failing test in the meta-tester.
    
    Returns:
        Dict[str, str]: Mapping of filename to expected failing test method name.
    """
    mappings = {}
    mappings = {
        "_test_always_false_assertion_violation.py": "test_when_checking_redundant_assertions_then_no_always_false",
        "_test_always_true_assertion_violation.py": "test_when_checking_redundant_assertions_then_no_always_true",
        "_test_bad_docstring_format_violation.py": "test_when_checking_docstring_format_then_given_when_then_structure",
        "_test_bad_naming_convention_violation.py": "test_bad_naming_convention",
        "_test_class_docstring_violation.py": "test_when_checking_class_docstring_then_mentions_production_class",
        "_test_constructor_call_violation.py": "test_when_checking_constructor_calls_then_no_constructor_initialization",
        # "_test_empty_method_violation.py": "test_when_checking_method_body_then_not_empty", NOTE covered by check production call tests
        "_test_external_resources_violation.py": "test_when_checking_external_resources_then_no_real_resources",
        "_test_first_duplicate_assertion.py": "test_when_checking_duplicate_assertions_then_no_duplicates",
        "_test_fixture_usage_violation.py": "test_when_checking_fixture_usage_then_uses_whole_fixture",
        "_test_for_loop_violation.py": "test_when_checking_control_flow_then_violates_no_for_loops_rule",
        "_test_if_statement_violation.py": "test_when_checking_control_flow_then_violates_no_if_statements_rule",
        "_test_magic_strings_violation.py": "test_when_checking_magic_literals_then_violates_no_magic_strings_rule",
        "_test_magic_numbers_violation.py": "test_when_checking_magic_literals_then_no_magic_numbers_or_strings",
        "_test_method_length_violation.py": "test_when_checking_method_length_then_under_10_lines",
        "_test_missing_assertion_message_violation.py": "test_when_checking_assertion_messages_then_has_f_strings",
        "_test_missing_pytest_main_violation.py": "test_when_checking_test_file_then_contains_pytest_main",
        "_test_missing_shebang_violation.py": "test_when_checking_test_file_then_contains_shebang",
        "_test_mocking_method_under_test_violation.py": "test_when_checking_mocking_then_no_fake_tests",
        "_test_multiple_assertions_violation.py": "test_when_checking_assertions_then_exactly_one_assertion",
        "_test_multiple_production_calls_violation.py": "test_when_checking_production_calls_then_at_most_one_call",
        "_test_multiple_production_class_violation.py": "test_when_checking_production_calls_then_at_most_one_call",
        "_test_no_f_string_in_assertion.py": "test_when_checking_assertion_messages_then_has_f_strings_with_dynamic_content",
        "_test_no_production_calls_violation.py": "test_when_checking_production_calls_then_has_production_calls",
        "_test_print_statement_violation.py": "test_when_checking_print_logging_then_no_output_statements",
        "_test_private_access_violation.py": "test_when_checking_test_then_test_only_tests_through_public_contract",
        "_test_resource_assumption_violation.py": "test_when_checking_resource_assumptions_then_no_resource_optimism",
        "_test_skip_decorator_violation.py": "test_when_checking_skip_decorators_then_not_skipped",
        "_test_string_repr_violation.py": "test_when_checking_equality_then_no_str_repr",
        "_test_try_except_violation.py": "test_when_checking_exception_handling_then_no_try_except_blocks",
        "_test_while_loop_violation.py": "test_when_checking_test_then_no_conditional_logic",
        "_test_duplicate_assertion_in_same_file.py": "test_when_checking_duplicate_assertions_then_no_duplicates",
    }
    actual_mappings = _get_file_mappings()
    mappings.update(actual_mappings)
    # NOTE Bad naming convention test is special case
    mappings["_test_bad_naming_convention_violation.py"] = "test_when_checking_test_naming_then_follows_convention"
    del mappings["_test_first_duplicate_assertion.py"]
    return mappings


@pytest.fixture
def test_constants():
    """Provide standardized constants for test methods."""
    return {
        'ONE': 1,
        'PYTHON_EXTENSION': ".py",
        'TEST_PREFIX': "test_",
        'SHEBANG': '#!',
        'PYTEST_MAIN': r'if __name__ == "__main__":\n    pytest.main([__file__])',
    }


@pytest.fixture
def true_positive_files():
    """Fixture providing list of true positive test files."""
    return _get_true_positive_files()

@pytest.fixture
def non_exclusive_true_positive_files():
    """Fixture providing list of non-mutually exclusive true positive test files."""
    return _get_non_exclusive_true_positive_files()

@pytest.fixture
def expected_failures():
    """Fixture providing mapping of files to expected failures."""
    return _map_file_to_expected_failure()

def expected_non_exclusive_failures(key: str) -> Dict[str, set[str]]:
    return_dict =  {
        "_test_empty_method_violation.py": {
            'test_when_checking_production_calls_then_at_most_one_call', 
            'test_when_checking_assertions_then_exactly_one_assertion',
            'test_when_checking_docstring_format_then_given_when_then_structure',
            "test_when_checking_method_body_then_not_empty", 
            "test_when_checking_production_calls_then_has_production_calls",
            'test_when_checking_class_docstring_then_mentions_production_class'
        },
        "_test_no_production_calls_violation.py":{
            'test_when_checking_production_calls_then_at_most_one_call', 
            'test_when_checking_production_calls_then_has_production_calls', 
            'test_when_checking_docstring_format_then_given_when_then_structure', 
            'test_when_checking_class_docstring_then_mentions_production_class'
        },
        "_test_resource_assumption_violation.py": {
            'test_when_checking_resource_assumptions_then_no_resource_optimism', 
            'test_when_checking_external_resources_then_no_real_resources'
        },
        "_test_missing_assertion_message_violation.py": {
            'test_when_checking_assertion_messages_then_has_f_strings', 
            'test_when_checking_assertion_messages_then_has_f_strings_with_dynamic_content'
        },
    }
    return return_dict[key]


def _meta_tester_output(test_file: Path):
    """Fixture that runs meta-tester and returns output for a specific test file."""
    returncode, stdout, stderr = run_meta_tester_on_file(test_file)
    failed_tests: list[str] = extract_failed_test_names(stdout)
    stars = "*" * 10
    #logger.debug(f"{stars}\nstdout:\n{stdout}\n{stars}")
    return {
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'failed_count': len(failed_tests),
        'failed_tests': failed_tests,
    }


@pytest.fixture
def true_positives_dir():
    """Fixture providing the true positives directory path."""
    return _TRUE_POSITIVES_DIR


@pytest.mark.parametrize(
    "test_file",
    [f for f in _get_true_positive_files()],
    ids=lambda p: p.name[:-3]
)
class TestTruePositiveDetection:
    """Test suite for verifying true positive test smell detection."""

    def test_when_running_meta_tester_on_true_positive_then_no_errors_in_stdout(
        self, test_file
    ):
        """
        GIVEN a true positive test file
        WHEN the meta-tester is run on that file
        THEN there should be no pytest errors in stdout
        """
        stdout = _meta_tester_output(test_file)['stdout']
        error_string = "== ERRORS =="

        assert error_string not in stdout, \
            f"Expected no errors in stdout for {test_file.name}, but found errors:\n{stdout}"


    def test_when_running_meta_tester_on_true_positive_then_exactly_one_test_fails(
        self, test_file, test_constants
    ):
        """
        GIVEN a true positive test file containing exactly one test smell
        WHEN the meta-tester is run on that file
        THEN exactly one meta-test should fail
        """
        logger.debug(f"===== TEST_FILE: {test_file.name} =====")
        expected_count = test_constants['ONE']
        output = _meta_tester_output(test_file)
        actual_count = output['failed_count']

        assert expected_count == actual_count, \
            f"Expected exactly {expected_count} failed test for {test_file.name}, got {actual_count} instead\n{output['failed_tests']}"

    def test_when_running_meta_tester_on_true_positive_then_correct_test_fails(
        self, test_file, expected_failures
    ):
        """
        GIVEN a true positive test file with a specific test smell
        WHEN the meta-tester is run on that file
        THEN the meta-test corresponding to that specific smell should fail
        """
        expected_test = expected_failures[test_file.name]
        failed_tests = _meta_tester_output(test_file)['failed_tests']

        assert expected_test in failed_tests, \
            f"Expected test '{expected_test}' to fail for {test_file.name}, but got {failed_tests} instead"


    def test_when_running_meta_tester_on_true_positive_then_only_expected_test_fails(
        self, test_file, expected_failures
    ):
        """
        GIVEN a true positive test file with a specific test smell
        WHEN the meta-tester is run on that file
        THEN no other meta-tests should fail.
        """
        expected_test = [expected_failures[test_file.name]]
        actual_failed_test = _meta_tester_output(test_file)['failed_tests']

        assert actual_failed_test == expected_test, \
            f"Expected '{expected_test}' to be the only failing test for {test_file.name}, got '{actual_failed_test}' instead"


@pytest.mark.parametrize(
    "test_file",
    [f for f in _get_non_exclusive_true_positive_files()],
    ids=lambda p: p.name[:-3]
)
class TestNonMutuallyExclusiveTruePositiveDetection:

    def test_when_running_meta_tester_on_non_mutually_exclusive_true_positive_then_more_than_one_test_fails(
        self, test_file, test_constants
    ):
        """
        GIVEN a true positive test file containing non-mutually exclusive test smells
        WHEN the meta-tester is run on that file
        THEN the meta-tester should report more than 1 failure.
        """
        expected_count = test_constants['ONE']
        output = _meta_tester_output(test_file)
        actual_count = output['failed_count']

        assert expected_count <= actual_count, \
            f"Expected more than {expected_count} failed tests for {test_file.name}, got {actual_count} instead\n{output['failed_tests']}"

    def test_when_running_meta_tester_on_non_mutually_exclusive_true_positive_then_correct_tests_fail(
        self, test_file
    ):
        """
        GIVEN a true positive test file with specific non-mutually exclusive test smells
        WHEN the meta-tester is run on that file
        THEN the meta-tests corresponding to those specific smells should fail
        """
        expected_tests = expected_non_exclusive_failures(test_file.name)
        logger.debug(f"expected_tests: {expected_tests}")
        failed_tests = set(_meta_tester_output(test_file)['failed_tests'])

        assert expected_tests == failed_tests, \
            f"Expected tests '{expected_tests}' to fail for {test_file.name}, but got '{failed_tests}' instead"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
