#!/usr/bin/env python3
"""
Meta-test suite to enforce good testing practices.

This module contains pytest tests that analyze other test files to ensure they follow
best practices for unit testing. It acts as a quality gate to prevent test smells
and ensure consistent testing standards across the codebase.
"""
import ast
import os
import re
from pathlib import Path
from typing import List


import pytest


from analyzers._test_file_analyzer import _TestFileAnalyzer
from logger import logger
from utils import read_file_content


EXCLUDED_DIRS = {
    '.venv', 'venv', 'node_modules', '.git', '__pycache__', '.pytest_cache', '.mypy_cache', 'site-packages'
}


def _read_first_line(test_file: str) -> str:
    """Read the first line of a test file.
    
    Args:
        test_file (str): Path to the test file.
        
    Returns:
        str: The first line of the file, stripped of whitespace.
        
    Raises:
        IOError: If the file cannot be read.
    """
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            return f.readline().strip()
    except Exception as e:
        raise IOError(f"Failed to read first line of {test_file}: {e}") from e


def _get_test_files(file_patterns: List[str], excluded_dirs: set[str] = EXCLUDED_DIRS) -> List[str]:
    """Get all test files matching the specified patterns."""
    test_files = []

    def _add_if_parent_not_in_excluded_dirs(path: Path, test_files: list[Path]) -> bool:
        if not any(excluded in path.parts for excluded in excluded_dirs):
            test_files.append(str(test_file.absolute()))

    for pattern in file_patterns:
        path = Path(pattern)
        if path.is_file() and path.suffix == '.py':
            test_files.append(str(path.absolute()))
        elif path.is_dir():
            for pattern in ['test_*.py', '*_test.py']:
                for test_file in path.rglob(pattern):
                    _add_if_parent_not_in_excluded_dirs(test_file, test_files)
        else:
            for test_file in Path('.').glob(pattern):
                if test_file.suffix == '.py':
                    _add_if_parent_not_in_excluded_dirs(test_file, test_files)

    return list(set(test_files))

analyzers: dict[str, _TestFileAnalyzer] = {}

def _get_analyzer_for_file(test_file: str) -> _TestFileAnalyzer:
    """Get or create a _TestFileAnalyzer for the given test file."""
    global analyzers
    if test_file not in analyzers:
        try:
            analyzers[test_file] = _TestFileAnalyzer(test_file)
        except Exception as e:
            logger.exception(e)
            raise RuntimeError(f"Failed to create analyzer for {test_file}: {e}") from e
    analyzer = analyzers[test_file]
    return analyzer


# Get test files and methods for parameterization
def _get_test_methods() -> List[tuple[str, str, ast.FunctionDef]]:
    """Get all test methods from all test files for parameterization."""

    print("Collecting test methods from test files...")
    # Check if we should analyze a specific file (for true positive testing)

    specific_file = os.environ.get('META_TESTER_TARGET_FILE')
    if specific_file:
        test_files = [specific_file]
    else:
        try:
            test_files = _get_test_files([
                "tests/meta_tester", 
            ])
        except Exception as e:
            raise RuntimeError(f"Failed to collect test files: {e}") from e

        # Remove this file itself from the list to prevent recursion
        test_files = {
            f for f in test_files 
            if Path(f).resolve() != Path(__file__).resolve()
        }

    test_methods = []
    for test_file in test_files:
        analyzer = _get_analyzer_for_file(test_file)
        try:
            methods = analyzer.get_test_methods()
            for method_name, test_node in methods:
                test_methods.append((test_file, method_name, test_node))
        except Exception as e:
            logger.exception(e)
            raise RuntimeError(
                f"Failed to parse {test_file} for test methods: {e}"
            ) from e

    return test_methods


def _get_test_classes() -> List[tuple[str, str, ast.ClassDef]]:
    """Get all test classes from all test files for parameterization."""

    # Check if we should analyze a specific file (for true positive testing)
    specific_file = os.environ.get('META_TESTER_TARGET_FILE')
    if specific_file:
        test_files = [specific_file]
    else:
        try:
            test_files = _get_test_files([
                "tests/meta_tester", 
            ])
        except Exception as e:
            raise RuntimeError(f"Failed to collect test files: {e}") from e

        test_files = {
            f for f in test_files 
            if Path(f).resolve() != Path(__file__).resolve()
        }

    test_classes = []
    for test_file in test_files:
        analyzer = _get_analyzer_for_file(test_file)
        try:
            classes = analyzer.get_test_classes()
            for class_name, class_node in classes:
                test_classes.append((test_file, class_name, class_node))
        except Exception as e:
            raise RuntimeError(
                f"Failed to parse {test_file} for test classes: {e}"
            ) from e

    return test_classes


TEST_METHODS = _get_test_methods()
TEST_CLASSES = _get_test_classes()
TEST_FILES = list({t[0] for t in TEST_METHODS})


@pytest.fixture
def make_analyzer():
    """Factory fixture to create a _TestFileAnalyzer instance."""
    def _make_analyzer(test_file: str) -> _TestFileAnalyzer:
        error = None
        try:
            analyzer = _get_analyzer_for_file(test_file)
            return analyzer
        except Exception as e:
            error = e
            logger.exception(error)
        finally:
            if error is not None:
                raise RuntimeError(f"Failed to create analyzer for {test_file}: {error}") from error
    return _make_analyzer


@pytest.mark.parametrize(
    "test_file,method_name,test_node", 
    TEST_METHODS,
    ids=[f"{Path(tf).stem}::{mn}" for tf, mn, _ in TEST_METHODS]
    )
class TestForTestSmells:

    def test_when_checking_test_then_test_only_tests_through_public_contract(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking that the test only tests through the public contract
        THEN the test should not access private attributes, methods, or properties
        """
        ZERO = 0
        analyzer = make_analyzer(test_file)
        private_attributes = analyzer.check_no_private_attribute_access(test_node)
        assert len(private_attributes) == ZERO, \
            f"{method_name}: Method accesses private attributes, methods, or properties.\n{private_attributes}" \
            " Tests must only interact with the public API of the class/module under test."

    # Individual parameterized tests for each violation type
    def test_when_checking_method_length_then_under_10_lines(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the method length excluding docstrings
        THEN the method should be 10 lines or fewer
        """
        analyzer = make_analyzer(test_file)
        TEN = 10
        number_of_lines = analyzer.check_method_length(test_node)
        assert number_of_lines <= TEN, \
            f"{method_name}: Method must be 10 lines or fewer (excluding docstrings), got {number_of_lines} instead."

    def test_when_checking_assertions_then_exactly_one_assertion(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the number of assertions
        THEN the method should have exactly one assert statement, no more, no less.
        """
        analyzer = make_analyzer(test_file)
        ONE = 1
        number_of_assertions = analyzer.check_single_assertion(test_node)
        assert number_of_assertions == ONE, \
            f"{method_name}: Method must have exactly 1 assert statement, got {number_of_assertions}"

    def test_when_checking_constructor_calls_then_no_constructor_initialization(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for constructor calls
        THEN the method should not contain constructor initialization
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_constructor_calls(test_node), \
            f"{method_name}: Method contains constructor calls. Object construction should be done in fixtures or setup methods."

    def test_when_checking_method_body_then_not_empty(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the method body
        THEN the method should contain executable statements
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_not_empty(test_node), \
            f"{method_name}: Method contains no executable statements. Empty test methods should be removed, implemented, or raise a NotImplementedError."

    def test_when_checking_assertion_messages_then_has_f_strings(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking assertion messages
        THEN all assertions must have an f-string message
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_assertion_for_f_string_messages(test_node), \
            f"{method_name}: Assertion does not have an f-string message"

    def test_when_checking_assertion_messages_then_has_f_strings_with_dynamic_content(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking assertion f-string messages
        THEN all f-string messages must contain dynamic content (e.g. {variable})
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_assertion_f_string_has_dynamic_content(test_node), \
            f"{method_name}: Assertions does not have an f-string with dynamic content" + "(e.g. assert x == y, f'Expected {x} to equal {y}')"

    def test_when_checking_production_calls_then_at_most_one_call(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking production method calls
        THEN the method should invoke at most one production method
        """
        analyzer = make_analyzer(test_file)
        ONE = 1
        num_production_calls = analyzer.check_single_production_call(test_node)
        assert num_production_calls == ONE, \
            f"{method_name}: Method invokes {num_production_calls} production methods. Should invoke at most 1 to minimize coupling of methods."

    def test_when_checking_production_calls_then_has_production_calls(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking production method calls
        THEN the method should invoke at least one production method
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_has_production_calls(test_node), \
            f"{method_name}: Method does not invoke any production methods. Should invoke at least 1."

    def test_when_checking_mocking_then_no_fake_tests(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for mocking patterns
        THEN the method should not mock the method under test
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_fake_tests(test_node), \
            f"{method_name}: Method mocks the method under test. Do not mock the method under test."

    def test_when_checking_skip_decorators_then_not_skipped(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for skip decorators
        THEN the method should not be skipped or ignored
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_not_skipped(test_node), \
            f"{method_name}: Method is skipped/ignored. Skipped/ignored tests should be removed or fixed."

    def test_when_checking_magic_literals_then_no_magic_numbers_or_strings(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for magic literals in assertions
        THEN the assertion should not contain magic numbers or strings
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_magic_literals(test_node), \
            f"{method_name}: Method assertion contains a magic number or string. Assign them to a named constant or variable, then test against that instead."

    def test_when_checking_external_resources_then_no_real_resources(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for external resource usage
        THEN the method should not use real external resources
        """
        analyzer = make_analyzer(test_file)
        ZERO = 0
        external_resources = analyzer.check_no_external_resources(test_node)
        assert len(external_resources) == ZERO, \
            f"{method_name}: Method calls the following real external resources\n{external_resources}. Use mocking, stubbing, fixtures, or programmatic generation in factories instead."

    def test_when_checking_print_logging_then_no_output_statements(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for the method's body.
        THEN the method should not contain print/logging statements.
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_print_logging(test_node), \
            f"{method_name}: Method contains print/logging statements. Logging/printing should be in production code, not in tests."

    def test_when_checking_redundant_assertions_then_no_always_true(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the method's assertions
        THEN "assert True" should not be present
        """
        boolean = True
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_redundant_assertions(test_node, boolean), \
            f"{method_name}: Method contains the assertion 'assert True'. Remove it."

    def test_when_checking_redundant_assertions_then_no_always_false(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the method's assertions
        THEN "assert False" should not be present
        """
        boolean = False
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_redundant_assertions(test_node, boolean), \
            f"{method_name}: Method contains the assertion 'assert False'. Remove it."

    def test_when_checking_equality_then_no_str_repr(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for equality patterns
        THEN the method should not use str or repr for comparisons
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_sensitive_equality(test_node), \
            f"{method_name}: Method uses str/repr in comparisons. Avoid using str/repr in tests."

    def test_when_checking_docstring_format_then_given_when_then_structure(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the docstring format
        THEN the docstring should follow GIVEN/WHEN/THEN structure with production method reference
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_given_when_then_format(test_node), \
            f"{method_name}: Docstring does not follow GIVEN/WHEN/THEN format with production method reference."

    def test_when_checking_test_naming_then_follows_convention(
        self,make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking the test naming convention
        THEN the method name should follow 'test_when_x_then_y' format
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_test_naming(method_name), \
            f"{method_name}: Method name does not follow 'test_when_x_then_y' format"

    def test_when_checking_fixture_usage_then_uses_whole_fixture(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking fixture usage patterns
        THEN the method should use the whole fixture instead of only accessing parts
        """
        # TODO: Include fixture's name in assert message.
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_partial_fixture_access(test_node), \
            f"{method_name}: Method only accesses parts of fixture instead of whole fixture"

    def test_when_checking_resource_assumptions_then_no_resource_optimism(
        self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN accessing external resources
        THEN the method should contain checks to confirm that the resource is available
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_resource_optimism(test_node), f"{method_name}: Method assumes external resource availability without checking (resource optimism)"


# TODO Finish writing fixture smell tests
# class TestForFixtureSmells:


#     def test_when_checking_fixture_then_no_resource_optimism(
#         self):
#         """
#         GIVEN a fixture defined in a test file
#         WHEN the fixtures AST body is checked
#         THEN the AST should contain at least one try-except block that raises an exception.
#         """
#         raise NotImplementedError("test_when_checking_fixture_then_no_resource_optimism not implemented yet")


#     def test_when_checking_fixture_usage_then_fixture_is_argument_in_one_or_more_callables(
#         self):
#         """
#         GIVEN a fixture defined in a test file
#         WHEN the arguments for all callables in the file are checked.
#         THEN fixture should be an argument in at least one callable.
#         """
#         raise NotImplementedError("test_when_checking_fixture_usage_then_fixture_is_argument_in_one_or_more_callables not implemented yet")


#     def test_when_checking_fixture_parameters_then_all_fixtures_used(
#         self
#     ):
#         """
#         GIVEN a callable with a fixture as a parameter
#         WHEN checking the callable's AST body
#         THEN the fixture should be referenced in the callable's body
#         """
#         raise NotImplementedError("test_when_checking_fixture_parameters_then_all_fixtures_used not implemented yet")
#         # analyzer = make_analyzer(test_file)
#         # unused_fixtures = analyzer.check_fixture_is_used(test_node)

#         # assert len(unused_fixtures) == 0, \
#         #     f"{method_name}: Unused fixture parameters: {unused_fixtures}. " \
#         #     "Remove unused fixtures from the method signature."


#     def test_when_fixture_defined_in_conftest_then_fixture_is_used_in_test_file(
#         self
#     ):
#         """
#         GIVEN a fixture defined in conftest.py
#         WHEN checking for fixture usage in a set of test files
#         THEN the fixture should be an argument in at least one test in the set
#         """
#         raise NotImplementedError("test_when_fixture_defined_in_conftest_then_fixture_is_used_in_test_file not implemented yet")


@pytest.mark.parametrize(
        "test_file,class_name,class_node", 
        TEST_CLASSES,
        ids=[f"{Path(tf).stem}::{mn}" for tf, mn, _ in TEST_CLASSES]
        )
def test_when_checking_class_docstring_then_mentions_production_class(
    make_analyzer, test_file, class_name, class_node):
    """
    GIVEN a test class in the codebase
    WHEN checking the class docstring
    THEN the docstring should mention the production method or function being tested
    """
    analyzer = make_analyzer(test_file)
    assert analyzer.check_class_docstring(class_node), \
        f"{class_name}: Class docstring does not mention production method/function being tested"


@pytest.mark.parametrize(
    "test_file,method_name,test_node", 
    TEST_METHODS,
    ids=[f"{Path(tf).stem}::{mn}" for tf, mn, _ in TEST_METHODS]
    )
class TestPresenceOfControlFlow:
    """Test that test methods do not contain control flow constructs."""

    @pytest.mark.parametrize("banned_node", [ast.If, ast.For, ast.While, ast.Match])
    def test_when_checking_test_then_no_conditional_logic(
        self, make_analyzer, test_file, method_name, test_node, banned_node
    ):
        """
        GIVEN a test method in the codebase
        WHEN checking the test method's AST
        THEN the method should not contain conditional logic constructs (if/for/while/try)
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_ast_node_not_present(test_node, banned_node), \
            f"{method_name}: Method contains conditional logic '{banned_node.__name__}'. Test methods should never contain conditional logic."

    def test_when_checking_exception_handling_then_no_try_except_blocks(self, make_analyzer, test_file, method_name, test_node):
        """
        GIVEN a test method in the codebase
        WHEN checking for exception handling
        THEN the method should not contain try/except blocks
        """
        banned_node = ast.Try
        analyzer = make_analyzer(test_file)
        assert analyzer.check_ast_node_not_present(test_node, banned_node), \
            f"{method_name}: Method contains try/except blocks. Exception handling should be done via pytest.raises or moved into a fixture/setup method."


@pytest.mark.parametrize("test_file", TEST_FILES)
class TestFileLevelChecks:
    """Test file-level checks that apply to the entire test file."""

    def test_when_checking_duplicate_assertions_then_no_duplicates(self, make_analyzer, test_file):
        """
        GIVEN a test file in the codebase
        WHEN checking for duplicate assertions
        THEN the file should not contain duplicate assertion patterns
        """
        analyzer = make_analyzer(test_file)
        assert analyzer.check_no_duplicate_assertions_within_file(), \
            f"{test_file}: File contains duplicate assertions. Each assertion across the entire test file must be unique. Either parameterize the tests, remove the duplicates, or move them to another test file."


    def test_when_checking_test_file_then_contains_shebang(self, test_file):
        """
        GIVEN a test file in the codebase
        WHEN checking for shebang presence
        THEN the file should contain a shebang line at the top
        """
        SHEBANG = '#!'

        # Get the first line of the file
        first_line = _read_first_line(test_file)

        assert first_line.startswith(SHEBANG), \
            f"{test_file}: File does not start with a shebang." \
            " All test files must start with a shebang line (e.g. #!/usr/bin/env python3)."

    def test_when_checking_test_file_then_contains_pytest_main(self, test_file):
        """
        GIVEN a test file in the codebase
        WHEN checking for pytest.main presence
        THEN the file should contain pytest.main at the bottom of the file.
        """
        PYTEST_MAIN = r'if\s+__name__\s*==\s*["\']__main__["\']\s*:\s+pytest\.main\(\[__file__\]\)'

        # Get the entire file content
        file_content = read_file_content(test_file)

        pytest_main_in_file = re.search(PYTEST_MAIN, file_content, re.MULTILINE)

        # Check if pytest.main is present in the file
        assert pytest_main_in_file is not None, \
            f"{test_file}: File does not contain pytest.main. All test files should contain pytest.main at the bottom (e.g. if __name__ == '__main__': pytest.main([__file__]))."


if __name__ == "__main__":
    pytest.main([__file__])
