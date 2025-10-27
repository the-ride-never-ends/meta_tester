from abc import ABC, abstractmethod
import ast
from enum import StrEnum
from pathlib import Path
from functools import cached_property
import logging
import hashlib
from typing import Any

from pydantic import BaseModel, Field, computed_field, FilePath


from ._production_class import ProductionClass
from logger import logger
from utils import read_file_content


class TestSmellName(StrEnum):
    ASSERTION_ROULETTE = "assertion_roulette"
    CONDITIONAL_LOGIC = "conditional_logic"
    CONSTRUCTOR_CALL = "constructor_call"
    DEFAULT_TEST = "default_test"
    DUPLICATE_ASSERTION = "duplicate_assertion"
    EAGER_TEST = "eager_test"
    EMPTY_TEST = "empty_test"
    EXCEPTION_HANDLING = "exception_handling"
    GENERAL_FIXTURE = "general_fixture"
    IGNORED_TEST = "ignored_test"
    LAZY_TEST = "lazy_test"
    MAGIC_LITERAL = "magic_literal"
    MYSTERY_GUEST = "mystery_guest"
    NO_ASSERTIONS = "no_assertions"
    MOCKING_TEST_METHOD = "mocking_test_method"
    REDUNDANT_PRINT = "redundant_print"
    RESOURCE_OPTIMISM = "resource_optimism"
    SENSITIVE_EQUALITY = "sensitive_equality"
    SLEEPY_TEST = "sleepy_test"
    UNKNOWN_TEST = "unknown_test"
    LONG_TEST = "long_test"
    IMPLEMENTATION_TEST = "implementation_test"
    GIVEN_WHEN_THEN_FORMAT = "given_when_then_format"
    CLASS_DOCSTRING_FORMAT = "class_docstring_format"


FILE_DICT = {
    "shebang": "#!/usr/bin/env python3",
    "encoding": "# -*- coding: utf-8 -*-",
    "main": "if __name__ == '__main__':\n    pytest.main()",
    "class_docstring": "Test class for the {smell_name} for {method_name} smell.",
    "method_docstring": """GIVEN a test method for {method_name}
        WHEN it has the {smell_name} smell
        THEN it should be detected by the meta-tester.""",
    "fixture": "@pytest.fixture\ndef {fixture_name}():\n    from tests._test_smell_generator import production_code\n    return production_code.ProductionClass()",
}

BUILTINS = set(dir(__builtins__))

def _md5_hash_string(string: str) -> str:
    return hashlib.md5(string.encode('utf-8')).digest().hex()

def _hash_node(node: ast.AST) -> str:
    return _md5_hash_string(ast.dump(node))

def _hash_nodes(nodes: list[ast.AST]) -> list[str]:
    return [_hash_node(node) for node in nodes]


def _check_if_ast_nodes_not_present(test_node, node_types: ast.AST | tuple[ast.AST]) -> bool:
    """Check for absence of specific AST node types in test methods."""
    if not isinstance(node_types, tuple):
        node_types = (node_types,)
    for child in ast.walk(test_node):
        if isinstance(child, node_types):
            return False
    return True


def _check_if_ast_nodes_are_present(test_node, node_types: ast.AST | tuple[ast.AST]) -> bool:
    """Check for presence of specific AST node types in test methods."""
    return _check_if_ast_nodes_not_present(test_node, node_types) is False


def _get_parent_class(method_node: ast.FunctionDef, tree: ast.AST) -> ast.ClassDef | None:
    class_name = None
    for parent in ast.walk(tree):
        if isinstance(parent, ast.ClassDef):
            for child in ast.walk(parent):
                if child is method_node:
                    class_name = parent.name
                    break
            if class_name:
                break
    return class_name

def _is_test_method(node: ast.AST) -> bool:
    return isinstance(node, ast.FunctionDef) and node.name.startswith('test_')

def _is_test_class(node: ast.AST) -> bool:
    return isinstance(node, ast.ClassDef) and node.name.startswith('Test')

def _is_fixture(node: ast.AST) -> bool:
    if isinstance(node, ast.FunctionDef):
        for decorator in node.decorator_list:
            match decorator:
                case ast.Name() if 'fixture' in decorator.id:
                    return True
                case ast.Attribute() if 'fixture' in decorator.attr:
                    return True
    return False

def _is_ast(child: Any) -> bool:
    """Check if child is an AST node."""
    return isinstance(child, ast.AST)

def _is_import(child: ast.AST) -> bool:
    """Check if AST node is an import statement."""
    return isinstance(child, (ast.Import, ast.ImportFrom))

# No imports falls under the "mystery guest" smell
def _check_has_no_imports(test_node: ast.AST) -> bool:
    """Check if AST node has import statements."""
    for child in ast.walk(test_node):
        if _is_import(child):
            return False
    return True


def _is_builtin(child: ast.AST) -> bool:
    """Check if AST node is a built-in."""
    return isinstance(child, ast.Name) and child.id in BUILTINS


def _is_assignment(child: ast.AST) -> bool:
    """Check if AST node is an assignment."""
    return isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign))

def _is_function_call(child: ast.AST) -> bool:
    """Check if AST node is a function call."""
    return isinstance(child, ast.Call) and isinstance(child.func, ast.Name)

def _is_module_level(node: ast.AST, tree: ast.AST) -> bool:
    """Check if AST node is at module level."""
    for parent in ast.walk(tree):
        if isinstance(parent, ast.Module):
            for child in ast.iter_child_nodes(parent):
                if child is node:
                    return True
    return False

def _is_async(node: ast.AST) -> bool:
    """Check if AST node is an async function."""
    return isinstance(node, ast.AsyncFunctionDef)

def _function_starts_with(string: str, node: ast.AST) -> bool:
    """Check if function call AST node starts with a specific string."""
    return node.func.id.startswith(string)


def _get_assertion_nodes(test_node: ast.AST) -> list[ast.AST]:
    assertions = []
    for child in ast.walk(test_node):
        match child:
            case ast.Assert():
                assertions.append(child)
            case ast.With() | ast.AsyncWith():
                if hasattr(child, 'items'):
                    for item in child.items:
                        if isinstance(item.context_expr, ast.Call):
                            raises = ('pytest.raises', 'unittest.TestCase.assertRaises')
                            if item.context_expr.func.id.startswith(raises):
                                assertions.append(child)
            case _:
                if _is_function_call(child) and _function_starts_with('assert', child):
                    assertions.append(child)
    return assertions

def _check_has_exactly_one_assert(test_node: ast.AST) -> bool:
    assertion_count = 0
    assertions = _get_assertion_nodes(test_node)
    return len(assertions) == 1





class TestSmell(BaseModel, ABC):

    path: FilePath = Field(..., description="The path to the test file.")
    logger: logging.Logger = Field(default=logger, description="Logger instance.")

    _tree: ast.Module | None = Field(default=None, description="The AST of the test file.")
    _source_code: str | None = Field(default=None, description="The source code of the test file.")
    _test_methods: dict[str, ast.FunctionDef] = Field(default_factory=dict, description="Dictionary of test methods in the file.")
    _test_classes: dict[str, ast.ClassDef] = Field(default_factory=dict, description="Dictionary of test classes in the file.")
    _fixtures: dict[str, ast.FunctionDef]  = Field(default_factory=dict, description="Dictionary of fixtures in the file.")
    _asserts: list[ast.AST] = Field(default_factory=list, description="List of assert statements in the file.")

    @computed_field
    @property
    def source_code(self) -> str:
        """Read the source code of the test file."""
        if self._source_code is None:
            try:
                self._source_code = read_file_content(self.path.resolve())
            except IOError as e:
                raise e
        return self._source_code

    @cached_property
    def tree(self) -> ast.Module:
        """Parse the test file content into an AST."""
        if self._tree is None:
            try:
                self._tree = ast.parse(self.source_code)
            except IOError as e:
                raise e
            except SyntaxError as e:
                raise SyntaxError(f"Failed to parse {self.path}: {e}") from e
            except Exception as e:
                raise RuntimeError(f"Unexpected error parsing {self.path}: {e}") from e
        return self._tree

    def _build_dictionaries(self) -> None:
        """Build internal dictionaries of test methods, classes, and fixtures."""
        for node in ast.walk(self.tree):
            if _is_module_level(node, self.tree):
                file_dict = {
                    'node': node,
                }

            if _is_test_method(node):
                class_name = _get_parent_class(node, self.tree)
                method_name = f"{class_name}.{node.name}" if class_name else node.name
                has_exactly_one_assert = _check_has_exactly_one_assert(node)

                method_dict = {
                    'node': node,
                    'class': class_name,
                    'async': _is_async(node),
                    'has_exactly_one_assert': has_exactly_one_assert,
                    'has_exactly_one_production_call': None, # TODO
                    'docstring_follows_given_when_then_format': None, # TODO
                    'docstring_has_production_name': None, # TODO
                    'has_no_imports': _check_has_no_imports(node),
                    'has_real_production_call': None, # TODO
                    'assertion_is_not_tautology': None, # TODO
                    'assertion_is_not_contradiction': None, # TODO
                }

                self._test_methods[method_name] = method_dict

            elif _is_test_class(node):

                class_dict = {
                    'node': node,
                    'has_docstring': bool(ast.get_docstring(node)),
                    'docstring_has_production_name': None, # TODO
                    'tests_exactly_one_production_callable': None, # TODO
                }
                self._test_classes[node.name]['node'] = class_dict

            elif _is_fixture(node):

                fixture_dict = {
                    'node': node,
                    'checks_resource_availability': None, # TODO
                }


                self._fixtures[node.name]['node'] = node


    @cached_property
    def python_builtins(self) -> set[str]:
        """Get a set of all Python built-in names."""
        return set(dir(__builtins__))

    @property
    def test_methods(self) -> dict[str, ast.FunctionDef]:
        """Get all test methods in the file."""
        if not self._test_methods:
            self._build_dictionaries()
        return self._test_methods

    @property
    def test_classes(self) -> dict[str, ast.ClassDef]:
        """Get all test classes in the file."""
        if not self._test_classes:
            self._build_dictionaries()
        return self._test_classes

    @property
    def fixtures(self) -> dict[str, ast.FunctionDef]:
        """Get all fixtures in the file."""
        if self._fixtures is None:
            self._build_dictionaries()
        return self._fixtures

    def get_node(self, key: str) -> ast.AST | None:
        for dict_ in (self.test_methods, self.test_classes, self.fixtures):
            if key in dict_:
                return dict_[key]['node'] 
        return None

    @abstractmethod
    def check_for(self, name: str) -> bool:
        """Check if the smell is present in the test file."""
        pass



class AssertionRoulette(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN each assertion should have a descriptive message.
        
        """
        assertion_count = 0
        test_node = self.get_node(name)

class StartsWithShebang(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test file
        WHEN the file is analyzed
        THEN it should start with a shebang line.
        """
        first_line = self.source_code.splitlines()[0]
        return first_line.startswith("#!")

class EndsWithPyTestMain(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test file
        WHEN the file is analyzed
        THEN it should end with a pytest main invocation.
        """
        last_lines = self.source_code.splitlines()[-2:]
        return any("if __name__ == '__main__':" in line for line in last_lines) and any("pytest.main" in line for line in last_lines)


class NoConditionalLogic(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be no conditional logic (if, else, elif, match).
        """
        test_node = self.get_node(name)
        return _check_if_ast_nodes_not_present(test_node, (ast.If, ast.Match))

class NoControlFlow(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be no control flow statements (for, while, break, continue).
        """
        test_node = self.get_node(name)
        return _check_if_ast_nodes_not_present(test_node, (ast.For, ast.While, ast.Break, ast.Continue))

class NoExceptionHandling(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be no exception handling (try, except, finally).
        """
        test_node = self.get_node(name)
        return _check_if_ast_nodes_not_present(test_node, ast.Try)

class NoConstructorInitializations(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be no instantiation of classes.
        """
        test_node = self.get_node(name)
        for child in ast.walk(test_node):
            if _is_function_call(child) and child.func.id[0].isupper():
                return False
        return True

def _check_test_value_is_boolean(assert_node: ast.Assert, boolean: bool) -> bool:
    """Check if an assert statement is a tautology (always true)."""
    if isinstance(assert_node.test, ast.Constant):
        return assert_node.test.value is boolean
    return False

def _check_tautology_in_assertion(assert_node: ast.Assert) -> bool:
    """Check if an assert statement is a tautology (always true)."""
    return _check_test_value_is_boolean(assert_node, True)

def check_contradiction_in_assertion(assert_node: ast.Assert) -> bool:
    """Check if an assert statement is a contradiction (always false)."""
    return _check_test_value_is_boolean(assert_node, False)




class NoAlwaysTrueAssertions(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be no assertions that are always true.
        """
        test_node = self.get_node(name)
        for child in ast.walk(test_node):
            if isinstance(child, ast.Assert):
                if isinstance(child.test, ast.Constant) and child.test.value is True:
                    return False
            elif _is_function_call(child) and child.func.id == 'assertTrue':
                return False
        return True



class ExactlyOneProductionCall(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN the callable should be called exactly once, no more, no less.
        """
        test_node = self.get_node(name)
        production_call_count = 0
        for child in ast.walk(test_node):
            if _is_function_call(child) and child.func.id == name:
                production_call_count += 1
        return production_call_count == 1


class ExactlyOneAssertion(TestSmell):

    def check_for(self, name: str) -> bool:
        """
        GIVEN a test method for a callable
        WHEN the method's AST is analyzed
        THEN there should be exactly one assertion present, no more, no less.
        """
        assertion_count = 0
        test_node = self.get_node(name)
        for child in ast.walk(test_node):
            match child:
                case ast.Assert():
                    assertion_count += 1
                case ast.With() | ast.AsyncWith():
                    if hasattr(child, 'items'):
                        for item in child.items:
                            if isinstance(item.context_expr, ast.Call):
                                if item.context_expr.func.id.startswith('pytest.raises'):
                                    assertion_count += 1
                case _:
                    if _is_function_call(child) and _function_starts_with('assert', child):
                        assertion_count += 1
        return assertion_count == 1



file_string = '''
{shebang}
{encoding}
"""
Test file with intentional {smell_name} smell for testing the meta-testing suite.
"""


import pytest


class TestSmell{smell_name}:
    """{class_docstring}"""

    def test_{smell_name}(self, {fixture_name}):
        """
        {method_docstring}
        """
        {test_code}

{main}

'''

def make_test_smell_file(
        *,
        smell_name: str,
        test_code: str,
        fixture_name: str = "production_class",
        method_name: str = "production_method", 
        ) -> Path:
    """Generate a test file string for a specific smell.

    Args:
        smell_name (str): Name of the smell (e.g., "NoAssertions").
        method_name (str): Name of the method being tested (e.g., "some_function").
        test_code (str): The test code that exhibits the smell.

    Returns:
        str: The path to the generated test file.
    """
