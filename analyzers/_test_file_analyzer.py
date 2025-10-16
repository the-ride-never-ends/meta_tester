#!/usr/bin/env python3
"""
Meta-test suite to enforce good testing practices.

This module contains pytest tests that analyze other test files to ensure they follow
best practices for unit testing. It acts as a quality gate to prevent test smells
and ensure consistent testing standards across the codebase.
"""
import ast
import builtins
import hashlib
import logging
import importlib.util
import re
from pathlib import Path
from typing import Any, Callable


from logger import logger
from utils import read_file_content
from individual_tests.check_method_length import check_method_length
from analyzers.fixture_analyzer import FixtureAnalyzer
from tests._fixture_attribute_analyzer import check_fixture_attribute

# Hash the file.
_THIS_DIR = Path(__file__).parent
hash_file_path = _THIS_DIR / "test_file_analyzer.txt"

EXCLUDED_DIRS = {
    '.venv', 'venv', 'node_modules', '.git', '__pycache__', '.pytest_cache', '.mypy_cache', 'site-packages'
}


# def _make_hash_of_this_file() -> str:
#     with open(__file__, 'rb') as f:
#         return hashlib.sha256(f.read()).hexdigest()

# try:
#     with open(hash_file_path, 'r') as f:
#         expected_hash = f.read().strip()

#     file_hash = _make_hash_of_this_file()

#     assert file_hash == expected_hash, \
#         "The test enforcement file has been modified without user permission." \
#         " DO NOT CHANGE THE TESTS TO MATCH THE IMPLEMENTATION. CHANGE THE IMPLEMENTATION TO MATCH THE TESTS." \
#         " CONSIDER THIS YOUR FINAL WARNING."

# except FileNotFoundError:

#     file_hash = _make_hash_of_this_file()
#     with open(hash_file_path, 'w') as f:
#         f.write(file_hash)

# except Exception as e:
#     raise RuntimeError(f"Error checking test enforcement file integrity: {e}") from e





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



class _TestFileAnalyzer:
    """Analyzes test files for various violations."""

    def __init__(self, 
                 file_path: str, 
                 logger: logging.Logger = logger,
                 check_fixture_attribute: Callable = check_fixture_attribute,
                 ):
        self.logger = logger
        self.file_path = file_path
        self.source_code = read_file_content(file_path)
        self.check_fixture_attribute = check_fixture_attribute
        #self.check_method_length = check_method_length
        try:
            self.tree = ast.parse(self.source_code)
        except SyntaxError as e:
            raise SyntaxError(f"Failed to parse {file_path}: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error parsing {file_path}: {e}") from e

        self.fixtures: dict[str, ast.FunctionDef] = FixtureAnalyzer(tree=self.tree, file_path=file_path, logger=logger).fixtures
        self.third_party_imports: set[str] = self._get_imports()
        self.builtins: set[str] = self._get_builtins()
        self.decorators: set[str] = self._get_decorators()
        self.builtin_attributes: set[str] = self._get_attributes_of_builtins()


        # Remove pytest from third-party imports if present
        if 'pytest' in self.third_party_imports:
            self.third_party_imports.remove('pytest')
        self.logger.debug(f"Third-party imports at __init__: {self.third_party_imports}")
        self.logger.debug(f"Decorators for file: {self.decorators}")
        # self.logger.debug(f"Built-in names: {self.builtins}")
        # self.logger.debug(f"Built-in attributes: {self.builtin_attributes}")

    def perform_test(self, name: str, *args) -> Any:
        class_dict = {
            attr for attr in dir(self) if not attr.startswith('_')
        }
        if name in class_dict:
            method = getattr(self, name)
            return method(*args)
        else:
            raise AttributeError(f"Test method {name} not found in _TestFileAnalyzer.")
 
    def _get_builtins(self) -> set:
        # Get all built-in names
        direct_builtins = set((sorted(set(dir(builtins)))))
        # Get all the imports into builtins too.
        imported_builtins = set()
        for name in direct_builtins:
            try:
                obj = getattr(builtins, name)
                if hasattr(obj, '__module__') and obj.__module__ == 'builtins':
                    imported_builtins.add(name)
            except Exception:
                continue
        imported_builtins = sorted(imported_builtins)
        self.logger.debug(f"Direct built-ins: {direct_builtins}")
        self.logger.debug(f"Imported built-ins: {imported_builtins}")
        all_builtins = direct_builtins.union(imported_builtins)
        return all_builtins


    def _get_attributes_of_builtins(self) -> set[str]:
        """Get all attributes of built-in types."""
        attributes = []
        for builtin_name in dir(builtins):
            try:
                builtin_obj = getattr(builtins, builtin_name)
                for attr in dir(builtin_obj):
                    attributes.append(attr)
            except Exception as e:
                self.logger.debug(f"Could not get attributes of builtin {builtin_name}: {e}")
        assert isinstance(attributes, list), f"Attributes list should be list, got {type(attributes)}"
        self.logger.debug(f"Attributes list before sorting: {attributes}")
        attributes = sorted(attributes) # TODO: Hack to include 'read' method of file objects. Should be fixed more robustly.
        assert isinstance(attributes, list), f"Attributes list should be list after sorting, got {type(attributes)}"
        attributes.append('read')
        self.logger.debug(f"Built-in attributes: {attributes}")
        attributes = set(attributes)
        self.logger.debug(f"Set of Built-in attributes: {attributes}")
        return attributes

    def get_test_methods(self):
        """Get all test methods in the file."""
        test_methods = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                class_name = None
                # Find parent class if exists
                for parent in ast.walk(self.tree):
                    if isinstance(parent, ast.ClassDef):
                        for child in ast.walk(parent):
                            if child is node:
                                class_name = parent.name
                                break
                        if class_name:
                            break

                method_name = f"{class_name}.{node.name}" if class_name else node.name
                test_methods.append((method_name, node))
        return test_methods

    def get_test_classes(self):
        """Get all test classes in the file."""
        test_classes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith('Test'):
                test_classes.append((node.name, node))
        return test_classes

    def _get_decorators(self) -> set[str]:
        """Get all decorators used in the file."""
        decorators = set()
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                if hasattr(node, 'decorator_list'):
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Name):
                            decorators.add(decorator.id)
                        elif isinstance(decorator, ast.Attribute):
                            decorators.add(decorator.attr)
        return decorators

    @staticmethod
    def _is_function_call(child: ast.AST) -> bool:
        """Check if AST node is a function call."""
        return isinstance(child, ast.Call) and isinstance(child.func, ast.Name)

    def check_method_length(self, test_node: ast.AST) -> int:
        """Check if method is longer than 10 lines (excluding docstrings)."""
        start_line = test_node.lineno
        end_line = test_node.end_lineno

        # Skip docstring if present
        docstring_lines = 0
        docstring = ast.get_docstring(test_node)
        if docstring is not None:
            docstring_end = test_node.body[0].end_lineno
            docstring_lines = docstring_end - start_line + 1

        total_lines = end_line - start_line + 1 - docstring_lines
        return total_lines

    def check_single_assertion(self, test_node: ast.AST) -> int:
        """Check for exactly one assertion in a test method."""
        assertion_count = 0
        for child in ast.walk(test_node):
            if self._is_function_call(child):
                if child.func.id.startswith('assert'):
                    assertion_count += 1
            elif isinstance(child, ast.Assert):
                assertion_count += 1
            # Handle pytest.raises context manager
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                if hasattr(child, 'items'):
                    for item in child.items:
                        if isinstance(item.context_expr, ast.Call):
                            if item.context_expr.func.id.startswith('pytest.raises'):
                                assertion_count += 1
        return assertion_count


    def check_ast_node_not_present(self, test_node, node_type) -> bool:
        """Check for absence of specific AST node types in test methods."""
        for child in ast.walk(test_node):
            if isinstance(child, node_type):
                return False
        return True


    def check_no_exception_handling(self, test_node: ast.AST) -> int:
        """Check for absence of try/except blocks in test methods."""
        return self.check_ast_node_not_present(test_node, ast.Try)


    def check_no_constructor_calls(self, test_node: ast.AST) -> bool:
        """Check for absence of constructor calls in test methods."""
        for child in ast.walk(test_node):
            if self._is_function_call(child) and child.func.id[0].isupper():
                return False
        return True


    def check_not_empty(self, test_node: ast.AST) -> bool:
        """
        Check for non-empty test methods.

        These are defined as as methods that do not contain an executable statement.
        
        Args:
            test_node: AST node of the test method

        Returns:
            bool: True if method is not empty, False otherwise
        """
        executable_statements = []
        for stmt in test_node.body:
            # Skip docstrings
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                continue
            # Skip pass and ellipsis statements
            if isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value == Ellipsis):
                continue
            executable_statements.append(stmt)
        return len(executable_statements) > 0


    def _is_assert(self, child: ast.AST) -> bool:
        # TODO: This works for pytest, but not for unittest assertions
        return isinstance(child, ast.Assert)


    def _get_msg_node(self, child):
        """Get message node from pytest assert statement.
        
        Args:
            child: AST node representing an assertion
            
        Returns:
            AST node representing the assertion message, or None if no message exists
        """
        if not isinstance(child, ast.Assert):
            return None
        return child.msg


    def check_assertion_for_f_string_messages(self, test_node: ast.AST) -> bool:
        """Check that assertions have descriptive f-string messages."""
        for child in ast.walk(test_node):
            if isinstance(child, ast.Assert) and child.msg is None:
                return False
        return True


    def check_assertion_f_string_has_dynamic_content(self, test_node: ast.AST) -> bool:
        """Check that f-string messages contain dynamic content (variables/expressions)."""

        for child in ast.walk(test_node):
            if self._has_decorator(child):
                #self.logger.debug(f"Skipping decorator: {ast.unparse(child)}")
                continue

            if self._is_assert(child):
                #self.logger.debug(f"assert_node: {ast.dump(child)}")
                msg_node = self._get_msg_node(child)

                # Check if f-string has dynamic content
                # NOTE: JoinedStr with actual dynamic content appears to be 
                    # a list of Constants and Formatted Values, 
                    # whereas non-dynamic f-strings are just a single Constant
                if msg_node and isinstance(msg_node, ast.JoinedStr):
                    for value in msg_node.values:
                        if isinstance(value, ast.FormattedValue):
                            return True
                    else:
                        return False
                else:
                    return False
        return True

    def _hash_nodes(self, nodes: ast.AST | list[ast.AST]) -> list[str]:
        if isinstance(nodes, ast.AST):
            nodes = [nodes]

        hashes = [
            hashlib.md5(ast.dump(node).encode('utf-8')).digest().hex() for node in nodes
        ]
        return hashes

    def _get_asserts(self, test_node: ast.AST) -> list[ast.Assert]:
        """Extract all assertion calls from a test method."""
        return [child for child in ast.walk(test_node) if self._is_assert(child)]

    def check_no_duplicate_assertions(self, test_node: ast.AST) -> bool:
        """Check for absence of duplicate assertion patterns."""
        asserts = self._get_asserts(test_node)

        # Get the left-side of each assertion for comparison
        self.logger.debug(f"Assertions in method {test_node.name}: {asserts}")

        for assertion in asserts:
            delattr(assertion, 'msg')
            self.logger.debug(f"Assertion without msg: {ast.dump(assertion)}")

        tests = self._hash_nodes(self, asserts)

        self.logger.debug(f"Assertion tests in method {test_node.name}: {tests}")

        # Get the left-side of each assertion for comparison
        self.logger.debug(f"Assertions bodies in file: {len(tests)}\n unique assertions: {len(set(tests))}")
        self.logger.debug(f"Assertion bodies in method: {tests}")

        return len(tests) == len(set(tests))

    def check_no_duplicate_assertions_within_file(self) -> bool:
        """Check for absence of duplicate assertion patterns within the entire test file."""
        try:
            asserts = []
            for node in ast.walk(self.tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                    assert_strings = self._get_asserts(node)
                    for string in assert_strings:
                        assertion_node = ast.parse(string)
                        #self.logger.debug(f"Assertion node before removing msg: {ast.dump(assertion_node)}")
                        #self.logger.debug("dir(assertion_node): " + str(dir(assertion_node)))
                        asserts.append(assertion_node)
            # self.logger.debug(f"All assertions: {asserts}")
            # self.logger.debug(f"Length of all assertions: {len(asserts)}")

            for assertion in asserts:
                delattr(assertion, 'msg')
            #     self.logger.debug(f"Assertion without msg: {ast.dump(assertion)}")
            # self.logger.debug("SHOULD_REACH_HERE")

            tests = [
                hashlib.md5(ast.dump(a).encode('utf-8')).digest().hex() for a in asserts
            ]

            # Get the left-side of each assertion for comparison
            #self.logger.debug(f"Assertions bodies in file: {len(tests)}\n unique assertions: {len(set(tests))}")
            #self.logger.debug(f"Assertion bodies in method: {tests}")

            return len(tests) == len(set(tests))
        except Exception as e:
            self.logger.exception(f"Error checking duplicate assertions: {e}")
            return False

    @staticmethod
    def is_callable_value(node):
        """Check if AST node represents callable value."""
        return isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef))

    def _is_call_and_attribute(self, child: ast.AST) -> bool:
        return isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)

    def check_exactly_one_production_call(self, test_node: ast.AST) -> bool:
        """Check for exactly one production method call."""
        calls = self.check_single_production_call(test_node)
        return calls == 1

    # TODO Fix this test.
    def check_single_production_call(self, test_node: ast.FunctionDef) -> int:
        """Check for at most one production method call."""
        self.logger.debug(f"Checking production calls in method {test_node.name}")
        calls = set()
        repeated_calls = set()
        fixture_params = self._get_fixture_params(test_node)

        try:
            # Get decorator nodes to exclude them
            decorator_nodes = set()
            if hasattr(test_node, 'decorator_list'):
                self.logger.debug(f"Decorator list: {test_node.decorator_list}")
                decorator_hashes = self._hash_nodes(test_node.decorator_list)
                decorator_nodes.update(set(decorator_hashes))
            self.logger.debug(f"Decorator nodes: {decorator_nodes}")

            method_name = self._get_method_name(test_node)

            # Count the number of times the production method name appears in the test body
            for node in ast.walk(test_node):
                if self._hash_nodes(node)[0] in decorator_nodes:
                    continue

                if isinstance(node, ast.Call):
                    callable_name = None
                    if isinstance(node.func, ast.Attribute):
                        callable_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        callable_name = node.func.id

                    if callable_name is not None and callable_name == method_name:
                        # Get the line number of the call
                        self.logger.debug(f"Found call to production method {callable_name} at line {node.lineno}")
                        repeated_calls.add((node.lineno, callable_name))

            self.logger.debug(f"Repeated calls: {repeated_calls}")

            # Count the number of different production method calls via fixtures
            for fixture in fixture_params:

                if fixture is None or not fixture.strip():
                    continue

                for node in ast.walk(test_node):
                    # Skip nodes that are part of decorators
                    if self._hash_nodes(node)[0] in decorator_nodes:
                        continue

                    if self._is_call_and_attribute(node):
                        self.logger.debug(f"Found call node: {ast.dump(node)}")
                        node_id = node.func.value.id
                        self.logger.debug(f"node_id: {node_id}, fixture: {fixture}")

                        # If the object being called is a third-party import or builtin, skip
                        if node_id in self.third_party_imports:
                            continue
                        self.logger.debug("node_id: " + str(node_id))
                        if node_id in self.builtins:
                            continue

                        is_attr = check_fixture_attribute(self.tree, fixture, node.func.attr)

                        if hasattr(node.func, 'attr'):
                            attr_name = node.func.attr
                            self.logger.debug(f"attr_name: {attr_name}")
                            if attr_name in self.builtins:
                                continue
                            if attr_name in self.builtin_attributes:
                                continue

                        calls.add((node.lineno, node.func.attr))
                        self.logger.debug(f"Found production call via fixture {fixture}: {node.func.attr} at line {node.lineno}")
                    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                        is_attr = check_fixture_attribute(self.tree, fixture, node.attr)
                        if is_attr:

                            if node.value.id == fixture:
                                self.logger.debug(f"Found attribute node: {ast.dump(node)}")
                                calls.add((node.lineno, node.attr))

            self.logger.debug(f"Production calls in method '{test_node.name}': {calls}\nNon-unique calls: {len(repeated_calls)}")

            if len(calls) > 1:
                self.logger.debug(f"Multiple different production calls found: {calls}")
                return len(calls)
            else:
                if len(repeated_calls) > 1:
                    self.logger.debug(f"Repeated calls found for {method_name}: {repeated_calls}")
                return len(repeated_calls)

        except Exception as e:
            self.logger.exception(f"Error checking production calls: {e}")


    def check_has_production_calls(self, test_node: ast.AST) -> bool:
        """Check for at least one production method call."""
        # Only walk the body, not decorators
        for stmt in test_node.body:
            for child in ast.walk(stmt):
                if not self._is_call_and_attribute(child):
                    continue
                    
                if (not child.func.attr.startswith('assert') and
                    not child.func.attr.startswith('mock')):
                    return True
        return False

    def _has_decorator(self, child: ast.AST) -> bool:
        """Check if an AST node is a decorator."""
        node_string = ast.unparse(child)
        if not node_string:
            return False
        if not node_string.startswith('@'):
            return False
        self.logger.debug(f"Found decorator node: {node_string}")
        return True

    def _get_definition_without_decorator(self, decorator_node: ast.AST) -> ast.AST | None:
        """Get the function or class definition that a decorator is applied to."""
        for node in ast.walk(self.tree):
            if hasattr(node, 'decorator_list'):
                if decorator_node in node.decorator_list:
                    # Get the AST without the decorator
                    node.decorator_list.remove(decorator_node)
                    self.logger.debug(f"Definition without decorator: {ast.unparse(node)}")
                    return node
        return None


    def check_no_fake_tests(self, test_node: ast.AST) -> bool:
        """Check for absence of mocking the method under test."""
        banned_calls = [
            'mock', 'patch', 'asyncmock', 'magicmock', 'sentinel',
            'create_autospec', 'propertymock', 'noncallablemock'
        ]
        self.logger.debug(f"Fixtures available: {self.fixtures}")
        method_name = self._get_method_name(test_node)

        if not method_name:
            self.logger.debug("No method name found in test node.")
            return True

        for name, fixture in self.fixtures.items():
            #self.logger.debug(f"Fixture {name}: {ast.dump(fixture)}")
            for stmt in fixture.body:
                stmt_string = ast.unparse(stmt)
                if method_name in stmt_string:
                    self.logger.debug(f"Method {method_name} found in fixture {name}: {ast.unparse(stmt)}")
                    for banned_call in banned_calls:
                        if banned_call in stmt_string.lower():
                            self.logger.debug(f"Found banned call {banned_call} in fixture {name}")
                            return False
        return True


    def check_not_skipped(self, test_node: ast.AST) -> bool:
        """Check for absence of skipped/ignored tests."""
        banned_decorators = ['skip', 'skipif']

        if self._has_decorator(test_node):
            node_string = ast.unparse(test_node)
            self.logger.debug(f"node_string: {node_string}")
            for decorator in banned_decorators:
                if decorator in node_string:
                    self.logger.debug(f"Found decorator: {ast.unparse(decorator)}")
                    return False
        return True

    def check_no_magic_literals(self, test_node: ast.AST) -> bool:
        """Check for absence of magic numbers/strings in assertions."""
        allowed_literals = [True, False, None]
        for child in ast.walk(test_node):
            if self._is_assert(child):
                # Check the test expression (left side of assertion)
                for node in ast.walk(child.test):
                    if isinstance(node, ast.Constant) and node.value not in allowed_literals:
                        self.logger.debug(f"Found magic literal in assertion test: {node.value}")
                        return False
        return True

    def _get_external_resources(self, test_node: ast.AST) -> list[str]:
        """
        Extract external resource calls (e.g. calls to files, database, etc.) from a test method.
        """
        banned_calls = [
            'open', 'requests', 'urllib', 'socket', 'database', 
            'db', 'http', 'https', 'ftp', 'ssh', 'telnet', 'smtp', 
            'pop3', 'imap', 'ldap', 'redis', 'mongodb', 'mysql', 
            'postgresql', 'sqlite', 'oracle', 'cassandra', 'elasticsearch', 
            'kafka', 'rabbitmq', 'memcached', 'consul', 'etcd', 'zookeeper', 
            'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'cloud', 'api', 
            'rest', 'graphql', 'grpc', 'soap', 'json', 'xml', 'csv', 'excel', 
            'pdf', 'email', 'sms', 'push', 'notification', 'webhook', 'cron', 
            'scheduler', 'queue', 'worker', 'celery', 'rq', 'background', 'async', 
            'thread', 'process', 'subprocess', 'shell', 'command', 'exec', 'system', 
            'os', 'path', 'file', 'directory', 'filesystem', 'network', 'internet', 
            'web', 'browser', 'selenium', 'webdriver', 'scraping', 'crawler', 'spider', 
            'download', 'upload', 'transfer', 'sync', 'backup', 'restore', 'migration', 
            'deploy', 'deployment', 'ci', 'cd', 'jenkins', 'gitlab', 'github', 'bitbucket', 
            'travis', 'circle', 'appveyor', 'azure-devops', 'terraform', 'ansible', 'puppet', 
            'chef', 'vagrant', 'docker-compose', 'helm', 'istio', 'prometheus', 'grafana', 'elk', 
            'splunk', 'datadog', 'newrelic', 'sentry', 'rollbar', 'bugsnag', 'honeybadger', 'airbrake', 
            'raygun', 'crashlytics', 'firebase', 'supabase', 'auth0', 'okta', 'cognito',
            'keycloak', 'ldap', 'saml', 'oauth', 'jwt', 'session', 'cookie', 'cache', 'storage', 
            's3', 'gcs', 'blob', 'cdn', 'cloudfront', 'cloudflare', 'fastly', 'akamai', 'maxcdn', 
            'keycdn', 'bunnycdn', 'jsdelivr', 'unpkg', 'cdnjs', 'bootcdn', 'staticfile'
        ]
        external_resources_list = []
        for child in ast.walk(test_node):
            if isinstance(child, ast.Call):
                call_name = ""
                match child.func:
                    case ast.Name():
                        # Simple function call like requests()
                        call_name = child.func.id.lower()
                        self.logger.debug(f"Found call from child.func and ast.Name: {call_name}")
                    case ast.Attribute():
                        # Attribute call like requests.get() or module.func()
                        # First, check if it's from a third-party import
                        # if call_name in self.imports:
                        #     call_name = child.func.attr.lower()

                        if isinstance(child.func.value, ast.Name):
                            call_name = f"{child.func.value.id}.{child.func.attr}".lower()
                            self.logger.debug(f"Found call from child.func.value and ast.Name: {call_name}")
                        else:
                            call_name = child.func.attr.lower()
                            self.logger.debug(f"Found call from child.func.attr: {call_name}")
                calls = [call for call in banned_calls if call in call_name]
                external_resources_list.extend(calls)
        return external_resources_list

    def check_no_external_resources(self, test_node: ast.AST) -> bool:
        """Check for absence of real external resources."""
        banned_ast_nodes = (ast.Import, ast.ImportFrom)
        external_resources_list = self._get_external_resources(test_node)

        for child in ast.walk(test_node):
            if isinstance(child, banned_ast_nodes):
                external_resources_list.append('import')
        return external_resources_list

    def check_no_print_logging(self, test_node: ast.AST) -> bool:
        """Check for absence of print/logging statements."""
        banned_calls = ['print', 'log', 'logger', 'logging']
        for child in ast.walk(test_node):
            if self._is_function_call(child):
                for banned_call in banned_calls:
                    if banned_call in child.func.id.lower():
                        return False
        return True

    def check_no_redundant_assertions(self, test_node, boolean: bool) -> bool:
        """Check for absence of assertions that are always true or false."""
        for node in ast.walk(test_node):
            if isinstance(node, ast.Assert):
                if isinstance(node.test, ast.Constant) and node.test.value is boolean:
                    self.logger.debug(f"Redundant assertion found: {ast.dump(node)}")
                    return False
        return True


    def check_no_sensitive_equality(self, test_node: ast.AST) -> bool:
        """Check for absence of str/repr usage in test methods."""
        banned_calls = ['str', 'repr']
        for child in ast.walk(test_node):
            if self._is_function_call(child) and child.func.id.lower() in banned_calls:
                return False
        return True


    def check_given_when_then_format(self, test_node: ast.AST) -> bool:
        """
        Check docstring format for GIVEN/WHEN/THEN structure. Docstring must contain
        - The keywords "GIVEN", "WHEN", and "THEN" in uppercase
        - The name of the production callable (method or function) being tested

        Args:
            test_node: AST node of the test method

        Returns:
            bool: True if docstring follows the format, False otherwise
        """
        docstring = ast.get_docstring(test_node)
        #self.logger.debug(f"docstring: {docstring}")
        if not docstring:
            return False

        # Check for GIVEN/WHEN/THEN format
        requirements = ['GIVEN', 'WHEN', 'THEN']
        for requirement in requirements:
            if requirement not in docstring:
                return False

        # Check for production method name
        method_name = self._get_method_name(test_node)
        self.logger.debug(f"method_name: {method_name}")
        if method_name is None:
            #self.logger.debug("Method name is None")
            return False

        if method_name in docstring:
            #self.logger.debug(f"Method name found in docstring: {method_name}\nDocstring: {docstring}")
            return True
        else:
            #self.logger.debug(f"Method name not in docstring: {method_name}\nDocstring: {docstring}")
            return False




    def _get_imports(self) -> set:
        # Get all imported names from the module
        third_party_imports = set()
        for node in ast.walk(self.tree):
            match node:
                case ast.Import() | ast.ImportFrom():
                    for alias in node.names:
                        #self.logger.debug(f"Import found: {alias.name}")
                        third_party_imports.add(alias.asname if alias.asname else alias.name)
                case _:
                    continue

        import_paths = {}
        for name in third_party_imports:
            try:
                spec = importlib.util.find_spec(name)
                if spec and spec.origin and spec.origin != 'built-in':
                    # Get canonical path to handle symlinks etc.
                    path = Path(spec.origin).resolve()
                    import_paths[name] = path
            except (ModuleNotFoundError, ImportError):
                self.logger.debug(f"Could not find spec for import '{name}'")
        #self.logger.debug(f"Import paths: {import_paths}")

        # Check if the imports come from a virtual environment
        # TODO This could be made more robust.
        venv_dir_names = {'venv', '.venv', 'env', '.env', 'site-packages'}
        filtered_imports = set()
        for name, path in import_paths.items():
            for venv in venv_dir_names:
                if venv in path.parts:
                    filtered_imports.add(name)
                    break
            else:
                self.logger.debug(f"Excluding import '{name}' with path: {path}")
        # self.logger.debug(f"Third-party imports: {filtered_imports}")
        return filtered_imports


    def _is_local(self, name: str) -> bool:
        if not self.third_party_imports:
            return True
        if name in self.builtins:
            return False
        if name in self.builtin_attributes:
            return False
        if name in self.third_party_imports:
            return False
        if name.startswith('_'):
            return False
        return True


    def _get_method_name(self, test_node: ast.AST) -> str:
        """
        Extract the name of the production callable (method or function) being tested.

        Strategy: Check imports in the module to determine which callables are 
        locally defined vs builtins/third-party. Prioritize methods, then functions, then classes.

        Args:
            test_node: AST node of the test method
            
        Returns:
            str: Name of the production callable being called, or "NOT FOUND" if not found
        """
        # Build symbol table for classes vs functions
        classes = set()
        functions = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                classes.add(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.add(node.name)

        method_candidate = None
        function_candidate = None
        class_candidate = None

        # Look for assignment patterns first: result = some.method() or result = function()
        for node in ast.walk(test_node):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if isinstance(node.value, ast.Call):
                        match node.value.func:
                            case ast.Attribute():
                                callable_name = node.value.func.attr
                                # If the attribute's id is a third-party import, skip
                                obj_id = node.value.func.value.id
                                if obj_id in self.third_party_imports:
                                    continue

                                if self._is_local(callable_name):
                                    if not method_candidate:
                                        method_candidate = callable_name
                            case ast.Name():
                                callable_name = node.value.func.id
                                if self._is_local(callable_name):
                                    if callable_name in functions:
                                        if not function_candidate:
                                            function_candidate = callable_name
                                    elif callable_name in classes:
                                        if not class_candidate:
                                            class_candidate = callable_name
                                    else:
                                        # Use PascalCase heuristic
                                        if callable_name[0].isupper():
                                            if not class_candidate:
                                                class_candidate = callable_name
                                        else:
                                            if not function_candidate:
                                                function_candidate = callable_name

        # Return early if we found a method
        if method_candidate:
            return method_candidate

        # If not found, look for direct calls: some.method() or function()
        for node in test_node.body:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    match child.func:
                        case ast.Attribute():
                            callable_name = child.func.attr
                            self.logger.debug(f"Found attribute call: {ast.dump(child)}")
                            # obj_id = node.value.func.value.id
                            # if obj_id in self.third_party_imports:
                            #     continue

                            if self._is_local(callable_name):
                                if not method_candidate:
                                    method_candidate = callable_name
                        case ast.Name():
                            callable_name = child.func.id
                            if self._is_local(callable_name):
                                if callable_name in functions:
                                    if not function_candidate:
                                        function_candidate = callable_name
                                elif callable_name in classes:
                                    if not class_candidate:
                                        class_candidate = callable_name
                                else:
                                    # Use PascalCase heuristic
                                    if callable_name[0].isupper():
                                        if not class_candidate:
                                            class_candidate = callable_name
                                    else:
                                        if not function_candidate:
                                            function_candidate = callable_name

        # Prioritize: method > function > class
        if method_candidate:
            return method_candidate
        if function_candidate:
            return function_candidate
        if class_candidate:
            return class_candidate

        return "NOT FOUND"


    @staticmethod
    def check_test_naming(method_name) -> bool:
        """Check test naming follows test_when_x_then_y format."""
        pattern = re.compile(r'^test_when_\w+_then_\w+$')
        # Extract just the method name without class prefix if present
        method_only = method_name.split('.')[-1] if '.' in method_name else method_name
        return pattern.match(method_only) is not None


    def check_class_docstring(self, class_node) -> bool:
        """Check test class docstrings."""
        production_method_name = None
        docstring = ast.get_docstring(class_node)
        if docstring is None:
            return False

        for method in class_node.body:
            if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'):
                method_name = self._get_method_name(method)
                if method_name and method_name in docstring:
                    production_method_name = method_name
                    break

        # Check for required elements in class docstring
        return True if production_method_name is not None else False

    def _get_fixture_params(self, test_node: ast.AST) -> list[str]:
        """Get fixture parameters used in a test method."""
        fixture_params = []
        if test_node.args.args:
            fixture_params = [arg.arg for arg in test_node.args.args if arg.arg != 'self']
        self.logger.debug(f"Fixture parameters in {test_node.name}: {fixture_params}")
        return fixture_params


    def check_no_partial_fixture_access(self, test_node: ast.AST) -> bool:
        """Check for tests that only access parts of a fixture.

        This check identifies tests that use only a subset of attributes from a
        fixture, which might indicate that the fixture is too broad or the test
        is not fully utilizing its setup.

        Args:
            test_node: AST node of the test method.

        Returns:
            True if no partial fixture access is detected, False otherwise.

        Examples:
            A fixture providing multiple attributes:
            >>> @pytest.fixture
            ... def my_fixture():
            ...     fixture = Mock()
            ...     fixture.attr1 = 420
            ...     fixture.attr2 = 69
            ...     return fixture
            Good usage (uses multiple parts of the fixture):
            >>> def test_when_using_fixture_then_uses_multiple_attributes(my_fixture):
            ...     funny_number1 = my_fixture.attr1
            ...     funny_number2 = my_fixture.attr2
            ...     result = production_code.do_something(funny_number1, funny_number2)
            ...     assert result is True
            Bad usage (only accesses one part of the fixture):
            >>> def test_when_using_fixture_then_uses_one_attribute(my_fixture):
            ...     value = my_fixture.attr1
            ...     assert value == 420
            >>> analyzer = _TestFileAnalyzer('test_file.py')
            assert analyzer.check_no_partial_fixture_access(test_node), 
                f"{method_name}: Method only accesses parts of fixture instead of whole fixture"
        """
        fixture_params = self._get_fixture_params(test_node)

        self.logger.debug(f"Fixture parameters in {test_node.name}: {fixture_params}")

        if not fixture_params:
            return True

        for fixture in fixture_params:
            # Find what attributes are used in the test
            used_attributes = set()
            for node in ast.walk(test_node):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    if node.value.id == fixture:
                        used_attributes.add(node.attr)

            self.logger.debug(f"Used attributes for {fixture}: {used_attributes}")

            # Find what attributes are declared in the fixture
            declared_attributes = set()
            if fixture in self.fixtures:
                fixture_node = self.fixtures[fixture]
                for node in ast.walk(fixture_node):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                                declared_attributes.add(target.attr)

            self.logger.debug(f"Declared attributes in {fixture}: {declared_attributes}")

            # Partial usage: fixture declares attributes that are not used in the test
            if declared_attributes and used_attributes:
                unused_attributes = declared_attributes - used_attributes
                if unused_attributes:
                    self.logger.debug(f"Unused attributes: {unused_attributes}")
                    return False

        return True

    def check_local_declarations_in_tests(self, test_node: ast.AST) -> list[str]:
        """Check for tests that declare callables locally instead of referencing them."""
        # TODO: Add this to the test suite.
        declared_callables = []
        for child in ast.walk(test_node):
            match child:
                case ast.FunctionDef() | ast.ClassDef(): 
                    if not child.name.startswith(('test_', 'Test')):
                        declared_callables.append(child.name)
        return declared_callables

    def check_no_private_attribute_access(self, test_node: ast.AST) -> list[str]:
        """Check for tests that access private attributes or methods."""
        private_callables = []
        for child in ast.walk(test_node):
            if isinstance(child, ast.Attribute):
                if child.attr.startswith('_'):
                    # Ensure it's not a dunder method
                    if not (child.attr.startswith('__') and child.attr.endswith('__')):
                        private_callables.append(child.attr)
        return private_callables


    def check_no_resource_optimism(self, test_node: ast.AST) -> bool:
        """Check for tests that assume external resource availability without checking."""
        # TODO This should be changed to test fixtures, mocks, tempfiles, etc. instead of the tests themselves.
        # Since these will be flagged for tests that use external resources anyways.
        resource_optimism_patterns = [
            # File operations without existence checks
            ('open', ['r', 'rb', 'w', 'wb', 'a', 'ab']),
            # Network operations without connection checks
            ('requests.get', 'requests.post', 'requests.put', 'requests.delete'),
            ('urllib.request.urlopen', 'urllib.request.urlretrieve'),
            # Database operations without connection verification
            ('sqlite3.connect', 'psycopg2.connect', 'pymongo.MongoClient'),
            # Path operations without existence checks
            ('os.path.exists', 'pathlib.Path.exists'),
        ]

        for node in ast.walk(test_node):
            if isinstance(node, ast.Call):
                match node.func:
                    case ast.Name():
                        # Check for file operations without error handling or existence checks
                        if node.func.id == 'open':
                            return False
                    case ast.Attribute():
                        func_name = f"{ast.unparse(node.func.value)}.{node.func.attr}"
                        if func_name in resource_optimism_patterns:
                            return False
        return True

    def _node_contains(self, parent, child) -> bool:
        """Check if parent node contains child node."""
        for node in ast.walk(parent):
            if node is child:
                return True
        return False