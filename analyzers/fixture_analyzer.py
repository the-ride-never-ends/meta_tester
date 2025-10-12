import ast
import logging


from logger import logger


class FixtureAnalyzer:

    def __init__(self, *, tree: str, file_path: str, logger: logging.Logger = logger):
        self.tree = tree
        self.logger = logger
        self.file_path = file_path
        try:
            self.fixtures = self._get_fixtures()
        except Exception as e:
            raise RuntimeError(f"Failed to extract fixtures: {e}") from e
        #self.logger.debug(f"Fixtures found: {list(self.fixtures.keys())}")

    def _get_fixtures(self) -> dict[str, ast.FunctionDef]:
        """Extract all fixtures in the test file."""
        fixtures = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    # Handles @pytest.fixture(scope=...)
                    decorator_func = decorator if not isinstance(decorator, ast.Call) else decorator.func

                    # Handles @pytest.fixture
                    if (isinstance(decorator_func, ast.Attribute) and
                            isinstance(decorator_func.value, ast.Name) and
                            decorator_func.value.id == 'pytest' and
                            decorator_func.attr == 'fixture'):
                        fixtures[node.name] = node
                        break
                    # Handles `from pytest import fixture` and then `@fixture`
                    elif (isinstance(decorator_func, ast.Name) and
                          decorator_func.id == 'fixture'):
                        is_fixture_from_pytest = False
                        for import_node in ast.walk(self.tree):
                            if isinstance(import_node, ast.ImportFrom) and import_node.module == 'pytest':
                                for alias in import_node.names:
                                    if alias.name == 'fixture':
                                        is_fixture_from_pytest = True
                                        break
                            if is_fixture_from_pytest:
                                break
                        
                        if not is_fixture_from_pytest:
                            continue
                        fixtures[node.name] = node
                        break
        return fixtures

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
