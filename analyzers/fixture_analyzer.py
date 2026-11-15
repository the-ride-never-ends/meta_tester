import ast
import logging

from logger import logger

from .symbols import import_names


class FixtureAnalyzer:

    def __init__(
        self, 
        *, 
        tree: ast.Module, 
        file_path: str, 
        logger: logging.Logger = logger
    ) -> None:
        self.tree = tree
        self.logger = logger
        self.file_path = file_path
        try:
            self.fixtures = self._collect()
        except Exception as e:
            raise RuntimeError(f"Failed to extract fixtures: {e}") from e
        # self.logger.debug(f"Fixtures found: {list(self.fixtures.keys())}")

    def _collect(self) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        fixtures = {}
        names = import_names(self.tree, "pytest", "fixture") | import_names(
            self.tree, "pytest_asyncio", "fixture"
        )
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    decorator_func = (
                        decorator.func 
                        if isinstance(decorator, ast.Call) 
                        else decorator
                    )
                    if ast.unparse(decorator_func) in names:
                        fixtures[node.name] = node
                        break
        return fixtures

    def get_test_methods(self):
        """Get all test methods in the file."""
        test_methods = []
        for node in ast.walk(self.tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")
                and node not in self.fixtures.values()
            ):
                cls_name = None
                # Find parent class if exists
                for parent in ast.walk(self.tree):
                    if isinstance(parent, ast.ClassDef):
                        for child in ast.walk(parent):
                            if child is node:
                                cls_name = parent.name
                                break
                        if cls_name:
                            break

                method_name = f"{cls_name}.{node.name}" if cls_name else node.name
                test_methods.append((method_name, node))
        return test_methods

    def get_test_classes(self):
        """Get all test classes in the file."""
        test_classes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                test_classes.append((node.name, node))
        return test_classes
