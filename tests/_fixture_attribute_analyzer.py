import ast
from typing import Optional

from analyzers.fixture_analyzer import FixtureAnalyzer

class FixtureAttributeAnalyzer(ast.NodeVisitor):
    """Analyze fixture attributes to determine if they're callable."""

    def __init__(self, tree: ast.AST | str):
        self.tree = tree if isinstance(tree, ast.AST) else ast.parse(tree)
        self.fixtures = {}
        self.parameterizations = set()
        self._collect()

    def _get_parameterizations(self, func_node: ast.FunctionDef) -> None:
        """Get argument names that are defined in a parameterization decorator."""
        if hasattr(func_node, 'decorator_list'):
            for decorator in func_node.decorator_list:
                if isinstance(decorator, ast.Call):
                    if (isinstance(decorator.func, ast.Attribute) and 
                        decorator.func.attr == "parametrize"):
                        # Get the parameter names
                        name = decorator.args[0].value
                        names = [n.strip() for n in name.split(',')] if ',' in name else [name.strip()]
                        self.parameterizations.update(names)


    def _collect(self):
        self.fixtures = FixtureAnalyzer(
            tree=self.tree, file_path="<ast>"
        ).fixtures
        for node in ast.walk(self.tree):
            self._get_parameterizations(node)
        self.parameterizations.update({"request", "caplog"})

    def is_attribute_callable(self, fixture_name: str, attr_name: str) -> bool:
        """
        Check if fixture attribute is callable.
        
        Args:
            fixture_name: Name of the fixture.
            attr_name: Name of the attribute being accessed.
            
        Returns:
            True if attribute is callable, False otherwise.
        """
        if not fixture_name.strip():
            return False

        # Skip parameterized fixtures
        if fixture_name in self.parameterizations:
            return False

        # Skip tmp_path
        # TODO This is hacky.
        if fixture_name == "tmp_path":
            return False

        #logger.debug(f"Checking if {fixture_name} is in {self.fixtures.keys()}")
        if fixture_name not in self.fixtures:
            raise ValueError(f"Fixture '{fixture_name}' not found")

        fixture_node = self.fixtures[fixture_name]
        return_value = self._get_return_value(fixture_node)
        
        if not return_value:
            return False
        
        return self._check_attribute_callable(return_value, attr_name, fixture_node)

    def _get_return_value(self, func_node: ast.FunctionDef) -> Optional[ast.Name]:
        """Extract the return value name from fixture."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name):
                    return node.value
        return None

    def _check_attribute_callable(
        self, return_value: ast.Name, attr_name: str, fixture_node: ast.FunctionDef
    ) -> bool:
        """Check if attribute on returned object is callable."""
        obj_name = return_value.id
        
        for node in ast.walk(fixture_node):
            # Check assignments: obj.attr = value
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        if (isinstance(target.value, ast.Name) and 
                            target.value.id == obj_name and 
                            target.attr == attr_name):
                            return self._is_value_callable(node.value)
        
        return False

    def _is_value_callable(self, node: ast.AST) -> bool:
        """Check if AST node represents callable value."""
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        
        # Check for callable constructors
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                # Common callable types
                callable_types = {'Mock', 'MagicMock', 'lambda', 'partial'}
                if node.func.id in callable_types:
                    return True
        
        return False


def check_fixture_attribute(tree: ast.AST, fixture_name: str, attr_name: str) -> bool:
    """
    Check if fixture attribute is callable.
    
    Args:
        tree: AST of Python source code containing fixtures.
        fixture_name: Name of the fixture to check.
        attr_name: Name of the attribute being accessed.
        
    Returns:
        True if attribute is callable, False otherwise.
    """
    analyzer = FixtureAttributeAnalyzer(tree)
    return analyzer.is_attribute_callable(fixture_name, attr_name)


# Example usage
if __name__ == "__main__":
    code = """
import pytest
from unittest.mock import Mock

@pytest.fixture
def sample_multiuse_fixture():
    mocked_obj = Mock()
    mocked_obj.name = "test"
    mocked_obj.value = 42
    mocked_obj.get_data = lambda: "data"
    return mocked_obj
"""

    analyzer = FixtureAttributeAnalyzer(code)
    
    print(f"name is callable: {analyzer.is_attribute_callable('sample_multiuse_fixture', 'name')}")
    print(f"value is callable: {analyzer.is_attribute_callable('sample_multiuse_fixture', 'value')}")
    print(f"get_data is callable: {analyzer.is_attribute_callable('sample_multiuse_fixture', 'get_data')}")
