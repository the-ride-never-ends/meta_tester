"""Check test entry points and async markers."""

import ast
from collections.abc import Iterator

from .symbols import import_names


def _calls(node: ast.AST) -> Iterator[ast.Call]:
    if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ):
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _calls(child)


def has_main(tree: ast.Module) -> bool:
    """Check for a pytest entry point at the end of a module.

    Args:
        tree: The module to check.

    Returns:
        True if the module has a guarded pytest entry point.
    """
    if not tree.body or not isinstance(tree.body[-1], ast.If):
        return False
    guard = tree.body[-1]
    condition = guard.test
    if not (
        isinstance(condition, ast.Compare)
        and len(condition.ops) == 1
        and isinstance(condition.ops[0], ast.Eq)
    ):
        return False
    operands = (condition.left, condition.comparators[0])
    if not (
        any(isinstance(node, ast.Name) and node.id == "__name__" for node in operands)
        and any(
            isinstance(node, ast.Constant) and node.value == "__main__"
            for node in operands
        )
    ):
        return False
    names = import_names(tree, "pytest", "main")
    return any(
        ast.unparse(call.func) in names
        for statement in guard.body
        for call in _calls(statement)
    )


def _markers(value: ast.expr) -> list[ast.expr]:
    if isinstance(value, (ast.List, ast.Tuple)):
        return value.elts
    return [value]


def has_marker(tree: ast.Module, node: ast.AST) -> bool:
    """Check that an async test has an asyncio marker.

    Args:
        tree: The module that contains the test.
        node: The test to check.

    Returns:
        True if the test is synchronous or has an asyncio marker.
    """
    if not isinstance(node, ast.AsyncFunctionDef):
        return True
    names = {f"{name}.asyncio" for name in import_names(tree, "pytest", "mark")}
    markers = list(node.decorator_list)
    scopes = [tree] + [
        scope
        for scope in ast.walk(tree)
        if isinstance(scope, ast.ClassDef) and node in ast.walk(scope)
    ]
    for scope in scopes:
        if isinstance(scope, ast.ClassDef):
            markers.extend(scope.decorator_list)
        for statement in scope.body:
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            if statement.value is not None and any(
                isinstance(target, ast.Name) and target.id == "pytestmark"
                for target in targets
            ):
                markers.extend(_markers(statement.value))
    return any(
        ast.unparse(
            marker.func if isinstance(marker, ast.Call) else marker
        ) in names for marker in markers
    )
