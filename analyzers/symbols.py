"""Find names from module imports."""

import ast


def import_names(tree: ast.Module, module: str, name: str) -> set[str]:
    """Get the imported names for a module member.

    Args:
        tree: The module to check.
        module: The module name.
        name: The member name.

    Returns:
        The names that refer to the member.
    """
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == module:
                    names.add(f"{alias.asname or module}.{name}")
        elif isinstance(node, ast.ImportFrom) and node.module == module:
            for alias in node.names:
                if alias.name == name:
                    names.add(alias.asname or name)
    return names
