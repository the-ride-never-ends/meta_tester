
import ast

def check_method_length(test_node) -> int:
    """Check if method is longer than 10 lines (excluding docstrings)."""
    start_line = test_node.lineno
    end_line = test_node.end_lineno

    # Skip docstring if present
    docstring_lines = 0
    if (test_node.body and isinstance(test_node.body[0], ast.Expr) and 
        isinstance(test_node.body[0].value, ast.Constant) and 
        isinstance(test_node.body[0].value.value, str)):
        docstring_end = test_node.body[0].end_lineno
        docstring_lines = docstring_end - start_line + 1

    total_lines = end_line - start_line + 1 - docstring_lines
    return total_lines
