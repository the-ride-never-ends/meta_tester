"""Check test collection and control flow rules."""

import ast

import pytest

from ..analyzers._test_file_analyzer import _TestFileAnalyzer
from ..analyzers.fixture_analyzer import FixtureAnalyzer
from .test_true_positives import run_meta_tester


@pytest.fixture(
    params=[
        ("import pytest", "pytest.fixture"),
        ("import pytest", "pytest.fixture()"),
        ("import pytest", 'pytest.fixture(scope="module")'),
        ("from pytest import fixture", "fixture"),
        ("from pytest import fixture", "fixture()"),
        ("from pytest import fixture as setup", "setup"),
        ("from pytest import fixture as setup", 'setup(name="test_value")'),
        ("import pytest as pt", "pt.fixture"),
        ("import pytest as pt", "pt.fixture()"),
        ("import pytest_asyncio as pa", "pa.fixture"),
        ("from pytest_asyncio import fixture as setup", "setup()"),
    ]
)
def fixture_source(request):
    imports, decorator = request.param
    return (
        f"{imports}\n@{decorator}\ndef test_resource():\n    pass\n"
        f"@{decorator}\nasync def test_async_resource():\n    pass\n"
        "def test_actual():\n    pass\n"
        "async def test_async_actual():\n    pass\n"
    )


@pytest.fixture(params=[FixtureAnalyzer, _TestFileAnalyzer])
def collection_case(request, fixture_source, tmp_path):
    path = tmp_path / "test_collection.py"
    path.write_text(fixture_source)
    if request.param is FixtureAnalyzer:
        analyzer = FixtureAnalyzer(tree=ast.parse(fixture_source), file_path=str(path))
    else:
        analyzer = _TestFileAnalyzer(str(path))
    return analyzer 


def test_when_collecting_tests_then_excludes_fixture_functions(collection_case):
    """GIVEN fixtures with a test prefix
    WHEN get_test_methods collects the tests
    THEN only test functions are returned.
    """
    expected =["test_actual", "test_async_actual"] 
    analyzer = collection_case
    actual = [name for name, node in analyzer.get_test_methods()]
    assert actual == expected


@pytest.fixture(
    params=[
        ("[value for value in values]", True),
        ("[value for value in values if value]", True),
        ("{value for value in values}", True),
        ("{value: value for value in values}", True),
        ("(value for value in values)", True),
        ("values if values else ()", True),
        ("values", False),
    ],
    ids=[
        "list comprehension",
        "list comprehension with if",
        "set comprehension",
        "dict comprehension",
        "generator expression",
        "ternary expression",
        "simple value",
    ]
)
def control_case(request, tmp_path, module_source):
    expression, violation = request.param
    source = module_source.format(
        imports="import pytest",
        markers="",
        definition="def",
        expression=expression,
        entry="pytest.main([__file__])",
    )
    path = tmp_path / "test_control.py"
    path.write_text(source)
    rule = "test_when_checking_test_then_no_conditional_logic"
    return str(path), {rule} if violation else set()


@pytest.fixture
def module_source():
    return (
        "#!/usr/bin/env python3\n{imports}\n"
        "class Calculator:\n"
        "    def calculate(self, values):\n        return values\n"
        "@pytest.fixture\ndef calculator():\n    return Calculator()\n"
        "{markers}\n"
        "{definition} test_when_calculating_then_returns_values(calculator):\n"
        '    """GIVEN values\n    WHEN calculate runs\n'
        '    THEN it returns the values.\n    """\n'
        "    values = ()\n"
        "    expected = {expression}\n"
        "    result = calculator.calculate(values)\n"
        '    assert result == expected, f"Expected {{expected}}, got {{result}}"\n'
        'if __name__ == "__main__":\n    {entry}\n'
    )


def test_when_checking_control_flow_then_detects_comprehensions(control_case):
    """GIVEN a test expression
    WHEN run_meta_tester checks the file
    THEN the control flow failures match the expected rules.
    """
    path, expected = control_case
    actual = set(run_meta_tester(path)["failed_tests"])
    assert actual == expected


@pytest.fixture(
    params=[
        ("", "", "def", "pytest.main()", None),
        ("import sys", "", "def", "sys.exit(pytest.main())", None),
        ("", "", "def", "raise SystemExit(pytest.main())", None),
        ("from pytest import main as run", "", "def", "run()", None),
        ("import pytest as pt", "", "def", "pt.main()", None),
        (
            "",
            "",
            "async def",
            "pytest.main()",
            "test_when_checking_async_test_then_has_asyncio_marker",
        ),
        ("", "@pytest.mark.asyncio", "async def", "pytest.main()", None),
        ("pytestmark = pytest.mark.asyncio", "", "async def", "pytest.main()", None),
        (
            "",
            "",
            "def",
            "pass",
            "test_when_checking_test_file_then_contains_pytest_main",
        ),
    ],
    ids=[
        "default entry",
        "sys exit",
        "raise system exit",
        "pytest main alias",
        "pytest main as pt",
        "async def default",
        "async def with marker",
        "pytestmark async def",
        "missing pytest main",
    ]
)
def pipeline_case(request, tmp_path, module_source):
    imports, markers, definition, entry, rule = request.param
    source = module_source.format(
        imports=f"import pytest\n{imports}",
        markers=markers,
        definition=definition,
        expression="values",
        entry=entry,
    )
    path = tmp_path / "test_pipeline.py"
    path.write_text(source)
    return str(path), {rule} if rule else set()


def test_when_checking_file_then_applies_marker_and_entry_rules(pipeline_case):
    """GIVEN a test file
    WHEN run_meta_tester checks its marker and entry point
    THEN the failures match the expected rules.
    """
    path, expected = pipeline_case
    actual = set(run_meta_tester(path)["failed_tests"])
    assert actual == expected


@pytest.fixture(
    params=[
        ("", "pytest.fixture", "def"),
        ("from pytest import fixture as setup", "setup()", "def"),
        ("import pytest as pt", "pt.fixture", "def"),
        ("import pytest_asyncio as pa", "pa.fixture", "async def"),
    ],
    ids=[
        "default fixture",
        "fixture alias",
        "pytest alias",
        "async fixture",
    ]
)
def prefix_case(request, tmp_path, module_source):
    imports, decorator, definition = request.param
    source = module_source.format(
        imports=f"import pytest\n{imports}",
        markers="",
        definition="def",
        expression="values",
        entry="pytest.main()",
    ).replace("calculator", "test_calculator")
    source = source.replace("@pytest.fixture", f"@{decorator}")
    source = source.replace("def test_calculator()", f"{definition} test_calculator()")
    source = source.replace(
        "    return Calculator()",
        "    expected = ()\n    result = ()\n"
        "    assert result == expected\n    return Calculator()",
    )
    path = tmp_path / "test_prefix.py"
    path.write_text(source)
    return str(path)


def test_when_checking_fixture_prefix_then_ignores_fixture_assertions(prefix_case):
    """GIVEN a fixture with a test prefix and a repeated assertion
    WHEN run_meta_tester checks the file
    THEN the fixture does not cause a test rule failure.
    """
    expected = set()
    path = prefix_case
    actual = set(run_meta_tester(path)["failed_tests"])
    assert actual == expected
