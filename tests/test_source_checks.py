"""Check test entry points and async markers."""

import ast

import pytest

from ..analyzers.source_checks import has_main, has_marker


@pytest.fixture(
    params=[
        ('import pytest\nif __name__ == "__main__":\n    pytest.main()', True),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                '    pytest.main([__file__, "-v"])'
            ),
            True,
        ),
        (
            (
                'import pytest\nimport sys\nif __name__ == "__main__":\n'
                "    sys.exit(pytest.main())"
            ),
            True,
        ),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                "    raise SystemExit(pytest.main())"
            ),
            True,
        ),
        (
            (
                'import pytest as pt\nif __name__ == "__main__":\n'
                "    raise SystemExit(pt.main())"
            ),
            True,
        ),
        (('from pytest import main\nif __name__ == "__main__":\n    main()'), True),
        (
            ('from pytest import main as run\nif "__main__" == __name__:\n    run()'),
            True,
        ),
        (
            (
                'import pytest\nif (__name__ == "__main__"):\n'
                "    # Run the tests.\n    pytest.main(\n        [__file__]\n    )"
            ),
            True,
        ),
        ("", False),
        ("import pytest\npytest.main()", False),
        ('import pytest\nif __name__ != "__main__":\n    pytest.main()', False),
        ('import pytest\nif other == "__main__":\n    pytest.main()', False),
        (
            'import pytest\nif __name__ == "__main__":\n    print("pytest.main()")',
            False,
        ),
        ('"""if __name__ == "__main__": pytest.main()"""', False),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                "    def run():\n        pytest.main()"
            ),
            False,
        ),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                "    callback = lambda: pytest.main()"
            ),
            False,
        ),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                "    pass\nelse:\n    pytest.main()"
            ),
            False,
        ),
        ('from other import main\nif __name__ == "__main__":\n    main()', False),
        (
            (
                'import pytest\nif __name__ == "__main__":\n'
                '    pytest.main()\nprint("done")'
            ),
            False,
        ),
    ],
    ids=[
        "guarded pytest main",
        "guarded pytest main with sys exit",
        "guarded pytest main with raise system exit",
        "guarded pytest main alias",
        "guarded pytest main as pt",
        "guarded pytest main with parentheses",
        "empty source",
        "unguarded pytest main",
        "unrelated guard",
        "print instead of pytest main",
        "docstring instead of pytest main",
        "function definition instead of pytest main",
        "lambda instead of pytest main",
        "pass then pytest main",
        "other import main",
        "print after pytest main",
        "function after pytest main",
        "function after pytest main with print",
        "function after pytest main with lambda",
    ]
)
def entry_case(request):
    source, expected = request.param
    return ast.parse(source), expected


def test_when_checking_entry_point_then_accepts_only_guarded_pytest(entry_case):
    """GIVEN module source
    WHEN has_main checks the entry point
    THEN the result matches the expected entry point state.
    """
    tree, expected = entry_case
    actual = has_main(tree)
    assert actual is expected


@pytest.fixture(
    params=[
        ("", "", "async def", False),
        ("", "", "def", True),
        ("", "@pytest.mark.asyncio", "async def", True),
        ("", "@pytest.mark.asyncio()", "async def", True),
        ("", '@pytest.mark.asyncio(loop_scope="module")', "async def", True),
        ("", "@pytest.mark.slow", "async def", False),
        ("pytestmark = pytest.mark.asyncio", "", "async def", True),
        ("pytestmark = [pytest.mark.slow, pytest.mark.asyncio]", "", "async def", True),
        ("pytestmark: object = pytest.mark.asyncio", "", "async def", True),
        ("import pytest as pt", "@pt.mark.asyncio", "async def", True),
        ("from pytest import mark as marker", "@marker.asyncio", "async def", True),
        ("", "@unrelated.asyncio", "async def", False),
        (
            (
                "@pytest.mark.asyncio\nclass TestGroup:\n    async def test_case(self):\n"
                "        pass\n"
            ),
            "",
            "",
            True,
        ),
        (
            (
                "class TestGroup:\n    pytestmark = pytest.mark.asyncio\n"
                "    async def test_case(self):\n        pass\n"
            ),
            "",
            "",
            True,
        ),
        (
            "class TestOther:\n    pytestmark = pytest.mark.asyncio\n",
            "",
            "async def",
            False,
        ),
    ],
    ids=[
        "no marker async def",
        "no marker def",
        "async def with marker",
        "async def with marker call",
        "async def with marker loop scope",
        "async def with unrelated marker",
        "pytestmark async def",
        "pytestmark list async def",
        "pytestmark typed async def",
        "pytest alias async def",
        "marker alias async def",
        "unrelated marker async def",
        "class decorator async def",
        "class pytestmark async def",
        "class pytestmark other async def",
    ]
)
def marker_case(request):
    prefix, decorator, definition, expected = request.param
    source = f"import pytest\n{prefix}\n"
    if definition:
        source += f"{decorator}\n{definition} test_case():\n    pass\n"
    tree = ast.parse(source)
    node = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    return tree, node, expected


def test_when_checking_async_test_then_requires_asyncio_marker(marker_case):
    """GIVEN a synchronous or async test
    WHEN has_marker checks the test
    THEN only async tests require an asyncio marker.
    """
    tree, node, expected = marker_case
    actual = has_marker(tree, node)
    assert actual is expected
