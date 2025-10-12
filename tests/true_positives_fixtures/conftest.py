
import pytest


@pytest.fixture
def fixture_function():
    return "This is a sample fixture"

@pytest.fixture
def unused_fixture():
    return "This fixture is not used in any test"

@pytest.fixture
def resource_optimism_fixture():
    """Fixture that assumes a resource exists without checking."""
    with open("some_file.txt", "r") as f:
        data = f.read()
    return data
