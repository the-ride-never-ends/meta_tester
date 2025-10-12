"""
Test file intentionally missing shebang line to test file-level violations.
This should trigger the shebang violation in the meta-testing suite.
"""

import pytest

import pytest
from unittest.mock import Mock
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMissingShebang:
    """Test class for missing shebang violation testing production_method."""

    def test_when_checking_test_file_then_contains_shebang(self, sample_fixture):
        """
        GIVEN a test file without shebang for production_method
        WHEN checking for shebang presence
        THEN this file should trigger a violation
        """
        x = 5
        result = sample_fixture.production_method(x, x)
        assert result == x, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])
