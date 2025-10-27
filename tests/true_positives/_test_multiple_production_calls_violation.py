#!/usr/bin/env python3
"""
Test file with intentional multiple production calls violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMultipleProductionCallsViolation:
    """Test violations for the production_method function."""

    def test_when_checking_production_calls_then_exactly_one_call(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking production calls
        THEN this method makes multiple production calls (violation)
        """
        x = 5
        y = 10
        z = 15
        result1 = sample_fixture.production_method(x, y)  # First call
        result2 = sample_fixture.production_method(y, z)  # Second call - violation
        assert result1 is not result2, f"Expected {result1} to not be {result2}."


if __name__ == "__main__":
    pytest.main([__file__])