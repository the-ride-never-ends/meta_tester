#!/usr/bin/env python3
"""
Test file with intentional multiple different production methods violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMultipleProductionMethodsViolation:
    """Test violations for the production_method function."""

    def test_when_checking_production_calls_then_exactly_one_call(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking production calls
        THEN this method makes calls to multiple different production methods (violation)
        """
        x = 5
        y = 10
        z = 15
        result1 = sample_fixture.production_method(x, y)  # First method
        result2 = sample_fixture.another_production_method(y, z)  # Second method- violation
        assert result1 == result2 + y + z, f"Expected {result1} to not be {result2}."


if __name__ == "__main__":
    pytest.main([__file__])