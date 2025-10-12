#!/usr/bin/env python3
"""
Test file with intentional multiple assertions violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMultipleAssertionsViolation:
    """Test violations for the production_method function."""

    def test_when_checking_assertions_then_exactly_one_assertion(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking assertions
        THEN this method has multiple assertions (violation)
        """
        x = 5
        y = 10
        answer = sample_fixture.production_method(x, y)
        assert answer == x, f"Expected {answer} to equal {x}"
        assert answer == y, f"Expected {answer} to equal {y}"  # Second assertion - violation


if __name__ == "__main__":
    pytest.main([__file__])