#!/usr/bin/env python3
"""
Test file with intentional for loop violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestForLoopViolation:
    """Test violations for the production_method function."""

    def test_when_checking_test_then_no_conditional_logic(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking control flow
        THEN this method contains for loops (violation)
        """
        total = 0
        for i in range(5):  # For loop - violation
            total += i
        result = sample_fixture.production_method(total, total)
        assert total == result, f"Expected {total} to equal 10"


if __name__ == "__main__":
    pytest.main([__file__])