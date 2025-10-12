#!/usr/bin/env python3
"""
Test file with intentional while loop violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestWhileLoopViolation:
    """Test violations for the production_method function."""

    def test_when_checking_test_then_no_conditional_logic(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking control flow 
        THEN this method contains while loops (violation)
        """
        x = 0
        y = 5
        while x < 5:  # While loop - violation
            x += 1
        result = sample_fixture.production_method(y, x)
        assert result != result + result, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])