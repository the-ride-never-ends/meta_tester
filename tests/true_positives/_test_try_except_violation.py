#!/usr/bin/env python3
"""
Test file with intentional try/except violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestTryExceptViolation:
    """Test violations for the production_method function."""

    def test_when_checking_exception_handling_then_no_try_except_blocks(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking exception handling
        THEN this method contains try/except blocks (violation)
        """
        y = 10
        try:  # Try/except block - violation
            x = 1 / 0
        except ZeroDivisionError:
            x = 0
        result = sample_fixture.production_method(y, x)
        assert result == result, f"Expected {x} to equal 0"


if __name__ == "__main__":
    pytest.main([__file__])