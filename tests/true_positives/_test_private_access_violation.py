#!/usr/bin/env python3
"""
Test file with intentional private access violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestPrivateAccessViolation:
    """Test violations for the _private_method function."""

    def test_when_checking_test_then_test_only_tests_through_public_contract(self, sample_fixture):
        """
        GIVEN a test method for _private_method
        WHEN checking private access
        THEN this method accesses private attributes (violation)
        """
        y = 777
        x = 444
        private = x + y 
        result = sample_fixture._private_method(y, x)  # Accessing private method - violation
        assert result == private, f"Expected {result} to equal 'private'"


if __name__ == "__main__":
    pytest.main([__file__])