#!/usr/bin/env python3
"""
Test file with intentional first duplicate assertion violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestFirstDuplicateAssertion:
    """Test class for duplicate assertion violations for production_method."""

    def test_when_checking_duplicate_assertions_then_no_duplicates(self, sample_fixture):
        """
        GIVEN a test method for 'production_method'
        WHEN checking duplicates
        THEN this is the first duplicate assertion
        """
        x = 5
        y = 5
        result = sample_fixture.production_method(y, x)
        assert x == result, f"Expected {x} to equal 5"

    def test_when_checking_duplicates_then_first_duplicate_assertion(self, sample_fixture):
        """
        GIVEN a test method for 'production_method'
        WHEN checking duplicates
        THEN this is the first duplicate assertion
        """
        x = 10
        y = 10
        result = sample_fixture.production_method(y, x)
        assert x == result, f"Expected {x} to equal 20"  # Same assertion pattern as in previous method - violation

if __name__ == "__main__":
    pytest.main([__file__])