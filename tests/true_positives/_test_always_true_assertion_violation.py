#!/usr/bin/env python3
"""
Test file with intentional always true assertion violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestAlwaysTrueAssertionViolation:
    """Test violations for the production_method function."""

    def test_when_checking_redundant_assertions_then_no_always_true(self, sample_fixture):
        """
        GIVEN a test method 'production_method'
        WHEN checking redundant assertions
        THEN this method has assertions that are always true (violation)
        """
        x = 4242
        answer = sample_fixture.production_method(x, x)
        assert True, f"This is always true, and {x}"  # Always true assertion - violation


if __name__ == "__main__":
    pytest.main([__file__])