#!/usr/bin/env python3
"""
Test file with intentional always false assertion violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestAlwaysFalseAssertionViolation:
    """Test violations for the production_method function."""

    def test_when_checking_redundant_assertions_then_no_always_false(self, sample_fixture):
        """
        GIVEN a test method production_method
        WHEN checking redundant assertions
        THEN this method has assertions that are always false (violation)
        """
        x = 4242
        answer = sample_fixture.production_method(x, x)
        assert False, f"This is always false, and {x}"  # Always false assertion - violation


if __name__ == "__main__":
    pytest.main([__file__])