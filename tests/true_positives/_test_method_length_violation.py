#!/usr/bin/env python3
"""
Test file with intentional method length violation for testing the meta-testing suite.
"""

import pytest
from unittest.mock import Mock

from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMethodLengthViolation:
    """Test violations for the production_method function."""

    def test_when_checking_method_length_then_under_10_lines(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking the method length
        THEN this method intentionally exceeds 10 lines to test the line limit rule
        """
        one = 1
        two = 2
        three = 3
        four = 4
        five = 5
        six = 6
        seven = 7
        eight = 8
        nine = one + two + three + four + five + six + seven + eight
        ten = sample_fixture.production_method(one, nine)
        assert one == ten, f"Expected {one} to equal {eight}"  # Line 11 - this should trigger the violation


if __name__ == "__main__":
    pytest.main([__file__])