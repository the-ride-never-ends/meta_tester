#!/usr/bin/env python3
"""
Compliant test file that should pass all meta-testing checks.
This file demonstrates proper testing practices and should not trigger any violations.
"""

import pytest
from unittest.mock import Mock

class Calculator:
    """A simple calculator class with basic arithmetic operations."""

    def add(self, a, b):
        """Returns the sum of a and b."""
        return a + b

    def subtract(self, a, b):
        """Returns the difference of a and b."""
        return a - b


@pytest.fixture
def calculator_fixture():
    """Fixture providing a Calculator instance for testing."""
    return Calculator()


class TestCalculatorSubtractMethod:
    """Test class for the Calculator.subtract method functionality."""

    # NOTE: This test is skipped to demonstrate that skips in docstrings are ignored.
    def test_when_subtracting_smaller_from_larger_then_returns_positive_difference(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the subtract method skipped
        WHEN subtracting a smaller number from a larger number
        THEN the method returns the positive difference
        """
        TEN = 10
        THREE = 3
        EXPECTED_DIFFERENCE = 7

        result = calculator_fixture.subtract(TEN, THREE)

        assert result == EXPECTED_DIFFERENCE, f"Expected {result} to equal {EXPECTED_DIFFERENCE}"


if __name__ == "__main__":
    pytest.main([__file__])
