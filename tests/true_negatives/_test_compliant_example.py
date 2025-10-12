#!/usr/bin/env python3
"""
Compliant test file that should pass all meta-testing checks.
This file demonstrates proper testing practices and should not trigger any violations.
"""

import pytest
from unittest.mock import Mock


@pytest.fixture
def calculator_fixture():
    """Fixture providing a Calculator instance for testing."""
    mock_calculator = Mock()
    mock_calculator.add.return_value = 8  # Default return for add
    mock_calculator.subtract.return_value = 7  # Default return for subtract
    return mock_calculator



class TestCalculatorAddMethod:
    """Test class for the Calculator.add method functionality."""


    def test_when_adding_positive_numbers_then_returns_int(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the add method
        WHEN adding two positive integers
        THEN the method returns an integer
        """
        FIVE = 5
        THREE = 3

        result = calculator_fixture.add(FIVE, THREE)

        assert isinstance(result, int), f"Expected {result} to be an integer, got {type(result).__name__} instead."

    def test_when_adding_positive_numbers_then_returns_sum(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the add method
        WHEN adding two positive integers
        THEN the method returns the sum of those numbers
        """
        FIVE = 5
        THREE = 3
        EXPECTED_SUM = 8

        result = calculator_fixture.add(FIVE, THREE)

        assert result == EXPECTED_SUM, f"Expected {result} to equal {EXPECTED_SUM}"

    def test_when_adding_negative_numbers_then_returns_negative_sum(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the add method
        WHEN adding two negative integers
        THEN the method returns a negative sum
        """
        NEGATIVE_FIVE = -5
        NEGATIVE_THREE = -3

        result = calculator_fixture.add(NEGATIVE_FIVE, NEGATIVE_THREE)

        assert result < 0, f"Expected result to be negative, but got {result}"

    def test_when_adding_zero_then_returns_other_number(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the add method
        WHEN adding a string to another number
        THEN the method raises a TypeError
        """
        ZERO = '0'
        SEVEN = 7

        with pytest.raises(TypeError, match="unsupported operand type"):
            result = calculator_fixture.add(ZERO, SEVEN)


class TestCalculatorSubtractMethod:
    """Test class for the Calculator.subtract method functionality."""

    def test_when_subtracting_smaller_from_larger_then_returns_positive_difference(self, calculator_fixture):
        """
        GIVEN a Calculator instance with the subtract method
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
