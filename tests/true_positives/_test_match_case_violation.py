#!/usr/bin/env python3
"""
Test file with intentional if statement violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMatchCaseViolation:
    """Test violations for the production_method function."""

    def test_when_checking_test_then_no_conditional_logic(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking control flow
        THEN this method contains match/case statements (violation)
        """
        x = 5
        positive_or_negative = "positive"
        match positive_or_negative:
            case "positive":  # Match/case statement - violation
                positive_or_negative = "positive"
            case _:
                positive_or_negative = "non-positive"
        result = sample_fixture.production_method(x, x)
        assert result == positive_or_negative, f"Expected {result} to equal 'positive'"


if __name__ == "__main__":
    pytest.main([__file__])
