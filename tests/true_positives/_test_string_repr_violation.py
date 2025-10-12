#!/usr/bin/env python3
"""
Test file with intentional str/repr usage violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestStringReprViolation:
    """Test violations for the production_method function."""

    def test_when_checking_equality_then_no_str_repr(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking sensitive equality
        THEN this method uses str/repr (violation)
        """
        x = [1, 2, 3]
        result = str(x)  # str() usage - violation
        answer = sample_fixture.production_method(x[0], x[1])
        assert result == answer, f"Expected {result} to equal '[1, 2, 3]'"


if __name__ == "__main__":
    pytest.main([__file__])