#!/usr/bin/env python3
"""
Test file with intentional print statement violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestPrintStatementViolation:
    """Test violations for the production_method function."""

    def test_when_checking_print_logging_then_no_output_statements(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking print/logging
        THEN this method contains print statements (violation)
        """
        x = 5
        z = x ^ 2
        result = sample_fixture.production_method(x, x)
        print(f"Debug: x = {x}")  # Print statement - violation
        assert z == result, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])