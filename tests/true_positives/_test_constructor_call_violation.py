#!/usr/bin/env python3
"""
Test file with intentional constructor call violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


class TestConstructorCallViolation:
    """Test violations for the production_method function."""

    def test_when_checking_constructor_calls_then_no_constructor_initialization(self):
        """
        GIVEN a test method for 'production_method'
        WHEN checking for constructor calls
        THEN this method creates objects directly (violation)
        """
        mock_obj = ProductionClass()  # Constructor call - violation
        result = mock_obj.production_method()
        assert result is not None, f"Expected result to not be None, got {result}"


if __name__ == "__main__":
    pytest.main([__file__])