#!/usr/bin/env python3
"""
Test file with intentional empty method violation for testing the meta-testing suite.
"""

import pytest


class TestEmptyMethodViolation:
    """Test violations for the production_method function."""

    def test_when_checking_empty_method_then_violates_not_empty_rule(self):
        """
        GIVEN a test method for 'production_method'
        WHEN checking method body
        THEN this method is empty (violation)
        """
        pass  # Empty method - violation


if __name__ == "__main__":
    pytest.main([__file__])