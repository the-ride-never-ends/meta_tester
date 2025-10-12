#!/usr/bin/env python3
"""
Test file with intentional no production calls violation for testing the meta-testing suite.
"""

import pytest


class TestNoProductionCallsViolation:
    """Test violations for the production_method function."""

    def test_when_checking_production_calls_then_violates_has_production_calls_rule(self):
        """
        GIVEN a test method
        WHEN checking production calls
        THEN this method has no production calls (violation)
        """
        x = 5
        d = 10
        assert x == d, f"Expected {x} to equal {d}"  # No production calls - violation


if __name__ == "__main__":
    pytest.main([__file__])