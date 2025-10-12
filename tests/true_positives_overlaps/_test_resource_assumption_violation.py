#!/usr/bin/env python3
"""
Test file with intentional resource assumption violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestResourceAssumptionViolation:
    """Test violations for the production_method function."""

    def test_when_checking_resource_assumptions_then_no_resource_optimism(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking resource assumptions
        THEN this method assumes file exists without checking (violation)
        """
        x = 5
        answer = sample_fixture.production_method(x, x)
        with open("nonexistent_file.txt", "r") as f:  # Assumes file exists - violation
            content = f.read()
        assert content == answer, f"Expected empty content, got {content}"


if __name__ == "__main__":
    pytest.main([__file__])