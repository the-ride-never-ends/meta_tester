#!/usr/bin/env python3
"""
Test file with intentional bad naming convention violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestBadNamingConventionViolation:
    """Test violations for the production_method function."""

    def test_bad_naming_convention(self, sample_fixture):
        """
        GIVEN a test method for 'production_method'
        WHEN checking naming convention
        THEN this method name doesn't follow test_when_x_then_y format (violation)
        """
        x = 5
        y = 10
        result = sample_fixture.production_method(x, y)
        assert result <= x, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])