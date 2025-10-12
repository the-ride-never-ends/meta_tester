#!/usr/bin/env python3
"""
Test file with intentional class docstring violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestClassDocstringViolation:
    """Test class docstring violation - no mention of method being tested."""

    def test_when_checking_class_docstring_then_mentions_production_class(self, sample_fixture):
        """
        GIVEN a test class for 'production_method'
        WHEN checking class docstring
        THEN this class docstring doesn't mention production method (violation)
        """
        x = 0
        y = 5
        result = sample_fixture.production_method(y, x)
        assert result != result + result + result, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])