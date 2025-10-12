#!/usr/bin/env python3
"""
Test file with intentional fixture usage violation for testing the meta-testing suite.
"""

import pytest
from unittest.mock import Mock
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


@pytest.fixture
def sample_multiuse_fixture():
    mocked_obj = Mock()
    mocked_obj.name = "test"
    mocked_obj.value = 42
    return mocked_obj


class TestFixtureUsageViolation:
    """Test violations for the production_method function."""

    def test_when_checking_fixture_usage_then_uses_whole_fixture(
        self, sample_fixture, sample_multiuse_fixture):
        """
        GIVEN a test method with fixture(s) for 'production_method'
        WHEN checking fixture usage
        THEN this method only accesses parts of fixture (violation)
        """
        value = sample_multiuse_fixture.value  # Only accessing one attribute, not using whole fixture - violation
        
        expected = value + value
        result = sample_fixture.production_method(value, value)
        assert result is expected, f"Expected {result} to equal 'test'"


if __name__ == "__main__":
    pytest.main([__file__])