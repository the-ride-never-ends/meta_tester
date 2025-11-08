#!/usr/bin/env python3
"""
Test file with intentional mocking method under test violation for testing the meta-testing suite.
"""

import pytest
from unittest.mock import Mock
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    prod_class = ProductionClass()
    prod_class.production_method = Mock(return_value=420)  # Mocking the method under test - violation
    return prod_class


class TestMockingMethodUnderTestViolation:
    """Test violations for the production_method function."""

    def test_when_checking_mocking_then_method_being_tested_is_not_mocked(self, sample_fixture):
        """
        GIVEN a test method 'production_method'
        WHEN checking mocking patterns
        THEN this method mocks the method under test (violation)
        """
        expected = 420

        mocked_result = sample_fixture.production_method(1, 2)
        assert mocked_result == expected, f"Expected {mocked_result} to equal '{expected}'"


if __name__ == "__main__":
    pytest.main([__file__])