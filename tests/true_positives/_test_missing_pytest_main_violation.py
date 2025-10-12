#!/usr/bin/env python3
"""
Test file intentionally missing pytest.main to test file-level violations.
This should trigger the pytest.main violation in the meta-testing suite.
"""

import pytest


import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMissingPytestMain:
    """Test class for missing pytest.main violation testing for production_method."""

    def test_when_checking_test_file_then_contains_pytest_main(self, sample_fixture):
        """
        GIVEN a test file without pytest.main for production_method
        WHEN checking for pytest.main presence
        THEN this file should trigger a violation
        """
        x = 5
        y = 10
        result = sample_fixture.production_method(x, y)
        assert y == result, f"Expected {x} to equal 5"


# Intentionally missing pytest.main here to trigger violation
