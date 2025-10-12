#!/usr/bin/env python3
"""
Test file with intentional skip decorator violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestSkipDecoratorViolation:
    """Test violations for the production_method function."""

    @pytest.mark.skip(reason="Testing violation")
    def test_when_checking_skip_decorators_then_not_skipped(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking skip decorators
        THEN this method is skipped (violation)
        """
        funny_number = 69
        regular_number = 42
        answer = sample_fixture.production_method(funny_number, regular_number)
        assert answer == funny_number + regular_number, f"This test with {regular_number} is skipped"


if __name__ == "__main__":
    pytest.main([__file__])