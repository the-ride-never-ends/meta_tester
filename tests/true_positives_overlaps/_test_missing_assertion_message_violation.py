#!/usr/bin/env python3
"""
Test file with intentional missing assertion message violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMissingAssertionMessageViolation:
    """Test violations for the production_method function."""

    def test_when_checking_assertion_messages_then_has_f_strings(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking assertion messages
        THEN this method lacks f-string messages (violation)
        """
        x = 5
        y = 5
        answer = sample_fixture.production_method(x, y)
        assert answer == y * x  # No message - violation


if __name__ == "__main__":
    pytest.main([__file__])