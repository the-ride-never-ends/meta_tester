#!/usr/bin/env python3
"""
Test file with intentional magic numbers violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestMagicNumbersViolation:
    """Test violations for the production_method function."""

    def test_when_checking_magic_literals_then_no_magic_numbers_or_strings(self, sample_fixture):
        """
        GIVEN a test method 'production_method'
        WHEN checking magic literals
        THEN this method uses magic numbers (violation)
        """
        x = 6
        y = 7
        answer = sample_fixture.production_method(x, y)
        assert answer == 420, f"Expected {answer} to equal magic number '{x}'"  # Magic number 42 - violation


if __name__ == "__main__":
    pytest.main([__file__])