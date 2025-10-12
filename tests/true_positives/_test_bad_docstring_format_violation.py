#!/usr/bin/env python3
"""
Test file with intentional bad docstring format violation for testing the meta-testing suite.
"""

import pytest
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestBadDocstringFormatViolation:
    """Test violations for the production_method function."""

    def test_when_checking_docstring_format_then_given_when_then_structure(self, sample_fixture):
        """
        This docstring does not follow the right format,
        even though it mentions the production method. (violation)
        """
        x = 5
        y = 10
        result = sample_fixture.production_method(x, y)
        assert result >= y, f"Expected {x} to equal 5"


if __name__ == "__main__":
    pytest.main([__file__])