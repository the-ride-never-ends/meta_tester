#!/usr/bin/env python3
import pytest


class TestNoFStringInAssertion:
    """Test class to demonstrate no f-string usage in assertions for production_method."""

    def test_when_checking_assertion_messages_then_has_f_strings_with_dynamic_content(self, sample_fixture):
        """
        GIVEN a test method for production_method
        WHEN checking f-string messages
        THEN this method has f-strings without dynamic content (violation)
        """
        x = 15
        y = 5
        answer = sample_fixture.production_method(x, y)
        assert answer != y, f"Static message without variables"  # No dynamic content - violation

if __name__ == "__main__":
    pytest.main([__file__])
