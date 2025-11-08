#!/usr/bin/env python3
"""
Test file with intentional optimistic fixture for testing the meta-testing suite.
"""
import pytest
from pathlib import Path
from .._production_class import ProductionClass


# NOTE: No try-except or file existence checks.
@pytest.fixture
def optimistic_fixture(tmp_path: Path):
    """This fixture does not check if the file was actually created."""
    string = "Testing 1, 2, 3..."
    test_file = tmp_path / "test_optimism.py"
    test_file.write_text(string)
    return string


# Dummy function
def retrieve_web_content(string: str):
    return {"id": string}


class TestBadDocstringFormatViolation:
    """Test violations for the production_method function."""

    def test_when_checking_docstring_format_then_given_when_then_structure(self, optimistic_fixture):
        """
        This docstring does not follow the right format,
        even though it mentions the production method. (violation)
        """
        expected_string = "Testing 1, 2, 3..."
        result = retrieve_web_content(expected_string)
        assert expected_string == optimistic_fixture, f"Expected {expected_string} to equal optimistic fixture content"

if __name__ == "__main__":
    pytest.main([__file__])
