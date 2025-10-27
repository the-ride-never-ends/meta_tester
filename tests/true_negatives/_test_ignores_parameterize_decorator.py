#!/usr/bin/env python3
import pytest


ARCHIVE_ID = "archive_123"


# Dummy function
def retrieve_web_content(string: str):
    return {"id": string}


class TestRetrieveWebContent:
    """Tests for the retrieve_web_content function."""

    @pytest.mark.parametrize("field", ["id", "url", "timestamp", "contnet", "metadata", "status"])
    def test_when_success_then_contains_data(self, field):
        """
        GIVEN existing archived content
        WHEN retrieve_web_content succeeds
        THEN data dict contains required fields
        """
        result = retrieve_web_content(ARCHIVE_ID)
        assert field in result, f"Expected 'data' key in result, got keys: {result.keys()}"


if __name__ == "__main__":
    pytest.main([__file__])
