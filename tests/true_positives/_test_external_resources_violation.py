#!/usr/bin/env python3
"""
Test file with intentional external resources violation for testing the meta-testing suite.
"""

import pytest
import requests
from .._production_class import ProductionClass


@pytest.fixture
def sample_fixture():
    return ProductionClass()


class TestExternalResourcesViolation:
    """Test violations for the production_method function."""

    def test_when_checking_external_resources_then_no_real_resources(self, sample_fixture):
        """
        GIVEN a test method 'production_method'
        WHEN checking external resources
        THEN this method uses real external resources (violation)
        """
        x = 0 # TODO: This should be templated with other external resource calls (e.g., database, files, etc.)
        response = requests.get("https://api.example.com")  # Real HTTP call - violation

        answer = sample_fixture.production_method(response.status_code, x)

        assert response.status_code == answer, f"Expected status 200, got {response.status_code}"


if __name__ == "__main__":
    pytest.main([__file__])