



from pathlib import Path
from typing import List


import pytest


_TRUE_NEGATIVES_DIR = Path(__file__).parent / "true_negatives"


from ..meta_test import logger  # noqa: F401


from .test_true_positives import _meta_tester_output  # noqa: F401


def _get_true_negative_files() -> List[Path]:
    """
    Get all Python test files from the true_negatives directory.
    
    Returns:
        List[Path]: List of paths to true positive test files.
    
    Raises:
        FileNotFoundError: If the true_negatives directory does not exist.
    """
    pattern = "_test_*.py"
    if not _TRUE_NEGATIVES_DIR.exists():
        raise FileNotFoundError(f"True positives directory not found at {_TRUE_NEGATIVES_DIR}")
    
    return sorted(_TRUE_NEGATIVES_DIR.glob(pattern))


@pytest.mark.parametrize(
    "test_file",
    [f for f in _get_true_negative_files()],
    ids=lambda p: p.name[:-3]
)
class TestTrueNegativeDetection:
    """Test suite for verifying true positive test smell detection."""

    def test_when_running_meta_tester_on_true_negative_then_no_errors_in_stdout(
        self, test_file
    ):
        """
        GIVEN a true negative test file
        WHEN the meta-tester is run on that file
        THEN there should be no pytest errors in stdout
        """
        stdout = _meta_tester_output(test_file)['stdout']
        error_string = "== ERRORS =="

        assert error_string not in stdout, \
            f"Expected no errors in stdout for {test_file.name}, but found errors:\n{stdout}"

    def test_when_running_meta_tester_on_true_negative_then_no_tests_fail(
        self, test_file
    ):
        """
        GIVEN a true positive test file containing no test smells
        WHEN the meta-tester is run on that file
        THEN no meta-tests should fail
        """
        logger.debug(f"===== TRUE_NEGATIVE_TEST_FILE: '{test_file.name}' =====")
        expected_count = 0
        output = _meta_tester_output(test_file)
        actual_count = output['failed_count']

        assert expected_count == actual_count, \
            f"Expected no failed tests for {test_file.name}, got {actual_count} instead\n{output['failed_tests']}"
