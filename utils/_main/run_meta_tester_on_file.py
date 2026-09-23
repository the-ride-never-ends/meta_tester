import os
import subprocess
import sys


from pathlib import Path


_BASE_DIR = Path(__file__).parent.parent.parent

_TRUE_POSITIVES_DIR = _BASE_DIR / "tests" / "true_positives"
_META_TESTER_FILE = _BASE_DIR / "meta_test.py"


def run_meta_tester_on_file(test_file: Path) -> tuple[int, str, str]:
    """
    Run the meta-tester on a specific test file.
    
    Args:
        test_file (Path): Path to the test file to analyze.
    
    Returns:
        Tuple[int, str, str]: Return code, stdout, and stderr from pytest run.
    """
    if not test_file.exists():
        raise FileNotFoundError(f"Test file not found: {test_file}")

    env = os.environ.copy()
    env['META_TESTER_TARGET_FILE'] = str(test_file.resolve())
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(_META_TESTER_FILE.resolve()), "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=_TRUE_POSITIVES_DIR.parent.parent.parent,
        env=env
    )
    return result.returncode, result.stdout, result.stderr
