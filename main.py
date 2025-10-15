#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from pathlib import Path
from typing import Any


try:
    import pytest
except ImportError as e:
    print("Error: pytest is not installed. Please install it with 'pip install pytest'.", file=sys.stderr)
    sys.exit(1)


from __version__ import __version__
from utils import run_meta_tester_on_file, parse_args, extract_failed_test_names


def run_meta_tester(test_file: str) -> dict[str, Any]:
    """
    Run the meta-tester on a specific test file.

    Meta-Tester is a unit test suite for for a pytest unit test suite. 
    It automatically detects common testing anti-patterns and 
    enforces consistent test standards. 

    Args:
        test_file (str): Path to the test file to analyze.

    Returns:
        dict[str, Any]: Dictionary of test results. The keys are the following:
            - 'returncode': int, the return code from pytest.
            - 'failed_count': int, number of failed tests.
            - 'failed_tests': list[str], names of the failed tests.
            - 'stdout': str, standard output from pytest.
            - 'stderr': str, standard error from pytest.

    Raises:
        TypeError: If test_file is not a string.
        ValueError: If test_file does not end with .py.
        FileNotFoundError: If the specified test file does not exist.
        RuntimeError: If an unexpected error occurs while running the meta-tester.
    """
    if not isinstance(test_file, str):
        raise TypeError(f"test_file must be a string, got {type(test_file).__name__}.")
    if not test_file.endswith(".py"):
        raise ValueError(f"test_file must be a Python file ending with .py, got {test_file}.")
    test_path = Path(test_file).resolve()
    if not test_path.exists():
        raise FileNotFoundError(f"Test file not found: {test_file}")
    try:
        returncode, stdout, stderr = run_meta_tester_on_file(test_path)
    except Exception as e:
        raise RuntimeError(f"Unexpected error running meta-tester on {test_file}: {e}") from e
    else:
        failed_tests: list[str] = extract_failed_test_names(stdout)
        return {
            'returncode': returncode,
            'failed_count': len(failed_tests),
            'failed_tests': failed_tests,
            'stdout': stdout,
            'stderr': stderr,
        }


def main() -> int:
    try:
        try:
            args = parse_args()
        except Exception as e:
            print(f"Error parsing arguments: {e}", file=sys.stderr)
            return 1
        try:
            results = run_meta_tester(args.test_file)
        except Exception as e:
            print(f"Error running meta-tester: {e}", file=sys.stderr)
            return 1
        else:
            print(f"Meta-tester results for {args.test_file}:")
            print(f"Return code: {results['returncode']}")
            print(f"Failed tests count: {results['failed_count']}")
            print(f"Failed tests: {results['failed_tests']}")
            print("Standard Output:")
            print(results['stdout'])
            print("Standard Error:")
            print(results['stderr'])
            return 0 if results['returncode'] == 0 else 1
    except KeyboardInterrupt:
        print("Program execution interrupted by user.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
