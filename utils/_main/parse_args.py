import argparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the meta-tester on a specific test file and report results.",
    )
    parser.add_argument(
        "test_file",
        type=str,
        help="Path to the test file to analyze (must end with .py)."
    )
    return parser.parse_args()
