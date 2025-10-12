import re


def extract_failed_test_names(stdout: str) -> list[str]:
    """
    Extract the names of failed tests from pytest output.

    Args:
        stdout (str): Standard output from pytest run.
    
    Returns:
        List[str]: List of failed test names.

    Raises:
        TypeError: If stdout is not a string.
        ValueError: If stdout is empty.
    """
    if not isinstance(stdout, str):
        raise TypeError(f"stdout must be a string, got {type(stdout).__name__}.")
    if not stdout:
        raise ValueError("stdout is empty.")

    failed_tests: list[str] = []
    all_unique_parts = set()

    summary_markers = ["Captured log call", "short test summary info"]
    for marker in summary_markers: 
        if marker in stdout:
            #marker = "short test summary info"
            stdout = stdout.split(marker, 1)[-1]

    for line in stdout.split('\n'):
        unique_parts = set()
        if 'FAILED' not in line:
            continue

        if "[" in line and "]" in line:
            # Remove anything between the brackets
            line = re.sub(r'\[.*?\]', '', line)

        if '::' in line:
            # Extract the test name from lines.
            parts = line.split('::')
            unique_parts = {
                part for part in parts 
                if part and # Remove empty parts, python file names, and lines that start with a capital letter
                not part.endswith(".py") and
                not part[0].isupper()
            }
            all_unique_parts.update(unique_parts)

            if len(parts) >= 2:
                # Get the last part and remove everything after the closing bracket
                last_part = parts[-1]
                # Split on ' ' to remove stuff like "- AssertionError"
                test_with_params = last_part.split(' ')[0]
                
                # Find the last closing bracket to handle nested brackets in parameters
                last_bracket_pos = test_with_params.rfind(']')
                if last_bracket_pos != -1:
                    # Remove everything from the last closing bracket onwards
                    test_with_params = test_with_params[:last_bracket_pos]

                # Now split on '[' to get just the test name without parameters
                test_name = test_with_params.split('[')[0].strip()
                # Remove 'FAILED' prefix if it somehow got through
                test_name = test_name.replace('FAILED', '').strip()

                # Split off the class name if present
                if '.' in test_name:
                    test_name = test_name.split('.')[-1].strip()

                if test_name:  # Only add non-empty test names
                    failed_tests.append(test_name)

    # Remove duplicates while preserving order
    seen = set()
    unique_tests = []
    for test in failed_tests:
        if test not in seen:
            seen.add(test)
            unique_tests.append(test)

    return unique_tests
