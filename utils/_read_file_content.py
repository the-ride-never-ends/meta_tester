def read_file_content(test_file: str) -> str:
    """Read the entire content of a test file.
    
    Args:
        test_file (str): Path to the test file.
        
    Returns:
        str: The entire content of the file.
        
    Raises:
        IOError: If the file cannot be read.
    """
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        raise IOError(f"Failed to read {test_file}: {e}") from e
