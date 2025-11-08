-- Schema for storing pytest results
CREATE SEQUENCE id_sequence START 1;
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY DEFAULT nextval('id_sequence'), -- Unique identifier for each test run
    test_file_path VARCHAR NOT NULL, -- Absolute path to the test file
    run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_passes INTEGER NOT NULL,
    total_failures INTEGER NOT NULL,
    failed_tests JSON NOT NULL, -- JSON array of failed test names, matched to their target (e.g. test method, test class, file, etc.)
);

-- Example failed_tests JSON:
/*
{
    "more_than_10_lines_long": ["test_example_function"]
    "no_assertions": ["test_another_function", "test_yet_another_function"]
    "no_class_docstring": ["TestExampleClass"]
    "no_shebang": ["script_without_shebang.py"]
}
*/

-- Index for quick lookups by test file
CREATE INDEX IF NOT EXISTS idx_test_file_path ON results(test_file_path);

-- Index for quick lookups by timestamp
CREATE INDEX IF NOT EXISTS idx_run_timestamp ON results(run_timestamp);
