#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
import traceback

try:
    from database import Database, make_db
    from logger import logger as module_logger
    from configs import configs
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

try:
    import pandas as pd
except ImportError as e:
    module_logger.error(f"Error importing pandas: {e}")
    sys.exit(1)

class InitializationError(Exception):
    """Custom exception for initialization errors."""

    def __init__(self, message: str):
        super().__init__(message)

class DatabaseError(Exception):
    """Custom exception for database errors."""

    def __init__(self, message: str):
        super().__init__(message)

class StatsCalculationError(Exception):
    """Custom exception for statistics calculation errors."""

    def __init__(self, message: str):
        super().__init__(message)

class ReportGenerationError(Exception):
    """Custom exception for report generation errors."""

    def __init__(self, message: str):
        super().__init__(message)

print("Modules imported successfully.")

def get_data_from_db(db: Database, test_file: str, n: int):
    assert isinstance(db, Database), f"db must be an instance of Database, got {type(db).__name__}"
    assert isinstance(test_file, str), f"test_file must be a string, got {type(test_file).__name__}"
    assert isinstance(n, int), f"n must be an integer, got {type(n).__name__}"
    assert n > 0, f"n must be a positive integer, got {n}"

    sql: str = """
    SELECT * FROM results
    WHERE test_file_path = ?
    ORDER BY run_timestamp DESC
    LIMIT ?
    """
    expected_columns = {"id", "test_file_path", "run_timestamp", "total_passes", "total_failures", "failed_tests"}
    df = None
    try:
        df = db.fetch_all(sql, return_format="dataframe", params=(str(test_file), n))
        assert df is not None, "Dataframe returned from database.fetch_all is None."
        assert isinstance(df, pd.DataFrame), f"Data returned from database.fetch_all must be a pandas DataFrame, got {type(df).__name__}"
        column_names = [col.lower() for col in df.columns]
        for col in column_names:
            assert col in expected_columns, f"Expected column '{col}' in the dataframe, but it is missing."
        return df
    except Exception as e:
        raise # Let the error propagate for higher-level handling
    finally:
        if db is not None:
            db.exit()


def calculate_statistics(data: pd.DataFrame) -> dict:
    """Calculate statistics from test run data.
    
    Args:
        data: DataFrame with columns: id, test_file_path, run_timestamp, 
              total_passes, total_failures, failed_tests.
    
    Returns:
        Dictionary containing calculated statistics.
    
    Raises:
        ValueError: If data is empty or missing required columns.
        TypeError: If data is not a DataFrame.
    """
    if not isinstance(data, pd.DataFrame):
        raise TypeError(f"data must be a pandas DataFrame, got {type(data).__name__}")

    if data.empty:
        raise ValueError("data cannot be empty")

    required_cols = {"id","test_file_path","run_timestamp","total_passes","total_failures", "failed_tests"}
    for col in required_cols:
        if col not in data.columns:
            raise ValueError(f"data is missing required column: {col}")

    data = data.sort_values("run_timestamp").reset_index(drop=True)

    stats = {
        "total_runs": len(data),
        "first_failures": int(data.iloc[0]["total_failures"]),
        "last_failures": int(data.iloc[-1]["total_failures"]),
        "total_reduction": int(data.iloc[0]["total_failures"] - data.iloc[-1]["total_failures"]),
        "runs_data": [{
            "run_number": idx + 1,
            "timestamp": row["run_timestamp"],
            "failed_tests": json.loads(row["failed_tests"]),
            "delta": 0 if idx == 0 else int(row["total_failures"] - data.iloc[idx-1]["total_failures"])
        } for idx, row in data.iterrows()]
    }

    for runs in [10, 20, 30]:
        if stats["total_runs"] >= runs:
            last_n = [r["delta"] for r in stats["runs_data"][-runs:]]
            stats[f"avg_delta_last_{runs}"] = sum(last_n) / len(last_n)
    return stats






def make_report(stats: dict, test_file: str, n: int) -> str:
    """Generate markdown report from statistics.
    
    Args:
        stats: Dictionary containing calculated statistics.
        test_file: Name of the test file.
        n: Number of runs included in report.
    
    Returns:
        Formatted markdown report string.
    
    Raises:
        ValueError: If stats is empty or missing required keys.
        TypeError: If arguments have incorrect types.
    """
    if not isinstance(stats, dict):
        raise TypeError(f"stats must be a dictionary, got {type(stats).__name__}")
    if not isinstance(test_file, str):
        raise TypeError(f"test_file must be a string, got {type(test_file).__name__}")
    if not isinstance(n, int):
        raise TypeError(f"n must be an integer, got {type(n).__name__}")

    test_file = test_file.strip()
    if not test_file:
        raise ValueError("test_file cannot be an empty string")
    if n <= 0:
        raise ValueError(f"n must be a positive integer, got {n}")
    required_keys = {"total_runs", "first_failures", "last_failures", "total_reduction", "runs_data"}
    for key in required_keys:
        if key not in stats:
            raise ValueError(f"stats missing required key: {key}")
    
    if not stats["runs_data"]:
        raise ValueError("stats['runs_data'] cannot be empty")

    print(f"runs data: {stats['runs_data']}")

    path = Path(test_file).resolve()
    reduction_pct = (stats["total_reduction"] / stats["first_failures"] * 100) if stats["first_failures"] > 0 else 0
    avg_reduction = stats["total_reduction"] / stats["total_runs"] if stats["total_runs"] > 0 else 0
    
    trend = "IMPROVING" if stats["total_reduction"] > 0 else "FLAT" if stats["total_reduction"] == 0 else "REGRESSING"
    
    report = f"""# Statistics Report: {path}
--------------------

# CONVERGENCE ANALYSIS
--------------------
Trend: {trend}

Starting Failures (Run 1):     {stats['first_failures']}
Current Failures (Run {stats['total_runs']}):     {stats['last_failures']}
Total Reduction:               {stats['total_reduction']} ({reduction_pct:.1f}%)
Average Reduction per Run:     {avg_reduction:.1f}
"""
    
    if "avg_delta_last_10" in stats:
        report += f"\n## Trend Analysis (Last 10 Runs):\n"
        report += f"- Average Δ: {stats['avg_delta_last_10']:.1f} failures/run\n"
    
    report += f"\n# RUNNING STATISTICS (Past {stats['total_runs']} Runs)\n"
    report += "----------------------------------\n"
    report += "| Run # | Date       | Total Failures | Δ from Previous | Trend    |\n"
    report += "|-------|------------|----------------|-----------------|----------|\n"
    
    for run in stats["runs_data"]:
        date_str = str(run["timestamp"])[:10]
        delta_str = "-" if run["delta"] == 0 and run["run_number"] == 1 else f"{run['delta']:+d}"
        
        if run["run_number"] == 1:
            trend_str = "baseline"
        elif run["delta"] < 0:
            trend_str = "improving"
        elif run["delta"] > 0:
            trend_str = "regressing"
        else:
            trend_str = "flat"
        
        failures = []
        for fail in run["failed_tests"].values():
            failures.extend(fail)
        len_failures = len(failures)
        
        report += f"| {run['run_number']:<5} | {date_str} | {len_failures:<14} | {delta_str:<15} | {trend_str:<8} |\n"

    report += f"\n# FAILURE TRENDS\n"
    report += "------------------------\n"
    report += "| Category                    | Run 1 | Run 10 | Run 20 | Run 30 | Status      |\n"
    report += "|-----------------------------|-------|--------|--------|--------|-------------|\n"

    # Extract failure categories and counts per run
    failure_trends = {}
    
    for run_data in stats["runs_data"]:
        run_num = run_data["run_number"]
        failed_tests = run_data["failed_tests"]
        
        for category, test_list in failed_tests.items():
            if category not in failure_trends:
                failure_trends[category] = {}
            failure_trends[category][run_num] = len(test_list)
    
    # Generate the trend table
    for category in sorted(failure_trends.keys()):
        run_counts = failure_trends[category]
        
        run_1 = run_counts.get(1, 0)
        run_10 = run_counts.get(10, "-") if stats["total_runs"] >= 10 else "-"
        run_20 = run_counts.get(20, "-") if stats["total_runs"] >= 20 else "-"
        run_30 = run_counts.get(30, "-") if stats["total_runs"] >= 30 else "-"

        # Determine status
        last_run = run_counts.get(stats["total_runs"], 0)
        if last_run == 0:
            status = "FIXED"
        elif last_run == run_1:
            status = "stagnant"
        elif last_run < run_1:
            reduction_rate = (run_1 - last_run) / stats["total_runs"]
            status = "converging" if reduction_rate >= 1.0 else "slow"
        else:
            status = "regressing"
        
        category_display = category.replace("_", " ")
        report += f"| {category_display:<27} | {run_1:<5} | {run_10!s:<6} | {run_20!s:<6} | {run_30!s:<6} | {status:<11} |\n"

    return report


def get_stats_report(filename: str, n: int = 30, save: bool = True) -> None:
    """

    Args:
        filename (str): Name of the test file.
        n (int): Number of most recent runs to include in the report. Baseline run is always included.
        save (bool): Whether to save the report to a markdown file. The file is named 'stats_report_<test_file_name>_n_<n>.md'. 
        Defaults to True.
    
    Raises:
        TypeError: If filename is not a string, n is not an integer, or save is not a boolean.
        ValueError: If n is not a positive integer or filename is an empty string or invalid file path.
        FileNotFoundError: If the specified test file does not exist in the database.
        InitializationError: If there is an error initializing the database.
        DatabaseError: If there is an error querying the database.
        IOError: If there is an error saving the report to a file.
        RuntimeError: If an unexpected error occurs during report generation.
    """
    print("Starting stats report generation...")
    if not isinstance(filename, str):
        raise TypeError(f"filename must be a string, got '{type(filename).__name__}'.")
    if not isinstance(n, int):
        raise TypeError(f"n must be an integer, got '{type(n).__name__}'.")
    if not isinstance(save, bool):
        raise TypeError(f"save must be a boolean, got '{type(save).__name__}'.")
    if n <= 0:
        raise ValueError(f"n must be a positive integer, got {n}.")

    filename = filename.strip()
    if not filename:
        raise ValueError("filename cannot be an empty string.")

    try:
        path: Path = Path(filename)
    except Exception as e:
        print(f"Error resolving file path: {e}")
        raise ValueError(f"Invalid filename '{filename}': {e}") from e

    print("Initializing database connection...")
    db: Database = None
    try:
        db: Database = make_db(mock_configs=configs)
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise InitializationError(f"Failed to initialize database: {e}") from e
    print("Database initialized successfully.")

    assert db is not None, "'db' variable is None after initialization."
    assert isinstance(db, Database), f"'db' variable must be an instance of Database, got {type(db).__name__}"

    # Get the data from the database
    df: pd.DataFrame = None
    try:
        df = get_data_from_db(db, str(path.resolve()), n)
    except Exception as e:
        print(f"Error retrieving data from database: {e}\n{traceback.format_exc()}")
        raise DatabaseError(f"Failed to retrieve data from database: {e}") from e

    assert df is not None, "Dataframe 'df' is None after fetching data from database."
    assert isinstance(df, pd.DataFrame), f"'df' must be a pandas DataFrame, got {type(df).__name__}"
    if df.empty:
        raise FileNotFoundError(f"No data found in database for test file '{filename}'.")

    # Calculate the stats
    stats: dict = None
    try:
        stats: dict = calculate_statistics(df)
    except Exception as e:
        print(f"Error calculating statistics: {e}\n{traceback.format_exc()}")
        raise StatsCalculationError(f"Failed to calculate statistics: {e}") from e

    assert stats is not None, "'stats' variable is None."
    assert isinstance(stats, dict), f"'stats' variable must be a dictionary, got {type(stats).__name__}"

    # Format the report
    report: str = None
    try:
        report = make_report(stats, filename, n)
    except Exception as e:
        print(f"Error generating report: {e}\n{traceback.format_exc()}")
        raise ReportGenerationError(f"Failed to generate report: {e}") from e

    assert isinstance(report, str), f"'report' variable must be a string, got {type(report).__name__}"
    assert not report.strip() == "", "'report' variable is an empty string."

    # Print the report
    print(report)

    # Save the report if specified
    try:
        with open(f"stats_report_{path.stem}_n_{n}.md", "w") as file:
            file.write(report)
    except Exception as e:
        print(f"Error saving report to file: {e}")
        raise IOError(f"Failed to save report: {e}") from e
    else:
        print(f"\nReport saved to 'stats_report_{path.stem}_n_{n}.md'.")


def main() -> int:
    """

    Args (from argparse):
        filename (str): name of the test file.
        n (int): Number of most recent runs to include in the report. Baseline run is always included.
        save (bool): Whether to save the report to a markdown file. The file is named 'stats_report_<test_file_name>_n_<n>.md'. 
        Defaults to True.

    Returns:
        int: Exit code (0 for success, 1 for failure/keyboard interrupt).

    Example:
    >>> python get_stats_report.py --filename test_file.py --n 30 --save True


    Example Report Output for Single File:

        Statistics Report: test_document_storage.py
        ================================================================================

        # CONVERGENCE ANALYSIS
        --------------------
        Test Creation LLM: Claude 4.5 Sonnet
        Test Correction LLM: Claude 4.5 Sonnet
        Trend: IMPROVING

        Starting Failures (Run 1):     427
        Current Failures (Run 30):     142
        Total Reduction:               285 (-66.7%)
        Average Reduction per Run:     9.5 
        Linear Projection to Zero:     15 more runs

        ## Trend Analysis (Failures/run, Last 10 Runs):
        - Average Δ: -7.2 failures/run
        - Volatility: ±2.3 failures/run
        - Regression Events: 1/10 runs

        # RUNNING STATISTICS (Past 30 Runs)
        ----------------------------------
        | Run # | Date       | Total Failures | Δ from Previous | Trend    | LLM Used  |
        |-------|------------|----------------|-----------------|----------|-----------|
        | 1     | 2025-10-15 | 427            | -               | baseline | Claude 4.5 Sonnet |
        | 2     | 2025-10-16 | 427            | 0               | flat   | Claude 4.5 Sonnet |
        | 3     | 2025-10-17 | 424            | -3              | improving | Claude 4.5 Sonnet |
        | 4     | 2025-10-18 | 420            | -4              | improving | Claude 4.5 Sonnet |
        | 5     | 2025-10-19 | 423            | +3              | regressing | Claude 4.5 Sonnet |
        | ...   | ...        | ...            | ...             | ...      | ...       |
        | 28    | 2025-11-12 | 156            | -8              | improving | Claude 4.5 Sonnet |
        | 29    | 2025-11-13 | 148            | -8              | improving | Claude 4.5 Sonnet |
        | 30    | 2025-11-14 | 142            | -6              | improving | Claude 4.5 Sonnet |

        # FAILURE TRENDS
        ------------------------
        | Category                    | Run 1 | Run 10 | Run 20 | Run 30 | Status      |
        |-----------------------------|-------|--------|--------|--------|-------------|
        | F-string assertions         | 67    | 67     | 45     | 12     | converging |
        | Production calls            | 67    | 67     | 52     | 38     | slow      |
        | Docstring format            | 67    | 58     | 28     | 8      | converging |
        | Test naming                 | 67    | 42     | 15     | 0      | FIXED     |
        | Class docstrings            | 14    | 14     | 10     | 4      | converging |
        | Duplicate assertions        | 1     | 1      | 1      | 1      | stagnant |
        | Missing shebang             | 1     | 0      | 0      | 0      | FIXED    |
        | Missing pytest.main()       | 1     | 0      | 0      | 1      | regressing |

        # Total Failures Over Time
        ------------------------------------
        450│ ●
        400│  ●
        350│    ●●
        300│       ●●
        250│          ●●●
        200│              ●●●
        150│                  ●●●●
        100│                       ●●
        50│
        0│________________________●? (projected)
            1  3  5  7  9 11 13 15 17 19 21 23 25 27 29 31 33
                                Run Number
        margin of error = ±5.2 failures

        # PREDICTIONS
        -------------------
        - Complete convergence: ~15 runs
        - 90% fixed: ~5 runs
        - High-risk stagnation categories: 
            - Production calls: 0.97 fixes/run
            - Duplicate assertions: 0 fixes/run
    """
    print("Parsing command-line arguments...")
    parser = argparse.ArgumentParser(description="Generate statistics report for test file.")
    parser.add_argument("--filename", type=str, required=True, help="Name of the test file.")
    parser.add_argument("--n", type=int, default=30, help="Number of most recent runs to include in the report. Baseline run is always included.")
    parser.add_argument("--save", action="store_true", default=True, help="Whether to save the report to a markdown file. Defaults to True.")

    try:
        args = parser.parse_args()
    except Exception as e:
        module_logger.error(f"Error parsing arguments: {e}")
        return 1

    try:
        get_stats_report(args.filename, n=args.n, save=args.save)
    except Exception as e:
        module_logger.error(f"Error generating report: {e}")
        return 1
    except KeyboardInterrupt:
        module_logger.info("\nReport generation interrupted by user.")
        return 1
    else:
        return 0

if __name__ == "__main__":
    sys.exit(main())
