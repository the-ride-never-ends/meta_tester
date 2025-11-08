"""
A module to manage the database connection and operations.
This module provides a singleton instance of the Database class, which is read-only by default.
"""
from typing import Callable


from configs import configs, Configs
from logger import logger as  module_logger
from ._database import Database
from .dependencies.duckdb_database import DuckDbDatabase



def make_db(mock_resources: dict[str, Callable] = None, mock_configs=None) -> Database:
    """
    Factory function to create a new Database instance.
    
    This function initializes a new Database object with the provided configurations
    and DuckDB resources. It is intended to be used for creating database connections
    as needed.

    Args:
        mock_resources (dict[str, Any], optional): A dictionary of callables to override injected defaults. Defaults to None.
        mock_configs (Configs, optional): A Configs object to override default configurations. Defaults to None.

    Returns:
        Database: A new instance of the Database class.
    """
    # Export resources dictionary for use with Database class
    configs = mock_configs or project_configs
    _resources = mock_resources or {}
    db = DuckDbDatabase()
    db.logger = logger = _resources.pop("logger", module_logger)

    duckdb_resources = {
        "begin": _resources.pop("begin", db.begin),
        "close": _resources.pop("close", db.close),
        "commit": _resources.pop("commit", db.commit),
        "connect": _resources.pop("connect", db.connect),
        "create_function": _resources.pop("create_function", db.create_function),
        "create_index_if_not_exists": _resources.pop("create_index_if_not_exists", db.create_index_if_not_exists),
        "create_table_if_not_exists": _resources.pop("create_table_if_not_exists", db.create_table_if_not_exists),
        "execute": _resources.pop("execute", db.execute),
        "fetch": _resources.pop("fetch", db.fetch),
        "fetch_all": _resources.pop("fetch_all", db.fetch_all),
        "fetch_one": _resources.pop("fetch_one", db.fetch),
        "get_cursor": _resources.pop("get_cursor", db.get_cursor),
        "rollback": _resources.pop("rollback", db.rollback),
        "read_only": _resources.pop("read_only", False),  # Set read_only to True for read-only access
        "logger": logger,
    }

    for key in _resources.keys():
        if key not in duckdb_resources:
            raise KeyError(f"Unexpected resource key: {key}")

    return Database(configs=configs, resources=duckdb_resources)
