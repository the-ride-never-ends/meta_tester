"""
DuckDB-specific implementation for the Database class.

This module provides DuckDB-specific implementations of database operations
for use with the Database class through dependency injection.
"""
import os
from typing import Any, Callable, Dict, List, Never, Optional, Tuple


import duckdb


from logger import logger
from configs import configs
from .types import DUCKDB_TYPE_DICT


# get_function_type_hints.py
import inspect
from typing import  Any, Callable, Dict, Optional, get_type_hints


def get_function_type_hints(func: Callable) -> Dict[str, str]:
    """
    Gets the type hints for a given Python function as string names.
    
    This function extracts parameter and return type annotations from a function
    using Python's introspection capabilities and returns them as string names
    rather than class objects.
    
    Args:
        func: The function to extract type hints from.
        
    Returns:
        Dict[str, str]: A dictionary mapping parameter names to their type hint names,
            with a special 'return' key for the return type hint name.
            
    Example:
        For a function defined as:
        ```
        def example(x: int, y: str) -> bool:
            return x > len(y)
        ```
        
        Calling get_function_type_hints(example) would return:
        {
            'x': 'int',
            'y': 'str',
            'return': 'bool'
        }
    """
    try:
        # Use the built-in get_type_hints function from typing module
        raw_type_hints = get_type_hints(func)
        
        # Convert type objects to their string representations
        type_hints = {}
        for name, type_hint in raw_type_hints.items():
            # For simple types, __name__ gives us the clean name
            if hasattr(type_hint, '__name__'):
                type_hints[name] = type_hint.__name__
            # For complex types from the typing module, use str() and clean up
            else:
                type_str = str(type_hint)
                # Handle typing module types which have format: typing.TypeName[args]
                if type_str.startswith('typing.'):
                    type_str = type_str.replace('typing.', '')
                # Remove unnecessary quotes from string representation
                type_hints[name] = type_str
                
        return type_hints
    
    except (TypeError, ValueError):
        # Fall back to manual extraction if get_type_hints fails
        type_hints = {}
        signature = inspect.signature(func)
        
        # Get parameter annotations
        for param_name, param in signature.parameters.items():
            if param.annotation is not inspect.Parameter.empty:
                # Convert annotation to string and clean up
                if hasattr(param.annotation, '__name__'):
                    type_hints[param_name] = param.annotation.__name__
                else:
                    type_str = str(param.annotation)
                    if type_str.startswith('typing.'):
                        type_str = type_str.replace('typing.', '')
                    type_hints[param_name] = type_str
                
        # Get return annotation
        if signature.return_annotation is not inspect.Signature.empty:
            if hasattr(signature.return_annotation, '__name__'):
                type_hints['return'] = signature.return_annotation.__name__
            else:
                type_str = str(signature.return_annotation)
                if type_str.startswith('typing.'):
                    type_str = type_str.replace('typing.', '')
                type_hints['return'] = type_str
            
        return type_hints




class DuckDbDatabase:
    """
    DuckDB-specific implementation of database operations.
    
    This class provides static methods that implement DuckDB-specific
    database operations for use with the Database class.
    NOTE Many of these methods lack try-except blocks because they are implemented in the interface.
    """
    _read_only = False # Default to non read-only mode
    FETCH_METHODS = ['records', 'dict', 'tuple', 'dataframe']

    logger = logger

    def __init__(self) -> None:
        # Only create an instance to change class attributes like the logger.
        pass

    @property
    def read_only(cls) -> bool:
        """
        Get the read-only status of the database.
        
        Returns:
            bool: True if the database is read-only, False otherwise
        """
        return cls._read_only

    @classmethod
    def connect(cls, db_path: str = ":memory:", read_only: bool = False) -> duckdb.DuckDBPyConnection:
        """
        Connect to a DuckDB database.
        
        Args:
            db_path: Path to the DuckDB database file. Defaults to in-memory database
            read_only: Whether to open the database in read-only mode. Defaults to True
            
        Returns:
            A DuckDB connection
        """
        if db_path == ":memory:" and read_only is True:
            raise ValueError("In-memory databases cannot be opened in read-only mode.")
        else:
            cls._read_only = read_only
            conn = duckdb.connect(db_path, read_only=cls._read_only)
            # Check what databases are attached
            attached_dbs = conn.execute("PRAGMA database_list").fetchall()

            print("Attached databases:", attached_dbs)
            return conn

    @classmethod
    def close(cls, conn: duckdb.DuckDBPyConnection) -> None:
        """
        Close a DuckDB connection.
        
        Args:
            conn: The DuckDB connection to close
        """
        try:
            conn.close()
        except Exception as e:
            cls.logger.warning(f"Error closing DuckDB connection: {e}")

    @classmethod
    def execute(
        cls,
        conn: duckdb.DuckDBPyConnection, 
        query: str, 
        params: Optional[Tuple | Dict[str, Any]] = None
        ) -> duckdb.DuckDBPyConnection:
        """
        Execute a query on a DuckDB connection.
        
        Args:
            conn: The DuckDB connection
            query: The SQL query to execute
            params: Optional parameters for the query
            
        Returns:
            The cursor after executing the query
            
        Raises:
            Exception: If query execution fails
        """
        try:
            with conn.cursor() as cursor:
                return cursor.execute(query, params) if params else cursor.execute(query)
        except Exception as e:
            cls.logger.error(f"Error executing DuckDB query: {e}")
            cls.logger.debug(f"Query: {query}")
            cls.logger.debug(f"Params: {params}")
            raise e

    @classmethod
    def fetch(
            cls,
            conn: duckdb.DuckDBPyConnection,
            query: str, 
            params: Optional[ Tuple | Dict[str, Any]] = None, 
            num_results: int = 1,
            return_format: Optional[str] = None,
            ) -> List[Dict[str, Any]] | None:

        print("In DuckDbDatabase.fetch")
        if return_format not in DuckDbDatabase.FETCH_METHODS:
            print("Invalid return format:", return_format)
            raise ValueError(f"Return format '{return_format}' is not supported by duckdb. Must be one of {DuckDbDatabase.FETCH_METHODS}")

        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params) if params else cursor.execute(query)
                match return_format:
                    case 'records':
                        print("Fetching as records")
                        return cursor.fetchdf().to_dict('records')[0:num_results] # -> list of dicts
                    case 'dict':
                        print("Fetching as dict")
                        return cursor.fetchdf().iloc[0:num_results].to_dict() # -> dict of lists
                    case 'tuple':
                        print("Fetching as tuples")
                        return cursor.fetchall()[0:num_results] # -> list of tuples
                    case 'dataframe':
                        print("Fetching as dataframe")
                        return cursor.fetchdf().iloc[0:num_results] # -> pd.DataFrame
                    case _:
                        print("Default fetching as records")
                        return cursor.fetchdf().to_dict('records')[0:num_results] # -> list of dicts

        except Exception as e:
            print("Error during fetch:", e)
            cls.logger.error(f"Error fetching results from DuckDB: {e}")
            raise e


    @classmethod
    def fetch_all(
                cls,
                conn: duckdb.DuckDBPyConnection, 
                query: str, 
                params: Optional[Tuple | Dict[str, Any]] = None,
                return_format: str = 'records'
                ) -> Any:
        """
        Fetch all results from a query.

        Args:
            conn: The DuckDB connection
            query: The SQL query to execute
            params: Optional parameters for the query
            return_format: Format for the returned data, one of 'records', 'dict', 'tuple', 'dataframe'
            
        Returns:
            Query results in the specified format
            
        Raises:
            Exception: If query execution fails
        """
        print("In DuckDbDatabase.fetch_all")
        if return_format not in DuckDbDatabase.FETCH_METHODS:
            print("Invalid return format:", return_format)
            raise ValueError(f"Return formate '{return_format}' is not supported by duckdb. Must be one of {DuckDbDatabase.FETCH_METHODS}")

        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params) if params else cursor.execute(query)
                match return_format:
                    case 'records':
                        print("Fetching all as records")
                        return cursor.fetchdf().to_dict('records') # -> list of dicts
                    case 'dict':
                        print("Fetching all as dict")
                        return cursor.fetchdf().to_dict() # -> dict of lists
                    case 'tuple':
                        print("Fetching all as tuples")
                        return cursor.fetchall() # -> list of tuples
                    case 'dataframe':
                        print("Fetching all as dataframe")
                        return cursor.fetchdf() # -> pd.DataFrame
                    case _:
                        print("Default fetching all as records")
                        return cursor.fetchdf().to_dict('records') # -> list of dicts
        except Exception as e:
            print("Error during fetch_all:", e)
            cls.logger.error(f"Error fetching results from DuckDB: {e}")
            return []

    @classmethod
    def begin(cls, conn: duckdb.DuckDBPyConnection) -> None:
        """
        Begin a transaction.
        
        Args:
            conn: The DuckDB connection

        Raises:
            Exception: If transaction begins fails
        """
        try:
           conn.begin()
        except Exception as e:
            cls.logger.error(f"Error beginning DuckDB transaction: {e}")
            raise e

    @classmethod
    def commit(cls, conn: duckdb.DuckDBPyConnection) -> None:
        """
        Commit the current transaction.
        
        Args:
            conn: The DuckDB connection
            
        Raises:
            Exception: If commit fails
        """
        try:
            conn.commit()
        except Exception as e:
            cls.logger.error(f"Error committing DuckDB transaction: {e}")
            raise e

    @classmethod
    def rollback(cls, conn: duckdb.DuckDBPyConnection) -> None:
        """
        Rollback the current transaction.
        
        Args:
            conn: The DuckDB connection
            
        Raises:
            Exception: If rollback fails
        """
        try:
            conn.rollback()
        except Exception as e:
            cls.logger.error(f"Error rolling back DuckDB transaction: {e}")
            raise e

    @classmethod
    def get_cursor(conn: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyConnection:
        """
        Get a cursor from a DuckDB connection.
        
        Args:
            conn: The DuckDB connection
            
        Returns:
            A cursor object
        """
        return conn.cursor()

    @classmethod
    def close_cursor(cls, cursor: duckdb.DuckDBPyConnection) -> None:
        """
        Close a cursor.
        
        Args:
            cursor: The DuckDB cursor to close
        """
        try:
            cursor.close()
        except Exception as e:
            cls.logger.warning(f"Error closing DuckDB cursor: {e}")
            raise e

    @classmethod
    def get_session(conn: duckdb.DuckDBPyConnection) -> Never:
        """
        Get a session from a DuckDB connection.
        
        Note: DuckDB doesn't have a separate session concept like SQLAlchemy,
        so this just returns the connection itself.
        
        Args:
            conn: The DuckDB connection
            
        Returns:
            The connection object (DuckDB doesn't have separate sessions)
        """
        raise NotImplementedError("DuckDB does not support sessions. Use the connection directly.")

    @classmethod
    def close_session(cls, conn: duckdb.DuckDBPyConnection) -> Never:
        """
        Close a session in DuckDB.
        
        Note: DuckDB doesn't have a separate session concept like SQLAlchemy,
        so this just closes the connection.
        
        Args:
            conn: The DuckDB connection
        """
        raise NotImplementedError("DuckDB does not support sessions. Close the connection directly.")

    @classmethod
    def create_function(
                    cls,
                    conn: duckdb.DuckDBPyConnection, 
                    name: str, 
                    function: Callable, 
                    argument_types: Optional[List[str]] = [], 
                    return_type: Optional[Any] = None,
                    side_effects: Optional[bool] = False
                    ) -> None:
        """
        Register a Python function with DuckDB.
        If argument types and return type are not provided, they will be inferred from the function's type hints.

        Args:
            conn: The DuckDB connection
            name: Name to register the function as
            function: The Python function to register
            argument_types: List of DuckDB argument types
            return_type: The function's declared DuckDB return type.
            side_effects: Whether the function has side effects. This 

        Raises:
            Exception: If function registration fails
        """
        try:
            if argument_types is None or return_type is None:
                # Get argument types and return type
                type_hints = get_function_type_hints(function)

                # Infer the python types from the function via its type hint
                if return_type is None:
                    return_type = DUCKDB_TYPE_DICT.get(type_hints.pop('return', None), None)

                if argument_types is None:
                    argument_types = [DUCKDB_TYPE_DICT.get(type, None) for type in type_hints.values() if type != 'return']

            conn.create_function(
                name, function, parameters=argument_types, 
                return_type=return_type, side_effects=side_effects
            )
        except Exception as e:
            cls.logger.error(f"Error registering function with DuckDB: {e}")
            raise

    @classmethod
    def create_table_if_not_exists(
                                cls,
                                conn: duckdb.DuckDBPyConnection, 
                                table_name: str, 
                                columns: List[Dict[str, str]], 
                                constraints: Optional[List[str]] = None
                                ) -> None:
        """
        Create a table if it doesn't exist.
        
        Args:
            conn: The DuckDB connection
            table_name: Name of the table to create
            columns: List of column definitions, each a dict with 'name' and 'type'
            constraints: Optional list of constraint definitions

        Raises:
            Exception: If table creation fails
        """
        try:
            # Build column definitions
            column_defs = [f"{col['name']} {col['type']}" for col in columns]
            
            # Add constraints if provided
            if constraints:
                column_defs.extend(constraints)
                
            # Build and execute CREATE TABLE statement
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                {', '.join(column_defs)}
            )
            """
            conn.execute(create_table_sql)
        except Exception as e:
            cls.logger.error(f"Error creating table {table_name}: {e}")
            raise

    @classmethod
    def create_index_if_not_exists(
                                cls,
                                conn: duckdb.DuckDBPyConnection, 
                                table_name: str, 
                                index_name: str, 
                                columns: List[str], 
                                unique: bool = False
                                ) -> None:
        """
        Create an index if it doesn't exist.
        
        Args:
            conn: The DuckDB connection
            table_name: Name of the table to create the index on
            index_name: Name of the index to create
            columns: List of column names to include in the index
            unique: Whether the index should enforce uniqueness
            
        Raises:
            Exception: If index creation fails
        """
        try:
            # Build and execute CREATE INDEX statement
            unique_str = "UNIQUE" if unique else ""
            create_index_sql = f"""
            CREATE {unique_str} INDEX IF NOT EXISTS {index_name}
            ON {table_name} ({', '.join(columns)})
            """
            conn.execute(create_index_sql)
        except Exception as e:
            cls.logger.error(f"Error creating index {index_name} on {table_name}: {e}")
            raise
