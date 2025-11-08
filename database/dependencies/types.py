from typing import TypeVar


SqlConnection = TypeVar("SqlConnection")
SqlCursor = TypeVar("SqlConnection")

# Mapping from Python type names to DuckDB type names
# This dictionary is used for automatic type inference when registering Python functions with DuckDB
# When a Python function is registered without explicit type information, we use this mapping
# to convert the Python type annotations to their DuckDB equivalents
DUCKDB_TYPE_DICT = {
    # Core Python types
    'int': 'INTEGER',
    'str': 'VARCHAR',
    'float': 'FLOAT',
    'bool': 'BOOLEAN',
    'bytes': 'BLOB',
    'bytearray': 'BLOB',
    'None': 'NULL',
    
    # Date and time types
    'datetime': 'TIMESTAMP',
    'date': 'DATE',
    'time': 'TIME',
    'timedelta': 'INTERVAL',
    
    # Numeric types with specific precision
    'Decimal': 'DECIMAL',
    
    # Collection types
    'list': 'LIST',
    'tuple': 'LIST',  # DuckDB doesn't have a tuple type, so use LIST
    'dict': 'MAP',     # For dictionaries with consistent key/value types
    'set': 'LIST',     # DuckDB doesn't have a set type, so use LIST
    
    # NumPy types
    'ndarray': 'LIST',  # Simplified mapping for numpy arrays
    'int8': 'TINYINT',
    'int16': 'SMALLINT',
    'int32': 'INTEGER',
    'int64': 'BIGINT',
    'uint8': 'UTINYINT',
    'uint16': 'USMALLINT',
    'uint32': 'UINTEGER',
    'uint64': 'UBIGINT',
    'float16': 'FLOAT',
    'float32': 'FLOAT',
    'float64': 'DOUBLE',
    
    # SQL-specific types
    'UUID': 'UUID',
    'JSON': 'JSON',
    
    # Special types
    'Any': None,      # Let DuckDB infer the type
    'Optional': None, # Let DuckDB infer the type
    
    # Struct and composite types (need special handling)
    'struct': 'STRUCT',
    'enum': 'VARCHAR',
    
    # Geographic types
    'Point': 'POINT',
    'LineString': 'LINESTRING',
    'Polygon': 'POLYGON',
    'MultiPoint': 'MULTIPOINT',
    'MultiLineString': 'MULTILINESTRING',
    'MultiPolygon': 'MULTIPOLYGON',
    'GeometryCollection': 'GEOMETRYCOLLECTION',
}