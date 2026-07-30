"""SQL interface to IDA via APSW SQLite virtual tables."""

from .db import execute_sql, reset_db
from .models import (
    TRANSPORT_MAX_ROWS,
    QueryError,
    QueryResult,
    Row,
)


def sql(query: str) -> QueryResult:
    """Execute a SQL query against IDA virtual tables."""
    return execute_sql(query)


__all__ = [
    "TRANSPORT_MAX_ROWS",
    "QueryError",
    "QueryResult",
    "Row",
    "reset_db",
    "sql",
]
