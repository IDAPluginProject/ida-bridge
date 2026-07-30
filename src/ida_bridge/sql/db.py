"""APSW database connection management and query execution."""

import apsw

from .models import TRANSPORT_MAX_ROWS, QueryError, QueryResult, Row
from .tables import (
    get_hex_columns,
    get_hex_columns_by_table,
    get_u64_columns,
    get_u64_columns_by_table,
)
from .u64 import decode_sql_u64

_db: apsw.Connection | None = None


def get_db() -> apsw.Connection:
    """Return the singleton APSW connection, creating it on first call."""
    global _db
    if _db is None:
        _db = apsw.Connection(":memory:")
        from .functions import register_all as register_functions
        from .tables import register_all as register_tables
        from .views import register_all as register_views

        register_tables(_db)
        register_functions(_db)
        register_views(_db)
    return _db


def reset_db() -> None:
    """Drop the current connection. Next ``get_db()`` creates a fresh one."""
    global _db
    _db = None


def _is_u64_function_result(column_name: str, function_names: frozenset[str]) -> bool:
    """Return True if *column_name* is an unaliased uint64 scalar expression."""
    return any(column_name.startswith(f"{name}(") for name in function_names)


def execute_sql(query: str) -> QueryResult:
    """Execute a SQL query and return columns + rows.

    Raises QueryError on bad SQL or when the result exceeds the
    transport safety limit (use LIMIT in your query).
    """
    db = get_db()

    # Capture column descriptions via exec tracer. APSW's
    # getdescription() fails after a 0-row result completes, but the
    # tracer fires at prepare time when descriptions are available.
    captured_desc: list[tuple[str, str | None]] = []
    captured_desc_full: list[tuple[str | None, str | None, str | None, str | None, str | None]] = []

    def _tracer(cursor: apsw.Cursor, sql: str, bindings: dict | None) -> bool:
        nonlocal captured_desc, captured_desc_full
        try:
            desc = list(cursor.getdescription())
        except apsw.ExecutionCompleteError:
            return True
        if not desc:
            return True
        if captured_desc:
            msg = (
                "multiple row-producing statements are not supported by --sql; "
                "use separate --sql commands or combine the reads into one SELECT"
            )
            raise QueryError(msg)
        captured_desc = desc
        try:
            captured_desc_full = list(cursor.description_full)
        except (AttributeError, apsw.ExecutionCompleteError):
            captured_desc_full = []
        return True

    db.set_exec_trace(_tracer)
    try:
        cursor = db.execute(query)

        columns = [name for name, _type in captured_desc]
        rows: list[Row] = []

        for row_tuple in cursor:
            if len(rows) >= TRANSPORT_MAX_ROWS:
                msg = f"result exceeded transport limit ({TRANSPORT_MAX_ROWS} rows); add LIMIT to your query"
                raise QueryError(msg)
            rows.append(dict(zip(columns, row_tuple, strict=True)))
    except QueryError:
        raise
    except (apsw.SQLError, apsw.Error, ValueError) as exc:
        raise QueryError(str(exc)) from None
    finally:
        db.set_exec_trace(None)

    all_hex = get_hex_columns()
    all_hex_by_table = get_hex_columns_by_table()
    all_u64 = get_u64_columns()
    all_u64_by_table = get_u64_columns_by_table()
    from .functions import get_u64_result_function_names

    u64_functions = get_u64_result_function_names()
    result_hex: set[str] = set()
    result_u64: set[str] = set()
    for i, column_name in enumerate(columns):
        if i < len(captured_desc_full):
            _name, _decltype, _db_name, table_name, origin_name = captured_desc_full[i]
            if table_name and origin_name:
                if origin_name in all_hex_by_table.get(table_name, frozenset()):
                    result_hex.add(column_name)
                if origin_name in all_u64_by_table.get(table_name, frozenset()):
                    result_u64.add(column_name)
        if not captured_desc_full and column_name in all_hex:
            result_hex.add(column_name)
        if _is_u64_function_result(column_name, u64_functions):
            result_u64.add(column_name)
        elif not captured_desc_full and column_name in all_u64:
            result_u64.add(column_name)

    if result_u64:
        for row in rows:
            for column_name in result_u64:
                value = row.get(column_name)
                if isinstance(value, int):
                    row[column_name] = decode_sql_u64(value)

    return QueryResult(columns=columns, rows=rows, hex_columns=frozenset(result_hex))
