"""Pydantic models and types for the SQL layer."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from .u64 import format_sql_u64_hex

Row = dict[str, Any]

# Transport-layer safety limit. Queries returning more rows than this raise
# QueryError instead of silently truncating. Use LIMIT in SQL to control size.
TRANSPORT_MAX_ROWS = 10_000


class QueryError(Exception):
    """SQL layer error: bad query, unknown table, missing filter, etc."""


class QueryResult(BaseModel):
    """Result of a SQL query execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    columns: list[str]
    rows: list[Row]
    hex_columns: frozenset[str] = frozenset()

    def format_for_transport(self) -> dict[str, Any]:
        """Serialize with address columns formatted as hex strings."""
        if not self.hex_columns:
            return self.model_dump(mode="json", exclude={"hex_columns"})
        formatted_rows: list[Row] = []
        for row in self.rows:
            out: Row = {}
            for k, v in row.items():
                if k in self.hex_columns and isinstance(v, int):
                    out[k] = format_sql_u64_hex(v)
                else:
                    out[k] = v
            formatted_rows.append(out)
        return {"columns": list(self.columns), "rows": formatted_rows}
