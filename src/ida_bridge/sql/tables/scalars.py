"""Virtual table exposing the registered scalar functions for discovery.

Scalars are invisible to ``PRAGMA``/``sqlite_master``. This table makes them
introspectable -- our scalars only, with signature and description -- backed by
the same ``ALL_FUNCTIONS`` registry that registers them, so it cannot drift.
"""

from collections.abc import Iterator
from typing import Any

from .base import BaseCursor, ColumnSpec, apply_schema_specs

_SCHEMA = "CREATE TABLE x(name TEXT, signature TEXT, description TEXT)"


class SqlFunctionsModule:
    COLUMN_SPECS: dict[str, ColumnSpec] = {}

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        apply_schema_specs(_SCHEMA, self.COLUMN_SPECS, SqlFunctionsCursor, table_name=tablename)
        return _SCHEMA, SqlFunctionsTable()

    Connect = Create


class SqlFunctionsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1
        ii.estimatedRows = 40
        return True

    def Open(self) -> "SqlFunctionsCursor":
        return SqlFunctionsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class SqlFunctionsCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        from ..functions import ALL_FUNCTIONS

        def _gen() -> Iterator[tuple[str, str, str]]:
            for spec in sorted(ALL_FUNCTIONS, key=lambda s: s.name):
                yield (spec.name, spec.signature, spec.description)

        self._set_iter(_gen())


ALL_TABLES = [
    (SqlFunctionsModule, "sql_functions"),
]
