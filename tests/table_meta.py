"""Introspection of SQL virtual-table declarations, shared by unit and e2e tests.

Runs host-side: ``Create``/``Open`` only apply schema specs and construct objects,
and every ``ida_*`` import in the table modules is function-local.
"""

from dataclasses import dataclass
from functools import cache
from typing import Any

from ida_bridge.sql.tables import ALL_TABLES
from ida_bridge.sql.tables.base import BaseCursor

UPDATE_METHODS = ("UpdateChangeRow", "UpdateInsertRow", "UpdateDeleteRow")


@dataclass(frozen=True)
class TableContract:
    name: str
    writable_table: bool
    has_column_rowid: bool
    has_custom_rowid: bool
    writable_columns: frozenset[str]

    @property
    def has_rowid_mechanism(self) -> bool:
        return self.has_column_rowid or self.has_custom_rowid


def inspect_table(module_cls: type[Any], table_name: str) -> TableContract:
    module = module_cls()
    _schema, table = module.Create(None, "", "", table_name)
    cursor = table.Open()

    return TableContract(
        name=table_name,
        writable_table=any(hasattr(table, method) for method in UPDATE_METHODS),
        # apply_schema_specs stamps only the classes it is given; read-only tables
        # pass their cursor alone, so their table class has no such attribute.
        has_column_rowid=getattr(table, "ROWID_COLUMN_SPEC", None) is not None,
        has_custom_rowid=type(cursor).Rowid is not BaseCursor.Rowid,
        writable_columns=frozenset(name for name, spec in module_cls.COLUMN_SPECS.items() if spec.writable),
    )


@cache
def all_contracts() -> tuple[TableContract, ...]:
    return tuple(inspect_table(module_cls, name) for module_cls, name in ALL_TABLES)


def writable_tables() -> set[str]:
    return {contract.name for contract in all_contracts() if contract.writable_table}


def writable_columns(table: str) -> frozenset[str]:
    for contract in all_contracts():
        if contract.name == table:
            return contract.writable_columns
    msg = f"unknown table: {table}"
    raise ValueError(msg)
