"""Virtual table registration."""

from typing import TYPE_CHECKING

from . import analysis, core, decompiler, heads, scalars, search, types
from .base import hex_column_names, u64_column_names

if TYPE_CHECKING:
    import apsw

ALL_TABLES = [
    *core.ALL_TABLES,
    *analysis.ALL_TABLES,
    *decompiler.ALL_TABLES,
    *search.ALL_TABLES,
    *heads.ALL_TABLES,
    *types.ALL_TABLES,
    *scalars.ALL_TABLES,
]

# Populated by register_all.
_hex_columns: set[str] = set()
_hex_columns_by_table: dict[str, frozenset[str]] = {}
_u64_columns: set[str] = set()
_u64_columns_by_table: dict[str, frozenset[str]] = {}


def get_hex_columns() -> frozenset[str]:
    """Return the set of column names that should be hex-formatted in transport."""
    return frozenset(_hex_columns)


def get_hex_columns_by_table() -> dict[str, frozenset[str]]:
    """Return per-table hex column metadata."""
    return dict(_hex_columns_by_table)


def get_u64_columns() -> frozenset[str]:
    """Return the set of column names whose values use uint64 boundary encoding."""
    return frozenset(_u64_columns)


def get_u64_columns_by_table() -> dict[str, frozenset[str]]:
    """Return per-table uint64 column metadata."""
    return dict(_u64_columns_by_table)


def register_all(db: "apsw.Connection") -> None:
    """Register all IDA virtual tables with the APSW connection."""
    _hex_columns.clear()
    _hex_columns_by_table.clear()
    _u64_columns.clear()
    _u64_columns_by_table.clear()
    for module_cls, table_name in ALL_TABLES:
        module_name = f"_{table_name}"
        db.create_module(
            module_name,
            module_cls(),
            use_bestindex_object=True,
            use_no_change=True,
        )
        db.execute(f"CREATE VIRTUAL TABLE [{table_name}] USING [{module_name}]")

        column_specs = module_cls.COLUMN_SPECS
        hex_cols = hex_column_names(column_specs)
        u64_cols = u64_column_names(column_specs)

        if hex_cols:
            _hex_columns.update(hex_cols)
            _hex_columns_by_table[table_name] = hex_cols

        if u64_cols:
            _u64_columns.update(u64_cols)
            _u64_columns_by_table[table_name] = u64_cols

    # Also collect hex columns from views (registered separately but
    # queried through the same execute_sql path).
    from ..views import get_hex_columns as view_hex_columns

    _hex_columns.update(view_hex_columns())
