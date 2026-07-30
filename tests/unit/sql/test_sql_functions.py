"""Tests for the sql_functions discovery table."""

from ida_bridge.sql import sql
from ida_bridge.sql.functions import ALL_FUNCTIONS


def test_lists_every_registered_scalar() -> None:
    result = sql("SELECT name FROM sql_functions")
    listed = {row["name"] for row in result.rows}
    registered = {spec.name for spec in ALL_FUNCTIONS}
    assert listed == registered


def test_rows_carry_signature_and_description() -> None:
    result = sql("SELECT name, signature, description FROM sql_functions WHERE name = 'read_bytes'")
    assert result.columns == ["name", "signature", "description"]
    assert result.rows == [
        {
            "name": "read_bytes",
            "signature": "read_bytes(ea, size)",
            "description": "Raw bytes at ea as a hex string; capped at 4 KiB, raises above.",
        }
    ]


def test_name_like_filters_a_family() -> None:
    result = sql("SELECT name FROM sql_functions WHERE name LIKE 'read\\_%' ESCAPE '\\' ORDER BY name")
    names = [row["name"] for row in result.rows]
    assert names == [
        "read_bytes",
        "read_cstr",
        "read_i32",
        "read_i64",
        "read_rel32",
        "read_u16",
        "read_u32",
        "read_u64",
        "read_u8",
    ]


def test_discoverable_via_sqlite_master() -> None:
    result = sql("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sql_functions'")
    assert [row["name"] for row in result.rows] == ["sql_functions"]
