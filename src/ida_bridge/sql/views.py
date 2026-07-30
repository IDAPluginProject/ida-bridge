"""SQL views over IDA virtual tables and scalar functions."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import apsw

ALL_VIEWS: list[tuple[str, str, set[str]]] = [
    (
        "callers",
        """
        CREATE VIEW IF NOT EXISTS callers AS
        SELECT
            f.start_ea AS func_addr,
            COALESCE(name_at(f.start_ea), printf('sub_%X', f.start_ea)) AS func_name,
            x.from_ea AS caller_addr,
            COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) AS caller_name,
            x.from_func AS caller_func
        FROM funcs f
        CROSS JOIN xrefs x
        WHERE x.to_ea = f.start_ea
          AND x.type IN (16, 17)
          AND x.from_func != 0
        """,
        {"func_addr", "caller_addr", "caller_func"},
    ),
    (
        "callees",
        """
        CREATE VIEW IF NOT EXISTS callees AS
        SELECT
            f.start_ea AS func_addr,
            COALESCE(name_at(f.start_ea), printf('sub_%X', f.start_ea)) AS func_name,
            x.to_ea AS callee_addr,
            COALESCE(name_at(x.to_ea), printf('sub_%X', x.to_ea)) AS callee_name,
            func_start(x.to_ea) AS callee_func
        FROM funcs f
        CROSS JOIN xrefs x
        WHERE x.from_func = f.start_ea
          AND x.type IN (16, 17)
          AND x.from_func != 0
        """,
        {"func_addr", "callee_addr", "callee_func"},
    ),
    (
        "string_refs",
        """
        CREATE VIEW IF NOT EXISTS string_refs AS
        SELECT
            s.address AS string_addr,
            s.string_value,
            s.length AS string_length,
            x.from_ea AS ref_addr,
            x.from_func AS func_addr,
            COALESCE(name_at(x.from_func), printf('sub_%X', x.from_func)) AS func_name
        FROM strings s
        JOIN xrefs x ON x.to_ea = s.address
        WHERE x.from_func != 0
        """,
        {"string_addr", "string_length", "ref_addr", "func_addr"},
    ),
]
"""(name, CREATE VIEW sql, hex_columns) triples for registration."""


def get_hex_columns() -> set[str]:
    """Return hex column names declared by views."""
    result: set[str] = set()
    for _name, _ddl, hex_cols in ALL_VIEWS:
        result.update(hex_cols)
    return result


def register_all(db: "apsw.Connection") -> None:
    """Register all views on the connection."""
    for _name, ddl, _hex_cols in ALL_VIEWS:
        db.execute(ddl)
