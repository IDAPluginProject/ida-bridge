"""Tests for execute_sql mechanics: transport limit, errors, discovery."""

from typing import Any

import pytest

from ida_bridge.sql import sql
from ida_bridge.sql.db import get_db
from ida_bridge.sql.models import TRANSPORT_MAX_ROWS, QueryError

# ---------------------------------------------------------------------------
# Stub virtual table helpers
# ---------------------------------------------------------------------------


class _StubCursor:
    def __init__(self, rows: list[tuple]) -> None:
        self._rows = rows
        self._pos = -1

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple) -> None:
        self._pos = 0

    def Eof(self) -> bool:
        return self._pos >= len(self._rows)

    def Next(self) -> None:
        self._pos += 1

    def Column(self, n: int) -> Any:
        return self._rows[self._pos][n]

    def Rowid(self) -> int:
        return self._pos

    def Close(self) -> None:
        pass


class _StubTable:
    def __init__(self, rows: list[tuple]) -> None:
        self._rows = rows

    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 100
        ii.estimatedRows = len(self._rows)
        return True

    def Open(self) -> _StubCursor:
        return _StubCursor(self._rows)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class _StubModule:
    def __init__(self, rows: list[tuple], schema: str = "CREATE TABLE x(a INTEGER, b TEXT)") -> None:
        self._rows = rows
        self._schema = schema

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        return self._schema, _StubTable(self._rows)

    Connect = Create


def _register_stub(name: str, rows: list[tuple], schema: str = "CREATE TABLE x(a INTEGER, b TEXT)") -> None:
    """Register a stub virtual table on the singleton connection."""
    db = get_db()
    mod = _StubModule(rows, schema)
    mod_name = f"_stub_{name}"
    db.create_module(mod_name, mod, use_bestindex_object=True)
    db.execute(f"CREATE VIRTUAL TABLE [{name}] USING [{mod_name}]")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestColumnMetadataConsistency:
    """Verify declared per-table column metadata matches the schema."""

    def test_hex_and_u64_columns_exist_in_table_schema(self) -> None:
        from ida_bridge.sql.tables import ALL_TABLES
        from ida_bridge.sql.tables.base import hex_column_names, u64_column_names

        errors: list[str] = []

        for module_cls, table_name in ALL_TABLES:
            instance = module_cls()
            schema = instance.Create(None, "", "", "")[0]
            inside = schema.split("(", 1)[1].rsplit(")", 1)[0]
            all_cols = {part.strip().split()[0] for part in inside.split(",")}

            derived_hex = set(hex_column_names(module_cls.COLUMN_SPECS))
            missing_hex = sorted(derived_hex - all_cols)
            if missing_hex:
                errors.append(f"{table_name}.COLUMN_SPECS hex: missing from schema: {', '.join(missing_hex)}")

            derived_u64 = set(u64_column_names(module_cls.COLUMN_SPECS))
            missing_u64 = sorted(derived_u64 - all_cols)
            if missing_u64:
                errors.append(f"{table_name}.COLUMN_SPECS u64: missing from schema: {', '.join(missing_u64)}")

        assert not errors, "column metadata mismatches:\n" + "\n".join(errors)


class TestConstraintPlanValidation:
    def test_duplicate_constraint_arg_names_raise(self) -> None:
        from ida_bridge.sql.tables.base import BaseCursor, ConstraintArgSpec, ConstraintPlanSpec

        class DupCursor(BaseCursor):
            CONSTRAINT_PLANS = {
                1: ConstraintPlanSpec(
                    args=(
                        ConstraintArgSpec("ea", "ea", "first"),
                        ConstraintArgSpec("ea", "ea", "second"),
                    )
                ),
            }

        cursor = DupCursor()
        with pytest.raises(ValueError, match="duplicate constraint arg names"):
            cursor._decode_constraint_args(1, (0x1000, 0x2000))


class TestQueryExecution:
    def test_empty_result_columns_preserved(self) -> None:
        """Column names available even on empty results (exec tracer)."""
        result = sql("SELECT * FROM funcs WHERE start_ea = -1")
        assert result.rows == []
        assert result.columns == [
            "start_ea",
            "name",
            "prototype",
            "comment",
            "rpt_comment",
            "size",
            "end_ea",
            "flags",
            "return_type",
            "arg_count",
            "calling_conv",
            "type_source",
        ]

    def test_hex_column_names_do_not_leak_to_unrelated_tables(self) -> None:
        db = get_db()
        db.execute("DROP TABLE IF EXISTS local_collision")
        db.execute("CREATE TABLE local_collision(address INTEGER, ordinal INTEGER, size INTEGER)")
        db.execute("INSERT INTO local_collision VALUES (4660, 7, 32)")

        result = sql("SELECT address, ordinal, size FROM local_collision")

        assert result.rows == [{"address": 4660, "ordinal": 7, "size": 32}]
        assert result.hex_columns == frozenset()
        assert result.format_for_transport()["rows"] == [{"address": 4660, "ordinal": 7, "size": 32}]

    def test_write_setup_then_single_result_set_is_allowed(self) -> None:
        result = sql(
            "CREATE TEMP TABLE multi_context(a INTEGER, b TEXT); "
            "INSERT INTO multi_context VALUES (1, 'one'); "
            "SELECT a, b FROM multi_context"
        )

        assert result.columns == ["a", "b"]
        assert result.rows == [{"a": 1, "b": "one"}]

    def test_write_only_multi_statement_returns_empty_result(self) -> None:
        result = sql(
            "CREATE TEMP TABLE multi_write_only(a INTEGER); "
            "INSERT INTO multi_write_only VALUES (1); "
            "UPDATE multi_write_only SET a = 2"
        )

        assert result.columns == []
        assert result.rows == []

    def test_single_result_set_then_write_is_allowed(self) -> None:
        sql("CREATE TEMP TABLE multi_after_result(a INTEGER); INSERT INTO multi_after_result VALUES (1)")

        result = sql("SELECT a FROM multi_after_result; UPDATE multi_after_result SET a = 2")
        readback = sql("SELECT a FROM multi_after_result")

        assert result.columns == ["a"]
        assert result.rows == [{"a": 1}]
        assert readback.rows == [{"a": 2}]

    @pytest.mark.parametrize(
        "query",
        (
            pytest.param("SELECT 1 AS first_col; SELECT 2 AS second_col", id="same-width-selects"),
            pytest.param("SELECT 1 AS a; SELECT 2 AS b, 3 AS c", id="different-width-selects"),
            pytest.param("SELECT 1 AS empty WHERE 0; SELECT 2 AS b", id="zero-row-select"),
            pytest.param("VALUES (1); SELECT 2 AS b", id="values"),
            pytest.param(
                "CREATE TEMP TABLE multi_pragma(a INTEGER); PRAGMA table_info(multi_pragma); SELECT 1 AS b",
                id="pragma",
            ),
            pytest.param(
                "CREATE TEMP TABLE multi_returning(a INTEGER, b TEXT); "
                "INSERT INTO multi_returning VALUES (1, 'one') RETURNING a; "
                "SELECT b FROM multi_returning",
                id="returning",
            ),
        ),
    )
    def test_multiple_result_sets_are_rejected(self, query: str) -> None:
        with pytest.raises(QueryError, match="multiple row-producing statements"):
            sql(query)


class TestTransportLimit:
    def test_under_limit(self) -> None:
        rows = [(i, f"r{i}") for i in range(10)]
        _register_stub("t", rows)
        result = sql("SELECT * FROM t")
        assert len(result.rows) == 10

    def test_at_limit(self) -> None:
        rows = [(i, f"r{i}") for i in range(TRANSPORT_MAX_ROWS)]
        _register_stub("t", rows)
        result = sql("SELECT * FROM t")
        assert len(result.rows) == TRANSPORT_MAX_ROWS

    def test_over_limit_raises(self) -> None:
        rows = [(i, f"r{i}") for i in range(TRANSPORT_MAX_ROWS + 100)]
        _register_stub("t", rows)
        with pytest.raises(QueryError, match="transport limit"):
            sql("SELECT * FROM t")


class TestErrors:
    def test_bad_sql(self) -> None:
        with pytest.raises(QueryError):
            sql("NOT VALID SQL")

    def test_unknown_table(self) -> None:
        with pytest.raises(QueryError):
            sql("SELECT * FROM nonexistent_table_xyz")


# ---------------------------------------------------------------------------
# Funcs enrichment columns
# ---------------------------------------------------------------------------


class TestFuncsEnrichment:
    """Test prototype, comment, rpt_comment, return_type, arg_count, calling_conv."""

    def test_columns_null_when_no_type_info(self) -> None:
        """With default stubs (no funcs), new columns are absent from results."""
        result = sql("SELECT * FROM funcs WHERE start_ea = -1")
        assert result.rows == []

    def test_all_enrichment_columns_populated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Wire up full stubs so all new columns get values."""
        import sys
        from types import SimpleNamespace

        func = SimpleNamespace(start_ea=0x1000, end_ea=0x1100, flags=0x14)

        # tinfo_t stub that reports a function with 2 args and int return
        def _make_tinfo():
            class FakeTinfo:
                def is_func(self) -> bool:
                    return True

                def get_rettype(self):
                    return SimpleNamespace(dstr=lambda: "int", empty=lambda: False)

                def get_nargs(self) -> int:
                    return 2

                def get_func_details(self, fti):
                    fti._cc = 0x30  # CM_CC_CDECL
                    return True

            return FakeTinfo()

        class FakeFti:
            def __init__(self) -> None:
                self._cc = 0

            def get_cc(self) -> int:
                return self._cc

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([0x1000]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=lambda ea: func if ea == 0x1000 else None,
            get_func_cmt=lambda f, r: "regular comment" if not r else "repeating comment",
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: "my_func",
        ))
        monkeypatch.setitem(sys.modules, "ida_typeinf", SimpleNamespace(
            tinfo_t=_make_tinfo,
            func_type_data_t=FakeFti,
            print_type=lambda ea, flags: "int __cdecl my_func(int a, char *b)",
            PRTYPE_1LINE=0x0001,
            is_custom_callcnv=lambda cc: False,
            get_custom_callcnv=lambda cc: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_nalt", SimpleNamespace(
            get_import_module_qty=lambda: 0,
            get_import_module_name=lambda i: "",
            enum_import_names=lambda i, cb: None,
            get_root_filename=lambda: "stub",
            get_imagebase=lambda: 0,
            get_tinfo=lambda tif, ea: True,
            get_aflags=lambda ea: 0x02000800,  # AFL_TI | AFL_USERTI
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT * FROM funcs")
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row["start_ea"] == 0x1000
        assert row["name"] == "my_func"
        assert row["prototype"] == "int __cdecl my_func(int a, char *b)"
        assert row["comment"] == "regular comment"
        assert row["rpt_comment"] == "repeating comment"
        assert row["return_type"] == "int"
        assert row["arg_count"] == 2
        assert row["calling_conv"] == "cdecl"
        assert row["flags"] == 0x14
        assert row["type_source"] == "user/til"

    def test_columns_null_when_no_tinfo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When get_tinfo returns False, type columns are NULL."""
        import sys
        from types import SimpleNamespace

        func = SimpleNamespace(start_ea=0x2000, end_ea=0x2100, flags=0)

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([0x2000]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=lambda ea: func if ea == 0x2000 else None,
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: "sub_2000",
        ))
        monkeypatch.setitem(sys.modules, "ida_typeinf", SimpleNamespace(
            tinfo_t=lambda: SimpleNamespace(
                is_func=lambda: False,
                get_rettype=lambda: SimpleNamespace(dstr=lambda: "", empty=lambda: True),
                get_nargs=lambda: -1,
                get_func_details=lambda fti: False,
            ),
            func_type_data_t=lambda: SimpleNamespace(get_cc=lambda: 0),
            print_type=lambda ea, flags: None,
            PRTYPE_1LINE=0x0001,
            is_custom_callcnv=lambda cc: False,
            get_custom_callcnv=lambda cc: None,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT * FROM funcs")
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row["start_ea"] == 0x2000
        assert row["name"] == "sub_2000"
        assert row["prototype"] is None
        assert row["comment"] is None
        assert row["rpt_comment"] is None
        assert row["return_type"] is None
        assert row["arg_count"] is None
        assert row["calling_conv"] is None
        assert row["flags"] == 0
        assert row["type_source"] is None

    def test_custom_calling_convention(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Custom CC registered via register_custom_callcnv resolves its name."""
        import sys
        from types import SimpleNamespace

        func = SimpleNamespace(start_ea=0x3000, end_ea=0x3100, flags=0)
        custom_cc_code = 0x200  # CM_CC_FIRST_PLAIN_CUSTOM

        def _make_tinfo():
            class FakeTinfo:
                def is_func(self) -> bool:
                    return True

                def get_rettype(self):
                    return SimpleNamespace(dstr=lambda: "void", empty=lambda: False)

                def get_nargs(self) -> int:
                    return 0

                def get_func_details(self, fti):
                    fti._cc = custom_cc_code
                    return True

            return FakeTinfo()

        class FakeFti:
            def __init__(self) -> None:
                self._cc = 0

            def get_cc(self) -> int:
                return self._cc

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([0x3000]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=lambda ea: func if ea == 0x3000 else None,
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: "custom_func",
        ))
        monkeypatch.setitem(sys.modules, "ida_typeinf", SimpleNamespace(
            tinfo_t=_make_tinfo,
            func_type_data_t=FakeFti,
            print_type=lambda ea, flags: "void __lstrcatn custom_func()",
            PRTYPE_1LINE=0x0001,
            is_custom_callcnv=lambda cc: cc >= 0x200,
            get_custom_callcnv=lambda cc: SimpleNamespace(name="__lstrcatn") if cc == custom_cc_code else None,
        ))
        monkeypatch.setitem(sys.modules, "ida_nalt", SimpleNamespace(
            get_import_module_qty=lambda: 0,
            get_import_module_name=lambda i: "",
            enum_import_names=lambda i, cb: None,
            get_root_filename=lambda: "stub",
            get_imagebase=lambda: 0,
            get_tinfo=lambda tif, ea: True,
            get_aflags=lambda ea: 0x02000800,  # AFL_TI | AFL_USERTI
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT calling_conv FROM funcs")
        assert len(result.rows) == 1
        assert result.rows[0]["calling_conv"] == "__lstrcatn"


# ---------------------------------------------------------------------------
# func_flag scalar
# ---------------------------------------------------------------------------


class TestFuncFlag:
    def test_known_flags(self) -> None:
        for name, expected in [
            ("noret", 0x01),
            ("far", 0x02),
            ("lib", 0x04),
            ("static", 0x08),
            ("frame", 0x10),
            ("userfar", 0x20),
            ("hidden", 0x40),
            ("thunk", 0x80),
        ]:
            result = sql(f"SELECT func_flag('{name}') AS v")
            assert result.rows[0]["v"] == expected, f"func_flag('{name}')"

    def test_unknown_raises(self) -> None:
        with pytest.raises(QueryError, match="unknown func_flag 'bogus'"):
            sql("SELECT func_flag('bogus')")

    def test_null_raises(self) -> None:
        with pytest.raises(QueryError, match="unknown func_flag None"):
            sql("SELECT func_flag(NULL)")

    def test_empty_raises(self) -> None:
        with pytest.raises(QueryError, match="unknown func_flag ''"):
            sql("SELECT func_flag('')")

    def test_composable_with_flags_column(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """func_flag works in WHERE with bitwise AND on flags column."""
        import sys
        from types import SimpleNamespace

        # Two funcs: one thunk (0x80), one normal (0x10)
        f1 = SimpleNamespace(start_ea=0x1000, end_ea=0x1010, flags=0x90)  # thunk + frame
        f2 = SimpleNamespace(start_ea=0x2000, end_ea=0x2010, flags=0x10)  # frame only

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([0x1000, 0x2000]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=lambda ea: {0x1000: f1, 0x2000: f2}.get(ea),
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: {0x1000: "thunk_func", 0x2000: "normal_func"}.get(ea, ""),
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT name FROM funcs WHERE flags & func_flag('thunk') != 0")
        assert len(result.rows) == 1
        assert result.rows[0]["name"] == "thunk_func"
