"""Tests for SQL views: callers, callees, string_refs."""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql import sql

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------
#
# func_a at 0x1000: calls func_b at 0x2000 (from 0x1050, code type 17)
# func_b at 0x2000: calls func_a at 0x1000 (from 0x2050, code type 17)
# func_a also has a data ref from 0x1080 to string at 0x3000 (type 1)
#
# String at 0x3000: "hello world", length 11

_FUNC_A = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
_FUNC_B = SimpleNamespace(start_ea=0x2000, end_ea=0x2100)

_XREFS_FROM: dict[int, list[SimpleNamespace]] = {
    0x1050: [SimpleNamespace(frm=0x1050, to=0x2000, type=17, iscode=True)],
    0x1080: [SimpleNamespace(frm=0x1080, to=0x3000, type=1, iscode=False)],
    0x2050: [SimpleNamespace(frm=0x2050, to=0x1000, type=17, iscode=True)],
}

_XREFS_TO: dict[int, list[SimpleNamespace]] = {
    0x2000: [SimpleNamespace(frm=0x1050, to=0x2000, type=17, iscode=True)],
    0x1000: [SimpleNamespace(frm=0x2050, to=0x1000, type=17, iscode=True)],
    0x3000: [SimpleNamespace(frm=0x1080, to=0x3000, type=1, iscode=False)],
}

_HEADS: dict[tuple[int, int], list[int]] = {
    (0x1000, 0x1100): [0x1000, 0x1050, 0x1080],
    (0x2000, 0x2100): [0x2000, 0x2050],
}


class _StringItem:
    """Mimics idautils.Strings() items where str(item) returns content."""

    def __init__(self, ea: int, length: int, strtype: int, content: str) -> None:
        self.ea = ea
        self.length = length
        self.strtype = strtype
        self._content = content

    def __str__(self) -> str:
        return self._content


_STRINGS = [_StringItem(0x3000, 11, 0, "hello world")]


@pytest.fixture(autouse=True)
def _view_stubs(monkeypatch: pytest.MonkeyPatch, _ida_stubs: None) -> None:
    """Override stubs with data for view tests."""

    def get_func(ea: int):
        if _FUNC_A.start_ea <= ea < _FUNC_A.end_ea:
            return _FUNC_A
        if _FUNC_B.start_ea <= ea < _FUNC_B.end_ea:
            return _FUNC_B
        return None

    def get_name(ea: int) -> str:
        names = {0x1000: "func_a", 0x2000: "func_b"}
        return names.get(ea, "")

    def get_strlist_item(si: SimpleNamespace, index: int) -> bool:
        if not 0 <= index < len(_STRINGS):
            return False
        item = _STRINGS[index]
        si.ea = item.ea
        si.length = item.length
        si.type = item.strtype
        return True

    def get_strlit_contents(ea: int, length: int, strtype: int) -> bytes | None:
        for item in _STRINGS:
            if item.ea == ea and item.length == length and item.strtype == strtype:
                return str(item).encode()
        return None

    # fmt: off
    monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
        get_func=get_func,
        get_func_cmt=lambda f, r: None,
    ))
    monkeypatch.setitem(sys.modules, "ida_name", SimpleNamespace(
        get_name=get_name,
    ))
    monkeypatch.setitem(sys.modules, "ida_strlist", SimpleNamespace(
        get_strlist_qty=lambda: len(_STRINGS),
        string_info_t=lambda: SimpleNamespace(ea=0, length=0, type=0),
        get_strlist_item=get_strlist_item,
    ))
    monkeypatch.setattr(sys.modules["ida_bytes"], "get_strlit_contents", get_strlit_contents, raising=False)
    monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
        Functions=lambda: iter([0x1000, 0x2000]),
        Names=lambda: iter([]),
        Strings=lambda: iter(_STRINGS),
        Segments=lambda: iter([]),
        Heads=lambda s, e: iter(_HEADS.get((s, e), [])),
        XrefsTo=lambda ea, f: iter(_XREFS_TO.get(ea, [])),
        XrefsFrom=lambda ea, f: iter(_XREFS_FROM.get(ea, [])),
    ))


# fmt: on
# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestViewDiscovery:
    def test_views_in_sqlite_master(self) -> None:
        result = sql("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
        names = [r["name"] for r in result.rows]
        assert names == ["callees", "callers", "string_refs"]

    def test_strings_columns_aligned(self) -> None:
        result = sql("PRAGMA table_info(strings)")
        col_names = [r["name"] for r in result.rows]
        assert col_names == ["address", "length", "type", "string_value"]

    def test_callers_view_uses_xref_pushdown(self) -> None:
        """Verify the planner pushes down into xrefs, not a full scan."""
        result = sql("EXPLAIN QUERY PLAN SELECT * FROM callers LIMIT 10")
        xref_scans = [row["detail"] for row in result.rows if "SCAN x VIRTUAL TABLE" in row["detail"]]
        assert xref_scans, "xrefs table not found in query plan"
        assert all("INDEX 0:" not in s for s in xref_scans), f"xrefs uses full-scan index: {xref_scans}"

    def test_callees_view_uses_xref_pushdown(self) -> None:
        """Verify the planner pushes down into xrefs, not a full scan."""
        result = sql("EXPLAIN QUERY PLAN SELECT * FROM callees LIMIT 10")
        xref_scans = [row["detail"] for row in result.rows if "SCAN x VIRTUAL TABLE" in row["detail"]]
        assert xref_scans, "xrefs table not found in query plan"
        assert all("INDEX 0:" not in s for s in xref_scans), f"xrefs uses full-scan index: {xref_scans}"


# ---------------------------------------------------------------------------
# callers
# ---------------------------------------------------------------------------


class TestCallers:
    def test_who_calls_func_b(self) -> None:
        result = sql("SELECT * FROM callers WHERE func_addr = 0x2000")
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row["func_addr"] == 0x2000
        assert row["func_name"] == "func_b"
        assert row["caller_addr"] == 0x1050
        assert row["caller_func"] == 0x1000
        assert row["caller_name"] == "func_a"

    def test_who_calls_func_a(self) -> None:
        result = sql("SELECT * FROM callers WHERE func_addr = 0x1000")
        assert len(result.rows) == 1
        assert result.rows[0]["caller_name"] == "func_b"

    def test_no_callers(self) -> None:
        result = sql("SELECT * FROM callers WHERE func_addr = 0xDEAD")
        assert result.rows == []

    def test_data_refs_excluded(self) -> None:
        """Data xref to 0x3000 should not appear (is_code=0)."""
        result = sql("SELECT * FROM callers WHERE func_addr = 0x3000")
        assert result.rows == []

    def test_columns(self) -> None:
        result = sql("SELECT * FROM callers WHERE func_addr = 0x2000")
        assert result.columns == ["func_addr", "func_name", "caller_addr", "caller_name", "caller_func"]


# ---------------------------------------------------------------------------
# callees
# ---------------------------------------------------------------------------


class TestCallees:
    def test_what_func_a_calls(self) -> None:
        result = sql("SELECT * FROM callees WHERE func_addr = 0x1000")
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row["func_addr"] == 0x1000
        assert row["func_name"] == "func_a"
        assert row["callee_addr"] == 0x2000
        assert row["callee_name"] == "func_b"
        assert row["callee_func"] == 0x2000

    def test_what_func_b_calls(self) -> None:
        result = sql("SELECT * FROM callees WHERE func_addr = 0x2000")
        assert len(result.rows) == 1
        assert result.rows[0]["callee_name"] == "func_a"

    def test_no_callees(self) -> None:
        result = sql("SELECT * FROM callees WHERE func_addr = 0xDEAD")
        assert result.rows == []

    def test_columns(self) -> None:
        result = sql("SELECT * FROM callees WHERE func_addr = 0x1000")
        assert result.columns == ["func_addr", "func_name", "callee_addr", "callee_name", "callee_func"]


# ---------------------------------------------------------------------------
# string_refs
# ---------------------------------------------------------------------------


class TestStringRefs:
    def test_string_ref(self) -> None:
        result = sql("SELECT * FROM string_refs WHERE string_addr = 0x3000")
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row["string_addr"] == 0x3000
        assert row["string_value"] == "hello world"
        assert row["string_length"] == 11
        assert row["ref_addr"] == 0x1080
        assert row["func_addr"] == 0x1000
        assert row["func_name"] == "func_a"

    def test_no_refs(self) -> None:
        result = sql("SELECT * FROM string_refs WHERE string_addr = 0xDEAD")
        assert result.rows == []

    def test_columns(self) -> None:
        result = sql("SELECT * FROM string_refs WHERE string_addr = 0x3000")
        assert result.columns == ["string_addr", "string_value", "string_length", "ref_addr", "func_addr", "func_name"]


# ---------------------------------------------------------------------------
# COALESCE fallback
# ---------------------------------------------------------------------------


class TestNameFallback:
    def test_unnamed_function_gets_sub_prefix(self) -> None:
        """When name_at returns NULL, COALESCE falls back to sub_XXX."""
        # 0x1050 is inside func_a but is not in the _NAMES dict for ida_name,
        # however from_func=0x1000 which IS named. Test with an unnamed callee.
        # func_addr=0x3000 has a data ref so won't appear in callers.
        # Instead, test callees: func_b calls func_a at 0x1000 which is named.
        # We need a call to an unnamed target. The stubs don't have one,
        # so test the COALESCE directly.
        result = sql("SELECT COALESCE(name_at(0xDEAD), printf('sub_%X', 0xDEAD)) AS name")
        assert result.rows[0]["name"] == "sub_DEAD"
