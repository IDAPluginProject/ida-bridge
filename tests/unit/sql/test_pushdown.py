"""Pushdown contract tests: verify SQLite picks the right index for each table.

Uses real APSW with the real table BestIndexObject implementations.
Xref tests use richer stubs with call tracking to verify the correct
IDA API path is taken (not just that the query runs).
"""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql import sql
from ida_bridge.sql.models import QueryError

# ---------------------------------------------------------------------------
# comments: pushdown on ea, full scan when unconstrained
# ---------------------------------------------------------------------------


class TestCommentsPushdown:
    def test_ea_uses_pushdown(self) -> None:
        result = sql("SELECT * FROM comments WHERE address = 0x1000")
        assert result.columns == ["address", "text", "repeatable"]


# ---------------------------------------------------------------------------
# instructions: pushdown (ea EQ, func_ea EQ, ea range, full scan)
# ---------------------------------------------------------------------------


class TestInstructionsPushdown:
    def _setup_instructions(
        self,
        monkeypatch: pytest.MonkeyPatch,
        calls: dict[str, int] | None = None,
    ) -> None:
        import sys
        from types import SimpleNamespace

        calls = {} if calls is None else calls

        func = SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
        heads = [0x1000, 0x1004, 0x1008]
        sizes = {0x1000: 4, 0x1004: 4, 0x1008: 2}

        def bump(name: str) -> None:
            calls[name] = calls.get(name, 0) + 1

        def fake_heads(start, end):
            if (start, end) == (0x1000, 0x1010):
                return iter(heads)
            return iter(ea for ea in heads if start <= ea < end)

        def fake_getseg(ea):
            bump("getseg")
            if ea == 0x1000:
                return func
            return None

        def fake_get_func(ea):
            bump("get_func")
            return func if 0x1000 <= ea < 0x1010 else None

        def fake_print_insn_mnem(ea):
            bump("print_insn_mnem")
            return {0x1000: "stp", 0x1004: "mov", 0x1008: "ret"}.get(ea, "")

        def fake_get_disasm(ea):
            bump("GetDisasm")
            return {0x1000: "stp x29, x30, [sp,#-0x10]!", 0x1004: "mov x29, sp", 0x1008: "ret"}.get(ea, "")

        def fake_decode_insn(_insn, ea):
            bump("decode_insn")
            return sizes.get(ea, 0)

        def fake_get_item_size(ea):
            bump("get_item_size")
            return sizes.get(ea, 1)

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([0x1000]),
            Heads=fake_heads,
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_segment", SimpleNamespace(
            getseg=fake_getseg,
            get_segm_qty=lambda: 0,
            getnseg=lambda i: None,
            get_segm_name=lambda s: "",
            get_segm_class=lambda s: "",
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=fake_get_func,
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_ua", SimpleNamespace(
            insn_t=lambda: object(),
            decode_insn=fake_decode_insn,
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: "",
            print_insn_mnem=fake_print_insn_mnem,
            GetDisasm=fake_get_disasm,
            get_item_size=fake_get_item_size,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

    def test_ea_uses_pushdown(self) -> None:
        result = sql("SELECT * FROM instructions WHERE address = 0x1000")
        assert result.columns == ["address", "mnemonic", "disasm", "size", "func_ea"]

    def test_func_ea_uses_pushdown(self) -> None:
        # func not found with stub -> empty results, but pushdown path was taken
        result = sql("SELECT * FROM instructions WHERE func_ea = 0x1000")
        assert result.rows == []

    def test_rejects_real_range_constraint(self) -> None:
        with pytest.raises(QueryError, match="instructions.address lower bound must be an INTEGER"):
            sql("SELECT * FROM instructions WHERE address >= 1.5 AND address <= 0x2000")

    def test_ea_range_uses_pushdown(self) -> None:
        result = sql("SELECT * FROM instructions WHERE address >= 0x1000 AND address <= 0x2000")
        assert result.rows == []

    def test_count_avoids_per_row_instruction_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, int] = {}
        self._setup_instructions(monkeypatch, calls)
        result = sql("SELECT count(*) AS cnt FROM instructions")
        assert result.rows[0]["cnt"] == 3
        assert calls.get("decode_insn", 0) == 0
        assert calls.get("print_insn_mnem", 0) == 0
        assert calls.get("GetDisasm", 0) == 0
        assert calls.get("get_item_size", 0) == 0
        assert calls.get("get_func", 0) == 0

    def test_func_address_scan_avoids_expensive_columns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, int] = {}
        self._setup_instructions(monkeypatch, calls)
        result = sql("SELECT address FROM instructions WHERE func_ea = 0x1000")
        assert [row["address"] for row in result.rows] == [0x1000, 0x1004, 0x1008]
        assert calls.get("decode_insn", 0) == 0
        assert calls.get("print_insn_mnem", 0) == 0
        assert calls.get("GetDisasm", 0) == 0
        assert calls.get("get_item_size", 0) == 0
        assert calls.get("get_func", 0) == 1


# ---------------------------------------------------------------------------
# pseudocode: pushdown required (func_ea EQ or ea EQ)
# ---------------------------------------------------------------------------


class TestPseudocodePushdown:
    def test_func_ea_uses_pushdown(self) -> None:
        # decompile raises with stub -> error propagated
        with pytest.raises(QueryError, match="decompile returned None"):
            sql("SELECT * FROM pseudocode WHERE func_ea = 0x1000")

    def test_ea_uses_pushdown(self) -> None:
        # get_func returns None with stub -> error
        with pytest.raises(QueryError, match="no function containing"):
            sql("SELECT * FROM pseudocode WHERE ea = 0x1050")

    def test_rejects_text_constraint(self) -> None:
        with pytest.raises(QueryError, match="pseudocode.func_ea constraint must be an INTEGER"):
            sql("SELECT * FROM pseudocode WHERE func_ea = '0xfffffe0007004000'")

    def test_no_constraint_raises(self) -> None:
        with pytest.raises(QueryError, match="pseudocode table requires WHERE"):
            sql("SELECT * FROM pseudocode")


# ---------------------------------------------------------------------------
# bin_search: pushdown required (pattern EQ)
# ---------------------------------------------------------------------------


class TestBinSearchPushdown:
    def test_pattern_returns_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pattern search yields matching addresses."""
        import sys
        from types import SimpleNamespace

        matches = iter(
            [
                (0x1000, 0),
                (0x2000, 0),
                (0xFFFFFFFFFFFFFFFF, 0),
            ]
        )

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1]),
            ),
            bin_search=lambda *a: next(matches),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
            get_cmt=lambda ea, r: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_ida", SimpleNamespace(
            inf_get_min_ea=lambda: 0,
            inf_get_max_ea=lambda: 0x10000,
            inf_get_procname=lambda: "arm",
            inf_is_64bit=lambda: True,
            inf_is_be=lambda: False,
            inf_get_filetype=lambda: 0,
            inf_is_dll=lambda: False,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT address FROM bin_search WHERE pattern = '7F 23 03 D5'")
        assert len(result.rows) == 2
        assert result.rows[0]["address"] == 0x1000
        assert result.rows[1]["address"] == 0x2000

    def test_no_pattern_raises(self) -> None:
        with pytest.raises(QueryError, match="bin_search table requires WHERE"):
            sql("SELECT * FROM bin_search")

    def test_invalid_pattern_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        from types import SimpleNamespace

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: None),
            ),
            bin_search=lambda *a: (0xFFFFFFFFFFFFFFFF, 0),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
            get_cmt=lambda ea, r: None,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        with pytest.raises(QueryError, match="invalid bin_search pattern"):
            sql("SELECT address FROM bin_search WHERE pattern = 'ZZZ'")

    def test_no_matches_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        from types import SimpleNamespace

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1]),
            ),
            bin_search=lambda *a: (0xFFFFFFFFFFFFFFFF, 0),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
            get_cmt=lambda ea, r: None,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT address FROM bin_search WHERE pattern = 'DE AD'")
        assert result.rows == []

    def test_composable_with_func_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """bin_search results join with scalar functions."""
        import sys
        from types import SimpleNamespace

        matches = iter(
            [
                (0x1000, 0),
                (0xFFFFFFFFFFFFFFFF, 0),
            ]
        )

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1]),
            ),
            bin_search=lambda *a: next(matches),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
            get_cmt=lambda ea, r: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_ida", SimpleNamespace(
            inf_get_min_ea=lambda: 0,
            inf_get_max_ea=lambda: 0x10000,
            inf_get_procname=lambda: "arm",
            inf_is_64bit=lambda: True,
            inf_is_be=lambda: False,
            inf_get_filetype=lambda: 0,
            inf_is_dll=lambda: False,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

        result = sql("SELECT address, func_start(address) as func FROM bin_search WHERE pattern = '7F 23 03 D5'")
        assert len(result.rows) == 1
        assert result.rows[0]["address"] == 0x1000
        # func_start returns None with default stubs
        assert result.rows[0]["func"] is None


# ---------------------------------------------------------------------------
# heads: pushdown on segment, func_ea, address range
# ---------------------------------------------------------------------------


class TestHeadsPushdown:
    def _setup_heads(
        self,
        monkeypatch: pytest.MonkeyPatch,
        calls: dict[str, int] | None = None,
    ) -> None:
        """Set up stubs with two segments and heads."""
        import sys
        from types import SimpleNamespace

        calls = {} if calls is None else calls

        # Segment stubs
        seg_text = SimpleNamespace(start_ea=0x1000, end_ea=0x2000, perm=5)
        seg_data = SimpleNamespace(start_ea=0x3000, end_ea=0x4000, perm=6)
        segs = [seg_text, seg_data]

        func = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)

        # Heads: 3 in __text (2 code, 1 data), 1 in __data
        heads_text = [0x1000, 0x1004, 0x1050]
        heads_data = [0x3000]
        all_heads = {
            (0x1000, 0x2000): heads_text,
            (0x3000, 0x4000): heads_data,
            (0x1000, 0x1100): [0x1000, 0x1004, 0x1050],  # func range overlaps
        }

        # fmt: off
        flags_map = {
            0x1000: 0x600,   # FF_CODE
            0x1004: 0x600,   # FF_CODE
            0x1050: 0x400,   # FF_DATA
            0x3000: 0x400,   # FF_DATA
        }
        # fmt: on
        size_map = {0x1000: 4, 0x1004: 4, 0x1050: 8, 0x3000: 16}

        def bump(name: str) -> None:
            calls[name] = calls.get(name, 0) + 1

        def fake_heads(start, end):
            key = (start, end)
            if key in all_heads:
                return iter(all_heads[key])
            # Range query: filter all heads
            result = []
            for ea_list in [heads_text, heads_data]:
                for ea in ea_list:
                    if start <= ea < end:
                        result.append(ea)
            return iter(result)

        def fake_getseg(ea):
            bump("getseg")
            if 0x1000 <= ea < 0x2000:
                return seg_text
            if 0x3000 <= ea < 0x4000:
                return seg_data
            return None

        def fake_get_segm_name(seg):
            bump("get_segm_name")
            if seg is seg_text or seg.start_ea == 0x1000:
                return "__text"
            if seg is seg_data or seg.start_ea == 0x3000:
                return "__data"
            return ""

        def fake_get_func(ea):
            bump("get_func")
            return func if 0x1000 <= ea < 0x1100 else None

        def fake_get_flags(ea):
            bump("get_flags")
            return flags_map.get(ea, 0)

        def fake_get_item_size(ea):
            bump("get_item_size")
            return size_map.get(ea, 1)

        # fmt: off
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([0x1000, 0x3000]),
            Heads=fake_heads,
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))
        monkeypatch.setitem(sys.modules, "ida_segment", SimpleNamespace(
            getseg=fake_getseg,
            get_segm_qty=lambda: 2,
            getnseg=lambda i: segs[i] if i < 2 else None,
            get_segm_name=fake_get_segm_name,
            get_segm_class=lambda s: "",
        ))
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=fake_get_func,
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(
            get_cmt=lambda ea, r: None,
            get_flags=fake_get_flags,
            is_code=lambda f: (f & 0x600) == 0x600,
            is_data=lambda f: (f & 0x600) == 0x400,
            is_strlit=lambda f: False,
            is_struct=lambda f: False,
            is_align=lambda f: False,
            is_unknown=lambda f: (f & 0x600) == 0,
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1] if pat else None),
            ),
            bin_search=lambda *a: (0xFFFFFFFFFFFFFFFF, 0),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
        ))
        monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
            get_func_name=lambda ea: "",
            print_insn_mnem=lambda ea: "",
            GetDisasm=lambda ea: "",
            get_item_size=fake_get_item_size,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

    def test_full_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_heads(monkeypatch)
        result = sql("SELECT address, type, segment FROM heads")
        assert len(result.rows) == 4

    def test_segment_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_heads(monkeypatch)
        result = sql("SELECT address, type FROM heads WHERE segment = '__text'")
        assert len(result.rows) == 3
        types = [r["type"] for r in result.rows]
        assert types.count("code") == 2
        assert types.count("data") == 1

    def test_func_ea_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_heads(monkeypatch)
        result = sql("SELECT address, type FROM heads WHERE func_ea = 0x1000")
        # All 3 __text heads are within func range
        assert len(result.rows) == 3

    def test_address_range_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_heads(monkeypatch)
        result = sql("SELECT address, type FROM heads WHERE address >= 0x1000 AND address <= 0x1004")
        assert len(result.rows) == 2

    def test_orphan_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Core use case: find code not in any function."""
        self._setup_heads(monkeypatch)
        result = sql("SELECT address FROM heads WHERE type = 'code' AND func_ea IS NULL")
        # Both code heads are in the function (0x1000-0x1100)
        assert len(result.rows) == 0

    def test_segment_not_found_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_heads(monkeypatch)
        result = sql("SELECT * FROM heads WHERE segment = '__nosuch'")
        assert result.rows == []

    def test_count_avoids_per_row_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, int] = {}
        self._setup_heads(monkeypatch, calls)
        result = sql("SELECT count(*) AS cnt FROM heads")
        assert result.rows[0]["cnt"] == 4
        assert calls.get("get_flags", 0) == 0
        assert calls.get("get_item_size", 0) == 0
        assert calls.get("get_func", 0) == 0

    def test_segment_address_scan_avoids_expensive_columns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, int] = {}
        self._setup_heads(monkeypatch, calls)
        result = sql("SELECT address FROM heads WHERE segment = '__text'")
        assert len(result.rows) == 3
        assert calls.get("get_flags", 0) == 0
        assert calls.get("get_item_size", 0) == 0
        assert calls.get("get_func", 0) == 0


# ---------------------------------------------------------------------------
# blocks + cfg_edges: basic blocks and control flow graph
# ---------------------------------------------------------------------------


class TestBlocksAndCfgEdges:
    """Tests for blocks and cfg_edges tables (shared stub setup)."""

    def _setup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up stubs with two functions, blocks, and edges.

        Function 0x1000 (3 blocks):
          block_a (0x1000-0x1040) -> block_b (flow)
          block_b (0x1040-0x1080) -> block_c (true), block_a (false)
          block_c (0x1080-0x1100) -> (no successors, return)

        Function 0x2000 (2 blocks):
          block_d (0x2000-0x2040) -> block_e (flow)
          block_e (0x2040-0x2080) -> (no successors, return)
        """
        func1 = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
        func2 = SimpleNamespace(start_ea=0x2000, end_ea=0x2080)

        # Build blocks with succs() for cfg_edges
        block_a = SimpleNamespace(start_ea=0x1000, end_ea=0x1040)
        block_b = SimpleNamespace(start_ea=0x1040, end_ea=0x1080)
        block_c = SimpleNamespace(start_ea=0x1080, end_ea=0x1100)
        block_d = SimpleNamespace(start_ea=0x2000, end_ea=0x2040)
        block_e = SimpleNamespace(start_ea=0x2040, end_ea=0x2080)

        # Wire up successors
        # fmt: off
        block_a.succs = lambda: iter([block_b])          # flow
        block_b.succs = lambda: iter([block_c, block_a]) # true, false
        block_c.succs = lambda: iter([])                 # return
        block_d.succs = lambda: iter([block_e])          # flow
        block_e.succs = lambda: iter([])                 # return
        # fmt: on

        flow_charts = {
            0x1000: [block_a, block_b, block_c],
            0x2000: [block_d, block_e],
        }

        def fake_get_func(ea):
            if func1.start_ea <= ea < func1.end_ea:
                return func1
            if func2.start_ea <= ea < func2.end_ea:
                return func2
            return None

        def fake_flow_chart(func, flags=0):
            return iter(flow_charts.get(func.start_ea, []))

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
            get_func=fake_get_func,
            get_func_cmt=lambda f, r: None,
        ))
        monkeypatch.setitem(sys.modules, "ida_gdl", SimpleNamespace(
            FlowChart=fake_flow_chart,
            FC_NOEXT=0x0002,
        ))
        monkeypatch.setitem(sys.modules, "idautils", SimpleNamespace(
            Functions=lambda: iter([0x1000, 0x2000]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

    # -- blocks --

    def test_blocks_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        result = sql("SELECT * FROM blocks WHERE func_ea = 0x1000")
        assert len(result.rows) == 3
        assert result.rows[0]["start_ea"] == 0x1000
        assert result.rows[0]["end_ea"] == 0x1040
        assert result.rows[0]["size"] == 0x40

    def test_blocks_second_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        result = sql("SELECT * FROM blocks WHERE func_ea = 0x2000")
        assert len(result.rows) == 2

    def test_blocks_no_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        result = sql("SELECT * FROM blocks WHERE func_ea = 0xDEAD")
        assert result.rows == []

    def test_blocks_requires_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        with pytest.raises(Exception, match="requires WHERE func_ea"):
            sql("SELECT * FROM blocks")

    # -- cfg_edges --

    def test_edges_flow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Single-successor block produces a 'flow' edge."""
        self._setup(monkeypatch)
        result = sql("SELECT * FROM cfg_edges WHERE func_ea = 0x1000 AND src_block = 0x1000")
        assert len(result.rows) == 1
        assert result.rows[0]["dst_block"] == 0x1040
        assert result.rows[0]["edge_type"] == "flow"

    def test_edges_conditional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two-successor block produces 'true' and 'false' edges."""
        self._setup(monkeypatch)
        result = sql("SELECT dst_block, edge_type FROM cfg_edges WHERE func_ea = 0x1000 AND src_block = 0x1040")
        assert len(result.rows) == 2
        assert result.rows[0]["edge_type"] == "true"
        assert result.rows[0]["dst_block"] == 0x1080
        assert result.rows[1]["edge_type"] == "false"
        assert result.rows[1]["dst_block"] == 0x1000

    def test_edges_return_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Block with no successors produces no edges."""
        self._setup(monkeypatch)
        result = sql("SELECT * FROM cfg_edges WHERE func_ea = 0x1000 AND src_block = 0x1080")
        assert result.rows == []

    def test_edges_all_for_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Total edge count for func 0x1000: 1 (flow) + 2 (cond) + 0 (ret) = 3."""
        self._setup(monkeypatch)
        result = sql("SELECT * FROM cfg_edges WHERE func_ea = 0x1000")
        assert len(result.rows) == 3

    def test_edges_simple_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """func 0x2000: 1 flow edge, 0 from return block."""
        self._setup(monkeypatch)
        result = sql("SELECT * FROM cfg_edges WHERE func_ea = 0x2000")
        assert len(result.rows) == 1
        assert result.rows[0]["edge_type"] == "flow"

    def test_edges_no_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        result = sql("SELECT * FROM cfg_edges WHERE func_ea = 0xDEAD")
        assert result.rows == []

    def test_edges_requires_pushdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup(monkeypatch)
        with pytest.raises(Exception, match="requires WHERE func_ea"):
            sql("SELECT * FROM cfg_edges")


# ---------------------------------------------------------------------------
# entries: export/entry points
# ---------------------------------------------------------------------------


class TestEntries:
    def _setup_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up stubs with entry points."""
        _entries = [
            (0, 0x1000, "_main"),
            (1, 0x2000, "_start"),
            (2, 0x3000, ""),
        ]

        def get_entry_qty():
            return len(_entries)

        def get_entry_ordinal(i):
            return _entries[i][0]

        def get_entry(ordinal):
            return _entries[ordinal][1]

        def get_entry_name(ordinal):
            return _entries[ordinal][2]

        # fmt: off
        monkeypatch.setitem(sys.modules, "ida_entry", SimpleNamespace(
            get_entry_qty=get_entry_qty,
            get_entry_ordinal=get_entry_ordinal,
            get_entry=get_entry,
            get_entry_name=get_entry_name,
        ))

        # fmt: on
        from ida_bridge.sql.db import reset_db

        reset_db()

    def test_all_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_entries(monkeypatch)
        result = sql("SELECT * FROM entries")
        assert len(result.rows) == 3
        assert result.rows[0]["ordinal"] == 0
        assert result.rows[0]["address"] == 0x1000
        assert result.rows[0]["name"] == "_main"

    def test_entry_with_empty_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._setup_entries(monkeypatch)
        result = sql("SELECT name FROM entries WHERE ordinal = 2")
        assert result.rows[0]["name"] == ""
