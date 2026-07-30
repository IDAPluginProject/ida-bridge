"""Analysis virtual tables with constraint pushdown: xrefs, comments, instructions."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ..rowid import pack_rowid, unpack_rowid
from .base import (
    SQLITE_INDEX_CONSTRAINT_GE,
    SQLITE_INDEX_CONSTRAINT_LE,
    BaseCursor,
    ColumnSpec,
    ConstraintArgSpec,
    ConstraintPlanSpec,
    apply_schema_specs,
    decode_u64_update_fields,
    find_eq_constraint,
    find_range_constraints,
    mark_constraint_used,
    reject_readonly_update,
)

# Index numbers for pushdown dispatch
_IDX_FULL_SCAN = 0
_IDX_XREF_FROM = 1
_IDX_XREF_TO = 2
_IDX_EA_EQ = 3
_IDX_FUNC_EA_EQ = 4
_IDX_EA_RANGE = 5
_IDX_XREF_FROM_FUNC = 6

# Row types -- (from_ea, to_ea, from_func, type, type_name, is_code)
type XrefRow = tuple[int, int, int, int, str | None, int]
type CommentRow = tuple[int, str, int]

_MISSING = object()


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------


class XrefsModule:
    COLUMN_SPECS = {
        "from_ea": ColumnSpec(hex=True, u64=True),
        "to_ea": ColumnSpec(hex=True, u64=True),
        "from_func": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(from_ea INTEGER, to_ea INTEGER, from_func INTEGER, type INTEGER, type_name TEXT, is_code INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, XrefsCursor, table_name=tablename)
        return schema, XrefsTable()

    Connect = Create


class XrefsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        # Check for EQ on from_ea (col 0), to_ea (col 1), or from_func (col 2)
        from_idx = find_eq_constraint(ii, 0)
        to_idx = find_eq_constraint(ii, 1)
        from_func_idx = find_eq_constraint(ii, 2)

        if to_idx is not None:
            mark_constraint_used(ii, to_idx, 1)
            ii.idxNum = _IDX_XREF_TO
            ii.estimatedCost = 10
            ii.estimatedRows = 5
        elif from_idx is not None:
            mark_constraint_used(ii, from_idx, 1)
            ii.idxNum = _IDX_XREF_FROM
            ii.estimatedCost = 10
            ii.estimatedRows = 5
        elif from_func_idx is not None:
            mark_constraint_used(ii, from_func_idx, 1)
            ii.idxNum = _IDX_XREF_FROM_FUNC
            ii.estimatedCost = 100
            ii.estimatedRows = 20
        else:
            ii.idxNum = _IDX_FULL_SCAN
            ii.estimatedCost = 1_000_000
            ii.estimatedRows = 100_000
        return True

    def Open(self) -> "XrefsCursor":
        return XrefsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class XrefsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_XREF_TO: ConstraintPlanSpec(args=(
            ConstraintArgSpec("to_ea", u64=True),
        )),
        _IDX_XREF_FROM: ConstraintPlanSpec(args=(
            ConstraintArgSpec("from_ea", u64=True),
        )),
        _IDX_XREF_FROM_FUNC: ConstraintPlanSpec(args=(
            ConstraintArgSpec("from_func", u64=True),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_XREF_TO:
            self._set_iter(_xrefs_to(args["to_ea"]))
        elif indexnum == _IDX_XREF_FROM:
            self._set_iter(_xrefs_from(args["from_ea"]))
        elif indexnum == _IDX_XREF_FROM_FUNC:
            self._set_iter(_xrefs_from_func(args["from_func"]))
        else:
            self._set_iter(_xrefs_all())


def _get_from_func(ea: int) -> int:
    """Return start EA of the function containing *ea*, or 0."""
    import ida_funcs

    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else 0


# IDA xref type codes (SDK xref.hpp). Disjoint ranges keyed by is_code:
# data (dref_t) 0-6, code (cref_t) 16-21. type_name collapses far/near (inter/intra-segment)
# into the semantic kind -- call/jump -- since that is what RE tasks care about; the raw `type`
# column keeps the far/near split. fl_USobsolete (20) is unmapped -> NULL.
_XREF_TYPE_NAMES: dict[int, str] = {
    0: "unknown",
    1: "offset",
    2: "write",
    3: "read",
    4: "text",
    5: "info",
    6: "enum",
    16: "call",  # fl_CF call far
    17: "call",  # fl_CN call near
    18: "jump",  # fl_JF jump far
    19: "jump",  # fl_JN jump near
    21: "flow",
}
_XREF_MASK = 0x1F  # strips USER/TAIL/BASE bits, leaving the cref/dref type


def _xref_type_name(xtype: int) -> str | None:
    """Readable name for an IDA xref type code, or None if unmapped."""
    return _XREF_TYPE_NAMES.get(xtype & _XREF_MASK)


def _make_xref_row(frm: int, to: int, xtype: int, iscode: int) -> XrefRow:
    """Build a row: (from_ea, to_ea, from_func, type, type_name, is_code)."""
    return (frm, to, _get_from_func(frm), xtype, _xref_type_name(xtype), iscode)


def _xrefs_to(ea: int) -> Iterator[XrefRow]:
    import idautils

    seen: set[XrefRow] = set()
    for xref in idautils.XrefsTo(ea, 0):
        row = _make_xref_row(int(xref.frm), int(xref.to), int(xref.type), int(xref.iscode))
        if row not in seen:
            seen.add(row)
            yield row


def _xrefs_from(ea: int) -> Iterator[XrefRow]:
    import idautils

    seen: set[XrefRow] = set()
    for xref in idautils.XrefsFrom(ea, 0):
        row = _make_xref_row(int(xref.frm), int(xref.to), int(xref.type), int(xref.iscode))
        if row not in seen:
            seen.add(row)
            yield row


def _xrefs_from_func(func_ea: int) -> Iterator[XrefRow]:
    """All xrefs originating from within a function (pushdown on from_func)."""
    import ida_funcs
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return
    seen: set[XrefRow] = set()
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(int(ea), 0):
            row: XrefRow = (
                int(xref.frm),
                int(xref.to),
                int(func.start_ea),
                int(xref.type),
                _xref_type_name(int(xref.type)),
                int(xref.iscode),
            )
            if row not in seen:
                seen.add(row)
                yield row


def _xrefs_all() -> Iterator[XrefRow]:
    import ida_segment
    import idautils

    seen: set[XrefRow] = set()
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            yield from _xrefs_from_deduped(int(ea), seen)


def _xrefs_from_deduped(ea: int, seen: set[XrefRow]) -> Iterator[XrefRow]:
    import idautils

    for xref in idautils.XrefsFrom(ea, 0):
        row = _make_xref_row(int(xref.frm), int(xref.to), int(xref.type), int(xref.iscode))
        if row not in seen:
            seen.add(row)
            yield row


# ---------------------------------------------------------------------------
# comments
# ---------------------------------------------------------------------------


# One payload bit: the repeatable flag.
_COMMENT_PAYLOAD_BITS = 1


def _decode_comment_rowid(rowid: int) -> tuple[int, bool]:
    ea, repeatable = unpack_rowid(rowid, payload_bits=_COMMENT_PAYLOAD_BITS)
    return ea, bool(repeatable)


class CommentsModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True),
        "text": ColumnSpec(writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, text TEXT, repeatable INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, CommentsCursor, CommentsTable, table_name=tablename)
        return schema, CommentsTable()

    Connect = Create


class CommentsTable:
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ()

    def BestIndexObject(self, ii: Any) -> bool:
        ea_idx = find_eq_constraint(ii, 0)
        if ea_idx is not None:
            mark_constraint_used(ii, ea_idx, 1)
            ii.idxNum = _IDX_EA_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 4
        else:
            ii.idxNum = _IDX_FULL_SCAN
            ii.estimatedCost = 1_000_000
            ii.estimatedRows = 10_000
        return True

    def Open(self) -> "CommentsCursor":
        return CommentsCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on writable column: text."""
        reject_readonly_update(self, fields)
        ea, repeatable = _decode_comment_rowid(rowid)
        new_text = fields[1]

        if new_text is None:
            return

        _set_comment(ea, str(new_text) if new_text else "", repeatable)

    def UpdateInsertRow(self, newrowid: int | None, fields: tuple[Any, ...]) -> int:
        """Handle INSERT: create an item comment.

        Required: address, text. Optional: repeatable (default 0).
        """
        fields = decode_u64_update_fields(self, fields)
        ea = fields[0]
        text = fields[1]
        repeatable = fields[2]

        if ea is None:
            msg = "comments INSERT requires address"
            raise ValueError(msg)
        if text is None or not str(text).strip():
            msg = "comments INSERT requires non-empty text"
            raise ValueError(msg)

        is_rpt = bool(repeatable) if repeatable is not None else False
        _set_comment(int(ea), str(text), is_rpt)
        return pack_rowid(int(ea), int(is_rpt), payload_bits=_COMMENT_PAYLOAD_BITS)

    def UpdateDeleteRow(self, rowid: int) -> None:
        """Handle DELETE: clear a comment."""
        ea, repeatable = _decode_comment_rowid(rowid)
        _set_comment(ea, "", repeatable)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


def _set_comment(ea: int, text: str, repeatable: bool) -> None:
    """Set or clear an item comment at *ea*."""
    import ida_bytes

    if not ida_bytes.set_cmt(ea, text, repeatable):
        msg = f"set_cmt failed at {ea:#x}"
        raise ValueError(msg)


class CommentsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("address", u64=True),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_EA_EQ:
            self._set_iter(_comments_at_ea(args["address"]))
        else:
            self._set_iter(_comments_all())

    def Rowid(self) -> int:
        return pack_rowid(self._current[0], self._current[2], payload_bits=_COMMENT_PAYLOAD_BITS)


def _comments_at_ea(ea: int) -> Iterator[CommentRow]:
    import ida_bytes

    for repeatable in (False, True):
        text = ida_bytes.get_cmt(ea, repeatable)
        if text:
            yield (int(ea), text, int(repeatable))


def _comments_all() -> Iterator[CommentRow]:
    import ida_bytes
    import ida_segment
    import idautils

    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            for repeatable in (False, True):
                text = ida_bytes.get_cmt(ea, repeatable)
                if text:
                    yield (int(ea), text, int(repeatable))


# ---------------------------------------------------------------------------
# instructions
# ---------------------------------------------------------------------------


class InstructionsModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True, rowid=True),
        "size": ColumnSpec(hex=True),
        "func_ea": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, mnemonic TEXT, disasm TEXT, size INTEGER, func_ea INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, InstructionsCursor, table_name=tablename)
        return schema, InstructionsTable()

    Connect = Create


class InstructionsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        # EQ on ea (col 0)
        ea_idx = find_eq_constraint(ii, 0)
        if ea_idx is not None:
            mark_constraint_used(ii, ea_idx, 1)
            ii.idxNum = _IDX_EA_EQ
            ii.estimatedCost = 1
            ii.estimatedRows = 1
            return True

        # EQ on func_ea (col 4)
        func_idx = find_eq_constraint(ii, 4)
        if func_idx is not None:
            mark_constraint_used(ii, func_idx, 1)
            ii.idxNum = _IDX_FUNC_EA_EQ
            ii.estimatedCost = 100
            ii.estimatedRows = 100
            return True

        # Range on ea (col 0)
        lower_idx, upper_idx = find_range_constraints(ii, 0)
        if lower_idx is not None and upper_idx is not None:
            lower_op = ii.get_aConstraint_op(lower_idx)
            upper_op = ii.get_aConstraint_op(upper_idx)
            mark_constraint_used(ii, lower_idx, 1)
            mark_constraint_used(ii, upper_idx, 2)
            # Encode ops in idxStr so Filter can adjust bounds
            ii.idxNum = _IDX_EA_RANGE
            ii.idxStr = f"{lower_op},{upper_op}"
            ii.estimatedCost = 100
            ii.estimatedRows = 100
            return True

        # No usable constraint -- full scan, very expensive
        ii.idxNum = _IDX_FULL_SCAN
        ii.estimatedCost = 1_000_000_000
        ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "InstructionsCursor":
        return InstructionsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class InstructionsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("address", u64=True),
        )),
        _IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("func_ea", u64=True),
        )),
        _IDX_EA_RANGE: ConstraintPlanSpec(args=(
            ConstraintArgSpec("lower", u64=True, what="instructions.address lower bound"),
            ConstraintArgSpec("upper", u64=True, what="instructions.address upper bound"),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_EA_EQ:
            self._set_iter(_instructions_at_ea(args["address"]))
        elif indexnum == _IDX_FUNC_EA_EQ:
            self._set_iter(_instructions_in_func(args["func_ea"]))
        elif indexnum == _IDX_EA_RANGE:
            lower_val = args["lower"]
            upper_val = args["upper"]
            # Adjust bounds: idautils.Heads(start, end) is [start, end)
            # GT -> start = val + 1, GE -> start = val
            # LT -> end = val, LE -> end = val + 1
            ops = indexstring.split(",") if indexstring else []
            lower_op = int(ops[0]) if len(ops) > 0 else SQLITE_INDEX_CONSTRAINT_GE
            upper_op = int(ops[1]) if len(ops) > 1 else SQLITE_INDEX_CONSTRAINT_LE
            start = lower_val if lower_op == SQLITE_INDEX_CONSTRAINT_GE else lower_val + 1
            end = upper_val + 1 if upper_op == SQLITE_INDEX_CONSTRAINT_LE else upper_val
            self._set_iter(_instructions_in_range(start, end))
        else:
            self._set_iter(_instructions_all())

    def _column_value(self, number: int) -> Any:
        if self._current is None:
            return None

        row = self._current
        if number == 0:
            return row.ea
        if number == 1:
            return row.mnemonic()
        if number == 2:
            return row.disasm()
        if number == 3:
            return row.size()
        if number == 4:
            return row.func_ea()
        msg = f"unknown instructions column index: {number}"
        raise IndexError(msg)


@dataclass
class _InstructionRow:
    ea: int
    _mnemonic: object = _MISSING
    _disasm: object = _MISSING
    _size: object = _MISSING
    _func_ea: object = _MISSING

    def mnemonic(self) -> str:
        if self._mnemonic is _MISSING:
            import idc

            self._mnemonic = idc.print_insn_mnem(self.ea) or ""
        return str(self._mnemonic)

    def disasm(self) -> str:
        if self._disasm is _MISSING:
            import idc

            self._disasm = idc.GetDisasm(self.ea) or ""
        return str(self._disasm)

    def size(self) -> int:
        if self._size is _MISSING:
            import ida_ua
            import idc

            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, self.ea)
            self._size = length if length > 0 else int(idc.get_item_size(self.ea))
        return int(self._size)

    def func_ea(self) -> int:
        if self._func_ea is _MISSING:
            import ida_funcs

            func = ida_funcs.get_func(self.ea)
            self._func_ea = int(func.start_ea) if func else 0
        return int(self._func_ea)


def _instructions_at_ea(ea: int) -> Iterator[_InstructionRow]:
    yield _InstructionRow(ea=int(ea))


def _instructions_in_func(func_ea: int) -> Iterator[_InstructionRow]:
    import ida_funcs
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        yield _InstructionRow(ea=int(ea), _func_ea=int(func.start_ea))


def _instructions_in_range(start: int, end: int) -> Iterator[_InstructionRow]:
    import idautils

    for ea in idautils.Heads(start, end):
        yield _InstructionRow(ea=int(ea))


def _instructions_all() -> Iterator[_InstructionRow]:
    import ida_segment
    import idautils

    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            yield _InstructionRow(ea=int(ea))


# ---------------------------------------------------------------------------
# blocks (basic blocks per function, requires func_ea pushdown)
# ---------------------------------------------------------------------------

# Row: (func_ea, start_ea, end_ea, size)
type BlockRow = tuple[int, int, int, int]

_IDX_NO_PUSH = 99


class BlocksModule:
    COLUMN_SPECS = {
        "func_ea": ColumnSpec(hex=True, u64=True),
        "start_ea": ColumnSpec(hex=True, u64=True),
        "end_ea": ColumnSpec(hex=True, u64=True),
        "size": ColumnSpec(hex=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(func_ea INTEGER, start_ea INTEGER, end_ea INTEGER, size INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, BlocksCursor, table_name=tablename)
        return schema, BlocksTable()

    Connect = Create


class BlocksTable:
    def BestIndexObject(self, ii: Any) -> bool:
        func_idx = find_eq_constraint(ii, 0)
        if func_idx is not None:
            mark_constraint_used(ii, func_idx, 1)
            ii.idxNum = _IDX_FUNC_EA_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 10
        else:
            ii.idxNum = _IDX_NO_PUSH
            ii.estimatedCost = 10_000_000_000
            ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "BlocksCursor":
        return BlocksCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class BlocksCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("func_ea", u64=True),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_FUNC_EA_EQ:
            self._set_iter(_blocks_in_func(args["func_ea"]))
        else:
            msg = "blocks table requires WHERE func_ea = <address>"
            raise ValueError(msg)


def _flowchart(func_ea: int) -> "list[Any] | None":
    """Build a FlowChart for the function at *func_ea*.

    Uses FC_NOEXT to exclude synthetic external-call nodes while still
    including all function chunks (including tail chunks from inlined code).
    Returns None if the function doesn't exist.
    """
    import ida_funcs
    import ida_gdl

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None
    return ida_gdl.FlowChart(func, flags=ida_gdl.FC_NOEXT)


def _blocks_in_func(func_ea: int) -> Iterator[BlockRow]:
    """Yield basic blocks for a single function."""
    fc = _flowchart(func_ea)
    if fc is None:
        return
    for block in fc:
        start = int(block.start_ea)
        end = int(block.end_ea)
        yield (int(func_ea), start, end, end - start)


# ---------------------------------------------------------------------------
# cfg_edges (control flow graph edges, requires func_ea pushdown)
# ---------------------------------------------------------------------------

# Row: (func_ea, src_block, dst_block, edge_type)
type CfgEdgeRow = tuple[int, int, int, str]


class CfgEdgesModule:
    COLUMN_SPECS = {
        "func_ea": ColumnSpec(hex=True, u64=True),
        "src_block": ColumnSpec(hex=True, u64=True),
        "dst_block": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(func_ea INTEGER, src_block INTEGER, dst_block INTEGER, edge_type TEXT)"
        apply_schema_specs(schema, self.COLUMN_SPECS, CfgEdgesCursor, table_name=tablename)
        return schema, CfgEdgesTable()

    Connect = Create


class CfgEdgesTable:
    def BestIndexObject(self, ii: Any) -> bool:
        func_idx = find_eq_constraint(ii, 0)
        if func_idx is not None:
            mark_constraint_used(ii, func_idx, 1)
            ii.idxNum = _IDX_FUNC_EA_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 20
        else:
            ii.idxNum = _IDX_NO_PUSH
            ii.estimatedCost = 10_000_000_000
            ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "CfgEdgesCursor":
        return CfgEdgesCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class CfgEdgesCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("func_ea", u64=True),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_FUNC_EA_EQ:
            self._set_iter(_cfg_edges_in_func(args["func_ea"]))
        else:
            msg = "cfg_edges table requires WHERE func_ea = <address>"
            raise ValueError(msg)


def _cfg_edges_in_func(func_ea: int) -> Iterator[CfgEdgeRow]:
    """Yield CFG edges for a single function.

    Edge types:
    - flow: single successor (unconditional)
    - true: first successor of a 2-way branch (IDA convention: branch taken)
    - false: second successor of a 2-way branch (fall-through)
    - switch: any successor of a 3+ way branch
    """
    fc = _flowchart(func_ea)
    if fc is None:
        return
    for block in fc:
        succs = list(block.succs())
        nsucc = len(succs)
        src = int(block.start_ea)
        for j, succ in enumerate(succs):
            dst = int(succ.start_ea)
            if nsucc == 1:
                edge_type = "flow"
            elif nsucc == 2:
                edge_type = "true" if j == 0 else "false"
            else:
                edge_type = "switch"
            yield (int(func_ea), src, dst, edge_type)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_TABLES: list[tuple[type, str]] = [
    (XrefsModule, "xrefs"),
    (CommentsModule, "comments"),
    (InstructionsModule, "instructions"),
    (BlocksModule, "blocks"),
    (CfgEdgesModule, "cfg_edges"),
]
