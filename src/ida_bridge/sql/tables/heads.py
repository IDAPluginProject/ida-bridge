"""Heads virtual table: per-address item map of the IDB."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .base import (
    SQLITE_INDEX_CONSTRAINT_GE,
    SQLITE_INDEX_CONSTRAINT_LE,
    BaseCursor,
    ColumnSpec,
    ConstraintArgSpec,
    ConstraintPlanSpec,
    apply_schema_specs,
    find_eq_constraint,
    find_range_constraints,
    mark_constraint_used,
)

_IDX_FULL_SCAN = 0
_IDX_SEGMENT_EQ = 1
_IDX_FUNC_EA_EQ = 2
_IDX_EA_RANGE = 3

_MISSING = object()


# Item type classification from IDA flags.
_TYPE_CODE = "code"
_TYPE_STRING = "string"
_TYPE_STRUCT = "struct"
_TYPE_ALIGN = "align"
_TYPE_DATA = "data"
_TYPE_UNKNOWN = "unknown"


def _item_type(flags_mod: Any, flags: int) -> str:
    """Classify an IDA item by its flags."""
    if flags_mod.is_code(flags):
        return _TYPE_CODE
    if flags_mod.is_strlit(flags):
        return _TYPE_STRING
    if flags_mod.is_struct(flags):
        return _TYPE_STRUCT
    if flags_mod.is_align(flags):
        return _TYPE_ALIGN
    if flags_mod.is_data(flags):
        return _TYPE_DATA
    return _TYPE_UNKNOWN


class HeadsModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True, rowid=True),
        "size": ColumnSpec(hex=True),
        "func_ea": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, size INTEGER, type TEXT, segment TEXT, func_ea INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, HeadsCursor, table_name=tablename)
        return schema, HeadsTable()

    Connect = Create


class HeadsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        # Segment name EQ (col 3)
        seg_idx = find_eq_constraint(ii, 3)
        if seg_idx is not None:
            mark_constraint_used(ii, seg_idx, 1)
            ii.idxNum = _IDX_SEGMENT_EQ
            ii.estimatedCost = 100_000
            ii.estimatedRows = 10_000
            return True

        # func_ea EQ (col 4)
        func_idx = find_eq_constraint(ii, 4)
        if func_idx is not None:
            mark_constraint_used(ii, func_idx, 1)
            ii.idxNum = _IDX_FUNC_EA_EQ
            ii.estimatedCost = 1_000
            ii.estimatedRows = 100
            return True

        # Address range (col 0)
        lower_idx, upper_idx = find_range_constraints(ii, 0)
        if lower_idx is not None and upper_idx is not None:
            lower_op = ii.get_aConstraint_op(lower_idx)
            upper_op = ii.get_aConstraint_op(upper_idx)
            mark_constraint_used(ii, lower_idx, 1)
            mark_constraint_used(ii, upper_idx, 2)
            ii.idxNum = _IDX_EA_RANGE
            ii.idxStr = f"{lower_op},{upper_op}"
            ii.estimatedCost = 10_000
            ii.estimatedRows = 1_000
            return True

        # Full scan
        ii.idxNum = _IDX_FULL_SCAN
        ii.estimatedCost = 1_000_000_000
        ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "HeadsCursor":
        return HeadsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class HeadsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_SEGMENT_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("segment"),
        )),
        _IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("func_ea", u64=True),
        )),
        _IDX_EA_RANGE: ConstraintPlanSpec(args=(
            ConstraintArgSpec("lower", u64=True, what="heads.address lower bound"),
            ConstraintArgSpec("upper", u64=True, what="heads.address upper bound"),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_SEGMENT_EQ:
            self._set_iter(_heads_in_segment(str(args["segment"])))
        elif indexnum == _IDX_FUNC_EA_EQ:
            self._set_iter(_heads_in_func(args["func_ea"]))
        elif indexnum == _IDX_EA_RANGE:
            lower_val = args["lower"]
            upper_val = args["upper"]
            ops = indexstring.split(",") if indexstring else []
            lower_op = int(ops[0]) if len(ops) > 0 else SQLITE_INDEX_CONSTRAINT_GE
            upper_op = int(ops[1]) if len(ops) > 1 else SQLITE_INDEX_CONSTRAINT_LE
            start = lower_val if lower_op == SQLITE_INDEX_CONSTRAINT_GE else lower_val + 1
            end = upper_val + 1 if upper_op == SQLITE_INDEX_CONSTRAINT_LE else upper_val
            self._set_iter(_heads_in_range(start, end))
        else:
            self._set_iter(_heads_all())

    def _column_value(self, number: int) -> Any:
        if self._current is None:
            return None

        row = self._current
        if number == 0:
            return row.ea
        if number == 1:
            return row.item_size()
        if number == 2:
            return row.item_type()
        if number == 3:
            return row.segment_name()
        if number == 4:
            return row.func_ea()
        msg = f"unknown heads column index: {number}"
        raise IndexError(msg)


@dataclass
class _HeadRow:
    ea: int
    _flags: object = _MISSING
    _size: object = _MISSING
    _segment_name: object = _MISSING
    _func_ea: object = _MISSING

    def flags(self) -> int:
        if self._flags is _MISSING:
            import ida_bytes

            self._flags = int(ida_bytes.get_flags(self.ea))
        return int(self._flags)

    def item_size(self) -> int:
        if self._size is _MISSING:
            import idc

            self._size = int(idc.get_item_size(self.ea))
        return int(self._size)

    def item_type(self) -> str:
        import ida_bytes

        return _item_type(ida_bytes, self.flags())

    def segment_name(self) -> str:
        if self._segment_name is _MISSING:
            import ida_segment

            seg = ida_segment.getseg(self.ea)
            self._segment_name = ida_segment.get_segm_name(seg) if seg else ""
        return str(self._segment_name)

    def func_ea(self) -> int | None:
        if self._func_ea is _MISSING:
            import ida_funcs

            func = ida_funcs.get_func(self.ea)
            self._func_ea = int(func.start_ea) if func else None
        return self._func_ea if self._func_ea is None else int(self._func_ea)


def _heads_in_segment(seg_name: str) -> Iterator[_HeadRow]:
    """Yield heads in a segment identified by name."""
    import ida_segment
    import idautils

    # Find the segment by name.
    seg = None
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s and ida_segment.get_segm_name(s) == seg_name:
            seg = s
            break
    if seg is None:
        return

    for ea in idautils.Heads(seg.start_ea, seg.end_ea):
        yield _HeadRow(ea=int(ea), _segment_name=seg_name)


def _heads_in_func(func_ea: int) -> Iterator[_HeadRow]:
    """Yield heads within a function's address range."""
    import ida_funcs
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        yield _HeadRow(ea=int(ea), _func_ea=int(func.start_ea))


def _heads_in_range(start: int, end: int) -> Iterator[_HeadRow]:
    """Yield heads in an address range [start, end)."""
    import idautils

    for ea in idautils.Heads(start, end):
        yield _HeadRow(ea=int(ea))


def _heads_all() -> Iterator[_HeadRow]:
    """Yield all heads in the IDB."""
    import ida_segment
    import idautils

    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            yield _HeadRow(ea=int(ea), _segment_name=seg_name)


ALL_TABLES: list[tuple[type, str]] = [
    (HeadsModule, "heads"),
]
