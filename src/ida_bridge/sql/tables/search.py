"""Binary pattern search virtual table."""

from collections.abc import Iterator
from typing import Any

from .base import (
    BaseCursor,
    ColumnSpec,
    ConstraintArgSpec,
    ConstraintPlanSpec,
    apply_schema_specs,
    find_eq_constraint,
    mark_constraint_used,
)

_IDX_NO_PUSH = 0
_IDX_PATTERN_EQ = 1

type BinSearchRow = tuple[int]


class BinSearchModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True, rowid=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, pattern TEXT HIDDEN)"
        apply_schema_specs(schema, self.COLUMN_SPECS, BinSearchCursor, table_name=tablename)
        return schema, BinSearchTable()

    Connect = Create


class BinSearchTable:
    def BestIndexObject(self, ii: Any) -> bool:
        pat_idx = find_eq_constraint(ii, 1)
        if pat_idx is not None:
            mark_constraint_used(ii, pat_idx, 1)
            ii.idxNum = _IDX_PATTERN_EQ
            ii.estimatedCost = 10_000
            ii.estimatedRows = 100
            return True

        # No pattern -- reject.
        ii.idxNum = _IDX_NO_PUSH
        ii.estimatedCost = 10_000_000_000
        ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "BinSearchCursor":
        return BinSearchCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class BinSearchCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _IDX_PATTERN_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("pattern"),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_PATTERN_EQ:
            self._set_iter(_search_pattern(str(args["pattern"])))
        else:
            msg = "bin_search table requires WHERE pattern = '...'"
            raise ValueError(msg)

    def _column_value(self, number: int) -> Any:
        if number == 0:
            return self._current[0]
        # Column 1 is the HIDDEN pattern -- not meaningful per-row.
        return None


def _search_pattern(pattern: str) -> Iterator[BinSearchRow]:
    """Yield (address,) for each match of the hex byte pattern."""
    import ida_bytes
    import ida_ida

    binpat = ida_bytes.compiled_binpat_vec_t.parse(0, pattern, 16)
    if binpat is None or len(binpat) == 0:
        msg = f"invalid bin_search pattern: {pattern!r}"
        raise ValueError(msg)

    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
    start = ida_ida.inf_get_min_ea()
    end = ida_ida.inf_get_max_ea()
    ea = start

    while True:
        found_ea, _ = ida_bytes.bin_search(ea, end, binpat, flags)
        if found_ea == 0xFFFFFFFFFFFFFFFF:
            break
        yield (int(found_ea),)
        ea = found_ea + 1


ALL_TABLES: list[tuple[type, str]] = [
    (BinSearchModule, "bin_search"),
]
