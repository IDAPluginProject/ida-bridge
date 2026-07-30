"""Base classes and helpers for APSW virtual table implementations."""

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import apsw

from ..u64 import decode_sql_u64_input, encode_sql_u64

# SQLite index constraint opcodes (from sqlite3.h)
SQLITE_INDEX_CONSTRAINT_EQ = 2
SQLITE_INDEX_CONSTRAINT_GT = 4
SQLITE_INDEX_CONSTRAINT_LE = 8
SQLITE_INDEX_CONSTRAINT_LT = 16
SQLITE_INDEX_CONSTRAINT_GE = 32


@dataclass(frozen=True)
class ColumnSpec:
    """Describe per-column formatting, rowid, and write semantics.

    ``writable`` is the whole write contract: on a writable table every column
    not marked ``writable`` -- data or identity -- is reported as unchanged
    during an UPDATE, and assigning it raises (see ``_no_change_columns`` and
    ``reject_readonly_update``). ``rowid`` marks the column SQLite's rowid is
    taken from; write handlers recover row identity from the rowid, never from
    the assigned ``fields``.
    """

    hex: bool = False
    u64: bool = False
    rowid: bool = False
    writable: bool = False


@dataclass(frozen=True)
class ConstraintArgSpec:
    """Describe one Filter argv slot for a chosen query plan."""

    name: str
    u64: bool = False
    what: str | None = None


@dataclass(frozen=True)
class ConstraintPlanSpec:
    """Describe constraint argv decoding for one idxNum plan."""

    args: tuple[ConstraintArgSpec, ...] = ()


def find_eq_constraint(ii: apsw.IndexInfo, col_index: int) -> int | None:
    """Find a usable EQ constraint on *col_index*. Returns constraint index or None."""
    for i in range(ii.nConstraint):
        if (
            ii.get_aConstraint_iColumn(i) == col_index
            and ii.get_aConstraint_op(i) == SQLITE_INDEX_CONSTRAINT_EQ
            and ii.get_aConstraint_usable(i)
        ):
            return i
    return None


def find_range_constraints(ii: apsw.IndexInfo, col_index: int) -> tuple[int | None, int | None]:
    """Find usable GE/GT and LE/LT constraints on *col_index*.

    Returns (lower_idx, upper_idx) -- constraint indices or None.
    """
    lower = None
    upper = None
    for i in range(ii.nConstraint):
        if ii.get_aConstraint_iColumn(i) != col_index:
            continue
        if not ii.get_aConstraint_usable(i):
            continue
        op = ii.get_aConstraint_op(i)
        if op in (SQLITE_INDEX_CONSTRAINT_GE, SQLITE_INDEX_CONSTRAINT_GT):
            lower = i
        elif op in (SQLITE_INDEX_CONSTRAINT_LE, SQLITE_INDEX_CONSTRAINT_LT):
            upper = i
    return lower, upper


def mark_constraint_used(ii: apsw.IndexInfo, constraint_idx: int, argv_index: int) -> None:
    """Mark a constraint as handled and tell SQLite to omit its own check."""
    ii.set_aConstraintUsage_argvIndex(constraint_idx, argv_index)
    ii.set_aConstraintUsage_omit(constraint_idx, True)


def hex_column_names(column_specs: Mapping[str, ColumnSpec]) -> frozenset[str]:
    """Return columns that should be hex-formatted in transport."""
    return frozenset(name for name, spec in column_specs.items() if spec.hex)


def u64_column_names(column_specs: Mapping[str, ColumnSpec]) -> frozenset[str]:
    """Return columns that use uint64 boundary encoding."""
    return frozenset(name for name, spec in column_specs.items() if spec.u64)


def u64_column_specs(
    schema: str,
    column_specs: Mapping[str, ColumnSpec],
) -> tuple[tuple[int, str], ...]:
    """Return schema indexes for columns marked as uint64 in metadata."""
    column_names = _schema_column_names(schema)
    names = set(u64_column_names(column_specs))
    return tuple((i, name) for i, name in enumerate(column_names) if name in names)


def rowid_column_spec(
    schema: str,
    column_specs: Mapping[str, ColumnSpec],
) -> tuple[int, str] | None:
    """Return the schema index/name for the column marked as rowid."""
    rowid_names = [name for name, spec in column_specs.items() if spec.rowid]
    if not rowid_names:
        return None
    if len(rowid_names) != 1:
        joined = ", ".join(sorted(rowid_names))
        msg = f"expected exactly one rowid column, got: {joined}"
        raise ValueError(msg)

    rowid_name = rowid_names[0]
    for i, name in enumerate(_schema_column_names(schema)):
        if name == rowid_name:
            return (i, name)

    msg = f"rowid column {rowid_name!r} is not present in schema"
    raise ValueError(msg)


def apply_schema_specs(
    schema: str,
    column_specs: Mapping[str, ColumnSpec],
    *targets: type[Any],
    table_name: str,
) -> None:
    """Apply derived schema metadata to cursor/table classes."""
    u64_specs = u64_column_specs(schema, column_specs)
    rowid_spec = rowid_column_spec(schema, column_specs)
    column_names = _schema_column_names(schema)
    no_change_columns = _no_change_columns(column_names, column_specs)
    for target in targets:
        target.TABLE_NAME = table_name
        target.U64_COLUMN_SPECS = u64_specs
        target.COLUMN_NAMES = column_names
        target.NO_CHANGE_COLUMNS = no_change_columns
        target.ROWID_COLUMN_SPEC = rowid_spec


def _no_change_columns(
    column_names: Sequence[str],
    column_specs: Mapping[str, ColumnSpec],
) -> frozenset[int]:
    """Return schema indexes for every non-writable column of a writable table.

    Empty for read-only tables (no writable column). Identity columns are
    included: handlers recover identity from the rowid, so an identity value in
    ``fields`` can only be a user assignment, which must be rejected.
    """
    writable = {name for name, spec in column_specs.items() if spec.writable}
    if not writable:
        return frozenset()
    return frozenset(i for i, name in enumerate(column_names) if name not in writable)


class SchemaSpecsBound(Protocol):
    """An object ``apply_schema_specs`` has populated with derived schema metadata.

    Both the virtual-table class and its cursor satisfy this; the update helpers
    read the metadata off the bound object instead of having it re-passed.
    """

    TABLE_NAME: str
    COLUMN_NAMES: tuple[str, ...]
    NO_CHANGE_COLUMNS: frozenset[int]
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...]
    ROWID_COLUMN_SPEC: tuple[int, str] | None


def reject_readonly_update(obj: SchemaSpecsBound, fields: Sequence[Any]) -> None:
    """Raise if an UPDATE assigned a read-only column.

    Under ``use_no_change``, an unmodified read-only column arrives as
    ``apsw.no_change``; a real value means the user wrote it.
    """
    for idx in obj.NO_CHANGE_COLUMNS:
        if fields[idx] is not apsw.no_change:
            msg = f"{obj.TABLE_NAME}.{obj.COLUMN_NAMES[idx]} is read-only"
            raise ValueError(msg)


def decode_u64_update_fields(obj: SchemaSpecsBound, fields: Sequence[Any]) -> tuple[Any, ...]:
    """Decode schema-ordered uint64 write fields before update handling."""
    decoded = list(fields)
    for idx, column_name in obj.U64_COLUMN_SPECS:
        value = decoded[idx]
        if value is not None and value is not apsw.no_change:
            decoded[idx] = decode_sql_u64_input(value, what=f"{obj.TABLE_NAME}.{column_name}")
    return tuple(decoded)


def decode_constraint_arg(value: Any, spec: ConstraintArgSpec, *, table_name: str | None = None) -> Any:
    """Decode one Filter argv value according to shared boundary metadata."""
    if spec.u64:
        what = spec.what
        if what is None and table_name is not None:
            what = f"{table_name}.{spec.name} constraint"
        return decode_sql_u64_input(value, what=what or spec.name)
    return value


def _schema_column_names(schema: str) -> tuple[str, ...]:
    """Extract column names from a simple ``CREATE TABLE`` schema string."""
    start = schema.find("(")
    end = schema.rfind(")")
    if start < 0 or end <= start:
        msg = f"invalid CREATE TABLE schema: {schema!r}"
        raise ValueError(msg)

    names: list[str] = []
    for part in schema[start + 1 : end].split(","):
        token = part.strip().split()[0].strip('[]`"')
        if token:
            names.append(token)
    return tuple(names)


class BaseCursor:
    """Generator-backed cursor base class.

    Subclasses must override ``Filter``. By default ``Column`` returns
    ``self._current[number]``. Object-backed rows can override
    ``_column_value()`` instead of reimplementing ``Column()``.
    """

    TABLE_NAME: str
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ()
    ROWID_COLUMN_SPEC: tuple[int, str] | None = None
    COLUMN_NAMES: tuple[str, ...] = ()
    NO_CHANGE_COLUMNS: frozenset[int] = frozenset()
    CONSTRAINT_PLANS: dict[int, ConstraintPlanSpec] = {}

    def __init__(self) -> None:
        self._iter: Iterator[Any] = iter([])
        self._current: Any = None
        self._eof: bool = True
        self._rowid: int = -1

    def _set_iter(self, it: Iterable[Any]) -> None:
        self._iter = iter(it)
        self._rowid = -1
        self._advance()

    def _decode_constraint_args(
        self,
        indexnum: int,
        constraintargs: Sequence[Any],
    ) -> dict[str, Any]:
        plan = self.CONSTRAINT_PLANS.get(indexnum)
        if plan is None:
            if constraintargs:
                msg = f"{type(self).__name__} has no constraint plan for idxNum {indexnum}"
                raise ValueError(msg)
            return {}

        names = [spec.name for spec in plan.args]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            joined = ", ".join(duplicates)
            msg = f"{type(self).__name__} has duplicate constraint arg names for idxNum {indexnum}: {joined}"
            raise ValueError(msg)

        if len(constraintargs) != len(plan.args):
            msg = (
                f"{type(self).__name__} expected {len(plan.args)} constraint args "
                f"for idxNum {indexnum}, got {len(constraintargs)}"
            )
            raise ValueError(msg)

        return {
            spec.name: decode_constraint_arg(
                constraintargs[i],
                spec,
                table_name=self.TABLE_NAME,
            )
            for i, spec in enumerate(plan.args)
        }

    def _advance(self) -> None:
        try:
            self._current = next(self._iter)
            self._eof = False
            self._rowid += 1
        except StopIteration:
            self._eof = True

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        raise NotImplementedError

    def _column_value(self, number: int) -> Any:
        return self._current[number]

    def _is_u64_column(self, number: int) -> bool:
        return any(idx == number for idx, _name in self.U64_COLUMN_SPECS)

    def Column(self, number: int) -> Any:
        value = self._column_value(number)
        if value is not None and self._is_u64_column(number):
            return encode_sql_u64(int(value))
        return value

    def ColumnNoChange(self, number: int) -> Any:
        """Report read-only data columns as unchanged during an UPDATE.

        Active only when the table marks read-only columns (writable tables);
        otherwise returns the real value, matching pre-no_change behavior.
        """
        if number in self.NO_CHANGE_COLUMNS:
            return apsw.no_change
        return self.Column(number)

    def Eof(self) -> bool:
        return self._eof

    def Next(self) -> None:
        self._advance()

    def _rowid_value(self) -> Any:
        if self.ROWID_COLUMN_SPEC is None:
            return self._rowid
        rowid_idx, _rowid_name = self.ROWID_COLUMN_SPEC
        return self._column_value(rowid_idx)

    def Rowid(self) -> int:
        value = self._rowid_value()
        if value is None:
            return 0
        if self.ROWID_COLUMN_SPEC is not None:
            rowid_idx, _rowid_name = self.ROWID_COLUMN_SPEC
            if self._is_u64_column(rowid_idx):
                return encode_sql_u64(int(value))
        return int(value)

    def Close(self) -> None:
        pass
