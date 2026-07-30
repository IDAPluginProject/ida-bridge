"""Ground-truth tests for APSW/SQLite uint64 boundary behavior.

These tests document what SQLite/APSW can and cannot represent as INTEGER
values before ida-bridge applies any address/u64 policy on top.
"""

from typing import Any

import apsw
import pytest

_S64_MAX = (1 << 63) - 1
_U64_MOD = 1 << 64
_HIGH_ADDR = 0xFFFFFE0007004000
_HIGH_ADDR_2 = 0xFFFFFE0008000000
_LOW_ADDR = 0x1000


def _encode_u64_as_i64(value: int) -> int:
    """Return *value* reinterpreted as signed 64-bit."""
    return value if value <= _S64_MAX else value - _U64_MOD


class _SingleValueCursor:
    def __init__(self, value: int) -> None:
        self._value = value
        self._done = False

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        self._done = False

    def Eof(self) -> bool:
        return self._done

    def Next(self) -> None:
        self._done = True

    def Column(self, number: int) -> int:
        return self._value

    def Rowid(self) -> int:
        return 0

    def Close(self) -> None:
        pass


class _SingleValueTable:
    def __init__(self, value: int) -> None:
        self._value = value

    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1
        ii.estimatedRows = 1
        return True

    def Open(self) -> _SingleValueCursor:
        return _SingleValueCursor(self._value)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class _SingleValueModule:
    def __init__(self, value: int) -> None:
        self._value = value

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        return "CREATE TABLE x(value INTEGER)", _SingleValueTable(self._value)

    Connect = Create


def _register_single_value_vtable(db: apsw.Connection, value: int) -> None:
    """Register a one-row virtual table returning *value* from xColumn."""
    db.create_module("_single_value", _SingleValueModule(value), use_bestindex_object=True)
    db.execute("CREATE VIRTUAL TABLE t USING _single_value")


class TestApswIntegerBoundary:
    def test_bind_parameter_accepts_signed_64_max(self) -> None:
        db = apsw.Connection(":memory:")

        row = next(db.execute("SELECT ?, typeof(?)", (_S64_MAX, _S64_MAX)))

        assert row == (_S64_MAX, "integer")

    @pytest.mark.parametrize("value", [1 << 63, _HIGH_ADDR, (1 << 64) - 1])
    def test_bind_parameter_rejects_unsigned_64_above_signed_max(self, value: int) -> None:
        db = apsw.Connection(":memory:")

        with pytest.raises(OverflowError, match="int too big to convert"):
            next(db.execute("SELECT ?", (value,)))

    @pytest.mark.parametrize("value", [1 << 63, _HIGH_ADDR, (1 << 64) - 1])
    def test_scalar_function_return_rejects_unsigned_64_above_signed_max(self, value: int) -> None:
        db = apsw.Connection(":memory:")
        db.create_scalar_function("f", lambda: value, 0)

        with pytest.raises(OverflowError, match="int too big to convert"):
            next(db.execute("SELECT f()"))

    @pytest.mark.parametrize("value", [1 << 63, _HIGH_ADDR, (1 << 64) - 1])
    def test_virtual_table_column_rejects_unsigned_64_above_signed_max(self, value: int) -> None:
        db = apsw.Connection(":memory:")
        _register_single_value_vtable(db, value)

        with pytest.raises(OverflowError, match="int too big to convert"):
            next(db.execute("SELECT value FROM t"))


class TestSqliteLiteralBehavior:
    def test_high_bit_hex_literal_is_signed_integer(self) -> None:
        db = apsw.Connection(":memory:")

        row = next(db.execute("SELECT 0xfffffe0007004000, typeof(0xfffffe0007004000)"))

        assert row == (_encode_u64_as_i64(_HIGH_ADDR), "integer")

    def test_large_decimal_literal_becomes_real(self) -> None:
        db = apsw.Connection(":memory:")

        row = next(db.execute("SELECT 18446744073709551615, typeof(18446744073709551615)"))

        assert row[1] == "real"


class TestSignedReinterpretationWorkaround:
    def test_signed_reinterpretation_preserves_bits(self) -> None:
        db = apsw.Connection(":memory:")
        encoded = _encode_u64_as_i64(_HIGH_ADDR)

        row = next(db.execute("SELECT printf('0x%016llx', ?), typeof(?)", (encoded, encoded)))

        assert row == ("0xfffffe0007004000", "integer")

    def test_high_bit_hex_literal_matches_signed_encoded_value(self) -> None:
        db = apsw.Connection(":memory:")
        db.execute("CREATE TABLE t(value INTEGER)")
        db.execute("INSERT INTO t VALUES(?)", (_encode_u64_as_i64(_HIGH_ADDR),))

        row = next(db.execute("SELECT count(*) FROM t WHERE value = 0xfffffe0007004000"))

        assert row == (1,)

    def test_high_address_range_predicates_work_when_values_are_signed_encoded(self) -> None:
        db = apsw.Connection(":memory:")
        db.execute("CREATE TABLE t(value INTEGER)")
        db.execute("INSERT INTO t VALUES(?)", (_encode_u64_as_i64(_LOW_ADDR),))
        db.execute("INSERT INTO t VALUES(?)", (_encode_u64_as_i64(_HIGH_ADDR),))
        db.execute("INSERT INTO t VALUES(?)", (_encode_u64_as_i64(_HIGH_ADDR_2),))

        row = next(db.execute("SELECT count(*) FROM t WHERE value BETWEEN 0xfffffe0007000000 AND 0xfffffe0008000000"))

        assert row == (2,)

    def test_order_by_uses_signed_order_not_unsigned_order(self) -> None:
        db = apsw.Connection(":memory:")
        db.execute("CREATE TABLE t(value INTEGER)")
        for value in (_LOW_ADDR, _HIGH_ADDR, _HIGH_ADDR_2):
            db.execute("INSERT INTO t VALUES(?)", (_encode_u64_as_i64(value),))

        rows = list(db.execute("SELECT printf('0x%016llx', value) FROM t ORDER BY value"))

        assert rows == [
            ("0xfffffe0007004000",),
            ("0xfffffe0008000000",),
            ("0x0000000000001000",),
        ]
