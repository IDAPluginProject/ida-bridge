"""Ground-truth tests for value provenance at SQLite/APSW boundaries.

These tests document one rule we rely on in ida-bridge virtual tables:
- expression-sourced values are dynamically typed and must be validated
- row-sourced values come back in the types emitted by the vtable itself
"""

from dataclasses import dataclass
from typing import Any

import apsw

SQLITE_INDEX_CONSTRAINT_EQ = 2


class TestSqliteExpressionResultTypes:
    def test_integer_literal_returns_python_int(self) -> None:
        db = apsw.Connection(":memory:")
        row = next(db.execute("SELECT 123"))
        assert row == (123,)
        assert isinstance(row[0], int)

    def test_cast_text_returns_python_str(self) -> None:
        db = apsw.Connection(":memory:")
        row = next(db.execute("SELECT CAST(123 AS TEXT)"))
        assert row == ("123",)
        assert isinstance(row[0], str)

    def test_null_returns_python_none(self) -> None:
        db = apsw.Connection(":memory:")
        row = next(db.execute("SELECT NULL"))
        assert row == (None,)


@dataclass
class _ConstraintProbeState:
    last_args: tuple[Any, ...] | None = None


class _ConstraintProbeCursor:
    def __init__(self, state: _ConstraintProbeState) -> None:
        self._state = state
        self._done = False

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        del indexnum, indexstring
        self._state.last_args = constraintargs
        self._done = False

    def Eof(self) -> bool:
        return self._done

    def Next(self) -> None:
        self._done = True

    def Column(self, number: int) -> int:
        del number
        return 0

    def Rowid(self) -> int:
        return 1

    def Close(self) -> None:
        pass


class _ConstraintProbeTable:
    def __init__(self, state: _ConstraintProbeState) -> None:
        self._state = state

    def BestIndexObject(self, ii: Any) -> bool:
        for i in range(ii.nConstraint):
            if (
                ii.get_aConstraint_iColumn(i) == 0
                and ii.get_aConstraint_op(i) == SQLITE_INDEX_CONSTRAINT_EQ
                and ii.get_aConstraint_usable(i)
            ):
                ii.set_aConstraintUsage_argvIndex(i, 1)
                ii.set_aConstraintUsage_omit(i, True)
                break
        ii.estimatedCost = 1
        ii.estimatedRows = 1
        return True

    def Open(self) -> _ConstraintProbeCursor:
        return _ConstraintProbeCursor(self._state)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class _ConstraintProbeModule:
    def __init__(self, state: _ConstraintProbeState, schema: str) -> None:
        self._state = state
        self._schema = schema

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        del db, modulename, dbname, tablename, args
        return self._schema, _ConstraintProbeTable(self._state)

    Connect = Create


def _register_constraint_probe(db: apsw.Connection, schema: str) -> _ConstraintProbeState:
    state = _ConstraintProbeState()
    db.create_module("_constraint_probe", _ConstraintProbeModule(state, schema), use_bestindex_object=True)
    db.execute("CREATE VIRTUAL TABLE t USING _constraint_probe")
    return state


class TestScalarFunctionArgumentTypes:
    def test_scalar_function_argument_from_integer_literal_is_python_int(self) -> None:
        db = apsw.Connection(":memory:")
        seen: list[Any] = []

        def f(value: Any) -> None:
            seen.append(value)
            return None

        db.create_scalar_function("f", f, 1)
        next(db.execute("SELECT f(123)"))

        assert seen == [123]
        assert isinstance(seen[0], int)

    def test_scalar_function_argument_from_cast_text_is_python_str(self) -> None:
        db = apsw.Connection(":memory:")
        seen: list[Any] = []

        def f(value: Any) -> None:
            seen.append(value)
            return None

        db.create_scalar_function("f", f, 1)
        next(db.execute("SELECT f(CAST(123 AS TEXT))"))

        assert seen == ["123"]
        assert isinstance(seen[0], str)


class TestVirtualTableConstraintTypes:
    def test_integer_declared_column_still_receives_python_str_from_text_literal(self) -> None:
        db = apsw.Connection(":memory:")
        state = _register_constraint_probe(db, "CREATE TABLE x(v INTEGER)")

        list(db.execute("SELECT * FROM t WHERE v = '3'"))

        assert state.last_args == ("3",)
        assert isinstance(state.last_args[0], str)

    def test_text_declared_column_still_receives_python_int_from_integer_literal(self) -> None:
        db = apsw.Connection(":memory:")
        state = _register_constraint_probe(db, "CREATE TABLE x(v TEXT)")

        list(db.execute("SELECT * FROM t WHERE v = 123"))

        assert state.last_args == (123,)
        assert isinstance(state.last_args[0], int)


@dataclass
class _UpdateProbeState:
    row: tuple[Any, Any] = (1, "orig")
    last_fields: tuple[Any, ...] | None = None


class _UpdateProbeCursor:
    def __init__(self, state: _UpdateProbeState) -> None:
        self._state = state
        self._done = False

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        del indexnum, indexstring, constraintargs
        self._done = False

    def Eof(self) -> bool:
        return self._done

    def Next(self) -> None:
        self._done = True

    def Column(self, number: int) -> Any:
        return self._state.row[number]

    def Rowid(self) -> int:
        return 1

    def Close(self) -> None:
        pass


class _UpdateProbeTable:
    def __init__(self, state: _UpdateProbeState) -> None:
        self._state = state

    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1
        ii.estimatedRows = 1
        return True

    def Open(self) -> _UpdateProbeCursor:
        return _UpdateProbeCursor(self._state)

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        del rowid, newrowid
        self._state.last_fields = fields
        self._state.row = fields

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class _UpdateProbeModule:
    def __init__(self, state: _UpdateProbeState) -> None:
        self._state = state

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        del db, modulename, dbname, tablename, args
        return "CREATE TABLE x(i INTEGER, t TEXT)", _UpdateProbeTable(self._state)

    Connect = Create


def _register_update_probe(db: apsw.Connection) -> _UpdateProbeState:
    state = _UpdateProbeState()
    db.create_module("_update_probe", _UpdateProbeModule(state), use_bestindex_object=True)
    db.execute("CREATE VIRTUAL TABLE t USING _update_probe")
    return state


class TestVirtualTableUpdateTypes:
    def test_update_fields_mix_row_sourced_and_expression_sourced_values(self) -> None:
        db = apsw.Connection(":memory:")
        state = _register_update_probe(db)

        db.execute("UPDATE t SET t = 123")

        assert state.last_fields == (1, 123)
        assert isinstance(state.last_fields[0], int)
        assert isinstance(state.last_fields[1], int)

    def test_update_text_literal_delivers_python_str(self) -> None:
        db = apsw.Connection(":memory:")
        state = _register_update_probe(db)

        db.execute("UPDATE t SET t = 'x'")

        assert state.last_fields == (1, "x")
        assert isinstance(state.last_fields[0], int)
        assert isinstance(state.last_fields[1], str)

    def test_update_null_delivers_python_none(self) -> None:
        db = apsw.Connection(":memory:")
        state = _register_update_probe(db)

        db.execute("UPDATE t SET t = NULL")

        assert state.last_fields == (1, None)
        assert isinstance(state.last_fields[0], int)
        assert state.last_fields[1] is None
