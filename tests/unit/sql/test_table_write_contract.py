"""Structural write-contract invariants for virtual tables (docs/sql-interface-design.md)."""

import pytest

from tests.table_meta import TableContract, all_contracts

_CONTRACTS = all_contracts()


@pytest.fixture(params=_CONTRACTS, ids=[c.name for c in _CONTRACTS])
def contract(request: pytest.FixtureRequest) -> TableContract:
    return request.param


class TestWriteContract:
    def test_writable_table_has_rowid_mechanism(self, contract: TableContract) -> None:
        """A write locates its row by rowid, so a writable table must have one."""
        if not contract.writable_table:
            pytest.skip("read-only table")
        assert contract.has_rowid_mechanism, (
            f"{contract.name} is writable but has no rowid mechanism: "
            "designate a column with ColumnSpec(rowid=True) or override Rowid()"
        )

    def test_writable_table_declares_writable_columns(self, contract: TableContract) -> None:
        """Declaring writable columns is what makes every other column reject writes."""
        if not contract.writable_table:
            pytest.skip("read-only table")
        assert contract.writable_columns, (
            f"{contract.name} has write handlers but declares no writable=True column, "
            "so no column is protected against assignment"
        )

    def test_table_without_rowid_mechanism_is_read_only(self, contract: TableContract) -> None:
        """A sequential-counter rowid carries no identity, so it cannot locate a row."""
        if contract.has_rowid_mechanism:
            pytest.skip("table has a rowid mechanism")
        assert not contract.writable_table, (
            f"{contract.name} is writable but falls back to a sequential rowid, "
            "which carries no identity to locate the row"
        )

    def test_exactly_one_rowid_mechanism(self, contract: TableContract) -> None:
        """The two mechanisms are alternatives; both means two sources of identity."""
        assert not (contract.has_column_rowid and contract.has_custom_rowid), (
            f"{contract.name} has both a rowid column and a Rowid() override; "
            "keep the column spec and drop the override"
        )

    def test_read_only_table_declares_no_writable_columns(self, contract: TableContract) -> None:
        """A writable column with no write handler is metadata that nothing honors."""
        if contract.writable_table:
            pytest.skip("writable table")
        assert not contract.writable_columns, f"{contract.name} declares writable columns but has no write handler"
