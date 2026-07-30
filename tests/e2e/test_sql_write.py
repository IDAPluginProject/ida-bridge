"""Generic SQL write tests on temp IDB copies."""

from dataclasses import dataclass
import re

import pytest

from tests.e2e.conftest import GenericIdalib
from tests.fixtures.idb_discovery import default_fixture
from tests.table_meta import writable_columns, writable_tables

pytestmark = [pytest.mark.asyncio(loop_scope="module")]


@dataclass(frozen=True)
class PseudocodeTarget:
    func_ea: str
    ea: str


@dataclass(frozen=True)
class StructMemberTarget:
    type_ordinal: int
    member_index: int
    member_name: str


@dataclass(frozen=True)
class PrototypeTarget:
    func_ea: str
    name: str
    prototype: str | None


_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


async def _scratch_type(gi: GenericIdalib, declaration: str) -> int:
    r = await gi.runner.sql(f"SELECT parse_type('{declaration}') AS ordinal")
    return int(r["rows"][0]["ordinal"])


async def _assert_non_writable_columns_reject(gi: GenericIdalib, table: str, where: str) -> None:
    """Every column not declared writable must reject an UPDATE on an existing row.

    Columns come from ``PRAGMA table_info`` so the assertion follows the surface an
    agent actually sees. The probe value is irrelevant: rejection precedes any value
    decoding. Failures are collected so one run reports every offending column.
    """
    info = await gi.runner.sql(f"PRAGMA table_info({table})")
    columns = [row["name"] for row in info["rows"]]
    assert columns, f"PRAGMA table_info({table}) returned no columns"

    writable = writable_columns(table)
    checked: list[str] = []
    failures: list[str] = []

    for column in columns:
        if column in writable:
            continue
        checked.append(column)
        message = await gi.runner.sql_err(f"UPDATE {table} SET {column} = 0 WHERE {where}")
        if f"{table}.{column} is read-only" not in message:
            failures.append(f"{column}: {message}")

    assert checked, f"{table} has no non-writable columns to check"
    assert not failures, f"{table} columns did not reject a write:\n" + "\n".join(failures)


async def _stable_func_eas(generic_idalib_w: GenericIdalib, limit: int) -> list[str]:
    r = await generic_idalib_w.runner.sql(
        "SELECT start_ea FROM funcs "
        "WHERE (flags & func_flag('thunk')) = 0 AND size >= 0x10 "
        f"ORDER BY start_ea LIMIT {limit}"
    )
    return [row["start_ea"] for row in r["rows"]]


async def _func_ea(generic_idalib_w: GenericIdalib, offset: int) -> str:
    funcs = await _stable_func_eas(generic_idalib_w, offset + 1)
    if len(funcs) <= offset:
        pytest.skip(f"fixture has too few stable functions (need > {offset}, have {len(funcs)})")
    return funcs[offset]


async def _pseudocode_target(generic_idalib_w: GenericIdalib, offset: int) -> PseudocodeTarget:
    targets: list[PseudocodeTarget] = []
    for func_ea in await _stable_func_eas(generic_idalib_w, 100):
        lines = await generic_idalib_w.runner.sql(
            f"SELECT ea FROM pseudocode WHERE func_ea = {func_ea} "
            f"AND type = 'code' AND ea IS NOT NULL AND valid_placements LIKE '%semi%' LIMIT 1"
        )
        if lines["rows"]:
            targets.append(
                PseudocodeTarget(
                    func_ea=func_ea,
                    ea=lines["rows"][0]["ea"],
                )
            )
        if len(targets) > offset:
            return targets[offset]
    pytest.skip(f"fixture has too few functions with addressable pseudocode (need > {offset}, have {len(targets)})")


async def _multi_placement_target(generic_idalib_w: GenericIdalib) -> PseudocodeTarget:
    """First code line that renders both a block1 and a semi comment."""
    for func_ea in await _stable_func_eas(generic_idalib_w, 100):
        r = await generic_idalib_w.runner.sql(
            f"SELECT ea FROM pseudocode WHERE func_ea = {func_ea} "
            f"AND type = 'code' AND ea IS NOT NULL "
            f"AND valid_placements LIKE '%semi%' AND valid_placements LIKE '%block1%' LIMIT 1"
        )
        if r["rows"]:
            return PseudocodeTarget(func_ea=func_ea, ea=r["rows"][0]["ea"])
    pytest.skip("no function with a semi+block1 pseudocode line")


def _different_lvar_type(current: str) -> str:
    for candidate in ("char *", "unsigned __int64", "unsigned int", "unsigned __int8"):
        if candidate != current:
            return candidate
    raise AssertionError(f"no different lvar type candidate for {current!r}")


def _sql_literal(value: str | None) -> str:
    if value is None:
        return "NULL"
    return "'" + value.replace("'", "''") + "'"


async def _prototype_target(generic_idalib_w: GenericIdalib, offset: int) -> PrototypeTarget:
    targets: list[PrototypeTarget] = []
    funcs = await generic_idalib_w.runner.sql(
        "SELECT start_ea, name, prototype FROM funcs "
        "WHERE (flags & func_flag('thunk')) = 0 AND size >= 0x10 "
        "ORDER BY start_ea LIMIT 100"
    )
    for row in funcs["rows"]:
        name = row["name"]
        if not _C_IDENTIFIER.fullmatch(name):
            continue
        targets.append(PrototypeTarget(func_ea=row["start_ea"], name=name, prototype=row["prototype"]))
        if len(targets) > offset:
            return targets[offset]
    pytest.skip(f"fixture has too few prototype targets with C identifier names (need > {offset}, have {len(targets)})")


async def _struct_member_target(
    generic_idalib_w: GenericIdalib,
    *,
    named: bool = False,
) -> StructMemberTarget:
    where = "WHERE member_name != ''" if named else ""
    r = await generic_idalib_w.runner.sql(
        f"SELECT type_ordinal, member_index, member_name FROM types_struct_members {where} LIMIT 1"
    )
    if not r["rows"]:
        pytest.skip("fixture has no struct member targets")
    row = r["rows"][0]
    return StructMemberTarget(
        type_ordinal=row["type_ordinal"],
        member_index=row["member_index"],
        member_name=row["member_name"],
    )


class TestFuncWrites:
    async def test_rename_visible_in_names(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 0)
        new_name = f"e2e_name_names_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(f"UPDATE funcs SET name = '{new_name}' WHERE start_ea = {ea}")

        funcs = await generic_idalib_w.runner.sql(f"SELECT name FROM funcs WHERE start_ea = {ea}")
        assert funcs["rows"][0]["name"] == new_name

        names = await generic_idalib_w.runner.sql(f"SELECT name FROM names WHERE address = {ea}")
        assert names["rows"], f"no name entry at {ea}"
        assert names["rows"][0]["name"] == new_name

    async def test_rename_visible_in_pseudocode(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 0)
        new_name = f"e2e_name_pseudo_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(f"UPDATE funcs SET name = '{new_name}' WHERE start_ea = {target.func_ea}")

        funcs = await generic_idalib_w.runner.sql(f"SELECT name FROM funcs WHERE start_ea = {target.func_ea}")
        assert funcs["rows"][0]["name"] == new_name

        pseudocode = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'code'"
        )
        lines = [row["line"] for row in pseudocode["rows"]]
        assert any(new_name in line for line in lines)

    async def test_comment_visible_in_comments(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 1)
        comment = f"e2e comment {generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(f"UPDATE funcs SET comment = '{comment}' WHERE start_ea = {ea}")

        funcs = await generic_idalib_w.runner.sql(f"SELECT comment FROM funcs WHERE start_ea = {ea}")
        assert funcs["rows"][0]["comment"] == comment

    async def test_rpt_comment_visible_in_comments(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 2)
        comment = f"e2e rpt comment {generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(f"UPDATE funcs SET rpt_comment = '{comment}' WHERE start_ea = {ea}")

        funcs = await generic_idalib_w.runner.sql(f"SELECT rpt_comment FROM funcs WHERE start_ea = {ea}")
        assert funcs["rows"][0]["rpt_comment"] == comment

    async def test_flags_sets_hidden_bit(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 3)
        current = await generic_idalib_w.runner.sql(f"SELECT flags FROM funcs WHERE start_ea = {ea}")
        old_flags = int(current["rows"][0]["flags"], 16)
        new_flags = old_flags | 0x40
        await generic_idalib_w.runner.sql(f"UPDATE funcs SET flags = {new_flags} WHERE start_ea = {ea}")

        updated = await generic_idalib_w.runner.sql(f"SELECT flags FROM funcs WHERE start_ea = {ea}")
        assert int(updated["rows"][0]["flags"], 16) & 0x40

    async def test_flags_via_func_flag_sets_hidden_bit(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 4)
        current = await generic_idalib_w.runner.sql(f"SELECT flags FROM funcs WHERE start_ea = {ea}")
        old_flags = int(current["rows"][0]["flags"], 16)
        await generic_idalib_w.runner.sql(
            f"UPDATE funcs SET flags = {old_flags} | func_flag('hidden') WHERE start_ea = {ea}"
        )

        updated = await generic_idalib_w.runner.sql(f"SELECT flags FROM funcs WHERE start_ea = {ea}")
        assert int(updated["rows"][0]["flags"], 16) & 0x40

    async def test_prototype_updates_parameter_names_and_types(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _prototype_target(generic_idalib_w, 0)
        prototype = f"int {target.name}(int e2e_count, char *e2e_buf)"

        try:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(prototype)} WHERE start_ea = {target.func_ea}"
            )

            funcs = await generic_idalib_w.runner.sql(
                f"SELECT prototype, arg_count FROM funcs WHERE start_ea = {target.func_ea}"
            )
            assert funcs["rows"][0]["arg_count"] == 2
            assert "int e2e_count" in funcs["rows"][0]["prototype"]
            assert "char *e2e_buf" in funcs["rows"][0]["prototype"]

            type_at = await generic_idalib_w.runner.sql(f"SELECT type_at({target.func_ea}) AS t")
            assert "int e2e_count" in type_at["rows"][0]["t"]
            assert "char *e2e_buf" in type_at["rows"][0]["t"]

            lvars = await generic_idalib_w.runner.sql(
                f"SELECT name, type FROM ctree_lvars WHERE func_ea = {target.func_ea} AND is_arg = 1 ORDER BY idx"
            )
            assert [row["name"] for row in lvars["rows"]] == ["e2e_count", "e2e_buf"]
            assert lvars["rows"][0]["type"] == "int"
            assert lvars["rows"][1]["type"] == "char *"

            pseudocode = await generic_idalib_w.runner.sql(
                f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} ORDER BY n LIMIT 8"
            )
            lines = [row["line"] for row in pseudocode["rows"]]
            assert any("e2e_count" in line for line in lines)
            assert any("e2e_buf" in line for line in lines)
        finally:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(target.prototype)} WHERE start_ea = {target.func_ea}"
            )

    async def test_prototype_updates_calling_convention(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _prototype_target(generic_idalib_w, 1)
        prototype = f"int __fastcall {target.name}(int e2e_arg)"

        try:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(prototype)} WHERE start_ea = {target.func_ea}"
            )

            funcs = await generic_idalib_w.runner.sql(
                f"SELECT prototype, calling_conv FROM funcs WHERE start_ea = {target.func_ea}"
            )
            assert funcs["rows"][0]["calling_conv"] == "fastcall"
            assert "__fastcall" in funcs["rows"][0]["prototype"]
        finally:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(target.prototype)} WHERE start_ea = {target.func_ea}"
            )

    async def test_prototype_updates_return_type_and_parameter_count(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _prototype_target(generic_idalib_w, 2)
        prototype = f"char *{target.name}(void)"

        try:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(prototype)} WHERE start_ea = {target.func_ea}"
            )

            funcs = await generic_idalib_w.runner.sql(
                f"SELECT prototype, return_type, arg_count FROM funcs WHERE start_ea = {target.func_ea}"
            )
            assert funcs["rows"][0]["return_type"] == "char *"
            assert funcs["rows"][0]["arg_count"] == 0
            assert "char *" in funcs["rows"][0]["prototype"]

            type_at = await generic_idalib_w.runner.sql(f"SELECT type_at({target.func_ea}) AS t")
            assert "char *" in type_at["rows"][0]["t"]

            lvars = await generic_idalib_w.runner.sql(
                f"SELECT name FROM ctree_lvars WHERE func_ea = {target.func_ea} AND is_arg = 1"
            )
            assert lvars["rows"] == []

            pseudocode = await generic_idalib_w.runner.sql(
                f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} ORDER BY n LIMIT 4"
            )
            assert any("char *" in row["line"] for row in pseudocode["rows"])
        finally:
            await generic_idalib_w.runner.sql(
                f"UPDATE funcs SET prototype = {_sql_literal(target.prototype)} WHERE start_ea = {target.func_ea}"
            )


class TestDecompilerCommentWrites:
    async def test_idapython_decompiler_comment_visible_in_sql(
        self,
        generic_idalib_w: GenericIdalib,
    ) -> None:
        target = await _pseudocode_target(generic_idalib_w, 1)
        comment = f"e2e_exec_comment_{generic_idalib_w.fixture.name}"
        result = await generic_idalib_w.runner.exec(f"""\
import ida_auto
import ida_hexrays

ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

cfunc = ida_hexrays.decompile({target.func_ea})
assert cfunc is not None, 'decompile failed'

target_ea = None
for sl in cfunc.get_pseudocode():
    raw = str(sl.line)
    for i in range(len(raw) - 1):
        if ord(raw[i]) == 1 and ord(raw[i + 1]) == 40:
            hex_str = raw[i + 2:i + 18]
            val = int(hex_str, 16)
            anchor = val & 0xFFFFFFFF
            if (anchor & 0xC0000000) == 0:
                idx = anchor & 0x1FFFFFFF
                if idx < len(cfunc.treeitems) and cfunc.treeitems[idx]:
                    candidate = cfunc.treeitems[idx].ea
                    if candidate != 0xFFFFFFFFFFFFFFFF:
                        target_ea = candidate
            break
    if target_ea is not None:
        break
assert target_ea is not None, 'no valid ea found in pseudocode'

tl = ida_hexrays.treeloc_t()
tl.ea = target_ea
tl.itp = ida_hexrays.ITP_SEMI
cfunc.set_user_cmt(tl, '{comment}')
cfunc.save_user_cmts()
_result_ = target_ea
""")
        assert isinstance(result, int), f"expected target_ea int, got {result!r}"

        # Comment should appear as a comment row in pseudocode.
        pseudocode = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        comments = [row["line"] for row in pseudocode["rows"]]
        assert comment in comments

    async def test_sql_decompiler_comment_round_trips(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 2)
        comment = f"e2e_sql_comment_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', '{comment}')"
        )

        # Verify comment appears as a comment row.
        r = await generic_idalib_w.runner.sql(
            f"SELECT line, placement, is_orphan FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        matches = [row for row in r["rows"] if row["line"] == comment]
        assert len(matches) == 1
        assert matches[0]["placement"] == "semi"
        assert matches[0]["is_orphan"] == 0

    async def test_decompiler_comment_not_duplicated_as_code(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 3)
        comment = f"e2e_no_dup_comment_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', '{comment}')"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT type, line FROM pseudocode WHERE func_ea = {target.func_ea} AND line LIKE '%{comment}%' ORDER BY n"
        )
        assert r["rows"] == [{"type": "comment", "line": comment}]

    async def test_sql_decompiler_block_comment(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 3)
        comment = f"e2e_block_comment_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'block1', '{comment}')"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT line, placement FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        matches = [row for row in r["rows"] if row["line"] == comment]
        assert len(matches) == 1
        assert matches[0]["placement"] == "block1"

    async def test_update_decompiler_comment_text(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 4)

        # Insert, then update.
        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', 'original')"
        )
        await generic_idalib_w.runner.sql(
            f"UPDATE pseudocode SET line = 'updated' "
            f"WHERE func_ea = {target.func_ea} AND ea = {target.ea} AND placement = 'semi'"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        matches = [row for row in r["rows"] if row["line"] == "updated"]
        assert len(matches) == 1

    async def test_insert_without_placement_raises(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 0)
        msg = await generic_idalib_w.runner.sql_err(
            f"INSERT INTO pseudocode (func_ea, ea, line) VALUES ({target.func_ea}, {target.ea}, 'no placement')"
        )
        assert "placement" in msg.lower()

    async def test_interleaving_order_semi_after_code(self, generic_idalib_w: GenericIdalib) -> None:
        """A semi comment should appear AFTER its code line in the n ordering."""
        target = await _pseudocode_target(generic_idalib_w, 5)
        comment = f"e2e_order_semi_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', '{comment}')"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT n, type, line, ea, placement FROM pseudocode "
            f"WHERE func_ea = {target.func_ea} AND ea = {target.ea} ORDER BY n"
        )
        rows = r["rows"]
        code_rows = [row for row in rows if row["type"] == "code"]
        comment_rows = [row for row in rows if row["type"] == "comment" and row["line"] == comment]
        assert code_rows, "expected at least one code row"
        assert comment_rows, "expected the semi comment row"
        # Semi comment n > code line n.
        assert comment_rows[0]["n"] > code_rows[0]["n"]
        assert comment_rows[0]["placement"] == "semi"

    async def test_interleaving_order_block1_before_code(self, generic_idalib_w: GenericIdalib) -> None:
        """A block1 comment should appear BEFORE its code line in the n ordering."""
        target = await _pseudocode_target(generic_idalib_w, 6)
        comment = f"e2e_order_block1_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'block1', '{comment}')"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT n, type, line, ea, placement FROM pseudocode "
            f"WHERE func_ea = {target.func_ea} AND ea = {target.ea} ORDER BY n"
        )
        rows = r["rows"]
        code_rows = [row for row in rows if row["type"] == "code"]
        comment_rows = [row for row in rows if row["type"] == "comment" and row["line"] == comment]
        assert code_rows, "expected at least one code row"
        assert comment_rows, "expected the block1 comment row"
        # Block1 comment n < first code line n at this ea.
        assert comment_rows[0]["n"] < code_rows[0]["n"]
        assert comment_rows[0]["placement"] == "block1"

    async def test_multiple_comments_same_ea(self, generic_idalib_w: GenericIdalib) -> None:
        """Both block1 and semi comments on the same ea produce separate rows in correct order."""
        target = await _multi_placement_target(generic_idalib_w)
        block_comment = f"e2e_multi_block_{generic_idalib_w.fixture.name}"
        semi_comment = f"e2e_multi_semi_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'block1', '{block_comment}')"
        )
        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', '{semi_comment}')"
        )

        r = await generic_idalib_w.runner.sql(
            f"SELECT n, type, line, placement FROM pseudocode "
            f"WHERE func_ea = {target.func_ea} AND ea = {target.ea} ORDER BY n"
        )
        rows = r["rows"]
        block_rows = [row for row in rows if row["line"] == block_comment]
        code_rows = [row for row in rows if row["type"] == "code"]
        semi_rows = [row for row in rows if row["line"] == semi_comment]
        assert block_rows and code_rows and semi_rows
        # Order: block1 < code < semi
        assert block_rows[0]["n"] < code_rows[0]["n"] < semi_rows[0]["n"]

    async def test_delete_comment(self, generic_idalib_w: GenericIdalib) -> None:
        """DELETE removes a comment row."""
        target = await _pseudocode_target(generic_idalib_w, 7)
        comment = f"e2e_delete_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', '{comment}')"
        )

        # Verify it exists.
        r = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        assert any(row["line"] == comment for row in r["rows"])

        # Delete it.
        await generic_idalib_w.runner.sql(
            f"DELETE FROM pseudocode WHERE func_ea = {target.func_ea} AND ea = {target.ea} AND placement = 'semi'"
        )

        # Verify it's gone from comment rows.
        r = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        assert not any(row["line"] == comment for row in r["rows"])

        # Verify no ghost in rendered code lines (regression: stale cfunc cache).
        r = await generic_idalib_w.runner.sql(
            f"SELECT line FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'code' AND line LIKE '%{comment}%'"
        )
        assert r["rows"] == []

    async def test_n_sequential_with_comments(self, generic_idalib_w: GenericIdalib) -> None:
        """After inserting comments, n values remain 1..N sequential."""
        target = await _pseudocode_target(generic_idalib_w, 8)

        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', 'seq test comment')"
        )

        r = await generic_idalib_w.runner.sql(f"SELECT n FROM pseudocode WHERE func_ea = {target.func_ea} ORDER BY n")
        nums = [row["n"] for row in r["rows"]]
        assert nums == list(range(1, len(nums) + 1))

    async def test_insert_using_valid_placements(self, generic_idalib_w: GenericIdalib) -> None:
        """Agent workflow: read valid_placements, pick one, INSERT with it."""
        target = await _pseudocode_target(generic_idalib_w, 9)

        # Step 1: read valid_placements for the target ea.
        r = await generic_idalib_w.runner.sql(
            f"SELECT valid_placements FROM pseudocode "
            f"WHERE func_ea = {target.func_ea} AND ea = {target.ea} AND type = 'code' LIMIT 1"
        )
        assert r["rows"], "expected code row"
        vp = r["rows"][0]["valid_placements"]
        assert vp is not None, "expected non-NULL valid_placements"
        placement = vp.split(",")[0]  # pick first valid placement

        # Step 2: INSERT using the discovered placement.
        comment = f"e2e_vp_driven_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, '{placement}', '{comment}')"
        )

        # Step 3: verify the comment appears.
        r = await generic_idalib_w.runner.sql(
            f"SELECT line, placement FROM pseudocode WHERE func_ea = {target.func_ea} AND type = 'comment'"
        )
        matches = [row for row in r["rows"] if row["line"] == comment]
        assert len(matches) == 1
        assert matches[0]["placement"] == placement


class TestTypesStructMemberWrites:
    async def test_update_member_name(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w, named=True)
        new_name = f"e2e_member_{target.type_ordinal}_{target.member_index}"

        await generic_idalib_w.runner.sql(
            "UPDATE types_struct_members "
            f"SET member_name = '{new_name}' "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        r2 = await generic_idalib_w.runner.sql(
            "SELECT member_name FROM types_struct_members "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert r2["rows"][0]["member_name"] == new_name

    async def test_update_comment_and_clear(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w)
        comment = f"e2e comment {target.type_ordinal}:{target.member_index}"

        await generic_idalib_w.runner.sql(
            "UPDATE types_struct_members "
            f"SET comment = '{comment}' "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        r2 = await generic_idalib_w.runner.sql(
            "SELECT comment FROM types_struct_members "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert r2["rows"][0]["comment"] == comment

        await generic_idalib_w.runner.sql(
            "UPDATE types_struct_members "
            f"SET comment = NULL "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        r3 = await generic_idalib_w.runner.sql(
            "SELECT comment FROM types_struct_members "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert r3["rows"][0]["comment"] is None

    async def test_update_member_type(self, generic_idalib_w: GenericIdalib) -> None:
        # Create a struct with a known member type, then change it.
        r = await generic_idalib_w.runner.sql(
            "SELECT parse_type('struct e2e_memtype { int field_a; int field_b; };') AS ordinal"
        )
        ordinal = r["rows"][0]["ordinal"]

        # Verify initial type.
        r2 = await generic_idalib_w.runner.sql(
            f"SELECT member_type FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 1"
        )
        assert r2["rows"][0]["member_type"] == "int"

        # Change member type.
        await generic_idalib_w.runner.sql(
            f"UPDATE types_struct_members SET member_type = 'char *' "
            f"WHERE type_ordinal = {ordinal} AND member_index = 1"
        )
        r3 = await generic_idalib_w.runner.sql(
            f"SELECT member_type, size FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 1"
        )
        assert r3["rows"][0]["member_type"] == "char *"

        # Clean up.
        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_empty_member_name_raises(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w)
        err = await generic_idalib_w.runner.sql_err(
            "UPDATE types_struct_members "
            "SET member_name = '' "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert "does not support setting member_name to empty string" in err

    async def test_non_text_member_name_raises(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w)
        err = await generic_idalib_w.runner.sql_err(
            "UPDATE types_struct_members "
            "SET member_name = 123 "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert "member_name must be TEXT" in err

    async def test_non_text_comment_raises(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w)
        err = await generic_idalib_w.runner.sql_err(
            "UPDATE types_struct_members "
            "SET comment = 123 "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {target.member_index}"
        )
        assert "comment must be TEXT or NULL" in err

    async def test_insert_and_delete_member(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _struct_member_target(generic_idalib_w)

        # Find the end of the struct to avoid overlap.
        members = await generic_idalib_w.runner.sql(
            f"SELECT offset, size FROM types_struct_members "
            f"WHERE type_ordinal = {target.type_ordinal} ORDER BY offset DESC LIMIT 1"
        )
        last = members["rows"][0]
        # Place new member after the last existing one.
        new_offset = int(last["offset"], 16) + int(last["size"], 16)

        before = await generic_idalib_w.runner.sql(
            f"SELECT COUNT(*) AS cnt FROM types_struct_members WHERE type_ordinal = {target.type_ordinal}"
        )
        before_cnt = before["rows"][0]["cnt"]

        await generic_idalib_w.runner.sql(
            "INSERT INTO types_struct_members (type_ordinal, member_name, member_type, offset) "
            f"VALUES ({target.type_ordinal}, 'e2e_inserted', 'int', {new_offset})"
        )
        after_insert = await generic_idalib_w.runner.sql(
            f"SELECT member_name FROM types_struct_members WHERE type_ordinal = {target.type_ordinal}"
        )
        names = [r["member_name"] for r in after_insert["rows"]]
        assert "e2e_inserted" in names
        assert len(after_insert["rows"]) == before_cnt + 1

        # Now delete the member we just added.
        inserted_idx = names.index("e2e_inserted")
        await generic_idalib_w.runner.sql(
            f"DELETE FROM types_struct_members "
            f"WHERE type_ordinal = {target.type_ordinal} AND member_index = {inserted_idx}"
        )
        after_delete = await generic_idalib_w.runner.sql(
            f"SELECT COUNT(*) AS cnt FROM types_struct_members WHERE type_ordinal = {target.type_ordinal}"
        )
        assert after_delete["rows"][0]["cnt"] == before_cnt


@dataclass(frozen=True)
class EnumValueTarget:
    type_ordinal: int
    value_index: int
    value_name: str


async def _enum_value_target(generic_idalib_w: GenericIdalib) -> EnumValueTarget:
    r = await generic_idalib_w.runner.sql(
        "SELECT type_ordinal, value_index, value_name FROM types_enum_values WHERE value_name != '' LIMIT 10"
    )
    if not r["rows"]:
        pytest.skip("no enum values in IDB")
    # Some enums come from imported TILs and silently ignore writes.
    # Probe each candidate until we find one where rename actually persists.
    for row in r["rows"]:
        ordinal = row["type_ordinal"]
        idx = row["value_index"]
        orig_name = row["value_name"]
        probe_name = f"_e2e_probe_{ordinal}_{idx}"
        await generic_idalib_w.runner.sql(
            f"UPDATE types_enum_values SET value_name = '{probe_name}' "
            f"WHERE type_ordinal = {ordinal} AND value_index = {idx}"
        )
        check = await generic_idalib_w.runner.sql(
            f"SELECT value_name FROM types_enum_values WHERE type_ordinal = {ordinal} AND value_index = {idx}"
        )
        if check["rows"][0]["value_name"] == probe_name:
            # Restore original name and return this target.
            await generic_idalib_w.runner.sql(
                f"UPDATE types_enum_values SET value_name = '{orig_name}' "
                f"WHERE type_ordinal = {ordinal} AND value_index = {idx}"
            )
            return EnumValueTarget(
                type_ordinal=ordinal,
                value_index=idx,
                value_name=orig_name,
            )
    pytest.skip("no writable enum values in IDB (all may be TIL-imported)")


class TestTypesEnumValueWrites:
    async def test_update_value_name(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _enum_value_target(generic_idalib_w)
        new_name = f"e2e_val_{target.type_ordinal}_{target.value_index}"

        await generic_idalib_w.runner.sql(
            "UPDATE types_enum_values "
            f"SET value_name = '{new_name}' "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        r = await generic_idalib_w.runner.sql(
            "SELECT value_name FROM types_enum_values "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        assert r["rows"][0]["value_name"] == new_name

    async def test_update_value(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _enum_value_target(generic_idalib_w)

        await generic_idalib_w.runner.sql(
            "UPDATE types_enum_values "
            f"SET value = 9999 "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        r = await generic_idalib_w.runner.sql(
            "SELECT value FROM types_enum_values "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        assert int(r["rows"][0]["value"], 16) == 9999

    async def test_update_comment_and_clear(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _enum_value_target(generic_idalib_w)
        comment = f"e2e enum cmt {target.type_ordinal}:{target.value_index}"

        await generic_idalib_w.runner.sql(
            "UPDATE types_enum_values "
            f"SET comment = '{comment}' "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        r = await generic_idalib_w.runner.sql(
            "SELECT comment FROM types_enum_values "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        assert r["rows"][0]["comment"] == comment

        await generic_idalib_w.runner.sql(
            "UPDATE types_enum_values "
            f"SET comment = NULL "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        r2 = await generic_idalib_w.runner.sql(
            "SELECT comment FROM types_enum_values "
            f"WHERE type_ordinal = {target.type_ordinal} AND value_index = {target.value_index}"
        )
        assert r2["rows"][0]["comment"] is None

    async def test_insert_and_delete_value(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _enum_value_target(generic_idalib_w)

        before = await generic_idalib_w.runner.sql(
            f"SELECT COUNT(*) AS cnt FROM types_enum_values WHERE type_ordinal = {target.type_ordinal}"
        )
        before_cnt = before["rows"][0]["cnt"]

        await generic_idalib_w.runner.sql(
            "INSERT INTO types_enum_values (type_ordinal, value_name, value) "
            f"VALUES ({target.type_ordinal}, 'E2E_INSERTED', 99999)"
        )
        after_insert = await generic_idalib_w.runner.sql(
            f"SELECT value_name FROM types_enum_values WHERE type_ordinal = {target.type_ordinal}"
        )
        names = [r["value_name"] for r in after_insert["rows"]]
        assert "E2E_INSERTED" in names
        assert len(after_insert["rows"]) == before_cnt + 1

        # Delete the constant we just added.
        inserted_idx = names.index("E2E_INSERTED")
        await generic_idalib_w.runner.sql(
            f"DELETE FROM types_enum_values WHERE type_ordinal = {target.type_ordinal} AND value_index = {inserted_idx}"
        )
        after_delete = await generic_idalib_w.runner.sql(
            f"SELECT COUNT(*) AS cnt FROM types_enum_values WHERE type_ordinal = {target.type_ordinal}"
        )
        assert after_delete["rows"][0]["cnt"] == before_cnt


class TestTypesWriteOps:
    async def test_delete_type(self, generic_idalib_w: GenericIdalib) -> None:
        # Pick a type to delete.
        r = await generic_idalib_w.runner.sql(
            "SELECT ordinal, name FROM types WHERE is_typedef = 0 AND is_forward_decl = 0 LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no types in IDB")
        ordinal = r["rows"][0]["ordinal"]

        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

        after = await generic_idalib_w.runner.sql(f"SELECT * FROM types WHERE ordinal = {ordinal}")
        assert len(after["rows"]) == 0

    async def test_insert_and_delete_type(self, generic_idalib_w: GenericIdalib) -> None:
        await generic_idalib_w.runner.sql("INSERT INTO types (name, kind) VALUES ('e2e_test_struct', 'struct')")
        created = await generic_idalib_w.runner.sql(
            "SELECT ordinal, name, kind FROM types WHERE name = 'e2e_test_struct'"
        )
        assert len(created["rows"]) == 1
        assert created["rows"][0]["kind"] == "struct"
        ordinal = created["rows"][0]["ordinal"]

        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")
        gone = await generic_idalib_w.runner.sql(f"SELECT * FROM types WHERE ordinal = {ordinal}")
        assert len(gone["rows"]) == 0

    async def test_rename_type(self, generic_idalib_w: GenericIdalib) -> None:
        # Create a type, rename it, verify.
        await generic_idalib_w.runner.sql("INSERT INTO types (name, kind) VALUES ('e2e_rename_src', 'struct')")
        created = await generic_idalib_w.runner.sql("SELECT ordinal FROM types WHERE name = 'e2e_rename_src'")
        ordinal = created["rows"][0]["ordinal"]

        await generic_idalib_w.runner.sql(f"UPDATE types SET name = 'e2e_rename_dst' WHERE ordinal = {ordinal}")
        after = await generic_idalib_w.runner.sql(f"SELECT name FROM types WHERE ordinal = {ordinal}")
        assert after["rows"][0]["name"] == "e2e_rename_dst"

        # Clean up.
        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_parse_type(self, generic_idalib_w: GenericIdalib) -> None:
        r = await generic_idalib_w.runner.sql("SELECT parse_type('struct e2e_parsed { int x; char *y; };') AS ordinal")
        ordinal = r["rows"][0]["ordinal"]
        assert ordinal > 0

        detail = await generic_idalib_w.runner.sql(
            f"SELECT name, kind, member_count FROM types WHERE ordinal = {ordinal}"
        )
        assert detail["rows"][0]["name"] == "e2e_parsed"
        assert detail["rows"][0]["kind"] == "struct"
        assert detail["rows"][0]["member_count"] == 2

        # Clean up.
        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_parse_type_replace(self, generic_idalib_w: GenericIdalib) -> None:
        # Create, then replace with a different definition (same name).
        r1 = await generic_idalib_w.runner.sql("SELECT parse_type('struct e2e_replace { int a; };') AS ordinal")
        ordinal = r1["rows"][0]["ordinal"]

        r2 = await generic_idalib_w.runner.sql(
            "SELECT parse_type('struct e2e_replace { int a; int b; int c; };') AS ordinal"
        )
        assert r2["rows"][0]["ordinal"] == ordinal

        detail = await generic_idalib_w.runner.sql(f"SELECT member_count FROM types WHERE ordinal = {ordinal}")
        assert detail["rows"][0]["member_count"] == 3

        await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_parse_types_batch(self, generic_idalib_w: GenericIdalib) -> None:
        import json

        r = await generic_idalib_w.runner.sql(
            "SELECT parse_types('"
            "struct e2e_batch_a { int x; }; "
            "struct e2e_batch_b { char c; int y; }; "
            "enum e2e_batch_e { E2E_VAL = 42 };"
            "') AS result"
        )
        result = json.loads(r["rows"][0]["result"])
        names = {t["name"] for t in result}
        assert "e2e_batch_a" in names
        assert "e2e_batch_b" in names
        assert "e2e_batch_e" in names

        # Clean up.
        for t in result:
            await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {t['ordinal']}")


class TestCommentsWrite:
    async def test_insert_item_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        comment = f"e2e_item_comment_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(
            f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, '{comment}', 0)"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 0")
        assert r["rows"][0]["text"] == comment

    async def test_insert_repeatable_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        comment = f"e2e_rpt_comment_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(
            f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, '{comment}', 1)"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 1")
        assert r["rows"][0]["text"] == comment

    async def test_update_existing_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        # Create, then update.
        await generic_idalib_w.runner.sql(
            f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, 'original', 0)"
        )
        await generic_idalib_w.runner.sql(
            f"UPDATE comments SET text = 'updated' WHERE address = {ea} AND repeatable = 0"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 0")
        assert r["rows"][0]["text"] == "updated"

    async def test_clear_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        # Create then clear.
        await generic_idalib_w.runner.sql(f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, 'temp', 0)")
        await generic_idalib_w.runner.sql(f"UPDATE comments SET text = '' WHERE address = {ea} AND repeatable = 0")
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 0")
        assert len(r["rows"]) == 0

    async def test_delete_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        # Create then delete.
        await generic_idalib_w.runner.sql(
            f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, 'to_delete', 0)"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 0")
        assert r["rows"][0]["text"] == "to_delete"

        await generic_idalib_w.runner.sql(f"DELETE FROM comments WHERE address = {ea} AND repeatable = 0")
        r = await generic_idalib_w.runner.sql(f"SELECT text FROM comments WHERE address = {ea} AND repeatable = 0")
        assert len(r["rows"]) == 0


class TestCtreeLvarWrites:
    async def test_reject_arg_name_and_type_writes(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs WHERE arg_count > 0 LIMIT 1")
        if not ea_r["rows"]:
            pytest.skip("no functions with args")
        ea = ea_r["rows"][0]["start_ea"]

        lvars = await generic_idalib_w.runner.sql(
            f"SELECT idx, type FROM ctree_lvars WHERE func_ea = {ea} AND is_arg = 1 LIMIT 1"
        )
        if not lvars["rows"]:
            pytest.skip("no argument lvars")
        idx = lvars["rows"][0]["idx"]
        new_type = _different_lvar_type(lvars["rows"][0]["type"])

        name_msg = await generic_idalib_w.runner.sql_err(
            f"UPDATE ctree_lvars SET name = 'e2e_arg_name_blocked' WHERE func_ea = {ea} AND idx = {idx}"
        )
        assert "argument" in name_msg.lower()
        assert "prototype" in name_msg.lower()

        type_msg = await generic_idalib_w.runner.sql_err(
            f"UPDATE ctree_lvars SET type = '{new_type}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        assert "argument" in type_msg.lower()
        assert "prototype" in type_msg.lower()

    async def test_arg_comment_writable(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs WHERE arg_count > 0 LIMIT 1")
        if not ea_r["rows"]:
            pytest.skip("no functions with args")
        ea = ea_r["rows"][0]["start_ea"]

        lvars = await generic_idalib_w.runner.sql(
            f"SELECT idx FROM ctree_lvars WHERE func_ea = {ea} AND is_arg = 1 LIMIT 1"
        )
        if not lvars["rows"]:
            pytest.skip("no argument lvars")
        idx = lvars["rows"][0]["idx"]
        comment = f"e2e_arg_comment_{generic_idalib_w.fixture.name}_{idx}"

        await generic_idalib_w.runner.sql(
            f"UPDATE ctree_lvars SET comment = '{comment}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT comment FROM ctree_lvars WHERE func_ea = {ea} AND idx = {idx}")
        assert r["rows"][0]["comment"] == comment

    async def test_reject_result_name_and_type_writes(self, generic_idalib_w: GenericIdalib) -> None:
        target = await self._result_lvar_target(generic_idalib_w)
        if target is None:
            pytest.skip("no result lvars")
        ea, idx, old_type = target
        new_type = _different_lvar_type(old_type)

        name_msg = await generic_idalib_w.runner.sql_err(
            f"UPDATE ctree_lvars SET name = 'e2e_result_name_blocked' WHERE func_ea = {ea} AND idx = {idx}"
        )
        assert "result" in name_msg.lower()
        assert "prototype" in name_msg.lower()

        type_msg = await generic_idalib_w.runner.sql_err(
            f"UPDATE ctree_lvars SET type = '{new_type}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        assert "result" in type_msg.lower()
        assert "prototype" in type_msg.lower()

    async def test_result_comment_writable(self, generic_idalib_w: GenericIdalib) -> None:
        for ea in await _stable_func_eas(generic_idalib_w, 100):
            lvars = await generic_idalib_w.runner.sql(
                f"SELECT idx FROM ctree_lvars WHERE func_ea = {ea} AND is_result = 1 LIMIT 10"
            )
            for row in lvars["rows"]:
                idx = row["idx"]
                comment = f"e2e_result_comment_{generic_idalib_w.fixture.name}_{idx}"

                await generic_idalib_w.runner.sql(
                    f"UPDATE ctree_lvars SET comment = '{comment}' WHERE func_ea = {ea} AND idx = {idx}"
                )
                r = await generic_idalib_w.runner.sql(
                    f"SELECT idx, comment FROM ctree_lvars WHERE func_ea = {ea} AND comment = '{comment}'"
                )
                if r["rows"]:
                    return
        pytest.skip("no result lvars accepted comments")

    async def _result_lvar_target(self, generic_idalib_w: GenericIdalib) -> tuple[str, int, str] | None:
        for ea in await _stable_func_eas(generic_idalib_w, 100):
            lvars = await generic_idalib_w.runner.sql(
                f"SELECT idx, type FROM ctree_lvars WHERE func_ea = {ea} AND is_result = 1 LIMIT 1"
            )
            if lvars["rows"]:
                return ea, lvars["rows"][0]["idx"], lvars["rows"][0]["type"]
        return None

    async def test_rename_lvar(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        lvars = await generic_idalib_w.runner.sql(
            f"SELECT idx, name FROM ctree_lvars WHERE func_ea = {ea} AND is_arg = 0 AND is_result = 0 AND name != '' LIMIT 1"
        )
        if not lvars["rows"]:
            pytest.skip("no local variables")
        idx = lvars["rows"][0]["idx"]
        new_name = f"e2e_lvar_{idx}"

        await generic_idalib_w.runner.sql(
            f"UPDATE ctree_lvars SET name = '{new_name}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT name FROM ctree_lvars WHERE func_ea = {ea} AND idx = {idx}")
        assert r["rows"][0]["name"] == new_name

    async def test_retype_lvar(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        lvars = await generic_idalib_w.runner.sql(
            f"SELECT idx, size FROM ctree_lvars WHERE func_ea = {ea} AND is_arg = 0 AND is_result = 0 LIMIT 1"
        )
        if not lvars["rows"]:
            pytest.skip("no local variables")
        idx = lvars["rows"][0]["idx"]
        size = lvars["rows"][0]["size"]

        # Pick an unsigned type matching the lvar's width.
        type_by_size = {1: "unsigned __int8", 2: "unsigned __int16", 4: "unsigned int", 8: "unsigned __int64"}
        new_type = type_by_size.get(size, "unsigned int")

        await generic_idalib_w.runner.sql(
            f"UPDATE ctree_lvars SET type = '{new_type}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT type FROM ctree_lvars WHERE func_ea = {ea} AND idx = {idx}")
        assert "unsigned" in r["rows"][0]["type"] or "uint" in r["rows"][0]["type"]

    async def test_set_lvar_comment(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        lvars = await generic_idalib_w.runner.sql(
            f"SELECT idx FROM ctree_lvars WHERE func_ea = {ea} AND is_arg = 0 AND is_result = 0 LIMIT 1"
        )
        if not lvars["rows"]:
            pytest.skip("no lvars")
        idx = lvars["rows"][0]["idx"]

        comment = f"e2e_comment_{idx}"
        await generic_idalib_w.runner.sql(
            f"UPDATE ctree_lvars SET comment = '{comment}' WHERE func_ea = {ea} AND idx = {idx}"
        )
        r = await generic_idalib_w.runner.sql(f"SELECT comment FROM ctree_lvars WHERE func_ea = {ea} AND idx = {idx}")
        assert r["rows"][0]["comment"] == comment


class TestSetTypeAndTypeAt:
    async def test_type_at_on_function(self, generic_idalib_w: GenericIdalib) -> None:
        # Find a function with a known prototype.
        r = await generic_idalib_w.runner.sql(
            "SELECT start_ea, prototype FROM funcs WHERE prototype IS NOT NULL LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no typed functions in IDB")
        ea = r["rows"][0]["start_ea"]

        r2 = await generic_idalib_w.runner.sql(f"SELECT type_at({ea}) AS t")
        assert r2["rows"][0]["t"] is not None

    async def test_type_at_untyped_returns_null(self, generic_idalib_w: GenericIdalib) -> None:
        r = await generic_idalib_w.runner.sql("SELECT type_at(0xDEADBEEF) AS t")
        assert r["rows"][0]["t"] is None

    async def test_set_type_on_function(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = ea_r["rows"][0]["start_ea"]

        await generic_idalib_w.runner.sql(f"SELECT set_type({ea}, 'int e2e_typed_func(int a, int b)')")
        r = await generic_idalib_w.runner.sql(f"SELECT type_at({ea}) AS t")
        t = r["rows"][0]["t"]
        assert t is not None
        # IDA replaces the name in the prototype with the actual function name,
        # so check the signature shape rather than our dummy name.
        assert "int" in t
        assert "int a" in t
        assert "int b" in t

    async def test_set_type_clear(self, generic_idalib_w: GenericIdalib) -> None:
        ea_r = await generic_idalib_w.runner.sql("SELECT start_ea FROM funcs WHERE prototype IS NOT NULL LIMIT 1")
        if not ea_r["rows"]:
            pytest.skip("no typed functions")
        ea = ea_r["rows"][0]["start_ea"]

        await generic_idalib_w.runner.sql(f"SELECT set_type({ea}, NULL)")
        r = await generic_idalib_w.runner.sql(f"SELECT type_at({ea}) AS t")
        # After clearing, type_at may still return a guessed type or NULL.
        # Just verify it didn't error.
        assert r["rows"] is not None

    async def test_set_type_data(self, generic_idalib_w: GenericIdalib) -> None:
        # Find a data address (not code).
        r = await generic_idalib_w.runner.sql(
            "SELECT address FROM names WHERE address NOT IN (SELECT start_ea FROM funcs) LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no data names in IDB")
        ea = r["rows"][0]["address"]

        await generic_idalib_w.runner.sql(f"SELECT set_type({ea}, 'unsigned int')")
        r2 = await generic_idalib_w.runner.sql(f"SELECT type_at({ea}) AS t")
        assert r2["rows"][0]["t"] is not None


class TestWriteErrors:
    async def test_insert_rejected(self, generic_idalib_w: GenericIdalib) -> None:
        msg = await generic_idalib_w.runner.sql_err("INSERT INTO funcs (start_ea, name) VALUES (0x0, 'x')")
        assert msg

    async def test_update_no_match_is_noop(self, generic_idalib_w: GenericIdalib) -> None:
        r = await generic_idalib_w.runner.sql("UPDATE funcs SET name = 'ghost' WHERE start_ea = 0xDEADBEEF")
        assert r["columns"] == []
        assert r["rows"] == []

    async def test_invalid_name(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 5)
        msg = await generic_idalib_w.runner.sql_err(f"UPDATE funcs SET name = '!!!invalid!!!' WHERE start_ea = {ea}")
        assert "set_name failed" in msg.lower()

    async def test_invalid_prototype(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 6)
        msg = await generic_idalib_w.runner.sql_err(
            f"UPDATE funcs SET prototype = 'not a valid prototype @@!' WHERE start_ea = {ea}"
        )
        assert "apply_cdecl failed" in msg.lower()


class TestNonWritableColumnsReject:
    """The read-only half of the write contract, one test per writable table.

    Identity columns are included: handlers take identity from the rowid, so an
    identity value in an UPDATE can only be a user assignment, which would
    otherwise retarget the write to another row.

    Each test is named after its table, and `test_every_writable_table_is_covered`
    derives coverage from those names, so a newly writable table fails until it
    gets a test. The contract does not depend on IDB data, so it runs on one IDB.
    """

    @pytest.fixture(autouse=True)
    def _only_contract_fixture(self, generic_idalib_w: GenericIdalib) -> None:
        if generic_idalib_w.fixture.name != default_fixture().name:
            pytest.skip("write contract does not depend on IDB data; asserted on the first fixture")

    async def test_every_writable_table_is_covered(self) -> None:
        covered = {
            name.removeprefix("test_")
            for name in dir(self)
            if name.startswith("test_") and name != "test_every_writable_table_is_covered"
        }
        assert covered == writable_tables()

    async def test_funcs(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 0)
        await _assert_non_writable_columns_reject(generic_idalib_w, "funcs", f"start_ea = {ea}")

    async def test_names(self, generic_idalib_w: GenericIdalib) -> None:
        r = await generic_idalib_w.runner.sql("SELECT address FROM names LIMIT 1")
        if not r["rows"]:
            pytest.skip("fixture has no names")
        await _assert_non_writable_columns_reject(generic_idalib_w, "names", f"address = {r['rows'][0]['address']}")

    async def test_comments(self, generic_idalib_w: GenericIdalib) -> None:
        ea = await _func_ea(generic_idalib_w, 0)
        where = f"address = {ea} AND repeatable = 0"
        await generic_idalib_w.runner.sql(
            f"INSERT INTO comments (address, text, repeatable) VALUES ({ea}, 'e2e contract probe', 0)"
        )
        try:
            await _assert_non_writable_columns_reject(generic_idalib_w, "comments", where)
        finally:
            await generic_idalib_w.runner.sql(f"DELETE FROM comments WHERE {where}")

    async def test_pseudocode(self, generic_idalib_w: GenericIdalib) -> None:
        target = await _pseudocode_target(generic_idalib_w, 0)
        where = f"func_ea = {target.func_ea} AND ea = {target.ea} AND placement = 'semi'"
        await generic_idalib_w.runner.sql(
            f"INSERT INTO pseudocode (func_ea, ea, placement, line) "
            f"VALUES ({target.func_ea}, {target.ea}, 'semi', 'e2e contract probe')"
        )
        try:
            await _assert_non_writable_columns_reject(generic_idalib_w, "pseudocode", where)
        finally:
            await generic_idalib_w.runner.sql(f"DELETE FROM pseudocode WHERE {where}")

    async def test_ctree_lvars(self, generic_idalib_w: GenericIdalib) -> None:
        for ea in await _stable_func_eas(generic_idalib_w, 20):
            lvars = await generic_idalib_w.runner.sql(f"SELECT idx FROM ctree_lvars WHERE func_ea = {ea} LIMIT 1")
            if lvars["rows"]:
                idx = lvars["rows"][0]["idx"]
                await _assert_non_writable_columns_reject(
                    generic_idalib_w, "ctree_lvars", f"func_ea = {ea} AND idx = {idx}"
                )
                return
        pytest.skip("fixture has no lvars")

    async def test_types(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _scratch_type(generic_idalib_w, "struct e2e_contract_t { int a; };")
        try:
            await _assert_non_writable_columns_reject(generic_idalib_w, "types", f"ordinal = {ordinal}")
        finally:
            await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_types_struct_members(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _scratch_type(generic_idalib_w, "struct e2e_contract_sm { int a; int b; };")
        try:
            await _assert_non_writable_columns_reject(
                generic_idalib_w, "types_struct_members", f"type_ordinal = {ordinal} AND member_index = 0"
            )
        finally:
            await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")

    async def test_types_enum_values(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _scratch_type(generic_idalib_w, "enum e2e_contract_ev { E_X = 1, E_Y = 2 };")
        try:
            await _assert_non_writable_columns_reject(
                generic_idalib_w, "types_enum_values", f"type_ordinal = {ordinal} AND value_index = 0"
            )
        finally:
            await generic_idalib_w.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")


class TestNamesWrites:
    async def _data_name_target(self, generic_idalib_w: GenericIdalib) -> tuple[str, str]:
        """Pick a named address that is not a function (a data global)."""
        r = await generic_idalib_w.runner.sql(
            "SELECT address, name FROM names WHERE address NOT IN (SELECT start_ea FROM funcs) LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no non-function named address in IDB")
        return r["rows"][0]["address"], r["rows"][0]["name"]

    async def test_rename_data_global(self, generic_idalib_w: GenericIdalib) -> None:
        address, _orig = await self._data_name_target(generic_idalib_w)
        new_name = f"e2e_g_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(f"UPDATE names SET name = '{new_name}' WHERE address = {address}")

        r = await generic_idalib_w.runner.sql(f"SELECT name, is_auto FROM names WHERE address = {address}")
        assert r["rows"][0]["name"] == new_name
        assert r["rows"][0]["is_auto"] == 0

    async def test_rename_visible_in_name_at(self, generic_idalib_w: GenericIdalib) -> None:
        address, _orig = await self._data_name_target(generic_idalib_w)
        new_name = f"e2e_nameat_{generic_idalib_w.fixture.name}"

        await generic_idalib_w.runner.sql(f"UPDATE names SET name = '{new_name}' WHERE address = {address}")

        r = await generic_idalib_w.runner.sql(f"SELECT name_at({address}) AS n")
        assert r["rows"][0]["n"] == new_name

    async def test_clear_name(self, generic_idalib_w: GenericIdalib) -> None:
        address, _orig = await self._data_name_target(generic_idalib_w)
        new_name = f"e2e_clear_{generic_idalib_w.fixture.name}"
        await generic_idalib_w.runner.sql(f"UPDATE names SET name = '{new_name}' WHERE address = {address}")

        await generic_idalib_w.runner.sql(f"UPDATE names SET name = '' WHERE address = {address}")

        r = await generic_idalib_w.runner.sql(f"SELECT name FROM names WHERE address = {address}")
        # Clearing a user name either drops the row or leaves an auto-generated name.
        assert not r["rows"] or r["rows"][0]["name"] != new_name

    async def test_is_auto_read_only(self, generic_idalib_w: GenericIdalib) -> None:
        address, _orig = await self._data_name_target(generic_idalib_w)
        msg = await generic_idalib_w.runner.sql_err(f"UPDATE names SET is_auto = 0 WHERE address = {address}")
        assert "names.is_auto is read-only" in msg

    async def test_invalid_name_raises(self, generic_idalib_w: GenericIdalib) -> None:
        address, _orig = await self._data_name_target(generic_idalib_w)
        msg = await generic_idalib_w.runner.sql_err(f"UPDATE names SET name = 'bad name!' WHERE address = {address}")
        assert "set_name failed" in msg
