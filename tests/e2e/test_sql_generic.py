"""Generic SQL tests parametrized over all discovered IDB fixtures.

Each test receives a ``generic_idalib`` (read-only) or ``generic_idalib_w``
(writable temp copy) fixture that cycles through every IDB discovered under
``tests/fixtures/idbs/``. Assertions are shape-independent invariants, so any
valid IDB works.
"""

import pytest

from tests.e2e.conftest import GenericIdalib, require_imports

pytestmark = [pytest.mark.asyncio(loop_scope="module")]


async def _stable_func_eas(generic_idalib: GenericIdalib, limit: int) -> list[str]:
    r = await generic_idalib.runner.sql(
        f"SELECT start_ea FROM funcs WHERE (flags & func_flag('thunk')) = 0 AND size >= 0x10 LIMIT {limit}"
    )
    return [row["start_ea"] for row in r["rows"]]


async def _func_ea_with_pseudocode(generic_idalib: GenericIdalib) -> str:
    for func_ea in await _stable_func_eas(generic_idalib, 100):
        pseudocode = await generic_idalib.runner.sql(f"SELECT n FROM pseudocode WHERE func_ea = {func_ea} LIMIT 1")
        if pseudocode["rows"]:
            return func_ea
    pytest.skip("no function with pseudocode rows found")


async def _addressable_pseudocode_target(generic_idalib: GenericIdalib) -> tuple[str, str]:
    for func_ea in await _stable_func_eas(generic_idalib, 100):
        lines = await generic_idalib.runner.sql(
            f"SELECT ea FROM pseudocode WHERE func_ea = {func_ea} AND ea IS NOT NULL LIMIT 1"
        )
        if lines["rows"]:
            return func_ea, lines["rows"][0]["ea"]
    pytest.skip("no function with addressable pseudocode rows found")


# ---------------------------------------------------------------------------
# db_info
# ---------------------------------------------------------------------------


class TestDbInfo:
    async def test_basic(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM db_info")
        assert len(r["rows"]) == 1
        row = r["rows"][0]
        assert isinstance(row["input_file"], str) and row["input_file"]
        assert isinstance(row["arch"], str) and row["arch"]
        assert row["bits"] in (32, 64)
        assert row["endian"] in ("little", "big")

    async def test_hex_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT image_base, min_ea, max_ea FROM db_info")
        row = r["rows"][0]
        for col in ("image_base", "min_ea", "max_ea"):
            assert isinstance(row[col], str) and row[col].startswith("0x"), f"{col}: {row[col]}"


# ---------------------------------------------------------------------------
# funcs
# ---------------------------------------------------------------------------


class TestFuncs:
    async def test_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM funcs")
        assert r["rows"][0]["cnt"] > 0

    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(funcs)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "start_ea",
            "name",
            "prototype",
            "comment",
            "rpt_comment",
            "size",
            "flags",
            "return_type",
            "arg_count",
            "calling_conv",
            "type_source",
        ):
            assert expected in cols, f"missing column: {expected}"

    async def test_select_with_limit(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT start_ea, name FROM funcs LIMIT 5")
        assert len(r["rows"]) == 5
        for row in r["rows"]:
            assert isinstance(row["start_ea"], str) and row["start_ea"].startswith("0x")

    async def test_order_by_name(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT name FROM funcs ORDER BY name LIMIT 10")
        names = [row["name"] for row in r["rows"]]
        assert names == sorted(names)

    async def test_filter_by_start_ea(self, generic_idalib: GenericIdalib) -> None:
        sample = await generic_idalib.runner.sql("SELECT start_ea, name FROM funcs LIMIT 1")
        assert sample["rows"], "no functions"
        row = sample["rows"][0]

        r = await generic_idalib.runner.sql(f"SELECT start_ea, name FROM funcs WHERE start_ea = {row['start_ea']}")
        assert r["rows"] == [row]

    async def test_filter_by_name(self, generic_idalib: GenericIdalib) -> None:
        sample = await generic_idalib.runner.sql("SELECT start_ea, name FROM funcs LIMIT 1")
        assert sample["rows"], "no functions"
        row = sample["rows"][0]
        name = row["name"].replace("'", "''")

        r = await generic_idalib.runner.sql(f"SELECT start_ea, name FROM funcs WHERE name = '{name}'")
        assert r["rows"] == [row]

    async def test_hex_transport(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT start_ea, end_ea, size, flags FROM funcs LIMIT 3")
        for row in r["rows"]:
            for col in ("start_ea", "end_ea", "size", "flags"):
                assert isinstance(row[col], str) and row[col].startswith("0x"), f"{col}: {row[col]}"

    async def test_type_source_vocabulary(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT DISTINCT type_source FROM funcs")
        sources = {row["type_source"] for row in r["rows"]}
        allowed = {None, "user/til", "hexrays", "ida"}
        assert sources <= allowed, f"unexpected type sources: {sources - allowed}"


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


class TestNames:
    async def test_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM names")
        assert r["rows"][0]["cnt"] > 0

    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(names)")
        cols = [row["name"] for row in r["rows"]]
        assert cols == ["address", "name", "is_auto"]

    async def test_filter(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM names WHERE name LIKE 'sub_%' LIMIT 5")
        for row in r["rows"]:
            assert row["name"].startswith("sub_")
            assert row["address"].startswith("0x")
            assert row["is_auto"] in (0, 1)

    async def test_is_auto_shape(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT address, name, is_auto FROM names LIMIT 20")
        for row in r["rows"]:
            assert row["address"].startswith("0x")
            assert isinstance(row["name"], str)
            assert row["is_auto"] in (0, 1)

    async def test_filter_by_address(self, generic_idalib: GenericIdalib) -> None:
        sample = await generic_idalib.runner.sql("SELECT address, name FROM names LIMIT 1")
        assert sample["rows"], "no names"
        row = sample["rows"][0]

        r = await generic_idalib.runner.sql(f"SELECT address, name FROM names WHERE address = {row['address']}")
        assert r["rows"] == [row]

    async def test_filter_by_name(self, generic_idalib: GenericIdalib) -> None:
        sample = await generic_idalib.runner.sql("SELECT address, name FROM names LIMIT 1")
        assert sample["rows"], "no names"
        row = sample["rows"][0]
        name = row["name"].replace("'", "''")

        r = await generic_idalib.runner.sql(f"SELECT address, name FROM names WHERE name = '{name}'")
        assert r["rows"] == [row]


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------


class TestStrings:
    async def test_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM strings")
        assert r["rows"][0]["cnt"] > 0

    async def test_content(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM strings LIMIT 5")
        for row in r["rows"]:
            assert isinstance(row["string_value"], str)
            assert isinstance(row["address"], str) and row["address"].startswith("0x")

    async def test_lookup_by_address(self, generic_idalib: GenericIdalib) -> None:
        sample = await generic_idalib.runner.sql("SELECT address, length, type, string_value FROM strings LIMIT 1")
        assert sample["rows"], "no strings"
        row = sample["rows"][0]

        r = await generic_idalib.runner.sql(
            f"SELECT address, length, type, string_value FROM strings WHERE address = {row['address']}"
        )
        assert r["rows"] == [row]


# ---------------------------------------------------------------------------
# segments
# ---------------------------------------------------------------------------


class TestSegments:
    async def test_has_text_segment(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM segments ORDER BY start_ea")
        seg_names = [row["name"] for row in r["rows"]]
        assert any("text" in n.lower() for n in seg_names), f"no text segment in {seg_names}"

    async def test_hex_transport(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT start_ea, end_ea, size, perm FROM segments LIMIT 1")
        row = r["rows"][0]
        for col in ("start_ea", "end_ea", "size", "perm"):
            assert isinstance(row[col], str) and row[col].startswith("0x"), f"{col}: {row[col]}"

    async def test_has_import_segment(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        r = await generic_idalib.runner.sql("SELECT name FROM segments")
        seg_names = [row["name"].lower() for row in r["rows"]]
        assert any("import" in n or "extern" in n or "got" in n for n in seg_names), (
            f"no import/extern segment in {seg_names}"
        )


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------


class TestXrefs:
    async def test_to_func(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM xrefs WHERE to_ea = {ea} LIMIT 20")
        assert set(r["columns"]) == {"from_ea", "to_ea", "from_func", "type", "type_name", "is_code"}

    async def test_type_name(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(
            f"SELECT type, type_name, is_code FROM xrefs WHERE from_func = {ea} LIMIT 50"
        )
        names = {
            1: "offset",
            2: "write",
            3: "read",
            4: "text",
            5: "info",
            6: "enum",
            16: "call",
            17: "call",
            18: "jump",
            19: "jump",
            21: "flow",
        }
        for row in r["rows"]:
            assert row["type_name"] == names.get(int(row["type"]) & 0x1F)

    async def test_callers_via_type_name(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT type FROM xrefs WHERE to_ea = {ea} AND type_name = 'call'")
        for row in r["rows"]:
            assert int(row["type"]) & 0x1F in (16, 17)

    async def test_from_func(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM xrefs WHERE from_func = {ea} LIMIT 50")
        for row in r["rows"]:
            assert row["from_func"] == ea

    async def test_hex_transport(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM xrefs WHERE from_func = {ea} LIMIT 5")
        if r["rows"]:
            row = r["rows"][0]
            for col in ("from_ea", "to_ea", "from_func"):
                assert isinstance(row[col], str) and row[col].startswith("0x")

    async def test_to_import(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        imp = await generic_idalib.runner.sql("SELECT address FROM imports LIMIT 1")
        ea = imp["rows"][0]["address"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM xrefs WHERE to_ea = {ea} LIMIT 20")
        assert set(r["columns"]) == {"from_ea", "to_ea", "from_func", "type", "type_name", "is_code"}


# ---------------------------------------------------------------------------
# instructions
# ---------------------------------------------------------------------------


class TestInstructions:
    async def test_in_func(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM instructions WHERE func_ea = {ea}")
        assert len(r["rows"]) >= 1
        for row in r["rows"]:
            assert row["func_ea"] == ea
            assert row["mnemonic"]
            assert row["disasm"]

    async def test_single_address(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM instructions WHERE address = {ea}")
        assert len(r["rows"]) == 1
        assert r["rows"][0]["address"] == ea

    async def test_full_scan_with_limit(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM instructions LIMIT 10")
        assert len(r["rows"]) == 10

    async def test_hex_transport(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM instructions WHERE func_ea = {ea} LIMIT 3")
        for row in r["rows"]:
            for col in ("address", "func_ea", "size"):
                assert isinstance(row[col], str) and row[col].startswith("0x"), f"{col}: {row[col]}"


# ---------------------------------------------------------------------------
# heads
# ---------------------------------------------------------------------------


class TestHeads:
    async def test_in_func(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM heads WHERE func_ea = {ea}")
        assert len(r["rows"]) >= 1
        assert "code" in {row["type"] for row in r["rows"]}

    async def test_by_segment(self, generic_idalib: GenericIdalib) -> None:
        segs = await generic_idalib.runner.sql("SELECT name FROM segments LIMIT 1")
        seg_name = segs["rows"][0]["name"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM heads WHERE segment = '{seg_name}' LIMIT 10")
        assert len(r["rows"]) >= 1
        for row in r["rows"]:
            assert row["segment"] == seg_name

    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(heads)")
        cols = [row["name"] for row in r["rows"]]
        assert cols == ["address", "size", "type", "segment", "func_ea"]


# ---------------------------------------------------------------------------
# pseudocode
# ---------------------------------------------------------------------------


class TestPseudocode:
    async def test_by_func_ea(self, generic_idalib: GenericIdalib) -> None:
        ea = await _func_ea_with_pseudocode(generic_idalib)
        r = await generic_idalib.runner.sql(f"SELECT * FROM pseudocode WHERE func_ea = {ea}")
        assert len(r["rows"]) >= 1
        assert set(r["columns"]) == {
            "n",
            "type",
            "func_ea",
            "line",
            "ea",
            "placement",
            "valid_placements",
            "is_orphan",
        }
        for row in r["rows"]:
            assert row["func_ea"] == ea
            assert isinstance(row["n"], int)
            assert row["type"] in ("code", "comment")
            assert isinstance(row["line"], str)

    async def test_has_addresses(self, generic_idalib: GenericIdalib) -> None:
        func_ea, target_ea = await _addressable_pseudocode_target(generic_idalib)
        r = await generic_idalib.runner.sql(f"SELECT ea FROM pseudocode WHERE func_ea = {func_ea} AND ea IS NOT NULL")
        assert len(r["rows"]) >= 1
        assert any(row["ea"] == target_ea for row in r["rows"])
        for row in r["rows"]:
            assert isinstance(row["ea"], str) and row["ea"].startswith("0x")

    async def test_valid_placements_populated(self, generic_idalib: GenericIdalib) -> None:
        ea = await _func_ea_with_pseudocode(generic_idalib)
        r = await generic_idalib.runner.sql(
            f"SELECT n, type, line, ea, valid_placements FROM pseudocode WHERE func_ea = {ea}"
        )
        rows = [row for row in r["rows"] if row["type"] == "code"]
        # At least some lines should have valid_placements.
        with_placements = [row for row in rows if row["valid_placements"] is not None]
        assert len(with_placements) >= 1
        # Every non-NULL valid_placements is a comma-separated list of known names.
        known = {
            "semi",
            "block1",
            "block2",
            "curly1",
            "curly2",
            "brace1",
            "brace2",
            "else",
            "do",
            "colon",
            "asm",
        } | {f"arg{i}" for i in range(1, 65)}
        for row in with_placements:
            names = row["valid_placements"].split(",")
            assert all(n in known for n in names), f"unexpected placement in {names}"
        # Lines with ea and semi placement should exist (regular statements).
        semi_lines = [row for row in rows if row["valid_placements"] and "semi" in row["valid_placements"]]
        assert len(semi_lines) >= 1
        for row in semi_lines:
            assert row["ea"] is not None

    async def test_n_sequential(self, generic_idalib: GenericIdalib) -> None:
        ea = await _func_ea_with_pseudocode(generic_idalib)
        r = await generic_idalib.runner.sql(f"SELECT n FROM pseudocode WHERE func_ea = {ea}")
        nums = [row["n"] for row in r["rows"]]
        assert nums == list(range(1, len(nums) + 1))

    async def test_requires_pushdown(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECT * FROM pseudocode")
        assert "requires" in msg.lower() or "where" in msg.lower()

    async def test_subquery_by_name(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea, name FROM funcs WHERE name NOT LIKE 'sub_%' LIMIT 1")
        if not func["rows"]:
            pytest.skip("no named functions")
        name = func["rows"][0]["name"]
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(
            f"SELECT func_ea, line FROM pseudocode WHERE func_ea = (SELECT start_ea FROM funcs WHERE name = '{name}')"
        )
        assert len(r["rows"]) >= 1
        assert r["rows"][0]["func_ea"] == ea

    async def test_ea_pushdown(self, generic_idalib: GenericIdalib) -> None:
        func_ea, target_ea = await _addressable_pseudocode_target(generic_idalib)
        r = await generic_idalib.runner.sql(f"SELECT func_ea, n, line, ea FROM pseudocode WHERE ea = {target_ea}")
        assert len(r["rows"]) >= 1
        for row in r["rows"]:
            assert row["func_ea"] == func_ea
            assert row["ea"] == target_ea

    async def test_ea_pushdown_no_func(self, generic_idalib: GenericIdalib) -> None:
        with pytest.raises(AssertionError, match="no function containing"):
            await generic_idalib.runner.sql("SELECT * FROM pseudocode WHERE ea = 0xDEAD")


# ---------------------------------------------------------------------------
# bin_search
# ---------------------------------------------------------------------------


class TestBinSearch:
    async def test_search_bytes(self, generic_idalib: GenericIdalib) -> None:
        funcs = await generic_idalib.runner.sql("SELECT start_ea FROM funcs ORDER BY start_ea LIMIT 1")
        ea = funcs["rows"][0]["start_ea"]
        hex_str = await generic_idalib.runner.exec(f"""\
import ida_bytes
raw = ida_bytes.get_bytes({ea}, 8)
_result_ = raw.hex().upper()
""")
        pattern = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
        r = await generic_idalib.runner.sql(f"SELECT * FROM bin_search WHERE pattern = '{pattern}' LIMIT 20")
        assert len(r["rows"]) >= 1
        assert any(row["address"] == ea for row in r["rows"])

    async def test_no_pattern_errors(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECT * FROM bin_search")
        assert "pattern" in msg.lower()


# ---------------------------------------------------------------------------
# scalar functions
# ---------------------------------------------------------------------------


class TestScalarFunctions:
    async def test_func_at(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea, name FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        name = func["rows"][0]["name"]
        r = await generic_idalib.runner.sql(f"SELECT func_at({ea}) as fname")
        assert r["rows"][0]["fname"] == name

    async def test_func_start(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT func_start({ea})")
        assert r["rows"][0][r["columns"][0]] == int(ea, 16)

    async def test_name_at(self, generic_idalib: GenericIdalib) -> None:
        n = await generic_idalib.runner.sql("SELECT address, name FROM names LIMIT 1")
        ea = n["rows"][0]["address"]
        name = n["rows"][0]["name"]
        r = await generic_idalib.runner.sql(f"SELECT name_at({ea}) as n")
        assert r["rows"][0]["n"] == name

    async def test_hex(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT hex(255) as h")
        assert r["rows"][0]["h"] == "0xff"

    async def test_segment_at(self, generic_idalib: GenericIdalib) -> None:
        func = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        ea = func["rows"][0]["start_ea"]
        r = await generic_idalib.runner.sql(f"SELECT segment_at({ea}) as seg")
        assert r["rows"][0]["seg"] is not None

    async def test_func_flag(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT func_flag('thunk') as f")
        assert r["rows"][0]["f"] == 0x80

    async def test_func_flag_invalid(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECT func_flag('bogus') as f")
        assert "unknown" in msg.lower()


# ---------------------------------------------------------------------------
# views
# ---------------------------------------------------------------------------


class TestViews:
    async def test_callers(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM callers LIMIT 10")
        assert set(r["columns"]) == {"func_addr", "func_name", "caller_addr", "caller_name", "caller_func"}
        assert len(r["rows"]) >= 1

    async def test_callees(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM callees LIMIT 10")
        assert set(r["columns"]) == {"func_addr", "func_name", "callee_addr", "callee_name", "callee_func"}
        assert len(r["rows"]) >= 1

    async def test_string_refs(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM string_refs LIMIT 10")
        assert set(r["columns"]) == {
            "string_addr",
            "string_value",
            "string_length",
            "ref_addr",
            "func_addr",
            "func_name",
        }

    async def test_string_refs_include_function_context(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT string_value, func_name FROM string_refs WHERE func_name IS NOT NULL LIMIT 10"
        )
        assert len(r["rows"]) >= 1
        for row in r["rows"]:
            assert row["func_name"]


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


class TestTypes:
    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(types)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "ordinal",
            "tid",
            "name",
            "kind",
            "size",
            "alignment",
            "unpadded_size",
            "member_count",
            "is_typedef",
            "is_forward_decl",
            "definition",
            "resolved_name",
            "resolved_ordinal",
            "source",
        ):
            assert expected in cols

    async def test_count_query(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM types")
        assert r["rows"][0]["cnt"] >= 0

    async def test_select_limit(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT ordinal, name, source, kind, is_typedef, is_forward_decl FROM types LIMIT 5"
        )
        assert len(r["rows"]) <= 5
        for row in r["rows"]:
            assert isinstance(row["ordinal"], int)
            assert row["source"] == "local"
            assert row["kind"] in {
                "struct",
                "union",
                "enum",
                "func",
                "ptr",
                "array",
                "bitfield",
                "typedef",
                "other",
            }
            assert row["is_typedef"] in (0, 1)
            assert row["is_forward_decl"] in (0, 1)

    async def test_source_is_local(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT count(*) AS cnt FROM types WHERE source != 'local' OR source IS NULL"
        )
        assert r["rows"][0]["cnt"] == 0

    async def test_typedef_resolution_excludes_self(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT count(*) AS cnt FROM types "
            "WHERE is_typedef = 1 "
            "AND ((resolved_name IS NOT NULL AND resolved_name = name) "
            "OR (resolved_ordinal IS NOT NULL AND resolved_ordinal = ordinal))"
        )
        assert r["rows"][0]["cnt"] == 0

    async def test_forward_decls_keep_specific_kind(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT name, kind, definition FROM types WHERE is_forward_decl = 1 LIMIT 20"
        )
        for row in r["rows"]:
            assert row["kind"] in {"struct", "union", "enum"}
            if row["name"]:
                assert row["definition"] is not None and row["name"] in row["definition"]

    async def test_forward_decl_definitions_are_not_lossy(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT count(*) AS cnt FROM types "
            "WHERE is_forward_decl = 1 AND definition IN ('struct;', 'union;', 'enum;')"
        )
        assert r["rows"][0]["cnt"] == 0

    async def test_resolved_metadata_only_appears_on_typedef_rows(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT count(*) AS cnt FROM types "
            "WHERE is_typedef = 0 AND (resolved_name IS NOT NULL OR resolved_ordinal IS NOT NULL)"
        )
        assert r["rows"][0]["cnt"] == 0

    async def test_forward_decl_shape(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT count(*) AS cnt FROM types "
            "WHERE is_forward_decl = 1 "
            "AND (size IS NOT NULL OR alignment IS NOT NULL OR unpadded_size IS NOT NULL OR member_count IS NOT NULL)"
        )
        assert r["rows"][0]["cnt"] == 0


class TestTypesMembers:
    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(types_struct_members)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "type_ordinal",
            "type_name",
            "member_index",
            "member_name",
            "offset",
            "offset_bits",
            "size",
            "size_bits",
            "member_type",
            "is_bitfield",
            "tafld_bits",
            "comment",
        ):
            assert expected in cols

    async def test_pushdown_by_ordinal(self, generic_idalib: GenericIdalib) -> None:
        # Find a struct with members.
        r = await generic_idalib.runner.sql(
            "SELECT ordinal, name FROM types WHERE kind = 'struct' AND member_count > 0 LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no structs with members in IDB")
        ordinal = r["rows"][0]["ordinal"]
        name = r["rows"][0]["name"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_struct_members WHERE type_ordinal = {ordinal}")
        assert len(r2["rows"]) > 0
        for row in r2["rows"]:
            assert row["type_ordinal"] == ordinal
            assert row["type_name"] == name
            assert isinstance(row["member_index"], int)
            assert isinstance(row["member_name"], str)

    async def test_pushdown_by_name(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT name, member_count FROM types WHERE kind = 'struct' AND member_count > 0 LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no structs with members in IDB")
        name = r["rows"][0]["name"]
        expected_count = r["rows"][0]["member_count"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_struct_members WHERE type_name = '{name}'")
        assert len(r2["rows"]) == expected_count

    async def test_full_scan_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) AS cnt FROM types_struct_members")
        assert r["rows"][0]["cnt"] >= 0

    async def test_member_index_is_zero_based(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT type_ordinal, min(member_index) AS mi FROM types_struct_members GROUP BY type_ordinal LIMIT 5"
        )
        for row in r["rows"]:
            assert row["mi"] == 0

    async def test_udm_flag_scalar(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT udm_flag('baseclass') AS v")
        assert r["rows"][0]["v"] == 0x0020


class TestTypesEnumValues:
    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(types_enum_values)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "type_ordinal",
            "type_name",
            "value_index",
            "value_name",
            "value",
            "comment",
        ):
            assert expected in cols

    async def test_pushdown_by_ordinal(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT ordinal, name FROM types WHERE kind = 'enum' AND member_count > 0 LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no enums with values in IDB")
        ordinal = r["rows"][0]["ordinal"]
        name = r["rows"][0]["name"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_enum_values WHERE type_ordinal = {ordinal}")
        assert len(r2["rows"]) > 0
        for row in r2["rows"]:
            assert row["type_ordinal"] == ordinal
            assert row["type_name"] == name
            assert isinstance(row["value"], str) and row["value"].startswith("0x")

    async def test_pushdown_by_name(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT name, member_count FROM types WHERE kind = 'enum' AND member_count > 0 LIMIT 1"
        )
        if not r["rows"]:
            pytest.skip("no enums with values in IDB")
        name = r["rows"][0]["name"]
        expected_count = r["rows"][0]["member_count"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_enum_values WHERE type_name = '{name}'")
        assert len(r2["rows"]) == expected_count

    async def test_full_scan_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) AS cnt FROM types_enum_values")
        assert r["rows"][0]["cnt"] >= 0

    async def test_value_index_is_zero_based(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT type_ordinal, min(value_index) AS mi FROM types_enum_values GROUP BY type_ordinal LIMIT 5"
        )
        for row in r["rows"]:
            assert row["mi"] == 0


class TestTypesFuncArgs:
    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(types_func_args)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "type_ordinal",
            "type_name",
            "arg_index",
            "arg_name",
            "arg_type",
            "calling_conv",
        ):
            assert expected in cols

    async def test_pushdown_by_ordinal(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT ordinal, name FROM types WHERE kind = 'func' LIMIT 1")
        if not r["rows"]:
            pytest.skip("no function types in IDB")
        ordinal = r["rows"][0]["ordinal"]
        name = r["rows"][0]["name"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_func_args WHERE type_ordinal = {ordinal}")
        assert len(r2["rows"]) > 0
        # First row should be the return type.
        ret_row = [row for row in r2["rows"] if row["arg_index"] == -1]
        assert len(ret_row) == 1
        assert ret_row[0]["arg_name"] == "(return)"
        assert ret_row[0]["calling_conv"] is not None
        for row in r2["rows"]:
            assert row["type_ordinal"] == ordinal
            assert row["type_name"] == name

    async def test_pushdown_by_name(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT name FROM types WHERE kind = 'func' LIMIT 1")
        if not r["rows"]:
            pytest.skip("no function types in IDB")
        name = r["rows"][0]["name"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM types_func_args WHERE type_name = '{name}'")
        assert len(r2["rows"]) > 0

    async def test_full_scan_count(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT count(*) AS cnt FROM types_func_args")
        assert r["rows"][0]["cnt"] >= 0

    async def test_arg_index_includes_return(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT type_ordinal, min(arg_index) AS mi FROM types_func_args GROUP BY type_ordinal LIMIT 5"
        )
        for row in r["rows"]:
            assert row["mi"] == -1

    async def test_param_rows_have_no_calling_conv(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM types_func_args WHERE arg_index >= 0 LIMIT 10")
        for row in r["rows"]:
            assert row["calling_conv"] is None


class TestCtreeLvars:
    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("PRAGMA table_info(ctree_lvars)")
        cols = [row["name"] for row in r["rows"]]
        for expected in (
            "func_ea",
            "idx",
            "name",
            "type",
            "comment",
            "size",
            "is_arg",
            "is_result",
            "is_stk_var",
            "is_reg_var",
            "stkoff",
        ):
            assert expected in cols

    async def test_pushdown_by_func_ea(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT start_ea FROM funcs LIMIT 1")
        if not r["rows"]:
            pytest.skip("no functions in IDB")
        ea = r["rows"][0]["start_ea"]

        r2 = await generic_idalib.runner.sql(f"SELECT * FROM ctree_lvars WHERE func_ea = {ea}")
        assert len(r2["rows"]) > 0
        for row in r2["rows"]:
            assert row["func_ea"] == ea
            assert isinstance(row["idx"], int)
            assert isinstance(row["name"], str)
            assert isinstance(row["type"], str)
            assert row["is_arg"] in (0, 1)

    async def test_requires_pushdown(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECT * FROM ctree_lvars")
        assert msg

    async def test_args_vs_locals(self, generic_idalib: GenericIdalib) -> None:
        # Find a function with arguments.
        r = await generic_idalib.runner.sql("SELECT start_ea FROM funcs WHERE arg_count > 0 LIMIT 1")
        if not r["rows"]:
            pytest.skip("no functions with args")
        ea = r["rows"][0]["start_ea"]

        r2 = await generic_idalib.runner.sql(f"SELECT name, is_arg FROM ctree_lvars WHERE func_ea = {ea}")
        args = [row for row in r2["rows"] if row["is_arg"] == 1]
        assert len(args) > 0


class TestDiscovery:
    async def test_sqlite_master_tables(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        names = [row["name"] for row in r["rows"]]
        for expected in (
            "funcs",
            "names",
            "segments",
            "strings",
            "imports",
            "db_info",
            "xrefs",
            "comments",
            "instructions",
            "pseudocode",
            "bin_search",
            "heads",
            "types",
            "types_struct_members",
            "types_enum_values",
            "types_func_args",
            "ctree_lvars",
        ):
            assert expected in names, f"{expected} not in sqlite_master"

    async def test_sqlite_master_views(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
        names = [row["name"] for row in r["rows"]]
        for expected in ("callers", "callees", "string_refs"):
            assert expected in names, f"view {expected} not in sqlite_master"


# ---------------------------------------------------------------------------
# composite queries
# ---------------------------------------------------------------------------


class TestCompositeQueries:
    async def test_func_instructions_join(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "SELECT f.name, i.disasm FROM funcs f "
            "JOIN instructions i ON i.func_ea = f.start_ea "
            "WHERE f.start_ea = (SELECT start_ea FROM funcs LIMIT 1) "
            "LIMIT 5",
        )
        assert len(r["rows"]) >= 1
        assert r["rows"][0]["name"]
        assert r["rows"][0]["disasm"]

    async def test_count_instructions_per_func(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql(
            "WITH sample_funcs AS ("
            "SELECT start_ea, name FROM funcs "
            "WHERE (flags & func_flag('thunk')) = 0 AND size >= 0x10 "
            "LIMIT 20"
            ") "
            "SELECT f.name, ("
            "SELECT count(*) FROM instructions i WHERE i.func_ea = f.start_ea"
            ") AS insn_count FROM sample_funcs f "
            "ORDER BY insn_count DESC LIMIT 5",
        )
        assert 1 <= len(r["rows"]) <= 5
        counts = [row["insn_count"] for row in r["rows"]]
        assert counts == sorted(counts, reverse=True)
        assert counts[0] > 0

    async def test_import_callers(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        imp = await generic_idalib.runner.sql("SELECT address, name FROM imports WHERE name IS NOT NULL LIMIT 1")
        assert imp["rows"], "no named imports"
        ea = imp["rows"][0]["address"]
        r = await generic_idalib.runner.sql(f"SELECT * FROM xrefs WHERE to_ea = {ea} LIMIT 10")
        assert set(r["columns"]) == {"from_ea", "to_ea", "from_func", "type", "type_name", "is_code"}


# ---------------------------------------------------------------------------
# hex transport (names non-hex)
# ---------------------------------------------------------------------------


class TestHexTransport:
    async def test_names_non_hex_name(self, generic_idalib: GenericIdalib) -> None:
        r = await generic_idalib.runner.sql("SELECT * FROM names LIMIT 1")
        row = r["rows"][0]
        assert isinstance(row["address"], str) and row["address"].startswith("0x")
        assert isinstance(row["name"], str) and not row["name"].startswith("0x")


# ---------------------------------------------------------------------------
# imports (property-gated)
# ---------------------------------------------------------------------------


class TestImports:
    async def test_count(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM imports")
        assert r["rows"][0]["cnt"] > 0

    async def test_has_modules(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        r = await generic_idalib.runner.sql("SELECT DISTINCT module FROM imports ORDER BY module")
        modules = [row["module"] for row in r["rows"]]
        assert len(modules) >= 1, "no import modules"

    async def test_columns(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        r = await generic_idalib.runner.sql("PRAGMA table_info(imports)")
        cols = [row["name"] for row in r["rows"]]
        assert "address" in cols
        assert "module" in cols
        assert "name" in cols

    async def test_named_imports(self, generic_idalib: GenericIdalib) -> None:
        await require_imports(generic_idalib)
        r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM imports WHERE name IS NOT NULL AND name != ''")
        named = r["rows"][0]["cnt"]
        total_r = await generic_idalib.runner.sql("SELECT count(*) as cnt FROM imports")
        total = total_r["rows"][0]["cnt"]
        assert named > total * 0.8, f"only {named}/{total} imports have names"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class TestErrors:
    async def test_bad_sql_syntax(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECTX * FROM funcs")
        assert msg

    async def test_nonexistent_table(self, generic_idalib: GenericIdalib) -> None:
        msg = await generic_idalib.runner.sql_err("SELECT * FROM nonexistent_table")
        assert msg
