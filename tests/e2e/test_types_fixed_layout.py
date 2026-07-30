"""E2E tests: struct fixed layout -- size/offset preservation on mutation.

Verifies that:
- structs created through the bridge have fixed layout (is_fixed = 1)
- fixed-layout structs preserve size and member offsets on delete/retype
- explicit size control via UPDATE types SET size works
- is_fixed is readable and writable
"""

import pytest

from tests.e2e.conftest import GenericIdalib

pytestmark = [pytest.mark.asyncio(loop_scope="module")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_struct(gi: GenericIdalib, decl: str) -> int:
    """Create a struct via parse_type and return its ordinal."""
    r = await gi.runner.sql(f"SELECT parse_type('{decl}') AS ordinal")
    return r["rows"][0]["ordinal"]


async def _type_info(gi: GenericIdalib, ordinal: int) -> dict:
    r = await gi.runner.sql(
        f"SELECT size, alignment, unpadded_size, member_count, is_fixed FROM types WHERE ordinal = {ordinal}"
    )
    assert r["rows"], f"type ordinal {ordinal} not found"
    return r["rows"][0]


async def _members(gi: GenericIdalib, ordinal: int) -> list[dict]:
    r = await gi.runner.sql(
        f"SELECT member_index, member_name, offset, size, member_type "
        f"FROM types_struct_members WHERE type_ordinal = {ordinal}"
    )
    return r["rows"]


async def _cleanup(gi: GenericIdalib, ordinal: int) -> None:
    await gi.runner.sql(f"DELETE FROM types WHERE ordinal = {ordinal}")


# ---------------------------------------------------------------------------
# Fixed layout is the default
# ---------------------------------------------------------------------------


class TestFixedLayoutDefault:
    """Structs created through the bridge have is_fixed = 1."""

    async def test_insert_type_is_fixed(self, generic_idalib_w: GenericIdalib) -> None:
        await generic_idalib_w.runner.sql("INSERT INTO types (name, kind) VALUES ('e2e_fixed_insert', 'struct')")
        r = await generic_idalib_w.runner.sql("SELECT ordinal, is_fixed FROM types WHERE name = 'e2e_fixed_insert'")
        ordinal = r["rows"][0]["ordinal"]
        try:
            assert r["rows"][0]["is_fixed"] == 1
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_parse_type_is_fixed(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_fixed_parse { int x; int y; };")
        try:
            info = await _type_info(generic_idalib_w, ordinal)
            assert info["is_fixed"] == 1
        finally:
            await _cleanup(generic_idalib_w, ordinal)


# ---------------------------------------------------------------------------
# Fixed layout preserves size and offsets on mutation
# ---------------------------------------------------------------------------


class TestFixedLayoutPreservation:
    """Deleting or retyping members on a fixed struct preserves size and offsets."""

    async def test_delete_last_member(self, generic_idalib_w: GenericIdalib) -> None:
        """Delete trailing member -- size stays."""
        ordinal = await _create_struct(
            generic_idalib_w, "struct e2e_del_last { uint32_t a; uint32_t b; uint32_t c; uint64_t last; };"
        )
        try:
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x18"

            await generic_idalib_w.runner.sql(
                f"DELETE FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 3"
            )

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x18"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_delete_middle_member(self, generic_idalib_w: GenericIdalib) -> None:
        """Delete middle member -- size stays, remaining offsets unchanged."""
        ordinal = await _create_struct(
            generic_idalib_w, "struct e2e_del_mid { uint32_t a; uint32_t b; uint32_t c; uint32_t d; };"
        )
        try:
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"

            await generic_idalib_w.runner.sql(
                f"DELETE FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 1"
            )

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"
            offsets = {m["member_name"]: m["offset"] for m in await _members(generic_idalib_w, ordinal)}
            assert offsets == {"a": "0x0", "c": "0x8", "d": "0xc"}
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_delete_alignment_driving_member(self, generic_idalib_w: GenericIdalib) -> None:
        """Delete the member that caused padding -- size stays."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_del_align { uint32_t x; uint64_t big; };")
        try:
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"

            await generic_idalib_w.runner.sql(
                f"DELETE FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 1"
            )

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_retype_smaller(self, generic_idalib_w: GenericIdalib) -> None:
        """Retype last member to smaller type -- size stays."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_retype { uint64_t a; uint64_t b; };")
        try:
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"

            await generic_idalib_w.runner.sql(
                f"UPDATE types_struct_members SET member_type = 'uint8_t' "
                f"WHERE type_ordinal = {ordinal} AND member_index = 1"
            )

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x10"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_retype_preserves_offsets(self, generic_idalib_w: GenericIdalib) -> None:
        """Retype first member smaller -- subsequent members keep offsets."""
        ordinal = await _create_struct(
            generic_idalib_w, "struct e2e_retype_off { uint64_t a; uint64_t b; uint64_t c; };"
        )
        try:
            await generic_idalib_w.runner.sql(
                f"UPDATE types_struct_members SET member_type = 'uint8_t' "
                f"WHERE type_ordinal = {ordinal} AND member_index = 0"
            )

            offsets = {m["member_name"]: m["offset"] for m in await _members(generic_idalib_w, ordinal)}
            assert offsets["b"] == "0x8"
            assert offsets["c"] == "0x10"
        finally:
            await _cleanup(generic_idalib_w, ordinal)


# ---------------------------------------------------------------------------
# Explicit size control
# ---------------------------------------------------------------------------


class TestExplicitSizeControl:
    """UPDATE types SET size = N on fixed structs."""

    async def test_grow(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_grow { uint32_t a; uint32_t b; };")
        try:
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x8"

            await generic_idalib_w.runner.sql(f"UPDATE types SET size = 0x100 WHERE ordinal = {ordinal}")

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x100"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_shrink_to_content(self, generic_idalib_w: GenericIdalib) -> None:
        """Shrink to exactly fit content (after growing)."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_shrink { uint32_t a; uint32_t b; };")
        try:
            await generic_idalib_w.runner.sql(f"UPDATE types SET size = 0x100 WHERE ordinal = {ordinal}")
            await generic_idalib_w.runner.sql(f"UPDATE types SET size = 0x8 WHERE ordinal = {ordinal}")

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x8"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_too_small_raises(self, generic_idalib_w: GenericIdalib) -> None:
        """Size smaller than content fails."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_toosmall { uint64_t a; uint64_t b; };")
        try:
            err = await generic_idalib_w.runner.sql_err(f"UPDATE types SET size = 4 WHERE ordinal = {ordinal}")
            assert "set_struct_size" in err
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_size_on_non_fixed_raises(self, generic_idalib_w: GenericIdalib) -> None:
        """Setting size on a non-fixed struct fails with clear error."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_nonfixed { uint32_t a; };")
        try:
            # Unfix first
            await generic_idalib_w.runner.sql(f"UPDATE types SET is_fixed = 0 WHERE ordinal = {ordinal}")
            err = await generic_idalib_w.runner.sql_err(f"UPDATE types SET size = 0x100 WHERE ordinal = {ordinal}")
            assert "is_fixed" in err
        finally:
            await _cleanup(generic_idalib_w, ordinal)


# ---------------------------------------------------------------------------
# is_fixed is writable
# ---------------------------------------------------------------------------


class TestIsFixedWritable:
    """Agent can toggle is_fixed and observe the effect."""

    async def test_unfix_recalculates(self, generic_idalib_w: GenericIdalib) -> None:
        """Setting is_fixed = 0 triggers layout recalculation."""
        # Create struct with trailing padding (grow it beyond content)
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_unfix { uint32_t a; uint32_t b; };")
        try:
            await generic_idalib_w.runner.sql(f"UPDATE types SET size = 0x100 WHERE ordinal = {ordinal}")
            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x100"

            # Unfix -- IDA recalculates to natural size
            await generic_idalib_w.runner.sql(f"UPDATE types SET is_fixed = 0 WHERE ordinal = {ordinal}")

            info = await _type_info(generic_idalib_w, ordinal)
            assert info["is_fixed"] == 0
            assert info["size"] == "0x8"  # natural size of two uint32s
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_refix_preserves_subsequent_mutations(self, generic_idalib_w: GenericIdalib) -> None:
        """After re-fixing, mutations are safe again."""
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_refix { uint64_t a; uint64_t b; uint64_t c; };")
        try:
            # Unfix then refix
            await generic_idalib_w.runner.sql(f"UPDATE types SET is_fixed = 0 WHERE ordinal = {ordinal}")
            await generic_idalib_w.runner.sql(f"UPDATE types SET is_fixed = 1 WHERE ordinal = {ordinal}")

            info = await _type_info(generic_idalib_w, ordinal)
            assert info["is_fixed"] == 1
            assert info["size"] == "0x18"

            # Delete last member -- size should be preserved
            await generic_idalib_w.runner.sql(
                f"DELETE FROM types_struct_members WHERE type_ordinal = {ordinal} AND member_index = 2"
            )

            assert (await _type_info(generic_idalib_w, ordinal))["size"] == "0x18"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_is_fixed_on_union_raises(self, generic_idalib_w: GenericIdalib) -> None:
        """Unions cannot be fixed (IDA limitation)."""
        await generic_idalib_w.runner.sql("INSERT INTO types (name, kind) VALUES ('e2e_union_fix', 'union')")
        r = await generic_idalib_w.runner.sql("SELECT ordinal FROM types WHERE name = 'e2e_union_fix'")
        ordinal = r["rows"][0]["ordinal"]
        try:
            err = await generic_idalib_w.runner.sql_err(f"UPDATE types SET is_fixed = 1 WHERE ordinal = {ordinal}")
            assert "union" in err.lower()
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_is_fixed_on_enum_raises(self, generic_idalib_w: GenericIdalib) -> None:
        """Enums cannot be fixed."""
        await generic_idalib_w.runner.sql("INSERT INTO types (name, kind) VALUES ('e2e_enum_fix', 'enum')")
        r = await generic_idalib_w.runner.sql("SELECT ordinal FROM types WHERE name = 'e2e_enum_fix'")
        ordinal = r["rows"][0]["ordinal"]
        try:
            err = await generic_idalib_w.runner.sql_err(f"UPDATE types SET is_fixed = 1 WHERE ordinal = {ordinal}")
            assert err  # should get an error
        finally:
            await _cleanup(generic_idalib_w, ordinal)


# ---------------------------------------------------------------------------
# tid_name() scalar: resolve type/member tids back to names
# ---------------------------------------------------------------------------


class TestTidName:
    """tid_name() resolves type and member tids to names; NULL for non-tids."""

    async def test_resolves_member_and_type(self, generic_idalib_w: GenericIdalib) -> None:
        ordinal = await _create_struct(generic_idalib_w, "struct e2e_tidname { int alpha; int beta; };")
        try:
            # member tid -> fully-qualified "Struct.member"
            r = await generic_idalib_w.runner.sql(
                f"SELECT tid_name(tid) AS n FROM types_struct_members "
                f"WHERE type_ordinal = {ordinal} AND member_name = 'beta'"
            )
            assert r["rows"][0]["n"] == "e2e_tidname.beta"
            # type tid -> bare type name
            r = await generic_idalib_w.runner.sql(f"SELECT tid_name(tid) AS n FROM types WHERE ordinal = {ordinal}")
            assert r["rows"][0]["n"] == "e2e_tidname"
        finally:
            await _cleanup(generic_idalib_w, ordinal)

    async def test_non_tid_is_null(self, generic_idalib_w: GenericIdalib) -> None:
        r = await generic_idalib_w.runner.sql("SELECT tid_name(0) AS n")
        assert r["rows"][0]["n"] is None
