"""Type virtual table: types."""

from collections.abc import Iterator
from typing import Any

from ..rowid import pack_rowid, unpack_rowid
from .base import (
    BaseCursor,
    ColumnSpec,
    ConstraintArgSpec,
    ConstraintPlanSpec,
    apply_schema_specs,
    decode_u64_update_fields,
    find_eq_constraint,
    mark_constraint_used,
    reject_readonly_update,
)

# BADSIZE in IDA (size_t(-1) on 64-bit).
_BADSIZE = 0xFFFFFFFFFFFFFFFF


def _classify_type(tif: Any) -> str:
    """Classify a tinfo_t into a compact kind string.

    Resolved kinds win for common RE-visible categories. Typedef aliases to
    structs/unions/enums/funcs/pointers/arrays/bitfields keep that resolved kind
    and expose alias-ness separately via ``is_typedef``.
    """
    if tif.is_forward_struct() or tif.is_struct():
        return "struct"
    if tif.is_forward_union() or tif.is_union():
        return "union"
    if tif.is_forward_enum() or tif.is_enum():
        return "enum"
    if tif.is_func():
        return "func"
    if tif.is_ptr():
        return "ptr"
    if tif.is_array():
        return "array"
    if tif.is_bitfield():
        return "bitfield"
    if tif.is_typedef():
        return "typedef"
    return "other"


def _normalize_size(raw: Any) -> int | None:
    if raw is None:
        return None
    value = int(raw)
    if value == _BADSIZE:
        return None
    return value


def _normalize_count(raw: Any) -> int | None:
    if raw is None:
        return None
    value = int(raw)
    if value < 0 or value == _BADSIZE:
        return None
    return value


# ---------------------------------------------------------------------------
# types (full scan, no pushdown)
# ---------------------------------------------------------------------------

# Row: (
#   ordinal, tid, name, kind, size, alignment, unpadded_size, member_count,
#   is_typedef, is_forward_decl, is_fixed, definition, resolved_name,
#   resolved_ordinal, source,
# )
type TypesRow = tuple[
    int,
    int | None,
    str,
    str,
    int | None,
    int | None,
    int | None,
    int | None,
    int,
    int,
    int,
    str | None,
    str | None,
    int | None,
    str,
]


class TypesModule:
    COLUMN_SPECS = {
        "ordinal": ColumnSpec(rowid=True),
        "tid": ColumnSpec(hex=True, u64=True),
        "name": ColumnSpec(writable=True),
        "size": ColumnSpec(hex=True, writable=True),
        "alignment": ColumnSpec(hex=True),
        "unpadded_size": ColumnSpec(hex=True),
        "is_fixed": ColumnSpec(writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x(ordinal INTEGER, tid INTEGER, name TEXT, kind TEXT, "
            "size INTEGER, alignment INTEGER, unpadded_size INTEGER, "
            "member_count INTEGER, is_typedef INTEGER, is_forward_decl INTEGER, "
            "is_fixed INTEGER, definition TEXT, resolved_name TEXT, "
            "resolved_ordinal INTEGER, source TEXT)"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, TypesCursor, TypesTable, table_name=tablename)
        return schema, TypesTable()

    Connect = Create


class TypesTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 10_000
        ii.estimatedRows = 1_000
        return True

    def Open(self) -> "TypesCursor":
        return TypesCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE: name, size, is_fixed."""
        import ida_typeinf

        reject_readonly_update(self, fields)
        ordinal = rowid
        new_name = fields[2]
        new_size = fields[4]
        new_is_fixed = fields[10]

        has_change = new_name is not None or new_size is not None or new_is_fixed is not None
        if not has_change:
            return

        result = _resolve_writable_type(ordinal=ordinal)
        _til, tif, ord_, current_name = result

        # Capture original size before any mutations (APSW passes current values
        # for columns not in SET -- we compare against this to detect real changes).
        original_size = _normalize_size(tif.get_size())

        # Handle is_fixed change first (size write depends on it).
        if new_is_fixed is not None:
            if not isinstance(new_is_fixed, int) or new_is_fixed not in (0, 1):
                msg = "types.is_fixed must be 0 or 1"
                raise ValueError(msg)
            want_fixed = new_is_fixed == 1
            cur_fixed = tif.is_fixed_struct() if (tif.is_struct() and not tif.is_forward_decl()) else False
            if want_fixed != cur_fixed:
                if not tif.is_udt() or tif.is_forward_decl():
                    msg = f"is_fixed requires a struct type (ordinal {ord_})"
                    raise ValueError(msg)
                if tif.is_union():
                    msg = "is_fixed cannot be set on unions (IDA limitation)"
                    raise ValueError(msg)
                code = tif.set_fixed_struct(want_fixed)
                if code != ida_typeinf.TERR_OK:
                    msg = f"set_fixed_struct failed for ordinal {ord_}: {code}"
                    raise ValueError(msg)
                if want_fixed:
                    # Lock in the current size when fixing.
                    rc = tif.set_struct_size(tif.get_size())
                    if rc != ida_typeinf.TERR_OK:
                        msg = f"set_struct_size failed for ordinal {ord_}: {rc}"
                        raise ValueError(msg)

        # Handle size change (skip if value matches original).
        if new_size is not None:
            if not isinstance(new_size, int) or new_size < 0:
                msg = "types.size must be a non-negative INTEGER"
                raise ValueError(msg)
            if new_size != original_size:
                if not tif.is_udt() or tif.is_forward_decl():
                    msg = f"size requires a struct type (ordinal {ord_})"
                    raise ValueError(msg)
                if not tif.is_fixed_struct():
                    msg = f"size can only be set on fixed structs; set is_fixed = 1 first (ordinal {ord_})"
                    raise ValueError(msg)
                code = tif.set_struct_size(new_size)
                if code != ida_typeinf.TERR_OK:
                    msg = f"set_struct_size({new_size:#x}) failed for ordinal {ord_}: {code}"
                    raise ValueError(msg)

        # Handle rename (skip if value matches current).
        if new_name is not None and new_name != current_name:
            if not isinstance(new_name, str):
                msg = "types.name must be TEXT"
                raise ValueError(msg)
            if not new_name:
                msg = "types does not support setting name to empty string"
                raise ValueError(msg)
            code = tif.rename_type(new_name)
            if code != ida_typeinf.TERR_OK:
                msg = f"rename_type failed for ordinal {ord_}: {code}"
                raise ValueError(msg)

    def UpdateDeleteRow(self, rowid: int) -> None:
        """Handle DELETE: remove a type by ordinal."""
        import ida_typeinf

        ordinal = rowid
        til = ida_typeinf.get_idati()
        if til is None:
            msg = "local type library not available"
            raise ValueError(msg)
        if not ida_typeinf.del_numbered_type(til, ordinal):
            msg = f"del_numbered_type failed for ordinal {ordinal}"
            raise ValueError(msg)

    def UpdateInsertRow(self, newrowid: int | None, fields: tuple[Any, ...]) -> int:
        """Handle INSERT: create an empty struct, union, or enum.

        Required columns: name.
        Optional: kind ('struct', 'union', 'enum'; defaults to 'struct').
        """
        import ida_typeinf

        name = fields[2]
        kind = fields[3]

        if not isinstance(name, str) or not name:
            msg = "types INSERT requires non-empty TEXT name"
            raise ValueError(msg)

        if kind is None:
            kind = "struct"
        if kind not in ("struct", "union", "enum"):
            msg = f"types INSERT kind must be 'struct', 'union', or 'enum', got '{kind}'"
            raise ValueError(msg)

        til = ida_typeinf.get_idati()
        if til is None:
            msg = "local type library not available"
            raise ValueError(msg)

        if ida_typeinf.get_type_ordinal(til, name) != 0:
            msg = f"type '{name}' already exists"
            raise ValueError(msg)

        ordinal = ida_typeinf.alloc_type_ordinal(til)
        if ordinal == 0:
            msg = "failed to allocate type ordinal"
            raise ValueError(msg)

        tif = ida_typeinf.tinfo_t()
        if kind == "enum":
            if not tif.create_enum():
                msg = "failed to create empty enum"
                raise ValueError(msg)
        else:
            if not tif.create_udt(kind == "union"):
                msg = f"failed to create empty {kind}"
                raise ValueError(msg)

        code = tif.set_numbered_type(til, ordinal, ida_typeinf.NTF_REPLACE, name)
        if code != ida_typeinf.TERR_OK:
            msg = f"set_numbered_type failed for '{name}': {code}"
            raise ValueError(msg)

        # Mark new structs as fixed so size is preserved on member mutations.
        if kind == "struct":
            _mark_struct_fixed(til, ordinal)

        return ordinal

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class TypesCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        self._set_iter(_types_all())


def _type_definition(tif: Any, ordinal: int, name: str) -> str | None:
    import ida_typeinf
    import idc

    flags = ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_SEMI
    if tif.is_forward_decl():
        definition = ida_typeinf.print_tinfo(None, 0, 0, flags, tif, name or None, None)
    else:
        definition = idc.GetLocalType(ordinal, flags)
    return definition or None


def _resolved_typedef_target(tif: Any, name: str, ordinal: int) -> tuple[str | None, int | None]:
    if not tif.is_typedef():
        return None, None

    resolved_name = tif.get_final_type_name() or None
    resolved_ordinal = int(tif.get_final_ordinal()) or None

    if resolved_name == name:
        resolved_name = None
    if resolved_ordinal == ordinal:
        resolved_ordinal = None

    return resolved_name, resolved_ordinal


def _types_all() -> Iterator[TypesRow]:
    """Enumerate all local types by ordinal."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    if til is None:
        return

    limit = ida_typeinf.get_ordinal_limit(til)
    if limit == 0 or limit == 0xFFFFFFFF:
        return

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
        kind = _classify_type(tif)
        is_typedef = 1 if tif.is_typedef() else 0
        is_forward_decl = 1 if tif.is_forward_decl() else 0
        is_fixed = 1 if (tif.is_struct() and not tif.is_forward_decl() and tif.is_fixed_struct()) else 0
        tid = int(tif.get_tid())

        size = _normalize_size(tif.get_size())
        alignment: int | None = None
        unpadded_size: int | None = None
        member_count: int | None = None
        if tif.is_udt() and not tif.is_forward_decl():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                alignment = int(udt.effalign)
            unpadded_size = _normalize_size(tif.get_unpadded_size())
            member_count = _normalize_count(tif.get_udt_nmembers())
        elif tif.is_enum():
            member_count = _normalize_count(tif.get_enum_nmembers())

        resolved_name, resolved_ordinal = _resolved_typedef_target(tif, name, ordinal)
        definition = _type_definition(tif, ordinal, name)

        yield (
            int(ordinal),
            tid,
            name,
            kind,
            size,
            alignment,
            unpadded_size,
            member_count,
            is_typedef,
            is_forward_decl,
            is_fixed,
            definition,
            resolved_name,
            resolved_ordinal,
            "local",
        )


# ---------------------------------------------------------------------------
# types_struct_members (struct/union field details)
# ---------------------------------------------------------------------------

_MEMBERS_IDX_FULL_SCAN = 0
_MEMBERS_IDX_ORDINAL_EQ = 1
_MEMBERS_IDX_NAME_EQ = 2

# Row: (
#   type_ordinal, type_name, member_index, member_name,
#   offset, offset_bits, size, size_bits,
#   member_type, is_bitfield, tafld_bits, comment, tid,
# )
type TypesStructMembersRow = tuple[
    int,
    str,
    int,
    str,
    int,
    int,
    int,
    int,
    str,
    int,
    int,
    str | None,
    int,
]


# 16 payload bits for the member/value/arg index. Type ordinals are small
# positives, so the value side has room to spare; more members than that raises.
_TYPE_INDEX_PAYLOAD_BITS = 16


class TypesStructMembersModule:
    COLUMN_SPECS = {
        "member_name": ColumnSpec(writable=True),
        "offset": ColumnSpec(hex=True),
        "size": ColumnSpec(hex=True),
        "member_type": ColumnSpec(writable=True),
        "tafld_bits": ColumnSpec(hex=True),
        "comment": ColumnSpec(writable=True),
        "tid": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x("
            "type_ordinal INTEGER, type_name TEXT, member_index INTEGER, member_name TEXT, "
            "offset INTEGER, offset_bits INTEGER, size INTEGER, size_bits INTEGER, "
            "member_type TEXT, is_bitfield INTEGER, tafld_bits INTEGER, comment TEXT, "
            "tid INTEGER)"
        )
        apply_schema_specs(
            schema, self.COLUMN_SPECS, TypesStructMembersCursor, TypesStructMembersTable, table_name=tablename
        )
        return schema, TypesStructMembersTable()

    Connect = Create


class TypesStructMembersTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ordinal_idx = find_eq_constraint(ii, 0)  # type_ordinal is column 0
        name_idx = find_eq_constraint(ii, 1)  # type_name is column 1
        if ordinal_idx is not None:
            mark_constraint_used(ii, ordinal_idx, 1)
            ii.idxNum = _MEMBERS_IDX_ORDINAL_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 10
        elif name_idx is not None:
            mark_constraint_used(ii, name_idx, 1)
            ii.idxNum = _MEMBERS_IDX_NAME_EQ
            ii.estimatedCost = 15
            ii.estimatedRows = 10
        else:
            ii.idxNum = _MEMBERS_IDX_FULL_SCAN
            ii.estimatedCost = 50_000
            ii.estimatedRows = 5_000
        return True

    def Open(self) -> "TypesStructMembersCursor":
        return TypesStructMembersCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on writable columns: member_name, member_type, comment."""
        import ida_typeinf

        reject_readonly_update(self, fields)
        ordinal, member_index = unpack_rowid(rowid, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)

        result = _resolve_writable_type(ordinal=ordinal)
        til, tif, ord_, _name = result
        if not tif.is_udt() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable struct/union"
            raise ValueError(msg)

        idx = member_index
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            msg = f"cannot load struct/union details for type ordinal {ord_}"
            raise ValueError(msg)
        if idx < 0 or idx >= len(udt):
            msg = f"member index {idx} out of range for type ordinal {ord_}"
            raise ValueError(msg)

        cur_member = udt[idx]
        new_member_name = fields[3]
        new_member_type = fields[8]
        new_comment = fields[11]

        if new_member_name is not None:
            if not isinstance(new_member_name, str):
                msg = "types_struct_members.member_name must be TEXT"
                raise ValueError(msg)
            member_name = new_member_name
            if not member_name:
                msg = "types_struct_members does not support setting member_name to empty string"
                raise ValueError(msg)
            if member_name != str(cur_member.name):
                code = tif.rename_udm(idx, member_name)
                if code != ida_typeinf.TERR_OK:
                    msg = f"rename_udm failed for type ordinal {ord_} member {idx}: {code}"
                    raise ValueError(msg)

        if new_member_type is not None:
            if not isinstance(new_member_type, str) or not new_member_type.strip():
                msg = "types_struct_members.member_type must be non-empty TEXT"
                raise ValueError(msg)
            # Parse the type string.
            new_tif = ida_typeinf.tinfo_t()
            if not new_tif.parse(str(new_member_type), None, ida_typeinf.PT_SIL):
                msg = f"types_struct_members.member_type: failed to parse type: {new_member_type!r}"
                raise ValueError(msg)
            code = tif.set_udm_type(idx, new_tif)
            if code != ida_typeinf.TERR_OK:
                msg = f"set_udm_type failed for type ordinal {ord_} member {idx}: {code}"
                raise ValueError(msg)

        if new_comment is not None and not isinstance(new_comment, str):
            msg = "types_struct_members.comment must be TEXT or NULL"
            raise ValueError(msg)
        comment = new_comment or ""
        current_comment = str(cur_member.cmt) if cur_member.cmt else ""
        if comment != current_comment:
            code = tif.set_udm_cmt(idx, comment, False)
            if code != ida_typeinf.TERR_OK:
                msg = f"set_udm_cmt failed for type ordinal {ord_} member {idx}: {code}"
                raise ValueError(msg)

    def UpdateInsertRow(self, newrowid: int | None, fields: tuple[Any, ...]) -> int:
        """Handle INSERT: add a struct/union member.

        Required columns: (type_ordinal or type_name), member_name, member_type, offset (bytes).
        """
        import ida_typeinf

        ordinal = fields[0]
        type_name = fields[1]
        member_name = fields[3]
        offset = fields[4]
        member_type = fields[8]

        if not isinstance(member_name, str) or not member_name:
            msg = "types_struct_members INSERT requires non-empty TEXT member_name"
            raise ValueError(msg)
        if not isinstance(member_type, str) or not member_type:
            msg = "types_struct_members INSERT requires non-empty TEXT member_type"
            raise ValueError(msg)
        if offset is None:
            msg = "types_struct_members INSERT requires offset (bytes)"
            raise ValueError(msg)

        _til, tif, ord_, _name = _resolve_writable_type(ordinal=ordinal, name=type_name)
        if not tif.is_udt() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable struct/union"
            raise ValueError(msg)

        offset_bits = int(offset) * 8
        code = tif.add_udm(member_name, member_type, offset_bits)
        if code != ida_typeinf.TERR_OK:
            msg = f"add_udm failed for type ordinal {ord_}: {code}"
            raise ValueError(msg)

        # Find the inserted member by offset. Unique in structs; in unions
        # (all offsets 0) this returns the first match.
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            msg = f"cannot read back struct details after add_udm for type ordinal {ord_}"
            raise ValueError(msg)
        for i in range(len(udt)):
            if int(udt[i].offset) == offset_bits:
                return pack_rowid(ord_, i, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)
        msg = f"inserted member not found at offset {offset_bits} in type ordinal {ord_}"
        raise ValueError(msg)

    def UpdateDeleteRow(self, rowid: int) -> None:
        """Handle DELETE: remove a struct/union member by rowid."""
        import ida_typeinf

        ordinal, member_index = unpack_rowid(rowid, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)

        result = _resolve_writable_type(ordinal=ordinal)
        _til, tif, ord_, _name = result
        if not tif.is_udt() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable struct/union"
            raise ValueError(msg)

        if member_index < 0 or member_index >= tif.get_udt_nmembers():
            msg = f"member index {member_index} out of range for type ordinal {ord_}"
            raise ValueError(msg)

        code = tif.del_udm(member_index)
        if code != ida_typeinf.TERR_OK:
            msg = f"del_udm failed for type ordinal {ord_} member {member_index}: {code}"
            raise ValueError(msg)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class TypesStructMembersCursor(BaseCursor):
    CONSTRAINT_PLANS = {
        _MEMBERS_IDX_ORDINAL_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_ordinal"),)),
        _MEMBERS_IDX_NAME_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_name"),)),
    }

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _MEMBERS_IDX_ORDINAL_EQ:
            self._set_iter(_members_by_ordinal(int(args["type_ordinal"])))
        elif indexnum == _MEMBERS_IDX_NAME_EQ:
            self._set_iter(_members_by_name(str(args["type_name"])))
        else:
            self._set_iter(_members_all())

    def Rowid(self) -> int:
        return pack_rowid(self._current[0], self._current[2], payload_bits=_TYPE_INDEX_PAYLOAD_BITS)


def _emit_members(tif: Any, ordinal: int, type_name: str) -> Iterator[TypesStructMembersRow]:
    """Yield member rows for a single UDT."""
    import ida_typeinf

    if not tif.is_udt() or tif.is_forward_decl():
        return

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return

    for i in range(len(udt)):
        m = udt[i]
        offset_bits = int(m.offset)
        size_bits = int(m.size)
        member_tid = int(tif.get_udm_tid(i))
        yield (
            ordinal,
            type_name,
            i,
            str(m.name),
            offset_bits // 8,
            offset_bits,
            size_bits // 8,
            size_bits,
            str(m.type),
            1 if m.is_bitfield() else 0,
            int(m.tafld_bits),
            str(m.cmt) if m.cmt else None,
            member_tid,
        )


def _lookup_by_ordinal(ordinal: int) -> tuple[Any, Any, int, str] | None:
    """Return (til, tif, ordinal, name) for a single ordinal, or None."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    if til is None:
        return None
    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(til, ordinal):
        return None
    name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
    return til, tif, ordinal, name


def _mark_struct_fixed(til: Any, ordinal: int) -> None:
    """Mark a type as fixed-layout if it is a struct (not union, not forward decl)."""
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(til, ordinal):
        msg = f"_mark_struct_fixed: type ordinal {ordinal} not found"
        raise ValueError(msg)
    if not tif.is_struct() or tif.is_forward_decl() or tif.is_union():
        return
    if tif.is_fixed_struct():
        return
    tif.set_fixed_struct(True)
    # Lock in the computed size.
    tif.set_struct_size(tif.get_size())


def _resolve_writable_type(
    *,
    ordinal: int | None = None,
    name: str | None = None,
) -> tuple[Any, Any, int, str]:
    """Look up a type by ordinal or name and resolve through typedefs for writing.

    IDA typedef entries report is_enum()/is_udt() == True and allow reads,
    but member-level writes (rename_udm, set_edm_cmt, etc.) return TERR_OK
    on a typedef tinfo_t and silently discard the change.

    This helper resolves to the concrete definition via get_final_ordinal()
    so that subsequent writes persist correctly.

    At least one of ordinal or name must be provided.  Ordinal is preferred
    when both are given.
    """
    if ordinal is None and name is not None:
        lookup = _lookup_by_name(name)
        if lookup is None:
            msg = f"no type named '{name}'"
            raise ValueError(msg)
        _, _, ordinal, _ = lookup
    if ordinal is None:
        msg = "type lookup requires ordinal or name"
        raise ValueError(msg)

    result = _lookup_by_ordinal(ordinal)
    if result is None:
        msg = f"no type at ordinal {ordinal}"
        raise ValueError(msg)
    til, tif, ord_, resolved_name = result

    if tif.is_typedef():
        final_ord = tif.get_final_ordinal()
        if not final_ord or final_ord == ord_:
            msg = f"type ordinal {ord_} is a typedef but cannot resolve to a concrete type for writing"
            raise ValueError(msg)
        result = _lookup_by_ordinal(final_ord)
        if result is None:
            msg = f"type ordinal {ord_} resolves to ordinal {final_ord} which does not exist"
            raise ValueError(msg)

    return result


def _lookup_by_name(name: str) -> tuple[Any, Any, int, str] | None:
    """Resolve type name to ordinal and return (til, tif, ordinal, name), or None."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    if til is None:
        return None
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    if ordinal == 0:
        return None
    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(til, ordinal):
        return None
    return til, tif, ordinal, name


def _iter_all_types() -> Iterator[tuple[Any, Any, int, str]]:
    """Yield (til, tif, ordinal, name) for every type in the local library."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    if til is None:
        return
    limit = ida_typeinf.get_ordinal_limit(til)
    if limit == 0 or limit == 0xFFFFFFFF:
        return
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue
        name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
        yield til, tif, ordinal, name


def _members_by_ordinal(ordinal: int) -> Iterator[TypesStructMembersRow]:
    """Yield members for a single type ordinal."""
    result = _lookup_by_ordinal(ordinal)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_members(tif, ord_, name)


def _members_by_name(name: str) -> Iterator[TypesStructMembersRow]:
    """Resolve type name to ordinal, then yield members."""
    result = _lookup_by_name(name)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_members(tif, ord_, name)


def _members_all() -> Iterator[TypesStructMembersRow]:
    """Enumerate members across all UDTs in the local type library."""
    for _, tif, ordinal, name in _iter_all_types():
        if not tif.is_udt() or tif.is_forward_decl():
            continue
        yield from _emit_members(tif, ordinal, name)


# ---------------------------------------------------------------------------
# types_enum_values (enum constant details)
# ---------------------------------------------------------------------------

_ENUMVALS_IDX_FULL_SCAN = 0
_ENUMVALS_IDX_ORDINAL_EQ = 1
_ENUMVALS_IDX_NAME_EQ = 2

# Row: (type_ordinal, type_name, value_index, value_name, value, comment, tid)
type TypesEnumValuesRow = tuple[int, str, int, str, int, str | None, int]


class TypesEnumValuesModule:
    COLUMN_SPECS: dict[str, ColumnSpec] = {
        "value_name": ColumnSpec(writable=True),
        "value": ColumnSpec(hex=True, u64=True, writable=True),
        "comment": ColumnSpec(writable=True),
        "tid": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x("
            "type_ordinal INTEGER, type_name TEXT, value_index INTEGER, "
            "value_name TEXT, value INTEGER, comment TEXT, tid INTEGER)"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, TypesEnumValuesCursor, TypesEnumValuesTable, table_name=tablename)
        return schema, TypesEnumValuesTable()

    Connect = Create


class TypesEnumValuesTable:
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ()

    def BestIndexObject(self, ii: Any) -> bool:
        ordinal_idx = find_eq_constraint(ii, 0)  # type_ordinal is column 0
        name_idx = find_eq_constraint(ii, 1)  # type_name is column 1
        if ordinal_idx is not None:
            mark_constraint_used(ii, ordinal_idx, 1)
            ii.idxNum = _ENUMVALS_IDX_ORDINAL_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 20
        elif name_idx is not None:
            mark_constraint_used(ii, name_idx, 1)
            ii.idxNum = _ENUMVALS_IDX_NAME_EQ
            ii.estimatedCost = 15
            ii.estimatedRows = 20
        else:
            ii.idxNum = _ENUMVALS_IDX_FULL_SCAN
            ii.estimatedCost = 50_000
            ii.estimatedRows = 10_000
        return True

    def Open(self) -> "TypesEnumValuesCursor":
        return TypesEnumValuesCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on writable columns: value_name, value, comment."""
        import ida_typeinf

        reject_readonly_update(self, fields)
        fields = decode_u64_update_fields(self, fields)

        ordinal, value_index = unpack_rowid(rowid, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)

        result = _resolve_writable_type(ordinal=ordinal)
        _til, tif, ord_, _name = result
        if not tif.is_enum() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable enum"
            raise ValueError(msg)

        idx = value_index
        ei = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(ei):
            msg = f"cannot load enum details for type ordinal {ord_}"
            raise ValueError(msg)
        if idx < 0 or idx >= len(ei):
            msg = f"value index {idx} out of range for type ordinal {ord_}"
            raise ValueError(msg)

        cur_edm = ei[idx]
        new_value_name = fields[3]
        new_value = fields[4]
        new_comment = fields[5]

        if new_value_name is not None:
            if not isinstance(new_value_name, str):
                msg = "types_enum_values.value_name must be TEXT"
                raise ValueError(msg)
            if not new_value_name:
                msg = "types_enum_values does not support setting value_name to empty string"
                raise ValueError(msg)
            if new_value_name != str(cur_edm.name):
                code = tif.rename_edm(idx, new_value_name)
                if code != ida_typeinf.TERR_OK:
                    msg = f"rename_edm failed for type ordinal {ord_} value {idx}: {code}"
                    raise ValueError(msg)

        if new_value is not None:
            if not isinstance(new_value, int):
                msg = "types_enum_values.value must be INTEGER"
                raise ValueError(msg)
            if new_value != int(cur_edm.value):
                code = tif.edit_edm(idx, new_value)
                if code != ida_typeinf.TERR_OK:
                    msg = f"edit_edm failed for type ordinal {ord_} value {idx}: {code}"
                    raise ValueError(msg)

        if new_comment is not None and not isinstance(new_comment, str):
            msg = "types_enum_values.comment must be TEXT or NULL"
            raise ValueError(msg)
        comment = new_comment or ""
        current_comment = str(cur_edm.cmt) if cur_edm.cmt else ""
        if comment != current_comment:
            code = tif.set_edm_cmt(idx, comment)
            if code != ida_typeinf.TERR_OK:
                msg = f"set_edm_cmt failed for type ordinal {ord_} value {idx}: {code}"
                raise ValueError(msg)

    def UpdateInsertRow(self, newrowid: int | None, fields: tuple[Any, ...]) -> int:
        """Handle INSERT: add an enum constant.

        Required columns: (type_ordinal or type_name), value_name, value.
        """
        import ida_typeinf

        fields = decode_u64_update_fields(self, fields)

        ordinal = fields[0]
        type_name = fields[1]
        value_name = fields[3]
        value = fields[4]

        if not isinstance(value_name, str) or not value_name:
            msg = "types_enum_values INSERT requires non-empty TEXT value_name"
            raise ValueError(msg)
        if value is None:
            msg = "types_enum_values INSERT requires value"
            raise ValueError(msg)
        if not isinstance(value, int):
            msg = "types_enum_values.value must be INTEGER"
            raise ValueError(msg)

        _til, tif, ord_, _name = _resolve_writable_type(ordinal=ordinal, name=type_name)
        if not tif.is_enum() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable enum"
            raise ValueError(msg)

        code = tif.add_edm(value_name, value)
        if code != ida_typeinf.TERR_OK:
            msg = f"add_edm failed for type ordinal {ord_}: {code}"
            raise ValueError(msg)

        # Find the inserted constant by name (unique within an enum).
        ei = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(ei):
            msg = f"cannot read back enum details after add_edm for type ordinal {ord_}"
            raise ValueError(msg)
        for i in range(len(ei)):
            if str(ei[i].name) == value_name:
                return pack_rowid(ord_, i, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)
        msg = f"inserted constant '{value_name}' not found in type ordinal {ord_}"
        raise ValueError(msg)

    def UpdateDeleteRow(self, rowid: int) -> None:
        """Handle DELETE: remove an enum constant by rowid."""
        import ida_typeinf

        ordinal, value_index = unpack_rowid(rowid, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)

        result = _resolve_writable_type(ordinal=ordinal)
        _til, tif, ord_, _name = result
        if not tif.is_enum() or tif.is_forward_decl():
            msg = f"type {ord_} is not a writable enum"
            raise ValueError(msg)

        if value_index < 0 or value_index >= tif.get_enum_nmembers():
            msg = f"value index {value_index} out of range for type ordinal {ord_}"
            raise ValueError(msg)

        code = tif.del_edm(value_index)
        if code != ida_typeinf.TERR_OK:
            msg = f"del_edm failed for type ordinal {ord_} value {value_index}: {code}"
            raise ValueError(msg)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class TypesEnumValuesCursor(BaseCursor):
    CONSTRAINT_PLANS = {
        _ENUMVALS_IDX_ORDINAL_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_ordinal"),)),
        _ENUMVALS_IDX_NAME_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_name"),)),
    }

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _ENUMVALS_IDX_ORDINAL_EQ:
            self._set_iter(_enum_values_by_ordinal(int(args["type_ordinal"])))
        elif indexnum == _ENUMVALS_IDX_NAME_EQ:
            self._set_iter(_enum_values_by_name(str(args["type_name"])))
        else:
            self._set_iter(_enum_values_all())

    def Rowid(self) -> int:
        return pack_rowid(self._current[0], self._current[2], payload_bits=_TYPE_INDEX_PAYLOAD_BITS)


def _emit_enum_values(tif: Any, ordinal: int, type_name: str) -> Iterator[TypesEnumValuesRow]:
    """Yield value rows for a single enum type."""
    import ida_typeinf

    if not tif.is_enum() or tif.is_forward_decl():
        return

    ei = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(ei):
        return

    for i in range(len(ei)):
        e = ei[i]
        edm_tid = int(tif.get_edm_tid(i))
        yield (
            ordinal,
            type_name,
            i,
            str(e.name),
            int(e.value),
            str(e.cmt) if e.cmt else None,
            edm_tid,
        )


def _enum_values_by_ordinal(ordinal: int) -> Iterator[TypesEnumValuesRow]:
    """Yield enum values for a single type ordinal."""
    result = _lookup_by_ordinal(ordinal)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_enum_values(tif, ord_, name)


def _enum_values_by_name(name: str) -> Iterator[TypesEnumValuesRow]:
    """Resolve type name to ordinal, then yield enum values."""
    result = _lookup_by_name(name)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_enum_values(tif, ord_, name)


def _enum_values_all() -> Iterator[TypesEnumValuesRow]:
    """Enumerate values across all enums in the local type library."""
    for _, tif, ordinal, name in _iter_all_types():
        if not tif.is_enum() or tif.is_forward_decl():
            continue
        yield from _emit_enum_values(tif, ordinal, name)


# ---------------------------------------------------------------------------
# types_func_args
# ---------------------------------------------------------------------------

_FUNCARGS_IDX_FULL_SCAN = 0
_FUNCARGS_IDX_ORDINAL_EQ = 1
_FUNCARGS_IDX_NAME_EQ = 2

# (type_ordinal, type_name, arg_index, arg_name, arg_type, calling_conv)
type TypesFuncArgsRow = tuple[int, str, int, str, str, str | None]


class TypesFuncArgsModule:
    COLUMN_SPECS: dict[str, ColumnSpec] = {}

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x("
            "type_ordinal INTEGER, type_name TEXT, arg_index INTEGER, "
            "arg_name TEXT, arg_type TEXT, calling_conv TEXT)"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, TypesFuncArgsCursor, table_name=tablename)
        return schema, TypesFuncArgsTable()

    Connect = Create


class TypesFuncArgsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ordinal_idx = find_eq_constraint(ii, 0)  # type_ordinal is column 0
        name_idx = find_eq_constraint(ii, 1)  # type_name is column 1
        if ordinal_idx is not None:
            mark_constraint_used(ii, ordinal_idx, 1)
            ii.idxNum = _FUNCARGS_IDX_ORDINAL_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 10
        elif name_idx is not None:
            mark_constraint_used(ii, name_idx, 1)
            ii.idxNum = _FUNCARGS_IDX_NAME_EQ
            ii.estimatedCost = 15
            ii.estimatedRows = 10
        else:
            ii.idxNum = _FUNCARGS_IDX_FULL_SCAN
            ii.estimatedCost = 50_000
            ii.estimatedRows = 5_000
        return True

    def Open(self) -> "TypesFuncArgsCursor":
        return TypesFuncArgsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class TypesFuncArgsCursor(BaseCursor):
    CONSTRAINT_PLANS = {
        _FUNCARGS_IDX_ORDINAL_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_ordinal"),)),
        _FUNCARGS_IDX_NAME_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("type_name"),)),
    }

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _FUNCARGS_IDX_ORDINAL_EQ:
            self._set_iter(_func_args_by_ordinal(int(args["type_ordinal"])))
        elif indexnum == _FUNCARGS_IDX_NAME_EQ:
            self._set_iter(_func_args_by_name(str(args["type_name"])))
        else:
            self._set_iter(_func_args_all())

    def Rowid(self) -> int:
        # arg_index + 1 keeps the return type's -1 non-negative for the payload.
        return pack_rowid(self._current[0], self._current[2] + 1, payload_bits=_TYPE_INDEX_PAYLOAD_BITS)


def _emit_func_args(tif: Any, ordinal: int, type_name: str) -> Iterator[TypesFuncArgsRow]:
    """Yield arg rows for a single function or function-pointer type."""
    import ida_typeinf

    from .core import _resolve_cc_name

    # Dereference function pointers to get to the function type.
    func_tif = tif
    if tif.is_funcptr():
        func_tif = tif.get_pointed_object()
        if func_tif is None:
            return
    if not func_tif.is_func():
        return

    fi = ida_typeinf.func_type_data_t()
    if not func_tif.get_func_details(fi):
        return

    # Return type as arg_index = -1.
    ret_type = str(fi.rettype) if fi.rettype else "void"
    cc_name = _resolve_cc_name(fi.get_cc())
    yield (
        ordinal,
        type_name,
        -1,
        "(return)",
        ret_type,
        cc_name,
    )

    # Parameters.
    for i in range(len(fi)):
        a = fi[i]
        yield (
            ordinal,
            type_name,
            i,
            str(a.name) if a.name else "",
            str(a.type) if a.type else "",
            None,
        )


def _func_args_by_ordinal(ordinal: int) -> Iterator[TypesFuncArgsRow]:
    result = _lookup_by_ordinal(ordinal)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_func_args(tif, ord_, name)


def _func_args_by_name(name: str) -> Iterator[TypesFuncArgsRow]:
    result = _lookup_by_name(name)
    if result is None:
        return
    _, tif, ord_, name = result
    yield from _emit_func_args(tif, ord_, name)


def _func_args_all() -> Iterator[TypesFuncArgsRow]:
    """Enumerate args across all function and function-pointer types."""
    for _, tif, ordinal, name in _iter_all_types():
        if not tif.is_func() and not tif.is_funcptr():
            continue
        yield from _emit_func_args(tif, ordinal, name)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_TABLES: list[tuple[type, str]] = [
    (TypesModule, "types"),
    (TypesStructMembersModule, "types_struct_members"),
    (TypesEnumValuesModule, "types_enum_values"),
    (TypesFuncArgsModule, "types_func_args"),
]
