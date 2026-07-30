"""Core IDA virtual tables: funcs, names, segments, strings, imports, db_info."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ..u64 import decode_sql_u64
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

_MISSING = object()


# ---------------------------------------------------------------------------
# funcs
# ---------------------------------------------------------------------------

_FUNCS_IDX_FULL_SCAN = 0
_FUNCS_IDX_START_EA_EQ = 1
_FUNCS_IDX_NAME_EQ = 2


class FuncsModule:
    COLUMN_SPECS = {
        "start_ea": ColumnSpec(hex=True, u64=True, rowid=True),
        "name": ColumnSpec(writable=True),
        "prototype": ColumnSpec(writable=True),
        "comment": ColumnSpec(writable=True),
        "rpt_comment": ColumnSpec(writable=True),
        "size": ColumnSpec(hex=True),
        "end_ea": ColumnSpec(hex=True, u64=True),
        "flags": ColumnSpec(hex=True, writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x(start_ea INTEGER, name TEXT, prototype TEXT, "
            "comment TEXT, rpt_comment TEXT, size INTEGER, end_ea INTEGER, "
            "flags INTEGER, return_type TEXT, arg_count INTEGER, "
            "calling_conv TEXT, type_source TEXT)"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, FuncsCursor, FuncsTable, table_name=tablename)
        return schema, FuncsTable()

    Connect = Create


class FuncsTable:
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ()

    def BestIndexObject(self, ii: Any) -> bool:
        start_ea_idx = find_eq_constraint(ii, 0)
        name_idx = find_eq_constraint(ii, 1)
        if start_ea_idx is not None:
            mark_constraint_used(ii, start_ea_idx, 1)
            ii.idxNum = _FUNCS_IDX_START_EA_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 1
        elif name_idx is not None:
            mark_constraint_used(ii, name_idx, 1)
            ii.idxNum = _FUNCS_IDX_NAME_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 1
        else:
            ii.idxNum = _FUNCS_IDX_FULL_SCAN
            ii.estimatedCost = 1_000_000
            ii.estimatedRows = 10_000
        return True

    def Open(self) -> "FuncsCursor":
        return FuncsCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on writable columns: name, prototype, comment, rpt_comment."""
        import ida_auto
        import ida_funcs
        import ida_name

        reject_readonly_update(self, fields)
        fields = decode_u64_update_fields(self, fields)
        ea = int(decode_sql_u64(rowid))
        func = ida_funcs.get_func(ea)
        if func is None:
            msg = f"no function at {ea:#x}"
            raise ValueError(msg)

        new_name = fields[1]
        new_prototype = fields[2]
        new_comment = fields[3]
        new_rpt_comment = fields[4]
        new_flags = fields[7]

        ida_auto.auto_wait()

        # Name.
        if new_name is not None:
            cur_name = ida_name.get_name(ea) or ""
            if str(new_name) != cur_name:
                if not ida_name.set_name(ea, str(new_name), ida_name.SN_CHECK):
                    msg = f"set_name failed at {ea:#x}"
                    raise ValueError(msg)
                _invalidate_decompiler_cache(ea)

        # Prototype.
        _apply_prototype(ea, new_prototype)

        # Comments.
        _apply_comment(func, new_comment, repeatable=False)
        _apply_comment(func, new_rpt_comment, repeatable=True)

        # Flags.
        if new_flags is not None and int(new_flags) != func.flags:
            func.flags = int(new_flags)
            if not ida_funcs.update_func(func):
                msg = f"update_func failed at {ea:#x}"
                raise ValueError(msg)
            _invalidate_decompiler_cache(ea)

        ida_auto.auto_wait()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


# Calling convention names derived from ida-sdk CM_CC_* constants (typeinf.hpp).
# Covers all user-visible values; CM_CC_SPOILED (serialization escape, not a
# real CC) and CM_CC_RESERVE3 (wide-CC sentinel) are never returned by
# get_cc() and omitted here. Custom CCs (>= 0x200 or usercall sub-ranges)
# are resolved at runtime via get_custom_callcnv().
_CC_NAMES: dict[int, str] = {
    0x20: "voidarg",
    0x30: "cdecl",
    0x40: "ellipsis",
    0x50: "stdcall",
    0x60: "pascal",
    0x70: "fastcall",
    0x80: "thiscall",
    0x90: "swift",
    0xB0: "golang",
    0xD0: "speciale",
    0xE0: "specialp",
    0xF0: "special",
    0x100: "gostk",
}


def _resolve_cc_name(cc: int) -> str | None:
    """Map a callcnv_t value to a human-readable name.

    Built-in CCs use the static table. Custom CCs (plugins that register
    via register_custom_callcnv) are resolved by querying the IDA kernel.
    Uses get_cc() (not get_explicit_cc()) so CM_CC_UNKNOWN is resolved to
    the platform default before reaching this function.
    """
    name = _CC_NAMES.get(cc)
    if name is not None:
        return name
    # Custom calling convention -- ask IDA.
    import ida_typeinf

    if ida_typeinf.is_custom_callcnv(cc):
        cnv = ida_typeinf.get_custom_callcnv(cc)
        if cnv is not None:
            return cnv.name or None
    return None


# Address flags that encode the type source (ida_nalt.h / nalt.hpp).
_AFL_TI = 0x00000800
_AFL_USERTI = 0x02000000
_AFL_TYPE_GUESSED = 0xC2000000
_AFL_IDA_GUESSED = 0x00000000
_AFL_HR_GUESSED_FUNC = 0x40000000
_AFL_HR_DETERMINED = 0xC0000000


def _resolve_type_source(aflags: int) -> str | None:
    """Derive the type source from IDA address flags.

    Returns "user/til", "hexrays", "ida", or None (no stored type).
    """
    if not (aflags & _AFL_TI):
        return None
    if aflags & _AFL_USERTI:
        return "user/til"
    guess_bits = aflags & _AFL_TYPE_GUESSED
    if guess_bits in (_AFL_HR_GUESSED_FUNC, _AFL_HR_DETERMINED):
        return "hexrays"
    # AFL_IDA_GUESSED is 0x00000000 -- the default when AFL_TI is set
    # but neither USERTI nor any HR bit is present.
    return "ida"


def _invalidate_decompiler_cache(ea: int) -> None:
    """Mark the decompiler cache dirty for the function at *ea*."""
    try:
        import ida_hexrays

        ida_hexrays.mark_cfunc_dirty(ea, False)
    except Exception:
        pass


def _apply_prototype(ea: int, new_prototype: str | None) -> None:
    """Apply or clear the function prototype at *ea*."""
    import ida_typeinf

    cur_prototype = ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or None
    if new_prototype == cur_prototype:
        return

    if not new_prototype:
        # Clear type info.
        import ida_nalt

        ida_nalt.del_tinfo(ea)
        _invalidate_decompiler_cache(ea)
        return

    # apply_cdecl requires a trailing semicolon.
    decl = str(new_prototype)
    if not decl.endswith(";"):
        decl += ";"

    if not ida_typeinf.apply_cdecl(None, ea, decl, 0):
        msg = f"apply_cdecl failed at {ea:#x}: {new_prototype!r}"
        raise ValueError(msg)
    _invalidate_decompiler_cache(ea)


def _apply_comment(func: Any, new_comment: str | None, *, repeatable: bool) -> None:
    """Set or clear a function comment."""
    import ida_funcs

    cur = ida_funcs.get_func_cmt(func, repeatable) or None
    if new_comment == cur:
        return

    # Normalize: treat None and empty string as "clear".
    text = str(new_comment) if new_comment else ""
    if not ida_funcs.set_func_cmt(func, text, repeatable):
        which = "rpt_comment" if repeatable else "comment"
        msg = f"set_func_cmt failed at {func.start_ea:#x} ({which})"
        raise ValueError(msg)


class FuncsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _FUNCS_IDX_START_EA_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("start_ea", u64=True),
        )),
        _FUNCS_IDX_NAME_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("name"),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _FUNCS_IDX_START_EA_EQ:
            self._set_iter(_func_at_ea(args["start_ea"]))
        elif indexnum == _FUNCS_IDX_NAME_EQ:
            self._set_iter(_func_named(str(args["name"])))
        else:
            self._set_iter(_funcs_all())

    def _column_value(self, number: int) -> Any:
        if self._current is None:
            return None

        row = self._current
        if number == 0:
            return row.ea
        if number == 1:
            return _func_name(row.ea)
        if number == 2:
            return _func_prototype(row.ea)
        if number == 3:
            import ida_funcs

            return ida_funcs.get_func_cmt(row.func, False) or None
        if number == 4:
            import ida_funcs

            return ida_funcs.get_func_cmt(row.func, True) or None
        if number == 5:
            return int(row.func.end_ea - row.func.start_ea)
        if number == 6:
            return int(row.func.end_ea)
        if number == 7:
            return int(row.func.flags)
        if number == 8:
            return row.type_details().return_type
        if number == 9:
            return row.type_details().arg_count
        if number == 10:
            return row.type_details().calling_conv
        if number == 11:
            return _func_type_source(row.ea)
        msg = f"unknown funcs column index: {number}"
        raise IndexError(msg)


@dataclass
class _FuncTypeDetails:
    return_type: str | None
    arg_count: int | None
    calling_conv: str | None


@dataclass
class _FuncRow:
    ea: int
    func: Any
    _type_details: _FuncTypeDetails | None = None

    def type_details(self) -> _FuncTypeDetails:
        if self._type_details is not None:
            return self._type_details

        import ida_nalt
        import ida_typeinf

        return_type: str | None = None
        arg_count: int | None = None
        calling_conv: str | None = None

        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, self.ea) and tif.is_func():
            ret_tif = tif.get_rettype()
            return_type = ret_tif.dstr() or None

            nargs = tif.get_nargs()
            if nargs >= 0:
                arg_count = nargs

            fti = ida_typeinf.func_type_data_t()
            if tif.get_func_details(fti):
                calling_conv = _resolve_cc_name(fti.get_cc())

        self._type_details = _FuncTypeDetails(
            return_type=return_type,
            arg_count=arg_count,
            calling_conv=calling_conv,
        )
        return self._type_details


def _funcs_all() -> Iterator[_FuncRow]:
    import idautils

    for ea in idautils.Functions():
        row = _func_row(int(ea))
        if row is not None:
            yield row


def _func_at_ea(ea: int) -> Iterator[_FuncRow]:
    row = _func_row(ea)
    if row is not None:
        yield row


def _func_named(name: str) -> Iterator[_FuncRow]:
    import ida_idaapi
    import ida_name

    ea = int(ida_name.get_name_ea(ida_idaapi.BADADDR, name))
    if ea == int(ida_idaapi.BADADDR):
        return
    row = _func_row(ea)
    if row is not None and _func_name(row.ea) == name:
        yield row


def _func_row(ea: int) -> _FuncRow | None:
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None or int(func.start_ea) != int(ea):
        return None
    return _FuncRow(ea=int(ea), func=func)


def _func_name(ea: int) -> str:
    import idc

    return idc.get_func_name(ea) or ""


def _func_prototype(ea: int) -> str | None:
    import ida_typeinf

    # Prototype: full declaration string.
    # PRTYPE_1LINE only, omitting PRTYPE_SEMI so the prototype is
    # cleaner for SQL consumption (no trailing ";").
    return ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or None


def _func_type_source(ea: int) -> str | None:
    import ida_nalt

    return _resolve_type_source(ida_nalt.get_aflags(ea))


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------

_NAMES_IDX_FULL_SCAN = 0
_NAMES_IDX_ADDRESS_EQ = 1
_NAMES_IDX_NAME_EQ = 2


class NamesModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True, rowid=True),
        "name": ColumnSpec(writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, name TEXT, is_auto INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, NamesCursor, NamesTable, table_name=tablename)
        return schema, NamesTable()

    Connect = Create


class NamesTable:
    def BestIndexObject(self, ii: Any) -> bool:
        address_idx = find_eq_constraint(ii, 0)
        name_idx = find_eq_constraint(ii, 1)
        if address_idx is not None:
            mark_constraint_used(ii, address_idx, 1)
            ii.idxNum = _NAMES_IDX_ADDRESS_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 1
        elif name_idx is not None:
            mark_constraint_used(ii, name_idx, 1)
            ii.idxNum = _NAMES_IDX_NAME_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 1
        else:
            ii.idxNum = _NAMES_IDX_FULL_SCAN
            ii.estimatedCost = 1_000_000
            ii.estimatedRows = 10_000
        return True

    def Open(self) -> "NamesCursor":
        return NamesCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on the writable name column: (re)name the address.

        An empty-string name clears a user name (IDA set_name(ea, "") semantics);
        a NULL name is a no-op.
        """
        import ida_name

        reject_readonly_update(self, fields)
        fields = decode_u64_update_fields(self, fields)
        ea = int(decode_sql_u64(rowid))
        new_name = fields[1]
        if new_name is None:
            return
        cur_name = ida_name.get_name(ea) or ""
        if str(new_name) == cur_name:
            return
        if not ida_name.set_name(ea, str(new_name), ida_name.SN_CHECK):
            msg = f"set_name failed at {ea:#x}: {new_name!r}"
            raise ValueError(msg)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class NamesCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _NAMES_IDX_ADDRESS_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("address", u64=True),
        )),
        _NAMES_IDX_NAME_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("name"),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _NAMES_IDX_ADDRESS_EQ:
            self._set_iter(_name_at_ea(args["address"]))
        elif indexnum == _NAMES_IDX_NAME_EQ:
            self._set_iter(_name_by_name(str(args["name"])))
        else:
            self._set_iter(_names_all())

    def _column_value(self, number: int) -> Any:
        if self._current is None:
            return None

        row = self._current
        if number == 0:
            return row.ea
        if number == 1:
            return row.name
        if number == 2:
            return row.is_auto()
        msg = f"unknown names column index: {number}"
        raise IndexError(msg)


@dataclass
class _NameRow:
    ea: int
    name: str
    _is_auto: object = _MISSING

    def is_auto(self) -> int:
        if self._is_auto is _MISSING:
            import ida_bytes

            flags = int(ida_bytes.get_flags(self.ea))
            self._is_auto = 0 if ida_bytes.has_user_name(flags) else 1
        return int(self._is_auto)


def _names_all() -> Iterator[_NameRow]:
    import ida_name

    qty = int(ida_name.get_nlist_size())
    for index in range(qty):
        yield _name_row_at_index(index)


def _name_at_ea(ea: int) -> Iterator[_NameRow]:
    row = _name_row_at_ea(ea)
    if row is not None:
        yield row


def _name_by_name(name: str) -> Iterator[_NameRow]:
    import ida_idaapi
    import ida_name

    ea = int(ida_name.get_name_ea(ida_idaapi.BADADDR, name))
    if ea == int(ida_idaapi.BADADDR):
        return
    row = _name_row_at_ea(ea)
    if row is not None and row.name == name:
        yield row


def _name_row_at_ea(ea: int) -> _NameRow | None:
    import ida_name

    if not ida_name.is_in_nlist(ea):
        return None
    index = int(ida_name.get_nlist_idx(ea))
    qty = int(ida_name.get_nlist_size())
    if index < 0 or index >= qty:
        return None
    row = _name_row_at_index(index)
    if row.ea != ea:
        return None
    return row


def _name_row_at_index(index: int) -> _NameRow:
    import ida_name

    ea = int(ida_name.get_nlist_ea(index))
    name = ida_name.get_nlist_name(index) or ""
    return _NameRow(ea=ea, name=name)


# ---------------------------------------------------------------------------
# segments
# ---------------------------------------------------------------------------


class SegmentsModule:
    COLUMN_SPECS = {
        "start_ea": ColumnSpec(hex=True, u64=True),
        "end_ea": ColumnSpec(hex=True, u64=True),
        "size": ColumnSpec(hex=True),
        "perm": ColumnSpec(hex=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(start_ea INTEGER, end_ea INTEGER, size INTEGER, name TEXT, class TEXT, perm INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, SegmentsCursor, table_name=tablename)
        return schema, SegmentsTable()

    Connect = Create


class SegmentsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 100
        ii.estimatedRows = 20
        return True

    def Open(self) -> "SegmentsCursor":
        return SegmentsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class SegmentsCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        import ida_segment

        def _gen() -> Iterator[tuple[int, int, int, str, str, int]]:
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg is None:
                    continue
                yield (
                    int(seg.start_ea),
                    int(seg.end_ea),
                    int(seg.end_ea - seg.start_ea),
                    ida_segment.get_segm_name(seg) or "",
                    ida_segment.get_segm_class(seg) or "",
                    int(seg.perm),
                )

        self._set_iter(_gen())


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------

_STRINGS_IDX_FULL_SCAN = 0
_STRINGS_IDX_ADDRESS_EQ = 1


@dataclass(frozen=True)
class _StringRow:
    ea: int
    length: int
    strtype: int


class StringsModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True, rowid=True),
        "length": ColumnSpec(hex=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, length INTEGER, type INTEGER, string_value TEXT)"
        apply_schema_specs(schema, self.COLUMN_SPECS, StringsCursor, table_name=tablename)
        return schema, StringsTable()

    Connect = Create


class StringsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        address_idx = find_eq_constraint(ii, 0)
        if address_idx is not None:
            mark_constraint_used(ii, address_idx, 1)
            ii.idxNum = _STRINGS_IDX_ADDRESS_EQ
            ii.estimatedCost = 10
            ii.estimatedRows = 1
        else:
            ii.idxNum = _STRINGS_IDX_FULL_SCAN
            ii.estimatedCost = 1_000_000
            ii.estimatedRows = 10_000
        return True

    def Open(self) -> "StringsCursor":
        return StringsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class StringsCursor(BaseCursor):
    # fmt: off
    CONSTRAINT_PLANS = {
        _STRINGS_IDX_ADDRESS_EQ: ConstraintPlanSpec(args=(
            ConstraintArgSpec("address", u64=True),
        )),
    }
    # fmt: on

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _STRINGS_IDX_ADDRESS_EQ:
            self._set_iter(_string_at_ea(args["address"]))
        else:
            self._set_iter(_strings_all())

    def _column_value(self, number: int) -> Any:
        if self._current is None:
            return None
        if number == 0:
            return self._current.ea
        if number == 1:
            return self._current.length
        if number == 2:
            return self._current.strtype
        if number == 3:
            return _string_content(self._current)
        msg = f"unknown strings column index: {number}"
        raise IndexError(msg)


def _strings_all() -> Iterator[_StringRow]:
    import ida_strlist

    qty = int(ida_strlist.get_strlist_qty())
    si = ida_strlist.string_info_t()
    for index in range(qty):
        yield _string_row_at_index(si, index)


def _string_at_ea(ea: int) -> Iterator[_StringRow]:
    import ida_strlist

    qty = int(ida_strlist.get_strlist_qty())
    si = ida_strlist.string_info_t()
    lo = 0
    hi = qty - 1
    while lo <= hi:
        index = (lo + hi) // 2
        row = _string_row_at_index(si, index)
        if row.ea == ea:
            yield row
            return
        if row.ea < ea:
            lo = index + 1
        else:
            hi = index - 1


def _string_row_at_index(si: Any, index: int) -> _StringRow:
    import ida_strlist

    if not ida_strlist.get_strlist_item(si, index):
        msg = f"get_strlist_item failed at index {index}"
        raise RuntimeError(msg)
    return _StringRow(ea=int(si.ea), length=int(si.length), strtype=int(si.type))


def _string_content(row: _StringRow) -> str | None:
    import ida_bytes

    raw = ida_bytes.get_strlit_contents(row.ea, row.length, row.strtype)
    if raw is None:
        return None
    return raw.decode("UTF-8", "replace")


# ---------------------------------------------------------------------------
# imports
# ---------------------------------------------------------------------------


class ImportsModule:
    COLUMN_SPECS = {
        "address": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(address INTEGER, module TEXT, name TEXT, ordinal INTEGER)"
        apply_schema_specs(schema, self.COLUMN_SPECS, ImportsCursor, table_name=tablename)
        return schema, ImportsTable()

    Connect = Create


class ImportsTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1_000_000
        ii.estimatedRows = 1_000
        return True

    def Open(self) -> "ImportsCursor":
        return ImportsCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class ImportsCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        import ida_nalt

        def _gen() -> Iterator[tuple[int, str, str, int]]:
            for module_idx in range(ida_nalt.get_import_module_qty()):
                module_name = ida_nalt.get_import_module_name(module_idx) or ""
                entries: list[tuple[int, str, str, int]] = []

                def _collect(ea: int, name: str | None, ordinal: int) -> bool:
                    entries.append((int(ea), module_name, name or "", int(ordinal)))  # noqa: B023
                    return True

                ida_nalt.enum_import_names(module_idx, _collect)
                yield from entries

        self._set_iter(_gen())


# ---------------------------------------------------------------------------
# db_info
# ---------------------------------------------------------------------------


class DbInfoModule:
    COLUMN_SPECS = {
        "image_base": ColumnSpec(hex=True, u64=True),
        "min_ea": ColumnSpec(hex=True, u64=True),
        "max_ea": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x(input_file TEXT, image_base INTEGER, arch TEXT, "
            "bits INTEGER, endian TEXT, filetype INTEGER, is_dll INTEGER, "
            "min_ea INTEGER, max_ea INTEGER)"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, DbInfoCursor, table_name=tablename)
        return schema, DbInfoTable()

    Connect = Create


class DbInfoTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1
        ii.estimatedRows = 1
        return True

    def Open(self) -> "DbInfoCursor":
        return DbInfoCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class DbInfoCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        import ida_ida
        import ida_nalt

        row = (
            ida_nalt.get_root_filename() or "",
            int(ida_nalt.get_imagebase()),
            ida_ida.inf_get_procname() or "",
            64 if ida_ida.inf_is_64bit() else 32,
            "big" if ida_ida.inf_is_be() else "little",
            int(ida_ida.inf_get_filetype()),
            1 if ida_ida.inf_is_dll() else 0,
            int(ida_ida.inf_get_min_ea()),
            int(ida_ida.inf_get_max_ea()),
        )
        self._set_iter([row])


# ---------------------------------------------------------------------------
# entries (export/entry points)
# ---------------------------------------------------------------------------


class EntriesModule:
    COLUMN_SPECS = {
        "ordinal": ColumnSpec(hex=True, u64=True),
        "address": ColumnSpec(hex=True, u64=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = "CREATE TABLE x(ordinal INTEGER, address INTEGER, name TEXT)"
        apply_schema_specs(schema, self.COLUMN_SPECS, EntriesCursor, table_name=tablename)
        return schema, EntriesTable()

    Connect = Create


class EntriesTable:
    def BestIndexObject(self, ii: Any) -> bool:
        ii.estimatedCost = 1_000
        ii.estimatedRows = 100
        return True

    def Open(self) -> "EntriesCursor":
        return EntriesCursor()

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class EntriesCursor(BaseCursor):
    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        import ida_entry

        def _gen() -> Iterator[tuple[int, int, str]]:
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ""
                yield (int(ordinal), int(ea), name)

        self._set_iter(_gen())


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_TABLES: list[tuple[type, str]] = [
    (FuncsModule, "funcs"),
    (NamesModule, "names"),
    (SegmentsModule, "segments"),
    (StringsModule, "strings"),
    (ImportsModule, "imports"),
    (EntriesModule, "entries"),
    (DbInfoModule, "db_info"),
]
