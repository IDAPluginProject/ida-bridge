"""Scalar SQL functions backed by IDA APIs."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .tables.types import _mark_struct_fixed
from .u64 import decode_sql_u64_input, encode_sql_u64, format_sql_u64_hex

if TYPE_CHECKING:
    import apsw


def _func_at(ea: int | None) -> str | None:
    """Return the name of the function containing *ea*, or NULL."""
    if ea is None:
        return None
    import ida_funcs
    import ida_name

    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    name = ida_name.get_name(func.start_ea)
    return name or None


def _func_start(ea: int | None) -> int | None:
    """Return the start EA of the function containing *ea*, or NULL."""
    if ea is None:
        return None
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return func.start_ea


def _name_at(ea: int | None) -> str | None:
    """Return the name at *ea*, or NULL."""
    if ea is None:
        return None
    import ida_name

    name = ida_name.get_name(ea)
    return name or None


def _tid_name(tid: int | None) -> str | None:
    """Return the type or member name for a tid, or NULL if *tid* is not a tid."""
    if tid is None:
        return None
    import ida_typeinf

    name = ida_typeinf.get_tid_name(tid)
    return name or None


def _hex(value: int | None) -> str | None:
    """Return *value* as a ``0x...`` hex string, or NULL."""
    if value is None:
        return None
    return format_sql_u64_hex(value)


def _func_end(ea: int | None) -> int | None:
    """Return the end EA of the function containing *ea*, or NULL."""
    if ea is None:
        return None
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return func.end_ea


def _segment_at(ea: int | None) -> str | None:
    """Return the segment name containing *ea*, or NULL."""
    if ea is None:
        return None
    import ida_segment

    seg = ida_segment.getseg(ea)
    if seg is None:
        return None
    name = ida_segment.get_segm_name(seg)
    return name or None


def _mnemonic(ea: int | None) -> str | None:
    """Return the instruction mnemonic at *ea*, or NULL."""
    if ea is None:
        return None
    import idc

    m = idc.print_insn_mnem(ea)
    return m or None


def _disasm(ea: int | None) -> str | None:
    """Return the disassembly text at *ea*, or NULL."""
    if ea is None:
        return None
    import idc

    text = idc.GetDisasm(ea)
    return text or None


def _item_type(ea: int | None) -> str | None:
    """Classify the item at *ea*: code/data/string/struct/align/unknown, or NULL."""
    if ea is None:
        return None
    import ida_bytes

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        return "code"
    if ida_bytes.is_strlit(flags):
        return "string"
    if ida_bytes.is_struct(flags):
        return "struct"
    if ida_bytes.is_align(flags):
        return "align"
    if ida_bytes.is_data(flags):
        return "data"
    return "unknown"


def _item_size(ea: int | None) -> int | None:
    """Return the size in bytes of the item at *ea*, or NULL."""
    if ea is None:
        return None
    import idc

    size = idc.get_item_size(ea)
    return int(size) if size else None


def _is_code(ea: int | None) -> int | None:
    """Return 1 if *ea* is code, 0 otherwise, or NULL."""
    if ea is None:
        return None
    import ida_bytes

    return 1 if ida_bytes.is_code(ida_bytes.get_flags(ea)) else 0


def _is_data(ea: int | None) -> int | None:
    """Return 1 if *ea* is data, 0 otherwise, or NULL."""
    if ea is None:
        return None
    import ida_bytes

    return 1 if ida_bytes.is_data(ida_bytes.get_flags(ea)) else 0


# func_t.flags bit constants (ida_funcs.h / funcs.hpp).
_FUNC_FLAGS: dict[str, int] = {
    "noret": 0x01,
    "far": 0x02,
    "lib": 0x04,
    "static": 0x08,
    "frame": 0x10,
    "userfar": 0x20,
    "hidden": 0x40,
    "thunk": 0x80,
}

_FUNC_FLAG_VALID = ", ".join(sorted(_FUNC_FLAGS))


def _func_flag(name: str | None) -> int:
    """Return the bit constant for a func_t flag name. Raises on invalid input."""
    if name is None or name not in _FUNC_FLAGS:
        msg = f"unknown func_flag {name!r}, valid: {_FUNC_FLAG_VALID}"
        raise ValueError(msg)
    return _FUNC_FLAGS[name]


# udm_t.tafld_bits constants (typeinf.hpp).
_UDM_FLAGS: dict[str, int] = {
    "baseclass": 0x0020,
    "unaligned": 0x0040,
    "virtbase": 0x0080,
    "vftable": 0x0100,
    "method": 0x0200,
    "gap": 0x0400,
    "regcmt": 0x0800,
    "retaddr": 0x1000,
    "savregs": 0x2000,
    "bytil": 0x4000,
}

_UDM_FLAG_VALID = ", ".join(sorted(_UDM_FLAGS))


def _udm_flag(name: str | None) -> int:
    """Return the bit constant for a udm_t tafld_bits flag name. Raises on invalid input."""
    if name is None or name not in _UDM_FLAGS:
        msg = f"unknown udm_flag {name!r}, valid: {_UDM_FLAG_VALID}"
        raise ValueError(msg)
    return _UDM_FLAGS[name]


# ---------------------------------------------------------------------------
# Type application scalars
# ---------------------------------------------------------------------------


def _set_type(ea: int | None, decl: str | None) -> int:
    """Apply a C type declaration at address *ea*.

    set_type(ea, decl) -- apply type. Returns 1 on success.
    set_type(ea, NULL) -- clear type info at ea. Returns 1 on success.
    """
    if ea is None:
        msg = "set_type: ea must not be NULL"
        raise ValueError(msg)

    import ida_typeinf

    if not decl:
        # Clear type info.
        import ida_nalt

        ida_nalt.del_tinfo(ea)
        return 1

    text = str(decl).strip()
    if not text.endswith(";"):
        text += ";"

    if not ida_typeinf.apply_cdecl(None, ea, text, 0):
        msg = f"set_type: apply_cdecl failed at {ea:#x}: {decl!r}"
        raise ValueError(msg)
    return 1


def _type_at(ea: int | None) -> str | None:
    """Return the C type declaration applied at *ea*, or NULL."""
    if ea is None:
        return None
    import ida_typeinf

    return ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or None


def _decompile_func(ea: int | None) -> str | None:
    """Decompile the function containing *ea*, return pseudocode text.

    Returns NULL if ea is NULL, no function at ea, or decompilation fails.
    Raises if the decompiler is not available.
    """
    if ea is None:
        return None

    import ida_auto
    import ida_funcs
    import ida_hexrays
    import ida_lines

    if not ida_hexrays.init_hexrays_plugin():
        msg = "decompile: Hex-Rays decompiler is not available"
        raise ValueError(msg)

    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    ida_auto.auto_wait()

    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure:
        return None

    if cfunc is None:
        return None

    sv = cfunc.get_pseudocode()
    lines = []
    for sl in sv:
        lines.append(ida_lines.tag_remove(str(sl.line)))
    return "\n".join(lines)


def _mark_cfunc_dirty(ea: int | None) -> int:
    """Invalidate the cached decompiler result for the function containing *ea*.

    Returns 1. Use after modifying types/globals that affect a function's pseudocode.
    """
    if ea is None:
        msg = "mark_cfunc_dirty: ea must not be NULL"
        raise ValueError(msg)

    import ida_funcs
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        msg = "mark_cfunc_dirty: decompiler not available"
        raise ValueError(msg)

    func = ida_funcs.get_func(ea)
    if func is None:
        msg = f"mark_cfunc_dirty: no function at {ea:#x}"
        raise ValueError(msg)

    ida_hexrays.mark_cfunc_dirty(func.start_ea, False)
    return 1


# ---------------------------------------------------------------------------
# Type parsing helpers
# ---------------------------------------------------------------------------


def _type_snapshot(til: Any) -> dict[int, tuple[str, tuple[Any, ...] | None]]:
    """Snapshot every ordinal as ``{ordinal: (name, raw_bytes)}``."""
    import ida_typeinf

    limit = ida_typeinf.get_ordinal_limit(til)
    snap: dict[int, tuple[str, tuple[Any, ...] | None]] = {}
    for i in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, i):
            name = ida_typeinf.get_numbered_type_name(til, i) or ""
            snap[i] = (name, ida_typeinf.idc_get_type_raw(i))
    return snap


def _type_diff(
    til: Any,
    before: dict[int, tuple[str, tuple[Any, ...] | None]],
) -> list[dict[str, Any]]:
    """Return ``[{ordinal, name}]`` for ordinals added or changed since *before*."""
    import ida_typeinf

    limit = ida_typeinf.get_ordinal_limit(til)
    result: list[dict[str, Any]] = []
    for i in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, i):
            continue
        name = ida_typeinf.get_numbered_type_name(til, i) or ""
        raw = ida_typeinf.idc_get_type_raw(i)
        prev = before.get(i)
        if prev is None or prev != (name, raw):
            result.append({"ordinal": i, "name": name})
    return result


def _parse_decls_diff(
    til: Any,
    decl_text: str,
    caller: str,
    parser_name: str | None = None,
) -> list[dict[str, Any]]:
    """Parse *decl_text*, return diff of changed types.

    Uses ``ida_srclang`` when *parser_name* is given, otherwise the
    built-in ``parse_decls``.
    """
    import ida_typeinf

    before = _type_snapshot(til)

    if parser_name is not None:
        import ida_srclang

        nerrors = ida_srclang.parse_decls_with_parser(parser_name, til, decl_text, False)
        if nerrors < 0:
            msg = f"{caller}: parser '{parser_name}' not found or error (code {nerrors})"
            raise ValueError(msg)
    else:
        nerrors = ida_typeinf.parse_decls(til, decl_text, None, ida_typeinf.HTI_DCL)
        if nerrors < 0:
            msg = f"{caller}: parser error (code {nerrors})"
            raise ValueError(msg)

    if nerrors > 0:
        msg = f"{caller}: {nerrors} error(s) parsing declarations"
        raise ValueError(msg)

    return _type_diff(til, before)


# ---------------------------------------------------------------------------
# Type parsing scalar functions
# ---------------------------------------------------------------------------


def _parse_type(*args: Any) -> int:
    """Parse a single C type declaration and save it to the local type library.

    parse_type(decl_text) -- create or replace by name, built-in parser.
    parse_type(decl_text, parser_name) -- create or replace by name, named parser.

    Returns the ordinal of the created/replaced type.
    """
    import ida_typeinf

    if not args or len(args) > 2:
        msg = "parse_type(decl_text[, parser_name]): 1 or 2 arguments required"
        raise ValueError(msg)

    decl_text = args[0]
    if not isinstance(decl_text, str) or not decl_text.strip():
        msg = "parse_type: decl_text must be non-empty TEXT"
        raise ValueError(msg)

    til = ida_typeinf.get_idati()
    if til is None:
        msg = "local type library not available"
        raise ValueError(msg)

    parser_name = None
    if len(args) == 2:
        if not isinstance(args[1], str):
            msg = "parse_type: second argument must be a parser name (TEXT)"
            raise ValueError(msg)
        parser_name = args[1]

    # Named parser path: parse via ida_srclang, find the result by diff.
    if parser_name is not None:
        diff = _parse_decls_diff(til, decl_text, "parse_type", parser_name)
        if not diff:
            msg = "parse_type: parser produced no types"
            raise ValueError(msg)
        ordinal = diff[-1]["ordinal"]
        _mark_struct_fixed(til, ordinal)
        return ordinal

    # Built-in parser: parse_decl returns the name on success.
    tif = ida_typeinf.tinfo_t()
    parsed_name = ida_typeinf.parse_decl(tif, til, decl_text, ida_typeinf.PT_TYP)
    if not parsed_name:
        msg = f"parse_type: failed to parse declaration: {decl_text!r}"
        raise ValueError(msg)

    code = tif.set_named_type(til, parsed_name, ida_typeinf.NTF_REPLACE)
    if code != ida_typeinf.TERR_OK:
        msg = f"parse_type: set_named_type failed for '{parsed_name}': {code}"
        raise ValueError(msg)

    ordinal = ida_typeinf.get_type_ordinal(til, parsed_name)
    if ordinal == 0:
        msg = f"parse_type: type '{parsed_name}' saved but ordinal lookup failed"
        raise ValueError(msg)

    _mark_struct_fixed(til, ordinal)
    return ordinal


def _parse_types(*args: Any) -> str:
    """Parse multiple C type declarations into the local type library.

    parse_types(decl_text) -- use the built-in parser.
    parse_types(decl_text, parser_name) -- use a named parser (e.g. 'idaclang').

    Returns a JSON array of {ordinal, name} for each type created or modified.
    """
    import json

    import ida_typeinf

    if not args or len(args) > 2:
        msg = "parse_types(decl_text[, parser_name]): 1 or 2 arguments required"
        raise ValueError(msg)

    decl_text = args[0]
    parser_name = args[1] if len(args) > 1 else None

    if not isinstance(decl_text, str) or not decl_text.strip():
        msg = "parse_types: decl_text must be non-empty TEXT"
        raise ValueError(msg)

    til = ida_typeinf.get_idati()
    if til is None:
        msg = "local type library not available"
        raise ValueError(msg)

    if parser_name is not None:
        diff = _parse_decls_diff(til, decl_text, "parse_types", parser_name)
    else:
        diff = _parse_decls_diff(til, decl_text, "parse_types")

    for entry in diff:
        _mark_struct_fixed(til, entry["ordinal"])

    return json.dumps(diff)


# ---------------------------------------------------------------------------
# UI functions (require IDA GUI, not idalib)
# ---------------------------------------------------------------------------


def _require_ui() -> None:
    """Raise if the IDA GUI is not available (idalib/batch mode)."""
    import ida_kernwin

    if not ida_kernwin.is_idaq():
        msg = "this function requires IDA GUI (not available in idalib/batch mode)"
        raise ValueError(msg)


def _bring_to_front() -> None:
    """Best-effort bring IDA's main window to front."""
    import ida_kernwin

    viewer = ida_kernwin.get_current_viewer()
    if viewer is None:
        return
    try:
        widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(viewer)
        window = widget.window()
        window.show()
        window.raise_()
        window.activateWindow()
    except Exception:
        pass


def _open_disasm(ea: int | None) -> int:
    """Navigate IDA's disassembly view to *ea* and bring the window to front.

    Returns 1 on success. Raises on NULL input, no UI, or invalid address.
    """
    if ea is None:
        msg = "ui_open_disasm() requires a non-NULL address"
        raise ValueError(msg)
    _require_ui()
    import ida_kernwin

    _bring_to_front()
    if not ida_kernwin.jumpto(ea, -1, ida_kernwin.UIJMP_ACTIVATE | ida_kernwin.UIJMP_IDAVIEW):
        msg = f"ui_open_disasm failed for {ea:#x}"
        raise ValueError(msg)
    return 1


def _open_pseudocode(ea: int | None) -> int:
    """Open pseudocode for the function containing *ea* and scroll to the
    matching line.

    If *ea* is a function start, opens at the top.  If *ea* is a line-level
    address (e.g. from the pseudocode table's ``ea`` column), scrolls to
    that specific line.

    Returns 1 on success. Raises on NULL input, no UI, no decompiler, or
    if *ea* is not inside a function.
    """
    if ea is None:
        msg = "ui_open_pseudocode() requires a non-NULL address"
        raise ValueError(msg)
    _require_ui()
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        msg = "Hex-Rays decompiler is not available"
        raise ValueError(msg)

    _bring_to_front()

    # OPF_REUSE = 0: reuse existing pseudocode window
    vu = ida_hexrays.open_pseudocode(ea, 0)
    if vu is None:
        msg = f"ui_open_pseudocode failed for {ea:#x} (not in a function?)"
        raise ValueError(msg)

    # Scroll to the line matching ea (if not the function entry).
    _scroll_pseudocode_to_ea(vu, ea)
    return 1


def _scroll_pseudocode_to_ea(vu: object, target_ea: int) -> None:
    """Position the pseudocode cursor on the line whose ea matches *target_ea*."""
    if getattr(vu, "ct", None) is None or getattr(vu, "cfunc", None) is None:
        return

    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import ida_moves

    sv = vu.cfunc.get_pseudocode()
    target_line: int | None = None
    for i, sl in enumerate(sv):
        raw = str(sl.line)
        if not ida_lines.tag_remove(raw).strip():
            continue  # blank spacer lines can carry the next statement's ea
        tail = ida_hexrays.ctree_item_t()
        vu.cfunc.get_line_item(raw, 0, True, None, None, tail)
        if tail.citype == ida_hexrays.VDI_TAIL and int(tail.loc.ea) == target_ea:
            target_line = i
            break

    if target_line is None:
        return  # ea is func_start or no matching line; stay at top

    loc = ida_moves.lochist_entry_t()
    if not ida_kernwin.get_custom_viewer_location(loc, vu.ct):
        return
    place = loc.place()
    slp = ida_kernwin.place_t.as_simpleline_place_t(place)
    if slp is None:
        return
    new_place = slp.makeplace(None, target_line, 0)
    loc.set_place(new_place)
    loc.renderer_info().pos.cx = 0
    ida_kernwin.custom_viewer_jump(vu.ct, loc, ida_kernwin.CVNF_LAZY)


def _get_selection() -> str | None:
    """Read the current selection from IDA's active view.

    Returns a JSON string with the selection contents:

    Pseudocode: ``{"view":"pseudocode", "func_ea":"0x...",
    "from_line":N, "to_line":N, "lines":["...", ...]}``

    Disassembly: ``{"view":"disasm", "from_ea":"0x...",
    "to_ea":"0x...", "lines":["0xADDR: INSN ...", ...]}``

    Returns None (SQL NULL) when nothing is selected -- a normal state.
    Raises with no GUI, no active viewer, or an unsupported view type.
    """
    _require_ui()
    import json

    import ida_kernwin

    v = ida_kernwin.get_current_viewer()
    if v is None:
        msg = "no active viewer"
        raise ValueError(msg)

    p1 = ida_kernwin.twinpos_t()
    p2 = ida_kernwin.twinpos_t()
    if not ida_kernwin.read_selection(v, p1, p2):
        return None  # no selection is a normal state, not an error

    wtype = ida_kernwin.get_widget_type(v)

    if wtype == ida_kernwin.BWN_PSEUDOCODE:
        result = _read_pseudocode_selection(v, p1, p2)
    elif wtype == ida_kernwin.BWN_DISASM:
        result = _read_disasm_selection(v, p1, p2)
    else:
        msg = f"unsupported view type {wtype} for ui_get_selection"
        raise ValueError(msg)

    return json.dumps(result)


def _read_pseudocode_selection(
    v: object,
    p1: object,
    p2: object,
) -> dict:
    """Extract pseudocode lines from a selection."""
    import ida_hexrays
    import ida_kernwin
    import ida_lines

    place0 = p1.place(v)
    place1 = p2.place(v)
    slp0 = ida_kernwin.place_t.as_simpleline_place_t(place0)
    slp1 = ida_kernwin.place_t.as_simpleline_place_t(place1)
    from_idx = slp0.n  # 0-based index into pseudocode array
    to_idx = slp1.n

    vu = ida_hexrays.get_widget_vdui(v)
    if vu is None:
        msg = "cannot get pseudocode data from widget"
        raise ValueError(msg)

    sv = vu.cfunc.get_pseudocode()
    lines = []
    for i in range(from_idx, to_idx + 1):
        if i < len(sv):
            lines.append(ida_lines.tag_remove(str(sv[i].line)))

    return {
        "view": "pseudocode",
        "func_ea": f"0x{vu.cfunc.entry_ea:x}",
        "from_line": from_idx + 1,  # 1-based to match IDA UI / pseudocode table
        "to_line": to_idx + 1,
        "lines": lines,
    }


def _read_disasm_selection(
    v: object,
    p1: object,
    p2: object,
) -> dict:
    """Extract disassembly lines from a selection."""
    import ida_kernwin
    import idc

    place0 = p1.place(v)
    place1 = p2.place(v)
    ip0 = ida_kernwin.place_t_as_idaplace_t(place0)
    ip1 = ida_kernwin.place_t_as_idaplace_t(place1)
    from_ea = ip0.ea
    to_ea = ip1.ea

    lines = []
    ea = from_ea
    while ea <= to_ea:
        lines.append(f"{ea:#x}: {idc.GetDisasm(ea)}")
        next_ea = idc.next_head(ea)
        if next_ea == 0xFFFFFFFFFFFFFFFF or next_ea <= ea:
            break
        ea = next_ea

    return {
        "view": "disasm",
        "from_ea": f"0x{from_ea:x}",
        "to_ea": f"0x{to_ea:x}",
        "lines": lines,
    }


# ---------------------------------------------------------------------------
# Memory-read functions
# ---------------------------------------------------------------------------

_MAX_READ_BYTES = 0x1000  # 4 KiB cap for read_bytes()


def _read_u8(ea: int | None) -> int | None:
    """Read an unsigned 8-bit value at *ea*."""
    if ea is None:
        return None
    import ida_bytes

    return ida_bytes.get_byte(ea)


def _read_u16(ea: int | None) -> int | None:
    """Read an unsigned 16-bit little-endian value at *ea*."""
    if ea is None:
        return None
    import ida_bytes

    return ida_bytes.get_word(ea)


def _read_u32(ea: int | None) -> int | None:
    """Read an unsigned 32-bit little-endian value at *ea*."""
    if ea is None:
        return None
    import ida_bytes

    return ida_bytes.get_dword(ea)


def _read_i32(ea: int | None) -> int | None:
    """Read a signed 32-bit little-endian value at *ea*."""
    if ea is None:
        return None
    import struct

    import ida_bytes

    raw = ida_bytes.get_bytes(ea, 4)
    if raw is None or len(raw) < 4:
        return None
    return struct.unpack("<i", raw)[0]


def _read_u64(ea: int | None) -> int | None:
    """Read an unsigned 64-bit little-endian value at *ea*."""
    if ea is None:
        return None
    import ida_bytes

    return ida_bytes.get_qword(ea)


def _read_i64(ea: int | None) -> int | None:
    """Read a signed 64-bit little-endian value at *ea*."""
    if ea is None:
        return None
    import struct

    import ida_bytes

    raw = ida_bytes.get_bytes(ea, 8)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack("<q", raw)[0]


def _read_rel32(ea: int | None) -> int | None:
    """Resolve a 32-bit relative pointer: ``ea + i32_at(ea)``.

    Returns the absolute target address, or NULL if the offset is zero
    (Swift uses zero to mean "no target").
    """
    if ea is None:
        return None
    import struct

    import ida_bytes

    raw = ida_bytes.get_bytes(ea, 4)
    if raw is None or len(raw) < 4:
        return None
    offset = struct.unpack("<i", raw)[0]
    if offset == 0:
        return None
    return ea + offset


def _read_bytes(ea: int | None, size: int | None) -> str | None:
    """Read *size* bytes at *ea*, returned as a hex string.

    Capped at 4 KiB. Returns NULL on invalid input.
    """
    if ea is None or size is None or size <= 0:
        return None
    if size > _MAX_READ_BYTES:
        msg = f"read_bytes size {size} exceeds limit {_MAX_READ_BYTES}"
        raise ValueError(msg)
    import ida_bytes

    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        return None
    return data.hex()


def _read_cstr(ea: int | None) -> str | None:
    """Read a null-terminated C string at *ea*, or NULL.

    Capped at 4 KiB. Returns the UTF-8 decoded string (lossy).
    """
    if ea is None:
        return None
    import idc

    s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if s is None:
        return None
    return s.decode("utf-8", errors="replace")


def _demangle(name: str | None) -> str | None:
    """Demangle a C++/Swift/ObjC/Rust mangled name, or NULL.

    Uses IDA's built-in demangler with no inhibit flags (full output).
    Returns NULL if the name cannot be demangled.
    """
    if name is None:
        return None
    import ida_name

    result = ida_name.demangle_name(name, 0, ida_name.DQT_FULL)
    return result or None


@dataclass(frozen=True)
class FunctionSpec:
    """One registered scalar: registration fields plus discovery metadata."""

    name: str
    func: object
    numargs: int
    deterministic: bool
    u64_args: tuple[int, ...]
    returns_u64: bool
    signature: str
    description: str


def _wrap_function(
    name: str,
    func: object,
    *,
    u64_args: tuple[int, ...] = (),
    returns_u64: bool = False,
) -> object:
    """Apply uint64 boundary conversion around a scalar SQL function."""
    if not u64_args and not returns_u64:
        return func

    def _wrapped(*args: Any) -> Any:
        if u64_args:
            converted = list(args)
            for idx in u64_args:
                if idx < len(converted) and converted[idx] is not None:
                    converted[idx] = decode_sql_u64_input(
                        converted[idx],
                        what=f"{name}() argument {idx + 1}",
                    )
            args = tuple(converted)
        result = func(*args)
        if returns_u64 and result is not None:
            return encode_sql_u64(int(result))
        return result

    return _wrapped


ALL_FUNCTIONS: list[FunctionSpec] = [
    FunctionSpec(
        "func_at", _func_at, 1, False, (0,), False, "func_at(ea)", "Name of the function containing ea, or NULL."
    ),
    FunctionSpec(
        "func_start",
        _func_start,
        1,
        False,
        (0,),
        True,
        "func_start(ea)",
        "Start EA of the function containing ea, or NULL.",
    ),
    FunctionSpec(
        "func_end", _func_end, 1, False, (0,), True, "func_end(ea)", "End EA of the function containing ea, or NULL."
    ),
    FunctionSpec("name_at", _name_at, 1, False, (0,), False, "name_at(ea)", "Symbol name at ea, or NULL."),
    FunctionSpec(
        "tid_name",
        _tid_name,
        1,
        False,
        (0,),
        False,
        "tid_name(id)",
        "Type or member name for a tid (e.g. 'Struct.field'), or NULL if id is not a tid.",
    ),
    FunctionSpec(
        "hex", _hex, 1, True, (), False, "hex(value)", "value as a 0x-prefixed lowercase hex string; integers only."
    ),
    FunctionSpec(
        "segment_at",
        _segment_at,
        1,
        False,
        (0,),
        False,
        "segment_at(ea)",
        "Name of the segment containing ea, or NULL.",
    ),
    FunctionSpec(
        "mnemonic_at", _mnemonic, 1, False, (0,), False, "mnemonic_at(ea)", "Instruction mnemonic at ea, or NULL."
    ),
    FunctionSpec("disasm_at", _disasm, 1, False, (0,), False, "disasm_at(ea)", "Disassembly text at ea, or NULL."),
    FunctionSpec(
        "item_type_at",
        _item_type,
        1,
        False,
        (0,),
        False,
        "item_type_at(ea)",
        "Item class at ea: code/data/string/struct/align/unknown, or NULL.",
    ),
    FunctionSpec(
        "item_size_at",
        _item_size,
        1,
        False,
        (0,),
        False,
        "item_size_at(ea)",
        "Size in bytes of the item at ea, or NULL.",
    ),
    FunctionSpec(
        "is_code_at", _is_code, 1, False, (0,), False, "is_code_at(ea)", "1 if ea is code, 0 otherwise, or NULL."
    ),
    FunctionSpec(
        "is_data_at", _is_data, 1, False, (0,), False, "is_data_at(ea)", "1 if ea is data, 0 otherwise, or NULL."
    ),
    FunctionSpec(
        "func_flag",
        _func_flag,
        1,
        True,
        (),
        False,
        "func_flag(name)",
        "Bit value for a func_t flag name; raises on unknown name.",
    ),
    FunctionSpec(
        "ui_open_disasm",
        _open_disasm,
        1,
        False,
        (0,),
        False,
        "ui_open_disasm(ea)",
        "Navigate the UI disassembly to ea and raise IDA to front; GUI only.",
    ),
    FunctionSpec(
        "ui_open_pseudocode",
        _open_pseudocode,
        1,
        False,
        (0,),
        False,
        "ui_open_pseudocode(ea)",
        "Open the UI pseudocode for ea, scrolling to its line; GUI only.",
    ),
    FunctionSpec(
        "ui_get_selection",
        _get_selection,
        0,
        False,
        (),
        False,
        "ui_get_selection()",
        "JSON of the active UI view selection, or NULL if none; GUI only.",
    ),
    FunctionSpec("read_u8", _read_u8, 1, False, (0,), False, "read_u8(ea)", "Unsigned 8-bit value at ea, or NULL."),
    FunctionSpec(
        "read_u16",
        _read_u16,
        1,
        False,
        (0,),
        False,
        "read_u16(ea)",
        "Unsigned 16-bit little-endian value at ea, or NULL.",
    ),
    FunctionSpec(
        "read_u32",
        _read_u32,
        1,
        False,
        (0,),
        False,
        "read_u32(ea)",
        "Unsigned 32-bit little-endian value at ea, or NULL.",
    ),
    FunctionSpec(
        "read_i32",
        _read_i32,
        1,
        False,
        (0,),
        False,
        "read_i32(ea)",
        "Signed 32-bit little-endian value at ea, or NULL.",
    ),
    FunctionSpec(
        "read_u64",
        _read_u64,
        1,
        False,
        (0,),
        True,
        "read_u64(ea)",
        "Unsigned 64-bit little-endian value at ea, or NULL.",
    ),
    FunctionSpec(
        "read_i64",
        _read_i64,
        1,
        False,
        (0,),
        False,
        "read_i64(ea)",
        "Signed 64-bit little-endian value at ea, or NULL.",
    ),
    FunctionSpec(
        "read_rel32",
        _read_rel32,
        1,
        False,
        (0,),
        True,
        "read_rel32(ea)",
        "Resolve a 32-bit relative pointer (ea + i32 at ea); NULL if offset is 0.",
    ),
    FunctionSpec(
        "read_bytes",
        _read_bytes,
        2,
        False,
        (0,),
        False,
        "read_bytes(ea, size)",
        "Raw bytes at ea as a hex string; capped at 4 KiB, raises above.",
    ),
    FunctionSpec(
        "read_cstr",
        _read_cstr,
        1,
        False,
        (0,),
        False,
        "read_cstr(ea)",
        "NUL-terminated C string at ea, UTF-8 lossy, or NULL.",
    ),
    FunctionSpec(
        "demangle",
        _demangle,
        1,
        False,
        (),
        False,
        "demangle(name)",
        "Demangled form of a mangled name, or NULL if not mangled.",
    ),
    FunctionSpec(
        "udm_flag",
        _udm_flag,
        1,
        True,
        (),
        False,
        "udm_flag(name)",
        "Bit value for a udm_t.tafld_bits flag name; raises on unknown name.",
    ),
    FunctionSpec(
        "set_type",
        _set_type,
        2,
        False,
        (0,),
        False,
        "set_type(ea, decl)",
        "Apply C declaration decl at ea; NULL decl clears; returns 1 on success.",
    ),
    FunctionSpec("type_at", _type_at, 1, False, (0,), False, "type_at(ea)", "C type string applied at ea, or NULL."),
    FunctionSpec(
        "mark_cfunc_dirty",
        _mark_cfunc_dirty,
        1,
        False,
        (0,),
        False,
        "mark_cfunc_dirty(ea)",
        "Invalidate the decompiler cache for the function at ea; returns 1.",
    ),
    FunctionSpec(
        "decompile",
        _decompile_func,
        1,
        False,
        (0,),
        False,
        "decompile(ea)",
        "Full pseudocode text for the function at ea, or NULL.",
    ),
    FunctionSpec(
        "parse_type",
        _parse_type,
        -1,
        False,
        (),
        False,
        "parse_type(decl[, parser])",
        "Parse one C declaration into local types; returns the ordinal.",
    ),
    FunctionSpec(
        "parse_types",
        _parse_types,
        -1,
        False,
        (),
        False,
        "parse_types(decls[, parser])",
        "Parse C declarations into local types; returns JSON [{ordinal,name}].",
    ),
]


def get_u64_result_function_names() -> frozenset[str]:
    """Return scalar function names whose results use uint64 boundary encoding."""
    return frozenset(spec.name for spec in ALL_FUNCTIONS if spec.returns_u64)


def register_all(db: "apsw.Connection") -> None:
    """Register all scalar functions on the connection."""
    for spec in ALL_FUNCTIONS:
        db.create_scalar_function(
            spec.name,
            _wrap_function(spec.name, spec.func, u64_args=spec.u64_args, returns_u64=spec.returns_u64),
            spec.numargs,
            deterministic=spec.deterministic,
        )
