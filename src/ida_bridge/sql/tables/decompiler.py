"""Decompiler virtual table: pseudocode (interleaved code + comment rows)."""

from collections.abc import Iterator
import logging
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

logger = logging.getLogger(__name__)

_IDX_NO_PUSH = 0
_IDX_FUNC_EA_EQ = 1
_IDX_EA_EQ = 2

# Row: (n, type, func_ea, line, ea, placement, valid_placements, is_orphan)
type PseudocodeRow = tuple[int, str, int, str, int | None, str | None, str | None, int | None]


# ITP name <-> int mapping.
# Covers all placements that the decompiler emits as tail/head anchors.
# The valid_placements column reports which of these work for each code line.
_ITP_NAMES: dict[str, int] = {
    "empty": 0,  # ITP_EMPTY: blank separator lines
    "arg1": 1,  # ITP_ARG1: after first call argument
    # ITP_ARG2..ARG64 are 2..64; resolved dynamically below
    "brace1": 65,  # ITP_BRACE1: opening paren of multi-line call
    "asm": 66,  # ITP_ASM: __asm line
    "else": 67,  # ITP_ELSE: else keyword
    "do": 68,  # ITP_DO: do keyword
    "semi": 69,  # ITP_SEMI: trailing comment after statement
    "curly1": 70,  # ITP_CURLY1: opening {
    "curly2": 71,  # ITP_CURLY2: closing }
    "brace2": 72,  # ITP_BRACE2: closing ) of condition
    "colon": 73,  # ITP_COLON: label colon
    "block1": 74,  # ITP_BLOCK1: standalone comment line before the item
    "block2": 75,  # ITP_BLOCK2: standalone comment line after the item
}
_ITP_INT_TO_NAME: dict[int, str] = {v: k for k, v in _ITP_NAMES.items()}
# Fill arg2..arg64 dynamically.
for _i in range(2, 65):
    _ITP_NAMES[f"arg{_i}"] = _i
    _ITP_INT_TO_NAME[_i] = f"arg{_i}"


# 9 payload bits: bit 8 marks a comment row, bits 7-0 carry the itp.
# itp values reaching the rowid always come from _ITP_NAMES (0..76), so 8 bits
# is the whole domain plus headroom.
_PSEUDOCODE_PAYLOAD_BITS = 9
_COMMENT_TYPE_BIT = 1 << 8
_ITP_MASK = 0xFF


def _encode_comment_rowid(ea: int, itp: int) -> int:
    if itp & ~_ITP_MASK:
        msg = f"itp {itp:#x} does not fit in 8 bits"
        raise ValueError(msg)
    return pack_rowid(ea, _COMMENT_TYPE_BIT | itp, payload_bits=_PSEUDOCODE_PAYLOAD_BITS)


def _encode_code_rowid(index: int) -> int:
    return pack_rowid(index, 0, payload_bits=_PSEUDOCODE_PAYLOAD_BITS)


def _containing_func_ea(ea: int) -> int:
    """Resolve the function that owns *ea*; the row's func_ea is derived, never assigned."""
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None:
        msg = f"no function containing {ea:#x}"
        raise ValueError(msg)
    return int(func.start_ea)


def _decode_rowid(rowid: int) -> tuple[bool, int, int]:
    """Decode rowid -> (is_comment, ea_or_index, itp)."""
    value, payload = unpack_rowid(rowid, payload_bits=_PSEUDOCODE_PAYLOAD_BITS)
    return bool(payload & _COMMENT_TYPE_BIT), value, payload & _ITP_MASK


# ---------------------------------------------------------------------------
# Shared decompiler helpers
# ---------------------------------------------------------------------------


def _decompile(func_ea: int) -> Any:
    """Decompile *func_ea*, return cfunc_t or raise."""
    import ida_auto
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        msg = "Hex-Rays decompiler is not available"
        raise RuntimeError(msg)

    ida_auto.auto_wait()

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure as exc:
        msg = f"decompile failed at {func_ea:#x}: {exc}"
        raise ValueError(msg) from None

    if cfunc is None:
        msg = f"decompile returned None at {func_ea:#x}"
        raise ValueError(msg)

    return cfunc


def _invalidate_decompiler_cache(func_ea: int) -> None:
    """Mark the cached cfunc dirty so the next decompile is fresh."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        return
    ida_hexrays.mark_cfunc_dirty(func_ea, False)


# ---------------------------------------------------------------------------
# pseudocode
# ---------------------------------------------------------------------------


class PseudocodeModule:
    COLUMN_SPECS = {
        "func_ea": ColumnSpec(hex=True, u64=True),
        "line": ColumnSpec(writable=True),
        "ea": ColumnSpec(hex=True, u64=True, writable=True),
        "placement": ColumnSpec(writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x("
            "n INTEGER, "
            "type TEXT, "
            "func_ea INTEGER, "
            "line TEXT, "
            "ea INTEGER, "
            "placement TEXT, "
            "valid_placements TEXT, "
            "is_orphan INTEGER"
            ")"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, PseudocodeCursor, PseudocodeTable, table_name=tablename)
        return schema, PseudocodeTable()

    Connect = Create


class PseudocodeTable:
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ((2, "func_ea"), (4, "ea"))

    def BestIndexObject(self, ii: Any) -> bool:
        func_ea_idx = find_eq_constraint(ii, 2)  # func_ea is column 2
        if func_ea_idx is not None:
            mark_constraint_used(ii, func_ea_idx, 1)
            ii.idxNum = _IDX_FUNC_EA_EQ
            ii.estimatedCost = 1_000
            ii.estimatedRows = 50
            return True

        ea_idx = find_eq_constraint(ii, 4)  # ea is column 4
        if ea_idx is not None:
            mark_constraint_used(ii, ea_idx, 1)
            ii.idxNum = _IDX_EA_EQ
            ii.estimatedCost = 1_500
            ii.estimatedRows = 5
            return True

        # No usable constraint -- prohibitive cost
        ii.idxNum = _IDX_NO_PUSH
        ii.estimatedCost = 10_000_000_000
        ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "PseudocodeCursor":
        return PseudocodeCursor()

    def UpdateInsertRow(self, newrowid: int | None, fields: tuple[Any, ...]) -> int:
        """Handle INSERT: create a decompiler comment."""
        fields = decode_u64_update_fields(self, fields)
        func_ea = fields[2]
        line = fields[3]
        ea = fields[4]
        placement = fields[5]

        if func_ea is None or ea is None:
            msg = "INSERT requires func_ea and ea"
            raise ValueError(msg)
        if placement is None:
            msg = "INSERT requires placement; pick from the valid_placements column"
            raise ValueError(msg)
        if line is None or not str(line).strip():
            msg = "INSERT requires non-empty line (comment text)"
            raise ValueError(msg)

        itp = _resolve_itp(placement)
        _set_decompiler_comment(func_ea, ea, itp, str(line))
        return _encode_comment_rowid(ea, itp)

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE: change comment text, ea, or placement."""
        is_comment, old_ea_or_idx, old_itp = _decode_rowid(rowid)
        if not is_comment:
            msg = "code rows are read-only"
            raise ValueError(msg)

        reject_readonly_update(self, fields)
        fields = decode_u64_update_fields(self, fields)
        func_ea = _containing_func_ea(old_ea_or_idx)
        new_line = fields[3]
        new_ea = fields[4]
        new_placement = fields[5]

        old_ea = old_ea_or_idx
        new_itp = _resolve_itp(new_placement) if new_placement is not None else old_itp
        target_ea = new_ea if new_ea is not None else old_ea
        location_changed = target_ea != old_ea or new_itp != old_itp

        # Resolve text: use new if provided, otherwise re-read current.
        if new_line is not None:
            text = str(new_line) if new_line else None
        elif location_changed:
            import ida_hexrays

            cfunc = _decompile(func_ea)
            tl = ida_hexrays.treeloc_t()
            tl.ea = old_ea
            tl.itp = old_itp
            text = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS)
        else:
            return  # nothing changed

        if location_changed:
            _set_decompiler_comment(func_ea, old_ea, old_itp, None)
        _set_decompiler_comment(func_ea, target_ea, new_itp, text)

    def UpdateDeleteRow(self, rowid: int) -> None:
        """Handle DELETE: clear a decompiler comment."""
        is_comment, ea, itp = _decode_rowid(rowid)
        if not is_comment:
            msg = "code rows are read-only"
            raise ValueError(msg)

        _set_decompiler_comment(_containing_func_ea(ea), ea, itp, None)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class PseudocodeCursor(BaseCursor):
    CONSTRAINT_PLANS = {
        _IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("func_ea", u64=True),)),
        _IDX_EA_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("ea", u64=True),)),
    }

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _IDX_FUNC_EA_EQ:
            self._set_iter(_pseudocode_lines(args["func_ea"]))
        elif indexnum == _IDX_EA_EQ:
            self._set_iter(_pseudocode_at_ea(args["ea"]))
        else:
            msg = "pseudocode table requires WHERE func_ea = <address> or ea = <address>"
            raise ValueError(msg)

    def Rowid(self) -> int:
        row = self._current
        if row[1] == "comment":
            ea = row[4]
            itp = _ITP_NAMES.get(row[5], 69) if row[5] else 69
            return _encode_comment_rowid(ea, itp)
        # Code row: use n (1-based) as index.
        return _encode_code_rowid(row[0])


# ---------------------------------------------------------------------------
# Interleaving engine
# ---------------------------------------------------------------------------


def _used_user_comments(cfunc: Any) -> dict[tuple[int, int], str]:
    """Return comments already rendered into Hex-Rays pseudocode text."""
    if cfunc.user_cmts is None:
        return {}
    comments: dict[tuple[int, int], str] = {}
    for tl, cmt in cfunc.user_cmts.items():
        if cmt and cmt.used:
            comments[(tl.ea, tl.itp)] = str(cmt)
    return comments


def _strip_inline_rendered_comment(line: str, comment: str) -> str:
    """Remove a rendered user comment suffix from a code line."""
    marker = line.rfind("//")
    if marker == -1:
        return line
    rendered = line[marker:]
    fragments = [part.strip() for part in comment.splitlines() if part.strip()]
    if fragments and any(fragment in rendered for fragment in fragments):
        return line[:marker].rstrip()
    return line


def _is_standalone_rendered_comment(line: str) -> bool:
    """Identify rendered user-comment lines that will be emitted separately."""
    stripped = line.strip()
    return not stripped or stripped.startswith("//")


def _pseudocode_lines(func_ea: int) -> Iterator[PseudocodeRow]:
    """Decompile and yield interleaved code + comment rows."""
    import ida_hexrays
    import ida_lines

    cfunc = _decompile(func_ea)
    sv = cfunc.get_pseudocode()
    rendered_comments = _used_user_comments(cfunc)

    # Pass 1: build code lines and position maps.
    code_lines: list[tuple[str, int | None, str | None]] = []  # (clean, ea, valid_placements)
    head_loc: dict[tuple[int, int], int] = {}  # (ea, itp) from head -> code line index
    tail_loc: dict[tuple[int, int], int] = {}  # (ea, itp) from tail -> code line index
    ea_first: dict[int, int] = {}  # ea -> first code line index (fallback)

    for sl in sv:
        raw = str(sl.line)
        clean = ida_lines.tag_remove(raw)

        head = ida_hexrays.ctree_item_t()
        tail = ida_hexrays.ctree_item_t()
        cfunc.get_line_item(raw, 0, True, head, None, tail)

        head_anchor = head.loc if head.citype == ida_hexrays.VDI_TAIL else None
        tail_anchor = tail.loc if tail.citype == ida_hexrays.VDI_TAIL else None
        head_key = (head_anchor.ea, head_anchor.itp) if head_anchor is not None else None
        tail_key = (tail_anchor.ea, tail_anchor.itp) if tail_anchor is not None else None

        if tail_key is not None and tail_key in rendered_comments:
            clean = _strip_inline_rendered_comment(clean, rendered_comments[tail_key])
        if tail_key is not None and not clean.strip() and tail_key in rendered_comments:
            continue
        if (
            tail_key is None
            and head_key is not None
            and head_key in rendered_comments
            and _is_standalone_rendered_comment(clean)
        ):
            continue

        # Extract ea: prefer tail, fall back to head.
        ea: int | None = None
        if tail_anchor is not None:
            ea = tail_anchor.ea
        elif head_anchor is not None:
            ea = head_anchor.ea

        # Extract valid placements.
        placements: list[str] = []
        if tail_anchor is not None:
            itp_name = _ITP_INT_TO_NAME.get(tail_anchor.itp)
            if itp_name and itp_name != "empty":
                placements.append(itp_name)
        if head_anchor is not None:
            head_name = _ITP_INT_TO_NAME.get(head_anchor.itp)
            if head_name and head_name not in placements:
                placements.append(head_name)

        valid_placements = ",".join(placements) if placements else None
        code_line_idx = len(code_lines)
        code_lines.append((clean, ea, valid_placements))

        # Build position maps.
        if ea is not None:
            if ea not in ea_first:
                ea_first[ea] = code_line_idx
            if tail_key is not None:
                if tail_key not in tail_loc:
                    tail_loc[tail_key] = code_line_idx
            if head_key is not None:
                if head_key not in head_loc:
                    head_loc[head_key] = code_line_idx

    # Pass 2: collect comments and classify positions.
    # before_line[i] = comments to insert BEFORE code line i
    # after_line[i] = comments to insert AFTER code line i
    before_line: dict[int, list[tuple[int, int, str]]] = {}  # idx -> [(ea, itp, text), ...]
    after_line: dict[int, list[tuple[int, int, str]]] = {}
    orphans: list[tuple[int, int, str]] = []

    cmts = ida_hexrays.restore_user_cmts(func_ea)
    if cmts is not None:
        it = ida_hexrays.user_cmts_begin(cmts)
        end = ida_hexrays.user_cmts_end(cmts)
        while it != end:
            treeloc = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmt_ea = treeloc.ea
            cmt_itp = treeloc.itp
            cmt_text = str(cmt) if cmt else ""
            if cmt_text:
                placed = False
                # Tail match -> AFTER that code line.
                if (cmt_ea, cmt_itp) in tail_loc:
                    idx = tail_loc[(cmt_ea, cmt_itp)]
                    after_line.setdefault(idx, []).append((cmt_ea, cmt_itp, cmt_text))
                    placed = True
                # Head match -> BEFORE that code line.
                elif (cmt_ea, cmt_itp) in head_loc:
                    idx = head_loc[(cmt_ea, cmt_itp)]
                    before_line.setdefault(idx, []).append((cmt_ea, cmt_itp, cmt_text))
                    placed = True
                # Fallback: ea match -> BEFORE first line with that ea.
                elif cmt_ea in ea_first:
                    idx = ea_first[cmt_ea]
                    before_line.setdefault(idx, []).append((cmt_ea, cmt_itp, cmt_text))
                    placed = True

                if not placed:
                    orphans.append((cmt_ea, cmt_itp, cmt_text))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(cmts)

    # Sort comment lists by itp for deterministic ordering.
    for lst in before_line.values():
        lst.sort(key=lambda x: x[1])
    for lst in after_line.values():
        lst.sort(key=lambda x: x[1])

    # Pass 3: interleave and yield rows with sequential n.
    n = 0

    def _comment_row(cmt_ea: int, cmt_itp: int, cmt_text: str, is_orphan: int) -> PseudocodeRow:
        nonlocal n
        n += 1
        placement_name = _ITP_INT_TO_NAME.get(cmt_itp, str(cmt_itp))
        return (n, "comment", func_ea, cmt_text, cmt_ea, placement_name, None, is_orphan)

    for i, (clean, ea, valid_placements) in enumerate(code_lines):
        # Comments BEFORE this code line.
        for cmt_ea, cmt_itp, cmt_text in before_line.get(i, ()):
            yield _comment_row(cmt_ea, cmt_itp, cmt_text, 0)

        # The code line itself.
        n += 1
        yield (n, "code", func_ea, clean, ea, None, valid_placements, None)

        # Comments AFTER this code line.
        for cmt_ea, cmt_itp, cmt_text in after_line.get(i, ()):
            yield _comment_row(cmt_ea, cmt_itp, cmt_text, 0)

    # Orphan comments at the end.
    for cmt_ea, cmt_itp, cmt_text in orphans:
        yield _comment_row(cmt_ea, cmt_itp, cmt_text, 1)


def _pseudocode_at_ea(ea: int) -> Iterator[PseudocodeRow]:
    """Resolve ea to containing function, decompile, yield rows where ea matches."""
    for row in _pseudocode_lines(_containing_func_ea(ea)):
        if row[4] == ea:
            yield row


# ---------------------------------------------------------------------------
# Comment helpers
# ---------------------------------------------------------------------------


def _resolve_itp(placement: str) -> int:
    """Resolve a placement name to an ITP constant."""
    name = placement.lower()
    itp = _ITP_NAMES.get(name)
    if itp is None:
        valid = ", ".join(sorted(_ITP_NAMES))
        msg = f"unknown placement '{placement}'; valid: {valid}"
        raise ValueError(msg)
    return itp


def _probe_valid_placements(func_ea: int, ea: int) -> list[str]:
    """Find valid placements for *ea* using get_line_item on rendered pseudocode."""
    import ida_hexrays

    cfunc = _decompile(func_ea)
    sv = cfunc.get_pseudocode()

    valid: list[str] = []
    seen: set[str] = set()
    for sl in sv:
        raw = str(sl.line)
        head = ida_hexrays.ctree_item_t()
        tail = ida_hexrays.ctree_item_t()
        cfunc.get_line_item(raw, 0, True, head, None, tail)

        line_ea: int | None = None
        if tail.citype == ida_hexrays.VDI_TAIL:
            line_ea = tail.loc.ea
        elif head.citype == ida_hexrays.VDI_TAIL:
            line_ea = head.loc.ea
        if line_ea != ea:
            continue

        if tail.citype == ida_hexrays.VDI_TAIL:
            name = _ITP_INT_TO_NAME.get(tail.loc.itp)
            if name and name != "empty" and name not in seen:
                valid.append(name)
                seen.add(name)
        if head.citype == ida_hexrays.VDI_TAIL:
            head_name = _ITP_INT_TO_NAME.get(head.loc.itp)
            if head_name and head_name not in seen:
                valid.append(head_name)
                seen.add(head_name)
    return valid


def _set_decompiler_comment(func_ea: int, ea: int, itp: int, text: str | None, *, validate: bool = True) -> None:
    """Set or clear a single decompiler comment and persist.

    If the comment doesn't render (used=false), it is removed and an error
    is raised listing which placements would work for that ea.
    """
    import ida_hexrays

    cfunc = _decompile(func_ea)
    tl = ida_hexrays.treeloc_t()
    tl.ea = ea
    tl.itp = itp
    if text:
        cfunc.set_user_cmt(tl, text)
    else:
        cfunc.set_user_cmt(tl, None)
    cfunc.save_user_cmts()
    _invalidate_decompiler_cache(func_ea)

    if validate and text:
        cfunc2 = _decompile(func_ea)
        cfunc2.get_pseudocode()
        used = False
        for k, v in cfunc2.user_cmts.items():
            if k.ea == ea and k.itp == itp:
                used = bool(v.used)
                break
        if not used:
            # Remove the ineffective comment.
            tl2 = ida_hexrays.treeloc_t()
            tl2.ea = ea
            tl2.itp = itp
            cfunc2.set_user_cmt(tl2, None)
            cfunc2.save_user_cmts()
            _invalidate_decompiler_cache(func_ea)
            placement = _ITP_INT_TO_NAME.get(itp, str(itp))
            valid = _probe_valid_placements(func_ea, ea)
            if valid:
                valid_str = ", ".join(valid)
                msg = (
                    f"comment at ea={hex(ea)} with placement='{placement}' did not render "
                    f"(IDA reports used=false); valid placements for this ea: {valid_str}"
                )
            else:
                msg = (
                    f"comment at ea={hex(ea)} with placement='{placement}' did not render "
                    f"(IDA reports used=false); no placement renders at this ea "
                    f"(address may not map to an addressable ctree item in this function)"
                )
            raise ValueError(msg)


# ---------------------------------------------------------------------------
# ctree_lvars
# ---------------------------------------------------------------------------

_LVARS_IDX_NO_PUSH = 0
_LVARS_IDX_FUNC_EA_EQ = 1

# (func_ea, idx, name, type, comment, size, is_arg, is_result, is_stk_var, is_reg_var, stkoff)
type LvarRow = tuple[int, int, str, str, str | None, int, int, int, int, int, int | None]


# 16 payload bits for the lvar index. Deliberately generous: the ea ceiling it
# leaves (2**47) still clears every real address, so there is nothing to gain by
# shrinking it, and a function with more lvars raises instead of colliding.
_LVAR_PAYLOAD_BITS = 16


class CtreeLvarsModule:
    COLUMN_SPECS = {
        "func_ea": ColumnSpec(hex=True, u64=True),
        "name": ColumnSpec(writable=True),
        "type": ColumnSpec(writable=True),
        "comment": ColumnSpec(writable=True),
    }

    def Create(self, db: Any, modulename: str, dbname: str, tablename: str, *args: str) -> tuple[str, Any]:
        schema = (
            "CREATE TABLE x("
            "func_ea INTEGER, "
            "idx INTEGER, "
            "name TEXT, "
            "type TEXT, "
            "comment TEXT, "
            "size INTEGER, "
            "is_arg INTEGER, "
            "is_result INTEGER, "
            "is_stk_var INTEGER, "
            "is_reg_var INTEGER, "
            "stkoff INTEGER"
            ")"
        )
        apply_schema_specs(schema, self.COLUMN_SPECS, CtreeLvarsCursor, CtreeLvarsTable, table_name=tablename)
        return schema, CtreeLvarsTable()

    Connect = Create


class CtreeLvarsTable:
    U64_COLUMN_SPECS: tuple[tuple[int, str], ...] = ()

    def BestIndexObject(self, ii: Any) -> bool:
        func_ea_idx = find_eq_constraint(ii, 0)  # func_ea is column 0
        if func_ea_idx is not None:
            mark_constraint_used(ii, func_ea_idx, 1)
            ii.idxNum = _LVARS_IDX_FUNC_EA_EQ
            ii.estimatedCost = 1_000
            ii.estimatedRows = 20
            return True

        ii.idxNum = _LVARS_IDX_NO_PUSH
        ii.estimatedCost = 10_000_000_000
        ii.estimatedRows = 1_000_000
        return True

    def Open(self) -> "CtreeLvarsCursor":
        return CtreeLvarsCursor()

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:
        """Handle UPDATE on writable columns: name, type, comment."""
        import ida_hexrays
        import ida_typeinf

        reject_readonly_update(self, fields)
        fields = decode_u64_update_fields(self, fields)
        func_ea, idx = unpack_rowid(rowid, payload_bits=_LVAR_PAYLOAD_BITS)

        new_name = fields[2]
        new_type = fields[3]
        new_comment = fields[4]

        if new_name is not None and not isinstance(new_name, str):
            msg = "ctree_lvars.name must be TEXT"
            raise ValueError(msg)
        if new_type is not None and not isinstance(new_type, str):
            msg = "ctree_lvars.type must be TEXT"
            raise ValueError(msg)
        if new_comment is not None and not isinstance(new_comment, str):
            msg = "ctree_lvars.comment must be TEXT"
            raise ValueError(msg)

        cfunc = _decompile(func_ea)
        lvars = cfunc.get_lvars()
        if lvars is None or idx < 0 or idx >= len(lvars):
            msg = f"lvar index {idx} out of range at {func_ea:#x}"
            raise ValueError(msg)

        lv = lvars[idx]
        new_name = new_name.strip() if new_name is not None else None
        new_type = new_type.strip() if new_type is not None else None

        changing_name = new_name and new_name != lv.name
        changing_type = new_type and new_type != str(lv.type())
        if (lv.is_arg_var or lv.is_result_var) and (changing_name or changing_type):
            kind = "argument" if lv.is_arg_var else "result variable"
            msg = f"ctree_lvars cannot change {kind} name/type; update the function prototype instead"
            raise ValueError(msg)

        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = lv
        mli_flags = 0

        if changing_name:
            lsi.name = new_name
            mli_flags |= ida_hexrays.MLI_NAME

        if changing_type:
            tif = ida_typeinf.tinfo_t()
            if not tif.parse(new_type, None, ida_typeinf.PT_SIL):
                msg = f"ctree_lvars.type: failed to parse type: {new_type!r}"
                raise ValueError(msg)
            lsi.type = tif
            mli_flags |= ida_hexrays.MLI_TYPE

        if new_comment is not None:
            current_cmt = lv.cmt or ""
            if new_comment != current_cmt:
                lsi.cmt = new_comment
                mli_flags |= ida_hexrays.MLI_CMT

        if mli_flags == 0:
            return

        if not ida_hexrays.modify_user_lvar_info(func_ea, mli_flags, lsi):
            parts = []
            if mli_flags & ida_hexrays.MLI_NAME:
                parts.append("name")
            if mli_flags & ida_hexrays.MLI_TYPE:
                parts.append("type")
            if mli_flags & ida_hexrays.MLI_CMT:
                parts.append("comment")
            msg = f"modify lvar {'+'.join(parts)} failed at {func_ea:#x} idx {idx}"
            raise ValueError(msg)
        _invalidate_decompiler_cache(func_ea)

    def Disconnect(self) -> None:
        pass

    Destroy = Disconnect


class CtreeLvarsCursor(BaseCursor):
    CONSTRAINT_PLANS = {
        _LVARS_IDX_FUNC_EA_EQ: ConstraintPlanSpec(args=(ConstraintArgSpec("func_ea", u64=True),)),
    }

    def Filter(self, indexnum: int, indexstring: str | None, constraintargs: tuple[Any, ...]) -> None:
        args = self._decode_constraint_args(indexnum, constraintargs)

        if indexnum == _LVARS_IDX_FUNC_EA_EQ:
            self._set_iter(_lvars_for_func(args["func_ea"]))
        else:
            msg = "ctree_lvars table requires WHERE func_ea = <address>"
            raise ValueError(msg)

    def Rowid(self) -> int:
        return pack_rowid(self._current[0], self._current[1], payload_bits=_LVAR_PAYLOAD_BITS)


def _lvars_for_func(func_ea: int) -> Iterator[LvarRow]:
    """Decompile and yield lvar rows for a function."""
    cfunc = _decompile(func_ea)

    lvars = cfunc.get_lvars()
    if lvars is None:
        msg = f"no lvars returned for {func_ea:#x}"
        raise ValueError(msg)

    for i in range(len(lvars)):
        lv = lvars[i]
        yield (
            func_ea,
            i,
            str(lv.name),
            str(lv.type()),
            str(lv.cmt) if lv.cmt else None,
            lv.width,
            1 if lv.is_arg_var else 0,
            1 if lv.is_result_var else 0,
            1 if lv.is_stk_var else 0,
            1 if lv.is_reg_var else 0,
            lv.get_stkoff() if lv.is_stk_var else None,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_TABLES: list[tuple[type, str]] = [
    (PseudocodeModule, "pseudocode"),
    (CtreeLvarsModule, "ctree_lvars"),
]
