"""Find references to addresses outside any loaded segment.

Entry points:

    unmapped_refs()                                   -> scan all segments
    unmapped_refs_seg(["__TEXT_EXEC", "__DATA"])       -> scan named segments
    unmapped_refs_range(0x1000, 0x2000)               -> scan an ea range

All accept an optional target_range=(lo, hi) to filter target addresses:

    unmapped_refs(target_range=(0xFFFFFE00_00000000, 0xFFFFFF00_00000000))
    unmapped_refs_seg(["__TEXT_EXEC"], target_range=(0x1000, 0x2000))

Returns dict:
    {"code": [0x...], "data": [0x...]}

    code  -- sorted unique unmapped EAs targeted by BL/B instructions (ARM64)
    data  -- sorted unique unmapped EAs targeted by data references

Use cases:
    - DSC modules: find external sections to load via dscu
    - Kernel/kext: map MMIO register accesses
    - Any binary: detect missing segments, measure IDB completeness

Notes:
    - Code targets found via decode_insn itype check (ARM64 B/BL only)
    - Data targets from IDA's xref database (ADRP+ADD/LDR, pointer tables)
    - Chained-fixup metadata (top 16 bits set) is filtered out
    - For large IDBs (DSC), prefer unmapped_refs_seg over full scan
"""

import ida_bytes
import ida_segment
import ida_ua
import idautils

# ARM64 instruction type codes (processor-defined)
_ITYPE_B = 3
_ITYPE_BL = 4
_O_NEAR = 7  # op_t.type for near code reference


def _scan_heads(heads, target_range=None):
    """Core scanner: find unmapped refs from an iterable of head EAs.

    Returns (code_targets, data_targets) as sets of int.
    """
    code_targets = set()
    data_targets = set()
    insn = ida_ua.insn_t()

    for head in heads:
        flags = ida_bytes.get_flags(head)
        if ida_bytes.is_code(flags):
            if ida_ua.decode_insn(insn, head) > 0:
                if insn.itype in (_ITYPE_B, _ITYPE_BL) and insn.ops[0].type == _O_NEAR:
                    ea = insn.ops[0].addr
                    if ea and ida_segment.getseg(ea) is None:
                        code_targets.add(ea)
            for ref in idautils.DataRefsFrom(head):
                if ref and ref >> 48 == 0 and ida_segment.getseg(ref) is None:
                    data_targets.add(ref)
        elif ida_bytes.is_data(flags):
            for ref in idautils.DataRefsFrom(head):
                if ref and ref >> 48 == 0 and ida_segment.getseg(ref) is None:
                    data_targets.add(ref)

    if target_range:
        lo, hi = target_range
        code_targets = {ea for ea in code_targets if lo <= ea < hi}
        data_targets = {ea for ea in data_targets if lo <= ea < hi}

    return code_targets, data_targets


def _build_result(code_targets, data_targets):
    return {
        "code": sorted(code_targets),
        "data": sorted(data_targets),
    }


def _all_heads():
    """Yield all heads across all segments."""
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            yield from idautils.Heads(seg.start_ea, seg.end_ea)


def unmapped_refs(target_range=None):
    """Scan all segments for references to unmapped addresses.

    Args:
        target_range: optional (lo, hi) to filter target addresses.

    Returns dict with 'code' and 'data' sorted lists.
    """
    code, data = _scan_heads(_all_heads(), target_range)
    return _build_result(code, data)


def unmapped_refs_seg(names, target_range=None):
    """Scan specific segments for references to unmapped addresses.

    Args:
        names: list of segment names to scan (e.g. ["__TEXT_EXEC", "__DATA"]).
        target_range: optional (lo, hi) to filter target addresses.

    Returns dict with 'code' and 'data' sorted lists.
    """
    name_set = set(names)
    code_all = set()
    data_all = set()

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name not in name_set:
            continue
        code, data = _scan_heads(idautils.Heads(seg.start_ea, seg.end_ea), target_range)
        code_all |= code
        data_all |= data

    return _build_result(code_all, data_all)


def unmapped_refs_range(lo, hi, target_range=None):
    """Scan an ea range for references to unmapped addresses.

    Args:
        lo: start address (inclusive).
        hi: end address (exclusive).
        target_range: optional (lo, hi) to filter target addresses.

    Returns dict with 'code' and 'data' sorted lists.
    """
    code, data = _scan_heads(idautils.Heads(lo, hi), target_range)
    return _build_result(code, data)
