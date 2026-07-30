"""IDB query utilities — structured data extraction for use with _result_.

Standalone helpers for common IDB queries. No heuristics or interpretation —
returns raw data, agent decides what to make of it.

Load once, call as needed:

    metadata() -> dict — format, arch, bitness, endianness, PIE, compiler, file type.
    segments() -> list[dict] — segment/section inventory with sizes, permissions, classes.
    entrypoints() -> list[dict] — entry points with names and addresses.
    imports() -> list[dict] — imported modules with per-symbol detail.
    libraries() -> list[dict] — linked libraries/frameworks with kind and import count.
    names(skip_auto=True) -> list[dict] — named addresses (functions, globals, labels).
    strings(min_length=4, max_strings=2000) -> list[dict] — strings with xref status.
    types() -> list[dict] — local type library entries (structs, enums, typedefs).
    function_stats(top_n=20) -> dict — count, size distribution, largest functions.
    xref_stats(top_n=20) -> dict — fan-in/fan-out per function, top callers/callees.
    idb_coverage(min_seg_size=0x1000) -> dict — undefined bytes, function coverage, unexplored regions.
    objc_metadata(max_selectors=500) -> dict — ObjC classes, selectors, protocols, categories.
    linkage_tables() -> list[dict] — GOT, PLT, auth stubs, lazy/non-lazy symbol pointers with resolved names.
    init_fini() -> list[dict] — constructors, destructors, mod_init/mod_term function pointers.
    code_patterns() -> dict — PAC usage, stack canaries, tail calls, ObjC messaging, exception handling.
    collect_all(output_path=None, exclude=None) -> dict — run every collector with optional regex filters; write to JSON file.

Filtering:

    collect_all accepts an exclude dict with regex patterns to filter noise at collection time.
    Keys:
        funcs    - patterns matched against function/data names. Filters: names, function_stats, xref_stats.
        segs     - patterns matched against segment names. Full positional exclusion: all items
                   (functions, names, strings, xrefs, ObjC metadata, linkage tables, init/fini,
                   code patterns) in matching segments are dropped. The segments
                   themselves are also hidden from segments and idb_coverage.
        strings  - patterns matched against string content. Filters: strings.

    Patterns use re.search (substring match unless anchored with ^/$).
    Excluded items are dropped before counting — function counts, xref stats, and coverage
    reflect only the retained set. The filter set is saved in the output under "filters".

    Example (dyld shared cache single-module IDB after prep):
        collect_all(output_path="/tmp/inv.json", exclude={
            "funcs": ["OUTLINED_FUNCTION", "^nullsub_", "^j_"],
            "segs": ["^inlined_", "^dyld_shared_cache"],
        })

    Build filters from what you observe in the IDB (segment names, function name prefixes,
    language signals, code_patterns() output). The platform-specific skill lists
    common patterns — select the ones that apply, don't apply blindly.
"""

import json
import re

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idautils

# auto-name prefixes IDA assigns to unnamed items
_AUTO_PREFIXES = (
    "sub_",
    "nullsub_",
    "loc_",
    "j_",
    "unk_",
    "byte_",
    "word_",
    "dword_",
    "qword_",
    "off_",
    "stru_",
    "enum_",
    "flt_",
    "dbl_",
)

# filetype id -> name
_FILETYPE_NAMES = {
    getattr(ida_ida, k): k[2:] for k in dir(ida_ida) if k.startswith("f_") and isinstance(getattr(ida_ida, k), int)
}


def _compile_excludes(patterns: list[str] | None) -> re.Pattern | None:
    """Compile a list of regex patterns into a single alternation."""
    if not patterns:
        return None
    return re.compile("|".join(f"(?:{p})" for p in patterns))


def _excluded_seg_starts(pattern: re.Pattern) -> set[int]:
    """Return start_ea set for segments whose name matches pattern."""
    result = set()
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if pattern.search(ida_segment.get_segm_name(seg)):
            result.add(seg.start_ea)
    return result


def _in_excluded_seg(ea: int, starts: set[int]) -> bool:
    """Check if ea falls in a segment whose start_ea is in the excluded set."""
    seg = ida_segment.getseg(ea)
    return seg is not None and seg.start_ea in starts


def metadata() -> dict:
    """Arch, bits, endianness, imagebase, input file, address range, file type."""
    ida_auto.auto_wait()
    ft = ida_ida.inf_get_filetype()
    return {
        "input_file": ida_nalt.get_root_filename(),
        "file_path": ida_nalt.get_input_file_path(),
        "image_base": hex(ida_nalt.get_imagebase()),
        "arch": ida_ida.inf_get_procname(),
        "bits": 64 if ida_ida.inf_is_64bit() else 32,
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "filetype": _FILETYPE_NAMES.get(ft, str(ft)),
        "is_dll": ida_ida.inf_is_dll(),
        "is_kernel": ida_ida.inf_is_kernel_mode(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
    }


def segments(exclude_re: re.Pattern | None = None) -> list[dict]:
    """All segments: name, range, size, permissions."""
    ida_auto.auto_wait()
    result = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        sname = ida_segment.get_segm_name(seg)
        if exclude_re and exclude_re.search(sname):
            continue
        p = seg.perm
        perm = ("r" if p & 4 else "-") + ("w" if p & 2 else "-") + ("x" if p & 1 else "-")
        result.append(
            {
                "name": sname,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.end_ea - seg.start_ea),
                "perm": perm,
            }
        )
    return result


def entrypoints() -> list[dict]:
    """Entrypoints / exports: ordinal, address, name."""
    ida_auto.auto_wait()
    result = []
    for i in range(ida_entry.get_entry_qty()):
        o = ida_entry.get_entry_ordinal(i)
        result.append(
            {
                "ordinal": o,
                "ea": hex(ida_entry.get_entry(o)),
                "name": ida_entry.get_entry_name(o) or "",
            }
        )
    return result


def imports() -> list[dict]:
    """Imported modules with their symbols."""
    ida_auto.auto_wait()
    result = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i)
        syms: list[dict] = []

        def _cb(ea: int, name: str | None, ordinal: int) -> int:
            syms.append(  # noqa: B023
                {
                    "ea": hex(ea),
                    "name": name or f"ord_{ordinal}",
                }
            )
            return 1

        ida_nalt.enum_import_names(i, _cb)
        result.append(
            {
                "module": mod_name or f"module_{i}",
                "count": len(syms),
                "symbols": syms,
            }
        )
    return result


def names(
    skip_auto: bool = True, exclude_re: re.Pattern | None = None, seg_starts: set[int] | None = None
) -> list[dict]:
    """Named addresses (functions + globals). skip_auto filters IDA auto-names."""
    ida_auto.auto_wait()
    result = []
    for ea, name in idautils.Names():
        if skip_auto and name.startswith(_AUTO_PREFIXES):
            continue
        if exclude_re and exclude_re.search(name):
            continue
        if seg_starts and _in_excluded_seg(ea, seg_starts):
            continue
        is_func = ida_funcs.get_func(ea) is not None
        demangled = ida_name.demangle_name(name, 0)
        entry = {
            "ea": hex(ea),
            "name": name,
            "type": "func" if is_func else "data",
        }
        if demangled:
            entry["demangled"] = demangled
        result.append(entry)
    return result


def strings(
    min_len: int = 6,
    max_strings: int = 2000,
    max_xrefs: int = 5,
    exclude_re: re.Pattern | None = None,
    seg_starts: set[int] | None = None,
) -> list[dict]:
    """All strings with xref status."""
    ida_auto.auto_wait()
    result = []
    for s in idautils.Strings():
        txt = str(s)
        if len(txt) < min_len:
            continue
        if exclude_re and exclude_re.search(txt):
            continue
        if seg_starts and _in_excluded_seg(s.ea, seg_starts):
            continue
        xref_funcs = []
        for x in idautils.XrefsTo(s.ea):
            func = ida_funcs.get_func(x.frm)
            if func:
                fname = ida_funcs.get_func_name(func.start_ea)
                if fname not in xref_funcs:
                    xref_funcs.append(fname)
                    if len(xref_funcs) >= max_xrefs:
                        break
        result.append(
            {
                "ea": hex(s.ea),
                "text": txt[:200],
                "length": len(txt),
                "xref_funcs": xref_funcs,
            }
        )
        if len(result) >= max_strings:
            break
    result.sort(key=lambda e: len(e["xref_funcs"]), reverse=True)
    return result


def types() -> list[dict]:
    """Local types with size, member count, and source TIL."""
    ida_auto.auto_wait()
    til = ida_typeinf.get_idati()

    # cache base TILs for source lookup
    base_tils = [til.base(i) for i in range(til.nbases)]

    result = []
    for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        kind = "other"
        if tif.is_struct():
            kind = "struct"
        elif tif.is_union():
            kind = "union"
        elif tif.is_enum():
            kind = "enum"
        elif tif.is_typedef():
            kind = "typedef"

        entry: dict = {
            "ordinal": ordinal,
            "name": name,
            "kind": kind,
        }

        if kind in ("struct", "union"):
            size = tif.get_size()
            if size != 0xFFFFFFFFFFFFFFFF:
                entry["size"] = hex(size)
            entry["members"] = tif.get_udt_nmembers()
        elif kind == "enum":
            entry["members"] = tif.get_enum_nmembers()
        elif kind == "typedef":
            size = tif.get_size()
            if size != 0xFFFFFFFFFFFFFFFF:
                entry["size"] = hex(size)

        # source: which TIL the type originates from
        source = "local"
        for btil in base_tils:
            check = ida_typeinf.tinfo_t()
            if check.get_named_type(btil, name):
                source = btil.name or "base"
                break
        entry["source"] = source

        result.append(entry)
    return result


def function_stats(top_n: int = 20, exclude_re: re.Pattern | None = None, seg_starts: set[int] | None = None) -> dict:
    """Function count and largest functions by size."""
    ida_auto.auto_wait()
    sizes = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f:
            if seg_starts and _in_excluded_seg(ea, seg_starts):
                continue
            fname = ida_funcs.get_func_name(ea)
            if exclude_re and exclude_re.search(fname):
                continue
            sizes.append({"ea": hex(ea), "name": fname, "size": f.size()})
    sizes.sort(key=lambda x: x["size"], reverse=True)
    for s in sizes:
        s["size"] = hex(s["size"])
    return {
        "count": len(sizes),
        "largest": sizes[:top_n],
    }


def xref_stats(top_n: int = 20, exclude_re: re.Pattern | None = None, seg_starts: set[int] | None = None) -> dict:
    """Top functions by fan-in and fan-out.

    fan_in: number of cross-references to this function.
    fan_out: number of unique function targets called from this function.
    """
    ida_auto.auto_wait()
    func_set = set()
    fan_in: dict[int, int] = {}
    fan_out: dict[int, set[int]] = {}
    for ea in idautils.Functions():
        if seg_starts and _in_excluded_seg(ea, seg_starts):
            continue
        if exclude_re and exclude_re.search(ida_funcs.get_func_name(ea) or ""):
            continue
        func_set.add(ea)
        fan_in[ea] = 0
        fan_out[ea] = set()

    for ea in func_set:
        for x in idautils.XrefsTo(ea):
            caller = ida_funcs.get_func(x.frm)
            if caller and caller.start_ea in func_set:
                fan_in[ea] += 1
                fan_out[caller.start_ea].add(ea)

    def _entry(ea: int) -> dict:
        return {
            "ea": hex(ea),
            "name": ida_funcs.get_func_name(ea),
            "fan_in": fan_in[ea],
            "fan_out": len(fan_out[ea]),
        }

    by_fan_in = sorted(func_set, key=lambda ea: fan_in[ea], reverse=True)[:top_n]
    by_fan_out = sorted(func_set, key=lambda ea: len(fan_out[ea]), reverse=True)[:top_n]
    return {
        "by_fan_in": [_entry(ea) for ea in by_fan_in],
        "by_fan_out": [_entry(ea) for ea in by_fan_out],
    }


def idb_coverage(min_seg_size: int = 0x1000, exclude_re: re.Pattern | None = None) -> dict:
    """IDB analysis coverage per segment: undefined bytes and function coverage.

    Segments smaller than min_seg_size are excluded from per-segment output
    but still count toward totals. Segments matching exclude_re are skipped entirely.
    """
    ida_auto.auto_wait()
    BADADDR = ida_idaapi.BADADDR
    results = []
    total_defined = 0
    total_undefined = 0
    skipped = 0

    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        sname = ida_segment.get_segm_name(seg)
        if exclude_re and exclude_re.search(sname):
            skipped += 1
            continue
        seg_size = seg.end_ea - seg.start_ea
        is_exec = bool(seg.perm & 1)

        # function bytes (exec segments only)
        func_bytes = 0
        if is_exec:
            for fea in idautils.Functions(seg.start_ea, seg.end_ea):
                f = ida_funcs.get_func(fea)
                if f:
                    start = max(f.start_ea, seg.start_ea)
                    end = min(f.end_ea, seg.end_ea)
                    if end > start:
                        func_bytes += end - start

        # undefined bytes via next_unknown() hops — O(undefined_regions)
        undef_bytes = 0
        undef_regions = 0
        cursor = ida_bytes.next_unknown(seg.start_ea - 1, seg.end_ea)
        while cursor != BADADDR and cursor < seg.end_ea:
            undef_regions += 1
            defined = ida_bytes.next_head(cursor, seg.end_ea)
            if defined == BADADDR or defined >= seg.end_ea:
                undef_bytes += seg.end_ea - cursor
            else:
                undef_bytes += defined - cursor
            cursor = ida_bytes.next_unknown(defined if defined != BADADDR else seg.end_ea, seg.end_ea)

        total_defined += seg_size - undef_bytes
        total_undefined += undef_bytes

        if seg_size < min_seg_size:
            skipped += 1
            continue

        entry = {
            "name": sname,
            "start": hex(seg.start_ea),
            "size": hex(seg_size),
            "undef_bytes": hex(undef_bytes),
            "undef_percent": round(undef_bytes / seg_size * 100, 1) if seg_size else 0,
            "undef_regions": undef_regions,
        }
        if is_exec:
            entry["func_bytes"] = hex(func_bytes)
            entry["func_percent"] = round(func_bytes / seg_size * 100, 1) if seg_size else 0
        results.append(entry)

    total = total_defined + total_undefined
    return {
        "total_bytes": hex(total),
        "defined_percent": round(total_defined / total * 100, 1) if total else 0,
        "skipped_segments": skipped,
        "segments": results,
    }


def objc_metadata(max_selectors: int = 500, seg_starts: set[int] | None = None) -> dict:
    """ObjC classes, selectors, and protocols from names and segment data.

    Combines three discovery methods:
    1. Names table: _OBJC_CLASS_$_, classRef_, _OBJC_SELECTOR_$_, sel_,
       _OBJC_PROTOCOL_$_ prefixes.
    2. Segment strings: __objc_classname (class names), __objc_methname
       (selector names).
    3. Stub functions: _objc_msgSend$<selector> in __objc_stubs segments.

    Names are walked first so that protocol identity is known before reading
    __objc_classname (which stores both class and protocol name strings).

    seg_starts: if provided, items in matching segments are excluded.
    """
    ida_auto.auto_wait()

    seen_classes: set[str] = set()
    seen_selectors: set[str] = set()
    seen_protocols: set[str] = set()
    classes: list[dict] = []
    selectors: list[dict] = []
    protocols: list[dict] = []

    def _add_class(name: str, ea: int) -> None:
        if name not in seen_classes:
            classes.append({"ea": hex(ea), "name": name})
            seen_classes.add(name)

    def _add_selector(name: str, ea: int) -> None:
        if name not in seen_selectors:
            selectors.append({"ea": hex(ea), "name": name})
            seen_selectors.add(name)

    def _add_protocol(name: str, ea: int) -> None:
        if name not in seen_protocols:
            protocols.append({"ea": hex(ea), "name": name})
            seen_protocols.add(name)

    # --- Pass 1: names table (definitive class/protocol/selector identity) ---

    for ea, name in idautils.Names():
        if seg_starts and _in_excluded_seg(ea, seg_starts):
            continue
        if name.startswith("_OBJC_CLASS_$_"):
            _add_class(name[14:], ea)
        elif name.startswith("OBJC_CLASS_$_"):
            _add_class(name[13:], ea)
        elif name.startswith("classRef_"):
            _add_class(name[9:], ea)
        elif name.startswith("_OBJC_SELECTOR_$_"):
            _add_selector(name[17:], ea)
        elif name.startswith("sel_"):
            _add_selector(name[4:], ea)
        elif name.startswith("_OBJC_PROTOCOL_$_"):
            _add_protocol(name[17:], ea)
        elif name.startswith("OBJC_PROTOCOL_$_"):
            _add_protocol(name[16:], ea)

    # --- Pass 2: segment data (supplements names) ---

    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg_starts and seg.start_ea in seg_starts:
            continue
        sname = ida_segment.get_segm_name(seg)

        if "__objc_classname" in sname:
            raw = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if raw:
                cursor = seg.start_ea
                for part in raw.split(b"\x00"):
                    if part:
                        cname = part.decode("utf-8", errors="replace")
                        # segment stores both class and protocol names;
                        # skip items already identified as protocols
                        if cname not in seen_protocols:
                            _add_class(cname, cursor)
                    cursor += len(part) + 1

        elif "__objc_methname" in sname:
            raw = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if raw:
                cursor = seg.start_ea
                for part in raw.split(b"\x00"):
                    if part:
                        s = part.decode("utf-8", errors="replace")
                        # filter property type encodings (e.g. T@"NSString",R,C)
                        if not (len(s) > 1 and s[0] == "T" and "," in s):
                            _add_selector(s, cursor)
                    cursor += len(part) + 1

        elif "__objc_stubs" in sname:
            for fea in idautils.Functions(seg.start_ea, seg.end_ea):
                fname = ida_funcs.get_func_name(fea)
                idx = fname.find("$")
                if idx >= 0:
                    _add_selector(fname[idx + 1 :], fea)

    sel_count = len(selectors)
    return {
        "class_count": len(classes),
        "classes": classes,
        "selector_count": sel_count,
        "selectors": selectors[:max_selectors],
        "protocol_count": len(protocols),
        "protocols": protocols,
    }


# segment names that hold linkage pointers (GOT, lazy/non-lazy symbol ptrs)
_LINKAGE_PTR_SEGS = {
    "__got",
    "__auth_got",
    "__auth_ptr",
    "__la_symbol_ptr",
    "__nl_symbol_ptr",
    ".got",
    ".got.plt",
}

# segment names that hold linkage stubs (executable thunks)
_LINKAGE_STUB_SEGS = {
    "__stubs",
    "__auth_stubs",
    "__objc_stubs",
    ".plt",
    ".plt.got",
}


def linkage_tables(seg_starts: set[int] | None = None) -> list[dict]:
    """Linkage segments: GOT, PLT, auth stubs, lazy/non-lazy symbol pointers.

    For pointer segments: reads pointer-sized entries, resolves slot and target names.
    For stub segments: enumerates functions, reports names.

    seg_starts: if provided, segments in the excluded set are skipped.
    """
    ida_auto.auto_wait()
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    read_ptr = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword

    result = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg_starts and seg.start_ea in seg_starts:
            continue
        sname = ida_segment.get_segm_name(seg)
        # DSC module IDBs prefix section names: "SomeLib:__got" -> "__got"
        section = sname.rsplit(":", 1)[-1] if ":" in sname else sname

        if section in _LINKAGE_PTR_SEGS:
            entries: list[dict] = []
            cursor = seg.start_ea
            while cursor < seg.end_ea:
                slot_name = ida_name.get_name(cursor) or ""
                val = read_ptr(cursor)
                target_name = ida_name.get_name(val) if val else ""
                entry: dict = {"ea": hex(cursor)}
                # prefer slot name; fall back to target name
                name = slot_name or target_name or ""
                if name:
                    entry["name"] = name
                entries.append(entry)
                cursor += ptr_size
            result.append(
                {
                    "segment": sname,
                    "kind": "pointer",
                    "count": len(entries),
                    "entries": entries,
                }
            )

        elif section in _LINKAGE_STUB_SEGS:
            entries = []
            for fea in idautils.Functions(seg.start_ea, seg.end_ea):
                fname = ida_funcs.get_func_name(fea)
                entries.append({"ea": hex(fea), "name": fname or ""})
            result.append(
                {
                    "segment": sname,
                    "kind": "stub",
                    "count": len(entries),
                    "entries": entries,
                }
            )

    return result


# segment names holding constructor / destructor pointer arrays
_INIT_FINI_SEGS = {
    "__mod_init_func",
    "__mod_term_func",
    ".init_array",
    ".fini_array",
    ".ctors",
    ".dtors",
}


def init_fini(seg_starts: set[int] | None = None) -> list[dict]:
    """Constructor and destructor tables (mod_init/term, init/fini_array).

    Reads pointer-sized entries, resolves each to a function name.

    seg_starts: if provided, segments in the excluded set are skipped.
    """
    ida_auto.auto_wait()
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    read_ptr = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword

    result = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg_starts and seg.start_ea in seg_starts:
            continue
        sname = ida_segment.get_segm_name(seg)
        section = sname.rsplit(":", 1)[-1] if ":" in sname else sname
        if section not in _INIT_FINI_SEGS:
            continue

        entries: list[dict] = []
        cursor = seg.start_ea
        while cursor < seg.end_ea:
            val = read_ptr(cursor)
            fname = ida_funcs.get_func_name(val) if val else ""
            entry: dict = {"ea": hex(cursor), "target": hex(val)}
            if fname:
                entry["name"] = fname
            entries.append(entry)
            cursor += ptr_size

        kind = "init" if "init" in section or "ctor" in section else "fini"
        result.append(
            {
                "segment": sname,
                "kind": kind,
                "count": len(entries),
                "entries": entries,
            }
        )

    return result


def code_patterns(seg_starts: set[int] | None = None) -> dict:
    """Observable code patterns: outlined chunks, ObjC, Swift, exception handling.

    All counts are deterministic (segment presence, name matching).

    seg_starts: if provided, segments in the excluded set are skipped.
    """
    ida_auto.auto_wait()

    outlined_functions = 0
    inlined_segments = 0
    swift_segments: list[dict] = []
    exception_segments: list[dict] = []
    objc_stubs_count = 0

    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg_starts and seg.start_ea in seg_starts:
            continue
        sname = ida_segment.get_segm_name(seg)
        seg_size = seg.end_ea - seg.start_ea

        if sname.startswith("inlined_"):
            inlined_segments += 1
        elif sname.startswith("__swift") or sname.startswith("__constg_swiftt"):
            swift_segments.append({"name": sname, "size": hex(seg_size)})
        elif any(k in sname for k in ("unwind_info", "eh_frame", "except_tab")):
            exception_segments.append({"name": sname, "size": hex(seg_size)})
        elif "__objc_stubs" in sname:
            objc_stubs_count += sum(1 for _ in idautils.Functions(seg.start_ea, seg.end_ea))

    # count OUTLINED_FUNCTION_ names across non-excluded functions
    for ea in idautils.Functions():
        if seg_starts and _in_excluded_seg(ea, seg_starts):
            continue
        fname = ida_funcs.get_func_name(ea)
        if fname and "OUTLINED_FUNCTION" in fname:
            outlined_functions += 1

    result: dict = {}

    if outlined_functions or inlined_segments:
        result["outlined"] = {
            "outlined_functions": outlined_functions,
            "inlined_segments": inlined_segments,
        }

    if objc_stubs_count:
        result["objc_stubs"] = objc_stubs_count

    if swift_segments:
        result["swift"] = swift_segments

    if exception_segments:
        result["exception_handling"] = exception_segments

    return result


def libraries() -> list[dict]:
    """Linked libraries and frameworks from import module table.

    Each entry has:
      - path: full dylib/framework path as recorded in the binary
      - name: short name (framework name or dylib basename)
      - kind: "framework", "dylib", or "other"
      - import_count: number of symbols imported from this library
    """
    ida_auto.auto_wait()
    result = []
    for i in range(ida_nalt.get_import_module_qty()):
        path = ida_nalt.get_import_module_name(i) or f"module_{i}"

        # count imports
        import_count = [0]

        def _count_cb(ea: int, name: str | None, ordinal: int) -> int:
            import_count[0] += 1  # noqa: B023
            return 1

        ida_nalt.enum_import_names(i, _count_cb)

        # classify
        if ".framework/" in path:
            kind = "framework"
            # last path component is the binary name
            name = path.rsplit("/", 1)[-1]
        elif path.startswith("<"):
            # e.g. "<dynamic>" for kexts
            kind = "other"
            name = path
        else:
            kind = "dylib"
            # basename, strip lib prefix and version suffix for short name
            name = path.rsplit("/", 1)[-1] if "/" in path else path

        result.append(
            {
                "path": path,
                "name": name,
                "kind": kind,
                "import_count": import_count[0],
            }
        )
    return result


def collect_all(
    output_path: str | None = None,
    exclude: dict | None = None,
) -> dict:
    """Run every collector and return a single dict.

    exclude: optional dict with keys:
        funcs    - list of regex patterns to exclude from names, function_stats, xref_stats
        segs     - list of regex patterns matching segment names. Full positional exclusion:
                   all items (functions, names, strings, xrefs) in matching segments are dropped.
                   The segments themselves are also hidden from segments and idb_coverage.
        strings  - list of regex patterns to exclude from strings
    Patterns are matched with re.search (substring unless anchored with ^/$).
    The filter set is recorded in the output under "filters" for auditability.
    """
    func_re = _compile_excludes(exclude.get("funcs")) if exclude else None
    str_re = _compile_excludes(exclude.get("strings")) if exclude else None
    seg_re = _compile_excludes(exclude.get("segs")) if exclude else None
    seg_starts = _excluded_seg_starts(seg_re) if seg_re else None

    result = {
        "metadata": metadata(),
        "segments": segments(exclude_re=seg_re),
        "entrypoints": entrypoints(),
        "imports": imports(),
        "libraries": libraries(),
        "names": names(exclude_re=func_re, seg_starts=seg_starts),
        "strings": strings(exclude_re=str_re, seg_starts=seg_starts),
        "types": types(),
        "function_stats": function_stats(exclude_re=func_re, seg_starts=seg_starts),
        "xref_stats": xref_stats(exclude_re=func_re, seg_starts=seg_starts),
        "idb_coverage": idb_coverage(exclude_re=seg_re),
        "objc_metadata": objc_metadata(seg_starts=seg_starts),
        "linkage_tables": linkage_tables(seg_starts=seg_starts),
        "init_fini": init_fini(seg_starts=seg_starts),
        "code_patterns": code_patterns(seg_starts=seg_starts),
    }

    if exclude:
        result["filters"] = {k: v for k, v in exclude.items() if v}

    if output_path:
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
    return result
