"""DYLD Shared Cache Utils helpers for single-module dyld-cache IDBs.

    load_module("/usr/lib/libobjc.A.dylib")       -> {ok, module, rc}
    load_section_for_ea(0x1AECFF7F9)              -> {ok, ea, rc}
    load_sections_for_eas([0x22D7FEED0, ...])     -> [{ok, ea, rc}, ...]

Requires an IDB created from Apple DYLD cache with the `single module` option.
"""

import ida_segment
import idaapi


def _dscu_node() -> "idaapi.netnode":
    """Return the dscu netnode, creating it if needed."""
    node = idaapi.netnode()
    node.create("$ dscu")
    return node


def load_module(module_path: str) -> dict:
    """Load one dyld-cache module into the current single-module IDB."""
    node = _dscu_node()
    node.supset(2, module_path)
    rc = bool(idaapi.load_and_run_plugin("dscu", 1))
    return {"ok": rc, "module": module_path, "rc": rc}


def load_section_for_ea(ea: int) -> dict:
    """Load the dyld-cache section containing ea into the current IDB."""
    seg = ida_segment.getseg(ea)
    if seg is not None:
        return {
            "ok": True,
            "ea": hex(ea),
            "rc": None,
            "segment": ida_segment.get_segm_name(seg),
            "skipped": "already loaded",
        }

    node = _dscu_node()
    node.altset(3, ea)
    rc = bool(idaapi.load_and_run_plugin("dscu", 2))
    return {"ok": rc, "ea": hex(ea), "rc": rc}


def load_sections_for_eas(eas: list[int]) -> list[dict]:
    """Load the dyld-cache sections containing the provided addresses."""
    return [load_section_for_ea(ea) for ea in eas]
