"""Type indirect calls for the decompiler via user-defined calls.

    set_call_type(func_ea, call_ea, c_decl)                    -- single
    set_call_types(func_ea, [{ea, decl}, ...])                 -- batch
    clear_call_types(func_ea)                                  -- remove all
    list_call_types(func_ea)                                   -- inspect

Returns dicts: {"ea": "0x...", "ok": bool, "error": "..."}

How it works:
    Uses save_user_defined_calls() which stores typed call info in the IDB
    keyed by (func_ea, call_ea). On the next decompile, Hex-Rays reads these
    entries and uses them for argument analysis. Parameter names propagate to
    local variable names and parameter types propagate to variable types.

    This is the same mechanism as the UI's "Set call type" (Y on a call in
    pseudocode). It works on all architectures including ARM64, where the
    operand-level apply_callee_tinfo() has no effect on decompiler output.

    Batch: apply all call types in one set_call_types() invocation before
    decompiling. Each save overwrites the full map for that function, so
    incremental single calls will lose earlier entries unless you use batch.

Notes:
    - c_decl is a C function declaration with a trailing semicolon optional:
      "int APFSVolumePayloadGet(int64_t volume, int flags, void *buf, uint64_t *size)"
    - Parameter names in the declaration become local variable names in pseudocode.
    - call_ea must be the EA of a call/branch instruction inside func_ea.
    - func_ea is the entry point of the containing function.
    - Use _result_ = ... to return data through ida-bridge.
"""

import ida_auto
import ida_funcs
import ida_hexrays


def _ensure_hexrays() -> None:
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays not available")


def _get_func_ea(call_ea: int) -> int:
    """Resolve the containing function's entry EA from a call EA."""
    func = ida_funcs.get_func(call_ea)
    if func is None:
        msg = f"no function at {call_ea:#x}"
        raise ValueError(msg)
    return func.start_ea


def set_call_type(func_ea: int, call_ea: int, c_decl: str) -> dict:
    """Set the type of an indirect call for the decompiler.

    Merges with any existing user-defined calls for func_ea.
    """
    _ensure_hexrays()

    udc = ida_hexrays.udcall_t()
    decl = c_decl if c_decl.rstrip().endswith(";") else c_decl + ";"
    if not ida_hexrays.parse_user_call(udc, decl, True):
        return {"ea": hex(call_ea), "ok": False, "error": f"parse_user_call failed: {c_decl!r}"}

    # Restore existing map so we don't clobber other entries
    ucmap = ida_hexrays.udcall_map_new()
    ida_hexrays.restore_user_defined_calls(ucmap, func_ea)
    ida_hexrays.udcall_map_insert(ucmap, call_ea, udc)
    ida_hexrays.save_user_defined_calls(func_ea, ucmap)

    return {"ea": hex(call_ea), "ok": True, "name": udc.name, "type": str(udc.tif)}


def set_call_types(func_ea: int, items: list[dict]) -> list[dict]:
    """Batch-set call types for multiple call sites in one function.

    Each item: {"ea": int, "decl": str}.

    All entries are saved in a single write so the next decompile sees
    them all simultaneously.
    """
    ida_auto.auto_wait()
    _ensure_hexrays()

    # Restore existing map
    ucmap = ida_hexrays.udcall_map_new()
    ida_hexrays.restore_user_defined_calls(ucmap, func_ea)

    results = []
    for item in items:
        ea = item["ea"]
        decl = item["decl"]
        udc = ida_hexrays.udcall_t()
        d = decl if decl.rstrip().endswith(";") else decl + ";"
        if not ida_hexrays.parse_user_call(udc, d, True):
            results.append({"ea": hex(ea), "ok": False, "error": f"parse_user_call failed: {decl!r}"})
            continue
        ida_hexrays.udcall_map_insert(ucmap, ea, udc)
        results.append({"ea": hex(ea), "ok": True, "name": udc.name, "type": str(udc.tif)})

    ida_hexrays.save_user_defined_calls(func_ea, ucmap)
    return results


def clear_call_types(func_ea: int) -> dict:
    """Remove all user-defined call types for a function."""
    _ensure_hexrays()
    ucmap = ida_hexrays.udcall_map_new()
    ida_hexrays.save_user_defined_calls(func_ea, ucmap)
    return {"func_ea": hex(func_ea), "cleared": True}


def list_call_types(func_ea: int) -> list[dict]:
    """List all user-defined call types for a function."""
    _ensure_hexrays()
    ucmap = ida_hexrays.udcall_map_new()
    if not ida_hexrays.restore_user_defined_calls(ucmap, func_ea):
        return []

    entries = []
    it = ida_hexrays.udcall_map_begin(ucmap)
    end = ida_hexrays.udcall_map_end(ucmap)
    while it != end:
        ea = ida_hexrays.udcall_map_first(it)
        udc = ida_hexrays.udcall_map_second(it)
        entries.append({"ea": hex(ea), "name": udc.name, "type": str(udc.tif)})
        it = ida_hexrays.udcall_map_next(it)
    return entries
