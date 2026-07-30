"""Shared fixtures for sql unit tests."""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql.db import reset_db


@pytest.fixture(autouse=True)
def _reset_sql_db():
    """Reset the APSW connection before and after each test."""
    reset_db()
    yield
    reset_db()


@pytest.fixture(autouse=True)
def _ida_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal IDA stubs that return empty data. Prevents ImportError only."""
    stubs: dict[str, object] = {
        "idautils": SimpleNamespace(
            Functions=lambda: iter([]),
            Names=lambda: iter([]),
            Strings=lambda: iter([]),
            Segments=lambda: iter([]),
            Heads=lambda s, e: iter([]),
            XrefsTo=lambda ea, f: iter([]),
            XrefsFrom=lambda ea, f: iter([]),
        ),
        "ida_funcs": SimpleNamespace(
            get_func=lambda ea: None,
            get_func_cmt=lambda f, r: None,
        ),
        "ida_typeinf": SimpleNamespace(
            tinfo_t=lambda: SimpleNamespace(
                get_numbered_type=lambda til, ordinal: False,
                is_func=lambda: False,
                is_struct=lambda: False,
                is_union=lambda: False,
                is_enum=lambda: False,
                is_udt=lambda: False,
                is_typedef=lambda: False,
                is_ptr=lambda: False,
                is_array=lambda: False,
                is_bitfield=lambda: False,
                is_forward_decl=lambda: False,
                is_forward_struct=lambda: False,
                is_forward_union=lambda: False,
                is_forward_enum=lambda: False,
                get_tid=lambda: 0,
                get_size=lambda: 0xFFFFFFFFFFFFFFFF,
                get_unpadded_size=lambda: 0xFFFFFFFFFFFFFFFF,
                get_udt_nmembers=lambda: -1,
                get_enum_nmembers=lambda: 0xFFFFFFFFFFFFFFFF,
                get_final_type_name=lambda: None,
                get_final_ordinal=lambda: 0,
                get_udt_details=lambda udt: False,
                get_rettype=lambda: SimpleNamespace(dstr=lambda: "", empty=lambda: True),
                get_nargs=lambda: -1,
                get_func_details=lambda fti: False,
            ),
            udt_type_data_t=lambda: SimpleNamespace(effalign=0),
            func_type_data_t=lambda: SimpleNamespace(get_cc=lambda: 0),
            print_type=lambda ea, flags: None,
            print_tinfo=lambda prefix, indent, cmtindent, flags, tif, name, cmt: None,
            PRTYPE_1LINE=0x0001,
            PRTYPE_DEF=0x0020,
            PRTYPE_TYPE=0x0002,
            PRTYPE_SEMI=0x0008,
            is_custom_callcnv=lambda cc: False,
            get_custom_callcnv=lambda cc: None,
            get_idati=lambda: SimpleNamespace(),
            get_ordinal_limit=lambda til: 0,
            get_numbered_type_name=lambda til, ordinal: None,
        ),
        "ida_nalt": SimpleNamespace(
            get_import_module_qty=lambda: 0,
            get_import_module_name=lambda i: "",
            enum_import_names=lambda i, cb: None,
            get_root_filename=lambda: "stub",
            get_imagebase=lambda: 0,
            get_tinfo=lambda tif, ea: False,
            get_aflags=lambda ea: 0,
        ),
        "ida_segment": SimpleNamespace(
            getseg=lambda ea: None,
            get_segm_qty=lambda: 0,
            getnseg=lambda i: None,
            get_segm_name=lambda s: "",
            get_segm_class=lambda s: "",
        ),
        "ida_bytes": SimpleNamespace(
            get_cmt=lambda ea, r: None,
            get_flags=lambda ea: 0,
            has_user_name=lambda flags: False,
            get_byte=lambda ea: 0,
            get_word=lambda ea: 0,
            get_dword=lambda ea: 0,
            get_qword=lambda ea: 0,
            get_bytes=lambda ea, size: b"\x00" * size,
            is_code=lambda f: False,
            is_data=lambda f: False,
            is_strlit=lambda f: False,
            is_struct=lambda f: False,
            is_align=lambda f: False,
            is_unknown=lambda f: True,
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1] if pat else None),
            ),
            bin_search=lambda start, end, pat, flags: (0xFFFFFFFFFFFFFFFF, 0),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
        ),
        "ida_ua": SimpleNamespace(
            insn_t=lambda: SimpleNamespace(ea=0),
            decode_insn=lambda insn, ea: 0,
        ),
        "idc": SimpleNamespace(
            get_func_name=lambda ea: "",
            print_insn_mnem=lambda ea: "",
            GetDisasm=lambda ea: "",
            GetLocalType=lambda ordinal, flags: None,
            get_item_size=lambda ea: 0,
            get_strlit_contents=lambda ea, length, strtype: None,
            STRTYPE_C=0,
        ),
        "ida_ida": SimpleNamespace(
            inf_get_procname=lambda: "arm",
            inf_is_64bit=lambda: True,
            inf_is_be=lambda: False,
            inf_get_filetype=lambda: 0,
            inf_is_dll=lambda: False,
            inf_get_min_ea=lambda: 0,
            inf_get_max_ea=lambda: 0,
        ),
        "idaapi": SimpleNamespace(
            BADADDR=0xFFFFFFFFFFFFFFFF,
            get_name=lambda ea: "",
            get_name_ea=lambda seg, name: 0xFFFFFFFFFFFFFFFF,
        ),
        "ida_idaapi": SimpleNamespace(
            BADADDR=0xFFFFFFFFFFFFFFFF,
        ),
        "ida_name": SimpleNamespace(
            get_name=lambda ea: "",
            get_name_ea=lambda seg, name: 0xFFFFFFFFFFFFFFFF,
            get_nlist_size=lambda: 0,
            get_nlist_ea=lambda index: 0xFFFFFFFFFFFFFFFF,
            get_nlist_name=lambda index: "",
            get_nlist_idx=lambda ea: -1,
            is_in_nlist=lambda ea: False,
            demangle_name=lambda name, mask, dqt=0: None,
            DQT_FULL=0,
        ),
        "ida_hexrays": SimpleNamespace(
            init_hexrays_plugin=lambda: True,
            decompile=lambda ea: None,
        ),
        "ida_auto": SimpleNamespace(auto_wait=lambda: None),
        "ida_lines": SimpleNamespace(tag_remove=lambda s: s),
        "ida_entry": SimpleNamespace(
            get_entry_qty=lambda: 0,
            get_entry_ordinal=lambda i: 0,
            get_entry=lambda ordinal: 0,
            get_entry_name=lambda ordinal: "",
        ),
        "ida_gdl": SimpleNamespace(
            FlowChart=lambda func, flags=0: iter([]),
            FC_NOEXT=0x0002,
        ),
    }
    for name, mod in stubs.items():
        monkeypatch.setitem(sys.modules, name, mod)
