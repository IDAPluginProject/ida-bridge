"""Tests for ida-bridge uint64/address policy on top of APSW/SQLite."""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql import sql

_HIGH_BASE = 0xFFFFFE0007004000
_FUNC_END = _HIGH_BASE + 0x100


class TestCoreU64Policy:
    @pytest.fixture(autouse=True)
    def _high_address_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        func = SimpleNamespace(start_ea=_HIGH_BASE, end_ea=_FUNC_END, flags=0x10)
        seg = SimpleNamespace(start_ea=_HIGH_BASE, end_ea=_FUNC_END, perm=7)

        monkeypatch.setitem(
            sys.modules,
            "idautils",
            SimpleNamespace(
                Functions=lambda: iter([_HIGH_BASE]),
                Names=lambda: iter([(_HIGH_BASE, "kernel_func")]),
                Strings=lambda: iter([]),
                Segments=lambda: iter([_HIGH_BASE]),
                Heads=lambda start, end: iter([]),
                XrefsTo=lambda ea, flags: iter([]),
                XrefsFrom=lambda ea, flags: iter([]),
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "ida_funcs",
            SimpleNamespace(
                get_func=lambda ea: func if _HIGH_BASE <= ea < _FUNC_END else None,
                get_func_cmt=lambda f, repeatable: None,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "idc",
            SimpleNamespace(
                get_func_name=lambda ea: "kernel_func" if ea == _HIGH_BASE else "",
                print_insn_mnem=lambda ea: "",
                GetDisasm=lambda ea: "",
                GetLocalType=lambda ordinal, flags: None,
                get_item_size=lambda ea: 0,
                get_strlit_contents=lambda ea, length, strtype: None,
                STRTYPE_C=0,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "ida_nalt",
            SimpleNamespace(
                get_import_module_qty=lambda: 0,
                get_import_module_name=lambda i: "",
                enum_import_names=lambda i, cb: None,
                get_root_filename=lambda: "sample.bin",
                get_imagebase=lambda: _HIGH_BASE,
                get_tinfo=lambda tif, ea: False,
                get_aflags=lambda ea: 0,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "ida_ida",
            SimpleNamespace(
                inf_get_procname=lambda: "arm",
                inf_is_64bit=lambda: True,
                inf_is_be=lambda: False,
                inf_get_filetype=lambda: 0,
                inf_is_dll=lambda: False,
                inf_get_min_ea=lambda: _HIGH_BASE,
                inf_get_max_ea=lambda: _FUNC_END,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "ida_segment",
            SimpleNamespace(
                getseg=lambda ea: seg if _HIGH_BASE <= ea < _FUNC_END else None,
                get_segm_qty=lambda: 1,
                getnseg=lambda i: seg if i == 0 else None,
                get_segm_name=lambda s: "__TEXT",
                get_segm_class=lambda s: "CODE",
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "ida_name",
            SimpleNamespace(
                get_name=lambda ea: "kernel_func" if ea == _HIGH_BASE else "",
                get_name_ea=lambda seg, name: _HIGH_BASE if name == "kernel_func" else 0xFFFFFFFFFFFFFFFF,
                get_nlist_size=lambda: 1,
                get_nlist_ea=lambda index: _HIGH_BASE if index == 0 else 0xFFFFFFFFFFFFFFFF,
                get_nlist_name=lambda index: "kernel_func" if index == 0 else "",
                get_nlist_idx=lambda ea: 0 if ea == _HIGH_BASE else -1,
                is_in_nlist=lambda ea: ea == _HIGH_BASE,
                demangle_name=lambda name, mask, dqt=0: None,
                DQT_FULL=0,
            ),
        )

    def test_db_info_decodes_u64_and_formats_alias_as_hex(self) -> None:
        result = sql("SELECT image_base AS base, min_ea, max_ea FROM db_info")

        assert result.rows == [{"base": _HIGH_BASE, "min_ea": _HIGH_BASE, "max_ea": _FUNC_END}]
        assert result.hex_columns == frozenset({"base", "min_ea", "max_ea"})
        assert result.format_for_transport()["rows"] == [
            {
                "base": f"0x{_HIGH_BASE:x}",
                "min_ea": f"0x{_HIGH_BASE:x}",
                "max_ea": f"0x{_FUNC_END:x}",
            }
        ]

    def test_funcs_names_and_segments_return_positive_python_addresses(self) -> None:
        funcs = sql("SELECT start_ea AS func_addr, end_ea FROM funcs")
        names = sql("SELECT address AS sym_addr FROM names")
        segs = sql("SELECT start_ea AS seg_start, end_ea AS seg_end FROM segments")

        assert funcs.rows == [{"func_addr": _HIGH_BASE, "end_ea": _FUNC_END}]
        assert names.rows == [{"sym_addr": _HIGH_BASE}]
        assert segs.rows == [{"seg_start": _HIGH_BASE, "seg_end": _FUNC_END}]

        assert funcs.format_for_transport()["rows"] == [
            {
                "func_addr": f"0x{_HIGH_BASE:x}",
                "end_ea": f"0x{_FUNC_END:x}",
            }
        ]
        assert names.format_for_transport()["rows"] == [{"sym_addr": f"0x{_HIGH_BASE:x}"}]
        assert segs.format_for_transport()["rows"] == [
            {
                "seg_start": f"0x{_HIGH_BASE:x}",
                "seg_end": f"0x{_FUNC_END:x}",
            }
        ]

    def test_high_bit_hex_predicate_matches_encoded_table_values(self) -> None:
        result = sql("SELECT start_ea FROM funcs WHERE start_ea = 0xfffffe0007004000")

        assert result.rows == [{"start_ea": _HIGH_BASE}]

    def test_unaliased_func_start_result_is_decoded_back_to_positive_python_int(self) -> None:
        result = sql("SELECT func_start(0xfffffe0007004008)")

        assert result.rows[0][result.columns[0]] == _HIGH_BASE

    def test_address_function_composition_works_with_high_addresses(self) -> None:
        result = sql("SELECT name_at(func_start(0xfffffe0007004008)) AS v")

        assert result.rows[0]["v"] == "kernel_func"

    def test_hex_function_formats_encoded_function_results(self) -> None:
        result = sql("SELECT hex(func_start(0xfffffe0007004008)) AS v")

        assert result.rows[0]["v"] == f"0x{_HIGH_BASE:x}"

    @pytest.mark.xfail(
        strict=True,
        reason="aliased scalar uint64 results lose semantic provenance",
    )
    def test_aliased_scalar_u64_result_should_decode_back_to_positive_python_int(self) -> None:
        result = sql("SELECT func_start(0xfffffe0007004008) AS fstart")

        assert result.rows[0]["fstart"] == _HIGH_BASE

    @pytest.mark.xfail(
        strict=True,
        reason="computed expressions over uint64 columns lose semantic provenance",
    )
    def test_expression_over_u64_column_should_decode_back_to_positive_python_int(self) -> None:
        result = sql("SELECT start_ea + 0 AS expr FROM funcs")

        assert result.rows[0]["expr"] == _HIGH_BASE
