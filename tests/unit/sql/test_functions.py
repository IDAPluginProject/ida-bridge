"""Tests for scalar SQL functions."""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql import QueryError, sql

# ---------------------------------------------------------------------------
# Richer IDA stubs for function tests
# ---------------------------------------------------------------------------

_FUNCS = {
    0x1000: SimpleNamespace(start_ea=0x1000, end_ea=0x1100),
    0x1050: SimpleNamespace(start_ea=0x1000, end_ea=0x1100),  # mid-function
    0x2000: SimpleNamespace(start_ea=0x2000, end_ea=0x2080),
}

_NAMES = {
    0x1000: "main",
    0x2000: "helper",
    0x3000: "my_global",
}

_SEGS = {
    0x1000: SimpleNamespace(name="__TEXT"),
    0x2000: SimpleNamespace(name="__TEXT"),
    0x5000: SimpleNamespace(name="__DATA"),
}


@pytest.fixture(autouse=True)
def _rich_ida_stubs(monkeypatch: pytest.MonkeyPatch, _ida_stubs: None) -> None:
    """Override the minimal conftest stubs with richer data for function tests."""

    def get_func(ea: int):
        # Check exact match, then walk back for mid-function addresses
        if ea in _FUNCS:
            return _FUNCS[ea]
        for _start_ea, func in _FUNCS.items():
            if func.start_ea <= ea < func.end_ea:
                return func
        return None

    def get_name(ea: int) -> str:
        return _NAMES.get(ea, "")

    def getseg(ea: int):
        for base, seg in _SEGS.items():
            if base <= ea < base + 0x1000:
                return seg
        return None

    def get_segm_name(seg) -> str:
        return seg.name

    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        SimpleNamespace(
            get_func=get_func,
            get_func_cmt=lambda f, r: None,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        SimpleNamespace(
            get_name=get_name,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_segment",
        SimpleNamespace(
            getseg=getseg,
            get_segm_qty=lambda: 0,
            getnseg=lambda i: None,
            get_segm_name=get_segm_name,
            get_segm_class=lambda s: "",
        ),
    )


# ---------------------------------------------------------------------------
# func_at
# ---------------------------------------------------------------------------


class TestFuncAt:
    def test_exact_start(self) -> None:
        result = sql("SELECT func_at(0x1000) AS v")
        assert result.rows[0]["v"] == "main"

    def test_mid_function(self) -> None:
        result = sql("SELECT func_at(0x1050) AS v")
        assert result.rows[0]["v"] == "main"

    def test_no_function(self) -> None:
        result = sql("SELECT func_at(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT func_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# func_start
# ---------------------------------------------------------------------------


class TestFuncStart:
    def test_exact_start(self) -> None:
        result = sql("SELECT func_start(0x1000) AS v")
        assert result.rows[0]["v"] == 0x1000

    def test_mid_function(self) -> None:
        result = sql("SELECT func_start(0x1050) AS v")
        assert result.rows[0]["v"] == 0x1000

    def test_no_function(self) -> None:
        result = sql("SELECT func_start(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT func_start(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# name_at
# ---------------------------------------------------------------------------


class TestNameAt:
    def test_known_name(self) -> None:
        result = sql("SELECT name_at(0x1000) AS v")
        assert result.rows[0]["v"] == "main"

    def test_global_name(self) -> None:
        result = sql("SELECT name_at(0x3000) AS v")
        assert result.rows[0]["v"] == "my_global"

    def test_no_name(self) -> None:
        result = sql("SELECT name_at(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT name_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# hex
# ---------------------------------------------------------------------------


class TestHex:
    def test_basic(self) -> None:
        result = sql("SELECT hex(255) AS v")
        assert result.rows[0]["v"] == "0xff"

    def test_zero(self) -> None:
        result = sql("SELECT hex(0) AS v")
        assert result.rows[0]["v"] == "0x0"

    def test_large_address(self) -> None:
        result = sql("SELECT hex(0x100003F40) AS v")
        assert result.rows[0]["v"] == "0x100003f40"

    def test_null_input(self) -> None:
        result = sql("SELECT hex(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# segment_at
# ---------------------------------------------------------------------------


class TestSegmentAt:
    def test_text_segment(self) -> None:
        result = sql("SELECT segment_at(0x1000) AS v")
        assert result.rows[0]["v"] == "__TEXT"

    def test_data_segment(self) -> None:
        result = sql("SELECT segment_at(0x5000) AS v")
        assert result.rows[0]["v"] == "__DATA"

    def test_no_segment(self) -> None:
        result = sql("SELECT segment_at(0xDEAD0000) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT segment_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


class TestComposition:
    def test_hex_of_func_start(self) -> None:
        result = sql("SELECT hex(func_start(0x1050)) AS v")
        assert result.rows[0]["v"] == "0x1000"

    def test_func_at_with_name_at(self) -> None:
        """Both resolve the same address but via different paths."""
        result = sql("SELECT func_at(0x1000) AS f, name_at(0x1000) AS n")
        assert result.rows[0]["f"] == "main"
        assert result.rows[0]["n"] == "main"

    def test_null_propagation(self) -> None:
        result = sql("SELECT hex(func_start(0xDEAD)) AS v")
        assert result.rows[0]["v"] is None


class TestAddressArgumentValidation:
    def test_rejects_real_for_address_argument(self) -> None:
        with pytest.raises(QueryError, match=r"func_start\(\) argument 1 must be an INTEGER"):
            sql("SELECT func_start(1.5)")

    def test_rejects_text_for_address_argument(self) -> None:
        with pytest.raises(QueryError, match=r"name_at\(\) argument 1 must be an INTEGER"):
            sql("SELECT name_at('0x1000')")


# ---------------------------------------------------------------------------
# func_end
# ---------------------------------------------------------------------------


class TestFuncEnd:
    def test_exact_start(self) -> None:
        result = sql("SELECT func_end(0x1000) AS v")
        assert result.rows[0]["v"] == 0x1100

    def test_mid_function(self) -> None:
        result = sql("SELECT func_end(0x1050) AS v")
        assert result.rows[0]["v"] == 0x1100

    def test_no_function(self) -> None:
        result = sql("SELECT func_end(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT func_end(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# mnemonic
# ---------------------------------------------------------------------------


class TestMnemonic:
    @pytest.fixture(autouse=True)
    def _idc_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mnemonics = {0x1000: "BL", 0x2000: "STR"}

        monkeypatch.setitem(
            sys.modules,
            "idc",
            SimpleNamespace(
                print_insn_mnem=lambda ea: _mnemonics.get(ea, ""),
                GetDisasm=lambda ea: "",
                get_item_size=lambda ea: 0,
                get_func_name=lambda ea: "",
            ),
        )

    def test_known(self) -> None:
        result = sql("SELECT mnemonic_at(0x1000) AS v")
        assert result.rows[0]["v"] == "BL"

    def test_unknown(self) -> None:
        result = sql("SELECT mnemonic_at(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT mnemonic_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# disasm (scalar)
# ---------------------------------------------------------------------------


class TestDisasmScalar:
    @pytest.fixture(autouse=True)
    def _idc_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _disasms = {0x1000: "BL sub_2000", 0x2000: "STR X0, [SP]"}

        monkeypatch.setitem(
            sys.modules,
            "idc",
            SimpleNamespace(
                GetDisasm=lambda ea: _disasms.get(ea, ""),
                print_insn_mnem=lambda ea: "",
                get_item_size=lambda ea: 0,
                get_func_name=lambda ea: "",
            ),
        )

    def test_known(self) -> None:
        result = sql("SELECT disasm_at(0x1000) AS v")
        assert result.rows[0]["v"] == "BL sub_2000"

    def test_unknown(self) -> None:
        result = sql("SELECT disasm_at(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT disasm_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# item_type
# ---------------------------------------------------------------------------


class TestItemType:
    @pytest.fixture(autouse=True)
    def _flags_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Flags: 1=code, 2=data, 4=strlit, 8=struct, 16=align
        _flags = {0x1000: 1, 0x2000: 2, 0x3000: 4, 0x4000: 8, 0x5000: 16, 0x6000: 0}

        monkeypatch.setitem(
            sys.modules,
            "ida_bytes",
            SimpleNamespace(
                get_flags=lambda ea: _flags.get(ea, 0),
                get_cmt=lambda ea, r: None,
                is_code=lambda f: f == 1,
                is_data=lambda f: f == 2,
                is_strlit=lambda f: f == 4,
                is_struct=lambda f: f == 8,
                is_align=lambda f: f == 16,
            ),
        )

    def test_code(self) -> None:
        result = sql("SELECT item_type_at(0x1000) AS v")
        assert result.rows[0]["v"] == "code"

    def test_data(self) -> None:
        result = sql("SELECT item_type_at(0x2000) AS v")
        assert result.rows[0]["v"] == "data"

    def test_string(self) -> None:
        result = sql("SELECT item_type_at(0x3000) AS v")
        assert result.rows[0]["v"] == "string"

    def test_struct(self) -> None:
        result = sql("SELECT item_type_at(0x4000) AS v")
        assert result.rows[0]["v"] == "struct"

    def test_align(self) -> None:
        result = sql("SELECT item_type_at(0x5000) AS v")
        assert result.rows[0]["v"] == "align"

    def test_unknown(self) -> None:
        result = sql("SELECT item_type_at(0x6000) AS v")
        assert result.rows[0]["v"] == "unknown"

    def test_null_input(self) -> None:
        result = sql("SELECT item_type_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# item_size
# ---------------------------------------------------------------------------


class TestItemSize:
    @pytest.fixture(autouse=True)
    def _idc_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _sizes = {0x1000: 4, 0x2000: 8}

        monkeypatch.setitem(
            sys.modules,
            "idc",
            SimpleNamespace(
                get_item_size=lambda ea: _sizes.get(ea, 0),
                print_insn_mnem=lambda ea: "",
                GetDisasm=lambda ea: "",
                get_func_name=lambda ea: "",
            ),
        )

    def test_known(self) -> None:
        result = sql("SELECT item_size_at(0x1000) AS v")
        assert result.rows[0]["v"] == 4

    def test_larger(self) -> None:
        result = sql("SELECT item_size_at(0x2000) AS v")
        assert result.rows[0]["v"] == 8

    def test_zero_size(self) -> None:
        """Zero-sized items (undefined) return NULL."""
        result = sql("SELECT item_size_at(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null_input(self) -> None:
        result = sql("SELECT item_size_at(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# is_code / is_data
# ---------------------------------------------------------------------------


class TestIsCodeIsData:
    @pytest.fixture(autouse=True)
    def _flags_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 1 = code flag, 2 = data flag
        _flags = {0x1000: 1, 0x2000: 2, 0x3000: 0}

        monkeypatch.setitem(
            sys.modules,
            "ida_bytes",
            SimpleNamespace(
                get_flags=lambda ea: _flags.get(ea, 0),
                get_cmt=lambda ea, r: None,
                is_code=lambda f: f == 1,
                is_data=lambda f: f == 2,
                is_strlit=lambda f: False,
                is_struct=lambda f: False,
                is_align=lambda f: False,
            ),
        )

    def test_is_code_yes(self) -> None:
        result = sql("SELECT is_code_at(0x1000) AS v")
        assert result.rows[0]["v"] == 1

    def test_is_code_no(self) -> None:
        result = sql("SELECT is_code_at(0x2000) AS v")
        assert result.rows[0]["v"] == 0

    def test_is_data_yes(self) -> None:
        result = sql("SELECT is_data_at(0x2000) AS v")
        assert result.rows[0]["v"] == 1

    def test_is_data_no(self) -> None:
        result = sql("SELECT is_data_at(0x1000) AS v")
        assert result.rows[0]["v"] == 0

    def test_neither(self) -> None:
        result = sql("SELECT is_code_at(0x3000) AS c, is_data_at(0x3000) AS d")
        assert result.rows[0]["c"] == 0
        assert result.rows[0]["d"] == 0

    def test_null_input(self) -> None:
        result = sql("SELECT is_code_at(NULL) AS c, is_data_at(NULL) AS d")
        assert result.rows[0]["c"] is None
        assert result.rows[0]["d"] is None


# ---------------------------------------------------------------------------
# Memory-read functions
# ---------------------------------------------------------------------------

# Simulated memory: address -> bytes mapping
# fmt: off
_MEM: dict[int, bytes] = {
    # Little-endian test values at 0x4000
    0x4000: b"\x42",                                         # u8 = 0x42
    0x4010: b"\x34\x12",                                     # u16 = 0x1234
    0x4020: b"\x78\x56\x34\x12",                             # u32 = 0x12345678
    0x4030: b"\xfe\xff\xff\xff",                              # i32 = -2
    0x4040: b"\xef\xcd\xab\x90\x78\x56\x34\x12",            # u64 = 0x1234567890abcdef
    0x4050: b"\xfe\xff\xff\xff\xff\xff\xff\xff",              # i64 = -2
    # Relative pointer: offset +0x100 at 0x4060 -> target 0x4160
    0x4060: b"\x00\x01\x00\x00",                             # i32 = 0x100
    # Zero relative pointer (no target)
    0x4070: b"\x00\x00\x00\x00",
    # Negative relative pointer: -0x10 at 0x4080 -> target 0x4070
    0x4080: b"\xf0\xff\xff\xff",                              # i32 = -0x10
}
# fmt: on


def _stub_get_byte(ea: int) -> int:
    data = _MEM.get(ea)
    return data[0] if data else 0


def _stub_get_word(ea: int) -> int:
    import struct

    data = _stub_get_bytes(ea, 2)
    return struct.unpack("<H", data)[0] if data and len(data) >= 2 else 0


def _stub_get_dword(ea: int) -> int:
    import struct

    data = _stub_get_bytes(ea, 4)
    return struct.unpack("<I", data)[0] if data and len(data) >= 4 else 0


def _stub_get_qword(ea: int) -> int:
    import struct

    data = _stub_get_bytes(ea, 8)
    return struct.unpack("<Q", data)[0] if data and len(data) >= 8 else 0


def _stub_get_bytes(ea: int, size: int) -> bytes | None:
    data = _MEM.get(ea)
    if data is not None and len(data) >= size:
        return data[:size]
    return b"\x00" * size


# C-string at 0x5000
_CSTRINGS: dict[int, bytes] = {
    0x5000: b"hello world",
}


def _stub_get_strlit_contents(ea: int, length: int, strtype: int) -> bytes | None:
    return _CSTRINGS.get(ea)


_MEM_BYTES_STUB = SimpleNamespace(
    get_byte=_stub_get_byte,
    get_word=_stub_get_word,
    get_dword=_stub_get_dword,
    get_qword=_stub_get_qword,
    get_bytes=_stub_get_bytes,
    get_cmt=lambda ea, r: None,
    get_flags=lambda ea: 0,
)


@pytest.fixture()
def _mem_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "ida_bytes", _MEM_BYTES_STUB)


class TestReadU8:
    def test_basic(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u8(0x4000) AS v")
        assert result.rows[0]["v"] == 0x42

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u8(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadU16:
    def test_basic(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u16(0x4010) AS v")
        assert result.rows[0]["v"] == 0x1234

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u16(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadU32:
    def test_basic(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u32(0x4020) AS v")
        assert result.rows[0]["v"] == 0x12345678

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u32(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadI32:
    def test_negative(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i32(0x4030) AS v")
        assert result.rows[0]["v"] == -2

    def test_positive(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i32(0x4020) AS v")
        assert result.rows[0]["v"] == 0x12345678

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i32(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadU64:
    def test_basic(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u64(0x4040) AS v")
        assert result.rows[0]["v"] == 0x1234567890ABCDEF

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_u64(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadI64:
    def test_negative(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i64(0x4050) AS v")
        assert result.rows[0]["v"] == -2

    def test_positive(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i64(0x4040) AS v")
        assert result.rows[0]["v"] == 0x1234567890ABCDEF

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_i64(NULL) AS v")
        assert result.rows[0]["v"] is None


class TestReadRel32:
    def test_positive_offset(self, _mem_stubs: None) -> None:
        """0x4060 + 0x100 = 0x4160."""
        result = sql("SELECT read_rel32(0x4060) AS v")
        assert result.rows[0]["v"] == 0x4160

    def test_zero_offset_returns_null(self, _mem_stubs: None) -> None:
        """Zero relative pointer means no target."""
        result = sql("SELECT read_rel32(0x4070) AS v")
        assert result.rows[0]["v"] is None

    def test_negative_offset(self, _mem_stubs: None) -> None:
        """0x4080 + (-0x10) = 0x4070."""
        result = sql("SELECT read_rel32(0x4080) AS v")
        assert result.rows[0]["v"] == 0x4070

    def test_null(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_rel32(NULL) AS v")
        assert result.rows[0]["v"] is None

    def test_composition_with_name_at(self, _mem_stubs: None) -> None:
        """read_rel32 composes with other functions."""
        result = sql("SELECT name_at(read_rel32(0x4060)) AS v")
        # 0x4160 has no name in our stubs
        assert result.rows[0]["v"] is None


class TestReadBytes:
    def test_basic(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_bytes(0x4020, 4) AS v")
        assert result.rows[0]["v"] == "78563412"

    def test_single_byte(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_bytes(0x4000, 1) AS v")
        assert result.rows[0]["v"] == "42"

    def test_null_ea(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_bytes(NULL, 4) AS v")
        assert result.rows[0]["v"] is None

    def test_null_size(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_bytes(0x4000, NULL) AS v")
        assert result.rows[0]["v"] is None

    def test_zero_size(self, _mem_stubs: None) -> None:
        result = sql("SELECT read_bytes(0x4000, 0) AS v")
        assert result.rows[0]["v"] is None

    def test_exceeds_limit(self, _mem_stubs: None) -> None:
        with pytest.raises(Exception, match="exceeds limit"):
            sql("SELECT read_bytes(0x4000, 8192) AS v")


class TestReadCstr:
    @pytest.fixture(autouse=True)
    def _cstr_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(
            sys.modules,
            "idc",
            SimpleNamespace(
                get_strlit_contents=_stub_get_strlit_contents,
                STRTYPE_C=0,
                get_func_name=lambda ea: "",
                print_insn_mnem=lambda ea: "",
                GetDisasm=lambda ea: "",
                get_item_size=lambda ea: 0,
            ),
        )

    def test_basic(self) -> None:
        result = sql("SELECT read_cstr(0x5000) AS v")
        assert result.rows[0]["v"] == "hello world"

    def test_no_string(self) -> None:
        result = sql("SELECT read_cstr(0xDEAD) AS v")
        assert result.rows[0]["v"] is None

    def test_null(self) -> None:
        result = sql("SELECT read_cstr(NULL) AS v")
        assert result.rows[0]["v"] is None


# ---------------------------------------------------------------------------
# demangle
# ---------------------------------------------------------------------------

_DEMANGLE_MAP: dict[str, str] = {
    "_$s4main5PointVMn": "nominal type descriptor for main.Point",
    "_ZN5boost6system14error_categoryD2Ev": "boost::system::error_category::~error_category()",
    "__ZN3foo3barEv": "foo::bar()",
}


class TestDemangle:
    @pytest.fixture(autouse=True)
    def _demangle_stubs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def demangle_name(name: str, mask: int, dqt: int = 0) -> str | None:
            return _DEMANGLE_MAP.get(name)

        monkeypatch.setitem(
            sys.modules,
            "ida_name",
            SimpleNamespace(
                get_name=lambda ea: "",
                demangle_name=demangle_name,
                DQT_FULL=0,
            ),
        )

    def test_swift(self) -> None:
        result = sql("SELECT demangle('_$s4main5PointVMn') AS v")
        assert result.rows[0]["v"] == "nominal type descriptor for main.Point"

    def test_cpp(self) -> None:
        result = sql("SELECT demangle('__ZN3foo3barEv') AS v")
        assert result.rows[0]["v"] == "foo::bar()"

    def test_not_mangled(self) -> None:
        result = sql("SELECT demangle('plain_name') AS v")
        assert result.rows[0]["v"] is None

    def test_null(self) -> None:
        result = sql("SELECT demangle(NULL) AS v")
        assert result.rows[0]["v"] is None

    def test_composition_with_name_at(self) -> None:
        """demangle(name_at(ea)) is the expected usage pattern."""
        result = sql("SELECT demangle(name_at(0xDEAD)) AS v")
        assert result.rows[0]["v"] is None
