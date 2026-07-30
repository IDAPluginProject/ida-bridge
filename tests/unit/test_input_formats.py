"""Tests for input format helpers."""

import struct

import pytest

from ida_bridge.input_formats import dyld_cache_arch, fat_macho_arches, fat_macho_ida_filetype_arg

_CPU = {"arm64": 0x0100000C, "x86_64": 0x01000007, "x86": 0x00000007}


def _fat_binary(arch_names: list[str]) -> bytes:
    """Build a minimal fat Mach-O from a list of arch names."""
    narch = len(arch_names)
    header = struct.pack(">II", 0xCAFEBABE, narch)
    offset = (8 + 20 * narch + 4095) & ~4095
    slices = b""
    for name in arch_names:
        ct = _CPU[name]
        entry = struct.pack(">IIIII", ct, 0, offset, 64, 12)
        header += entry
        slices += b"\x00" * 64
        offset += 64
    pad_len = ((8 + 20 * narch + 4095) & ~4095) - len(header)
    return header + b"\x00" * pad_len + slices


def _thin_macho() -> bytes:
    """Minimal thin Mach-O magic (not fat)."""
    return struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"\x00" * 24


def _dyld_cache_header(arch: str) -> bytes:
    return f"dyld_v1  {arch}".encode("ascii").ljust(16, b"\x00") + b"\x00" * 32


class TestFatMachoArches:
    def test_fat_two_arches(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["x86_64", "arm64"]))
        assert fat_macho_arches(p) == ["x86_64", "arm64"]

    def test_fat_single_arch(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["arm64"]))
        assert fat_macho_arches(p) == ["arm64"]

    def test_fat_three_arches(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["x86", "x86_64", "arm64"]))
        assert fat_macho_arches(p) == ["x86", "x86_64", "arm64"]

    def test_preserves_header_order(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["arm64", "x86_64"]))
        assert fat_macho_arches(p) == ["arm64", "x86_64"]

    def test_thin_macho_returns_none(self, tmp_path) -> None:
        p = tmp_path / "thin"
        p.write_bytes(_thin_macho())
        assert fat_macho_arches(p) is None

    def test_not_macho_returns_none(self, tmp_path) -> None:
        p = tmp_path / "random"
        p.write_bytes(b"not a binary at all")
        assert fat_macho_arches(p) is None

    def test_empty_file_returns_none(self, tmp_path) -> None:
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert fat_macho_arches(p) is None

    def test_truncated_header_returns_none(self, tmp_path) -> None:
        p = tmp_path / "trunc"
        p.write_bytes(struct.pack(">I", 0xCAFEBABE))
        assert fat_macho_arches(p) is None

    def test_unknown_cputype(self, tmp_path) -> None:
        narch = 1
        header = struct.pack(">II", 0xCAFEBABE, narch)
        header += struct.pack(">IIIII", 0xDEAD, 0, 4096, 64, 12)
        p = tmp_path / "fat"
        p.write_bytes(header + b"\x00" * 4096)
        assert fat_macho_arches(p) == ["unknown_0xdead"]


class TestFatMachoIdaFiletypeArg:
    def test_first_arch(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["x86_64", "arm64"]))
        assert fat_macho_ida_filetype_arg(p, "x86_64") == "Fat Mach-O file, 1"

    def test_second_arch(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["x86_64", "arm64"]))
        assert fat_macho_ida_filetype_arg(p, "arm64") == "Fat Mach-O file, 2"

    def test_reversed_order(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["arm64", "x86_64"]))
        assert fat_macho_ida_filetype_arg(p, "arm64") == "Fat Mach-O file, 1"
        assert fat_macho_ida_filetype_arg(p, "x86_64") == "Fat Mach-O file, 2"

    def test_missing_arch_raises(self, tmp_path) -> None:
        p = tmp_path / "fat"
        p.write_bytes(_fat_binary(["x86_64", "arm64"]))
        with pytest.raises(ValueError, match="ppc.*Available.*x86_64.*arm64"):
            fat_macho_ida_filetype_arg(p, "ppc")

    def test_not_fat_raises(self, tmp_path) -> None:
        p = tmp_path / "thin"
        p.write_bytes(_thin_macho())
        with pytest.raises(ValueError, match="not a fat"):
            fat_macho_ida_filetype_arg(p, "arm64")


class TestDyldCacheArch:
    def test_extracts_arm64e_arch(self, tmp_path) -> None:
        path = tmp_path / "cache.bin"
        path.write_bytes(_dyld_cache_header("arm64e"))
        assert dyld_cache_arch(path) == "arm64e"

    def test_extracts_x86_64h_arch(self, tmp_path) -> None:
        path = tmp_path / "cache.bin"
        path.write_bytes(_dyld_cache_header("x86_64h"))
        assert dyld_cache_arch(path) == "x86_64h"

    def test_rejects_non_cache_header(self, tmp_path) -> None:
        path = tmp_path / "blob.bin"
        path.write_bytes(b"not a dyld cache")
        assert dyld_cache_arch(path) is None
