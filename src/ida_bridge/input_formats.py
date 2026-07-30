"""Input format sniffing and IDA file-type argument helpers."""

from pathlib import Path
import re
import struct

_FAT_MAGIC_BE = 0xCAFEBABE
_DYLD_CACHE_MAGIC_RE = re.compile(r"^dyld_v\d+\s+(?P<arch>[^\s]+)$")

# cputype constants (big-endian in the fat header).
_CPU_NAMES: dict[int, str] = {
    0x00000007: "x86",
    0x01000007: "x86_64",
    0x0000000C: "arm",
    0x0100000C: "arm64",
    0x00000012: "ppc",
    0x01000012: "ppc64",
}


def fat_macho_arches(path: Path) -> list[str] | None:
    """Return arch names in fat-header order, or ``None`` if not a fat Mach-O."""
    with open(path, "rb") as f:
        header = f.read(8)
        if len(header) < 8:
            return None
        magic, narch = struct.unpack(">II", header)
        if magic != _FAT_MAGIC_BE:
            return None
        arches: list[str] = []
        for _ in range(narch):
            entry = f.read(20)
            if len(entry) < 20:
                return None
            (cputype,) = struct.unpack(">I", entry[:4])
            arches.append(_CPU_NAMES.get(cputype, f"unknown_0x{cputype:x}"))
        return arches


def fat_macho_ida_filetype_arg(path: Path, arch: str) -> str:
    """Return the ``-T`` value for *arch* in a fat Mach-O at *path*."""
    arches = fat_macho_arches(path)
    if arches is None:
        raise ValueError(f"not a fat Mach-O: {path}")
    try:
        ordinal = arches.index(arch) + 1
    except ValueError:
        available = ", ".join(arches)
        raise ValueError(f"arch {arch!r} not found in {path}. Available: {available}") from None
    return f"Fat Mach-O file, {ordinal}"


def dyld_cache_arch(path: Path) -> str | None:
    """Return the architecture encoded in a dyld_shared_cache header."""
    with open(path, "rb") as f:
        magic = f.read(16)

    text = magic.rstrip(b"\x00").decode("ascii", errors="ignore")
    match = _DYLD_CACHE_MAGIC_RE.match(text)
    if match is None:
        return None

    return match.group("arch")
