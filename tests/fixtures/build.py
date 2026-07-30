#!/usr/bin/env python3
"""Generate e2e test fixtures: compile src/ into bins/, then create IDBs in idbs/.

Requires clang/clang++/lipo/strip and a running bridge server that exec-idb connects to.
See docs/testing.md for the fixture model.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys

FIXTURES_DIR = Path(__file__).resolve().parent
SRC_DIR = FIXTURES_DIR / "src"
BINS_DIR = FIXTURES_DIR / "bins"
IDBS_DIR = FIXTURES_DIR / "idbs"

# Canonical fixture binary names (also the filenames under bins/): source, arch,
# and processing.
CALC_ARM64 = "calc_arm64"
CALC_ARM64_STRIPPED = "calc_arm64_stripped"
CALC_X86_64 = "calc_x86_64"
CALC_FAT = "calc_fat"
SHAPES_ARM64 = "shapes_arm64"
ENUMS_ARM64 = "enums_arm64"

# Semantic handles for test consumers (see tests/e2e/conftest.py).
SMALL_MACHO_ARM64 = CALC_ARM64
FAT_MACHO = CALC_FAT


def bin_path(name: str) -> Path:
    """Path to a compiled fixture binary under bins/ (may not exist until built)."""
    return BINS_DIR / name


@dataclass(frozen=True)
class Binary:
    """A compiled binary variant produced from one source file."""

    name: str
    source: str
    arch: str = "arm64"  # arm64 | x86_64
    opt: str = "0"  # clang -O level
    strip: bool = False
    cpp: bool = False
    debug: bool = False  # -g, so IDA imports the source's types (e.g. enums)


@dataclass(frozen=True)
class Fat:
    """A universal binary produced by lipo-ing thin binaries together."""

    name: str
    members: tuple[str, ...]  # names of Binary entries


@dataclass(frozen=True)
class Idb:
    """An IDB produced from a binary via ``ida-bridge exec-idb``."""

    name: str  # -> idbs[/heavy]/<name>.i64
    binary: str  # name of a Binary or Fat entry
    arch: str | None = None  # slice to load from a fat binary
    prep: str | None = None  # optional prep script in src/, run after load
    heavy: bool = False  # place under idbs/heavy/ (opt-in set)


BINARIES: tuple[Binary, ...] = (
    Binary(name=CALC_ARM64, source="calc.c", arch="arm64", opt="0"),
    Binary(name=CALC_ARM64_STRIPPED, source="calc.c", arch="arm64", opt="2", strip=True),
    Binary(name=CALC_X86_64, source="calc.c", arch="x86_64", opt="0"),
    Binary(name=SHAPES_ARM64, source="shapes.cpp", arch="arm64", opt="0", cpp=True),
    Binary(name=ENUMS_ARM64, source="enums.c", arch="arm64", opt="0", debug=True),
)

FATS: tuple[Fat, ...] = (Fat(name=CALC_FAT, members=(CALC_ARM64, CALC_X86_64)),)

IDBS: tuple[Idb, ...] = (
    Idb(name=CALC_ARM64, binary=CALC_ARM64),
    Idb(name=CALC_ARM64_STRIPPED, binary=CALC_ARM64_STRIPPED),
    Idb(name=CALC_X86_64, binary=CALC_X86_64),
    Idb(name=SHAPES_ARM64, binary=SHAPES_ARM64),
    Idb(name=ENUMS_ARM64, binary=ENUMS_ARM64),
)

REQUIRED_TOOLS = ("clang", "clang++", "lipo", "strip")


def _run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)


def _stale(out: Path, *inputs: Path) -> bool:
    return not out.exists() or any(out.stat().st_mtime < i.stat().st_mtime for i in inputs)


def compile_binary(b: Binary, *, force: bool) -> Path:
    src = SRC_DIR / b.source
    out = bin_path(b.name)
    if force or _stale(out, src):
        tool = "clang++" if b.cpp else "clang"
        cmd = [tool, "-arch", b.arch, f"-O{b.opt}"]
        if b.debug:
            cmd.append("-g")
            # -g on Darwin emits a companion .dSYM (via dsymutil). Drop any stale
            # bundle first so IDA never imports DWARF from a previous build.
            shutil.rmtree(out.parent / f"{out.name}.dSYM", ignore_errors=True)
        cmd += ["-o", str(out), str(src)]
        _run(cmd)
        if b.strip:
            _run(["strip", "-x", str(out)])
    return out


def make_fat(f: Fat, *, force: bool) -> Path:
    out = bin_path(f.name)
    members = [bin_path(m) for m in f.members]
    if force or _stale(out, *members):
        _run(["lipo", "-create", *[str(m) for m in members], "-output", str(out)])
    return out


def make_idb(i: Idb, *, force: bool) -> Path:
    binary = bin_path(i.binary)
    out_dir = IDBS_DIR / "heavy" if i.heavy else IDBS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{i.name}.i64"
    prep = SRC_DIR / i.prep if i.prep else None
    inputs = [binary] + ([prep] if prep else [])
    if force or _stale(out, *inputs):
        cmd = [sys.executable, "-m", "ida_bridge.cli", "exec-idb"]
        cmd += ["--input", str(binary), "--out-idb", str(out), "--force", "--save"]
        if i.arch:
            cmd += ["--arch", i.arch]
        if prep:
            cmd += ["--file", str(prep)]
        _run(cmd)
    return out


def _require_tools() -> None:
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        raise SystemExit(f"missing required tools: {', '.join(missing)} (install Xcode command line tools)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build.py", description=__doc__)
    parser.add_argument("--force", action="store_true", help="rebuild everything, ignoring mtimes")
    args = parser.parse_args(argv)

    _require_tools()
    BINS_DIR.mkdir(parents=True, exist_ok=True)

    for b in BINARIES:
        compile_binary(b, force=args.force)
    for f in FATS:
        make_fat(f, force=args.force)
    for i in IDBS:
        make_idb(i, force=args.force)

    print(f"\nbinaries -> {BINS_DIR}")
    print(f"idbs     -> {IDBS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
