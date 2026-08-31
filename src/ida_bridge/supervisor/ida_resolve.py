"""Locate IDA installs: macOS .app bundles or Windows install directories."""

import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys


def _read_ida_app_version(app_path: Path) -> tuple[int, ...]:
    """Parse IDA version from the app bundle's Info.plist."""
    info_plist = app_path / "Contents" / "Info.plist"
    try:
        with info_plist.open("rb") as f:
            data = plistlib.load(f)
    except Exception as exc:
        raise SystemExit(f"failed to read Info.plist: {info_plist} ({exc})") from exc

    ver = data.get("CFBundleShortVersionString")
    if not isinstance(ver, str) or not ver.strip():
        raise SystemExit(f"missing CFBundleShortVersionString in Info.plist: {info_plist}")

    ver = ver.strip()
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)", ver)
    if not m:
        raise SystemExit(f"invalid CFBundleShortVersionString in Info.plist: {info_plist} (value: {ver!r})")

    return tuple(int(x) for x in m.group(1).split("."))


def find_ida_app_bundle_macos() -> Path:
    """Find the newest installed IDA Professional .app using Spotlight."""
    res = subprocess.run(
        ["mdfind", "kMDItemFSName == 'IDA Professional*.app'"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if res.returncode != 0:
        err = (res.stderr or "").strip()
        raise SystemExit(
            "mdfind failed while searching for IDA installations. "
            "Pass --ida explicitly.\n" + (f"mdfind stderr: {err}" if err else "")
        )

    candidates: list[Path] = []
    for line in res.stdout.splitlines():
        p = Path(line.strip())
        if p.suffix == ".app" and p.exists():
            candidates.append(p)

    if not candidates:
        raise SystemExit(
            "No IDA Professional .app bundles found via Spotlight. "
            "Install IDA or pass --ida '/Applications/IDA Professional X.Y.app'."
        )

    best: Path | None = None
    best_ver: tuple[int, ...] = ()
    errors: list[str] = []

    for p in sorted(set(candidates)):
        try:
            ver = _read_ida_app_version(p)
        except SystemExit as exc:
            errors.append(f"{p}: {exc}")
            continue
        if ver > best_ver:
            best_ver = ver
            best = p

    if best is None:
        msg = "\n".join(f"- {x}" for x in errors) if errors else "(none)"
        raise SystemExit(
            "IDA installations found via Spotlight, but none could be version-parsed.\n"
            + msg
            + "\n\nPass --ida explicitly."
        )

    return best


_IDA_EXE_NAMES = ("ida.exe", "ida64.exe")


def _parse_dir_version(dirname: str) -> tuple[int, ...] | None:
    m = re.search(r"([0-9]+(?:\.[0-9]+)*)", dirname)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _looks_like_ida_dir(name: str) -> bool:
    n = name.lower()
    return n.startswith("ida") and not n.startswith("idapython")


def _ida_exe_in(directory: Path) -> Path | None:
    for name in _IDA_EXE_NAMES:
        exe = directory / name
        if exe.is_file():
            return exe
    return None


def _windows_search_roots() -> list[Path]:
    roots: list[Path] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(var)
        if value:
            roots.append(Path(value))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "Programs")
    return roots


def find_ida_windows(*, search_roots: list[Path] | None = None) -> Path:
    """Find the newest IDA launcher exe under typical Windows install roots.

    ``IDADIR`` wins when it points at a directory that contains ``ida.exe``
    or ``ida64.exe``. Otherwise ``Program Files``, ``Program Files (x86)``,
    and ``%LOCALAPPDATA%\\Programs`` are scanned for directories whose names
    start with ``IDA``.
    """
    idadir = os.environ.get("IDADIR")
    if idadir:
        exe = _ida_exe_in(Path(idadir))
        if exe is not None:
            return exe

    roots = search_roots if search_roots is not None else _windows_search_roots()
    candidates: list[tuple[tuple[int, ...], Path]] = []
    unversioned: list[Path] = []

    for root in roots:
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir() or not _looks_like_ida_dir(entry.name):
                continue
            exe = _ida_exe_in(entry)
            if exe is None:
                continue
            ver = _parse_dir_version(entry.name)
            if ver is None:
                unversioned.append(exe)
            else:
                candidates.append((ver, exe))

    if candidates:
        return max(candidates, key=lambda item: item[0])[1]
    if unversioned:
        return sorted(unversioned)[-1]

    raise SystemExit("No IDA installation found. Pass --ida 'C:\\Program Files\\IDA Professional 9.x\\ida.exe'.")


def find_ida() -> Path:
    """Locate the IDA launcher for the current platform."""
    if sys.platform == "win32":
        return find_ida_windows()
    if sys.platform == "darwin":
        return find_ida_app_bundle_macos()
    raise SystemExit("IDA auto-detect supports macOS and Windows only. Pass --ida explicitly.")
