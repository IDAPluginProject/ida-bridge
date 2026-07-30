"""Locate IDA .app bundles on macOS."""

from pathlib import Path
import plistlib
import re
import subprocess


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
