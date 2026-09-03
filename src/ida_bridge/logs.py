"""Shared logging primitives.

Import-safe so the IDA side (``idalib_runner``) can import it after
``import idapro``: only stdlib plus ``ida_bridge.proc`` (itself stdlib-only).
"""

import logging
import os
from pathlib import Path
import sys

from ida_bridge import proc

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Per-prefix retention for dead instance logs, and how often the server sweeps.
LOG_KEEP = int(os.getenv("IDA_BRIDGE_LOG_KEEP", "30"))
LOG_PRUNE_INTERVAL_S = float(os.getenv("IDA_BRIDGE_LOG_PRUNE_INTERVAL_S", "3600"))

_log = logging.getLogger("ida-bridge")


def _default_log_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ida-bridge" / "logs"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "ida-bridge"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "ida-bridge" / "logs"


def log_dir() -> Path:
    """Base directory for bridge logs (server log + per-instance launch logs).

    Overridable via ``IDA_BRIDGE_LOG_DIR``. The server log can be relocated
    independently via ``IDA_BRIDGE_LOG_FILE``.
    """
    return Path(os.getenv("IDA_BRIDGE_LOG_DIR", str(_default_log_dir()))).expanduser()


def make_formatter() -> logging.Formatter:
    return logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)


def _log_mtime(p: Path) -> float:
    """Return mtime for sorting; 0.0 if the file was concurrently deleted."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _pid_from_instance_log(prefix: str, path: Path) -> int | None:
    """Pid from ``<prefix>-<pid>.log``, or None if the name is not a pid log.

    Placeholders (``idalib-starting-1710000000.log``) must not be parsed as a pid:
    the trailing token is a timestamp, and treating it as dead would let prune
    delete a live Windows capture file after ``LOG_KEEP`` newer deads.
    """
    rest = path.stem[len(prefix) + 1 :] if path.stem.startswith(f"{prefix}-") else ""
    if rest.isdigit():
        return int(rest)
    return None


def _file_held(path: Path) -> bool:
    """True if another process currently has *path* open (Windows only).

    Used so a placeholder log that could not be renamed still counts as live
    while IDA or the runner holds it. POSIX live logs are pid-named (rename of
    an open inode works), so this is not needed there.
    """
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    generic_read = 0x80000000
    open_existing = 3
    file_attribute_normal = 0x80
    error_sharing_violation = 32
    error_access_denied = 5
    invalid = wintypes.HANDLE(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateFileW(str(path), generic_read, 0, None, open_existing, file_attribute_normal, None)
    if handle == invalid:
        return ctypes.get_last_error() in (error_sharing_violation, error_access_denied)
    kernel32.CloseHandle(handle)
    return False


def prune_instance_logs() -> None:
    """Bound the instance-log directory: keep every live instance's log plus the
    ``LOG_KEEP`` most-recent dead logs per prefix, delete the rest.

    Owned by the bridge server (single writer). Best-effort -- never raises, so a
    cleanup hiccup cannot disrupt the server.
    """
    base = log_dir()
    try:
        for prefix in ("idaui", "idalib"):
            entries = sorted(base.glob(f"{prefix}-*.log"), key=_log_mtime, reverse=True)
            dead = []
            for p in entries:
                pid = _pid_from_instance_log(prefix, p)
                if pid is not None and proc.is_pid_alive(pid):
                    continue
                if pid is None and _file_held(p):
                    continue
                dead.append(p)
            for stale in dead[LOG_KEEP:]:
                stale.unlink(missing_ok=True)
    except OSError as exc:
        _log.warning("instance-log cleanup skipped: %s", exc)
