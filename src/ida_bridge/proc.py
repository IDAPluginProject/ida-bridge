"""Process lifecycle primitives. Stdlib-only and import-safe (no ida_bridge imports)."""

import os
import signal
import time


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # Process entry exists but may be a zombie child -- try to reap.
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return False
    except ChildProcessError:
        pass  # not our child
    return True


def wait_for_exit(pid: int, timeout_s: float = 20.0) -> bool:
    """Poll until pid exits. Returns True if it exited within the timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not is_pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def terminate_pid(pid: int, *, timeout_s: float = 10.0) -> str:
    """Best-effort SIGTERM then SIGKILL. Returns method: 'already_dead', 'sigterm', 'sigkill'."""
    if not is_pid_alive(pid):
        return "already_dead"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "already_dead"
    if wait_for_exit(pid, timeout_s):
        return "sigterm"
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "sigterm"
    return "sigkill"
