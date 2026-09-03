"""Process lifecycle primitives. Stdlib-only and import-safe (no ida_bridge imports)."""

import os
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Any

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _PROCESS_TERMINATE = 0x0001
    _STILL_ACTIVE = 259
    _ERROR_ACCESS_DENIED = 5
    _TH32CS_SNAPPROCESS = 0x00000002
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if _IS_WINDOWS:
        return _is_pid_alive_windows(pid)
    return _is_pid_alive_posix(pid)


def _is_pid_alive_posix(pid: int) -> bool:
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


def _is_pid_alive_windows(pid: int) -> bool:
    """Liveness via OpenProcess + GetExitCodeProcess.

    ``os.kill(pid, 0)`` is not a probe on Windows: ``os.kill`` terminates.
    Access-denied counts as alive, as ``PermissionError`` does on POSIX.
    """
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # The process exists, this token just cannot open it (other user, elevated, protected).
        return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
    try:
        code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == _STILL_ACTIVE
    finally:
        _kernel32.CloseHandle(handle)


def wait_for_exit(pid: int, timeout_s: float = 20.0) -> bool:
    """Poll until pid exits. Returns True if it exited within the timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not is_pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def terminate_pid(pid: int, *, timeout_s: float = 10.0) -> str:
    """Best-effort terminate. Returns method: 'already_dead', 'sigterm', 'sigkill'.

    POSIX: SIGTERM, then SIGKILL if still alive.
    Windows: TerminateProcess on the pid and its descendants. There is no
    graceful OS signal; callers that can reach the process should send the
    bridge quit RPC first. The method string stays ``sigkill`` so existing
    stop output and JSON keep working.
    """
    if _IS_WINDOWS:
        return _terminate_pid_windows(pid, timeout_s=timeout_s)
    return _terminate_pid_posix(pid, timeout_s=timeout_s)


def _terminate_pid_posix(pid: int, *, timeout_s: float) -> str:
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


def _terminate_pid_windows(pid: int, *, timeout_s: float) -> str:
    if not is_pid_alive(pid):
        return "already_dead"
    # Venv redirector on Windows is a stub whose child is the real interpreter.
    # Kill descendants first so TerminateProcess(redirector) cannot leak them.
    for child in reversed(_windows_descendant_pids(pid)):
        _windows_terminate_one(child)
    _windows_terminate_one(pid)
    wait_for_exit(pid, timeout_s)
    return "sigkill"


def _windows_terminate_one(pid: int) -> None:
    handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, False, pid)
    if not handle:
        return
    try:
        _kernel32.TerminateProcess(handle, 1)
    finally:
        _kernel32.CloseHandle(handle)


def _windows_descendant_pids(root_pid: int) -> list[int]:
    """PIDs descended from *root_pid*, not including *root_pid*."""
    children_of: dict[int, list[int]] = {}
    snap = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap == _INVALID_HANDLE_VALUE:
        return []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not _kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return []
        while True:
            children_of.setdefault(entry.th32ParentProcessID, []).append(entry.th32ProcessID)
            if not _kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        _kernel32.CloseHandle(snap)

    out: list[int] = []
    stack = list(children_of.get(root_pid, ()))
    seen = {root_pid}
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        out.append(cur)
        stack.extend(children_of.get(cur, ()))
    return out


def is_pid_in_tree(root_pid: int, pid: int) -> bool:
    """True if *pid* is *root_pid* or a Windows descendant of it.

    On non-Windows this is equality only (no process-tree walk). Used to match
    an idalib client whose ``os.getpid()`` is the venv redirector's child.
    """
    if pid == root_pid:
        return True
    if not _IS_WINDOWS or root_pid <= 0 or pid <= 0:
        return False
    return pid in _windows_descendant_pids(root_pid)


def detached_popen_kwargs() -> dict[str, Any]:
    """Kwargs so a background child does not take over the caller's console.

    POSIX: new session (survives caller hangup).
    Windows: no extra console window. The child still outlives the caller.
    """
    if _IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


def listening_pid(port: int) -> int | None:
    """PID of the process listening on TCP *port*, or None."""
    if _IS_WINDOWS:
        return _listening_pid_windows(port)
    if sys.platform == "linux":
        return _listening_pid_via_proc(port)
    return _listening_pid_via_lsof(port)


_TCP_LISTEN = "0A"  # st field in /proc/net/tcp


def _listening_inodes(port: int) -> set[str]:
    inodes: set[str] = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as fh:
                lines = fh.read().splitlines()[1:]  # tcp6 is absent without IPv6
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != _TCP_LISTEN:
                continue
            if int(fields[1].rsplit(":", 1)[1], 16) == port:
                inodes.add(fields[9])
    return inodes


def _listening_pid_via_proc(port: int) -> int | None:
    """Listener PID from ``/proc`` alone.

    ``lsof`` is absent from minimal images, including the one CI runs in, so
    Linux reads the socket inode from ``/proc/net/tcp`` and ``tcp6``, then finds
    the process holding it. Only processes this user can read are visible, which
    is enough: the server we look for is our own.
    """
    targets = {f"socket:[{inode}]" for inode in _listening_inodes(port)}
    if not targets:
        return None
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = f"/proc/{entry}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") in targets:
                    return int(entry)
            except OSError:
                continue
    return None


def _listening_pid_via_lsof(port: int) -> int | None:
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, ValueError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return int(result.stdout.strip().split()[0])
    except ValueError:
        return None


def _listening_pid_windows(port: int) -> int | None:
    """Prefer GetExtendedTcpTable; fall back to ``netstat -ano``."""
    try:
        pid = _listening_pid_iphlpapi(port)
    except OSError:
        pid = None
    if pid is not None:
        return pid
    return _listening_pid_netstat(port)


def _listening_pid_iphlpapi(port: int) -> int | None:
    iphlpapi = ctypes.WinDLL("iphlpapi")
    for af in (socket.AF_INET, socket.AF_INET6):
        pid = _tcp_table_listener(iphlpapi, af, port)
        if pid is not None:
            return pid
    return None


_TCP_TABLE_OWNER_PID_LISTENER = 3
_ERROR_INSUFFICIENT_BUFFER = 122


def _tcp_table_listener(iphlpapi: Any, af: int, port: int) -> int | None:
    get_table = iphlpapi.GetExtendedTcpTable
    get_table.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    get_table.restype = wintypes.DWORD

    # Table can grow between the size probe and the read; retry a few times.
    size = wintypes.DWORD(0)
    for _ in range(3):
        err = get_table(None, ctypes.byref(size), False, af, _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if err != _ERROR_INSUFFICIENT_BUFFER or size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        err = get_table(buf, ctypes.byref(size), False, af, _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if err == 0:
            return _pid_for_port_in_tcp_table(buf.raw, af, port)
        if err != _ERROR_INSUFFICIENT_BUFFER:
            return None
    return None


def _pid_for_port_in_tcp_table(raw: bytes, af: int, port: int) -> int | None:
    if len(raw) < 4:
        return None
    (count,) = struct.unpack_from("I", raw, 0)
    offset = 4
    if af == socket.AF_INET:
        row_size = 24
        port_off = 8
        pid_off = 20
    else:
        row_size = 56
        port_off = 20
        pid_off = 52
    for _ in range(count):
        if offset + row_size > len(raw):
            break
        (local_port,) = struct.unpack_from("I", raw, offset + port_off)
        (pid,) = struct.unpack_from("I", raw, offset + pid_off)
        if socket.ntohs(local_port & 0xFFFF) == port and pid != 0:
            return pid
        offset += row_size
    return None


def parse_netstat_listening_pid(stdout: str, port: int) -> int | None:
    """Return the listener PID for *port* from Windows ``netstat -ano`` output."""
    wanted = str(port)
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens) < 4:
            continue
        if not any(tok.upper() == "LISTENING" for tok in tokens):
            continue
        local = tokens[1]
        _, sep, local_port = local.rpartition(":")
        if not sep or local_port != wanted:
            continue
        try:
            return int(tokens[-1])
        except ValueError:
            continue
    return None


def _listening_pid_netstat(port: int) -> int | None:
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    return parse_netstat_listening_pid(result.stdout, port)
