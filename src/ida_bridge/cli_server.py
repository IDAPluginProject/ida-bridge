"""IDA Bridge server management."""

import argparse
from collections import deque
import os
from pathlib import Path
import subprocess
import sys
import time

from ida_bridge import logs, proc, protocol

SERVER_MODULE = "ida_bridge.server"

LOG_FILE = Path(os.getenv("IDA_BRIDGE_LOG_FILE", str(logs.log_dir() / "server.log"))).expanduser()
# Raw stdout/stderr capture for the server process: crash tracebacks and any output that
# bypasses logging. Kept separate from LOG_FILE so the server's RotatingFileHandler is the
# sole writer of LOG_FILE (a second writer would keep writing a rotated-out inode).
OUT_FILE = LOG_FILE.with_suffix(".out")

PORT = protocol.bridge_port()

_POLL_INTERVAL_S = 0.05
_READY_TIMEOUT_S = 5.0


def _server_cmd() -> list[str]:
    return [sys.executable, "-m", SERVER_MODULE]


def get_server_pid() -> int | None:
    """Get PID of process listening on our port."""
    return proc.listening_pid(PORT)


def _wait_for_listener(child: subprocess.Popen[bytes], timeout_s: float) -> int | None:
    """PID of the server's listener once it appears, or None if the child exits first."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pid = get_server_pid()
        if pid:
            return pid
        if child.poll() is not None:
            return None
        time.sleep(_POLL_INTERVAL_S)
    return get_server_pid()


def _wait_for_port_free(timeout_s: float) -> bool:
    """True once nothing is listening on the port."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if get_server_pid() is None:
            return True
        time.sleep(_POLL_INTERVAL_S)
    return get_server_pid() is None


def cmd_status(args: argparse.Namespace) -> int:
    pid = get_server_pid()
    if pid:
        print(f"Server running (PID: {pid})")
        return 0
    print("Server not running")
    return 1


def cmd_start(args: argparse.Namespace) -> int:
    if get_server_pid():
        print("Server already running")
        return 0

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["IDA_BRIDGE_LOG_FILE"] = str(LOG_FILE)

    print(f"Starting server... (logging to {LOG_FILE})")
    # Truncate per boot: this holds only the current run's raw output (mostly empty).
    with open(OUT_FILE, "w") as out:
        child = subprocess.Popen(
            _server_cmd(),
            stdout=out,
            stderr=subprocess.STDOUT,
            env=env,
            **proc.detached_popen_kwargs(),
        )

    listener_pid = _wait_for_listener(child, _READY_TIMEOUT_S)
    if listener_pid:
        print(f"Server started (PID: {listener_pid})")
        return 0

    print(f"Failed to start. Check logs: {LOG_FILE} and {OUT_FILE}")
    return 1


def cmd_stop(args: argparse.Namespace) -> int:
    pid = get_server_pid()
    if not pid:
        print("Server not running")
        return 0

    print(f"Stopping server (PID: {pid})...")
    method = proc.terminate_pid(pid, timeout_s=2.0)
    if not _wait_for_port_free(_READY_TIMEOUT_S):
        print("Server did not stop")
        return 1
    print("Server killed" if method == "sigkill" else "Server stopped")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    if not LOG_FILE.exists():
        print(f"No log file: {LOG_FILE}")
        return 1
    try:
        with LOG_FILE.open(encoding="utf-8", errors="replace") as fh:
            for line in deque(fh, maxlen=10):
                print(line, end="", flush=True)
            while True:
                line = fh.readline()
                if line:
                    print(line, end="", flush=True)
                else:
                    time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_log_clear(args: argparse.Namespace) -> int:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if LOG_FILE.exists():
        LOG_FILE.write_text("")
        print(f"Log cleared: {LOG_FILE}")
    else:
        print(f"No log file to clear: {LOG_FILE}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IDA Bridge server management")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="Check if server is running")
    sub.add_parser("start", help="Start server in background")
    sub.add_parser("stop", help="Stop the server")
    sub.add_parser("log", help="Tail the server log")
    sub.add_parser("log-clear", help="Clear the server log")

    args = parser.parse_args(argv)
    commands = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "log": cmd_log,
        "log-clear": cmd_log_clear,
    }

    if args.cmd in commands:
        return commands[args.cmd](args)
    parser.print_help()
    return 1
