"""IDA-side bridge client for the UI plugin.

Wraps BridgeConn (shared connection) and RequestHandler (shared exec dispatch)
with UI-specific behavior:
- Metadata collected on IDA's main thread via execute_sync.
- Code executed on IDA's main thread via execute_sync.
- Quit via idc.qexit().
"""

import logging
import os
import threading
from typing import Any

# IDA-side imports: this module is meant to run inside IDA.
import ida_kernwin
import idc

from .bridge_conn import BridgeConn
from .ida_runtime import RequestHandler, collect_meta, run_user_code

log = logging.getLogger(__name__)


class _IDAOutputHandler(logging.Handler):
    """Route ida_bridge log messages to IDA's Output window."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ida_kernwin.msg(f"[ida-bridge] {record.getMessage()}\n")
        except Exception:
            pass


def _install_log_handler() -> None:
    """Install the IDA Output handler on the ida_bridge logger (once)."""
    logger = logging.getLogger("ida_bridge")
    if not any(isinstance(h, _IDAOutputHandler) for h in logger.handlers):
        logger.addHandler(_IDAOutputHandler())
        logger.setLevel(logging.INFO)
        logger.propagate = False

    # Suppress per-attempt noise from the websocket library.
    logging.getLogger("websocket").setLevel(logging.CRITICAL)


class IDAClient:
    """IDA-side client for the ida-bridge protocol.

    Manages a BridgeConn and an executor thread that processes requests
    serially on IDA's main thread via execute_sync.
    """

    def __init__(self) -> None:
        _install_log_handler()

        self._client_id = f"idaui-{os.getpid()}"

        self._conn: BridgeConn | None = None
        self._exec_thread: threading.Thread | None = None
        self._stop = threading.Event()

    def connect(self) -> None:
        """Collect metadata and start connection + executor.

        No-op if already started (connecting or connected).
        Call disconnect() first to restart.
        """
        if self._conn is not None:
            return

        self._stop.clear()

        # Collect metadata on IDA's main thread.
        meta: dict[str, Any] = {}

        def _collect() -> None:
            nonlocal meta
            meta = collect_meta(client_id=self._client_id, runtime="ui")

        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)

        # Create connection and start.
        self._conn = BridgeConn(client_id=self._client_id, meta=meta)
        self._conn.start()

        # Start executor thread.
        self._exec_thread = threading.Thread(target=self._run_executor, name="ida-bridge-exec", daemon=True)
        self._exec_thread.start()

    def disconnect(self) -> None:
        """Stop connection and executor."""
        self._stop.set()

        if self._conn:
            self._conn.stop()
            self._conn = None

        self._exec_thread = None

    def is_connected(self) -> bool:
        return self._conn is not None and self._conn.is_connected()

    def _exec_on_main_thread(
        self,
        code: str,
        exec_env: dict[str, Any],
    ) -> tuple[Any, str, str, Exception | None]:
        """Execute user code on IDA's main thread via execute_sync."""
        result: dict[str, Any] = {"value": None, "stdout": "", "stderr": "", "error": None}

        def _run() -> None:
            v, o, e, err = run_user_code(code=code, exec_env=exec_env)
            result["value"] = v
            result["stdout"] = o
            result["stderr"] = e
            result["error"] = err

        ida_kernwin.execute_sync(_run, ida_kernwin.MFF_WRITE)
        return (result["value"], result["stdout"], result["stderr"], result["error"])

    def _run_executor(self) -> None:
        conn = self._conn
        if conn is None:
            return

        handler = RequestHandler(client_id=self._client_id, run_code=self._exec_on_main_thread, send=conn.send)

        while not self._stop.is_set():
            msg = conn.recv(timeout_s=0.25)
            if msg is None:
                continue

            handler.handle_request(msg)

            if handler.quit_requested:
                log.info("shutdown requested")
                ida_kernwin.execute_sync(lambda: idc.qexit(0), ida_kernwin.MFF_FAST)
