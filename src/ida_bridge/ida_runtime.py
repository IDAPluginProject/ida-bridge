"""Shared utilities for IDA bridge exec environments (UI plugin + idalib runner)."""

from collections.abc import Callable
import io
import logging
import os
import queue
import sys
import traceback
from typing import Any

from . import protocol

log = logging.getLogger(__name__)


def serialize_result(obj: Any, *, depth: int = 0, max_depth: int = 4) -> Any:
    """Serialize Python objects to JSON-compatible values."""

    if depth > max_depth:
        return {"_truncated_at_depth": depth, "_type": type(obj).__name__, "_repr": repr(obj)}

    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, bytes):
        if len(obj) > 1024:
            return {"_bytes_hex": obj[:1024].hex(), "_truncated": True, "_len": len(obj)}
        return {"_bytes_hex": obj.hex(), "_len": len(obj)}

    if isinstance(obj, (list, tuple)):
        return [serialize_result(x, depth=depth + 1, max_depth=max_depth) for x in obj]

    if isinstance(obj, dict):
        return {str(k): serialize_result(v, depth=depth + 1, max_depth=max_depth) for k, v in obj.items()}

    if isinstance(obj, set):
        return [serialize_result(x, depth=depth + 1, max_depth=max_depth) for x in obj]

    from pydantic import BaseModel

    if isinstance(obj, BaseModel):
        from .sql.models import QueryResult

        if isinstance(obj, QueryResult):
            return obj.format_for_transport()
        return obj.model_dump(mode="json")

    if hasattr(obj, "__dict__"):
        d: dict[str, Any] = {"_type": type(obj).__name__}
        for k, v in obj.__dict__.items():
            if not k.startswith("_"):
                d[k] = serialize_result(v, depth=depth + 1, max_depth=max_depth)
        return d

    return {"_type": type(obj).__name__, "_repr": repr(obj)}


class Tee(io.TextIOBase):
    """Multiplex writes to multiple streams (e.g. capture + original stdout)."""

    def __init__(self, *streams: Any):
        self._streams = streams

    def write(self, s: str) -> int:
        n = 0
        for st in self._streams:
            try:
                r = st.write(s)
                if isinstance(r, int):
                    n = max(n, r)
            except Exception:
                pass
        return n

    def flush(self) -> None:
        for st in self._streams:
            try:
                st.flush()
            except Exception:
                pass


def run_user_code(
    *,
    code: str,
    exec_env: dict[str, Any],
) -> tuple[Any, str, str, Exception | None]:
    """Execute user code with stdout/stderr capture.

    Returns (value, stdout, stderr, error).
    Tees captured output to the original streams so a human can observe it.
    """

    value: Any = None
    err: Exception | None = None

    old_stdout, old_stderr = sys.stdout, sys.stderr
    cap_out, cap_err = io.StringIO(), io.StringIO()
    sys.stdout = Tee(cap_out, old_stdout)
    sys.stderr = Tee(cap_err, old_stderr)
    try:
        exec(code, exec_env, exec_env)
        if "_result_" in exec_env:
            value = exec_env.pop("_result_")
    except Exception as exc:
        err = exc
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    return value, cap_out.getvalue(), cap_err.getvalue(), err


# ---------------------------------------------------------------------------
# Exec env
# ---------------------------------------------------------------------------


def make_exec_env() -> dict[str, Any]:
    """Build a fresh execution environment for user code.

    Injects an ``idb`` helper namespace (``Idb`` instance) for lifecycle
    and analysis operations.
    """
    from .idb import Idb

    return {"__name__": "__ida_bridge__", "__builtins__": __builtins__, "idb": Idb()}


# ---------------------------------------------------------------------------
# Exec response builders
# ---------------------------------------------------------------------------


def build_exec_error(
    *,
    req_id: str,
    client_id: str,
    dst: str,
    exc: Exception,
) -> protocol.ExecResponse:
    """Build an error ExecResponse from an exception."""
    try:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    except Exception:
        tb = "<traceback unavailable>"

    try:
        message = str(exc) or "execution failed"
    except Exception:
        message = "execution failed"

    return protocol.ExecResponse(
        id=req_id,
        src=client_id,
        dst=dst,
        ok=False,
        code="EXEC_ERROR",
        message=message,
        traceback=tb,
    )


def build_exec_response(
    *,
    req_id: str,
    client_id: str,
    dst: str,
    value: Any,
    stdout: str,
    stderr: str,
    error: Exception | None,
) -> protocol.ExecResponse:
    """Build an ExecResponse from run_user_code results."""
    if error is not None:
        return build_exec_error(req_id=req_id, client_id=client_id, dst=dst, exc=error)

    try:
        ser = serialize_result(value)
    except Exception as exc:
        return build_exec_error(req_id=req_id, client_id=client_id, dst=dst, exc=exc)

    return protocol.ExecResponse(
        id=req_id,
        src=client_id,
        dst=dst,
        ok=True,
        result=ser,
        stdout=stdout or None,
        stderr=stderr or None,
    )


# ---------------------------------------------------------------------------
# Queue helpers
# ---------------------------------------------------------------------------

QUEUE_SENTINEL = object()


def shutdown_queue(q: queue.Queue[object], *, immediate: bool) -> None:
    """Best-effort unblock for a thread waiting on Queue.get().

    If immediate=True, drain the queue first.  Then enqueue QUEUE_SENTINEL
    so the consumer wakes up and can check its stop condition.
    """
    if immediate:
        while True:
            try:
                q.get_nowait()
            except queue.Empty:
                break

    try:
        q.put_nowait(QUEUE_SENTINEL)
    except queue.Full:
        try:
            q.get_nowait()
        except queue.Empty:
            pass
        try:
            q.put_nowait(QUEUE_SENTINEL)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# IDA metadata
# ---------------------------------------------------------------------------


def collect_meta(*, client_id: str, runtime: str) -> dict[str, Any]:
    """Collect IDA client metadata. Must run on the correct thread for the runtime."""
    import ida_ida
    import ida_idp
    import idaapi
    import idc

    return {
        "pid": os.getpid(),
        "client_id": client_id,
        "runtime": runtime,
        "idb_path": idc.get_idb_path() or "",
        "input_file": idc.get_input_file_path() or "",
        "ida_version": idaapi.get_kernel_version(),
        "file_type": idaapi.get_file_type_name(),
        "bits": ida_ida.inf_get_app_bitness(),
        "processor": ida_idp.get_idp_name(),
    }


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


def _wire_safe_text(text: str, *, fallback: str) -> str:
    sanitized = text.encode("ascii", "backslashreplace").decode("ascii")
    return sanitized if sanitized.strip() else fallback


def _exception_text(exc: BaseException) -> str:
    try:
        return f"{type(exc).__name__}: {exc}"
    except Exception:
        return type(exc).__name__


def _internal_error_response(
    client_id: str,
    msg: protocol.ExecRequest | protocol.ResetRequest | protocol.QuitRequest,
    exc: BaseException,
) -> protocol.Message:
    response_cls = {
        protocol.MSG_EXEC: protocol.ExecResponse,
        protocol.MSG_RESET: protocol.ResetResponse,
        protocol.MSG_QUIT: protocol.QuitResponse,
    }.get(msg.type)
    if response_cls is None:
        msg_err = f"unexpected request type for internal-error handling: {msg.type}"
        raise AssertionError(msg_err)

    message = _wire_safe_text(_exception_text(exc), fallback="internal error")
    kwargs: dict[str, Any] = {
        "id": msg.id,
        "src": client_id,
        "dst": msg.src,
        "ok": False,
        "code": protocol.ERR_TARGET_INTERNAL_ERROR,
        "message": message,
    }
    if response_cls is protocol.ExecResponse:
        try:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        except Exception:
            tb = "traceback unavailable"
        kwargs["traceback"] = _wire_safe_text(tb, fallback="traceback unavailable")
    return response_cls(**kwargs)


# Signature for code execution callbacks.
# (code, exec_env) -> (value, stdout, stderr, error)
type RunCodeFn = Callable[[str, dict[str, Any]], tuple[Any, str, str, Exception | None]]

# Signature for sending a response message.
type SendFn = Callable[[protocol.Message], None]


class RequestHandler:
    """Shared request handler for both UI and idalib runtimes.

    Owns the exec environment lifecycle and dispatches exec/reset messages.
    Runtimes provide callbacks for the two things that differ:
    - ``run_code``: how to execute user code (execute_sync vs direct call).
    - ``send``: how to send a response message.
    """

    def __init__(
        self,
        *,
        client_id: str,
        run_code: RunCodeFn,
        send: SendFn,
    ) -> None:
        self._client_id = client_id
        self._run_code = run_code
        self._send = send
        self._exec_env = make_exec_env()

    @property
    def quit_requested(self) -> bool:
        idb = self._exec_env.get("idb")
        return idb is not None and idb.quit_requested

    def handle(self, msg: protocol.ExecRequest | protocol.ResetRequest | protocol.QuitRequest) -> None:
        """Dispatch a single request. Raises on internal errors (not user code errors)."""
        if isinstance(msg, protocol.ResetRequest):
            self._handle_reset(msg)
        elif isinstance(msg, protocol.ExecRequest):
            self._handle_exec(msg)
        elif isinstance(msg, protocol.QuitRequest):
            self._handle_quit(msg)

    def handle_request(self, msg: protocol.ExecRequest | protocol.ResetRequest | protocol.QuitRequest) -> None:
        """Handle one request; on internal exception log and send TARGET_INTERNAL_ERROR."""
        try:
            self.handle(msg)
        except Exception as exc:
            log.error("internal error handling request", exc_info=True)
            try:
                self._send(_internal_error_response(self._client_id, msg, exc))
            except Exception:
                log.error("failed to send internal error response", exc_info=True)

    def _handle_exec(self, msg: protocol.ExecRequest) -> None:
        if msg.reset_env:
            self._exec_env = make_exec_env()

        value, stdout, stderr, err = self._run_code(msg.code, self._exec_env)
        resp = build_exec_response(
            req_id=msg.id,
            client_id=self._client_id,
            dst=msg.src,
            value=value,
            stdout=stdout,
            stderr=stderr,
            error=err,
        )
        self._send(resp)

    def _handle_reset(self, msg: protocol.ResetRequest) -> None:
        self._exec_env = make_exec_env()
        self._send(protocol.ResetResponse(id=msg.id, src=self._client_id, dst=msg.src, ok=True))

    def _handle_quit(self, msg: protocol.QuitRequest) -> None:
        """Acknowledge quit and set the flag. Caller loop exits after handle() returns."""
        idb = self._exec_env.get("idb")
        if idb is not None:
            idb.quit()
        self._send(protocol.QuitResponse(id=msg.id, src=self._client_id, dst=msg.src, ok=True))
