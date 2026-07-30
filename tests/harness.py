import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING

import websockets

from ida_bridge import protocol

if TYPE_CHECKING:
    from ida_bridge.server import BridgeServer

type ServeBridge = Callable[..., AbstractAsyncContextManager[tuple["BridgeServer", str]]]


async def send_msg(ws: websockets.ClientConnection, msg: protocol.Message) -> None:
    await ws.send(protocol.dump_message_json(msg))


async def recv_msg(ws: websockets.ClientConnection) -> protocol.Message:
    raw = await ws.recv()
    assert isinstance(raw, str)
    return protocol.parse_message_json(raw)


async def recv_typed[T](ws: websockets.ClientConnection, cls: type[T], *, timeout_s: float = 1.0) -> T:
    msg = await asyncio.wait_for(recv_msg(ws), timeout=timeout_s)
    assert isinstance(msg, cls)
    return msg


async def assert_no_message(ws: websockets.ClientConnection, *, timeout_s: float = 0.1) -> None:
    try:
        msg = await asyncio.wait_for(recv_msg(ws), timeout=timeout_s)
    except TimeoutError:
        return
    raise AssertionError(f"unexpected message: {msg!r}")


async def connect_client(
    url: str,
    *,
    role: protocol.ClientRole,
    client_id: str,
    meta: dict[str, object] | None = None,
) -> websockets.ClientConnection:
    ws = await websockets.connect(url)
    await send_msg(ws, protocol.Hello(role=role, client_id=client_id, meta=meta or {}))
    ack = await recv_msg(ws)
    assert isinstance(ack, protocol.HelloAck)
    assert ack.client_id == client_id
    return ws


@asynccontextmanager
async def connected_client(
    url: str,
    *,
    role: protocol.ClientRole,
    client_id: str,
    meta: dict[str, object] | None = None,
) -> AsyncIterator[websockets.ClientConnection]:
    """Connect and handshake a client, closing it on exit.

    Safe to use even if the server closes the connection mid-test
    (websockets close() is idempotent).
    """
    ws = await connect_client(url, role=role, client_id=client_id, meta=meta)
    try:
        yield ws
    finally:
        await ws.close()


async def send_exec(
    ws: websockets.ClientConnection,
    *,
    agent_id: str,
    target: str,
    code: str = "_result_ = 1",
    persist: bool = False,
    session_id: str | None = None,
    timeout_s: int | None = None,
) -> protocol.ExecRequest:
    req = protocol.ExecRequest(
        id=protocol.new_req_id(),
        src=agent_id,
        dst=target,
        persist=persist,
        session_id=session_id,
        code=code,
        timeout_s=timeout_s,
    )
    await send_msg(ws, req)
    return req


async def send_reset(
    ws: websockets.ClientConnection,
    *,
    agent_id: str,
    target: str,
    session_id: str,
    release: bool = False,
    takeover: bool = False,
    timeout_s: int | None = None,
) -> protocol.ResetRequest:
    req = protocol.ResetRequest(
        id=protocol.new_req_id(),
        src=agent_id,
        dst=target,
        session_id=session_id,
        release=release,
        takeover=takeover,
        timeout_s=timeout_s,
    )
    await send_msg(ws, req)
    return req


async def respond_exec_ok(
    ws: websockets.ClientConnection,
    forwarded: protocol.ExecRequest,
    *,
    result: object = 1,
) -> None:
    await send_msg(
        ws,
        protocol.ExecResponse(
            id=forwarded.id,
            src=forwarded.dst,
            dst=forwarded.src,
            ok=True,
            result=result,
        ),
    )


async def respond_reset(
    ws: websockets.ClientConnection,
    forwarded: protocol.ResetRequest,
    *,
    ok: bool = True,
    code: str = "RESET_FAILED",
    message: str = "reset failed",
) -> None:
    if ok:
        resp = protocol.ResetResponse(id=forwarded.id, src=forwarded.dst, dst=forwarded.src, ok=True)
    else:
        resp = protocol.ResetResponse(
            id=forwarded.id,
            src=forwarded.dst,
            dst=forwarded.src,
            ok=False,
            code=code,
            message=message,
        )
    await send_msg(ws, resp)


async def recv_exec_response(ws: websockets.ClientConnection, *, timeout_s: float = 1.0) -> protocol.ExecResponse:
    return await recv_typed(ws, protocol.ExecResponse, timeout_s=timeout_s)


async def recv_reset_response(ws: websockets.ClientConnection, *, timeout_s: float = 1.0) -> protocol.ResetResponse:
    return await recv_typed(ws, protocol.ResetResponse, timeout_s=timeout_s)


async def list_ida_sessions(
    ws: websockets.ClientConnection,
    *,
    agent_id: str,
    bridge_id: str,
    timeout_s: float = 1.0,
) -> dict[str, str | None]:
    req = protocol.ListRequest(
        id=protocol.new_req_id(),
        src=agent_id,
        dst=bridge_id,
        kind=protocol.LIST_KIND_IDA,
    )
    await send_msg(ws, req)
    resp = await recv_typed(ws, protocol.ListResponse, timeout_s=timeout_s)
    assert resp.ok is True
    assert resp.clients is not None
    return {client.client_id: client.session_id for client in resp.clients}


async def get_ida_session_id(
    ws: websockets.ClientConnection,
    *,
    agent_id: str,
    bridge_id: str,
    target: str,
    timeout_s: float = 1.0,
) -> str | None:
    sessions = await list_ida_sessions(ws, agent_id=agent_id, bridge_id=bridge_id, timeout_s=timeout_s)
    return sessions[target]


async def expect_protocol_error_and_close(
    ws: websockets.ClientConnection,
    *,
    code: str,
    close_code: int,
    timeout_s: float = 1.0,
) -> protocol.ProtocolError:
    msg = await asyncio.wait_for(recv_msg(ws), timeout=timeout_s)
    assert isinstance(msg, protocol.ProtocolError)
    assert msg.code == code

    await asyncio.wait_for(ws.wait_closed(), timeout=timeout_s)
    assert ws.close_code == close_code
    return msg
