import asyncio

import websockets

from ida_bridge import protocol
from tests.harness import (
    ServeBridge,
    connect_client,
    connected_client,
    expect_protocol_error_and_close,
    recv_msg,
    send_msg,
)


async def test_duplicate_request_id_is_fatal_to_agent(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")

            req_id = protocol.new_req_id()
            req = protocol.ExecRequest(
                id=req_id,
                src="agent-1",
                dst="ida-1",
                persist=True,
                session_id="sess-1",
                code="print('hi')",
            )

            # First request creates the pending entry.
            await send_msg(agent, req)
            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req

            # Second request with same id while pending => fatal.
            await send_msg(agent, req)
            await expect_protocol_error_and_close(
                agent,
                code=protocol.ERR_DUPLICATE_REQUEST_ID,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )

            # IDA connection should remain usable (bridge must not close unrelated connections).
            pong_waiter = await ida.ping()
            await asyncio.wait_for(pong_waiter, timeout=1.0)

            # Late IDA response should be dropped (no pending after agent disconnect).
            await send_msg(
                ida,
                protocol.ExecResponse(
                    id=req_id,
                    src="ida-1",
                    dst="agent-1",
                    ok=True,
                    result=None,
                ),
            )


async def test_binary_websocket_frame_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        ws = await websockets.connect(url)
        try:
            await ws.send(b"not-json")
            await expect_protocol_error_and_close(
                ws,
                code=protocol.ERR_UNSUPPORTED_FRAME,
                close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
            )
        finally:
            await ws.close()


async def test_response_mismatch_is_fatal_to_ida(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            req_id = protocol.new_req_id()
            await send_msg(
                agent,
                protocol.ExecRequest(
                    id=req_id,
                    src="agent-1",
                    dst="ida-1",
                    persist=True,
                    session_id="sess-1",
                    code="print('hi')",
                ),
            )
            _ = await recv_msg(ida)  # forwarded request

            # Wrong response type for this pending exec id => RESPONSE_MISMATCH + close.
            await send_msg(
                ida,
                protocol.ResetResponse(
                    id=req_id,
                    src="ida-1",
                    dst="agent-1",
                    ok=True,
                ),
            )

            await expect_protocol_error_and_close(
                ida,
                code=protocol.ERR_RESPONSE_MISMATCH,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )

            # Agent should still be usable.
            await send_msg(
                agent,
                protocol.ListRequest(
                    id=protocol.new_req_id(),
                    src="agent-1",
                    dst=server.bridge_id,
                    kind=protocol.LIST_KIND_ALL,
                ),
            )
            resp = await recv_msg(agent)
            assert isinstance(resp, protocol.ListResponse)
