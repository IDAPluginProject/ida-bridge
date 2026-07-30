import asyncio

from websockets.exceptions import ConnectionClosedOK
from websockets.frames import Close

from ida_bridge import protocol
from tests.harness import ServeBridge, connect_client, connected_client, recv_msg, send_msg


async def test_forward_to_ida_send_failure_results_in_target_disconnected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(default_timeout_s=1, timeout_tick_s=0.01) as (server, url):
        ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            orig_send = server._send

            async def failing_send(ws, msg):
                # Simulate a disconnect right when the bridge attempts to forward
                # the request to IDA.
                if isinstance(msg, protocol.ExecRequest) and msg.dst == "ida-1":
                    await ws.close(code=1001, reason="test disconnect")
                    raise ConnectionClosedOK(Close(1001, "test"), Close(1001, "test"), True)
                await orig_send(ws, msg)

            server._send = failing_send

            try:
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

                resp = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
                assert isinstance(resp, protocol.ExecResponse)
                assert resp.ok is False
                assert resp.code == protocol.ERR_TARGET_DISCONNECTED
                assert resp.src == server.bridge_id
                assert resp.dst == "agent-1"
                assert resp.id == req_id

                # The IDA websocket should be closed by the server.
                await asyncio.wait_for(ida.wait_closed(), timeout=1.0)

            finally:
                # Restore to avoid cross-test leakage.
                server._send = orig_send
