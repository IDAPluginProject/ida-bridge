import asyncio

import websockets
from websockets.frames import Frame, Opcode

from ida_bridge import protocol
from tests.harness import ServeBridge, connected_client, recv_msg, send_msg


async def test_ping_timeout_produces_target_ping_timeout_error(serve_bridge: ServeBridge) -> None:
    """When IDA's pong is never received, the agent gets ERR_TARGET_PING_TIMEOUT."""
    async with serve_bridge(
        default_timeout_s=30,
        timeout_tick_s=0.01,
        # Fast ping cycle so the test completes quickly.
        ping_interval=0.5,
        ping_timeout=1,
    ) as (_, url):
        # Connect IDA with pong responses suppressed.
        ida = await websockets.connect(url, ping_interval=None)
        await send_msg(ida, protocol.Hello(role=protocol.ROLE_IDA, client_id="ida-1", meta={}))
        ack = await recv_msg(ida)
        assert isinstance(ack, protocol.HelloAck)

        # Suppress auto-pong: the protocol's ping handler calls
        # send_frame(Frame(OP_PONG, ...)) directly.  Intercept it.
        orig_send_frame = ida.protocol.send_frame

        def send_frame_drop_pong(frame: Frame) -> None:
            if frame.opcode is Opcode.PONG:
                return
            orig_send_frame(frame)

        ida.protocol.send_frame = send_frame_drop_pong  # type: ignore[assignment]

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
                    code="1 + 1",
                ),
            )

            # The request is forwarded to IDA but we never respond.
            # Wait for the ping timeout to close IDA's connection and
            # propagate as ERR_TARGET_PING_TIMEOUT to the agent.
            resp = await asyncio.wait_for(recv_msg(agent), timeout=10.0)
            assert isinstance(resp, protocol.ExecResponse)
            assert resp.ok is False
            assert resp.code == protocol.ERR_TARGET_PING_TIMEOUT
            assert resp.id == req_id
