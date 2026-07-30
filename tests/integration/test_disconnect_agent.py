import asyncio

import pytest

from ida_bridge import protocol
from tests.harness import ServeBridge, connect_client, connected_client, recv_msg, send_msg


async def test_agent_disconnect_drops_pending_and_late_response_is_dropped(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(default_timeout_s=1, timeout_tick_s=0.01) as (_, url):
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")

            req_id = protocol.new_req_id()
            req = protocol.ExecRequest(
                id=req_id,
                src="agent-1",
                dst="ida-1",
                persist=True,
                session_id="sess-1",
                code="1 + 1",
            )
            await send_msg(agent, req)

            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req

            # Agent disconnects while request is in-flight.
            await agent.close()

            # IDA sends the response anyway. Bridge should drop it (agent gone) without
            # penalizing IDA.
            await send_msg(
                ida,
                protocol.ExecResponse(
                    id=req_id,
                    src="ida-1",
                    dst="agent-1",
                    ok=True,
                    result=2,
                ),
            )

            # Bridge should not close IDA connection.
            pong = await ida.ping()
            await asyncio.wait_for(pong, timeout=1.0)

            # And it should not send any message to IDA.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(ida), timeout=0.1)
