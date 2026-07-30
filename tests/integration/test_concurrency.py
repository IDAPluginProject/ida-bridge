import asyncio

import pytest

from ida_bridge import protocol
from tests.harness import ServeBridge, connected_client, recv_msg, send_msg


async def test_concurrency_multiple_in_flight_out_of_order_responses(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            n = 10
            reqs: list[protocol.ExecRequest] = []
            for i in range(n):
                reqs.append(
                    protocol.ExecRequest(
                        id=protocol.new_req_id(),
                        src="agent-1",
                        dst="ida-1",
                        persist=True,
                        session_id="sess-1",
                        code=str(i),
                    )
                )

            # Send all requests without waiting for responses.
            await asyncio.gather(*(send_msg(agent, r) for r in reqs))

            # IDA should receive all forwarded requests (order is not guaranteed, but likely).
            forwarded: list[protocol.ExecRequest] = []
            for _ in range(n):
                msg = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(msg, protocol.ExecRequest)
                forwarded.append(msg)

            forwarded_ids = {m.id for m in forwarded}
            req_ids = {r.id for r in reqs}
            assert forwarded_ids == req_ids

            # Respond out-of-order (reverse). Use result=i parsed from request.code.
            for m in reversed(forwarded):
                await send_msg(
                    ida,
                    protocol.ExecResponse(
                        id=m.id,
                        src="ida-1",
                        dst="agent-1",
                        ok=True,
                        result=int(m.code),
                    ),
                )

            responses: list[protocol.ExecResponse] = []
            for _ in range(n):
                msg = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
                assert isinstance(msg, protocol.ExecResponse)
                assert msg.ok is True
                responses.append(msg)

            # Correlate by id and check each response carries the intended result.
            by_id = {r.id: r for r in responses}
            assert set(by_id.keys()) == req_ids

            expected_by_id = {r.id: int(r.code) for r in reqs}
            got_by_id = {rid: resp.result for rid, resp in by_id.items()}
            assert got_by_id == expected_by_id


async def test_concurrency_multi_client_isolation_no_crosstalk(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida1,
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-2") as ida2,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            req1 = protocol.ExecRequest(
                id=protocol.new_req_id(),
                src="agent-1",
                dst="ida-1",
                persist=True,
                session_id="sess-1",
                code="100",
            )
            req2 = protocol.ExecRequest(
                id=protocol.new_req_id(),
                src="agent-2",
                dst="ida-2",
                persist=True,
                session_id="sess-2",
                code="200",
            )

            await asyncio.gather(send_msg(agent1, req1), send_msg(agent2, req2))

            fwd1 = await asyncio.wait_for(recv_msg(ida1), timeout=1.0)
            fwd2 = await asyncio.wait_for(recv_msg(ida2), timeout=1.0)
            assert fwd1 == req1
            assert fwd2 == req2

            await asyncio.gather(
                send_msg(
                    ida1,
                    protocol.ExecResponse(
                        id=req1.id,
                        src="ida-1",
                        dst="agent-1",
                        ok=True,
                        result=101,
                    ),
                ),
                send_msg(
                    ida2,
                    protocol.ExecResponse(
                        id=req2.id,
                        src="ida-2",
                        dst="agent-2",
                        ok=True,
                        result=201,
                    ),
                ),
            )

            got1 = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            got2 = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(got1, protocol.ExecResponse)
            assert isinstance(got2, protocol.ExecResponse)

            assert got1.id == req1.id
            assert got1.dst == "agent-1"
            assert got1.src == "ida-1"
            assert got1.result == 101

            assert got2.id == req2.id
            assert got2.dst == "agent-2"
            assert got2.src == "ida-2"
            assert got2.result == 201

            # Ensure no extra cross-talk messages arrive.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(agent1), timeout=0.1)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(agent2), timeout=0.1)
