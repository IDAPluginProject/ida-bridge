import asyncio

import pytest

from ida_bridge import protocol
from ida_bridge.bridge_conn import BridgeConn
from tests.harness import ServeBridge, connect_client, recv_msg, send_msg


def _make_req(req_type: str, *, req_id: str) -> protocol.RequestBase:
    if req_type == protocol.MSG_EXEC:
        return protocol.ExecRequest(
            id=req_id, src="agent-1", dst="ida-qfull", persist=True, session_id="sess-1", code="1"
        )
    if req_type == protocol.MSG_RESET:
        return protocol.ResetRequest(id=req_id, src="agent-1", dst="ida-qfull", session_id="sess-1")
    if req_type == protocol.MSG_QUIT:
        return protocol.QuitRequest(id=req_id, src="agent-1", dst="ida-qfull")
    raise AssertionError(f"unexpected req_type: {req_type}")


def _expect_resp_type(req_type: str) -> type[protocol.ResponseBase]:
    if req_type == protocol.MSG_EXEC:
        return protocol.ExecResponse
    if req_type == protocol.MSG_RESET:
        return protocol.ResetResponse
    if req_type == protocol.MSG_QUIT:
        return protocol.QuitResponse
    raise AssertionError(f"unexpected req_type: {req_type}")


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET, protocol.MSG_QUIT])
async def test_ida_runtime_queue_full_returns_error(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge(default_timeout_s=60, timeout_tick_s=0.01) as (_, url):
        ida = BridgeConn(client_id="ida-qfull", url=url, meta={}, queue_max=1)
        ida.start()
        try:
            assert await asyncio.to_thread(ida.wait_ready, timeout_s=2.0)

            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                # First request fills the runtime inbox (we never call ida.recv()).
                await send_msg(agent, _make_req(req_type, req_id=protocol.new_req_id()))

                # Second request should be rejected by the IDA runtime with QUEUE_FULL.
                req_id2 = protocol.new_req_id()
                await send_msg(agent, _make_req(req_type, req_id=req_id2))

                resp = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
                expected_cls = _expect_resp_type(req_type)
                assert isinstance(resp, expected_cls)
                assert resp.id == req_id2
                assert resp.src == "ida-qfull"
                assert resp.dst == "agent-1"
                assert resp.ok is False
                assert resp.code == protocol.ERR_QUEUE_FULL
            finally:
                await agent.close()
        finally:
            ida.stop()
