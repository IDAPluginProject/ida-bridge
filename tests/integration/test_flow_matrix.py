from ida_bridge import protocol
from tests.harness import (
    ServeBridge,
    connect_client,
    connected_client,
    expect_protocol_error_and_close,
    recv_msg,
    send_msg,
)


async def test_agent_may_only_send_requests(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
        # Agent sending a response is forbidden.
        await send_msg(
            agent,
            protocol.ExecResponse(
                id=protocol.new_req_id(),
                src="agent-1",
                dst="agent-1",
                ok=True,
                result=None,
            ),
        )
        await expect_protocol_error_and_close(
            agent,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )


async def test_agent_to_bridge_only_list_is_allowed(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
        await send_msg(
            agent,
            protocol.ExecRequest(
                id=protocol.new_req_id(),
                src="agent-1",
                dst=server.bridge_id,
                persist=True,
                session_id="sess-1",
                code="print('hi')",
            ),
        )
        await expect_protocol_error_and_close(
            agent,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )


async def test_agent_to_ida_only_exec_reset(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1"):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            await send_msg(
                agent,
                protocol.ListRequest(
                    id=protocol.new_req_id(),
                    src="agent-1",
                    dst="ida-1",
                    kind=protocol.LIST_KIND_ALL,
                ),
            )
            await expect_protocol_error_and_close(
                agent,
                code=protocol.ERR_UNSUPPORTED_MESSAGE,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )


async def test_ida_may_only_send_responses(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        await send_msg(
            ida,
            protocol.ExecRequest(
                id=protocol.new_req_id(),
                src="ida-1",
                dst="ida-1",
                persist=True,
                session_id="sess-1",
                code="print('hi')",
            ),
        )
        await expect_protocol_error_and_close(
            ida,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )


async def test_ida_may_not_send_messages_to_bridge(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        await send_msg(
            ida,
            protocol.ListRequest(
                id=protocol.new_req_id(),
                src="ida-1",
                dst=server.bridge_id,
                kind=protocol.LIST_KIND_ALL,
            ),
        )
        await expect_protocol_error_and_close(
            ida,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )


async def test_agent_to_connected_non_ida_dst_is_invalid_target_role(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        agent1 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2:
            await send_msg(
                agent1,
                protocol.ExecRequest(
                    id=protocol.new_req_id(),
                    src="agent-1",
                    dst="agent-2",
                    persist=True,
                    session_id="sess-1",
                    code="print('hi')",
                ),
            )
            await expect_protocol_error_and_close(
                agent1,
                code=protocol.ERR_INVALID_TARGET_ROLE,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )

            # The other agent should remain connected and usable.
            await send_msg(
                agent2,
                protocol.ListRequest(
                    id=protocol.new_req_id(),
                    src="agent-2",
                    dst="bridge",
                    kind=protocol.LIST_KIND_ALL,
                ),
            )
            resp = await recv_msg(agent2)
            assert isinstance(resp, protocol.ListResponse)
            assert resp.ok is True
