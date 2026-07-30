import asyncio

import pytest

from ida_bridge import protocol
from tests.harness import (
    ServeBridge,
    assert_no_message,
    connect_client,
    connected_client,
    get_ida_session_id,
    recv_exec_response,
    recv_reset_response,
    recv_typed,
    respond_exec_ok,
    respond_reset,
    send_exec,
    send_reset,
)

TARGET = "ida-stateful"


async def _claim_stateful(agent, ida, *, agent_id: str, session_id: str) -> protocol.ExecResponse:
    await send_exec(agent, agent_id=agent_id, target=TARGET, persist=True, session_id=session_id)
    forwarded = await recv_typed(ida, protocol.ExecRequest)
    assert forwarded.persist is True
    assert forwarded.session_id == session_id
    assert forwarded.reset_env is True
    await respond_exec_ok(ida, forwarded)
    resp = await recv_exec_response(agent)
    assert resp.ok is True
    return resp


async def test_stateless_exec_forwards_without_claiming_ownership(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await send_exec(agent, agent_id="agent-1", target=TARGET)
            forwarded = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded.persist is False
            assert forwarded.session_id is None
            assert forwarded.reset_env is True

            await respond_exec_ok(ida, forwarded)
            resp = await recv_exec_response(agent)
            assert resp.ok is True

            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )


async def test_stateful_exec_claims_and_reuses_env(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await _claim_stateful(agent, ida, agent_id="agent-1", session_id="sess-1")
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET)
                == "sess-1"
            )

            await send_exec(agent, agent_id="agent-1", target=TARGET, persist=True, session_id="sess-1")
            forwarded = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded.persist is True
            assert forwarded.session_id == "sess-1"
            assert forwarded.reset_env is False


async def test_stateful_owner_blocks_stateless_exec(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_exec(agent2, agent_id="agent-2", target=TARGET)
            resp = await recv_exec_response(agent2)
            assert resp.ok is False
            assert resp.code == protocol.ERR_SESSION_CONFLICT
            assert resp.trace == {"target_client_id": TARGET, "current_session_id": "sess-1"}

            await assert_no_message(ida)


async def test_different_stateful_session_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_exec(agent2, agent_id="agent-2", target=TARGET, persist=True, session_id="sess-2")
            resp = await recv_exec_response(agent2)
            assert resp.ok is False
            assert resp.code == protocol.ERR_SESSION_CONFLICT
            assert resp.trace == {
                "target_client_id": TARGET,
                "current_session_id": "sess-1",
                "requested_session_id": "sess-2",
            }

            await assert_no_message(ida)


async def test_release_reset_clears_ownership_after_success(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await _claim_stateful(agent, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent, agent_id="agent-1", target=TARGET, session_id="sess-1", release=True)
            forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
            assert forwarded_reset.release is True
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )

            await send_exec(agent, agent_id="agent-1", target=TARGET, persist=True, session_id="sess-1")
            blocked_exec = await recv_exec_response(agent)
            assert blocked_exec.ok is False
            assert blocked_exec.code == protocol.ERR_RELEASE_PENDING
            assert blocked_exec.trace == {
                "target_client_id": TARGET,
                "current_session_id": "sess-1",
                "requested_session_id": "sess-1",
            }
            await assert_no_message(ida)

            await respond_reset(ida, forwarded_reset, ok=True)
            reset_resp = await recv_reset_response(agent)
            assert reset_resp.ok is True
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )

            await send_exec(agent, agent_id="agent-1", target=TARGET)
            forwarded_exec = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded_exec.reset_env is True


async def test_failed_release_reset_keeps_ownership(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent1, agent_id="agent-1", target=TARGET, session_id="sess-1", release=True)
            forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
            await respond_reset(ida, forwarded_reset, ok=False)
            reset_resp = await recv_reset_response(agent1)
            assert reset_resp.ok is False
            assert reset_resp.code == "RESET_FAILED"
            assert (
                await get_ida_session_id(agent1, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET)
                == "sess-1"
            )

            await send_exec(agent2, agent_id="agent-2", target=TARGET)
            exec_resp = await recv_exec_response(agent2)
            assert exec_resp.ok is False
            assert exec_resp.code == protocol.ERR_SESSION_CONFLICT

            await assert_no_message(ida)


async def test_release_reset_timeout_locks_ownership(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(default_timeout_s=0.05, timeout_tick_s=0.01) as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await _claim_stateful(agent, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent, agent_id="agent-1", target=TARGET, session_id="sess-1", release=True)
            forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
            assert forwarded_reset.release is True

            reset_resp = await recv_reset_response(agent)
            assert reset_resp.ok is False
            assert reset_resp.code == protocol.ERR_TIMEOUT

            await send_exec(agent, agent_id="agent-1", target=TARGET, persist=True, session_id="sess-1")
            exec_resp = await recv_exec_response(agent)
            assert exec_resp.ok is False
            assert exec_resp.code == protocol.ERR_SESSION_LOCKED
            assert exec_resp.trace == {
                "target_client_id": TARGET,
                "requested_session_id": "sess-1",
            }

            await assert_no_message(ida)


async def test_release_reset_survives_requesting_agent_disconnect_until_response(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida:
            agent1 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

                await send_reset(agent1, agent_id="agent-1", target=TARGET, session_id="sess-1", release=True)
                forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
                assert forwarded_reset.release is True
            finally:
                await agent1.close()

            await asyncio.sleep(0.05)
            await respond_reset(ida, forwarded_reset, ok=True)

            async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2:
                await send_exec(agent2, agent_id="agent-2", target=TARGET)
                forwarded_exec = await recv_typed(ida, protocol.ExecRequest)
                assert forwarded_exec.persist is False
                assert forwarded_exec.session_id is None
                assert forwarded_exec.reset_env is True


async def test_wrong_session_release_reset_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent2, agent_id="agent-2", target=TARGET, session_id="sess-2", release=True)
            reset_resp = await recv_reset_response(agent2)
            assert reset_resp.ok is False
            assert reset_resp.code == protocol.ERR_SESSION_CONFLICT
            assert reset_resp.trace == {
                "target_client_id": TARGET,
                "current_session_id": "sess-1",
                "requested_session_id": "sess-2",
            }
            assert (
                await get_ida_session_id(agent1, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET)
                == "sess-1"
            )

            await assert_no_message(ida)


async def test_takeover_reset_transfers_owner_and_next_exec_reuses_env(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent2, agent_id="agent-2", target=TARGET, session_id="sess-2", takeover=True)
            forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
            assert forwarded_reset.takeover is True
            await respond_reset(ida, forwarded_reset, ok=True)
            takeover_resp = await recv_reset_response(agent2)
            assert takeover_resp.ok is True

            await send_exec(agent2, agent_id="agent-2", target=TARGET, persist=True, session_id="sess-2")
            forwarded_exec = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded_exec.reset_env is False


async def test_stateless_exec_is_rejected_while_takeover_is_pending(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")

            await send_reset(agent2, agent_id="agent-2", target=TARGET, session_id="sess-2", takeover=True)
            forwarded_takeover = await recv_typed(ida, protocol.ResetRequest)
            assert forwarded_takeover.takeover is True

            await send_exec(agent1, agent_id="agent-1", target=TARGET)
            exec_resp = await recv_exec_response(agent1)
            assert exec_resp.ok is False
            assert exec_resp.code == protocol.ERR_TAKEOVER_PENDING
            assert exec_resp.trace == {"target_client_id": TARGET}

            await assert_no_message(ida)


@pytest.mark.parametrize("refresh_request", ["exec", "reset"])
async def test_stateful_request_refreshes_ttl(serve_bridge: ServeBridge, refresh_request: str) -> None:
    async with serve_bridge(stateful_ttl_s=0.4, timeout_tick_s=0.02) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await _claim_stateful(agent, ida, agent_id="agent-1", session_id="sess-1")
            await asyncio.sleep(0.25)

            if refresh_request == "exec":
                await send_exec(agent, agent_id="agent-1", target=TARGET, persist=True, session_id="sess-1")
                forwarded_exec = await recv_typed(ida, protocol.ExecRequest)
                assert forwarded_exec.reset_env is False
                await respond_exec_ok(ida, forwarded_exec)
                exec_resp = await recv_exec_response(agent)
                assert exec_resp.ok is True
            elif refresh_request == "reset":
                await send_reset(agent, agent_id="agent-1", target=TARGET, session_id="sess-1")
                forwarded_reset = await recv_typed(ida, protocol.ResetRequest)
                assert forwarded_reset.release is False
                assert forwarded_reset.takeover is False
                await respond_reset(ida, forwarded_reset, ok=True)
                reset_resp = await recv_reset_response(agent)
                assert reset_resp.ok is True
            else:
                raise AssertionError(f"unexpected refresh request: {refresh_request}")

            await asyncio.sleep(0.25)
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET)
                == "sess-1"
            )

            await asyncio.sleep(0.25)
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )


async def test_same_session_after_ttl_expiry_resets_env(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(stateful_ttl_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            await _claim_stateful(agent, ida, agent_id="agent-1", session_id="sess-1")
            await asyncio.sleep(0.1)
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )

            await send_exec(agent, agent_id="agent-1", target=TARGET, persist=True, session_id="sess-1")
            forwarded_exec = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded_exec.persist is True
            assert forwarded_exec.session_id == "sess-1"
            assert forwarded_exec.reset_env is True
            await respond_exec_ok(ida, forwarded_exec)
            exec_resp = await recv_exec_response(agent)
            assert exec_resp.ok is True
            assert (
                await get_ida_session_id(agent, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET)
                == "sess-1"
            )


async def test_stateful_ttl_expiry_clears_owner_and_resets_next_exec(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(stateful_ttl_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id=TARGET) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            await _claim_stateful(agent1, ida, agent_id="agent-1", session_id="sess-1")
            await asyncio.sleep(0.1)
            assert (
                await get_ida_session_id(agent1, agent_id="agent-1", bridge_id=server.bridge_id, target=TARGET) is None
            )

            await send_exec(agent2, agent_id="agent-2", target=TARGET, persist=True, session_id="sess-2")
            forwarded_stateful = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded_stateful.session_id == "sess-2"
            assert forwarded_stateful.reset_env is True
            await respond_exec_ok(ida, forwarded_stateful)
            stateful_resp = await recv_exec_response(agent2)
            assert stateful_resp.ok is True
            assert (
                await get_ida_session_id(agent2, agent_id="agent-2", bridge_id=server.bridge_id, target=TARGET)
                == "sess-2"
            )

            await asyncio.sleep(0.1)
            assert (
                await get_ida_session_id(agent2, agent_id="agent-2", bridge_id=server.bridge_id, target=TARGET) is None
            )

            await send_exec(agent1, agent_id="agent-1", target=TARGET)
            forwarded_stateless = await recv_typed(ida, protocol.ExecRequest)
            assert forwarded_stateless.persist is False
            assert forwarded_stateless.session_id is None
            assert forwarded_stateless.reset_env is True
            await respond_exec_ok(ida, forwarded_stateless)
            stateless_resp = await recv_exec_response(agent1)
            assert stateless_resp.ok is True
