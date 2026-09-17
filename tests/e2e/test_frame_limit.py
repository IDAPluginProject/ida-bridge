"""A reply that does not fit the websocket frame must not cost us the instance.

The cap is lowered for this module so an ordinary payload exceeds it; the alternative is
building a 64 MiB result, which costs a minute and a lot of memory to prove the same thing.
"""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from ida_bridge import protocol
from tests.e2e.conftest import IdalibInstance
from tests.e2e.helpers import BridgeInfo, spawn_idalib, start_bridge, terminate_idalib, wait_for_idalib

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

FRAME_LIMIT = protocol.MIN_WS_MAX_SIZE


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def small_frame_idalib(
    _module_binary: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> AsyncIterator[IdalibInstance]:
    """Bridge and runner that both cap frames at the protocol minimum."""
    mp = pytest.MonkeyPatch()
    mp.setenv("IDA_BRIDGE_WS_MAX_SIZE", str(FRAME_LIMIT))
    try:
        bridge: BridgeInfo
        async for bridge in start_bridge():
            work_dir = tmp_path_factory.mktemp("small-frame")
            proc, out_idb = spawn_idalib(bridge, work_dir, binary_path=_module_binary)
            try:
                ready = await wait_for_idalib(bridge, proc, idb_path=out_idb)
                yield IdalibInstance(
                    client_id=ready.client_id,
                    pid=ready.pid,
                    process=proc,
                    out_idb=out_idb,
                    bridge=bridge,
                    agent_url=bridge.url,
                )
            finally:
                terminate_idalib(proc)
    finally:
        mp.undo()


async def test_oversized_reply_errors_and_instance_survives(small_frame_idalib: IdalibInstance) -> None:
    async with small_frame_idalib.agent_client() as agent:
        resp = await agent.exec(small_frame_idalib.client_id, f"_result_ = 'z' * {FRAME_LIMIT * 4}")
        assert not resp.ok
        assert resp.code == protocol.ERR_RESPONSE_TOO_LARGE
        assert resp.message and str(FRAME_LIMIT) in resp.message

        after = await agent.exec(small_frame_idalib.client_id, "_result_ = 42")
        assert after.ok
        assert after.result == 42
