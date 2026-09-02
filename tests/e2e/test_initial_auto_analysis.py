"""E2E: initial auto-analysis wait vs --skip-initial-auto-analysis on a fresh input.

Uses ``--input`` (not a pre-analyzed IDB). Default must drive ``auto_wait()``
to completion. Skip must connect without that wait.
"""

from pathlib import Path

import pytest

from ida_bridge.agent_client import open_agent_client
from tests.e2e.helpers import (
    BridgeInfo,
    spawn_idalib,
    terminate_idalib,
    wait_for_idalib,
)

_PROBE = """\
import ida_auto
import idautils
_result_ = {
    "auto_is_ok": bool(ida_auto.auto_is_ok()),
    "nfuncs": len(list(idautils.Functions())),
}
"""


async def _probe(bridge: BridgeInfo, client_id: str) -> dict:
    async with open_agent_client(client_id="e2e-auto-analysis", url=bridge.url) as agent:
        resp = await agent.exec(client_id, _PROBE, session_id="e2e-auto-analysis")
    assert resp.ok, f"{resp.code} {resp.message}"
    assert isinstance(resp.result, dict)
    return resp.result


class TestInitialAutoAnalysis:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_default_completes_initial_analysis(
        self, live_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
    ) -> None:
        proc, out_idb = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        try:
            ready = await wait_for_idalib(live_bridge, proc, idb_path=out_idb)
            result = await _probe(live_bridge, ready.client_id)
            assert result["auto_is_ok"] is True
            assert result["nfuncs"] >= 5
        finally:
            terminate_idalib(proc)

    @pytest.mark.asyncio(loop_scope="function")
    async def test_skip_connects_without_completing_initial_analysis(
        self, live_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
    ) -> None:
        proc, out_idb = spawn_idalib(
            live_bridge, tmp_path, binary_path=small_macho_arm64, skip_initial_auto_analysis=True
        )
        try:
            ready = await wait_for_idalib(live_bridge, proc, idb_path=out_idb)
            result = await _probe(live_bridge, ready.client_id)
            assert result["auto_is_ok"] is False
        finally:
            terminate_idalib(proc)
