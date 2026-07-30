"""E2E tests: IDB round-trip (create .i64 from binary, reopen, verify state)."""

import pytest

from tests.e2e.conftest import IdalibInstance

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

SESSION_ID = "e2e-idb-roundtrip"


class TestIdbRoundTrip:
    """Verify that functions and strings survive a save/reopen cycle."""

    async def test_idb_exists(self, shared_idalib_idb: IdalibInstance) -> None:
        assert shared_idalib_idb.out_idb.exists()
        assert shared_idalib_idb.out_idb.suffix == ".i64"

    async def test_function_names_preserved(self, shared_idalib_idb: IdalibInstance) -> None:
        code = """\
import idautils, idc
_result_ = [idc.get_func_name(ea) for ea in idautils.Functions()]
"""
        async with shared_idalib_idb.agent_client() as agent:
            resp = await agent.exec(shared_idalib_idb.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            names = resp.result
            assert isinstance(names, list)
            for expected in ("_add", "_multiply", "_get_greeting", "_compute", "_main"):
                assert expected in names, f"{expected} not found after IDB reopen: {names}"

    async def test_function_count_preserved(self, shared_idalib_idb: IdalibInstance) -> None:
        code = "import idautils; _result_ = len(list(idautils.Functions()))"
        async with shared_idalib_idb.agent_client() as agent:
            resp = await agent.exec(shared_idalib_idb.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert isinstance(resp.result, int)
            assert resp.result >= 5

    async def test_strings_preserved(self, shared_idalib_idb: IdalibInstance) -> None:
        code = """\
import idautils
_result_ = [str(s) for s in idautils.Strings()]
"""
        async with shared_idalib_idb.agent_client() as agent:
            resp = await agent.exec(shared_idalib_idb.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            strings = resp.result
            assert isinstance(strings, list)
            assert any("hello from ida-bridge test binary" in s for s in strings)

    async def test_entry_point_preserved(self, shared_idalib_idb: IdalibInstance) -> None:
        code = "import idc; _result_ = idc.get_inf_attr(idc.INF_START_IP)"
        async with shared_idalib_idb.agent_client() as agent:
            resp = await agent.exec(shared_idalib_idb.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert isinstance(resp.result, int)
            assert resp.result > 0

    async def test_metadata_shows_idb_path(self, shared_idalib_idb: IdalibInstance) -> None:
        from ida_bridge import protocol

        async with shared_idalib_idb.agent_client() as agent:
            resp = await agent.list(kind=protocol.LIST_KIND_IDA)
            assert resp.ok
            match = [c for c in resp.clients if c.client_id == shared_idalib_idb.client_id]
            assert len(match) == 1
            meta = match[0].meta or {}
            assert meta.get("idb_path", "").endswith(".i64")
