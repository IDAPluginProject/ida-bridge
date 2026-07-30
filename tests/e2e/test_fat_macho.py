"""E2E: fat Mach-O arch selection via --arch flag.

Uses module-scoped shared fixtures (shared_idalib_fat_arm64, shared_idalib_fat_x86_64)
to avoid paying idalib startup cost per test.
"""

import pytest

from tests.e2e.conftest import IdalibInstance

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

ARM64_SESSION_ID = "e2e-fat-arm64"
X86_64_SESSION_ID = "e2e-fat-x86_64"


class TestFatMachoArm64:
    """Verify the arm64 slice was loaded correctly."""

    async def test_processor_is_arm(self, shared_idalib_fat_arm64: IdalibInstance) -> None:
        inst = shared_idalib_fat_arm64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import idautils; _result_ = idautils.GetIdbDir()",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok

        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import ida_idp; _result_ = ida_idp.get_idp_name()",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            proc_name = resp.result
            assert proc_name is not None
            assert proc_name.lower() in ("arm", "arm64"), f"expected ARM processor, got {proc_name!r}"

    async def test_has_expected_functions(self, shared_idalib_fat_arm64: IdalibInstance) -> None:
        inst = shared_idalib_fat_arm64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import idautils, idc; _result_ = [idc.get_func_name(ea) for ea in idautils.Functions()]",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            names = resp.result
            for expected in ("_add", "_multiply", "_compute", "_main"):
                assert expected in names, f"{expected} not found in {names}"

    async def test_has_expected_string(self, shared_idalib_fat_arm64: IdalibInstance) -> None:
        inst = shared_idalib_fat_arm64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import idautils; _result_ = [str(s) for s in idautils.Strings()]",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            strings = resp.result
            assert any("hello from ida-bridge test binary" in s for s in strings)

    async def test_original_file_path_preserved(self, shared_idalib_fat_arm64: IdalibInstance) -> None:
        inst = shared_idalib_fat_arm64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import ida_nalt; _result_ = ida_nalt.get_input_file_path()",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            path = resp.result
            assert "calc_fat" in path, f"expected original fat binary path, got {path!r}"

    async def test_file_type_name_shows_arm64(self, shared_idalib_fat_arm64: IdalibInstance) -> None:
        inst = shared_idalib_fat_arm64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import ida_loader; _result_ = ida_loader.get_file_type_name()",
                session_id=ARM64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            ftype = resp.result
            assert "ARM64" in ftype.upper(), f"expected ARM64 in file type, got {ftype!r}"


class TestFatMachoX86_64:
    """Verify the x86_64 slice was loaded correctly."""

    async def test_processor_is_x86(self, shared_idalib_fat_x86_64: IdalibInstance) -> None:
        inst = shared_idalib_fat_x86_64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import ida_idp; _result_ = ida_idp.get_idp_name()",
                session_id=X86_64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            proc_name = resp.result
            assert proc_name is not None
            assert proc_name.lower() in ("metapc", "pc", "x86"), f"expected x86 processor, got {proc_name!r}"

    async def test_has_expected_functions(self, shared_idalib_fat_x86_64: IdalibInstance) -> None:
        inst = shared_idalib_fat_x86_64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import idautils, idc; _result_ = [idc.get_func_name(ea) for ea in idautils.Functions()]",
                session_id=X86_64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            names = resp.result
            for expected in ("_add", "_multiply", "_compute", "_main"):
                assert expected in names, f"{expected} not found in {names}"

    async def test_has_expected_string(self, shared_idalib_fat_x86_64: IdalibInstance) -> None:
        inst = shared_idalib_fat_x86_64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import idautils; _result_ = [str(s) for s in idautils.Strings()]",
                session_id=X86_64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            strings = resp.result
            assert any("hello from ida-bridge test binary" in s for s in strings)

    async def test_file_type_name_shows_x86_64(self, shared_idalib_fat_x86_64: IdalibInstance) -> None:
        inst = shared_idalib_fat_x86_64
        async with inst.agent_client() as agent:
            resp = await agent.exec(
                inst.client_id,
                "import ida_loader; _result_ = ida_loader.get_file_type_name()",
                session_id=X86_64_SESSION_ID,
                persist=True,
            )
            assert resp.ok
            ftype = resp.result
            assert "X86_64" in ftype.upper() or "X86-64" in ftype.upper(), (
                f"expected X86_64 in file type, got {ftype!r}"
            )
