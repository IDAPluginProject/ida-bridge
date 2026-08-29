"""E2E: idalib_runner.py overwrite/lock-safety validation.

Drives the runner script directly rather than through ``ida-bridge exec-idb``, so
assertions read the runner's stderr instead of the CLI's log-file indirection.
"""

import asyncio
from pathlib import Path
import sys

import pytest

from ida_bridge.agent_client import open_agent_client
from tests.e2e.helpers import (
    BridgeInfo,
    run_idalib_runner_to_exit,
    shutdown_and_save,
    spawn_idalib,
    terminate_idalib,
    wait_for_idalib,
)

pytestmark = [pytest.mark.asyncio(loop_scope="function")]

_COMPANION_SUFFIXES = (".id0", ".id1", ".nam")


class TestIdalibRunnerOverwriteSafety:
    async def test_stale_full_idb_overwrite(
        self, live_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
    ) -> None:
        # Produce a stale target: a real packed .i64, cleanly closed and no longer
        # open (save+quit) -- distinct from the live-session and companions-only cases.
        proc, target = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        client_id = (await wait_for_idalib(live_bridge, proc, idb_path=target)).client_id
        await shutdown_and_save(live_bridge, client_id, proc)
        assert target.exists(), "expected a packed .i64 after save+quit"
        before = target.read_bytes()

        # Without --force: refused, target untouched.
        result = await asyncio.to_thread(
            run_idalib_runner_to_exit,
            live_bridge,
            input_file=small_macho_arm64,
            out_idb=target,
        )
        assert result.returncode == 2, f"expected refusal, got: {result.stdout}\n{result.stderr}"
        assert "refusing to overwrite existing out-idb (use --force)" in result.stderr
        assert target.read_bytes() == before, "target was modified despite refusal"

        # With --force: succeeds (reaches ready state; content is fully rebuilt).
        proc2, target2 = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        assert target2 == target
        try:
            await wait_for_idalib(live_bridge, proc2, idb_path=target2)
        finally:
            terminate_idalib(proc2)

    @pytest.mark.parametrize("attack", ["force_overwrite", "idb_open"])
    async def test_live_session_overwrite_refused(
        self,
        live_bridge: BridgeInfo,
        small_macho_arm64: Path,
        tmp_path: Path,
        attack: str,
    ) -> None:
        """Attacking a target another idalib session currently has open must be
        refused (never silently orphan the live session's data), and the live
        session must remain alive and functional afterward.

        force_overwrite's victim is a live --input build (packed file never hits
        disk until an explicit save -- only companions exist, which is what the
        --force/--out-idb path checks). idb_open's victim must instead be a real
        pre-existing packed .i64 reopened via --idb, since --idb's own early
        validation requires the literal path to already exist on disk.
        """
        if attack == "force_overwrite":
            proc, target = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        else:
            setup_proc, target = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
            setup_client_id = (await wait_for_idalib(live_bridge, setup_proc, idb_path=target)).client_id
            await shutdown_and_save(live_bridge, setup_client_id, setup_proc)
            proc, _ = spawn_idalib(live_bridge, tmp_path, idb_path=target)

        try:
            client_id = (await wait_for_idalib(live_bridge, proc, idb_path=target)).client_id

            if attack == "force_overwrite":
                result = await asyncio.to_thread(
                    run_idalib_runner_to_exit,
                    live_bridge,
                    input_file=small_macho_arm64,
                    out_idb=target,
                    force=True,
                )
            else:
                result = await asyncio.to_thread(run_idalib_runner_to_exit, live_bridge, idb=target)

            assert result.returncode == 2, f"expected refusal, got: {result.stdout}\n{result.stderr}"
            assert "is held by another process" in result.stderr
            assert "ida-bridge list" in result.stderr

            # Victim session must still be alive and functional.
            assert proc.poll() is None, "victim process died during the attack"
            async with open_agent_client(client_id="e2e-attack-check", url=live_bridge.url) as agent:
                resp = await agent.exec(
                    client_id,
                    "import idautils; _result_ = len(list(idautils.Functions()))",
                    session_id="e2e-attack-check",
                    persist=True,
                )
                assert resp.ok, f"victim session unresponsive after attack: {resp.message}"
                assert resp.result > 0
        finally:
            terminate_idalib(proc)

    @pytest.mark.skipif(sys.platform != "win32", reason="POSIX unlinks files that are open")
    async def test_held_packed_idb_overwrite_refused(
        self, live_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
    ) -> None:
        """A packed .i64 held open by any process is undeletable on Windows while
        staying readable, so the lock probe misses it. The unlink must still be
        reported as a refusal, not raised as an unlink traceback."""
        proc, target = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        client_id = (await wait_for_idalib(live_bridge, proc, idb_path=target)).client_id
        await shutdown_and_save(live_bridge, client_id, proc)
        assert target.exists(), "expected a packed .i64 after save+quit"

        with target.open("rb"):
            result = await asyncio.to_thread(
                run_idalib_runner_to_exit,
                live_bridge,
                input_file=small_macho_arm64,
                out_idb=target,
                force=True,
            )

        assert result.returncode == 2, f"expected refusal, got: {result.stdout}\n{result.stderr}"
        assert "is held by another process" in result.stderr
        assert "ida-bridge list" in result.stderr
        assert target.exists(), "held target must survive the refused overwrite"

    async def test_companions_only_leftover_overwrite(
        self, live_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
    ) -> None:
        """A build killed before its pack-on-close step leaves unpacked companions
        with no packed .i64 at all -- the overwrite gate must catch that state, not
        only a packed file."""
        proc, target = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        await wait_for_idalib(live_bridge, proc, idb_path=target)
        # Kill (not graceful terminate): close_database() is only reached via the
        # request loop exiting, which we're bypassing entirely -- so this
        # deterministically leaves companions with no packed file, regardless of
        # timing (no race to get right).
        proc.kill()
        proc.wait(timeout=10)

        assert not target.exists(), "packed .i64 should not exist yet"
        companions = [target.with_suffix(s) for s in _COMPANION_SUFFIXES]
        assert all(c.exists() for c in companions), f"expected leftover companions: {companions}"

        # Without --force: refused.
        result = await asyncio.to_thread(
            run_idalib_runner_to_exit,
            live_bridge,
            input_file=small_macho_arm64,
            out_idb=target,
        )
        assert result.returncode == 2, f"expected refusal, got: {result.stdout}\n{result.stderr}"
        assert "refusing to overwrite existing out-idb (use --force)" in result.stderr

        # With --force: succeeds.
        proc2, target2 = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)
        assert target2 == target
        try:
            await wait_for_idalib(live_bridge, proc2, idb_path=target2)
        finally:
            terminate_idalib(proc2)
