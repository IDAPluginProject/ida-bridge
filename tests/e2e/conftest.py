"""E2E test fixtures: real bridge server + idalib runner.

Provides several fixture scopes:

- shared_idalib (module-scoped): one bridge + one idalib runner for the entire
  test module.  Non-destructive tests use this to avoid paying the idalib startup
  cost (~seconds for auto-analysis) per test.

- idalib_instance (function-scoped): a fresh bridge + runner per test.
  Use for destructive tests (e.g. shutdown) that kill the process.

- generic_idalib (module-scoped, parametrized): one bridge + idalib per IDB
  in the selected fixture set. Generic SQL tests run against that fixture bank.

- generic_idalib_w (module-scoped, parametrized): same, but on temp copies
  for write tests.
"""

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

import pytest
import pytest_asyncio

from ida_bridge.agent_client import open_agent_client
from tests.e2e.helpers import (
    IDALIB_VENV_PYTHON,
    REPO_SRC,
    BridgeInfo,
    SqlRunner,
    shutdown_and_save,
    spawn_idalib,
    start_bridge,
    terminate_idalib,
    wait_for_idalib,
)
from tests.fixtures.build import FAT_MACHO, SMALL_MACHO_ARM64, bin_path
from tests.fixtures.idb_discovery import IdbFixture

# ---------------------------------------------------------------------------
# Runner code under test
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def idalib_runs_this_checkout() -> Iterator[None]:
    """Point headless runners at this checkout, and prove that they land there.

    The idalib venv has its own ``ida_bridge`` install, which is what a spawned runner
    imports by default. When that is not this checkout -- typically because tests run from a
    second worktree or clone -- an e2e run exercises the other tree and a green result says
    nothing about the code under test. PYTHONPATH on the session's environment reaches both
    directly spawned runners and the ones the CLI spawns.

    UI IDA is not covered: ``supervisor._clean_env`` drops PYTHONPATH on purpose, so a UI
    instance always runs the venv's installed copy.
    """
    with pytest.MonkeyPatch.context() as mp:
        # An empty entry in PYTHONPATH means the cwd, so drop the inherited value when unset.
        inherited = os.environ.get("PYTHONPATH", "")
        entries = [str(REPO_SRC), inherited] if inherited else [str(REPO_SRC)]
        mp.setenv("PYTHONPATH", os.pathsep.join(entries))

        # -P keeps the cwd off sys.path, as it is for the runner's own script-mode launch.
        probe = subprocess.run(
            [str(IDALIB_VENV_PYTHON), "-P", "-c", "import ida_bridge; print(ida_bridge.__file__)"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if probe.returncode != 0:
            pytest.fail(f"idalib venv cannot import ida_bridge:\n{probe.stderr.strip()}")

        resolved = Path(probe.stdout.strip()).resolve()
        if REPO_SRC not in resolved.parents:
            pytest.fail(
                f"idalib runner would import ida_bridge from {resolved}, not {REPO_SRC};\n"
                "e2e results would describe a different checkout."
            )

        yield


# ---------------------------------------------------------------------------
# Bridge server fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def live_bridge() -> AsyncIterator[BridgeInfo]:
    """Function-scoped bridge server on an ephemeral port."""
    async for info in start_bridge():
        yield info


# ---------------------------------------------------------------------------
# Binary fixtures (compiled by tests/fixtures/build.py)
# ---------------------------------------------------------------------------


def _bin(name: str) -> Path:
    p = bin_path(name)
    if not p.is_file():
        pytest.skip(f"missing fixture binary {name!r}; run tests/fixtures/build.py")
    return p


@pytest.fixture
def small_macho_arm64() -> Path:
    """The small arm64 Mach-O test binary."""
    return _bin(SMALL_MACHO_ARM64)


@pytest.fixture
def fat_macho() -> Path:
    """The fat (universal) Mach-O test binary."""
    return _bin(FAT_MACHO)


# ---------------------------------------------------------------------------
# idalib instance — shared helpers
# ---------------------------------------------------------------------------


@dataclass
class IdalibInstance:
    client_id: str
    pid: int
    process: subprocess.Popen[bytes]
    out_idb: Path
    bridge: BridgeInfo
    agent_url: str

    def agent_client(self, client_id: str = "e2e-agent") -> Any:
        """Return an ``open_agent_client`` context manager pointed at our bridge."""
        return open_agent_client(client_id=client_id, url=self.agent_url)


# ---------------------------------------------------------------------------
# idalib instance — function-scoped (for destructive tests)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def idalib_instance(
    live_bridge: BridgeInfo,
    small_macho_arm64: Path,
    tmp_path: Path,
) -> AsyncIterator[IdalibInstance]:
    """Fresh idalib runner per test. Use for destructive tests (e.g. shutdown)."""
    proc, out_idb = spawn_idalib(live_bridge, tmp_path, binary_path=small_macho_arm64)

    try:
        ready = await wait_for_idalib(live_bridge, proc, idb_path=out_idb)
        yield IdalibInstance(
            client_id=ready.client_id,
            pid=ready.pid,
            process=proc,
            out_idb=out_idb,
            bridge=live_bridge,
            agent_url=live_bridge.url,
        )
    finally:
        terminate_idalib(proc)


# ---------------------------------------------------------------------------
# idalib instance — module-scoped (shared across non-destructive tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _module_tmp_dir() -> Path:
    """Module-scoped temp directory (pytest's tmp_path is function-scoped)."""
    d = Path(tempfile.mkdtemp(prefix="ida_bridge_e2e_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def _module_binary() -> Path:
    """Module-scoped test binary."""
    return _bin(SMALL_MACHO_ARM64)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_idalib(
    _module_tmp_dir: Path,
    _module_binary: Path,
) -> AsyncIterator[IdalibInstance]:
    """Single bridge + idalib runner shared by all non-destructive tests in a module."""
    async for bridge in start_bridge():
        proc, out_idb = spawn_idalib(bridge, _module_tmp_dir, binary_path=_module_binary)
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


# ---------------------------------------------------------------------------
# Fat Mach-O fixtures (module-scoped)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _module_fat_binary() -> Path:
    """Module-scoped fat Mach-O test binary."""
    return _bin(FAT_MACHO)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_idalib_fat_arm64(
    _module_tmp_dir: Path,
    _module_fat_binary: Path,
) -> AsyncIterator[IdalibInstance]:
    """Bridge + idalib loading the arm64 slice of a fat Mach-O."""
    work_dir = _module_tmp_dir / "fat_arm64"
    work_dir.mkdir(exist_ok=True)
    async for bridge in start_bridge():
        proc, out_idb = spawn_idalib(bridge, work_dir, binary_path=_module_fat_binary, arch="arm64")
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


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_idalib_fat_x86_64(
    _module_tmp_dir: Path,
    _module_fat_binary: Path,
) -> AsyncIterator[IdalibInstance]:
    """Bridge + idalib loading the x86_64 slice of a fat Mach-O."""
    work_dir = _module_tmp_dir / "fat_x86_64"
    work_dir.mkdir(exist_ok=True)
    async for bridge in start_bridge():
        proc, out_idb = spawn_idalib(bridge, work_dir, binary_path=_module_fat_binary, arch="x86_64")
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


# ---------------------------------------------------------------------------
# IDB round-trip fixture (module-scoped)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_idalib_idb(
    _module_tmp_dir: Path,
    _module_binary: Path,
) -> AsyncIterator[IdalibInstance]:
    """Create an .i64 from the test binary, then reopen it via --idb.

    Phase 1: analyze binary -> save IDB -> exit.
    Phase 2: open saved IDB -> yield instance for tests.
    """
    # Phase 1: create the .i64.
    async for bridge1 in start_bridge():
        proc1, idb_path = spawn_idalib(bridge1, _module_tmp_dir, binary_path=_module_binary)
        try:
            ready1 = await wait_for_idalib(bridge1, proc1, idb_path=idb_path)
            await shutdown_and_save(bridge1, ready1.client_id, proc1)
        except BaseException:
            terminate_idalib(proc1)
            raise

    if not idb_path.exists():
        pytest.fail(f"IDB was not created: {idb_path}")

    # Phase 2: reopen the saved .i64.
    async for bridge2 in start_bridge():
        proc2, _ = spawn_idalib(bridge2, _module_tmp_dir, idb_path=idb_path)
        try:
            ready2 = await wait_for_idalib(bridge2, proc2, idb_path=idb_path)
            yield IdalibInstance(
                client_id=ready2.client_id,
                pid=ready2.pid,
                process=proc2,
                out_idb=idb_path,
                bridge=bridge2,
                agent_url=bridge2.url,
            )
        finally:
            terminate_idalib(proc2)


# ---------------------------------------------------------------------------
# Generic IDB fixtures (parametrized over discovered fixtures)
# ---------------------------------------------------------------------------


@dataclass
class GenericIdalib:
    runner: SqlRunner
    fixture: IdbFixture


async def require_imports(gi: GenericIdalib) -> None:
    """Skip the current test if the fixture IDB has no imports."""
    r = await gi.runner.sql("SELECT count(*) AS cnt FROM imports")
    if r["rows"][0]["cnt"] == 0:
        pytest.skip(f"fixture {gi.fixture.name!r} has no imports")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def generic_idalib(idb_fixture: IdbFixture) -> AsyncIterator[GenericIdalib]:
    """Module-scoped read-only runner for each selected IDB fixture."""
    tmp_dir = Path(tempfile.mkdtemp(prefix=f"ida_bridge_generic_{idb_fixture.name}_"))
    idb_copy = tmp_dir / f"{idb_fixture.name}-read.i64"
    shutil.copy2(idb_fixture.path, idb_copy)
    try:
        async for bridge in start_bridge():
            proc, _ = spawn_idalib(bridge, tmp_dir, idb_path=idb_copy)
            try:
                ready = await wait_for_idalib(bridge, proc, idb_path=idb_copy)
                agent_id = f"e2e-generic-{idb_fixture.name}"
                async with open_agent_client(client_id=agent_id, url=bridge.url) as agent:
                    yield GenericIdalib(
                        runner=SqlRunner(agent, ready.client_id, session_id=agent_id), fixture=idb_fixture
                    )
            finally:
                terminate_idalib(proc)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def generic_idalib_w(idb_fixture: IdbFixture) -> AsyncIterator[GenericIdalib]:
    """Module-scoped writable runner on a temp copy of each selected IDB fixture."""
    tmp_dir = Path(tempfile.mkdtemp(prefix=f"ida_bridge_generic_w_{idb_fixture.name}_"))
    idb_copy = tmp_dir / f"{idb_fixture.name}-write.i64"
    shutil.copy2(idb_fixture.path, idb_copy)
    try:
        async for bridge in start_bridge():
            proc, _ = spawn_idalib(bridge, tmp_dir, idb_path=idb_copy)
            try:
                ready = await wait_for_idalib(bridge, proc, idb_path=idb_copy)
                agent_id = f"e2e-generic-w-{idb_fixture.name}"
                async with open_agent_client(client_id=agent_id, url=bridge.url) as agent:
                    yield GenericIdalib(
                        runner=SqlRunner(agent, ready.client_id, session_id=agent_id), fixture=idb_fixture
                    )
            finally:
                terminate_idalib(proc)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
