"""Tests for instance-log GC: prune behavior and the server-owned sweep task."""

import asyncio
from collections.abc import Callable
import os
from pathlib import Path
import sys
import time

import pytest

from ida_bridge import logs
from ida_bridge.logs import _default_log_dir, _pid_from_instance_log, prune_instance_logs
from ida_bridge.server import BridgeServer


def _touch(path: Path, mtime: float) -> None:
    path.write_text("x", encoding="utf-8")
    os.utime(path, (mtime, mtime))


class TestDefaultLogDir:
    """Each platform gets its own convention; a new one must not inherit another's."""

    def test_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
        assert _default_log_dir() == Path(r"C:\Users\test\AppData\Local") / "ida-bridge" / "logs"

    def test_macos(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        assert _default_log_dir() == Path.home() / "Library" / "Logs" / "ida-bridge"

    def test_linux_honours_xdg_state_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("XDG_STATE_HOME", "/xdg/state")
        assert _default_log_dir() == Path("/xdg/state") / "ida-bridge" / "logs"

    def test_linux_without_xdg_state_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        assert _default_log_dir() == Path.home() / ".local" / "state" / "ida-bridge" / "logs"

    def test_unknown_platform_falls_back_to_xdg(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG is a cross-Unix convention, so it is the deliberate default, not a leftover."""
        monkeypatch.setattr(sys, "platform", "freebsd14")
        monkeypatch.setenv("XDG_STATE_HOME", "/xdg/state")
        assert _default_log_dir() == Path("/xdg/state") / "ida-bridge" / "logs"


class TestPruneInstanceLogs:
    """Dead pids use values far above typical pid_max so they are reliably not alive."""

    def test_keeps_newest_dead_per_prefix(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path))
        monkeypatch.setattr("ida_bridge.logs.LOG_KEEP", 2)
        base = time.time()
        for i, dead in enumerate([900001, 900002, 900003, 900004]):
            _touch(tmp_path / f"idaui-{dead}.log", base + i)
        prune_instance_logs()
        remaining = sorted(p.name for p in tmp_path.glob("idaui-*.log"))
        assert remaining == ["idaui-900003.log", "idaui-900004.log"]

    def test_live_logs_always_kept(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path))
        monkeypatch.setattr("ida_bridge.logs.LOG_KEEP", 1)
        base = time.time()
        live = tmp_path / f"idaui-{os.getpid()}.log"
        _touch(live, base)  # oldest
        for i, dead in enumerate([900001, 900002, 900003], start=1):
            _touch(tmp_path / f"idaui-{dead}.log", base + i)
        prune_instance_logs()
        names = {p.name for p in tmp_path.glob("idaui-*.log")}
        assert live.name in names  # live kept despite being oldest
        assert len([n for n in names if n != live.name]) == 1  # only the newest dead survives

    def test_prefixes_isolated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path))
        monkeypatch.setattr("ida_bridge.logs.LOG_KEEP", 2)
        base = time.time()
        for i in range(5):
            _touch(tmp_path / f"idalib-{900100 + i}.log", base + i)
        _touch(tmp_path / "idaui-900200.log", base)
        prune_instance_logs()
        assert (tmp_path / "idaui-900200.log").exists()  # not evicted by the idalib flood
        assert len(list(tmp_path.glob("idalib-*.log"))) == 2

    def test_no_raise_when_dir_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path / "nope"))
        prune_instance_logs()  # best-effort: must not raise

    def test_starting_placeholder_is_not_a_pid(self) -> None:
        path = Path("idalib-starting-1710000000.log")
        assert _pid_from_instance_log("idalib", path) is None
        assert _pid_from_instance_log("idalib", Path("idalib-4321.log")) == 4321

    def test_unheld_starting_logs_are_pruned(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path))
        monkeypatch.setattr("ida_bridge.logs.LOG_KEEP", 1)
        monkeypatch.setattr("ida_bridge.logs._file_held", lambda _p: False)
        base = time.time()
        _touch(tmp_path / "idalib-starting-100.log", base)
        _touch(tmp_path / "idalib-starting-200.log", base + 1)
        _touch(tmp_path / "idalib-starting-300.log", base + 2)
        prune_instance_logs()
        remaining = sorted(p.name for p in tmp_path.glob("idalib-*.log"))
        assert remaining == ["idalib-starting-300.log"]

    def test_held_starting_log_is_kept(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_BRIDGE_LOG_DIR", str(tmp_path))
        monkeypatch.setattr("ida_bridge.logs.LOG_KEEP", 1)
        held = tmp_path / "idalib-starting-100.log"
        _touch(held, time.time())
        _touch(tmp_path / "idalib-starting-200.log", time.time() + 1)
        _touch(tmp_path / "idalib-starting-300.log", time.time() + 2)
        monkeypatch.setattr("ida_bridge.logs._file_held", lambda p: p == held)
        prune_instance_logs()
        names = {p.name for p in tmp_path.glob("idalib-*.log")}
        assert held.name in names
        assert "idalib-starting-300.log" in names
        assert "idalib-starting-200.log" not in names


async def _wait_until(predicate: Callable[[], bool], *, timeout_s: float = 2.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


class TestServerPruneTask:
    """The server owns log GC: it prunes once at startup and repeatedly on a cadence."""

    async def test_prunes_at_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = 0

        def _record() -> None:
            nonlocal calls
            calls += 1

        monkeypatch.setattr(logs, "prune_instance_logs", _record)
        monkeypatch.setattr(logs, "LOG_PRUNE_INTERVAL_S", 3600.0)  # no sweep fires within the test

        server = BridgeServer(timeout_tick_s=0.5)
        server.start_background_tasks()
        try:
            assert await _wait_until(lambda: calls == 1)
            assert server._log_prune_task is not None and not server._log_prune_task.done()
        finally:
            await server.stop_background_tasks()
        assert server._log_prune_task is None

    async def test_prunes_on_cadence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = 0

        def _record() -> None:
            nonlocal calls
            calls += 1

        monkeypatch.setattr(logs, "prune_instance_logs", _record)
        monkeypatch.setattr(logs, "LOG_PRUNE_INTERVAL_S", 0.01)

        server = BridgeServer(timeout_tick_s=0.5)
        server.start_background_tasks()
        try:
            assert await _wait_until(lambda: calls >= 3)  # startup prune plus repeated sweeps
        finally:
            await server.stop_background_tasks()
