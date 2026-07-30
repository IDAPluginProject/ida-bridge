"""Tests for instance-log GC: prune behavior and the server-owned sweep task."""

import asyncio
from collections.abc import Callable
import os
from pathlib import Path
import time

import pytest

from ida_bridge import logs
from ida_bridge.logs import prune_instance_logs
from ida_bridge.server import BridgeServer


def _touch(path: Path, mtime: float) -> None:
    path.write_text("x", encoding="utf-8")
    os.utime(path, (mtime, mtime))


class TestPruneInstanceLogs:
    """Dead pids use values above macOS pid_max (99999) so they are reliably not alive."""

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
