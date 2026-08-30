"""Unit tests for server start/stop readiness reporting."""

import argparse
from pathlib import Path
from typing import Any

import pytest

from ida_bridge import cli_server


class _FakeChild:
    """Stands in for the spawned server process: alive until *exits_after* polls."""

    def __init__(self, exits_after: int | None = None) -> None:
        self._polls = 0
        self._exits_after = exits_after

    def poll(self) -> int | None:
        self._polls += 1
        if self._exits_after is not None and self._polls > self._exits_after:
            return 1
        return None


def _pids(monkeypatch: pytest.MonkeyPatch, sequence: list[Any]) -> None:
    """get_server_pid() returns each element of *sequence* in turn, then repeats the last."""
    remaining = list(sequence)

    def fake() -> Any:
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    monkeypatch.setattr(cli_server, "get_server_pid", fake)


def _spawns(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, child: _FakeChild) -> None:
    monkeypatch.setattr(cli_server, "LOG_FILE", tmp_path / "server.log")
    monkeypatch.setattr(cli_server, "OUT_FILE", tmp_path / "server.out")
    monkeypatch.setattr(cli_server.subprocess, "Popen", lambda *a, **kw: child)


class TestCmdStart:
    def test_reports_success_when_the_listener_is_slow_to_bind(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Binding slower than one check is a successful start, not a failure."""
        _pids(monkeypatch, [None, None, 4242])
        _spawns(monkeypatch, tmp_path, _FakeChild())

        assert cli_server.cmd_start(argparse.Namespace()) == 0
        assert "Server started (PID: 4242)" in capsys.readouterr().out

    def test_reports_failure_when_the_child_exits(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A server that dies on boot is reported at once, not at the deadline."""
        _pids(monkeypatch, [None])
        _spawns(monkeypatch, tmp_path, _FakeChild(exits_after=1))

        assert cli_server.cmd_start(argparse.Namespace()) == 1
        assert "Failed to start" in capsys.readouterr().out


class TestCmdStop:
    def test_tolerates_a_stale_listener_entry(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OS tables list the dead pid briefly after exit; that is not a failed stop."""
        _pids(monkeypatch, [4242, 4242, None])
        monkeypatch.setattr(cli_server.proc, "terminate_pid", lambda *a, **kw: "sigterm")

        assert cli_server.cmd_stop(argparse.Namespace()) == 0
        assert "Server stopped" in capsys.readouterr().out

    def test_reports_failure_when_the_port_stays_held(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _pids(monkeypatch, [4242])
        monkeypatch.setattr(cli_server.proc, "terminate_pid", lambda *a, **kw: "sigkill")
        monkeypatch.setattr(cli_server, "_READY_TIMEOUT_S", 0.15)

        assert cli_server.cmd_stop(argparse.Namespace()) == 1
        assert "Server did not stop" in capsys.readouterr().out
