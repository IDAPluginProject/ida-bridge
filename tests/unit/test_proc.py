"""Unit tests for process lifecycle primitives."""

import os
import socket
import subprocess
import sys
import time

import pytest

from ida_bridge.proc import (
    is_pid_alive,
    is_pid_in_tree,
    listening_pid,
    parse_netstat_listening_pid,
    terminate_pid,
    wait_for_exit,
)


class TestIsPidAlive:
    @pytest.mark.skipif(sys.platform == "win32", reason="Windows does not keep POSIX zombies")
    def test_returns_false_for_zombie_child(self) -> None:
        """is_pid_alive must detect zombie (exited but un-reaped) children."""
        child = subprocess.Popen([sys.executable, "-c", ""])
        # Let child exit; don't call child.wait() so it remains a zombie.
        time.sleep(0.2)

        try:
            os.kill(child.pid, 0)
        except ProcessLookupError:
            pytest.skip("child already reaped")

        assert not is_pid_alive(child.pid)

    def test_returns_false_for_nonexistent_pid(self) -> None:
        assert not is_pid_alive(2_000_000_000)

    def test_returns_false_for_non_positive_pid(self) -> None:
        assert not is_pid_alive(0)
        assert not is_pid_alive(-1)

    def test_returns_true_for_own_process(self) -> None:
        assert is_pid_alive(os.getpid())

    def test_probe_does_not_kill_live_process(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert is_pid_alive(child.pid)
            assert child.poll() is None
        finally:
            child.kill()
            child.wait()


class TestWaitForExit:
    def test_returns_true_when_process_exits(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.1)"])
        assert wait_for_exit(child.pid, timeout_s=5.0)
        child.wait()

    def test_returns_false_on_timeout(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            assert not wait_for_exit(child.pid, timeout_s=0.2)
        finally:
            child.kill()
            child.wait()


class TestTerminatePid:
    def test_already_dead(self) -> None:
        assert terminate_pid(2_000_000_000) == "already_dead"

    def test_terminates_live_process(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            method = terminate_pid(child.pid, timeout_s=5.0)
            if sys.platform == "win32":
                assert method == "sigkill"
            else:
                assert method == "sigterm"
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


class TestParseNetstatListeningPid:
    _SAMPLE = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
  TCP    127.0.0.1:8765         0.0.0.0:0              LISTENING       4321
  TCP    127.0.0.1:18765        0.0.0.0:0              LISTENING       99
  TCP    [::]:8765              [::]:0                 LISTENING       4321
  TCP    127.0.0.1:8765         127.0.0.1:50000        ESTABLISHED     7
"""

    def test_matches_exact_port(self) -> None:
        assert parse_netstat_listening_pid(self._SAMPLE, 8765) == 4321

    def test_does_not_match_suffix_port(self) -> None:
        assert parse_netstat_listening_pid(self._SAMPLE, 765) is None

    def test_missing_port(self) -> None:
        assert parse_netstat_listening_pid(self._SAMPLE, 9) is None


class TestListeningPid:
    def test_finds_this_process(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert listening_pid(port) == os.getpid()
        finally:
            srv.close()


class TestIsPidInTree:
    def test_self_is_in_tree(self) -> None:
        pid = os.getpid()
        assert is_pid_in_tree(pid, pid)

    def test_unrelated_pid_not_in_tree(self) -> None:
        assert not is_pid_in_tree(os.getpid(), 2_000_000_000)

    @pytest.mark.skipif(sys.platform != "win32", reason="process-tree walk is Windows-only")
    def test_windows_child_is_in_tree(self) -> None:
        # Spawn a child that outlives a short parent check window.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert is_pid_in_tree(os.getpid(), child.pid)
        finally:
            child.kill()
            child.wait()

    @pytest.mark.skipif(sys.platform == "win32", reason="non-Windows is equality-only")
    def test_posix_is_equality_only(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert not is_pid_in_tree(os.getpid(), child.pid)
        finally:
            child.kill()
            child.wait()
