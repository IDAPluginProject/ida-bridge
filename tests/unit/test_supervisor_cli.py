import pytest

from ida_bridge.supervisor import main as supervisor_main


class TestSupervisorCliSessionId:
    def test_save_does_not_require_session_id(self) -> None:
        rc = supervisor_main(["save", "ida-1"])
        assert rc == 2

    def test_save_rejects_session_id_without_stateful(self) -> None:
        with pytest.raises(SystemExit):
            supervisor_main(["save", "ida-1", "--session-id", "sess-1"])

    def test_save_rejects_stateful_without_session_id(self) -> None:
        with pytest.raises(SystemExit):
            supervisor_main(["save", "ida-1", "--stateful"])

    def test_stop_does_not_require_session_id(self) -> None:
        # stop uses a dedicated quit RPC that bypasses session ownership.
        # Without a bridge running, it falls through to pid-based kill.
        # The important thing: no SystemExit from missing --session-id.
        rc = supervisor_main(["stop", "ida-1"])
        assert rc == 2  # no bridge, no pid -> exit 2
