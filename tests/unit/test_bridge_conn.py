"""Tests for BridgeConn.send serialization failure handling."""

import logging

import pytest

from ida_bridge import protocol
from ida_bridge.bridge_conn import BridgeConn
from ida_bridge.ida_runtime import RequestHandler, run_user_code


def _direct_run_code(
    code: str,
    exec_env: dict,
) -> tuple[object, str, str, Exception | None]:
    return run_user_code(code=code, exec_env=exec_env)


class _FakeWS:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, data: str) -> None:
        self.sent.append(data)


def _conn_with_fake_ws() -> tuple[BridgeConn, _FakeWS]:
    conn = BridgeConn(client_id="ida-1", url="ws://127.0.0.1:9", meta={})
    ws = _FakeWS()
    conn._ws = ws  # type: ignore[assignment]
    return conn, ws


def _surrogate_text() -> str:
    return b"PRE_abc\xff_POST".decode("utf-8", "surrogateescape")


def test_send_unserializable_response_replies_error(caplog: pytest.LogCaptureFixture) -> None:
    conn, ws = _conn_with_fake_ws()
    req_id = protocol.new_req_id()
    bad = protocol.ExecResponse(
        id=req_id,
        src="ida-1",
        dst="agent-1",
        ok=True,
        stdout=_surrogate_text(),
    )

    with caplog.at_level(logging.ERROR, logger="ida_bridge.bridge_conn"):
        conn.send(bad)

    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == req_id
    assert parsed.src == "ida-1"
    assert parsed.dst == "agent-1"
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "stdout" in parsed.message
    parsed.message.encode("utf-8")
    ws.sent[0].encode("utf-8")

    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(error_records) == 1
    assert error_records[0].exc_info is not None


def test_send_unserializable_result_names_field() -> None:
    conn, ws = _conn_with_fake_ws()
    bad = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=_surrogate_text(),
    )
    conn.send(bad)
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "result" in parsed.message


def test_send_serializable_response_unchanged() -> None:
    conn, ws = _conn_with_fake_ws()
    ok = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=1,
        stdout="hello",
    )
    conn.send(ok)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is True
    assert parsed.id == ok.id
    assert parsed.result == 1
    assert parsed.stdout == "hello"


def test_send_non_ascii_serialize_error_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, ws = _conn_with_fake_ws()
    ok = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=1,
    )
    orig = protocol.dump_message_json
    calls = {"n": 0}

    def dump(msg: protocol.Message) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("café")
        return orig(msg)

    monkeypatch.setattr("ida_bridge.bridge_conn.protocol.dump_message_json", dump)
    conn.send(ok)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == ok.id
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    parsed.message.encode("ascii")
    ws.sent[0].encode("utf-8")


def test_exec_surrogate_stdout_does_not_raise() -> None:
    conn, ws = _conn_with_fake_ws()
    handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=conn.send)
    req = protocol.ExecRequest(
        id=protocol.new_req_id(),
        src="agent-1",
        dst="ida-1",
        code="print(b'PRE_abc\\xff_POST'.decode('utf-8', 'surrogateescape'))",
    )
    handler.handle(req)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == req.id
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "stdout" in parsed.message
