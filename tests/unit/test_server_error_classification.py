import json

import pytest

from ida_bridge import protocol


def _classify(raw: str) -> tuple[str, str, dict]:
    try:
        protocol.parse_message_json(raw)
    except protocol.ValidationError as exc:
        code, msg, trace = protocol.classify_validation_error(exc)
        return code, msg, trace

    raise AssertionError("expected ValidationError")


def test_classify_invalid_json() -> None:
    code, msg, trace = _classify("{not json")
    assert code == protocol.ERR_INVALID_JSON
    assert "errors" in trace


def test_classify_missing_version() -> None:
    raw = json.dumps({"type": protocol.MSG_HELLO, "role": protocol.ROLE_AGENT, "client_id": "agent-1", "meta": {}})
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_MISSING_VERSION
    assert "errors" in trace


def test_classify_unsupported_version() -> None:
    raw = json.dumps(
        {"v": 999, "type": protocol.MSG_HELLO, "role": protocol.ROLE_AGENT, "client_id": "agent-1", "meta": {}}
    )
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_UNSUPPORTED_VERSION


def test_classify_invalid_request_id() -> None:
    raw = json.dumps(
        {
            "v": protocol.PROTO_VERSION,
            "type": protocol.MSG_LIST,
            "id": "not-a-uuid",
            "src": "agent-1",
            "dst": "bridge",
            "kind": protocol.LIST_KIND_ALL,
        }
    )
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_INVALID_REQUEST_ID


def test_classify_unknown_message_type() -> None:
    raw = json.dumps({"v": protocol.PROTO_VERSION, "type": "nope"})
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_UNSUPPORTED_MESSAGE


def test_classify_invalid_role() -> None:
    raw = json.dumps(
        {"v": protocol.PROTO_VERSION, "type": protocol.MSG_HELLO, "role": "nope", "client_id": "x", "meta": {}}
    )
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_INVALID_ROLE


@pytest.mark.parametrize(
    "payload",
    [
        {"v": protocol.PROTO_VERSION, "type": protocol.MSG_HELLO, "role": protocol.ROLE_AGENT, "meta": {}},
        {
            "v": protocol.PROTO_VERSION,
            "type": protocol.MSG_HELLO,
            "role": protocol.ROLE_AGENT,
            "client_id": "",
            "meta": {},
        },
    ],
)
def test_classify_invalid_client_id(payload: dict) -> None:
    code, msg, trace = _classify(json.dumps(payload))
    assert code == protocol.ERR_INVALID_CLIENT_ID


def test_classify_fallback_invalid_message() -> None:
    raw = json.dumps(
        {
            "v": protocol.PROTO_VERSION,
            "type": protocol.MSG_LIST,
            "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "src": "agent-1",
            "dst": "bridge",
            "kind": "nope",
        }
    )
    code, msg, trace = _classify(raw)
    assert code == protocol.ERR_INVALID_MESSAGE
