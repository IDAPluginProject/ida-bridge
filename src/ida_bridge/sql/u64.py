"""Helpers for exact uint64/address handling across the SQLite boundary."""

_S64_MAX = (1 << 63) - 1
_U64_MOD = 1 << 64
_U64_MASK = _U64_MOD - 1


def encode_sql_u64(value: int | None) -> int | None:
    """Encode an unsigned 64-bit value as SQLite's signed INTEGER."""
    if value is None:
        return None
    value = int(value)
    if value < 0 or value <= _S64_MAX:
        return value
    return value - _U64_MOD


def decode_sql_u64(value: int | None) -> int | None:
    """Decode a signed SQLite INTEGER back to an unsigned 64-bit value."""
    if value is None:
        return None
    value = int(value)
    if value >= 0:
        return value
    return value + _U64_MOD


def decode_sql_u64_input(value: object | None, *, what: str = "address") -> int | None:
    """Require a SQLite INTEGER input and decode uint64 boundary encoding."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{what} must be an INTEGER; use an unquoted 0x... literal for high addresses"
        raise ValueError(msg)
    return decode_sql_u64(value)


def format_sql_u64_hex(value: int | None) -> str | None:
    """Format a signed-or-unsigned 64-bit value as ``0x...``."""
    if value is None:
        return None
    return f"0x{decode_sql_u64(value) & _U64_MASK:x}"
