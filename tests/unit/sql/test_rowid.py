"""Unit tests for rowid packing: the shared helper and each table's use of it."""

import pytest

from ida_bridge.sql.rowid import pack_rowid, unpack_rowid
from ida_bridge.sql.tables.analysis import _COMMENT_PAYLOAD_BITS
from ida_bridge.sql.tables.decompiler import (
    _COMMENT_TYPE_BIT,
    _LVAR_PAYLOAD_BITS,
    _PSEUDOCODE_PAYLOAD_BITS,
    _decode_rowid,
    _encode_code_rowid,
    _encode_comment_rowid,
)
from ida_bridge.sql.tables.types import _TYPE_INDEX_PAYLOAD_BITS
from ida_bridge.sql.u64 import encode_sql_u64

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

# Taken from the tables themselves, so the helper is exercised at the widths in use.
_PAYLOAD_BITS = tuple(
    sorted({_COMMENT_PAYLOAD_BITS, _PSEUDOCODE_PAYLOAD_BITS, _LVAR_PAYLOAD_BITS, _TYPE_INDEX_PAYLOAD_BITS})
)


def _max_canonical_low(payload_bits: int) -> int:
    """Largest value whose borrowed high bits are all zero."""
    return (1 << (63 - payload_bits)) - 1


def _min_canonical_high(payload_bits: int) -> int:
    """Smallest value whose borrowed high bits are all one."""
    return (1 << 64) - (1 << (63 - payload_bits))


def _payload_samples(payload_bits: int, count: int = 10) -> list[int]:
    """Both edges plus an even spread; deterministic so a failure reproduces."""
    limit = 1 << payload_bits
    if limit <= count:
        return list(range(limit))
    stride = limit // (count - 1)
    return sorted({0, *range(stride, limit - 1, stride), limit - 1})


class TestPackRowid:
    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    @pytest.mark.parametrize(
        "value",
        [
            0,
            0x1000,
            0x100000548,  # userspace
            0x1800000000,  # dyld shared cache
            0xFFFFFFF007000000,  # kernel
            0xFFFFFE0000000000,  # low kernel
            0xFFFFFFFFFFFFFFFF,  # max uint64
        ],
    )
    def test_round_trip(self, value: int, payload_bits: int) -> None:
        payload = (1 << payload_bits) - 1
        rowid = pack_rowid(value, payload, payload_bits=payload_bits)
        assert _INT64_MIN <= rowid <= _INT64_MAX, "rowid must fit a signed 64-bit column"
        assert unpack_rowid(rowid, payload_bits=payload_bits) == (value, payload)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_round_trip_at_canonical_boundaries(self, payload_bits: int) -> None:
        for value in (_max_canonical_low(payload_bits), _min_canonical_high(payload_bits)):
            rowid = pack_rowid(value, 0, payload_bits=payload_bits)
            assert unpack_rowid(rowid, payload_bits=payload_bits) == (value, 0)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_payload_does_not_disturb_value(self, payload_bits: int) -> None:
        value = 0xFFFFFFF007000000
        for payload in _payload_samples(payload_bits):
            rowid = pack_rowid(value, payload, payload_bits=payload_bits)
            assert unpack_rowid(rowid, payload_bits=payload_bits) == (value, payload)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_non_canonical_value_raises(self, payload_bits: int) -> None:
        """Borrowed bits that are not uniform cannot be regenerated, so packing must refuse."""
        value = _max_canonical_low(payload_bits) + 1
        with pytest.raises(ValueError, match="all 0 or all 1"):
            pack_rowid(value, 0, payload_bits=payload_bits)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_signed_value_raises(self, payload_bits: int) -> None:
        """The canonical check is also the unsigned check: an already-encoded ea must not pass."""
        with pytest.raises(ValueError, match="unsigned 64-bit integer"):
            pack_rowid(encode_sql_u64(0xFFFFFFF007000000), 0, payload_bits=payload_bits)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_value_beyond_u64_raises(self, payload_bits: int) -> None:
        """The canonical check is also the range check, so no separate bound is needed."""
        with pytest.raises(ValueError, match="unsigned 64-bit integer"):
            pack_rowid(1 << 64, 0, payload_bits=payload_bits)

    @pytest.mark.parametrize("payload_bits", _PAYLOAD_BITS)
    def test_oversized_payload_raises(self, payload_bits: int) -> None:
        """An oversized payload would overwrite value bits instead of overflowing."""
        with pytest.raises(ValueError, match="does not fit"):
            pack_rowid(0x1000, 1 << payload_bits, payload_bits=payload_bits)

    def test_distinct_values_give_distinct_rowids(self) -> None:
        addresses = 200
        payloads = (0, 69)
        rowids = {
            pack_rowid(0xFFFFFFF007000000 + i * 4, payload, payload_bits=_PSEUDOCODE_PAYLOAD_BITS)
            for i in range(addresses)
            for payload in payloads
        }
        assert len(rowids) == addresses * len(payloads)


class TestPseudocodeRowid:
    def test_code_rowid_round_trip(self) -> None:
        for index in (0, 1, 42, 255, 1000, 5000):
            is_comment, val, itp = _decode_rowid(_encode_code_rowid(index))
            assert not is_comment
            assert val == index
            assert itp == 0

    @pytest.mark.parametrize(
        ("ea", "itp"),
        [
            (0x100003158, 69),  # userland, ITP_SEMI
            (0x100003158, 74),  # userland, ITP_BLOCK1
            (0x100003158, 75),  # userland, ITP_BLOCK2
            (0x0, 69),  # zero address
            (0x1000, 1),  # small address, ITP_ARG1
        ],
    )
    def test_comment_rowid_round_trip(self, ea: int, itp: int) -> None:
        is_comment, decoded_ea, decoded_itp = _decode_rowid(_encode_comment_rowid(ea, itp))
        assert is_comment
        assert decoded_ea == ea, f"{decoded_ea:#x} != {ea:#x}"
        assert decoded_itp == itp

    @pytest.mark.parametrize(
        "ea",
        [
            0x0020000000000000,  # bit 53 clear, large positive
            0x003FFFFFFFFFFFFF,  # max canonical positive
            0xFFC0000000000000,  # canonical with bit 53 clear
            0xFFE0000000000000,  # canonical with bit 53 set
            0xFFFFFF8000000000,  # kernel
            0xFFFFFFF000100000,  # kernel
            0xFFFFFFFFFFFFFFFF,  # max uint64
        ],
    )
    def test_canonical_address_round_trip(self, ea: int) -> None:
        is_comment, decoded_ea, _ = _decode_rowid(_encode_comment_rowid(ea, 69))
        assert is_comment
        assert decoded_ea == ea, f"{decoded_ea:#x} != {ea:#x}"

    @pytest.mark.parametrize("ea", [1 << 54, 0x0040000000001000, 0x7FFFFFFFFFFFFFFF])
    def test_non_canonical_address_raises(self, ea: int) -> None:
        """A rowid that cannot decode back to this address must not be produced."""
        with pytest.raises(ValueError, match="all 0 or all 1"):
            _encode_comment_rowid(ea, 69)

    def test_itp_beyond_8_bits_raises(self) -> None:
        """An itp reaching the type bit stays inside the 9-bit payload, so only this check catches it."""
        with pytest.raises(ValueError, match="does not fit in 8 bits"):
            _encode_comment_rowid(0x100000, _COMMENT_TYPE_BIT)

    def test_code_and_comment_rowids_dont_collide(self) -> None:
        code_rowids = {_encode_code_rowid(i) for i in range(1000)}
        comment_rowids = {_encode_comment_rowid(0x100003158 + i * 4, 69) for i in range(1000)}
        assert not code_rowids & comment_rowids

    def test_type_bit_discriminates_comment_from_code(self) -> None:
        for itp in (0, 1, 64, 69, 74, 75):
            is_comment, _, decoded_itp = _decode_rowid(_encode_comment_rowid(0x100000, itp))
            assert is_comment
            assert decoded_itp == itp
        for index in range(300):
            is_comment, _, _ = _decode_rowid(_encode_code_rowid(index))
            assert not is_comment
