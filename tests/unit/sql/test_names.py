"""Tests for the names virtual table."""

import sys
from types import SimpleNamespace

import pytest

from ida_bridge.sql import sql


@pytest.fixture()
def name_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        (0x1000, "user_symbol", True),
        (0x2000, "sub_2000", False),
    ]
    by_ea = {ea: {"name": name, "is_user": is_user} for ea, name, is_user in rows}
    by_name = {name: ea for ea, name, _is_user in rows}
    indexes = {ea: index for index, (ea, _name, _is_user) in enumerate(rows)}

    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        SimpleNamespace(
            get_name=lambda ea: by_ea.get(ea, {}).get("name", ""),
            get_name_ea=lambda seg, name: by_name.get(name, 0xFFFFFFFFFFFFFFFF),
            get_nlist_size=lambda: len(rows),
            get_nlist_ea=lambda index: rows[index][0],
            get_nlist_name=lambda index: rows[index][1],
            get_nlist_idx=lambda ea: indexes.get(ea, -1),
            is_in_nlist=lambda ea: ea in by_ea,
            demangle_name=lambda name, mask, dqt=0: None,
            DQT_FULL=0,
        ),
    )

    calls = {"get_flags": 0, "has_user_name": 0}

    def get_flags(ea: int) -> int:
        calls["get_flags"] += 1
        return ea

    def has_user_name(flags: int) -> bool:
        calls["has_user_name"] += 1
        return bool(by_ea[flags]["is_user"])

    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        SimpleNamespace(
            get_flags=get_flags,
            has_user_name=has_user_name,
            get_cmt=lambda ea, r: None,
            get_byte=lambda ea: 0,
            get_word=lambda ea: 0,
            get_dword=lambda ea: 0,
            get_qword=lambda ea: 0,
            get_bytes=lambda ea, size: b"\x00" * size,
            is_code=lambda f: False,
            is_data=lambda f: False,
            is_strlit=lambda f: False,
            is_struct=lambda f: False,
            is_align=lambda f: False,
            is_unknown=lambda f: True,
            compiled_binpat_vec_t=SimpleNamespace(
                parse=staticmethod(lambda ea, pat, radix: [1] if pat else None),
            ),
            bin_search=lambda start, end, pat, flags: (0xFFFFFFFFFFFFFFFF, 0),
            BIN_SEARCH_FORWARD=0x00,
            BIN_SEARCH_NOBREAK=0x02,
            BIN_SEARCH_NOSHOW=0x08,
        ),
    )

    from ida_bridge.sql.db import reset_db

    reset_db()
    return calls


class TestNames:
    def test_full_scan(self, name_stubs: dict[str, int]) -> None:
        result = sql("SELECT * FROM names ORDER BY address")
        assert result.columns == ["address", "name", "is_auto"]
        assert result.rows == [
            {"address": 0x1000, "name": "user_symbol", "is_auto": 0},
            {"address": 0x2000, "name": "sub_2000", "is_auto": 1},
        ]
        assert name_stubs == {"get_flags": 2, "has_user_name": 2}

    def test_filter_by_is_auto(self, name_stubs: dict[str, int]) -> None:
        result = sql("SELECT name FROM names WHERE is_auto = 1")
        assert result.rows == [{"name": "sub_2000"}]

    def test_address_and_name_scan_stays_lazy(self, name_stubs: dict[str, int]) -> None:
        result = sql("SELECT address, name FROM names ORDER BY address")
        assert result.rows == [
            {"address": 0x1000, "name": "user_symbol"},
            {"address": 0x2000, "name": "sub_2000"},
        ]
        assert name_stubs == {"get_flags": 0, "has_user_name": 0}
