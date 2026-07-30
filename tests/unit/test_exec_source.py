"""Unit tests for exec source composition helpers."""

import traceback

import pytest

from ida_bridge.cli_common import _INLINE_FILENAME, build_exec_code


class TestBuildExecCode:
    def test_rejects_missing_code_and_file(self) -> None:
        with pytest.raises(ValueError, match="sql, code, or file required"):
            build_exec_code(code=None, files=None)

    def test_code_only(self) -> None:
        code = build_exec_code(code="_result_ = 7", files=None)

        env = {"__builtins__": __builtins__}
        exec(code, env, env)

        assert env["_result_"] == 7

    def test_file_then_code_share_globals(self, tmp_path) -> None:
        snippet = tmp_path / "snippet.py"
        snippet.write_text("x = 40\n", encoding="utf-8")

        code = build_exec_code(code="_result_ = x + 2", files=[str(snippet)])

        env = {"__builtins__": __builtins__}
        exec(code, env, env)

        assert env["_result_"] == 42

    def test_multiple_files_run_in_order(self, tmp_path) -> None:
        a = tmp_path / "a.py"
        a.write_text("x = 10\n", encoding="utf-8")
        b = tmp_path / "b.py"
        b.write_text("y = x + 5\n", encoding="utf-8")

        code = build_exec_code(code="_result_ = y * 2", files=[str(a), str(b)])

        env = {"__builtins__": __builtins__}
        exec(code, env, env)

        assert env["_result_"] == 30

    def test_multiple_files_no_code(self, tmp_path) -> None:
        a = tmp_path / "a.py"
        a.write_text("x = 1\n", encoding="utf-8")
        b = tmp_path / "b.py"
        b.write_text("_result_ = x + 1\n", encoding="utf-8")

        code = build_exec_code(code=None, files=[str(a), str(b)])

        env = {"__builtins__": __builtins__}
        exec(code, env, env)

        assert env["_result_"] == 2

    def test_file_traceback_uses_real_filename(self, tmp_path) -> None:
        snippet = tmp_path / "boom.py"
        snippet.write_text("raise RuntimeError('boom')\n", encoding="utf-8")

        code = build_exec_code(code=None, files=[str(snippet)])
        env = {"__builtins__": __builtins__}

        try:
            exec(code, env, env)
        except RuntimeError:
            tb = traceback.format_exc()
        else:
            pytest.fail("expected RuntimeError")

        assert str(snippet) in tb

    def test_inline_traceback_uses_synthetic_filename(self) -> None:
        code = build_exec_code(code="raise RuntimeError('boom')", files=None)
        env = {"__builtins__": __builtins__}

        try:
            exec(code, env, env)
        except RuntimeError:
            tb = traceback.format_exc()
        else:
            pytest.fail("expected RuntimeError")

        assert _INLINE_FILENAME in tb

    def test_sql_only(self) -> None:
        code = build_exec_code(sql="SELECT * FROM funcs", code=None, files=None)
        assert "idb.sql(" in code
        assert "SELECT * FROM funcs" in code

    def test_sql_with_single_quotes(self) -> None:
        code = build_exec_code(sql="SELECT * FROM funcs WHERE name = 'main'", code=None, files=None)
        # repr() should handle the quoting — the generated code must be valid Python
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: q)})()}
        exec(code, env, env)
        assert env["_result_"] == "SELECT * FROM funcs WHERE name = 'main'"

    def test_sql_then_code(self) -> None:
        mock_qr = type("QR", (), {"columns": ["v"], "rows": [{"v": 1}]})()
        code = build_exec_code(sql="SELECT 1", code="_result_ = _result_['rows'][0]['v']", files=None)
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: mock_qr)})()}
        exec(code, env, env)
        assert env["_result_"] == 1

    def test_sql_then_file_then_code(self, tmp_path) -> None:
        f = tmp_path / "helper.py"
        f.write_text("row_count = len(_result_['rows'])\n", encoding="utf-8")
        mock_qr = type("QR", (), {"columns": ["v"], "rows": [{"v": 1}, {"v": 2}]})()
        code = build_exec_code(sql="SELECT 1", code="_result_ = row_count", files=[str(f)])
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: mock_qr)})()}
        exec(code, env, env)
        assert env["_result_"] == 2

    def test_sql_runs_before_file(self, tmp_path) -> None:
        f = tmp_path / "check.py"
        f.write_text("saw_result = '_result_' in dir()\n", encoding="utf-8")
        mock_qr = type("QR", (), {"columns": ["v"], "rows": [{"v": 1}]})()
        code = build_exec_code(sql="SELECT 1", code=None, files=[str(f)])
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: mock_qr)})()}
        exec(code, env, env)
        # _result_ was set by SQL before the file ran
        assert env["saw_result"] is True

    def test_sql_only_preserves_raw_object(self) -> None:
        """SQL-only (no -c/-f) keeps QueryResult so serialize_result handles it."""
        mock_qr = type("QR", (), {"columns": ["v"], "rows": [{"v": 1}]})()
        code = build_exec_code(sql="SELECT 1", code=None, files=None)
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: mock_qr)})()}
        exec(code, env, env)
        # No conversion -- _result_ is the original object, not a dict
        assert env["_result_"] is mock_qr

    def test_sql_with_code_converts_to_dict(self) -> None:
        """SQL + -c converts to plain dict with raw values (ints, not hex strings)."""
        mock_qr = type(
            "QR", (), {"columns": ["start_ea", "name"], "rows": [{"start_ea": 0x100003F40, "name": "main"}]}
        )()
        code = build_exec_code(
            sql="SELECT start_ea, name FROM funcs", code="_result_ = _result_['rows'][0]['start_ea']", files=None
        )
        env = {"__builtins__": __builtins__, "idb": type("idb", (), {"sql": staticmethod(lambda q: mock_qr)})()}
        exec(code, env, env)
        assert env["_result_"] == 0x100003F40
