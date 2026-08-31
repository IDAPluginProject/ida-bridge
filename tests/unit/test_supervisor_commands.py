"""Unit tests for supervisor command validation."""

from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from ida_bridge.supervisor.commands import StartError, default_idalib_python, start_idalib


class TestDefaultIdalibPython:
    def test_uses_venv_layout_for_platform(self) -> None:
        path = default_idalib_python()
        assert path.parent.parent.name == "venv"
        if sys.platform == "win32":
            assert path.parts[-2:] == ("Scripts", "python.exe")
        else:
            assert path.parts[-2:] == ("bin", "python3")


def _thin_macho() -> bytes:
    return bytes.fromhex("cffaedfe") + b"\x00" * 28


class TestStartIdalibDyldValidation:
    def test_rejects_macho_input_with_dyld_module(self, tmp_path: Path) -> None:
        macho = tmp_path / "thin_macho"
        macho.write_bytes(_thin_macho())
        out_idb = tmp_path / "out.i64"
        runner = tmp_path / "idalib_runner.py"
        runner.write_text("# test\n", encoding="utf-8")

        with (
            patch("ida_bridge.supervisor.commands._resolve_python", return_value="/usr/bin/python3"),
            patch("ida_bridge.supervisor.commands._idalib_runner_path", return_value=runner),
        ):
            with pytest.raises(StartError, match="requires a dyld_shared_cache input"):
                start_idalib(
                    input_file=str(macho),
                    out_idb=str(out_idb),
                    dyld_module="/usr/lib/system/libcompiler_rt.dylib",
                )

    def test_rejects_non_cache_non_macho_input_with_dyld_module(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob.bin"
        blob.write_bytes(b"not macho")
        out_idb = tmp_path / "out.i64"
        runner = tmp_path / "idalib_runner.py"
        runner.write_text("# test\n", encoding="utf-8")

        with (
            patch("ida_bridge.supervisor.commands._resolve_python", return_value="/usr/bin/python3"),
            patch("ida_bridge.supervisor.commands._idalib_runner_path", return_value=runner),
        ):
            with pytest.raises(StartError, match=r"requires a dyld_shared_cache input"):
                start_idalib(
                    input_file=str(blob),
                    out_idb=str(out_idb),
                    dyld_module="/usr/lib/system/libcompiler_rt.dylib",
                )
