"""Unit tests for IDA install discovery."""

from pathlib import Path

import pytest

from ida_bridge.supervisor.ida_resolve import find_ida_windows


def _touch_exe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")


class TestFindIdaWindows:
    def test_picks_newest_versioned_dir(self, tmp_path: Path) -> None:
        _touch_exe(tmp_path / "IDA Professional 9.0" / "ida.exe")
        newest = tmp_path / "IDA Professional 9.3" / "ida.exe"
        _touch_exe(newest)
        assert find_ida_windows(search_roots=[tmp_path]) == newest

    def test_prefers_ida_exe_over_ida64(self, tmp_path: Path) -> None:
        root = tmp_path / "IDA Professional 9.3"
        _touch_exe(root / "ida64.exe")
        wanted = root / "ida.exe"
        _touch_exe(wanted)
        assert find_ida_windows(search_roots=[tmp_path]) == wanted

    def test_ignores_nvidia_style_false_positive(self, tmp_path: Path) -> None:
        _touch_exe(tmp_path / "NVIDIA Corporation" / "ida.exe")
        wanted = tmp_path / "IDA Professional 9.2" / "ida.exe"
        _touch_exe(wanted)
        assert find_ida_windows(search_roots=[tmp_path]) == wanted

    def test_idadir_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        other = tmp_path / "IDA Professional 9.9" / "ida.exe"
        _touch_exe(other)
        explicit = tmp_path / "custom" / "ida.exe"
        _touch_exe(explicit)
        monkeypatch.setenv("IDADIR", str(explicit.parent))
        assert find_ida_windows(search_roots=[tmp_path]) == explicit

    def test_missing_install_exits(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IDADIR", raising=False)
        with pytest.raises(SystemExit, match="No IDA installation found"):
            find_ida_windows(search_roots=[tmp_path])
