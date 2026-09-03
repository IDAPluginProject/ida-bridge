"""Unit tests for IDA install discovery."""

import json
import os
from pathlib import Path
import sys

import pytest

from ida_bridge.supervisor.ida_resolve import find_ida_linux, find_ida_windows, ida_user_dirs


def _touch_exe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")


def _touch_bin(path: Path) -> None:
    _touch_exe(path)
    path.chmod(0o755)


def _write_config(user_dir: Path, install_dir: Path) -> None:
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "ida-config.json").write_text(json.dumps({"Paths": {"ida-install-dir": str(install_dir)}}))


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


class TestIdaUserDirs:
    def test_idausr_lists_every_component(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """IDA scans every component of IDAUSR, so all of them are candidates."""
        monkeypatch.setenv("IDAUSR", f"/first{os.pathsep}/second")
        assert ida_user_dirs() == [Path("/first"), Path("/second")]

    def test_falls_back_to_dot_idapro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IDAUSR", raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        assert ida_user_dirs() == [Path.home() / ".idapro"]


class TestFindIdaLinux:
    def test_idadir_wins_over_config_and_scan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        explicit = tmp_path / "custom" / "ida"
        _touch_bin(explicit)
        _touch_bin(tmp_path / "roots" / "IDA Professional 9.9" / "ida")
        _write_config(tmp_path / "usr", tmp_path / "roots" / "IDA Professional 9.9")
        monkeypatch.setenv("IDAUSR", str(tmp_path / "usr"))
        monkeypatch.setenv("IDADIR", str(explicit.parent))
        assert find_ida_linux(search_roots=[tmp_path / "roots"]) == explicit

    def test_config_found_in_a_later_idausr_component(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only one component need hold ida-config.json."""
        recorded = tmp_path / "anywhere" / "IDA Professional 9.4"
        _touch_bin(recorded / "ida")
        _write_config(tmp_path / "second", recorded)
        monkeypatch.setenv("IDAUSR", f"{tmp_path / 'first'}{os.pathsep}{tmp_path / 'second'}")
        monkeypatch.delenv("IDADIR", raising=False)
        assert find_ida_linux(search_roots=[]) == recorded / "ida"

    def test_config_wins_over_scan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux has no install-path convention, so the recorded path beats a guess."""
        recorded = tmp_path / "anywhere" / "IDA Professional 9.4"
        _touch_bin(recorded / "ida")
        _touch_bin(tmp_path / "roots" / "IDA Professional 9.9" / "ida")
        _write_config(tmp_path / "usr", recorded)
        monkeypatch.setenv("IDAUSR", str(tmp_path / "usr"))
        monkeypatch.delenv("IDADIR", raising=False)
        assert find_ida_linux(search_roots=[tmp_path / "roots"]) == recorded / "ida"

    def test_scan_picks_newest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _touch_bin(tmp_path / "IDA Professional 9.0" / "ida")
        newest = tmp_path / "IDA Professional 9.4" / "ida"
        _touch_bin(newest)
        monkeypatch.setenv("IDAUSR", str(tmp_path / "empty-usr"))
        monkeypatch.delenv("IDADIR", raising=False)
        assert find_ida_linux(search_roots=[tmp_path]) == newest

    def test_ignores_non_executable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _touch_exe(tmp_path / "IDA Professional 9.4" / "ida")  # not chmod +x
        monkeypatch.setenv("IDAUSR", str(tmp_path / "empty-usr"))
        monkeypatch.delenv("IDADIR", raising=False)
        with pytest.raises(SystemExit, match="No IDA installation found"):
            find_ida_linux(search_roots=[tmp_path])
