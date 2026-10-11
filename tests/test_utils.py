from __future__ import annotations

import os
from pathlib import Path

import pytest

from wgau.utils import atomic_write, atomic_write_bytes


def test_creates_file(tmp_path: Path):
    target = tmp_path / "file.txt"
    atomic_write(target, "hello")
    assert target.read_text(encoding="utf-8") == "hello"


def test_replaces_existing_content(tmp_path: Path):
    target = tmp_path / "file.txt"
    target.write_text("old")
    atomic_write(target, "new")
    assert target.read_text() == "new"


def test_sets_mode(tmp_path: Path):
    target = tmp_path / "sec.key"
    atomic_write(target, "secret", mode=0o600)
    assert target.stat().st_mode & 0o777 == 0o600


def test_keeps_directory_clean(tmp_path: Path):
    # после записи не должно остаться tmp-файлов
    atomic_write(tmp_path / "a.txt", "x")
    atomic_write(tmp_path / "b.txt", "y")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt", "b.txt"]


def test_failure_keeps_original_and_cleans_tmp(tmp_path: Path, monkeypatch):
    target = tmp_path / "file.txt"
    target.write_text("original")

    def broken_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError):
        atomic_write(target, "new")

    # оригинал цел, мусор удалён
    assert target.read_text() == "original"
    assert [p.name for p in tmp_path.iterdir()] == ["file.txt"]

def test_bytes_version(tmp_path: Path):
    target = tmp_path / "img.png"
    atomic_write_bytes(target, b"\x89PNG\r\n\x1a\n....", mode=0o600)
    assert target.read_bytes() == b"\x89PNG\r\n\x1a\n...."
    assert target.stat().st_mode & 0o777 == 0o600