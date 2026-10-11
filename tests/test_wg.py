from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from wgau import wg
from wgau.errors import WgError
from wgau.models import KeyPair


def fake_completed(stdout: str) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout)


class TestRunWg:
    def test_success_returns_stripped_stdout(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            assert cmd == ["wg", "genkey"]
            return fake_completed("  KEY-VALUE\n\n")
        monkeypatch.setattr(subprocess, "run", fake_run)
        assert wg.run_wg(["genkey"]) == "KEY-VALUE"

    def test_stdin_passed(self, monkeypatch):
        seen = {}

        def fake_run(cmd, input=None, **kwargs):
            seen["input"] = input
            return fake_completed("PUB\n")
        monkeypatch.setattr(subprocess, "run", fake_run)
        wg.run_wg(["pubkey"], stdin_data="SEC\n")
        assert seen["input"] == "SEC\n"

    def test_binary_missing(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("wg")
        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(WgError):
            wg.run_wg(["genkey"])

    def test_process_failure_message_contains_stderr(self, monkeypatch):
        error = subprocess.CalledProcessError(1, ["wg", "pubkey"], stderr="invalid key")

        def fake_run(cmd, **kwargs):
            raise error
        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(WgError) as excinfo:
            wg.run_wg(["pubkey"])
        assert "invalid key" in str(excinfo.value)


def test_generate_keys(monkeypatch):
    outputs = {("genkey",): "SEC\n", ("pubkey",): "PUB\n", ("genpsk",): "PSK\n"}

    def fake_run(cmd, input=None, **kwargs):
        return fake_completed(outputs[tuple(cmd[1:])])
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert wg.generate_keys() == KeyPair("SEC", "PUB", "PSK")


def test_derive_public_key(monkeypatch):
    def fake_run(cmd, input=None, **kwargs):
        assert input == "SEC\n"
        return fake_completed("PUB\n")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert wg.derive_public_key("SEC\n") == "PUB"


class TestSyncconf:
    def test_strips_then_syncs(self, monkeypatch, tmp_path):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["wg-quick", "strip"]:
                return fake_completed("[Interface]\n...")
            raise AssertionError(f"unexpected call: {cmd}")

        monkeypatch.setattr(subprocess, "run", fake_run)

        def fake_run_wg(args, stdin_data=None):
            calls.append(["wg", *args])
            assert stdin_data == "[Interface]\n..."
            return "ok"

        monkeypatch.setattr(wg, "run_wg", fake_run_wg)

        wg.syncconf("wg0", tmp_path / "wg0.conf")
        assert ["wg-quick", "strip", str(tmp_path / "wg0.conf")] in calls
        assert ["wg", "syncconf", "wg0", "/dev/stdin"] in calls

    def test_strip_failure(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)
        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(WgError):
            wg.syncconf("wg0", tmp_path / "wg0.conf")