from __future__ import annotations

import subprocess

import inertia.cli.rizin_discovery as rizin_discovery


def test_rizin_json_timeout_is_optional(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=3)

    monkeypatch.setattr(rizin_discovery.subprocess, "run", timeout)

    assert rizin_discovery._run_rizin_json(binary, "iSj", timeout_sec=3) is None


def test_mz_prologue_candidates_survive_entrypoint_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes((b"\0" * 0x20) + b"\x55\x8b\xec")
    segments = [{"paddr": 0x10, "vaddr": 0, "vsize": 0x100, "perm": "-r-x"}]
    monkeypatch.setattr(rizin_discovery, "_run_rizin_json", lambda *args, **kwargs: segments)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=2)

    monkeypatch.setattr(rizin_discovery.subprocess, "run", timeout)

    candidates, detail = rizin_discovery._mz_linear_candidates_from_prologues(binary)

    assert candidates == [0x10010]
    assert detail == "mz_prologue_fallback"


def test_discovery_uses_segment_safe_conservative_rizin_analysis(monkeypatch, tmp_path):
    """DOS discovery must not ask Rizin to recursively turn segmented data into code."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    commands: list[list[str]] = []

    def completed(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '[{"offset": 4660, "size": 2, "nbbs": 1}]', "")

    monkeypatch.setattr(rizin_discovery, "_rizin_available", lambda: True)
    monkeypatch.setattr(rizin_discovery, "_load_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery, "_store_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery.subprocess, "run", completed)

    result = rizin_discovery.discover_rizin_function_entries(binary)

    assert result.status is rizin_discovery.RizinDiscoveryStatus.OK
    assert result.offsets == (0x11234,)
    assert commands[0][4] == "aa;aflj"
    assert "aaa" not in commands[0][4]


def test_discovery_preserves_non_mz_rizin_addresses(monkeypatch, tmp_path):
    """Only DOS load-module offsets require Inertia's MZ load base."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"not-mz")

    def completed(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, '[{"offset": 4660, "size": 2, "nbbs": 1}]', "")

    monkeypatch.setattr(rizin_discovery, "_rizin_available", lambda: True)
    monkeypatch.setattr(rizin_discovery, "_load_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery, "_store_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery.subprocess, "run", completed)

    result = rizin_discovery.discover_rizin_function_entries(binary)

    assert result.status is rizin_discovery.RizinDiscoveryStatus.OK
    assert result.offsets == (0x1234,)


def test_discovery_adds_direct_rizin_call_targets(monkeypatch, tmp_path):
    """Segmented functions merged by Rizin still expose useful CALL roots."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    def completed(command, **kwargs):
        rizin_command = command[4]
        if rizin_command == "aa;aflj":
            payload = '[{"offset": 256, "size": 16, "nbbs": 2}]'
        elif rizin_command == "aa;axlj":
            payload = '[{"from": 260, "to": 512, "type": "CALL"}, {"from": 270, "to": 768, "type": "CODE"}]'
        else:
            payload = "[]"
        return subprocess.CompletedProcess(command, 0, payload, "")

    monkeypatch.setattr(rizin_discovery, "_rizin_available", lambda: True)
    monkeypatch.setattr(rizin_discovery, "_load_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery, "_store_cache_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(rizin_discovery.subprocess, "run", completed)

    result = rizin_discovery.discover_rizin_function_entries(binary)

    assert result.status is rizin_discovery.RizinDiscoveryStatus.OK
    assert result.offsets == (0x10100, 0x10200)
