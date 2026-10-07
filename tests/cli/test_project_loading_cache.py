"""Focused contracts for cached CLI project probes.

Layer: CLI/fallback/reporting tests.
Responsibility: keep normalized cache keys compatible with filesystem path operations.
"""

from pathlib import Path

from inertia.cli.project_loading import (
    _find_sidecar_file,
    _find_sidecar_file_cached,
    _probe_ida_base_linear,
    _probe_ida_base_linear_cached,
)


def test_cached_sidecar_and_ida_base_probes_accept_normalized_string_keys(tmp_path: Path) -> None:
    binary = tmp_path / "SAMPLE.EXE"
    listing = tmp_path / "SAMPLE.lst"
    binary.write_bytes(b"MZ")
    listing.write_text("Base Address: 1234h\n", encoding="utf-8")

    _find_sidecar_file_cached.cache_clear()
    _probe_ida_base_linear_cached.cache_clear()
    try:
        assert _find_sidecar_file_cached(binary.as_posix(), ".lst") == listing
        assert _find_sidecar_file(binary, ".LST") == listing
        assert _probe_ida_base_linear(binary, 0x10000) == 0x12340
        assert _probe_ida_base_linear(binary, 0x10000) == 0x12340
    finally:
        _find_sidecar_file_cached.cache_clear()
        _probe_ida_base_linear_cached.cache_clear()
