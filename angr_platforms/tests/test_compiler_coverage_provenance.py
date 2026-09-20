"""Input fingerprints must change with content and toolchain file identity."""

import hashlib

from scripts.compiler_coverage_provenance import input_fingerprint


def test_missing_tool_is_explicit(tmp_path):
    assert input_fingerprint(tmp_path / "missing")["error"] == "missing"


def test_source_hash_is_standard_sha256(tmp_path):
    source = tmp_path / "case.c"
    source.write_bytes(b"int main(void) { return 0; }\n")
    assert input_fingerprint(source)["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_toolchain_hash_tracks_names_and_content(tmp_path):
    tool = tmp_path / "CL.EXE"
    tool.write_bytes(b"compiler")
    first = input_fingerprint(tmp_path)
    assert first == input_fingerprint(tmp_path)
    assert first["files"] == 1
    tool.write_bytes(b"updated")
    changed = input_fingerprint(tmp_path)
    assert changed["sha256"] != first["sha256"]
    tool.rename(tmp_path / "OTHER.EXE")
    assert input_fingerprint(tmp_path)["sha256"] != changed["sha256"]
