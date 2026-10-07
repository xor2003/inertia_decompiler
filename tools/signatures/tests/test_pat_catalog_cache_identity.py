"""Catalog pattern caches follow catalog identity, not binary artifact paths."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.signatures.omf_pat as omf_pat
import tools.signatures.pat_literal_filter as pat_literal_filter
import tools.signatures.signature_catalog as signature_catalog


def test_catalog_match_identity_covers_existing_parser_and_literal_owners():
    """Matching cache invalidation must retain both relocated dependencies."""
    components = signature_catalog._SIGNATURE_MATCH_CACHE_COMPONENTS
    assert components == (
        Path(signature_catalog.__file__).resolve(),
        Path(omf_pat.__file__).resolve(),
        Path(pat_literal_filter.__file__).resolve(),
    )
    assert all(path.is_file() for path in components)


def test_pattern_cache_key_canonicalizes_relative_catalog_path(tmp_path, monkeypatch):
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("90" * 32 + " 00 0000 0001 :0000 function\n---\n")
    monkeypatch.chdir(tmp_path)
    cache_dir = tmp_path / "specs"
    first = omf_pat.load_cached_pat_regex_specs(Path("catalog.pat"), cache_dir)
    second = omf_pat.load_cached_pat_regex_specs(catalog, cache_dir)
    assert first == second
    assert first[0].source_path == str(catalog)
    assert len(tuple(cache_dir.glob("*.patrx.pickle"))) == 1


def test_catalog_specs_reused_across_binary_artifact_directories(tmp_path, monkeypatch):
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    seen = []

    def load_specs(path, cache_dir):
        assert path == catalog
        seen.append(cache_dir)
        return ()

    monkeypatch.setattr(signature_catalog, "load_cached_pat_regex_specs", load_specs)
    monkeypatch.setattr(signature_catalog, "_load_cache_json", lambda *_args: None)
    project = SimpleNamespace(loader=SimpleNamespace(
        main_object=SimpleNamespace(min_addr=0, max_addr=3),
        memory=SimpleNamespace(load=lambda *_args: b"\x90" * 4),
    ))
    for name in ("first", "second"):
        directory = tmp_path / name
        directory.mkdir()
        binary = directory / "program.exe"
        binary.write_bytes(b"\x90" * 4)
        signature_catalog.match_signature_catalog(catalog, binary, project)
    assert len(seen) == 2
    assert seen[0] == seen[1]
    explicit = tmp_path / "explicit"
    signature_catalog.match_signature_catalog(catalog, binary, project, cache_dir=explicit)
    assert seen[-1] == explicit


def test_pattern_cache_identity_includes_literal_implementation(tmp_path, monkeypatch):
    tool = tmp_path / "omf_pat.py"
    helper = tmp_path / "pat_literal_filter.py"
    tool.write_text("# pattern implementation\n")
    helper.write_text("# original literal implementation\n")
    monkeypatch.setattr(omf_pat, "__file__", str(tool))
    omf_pat._omf_pat_tool_cache_fingerprint.cache_clear()
    try:
        before = omf_pat._omf_pat_tool_cache_fingerprint()
        helper.write_text("# changed literal implementation with distinct size\n")
        omf_pat._omf_pat_tool_cache_fingerprint.cache_clear()
        assert omf_pat._omf_pat_tool_cache_fingerprint() != before
        helper.unlink()
        omf_pat._omf_pat_tool_cache_fingerprint.cache_clear()
        with pytest.raises(FileNotFoundError):
            omf_pat._omf_pat_tool_cache_fingerprint()
    finally:
        omf_pat._omf_pat_tool_cache_fingerprint.cache_clear()
