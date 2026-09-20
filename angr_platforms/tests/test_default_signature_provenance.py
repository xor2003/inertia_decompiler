"""Automatic runtime catalogs must not hide application functions."""


from inertia_decompiler.default_signature_catalog import default_signature_catalog_path
from omf_pat import format_pat_module_line, parse_pat_file, parse_pat_line
from signature_catalog import build_signature_catalog, discover_signature_inputs


def _pattern(name: str, source: str) -> str:
    return f"558BECC3{'90' * 28} 00 0000 0020 :0000 {name} ; mod={name} | src={source}\n"


def test_merged_provenance_survives_pat_roundtrip():
    source = "/generated.pat || C:\\MSC\\LIB\\SLIBCE.LIB"
    module = parse_pat_line(_pattern("runtime", source))
    assert module is not None
    assert module.source_path == source
    assert parse_pat_line(format_pat_module_line(module)) == module


def test_default_catalog_requires_library_provenance(tmp_path):
    root = tmp_path / "signature_catalogs"
    root.mkdir()
    (root / "mixed.pat").write_text(
        _pattern("runtime", "C:\\MSC\\LIB\\SLIBCE.LIB")
        + _pattern("sample", "/compiler/SOURCE/SAMPLES/demo.obj")
        + _pattern("unknown", "/imports/unknown.pat")
        + _pattern("merged", "/cache/generated.pat || /compiler/lib/runtime.lib")
        + "---\n"
    )
    default_signature_catalog_path.cache_clear()
    output = default_signature_catalog_path(tmp_path)
    assert output is not None
    assert {module.module_name for module in parse_pat_file(output)} == {"runtime", "merged"}
    explicit = tmp_path / "explicit.pat"
    build_signature_catalog((root / "mixed.pat",), explicit)
    assert len(parse_pat_file(explicit)) == 4


def test_catalog_discovery_does_not_reimport_generated_cache(tmp_path):
    cache = tmp_path / ".signature_catalog_cache"
    cache.mkdir()
    (cache / "stale.pat").write_text(_pattern("stale", "/old.lib"))
    original = tmp_path / "source.pat"
    original.write_text("---\n")
    assert discover_signature_inputs((tmp_path,)) == (original,)


def test_default_catalog_rebuilds_when_builder_policy_changes(tmp_path, monkeypatch):
    from inertia_decompiler import default_signature_catalog as owner

    root = tmp_path / "signature_catalogs"
    root.mkdir()
    (root / "runtime.pat").write_text(_pattern("runtime", "/runtime.lib"))
    owner.default_signature_catalog_path.cache_clear()
    output = owner.default_signature_catalog_path(tmp_path)
    assert output is not None
    output.write_text(_pattern("obsolete", "/sample.obj"))
    monkeypatch.setattr(owner, "_catalog_tool_lines", lambda root: ("new-builder-policy",))
    owner.default_signature_catalog_path.cache_clear()
    assert owner.default_signature_catalog_path(tmp_path) == output
    assert {module.module_name for module in parse_pat_file(output)} == {"runtime"}
