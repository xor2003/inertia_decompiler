"""An explicit PAT catalog does not depend on optional FLAIR startup assets."""

from types import SimpleNamespace
from unittest.mock import Mock

from inertia_decompiler import sidecar_parsers


def test_catalog_loaded_without_flair_directory(tmp_path, monkeypatch):
    missing_root = tmp_path / "missing-flair"
    catalog = tmp_path / "runtime.pat"
    catalog.write_text("---\n")
    binary = tmp_path / "APP.EXE"
    project = SimpleNamespace(
        entry=0x10000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *args: b"\x90" * 32),
        ),
    )
    match = Mock(return_value=SimpleNamespace(
        code_labels={0x10100: "runtime"}, code_ranges={0x10100: (0x10100, 0x10120)},
        source_formats=("signature_catalog",), matched_compiler_names=(),
    ))
    monkeypatch.setattr(sidecar_parsers, "flair_signature_root", lambda: missing_root)
    monkeypatch.setattr(sidecar_parsers, "match_signature_catalog", match)
    labels, ranges, formats = sidecar_parsers._detect_flair_metadata(
        binary, project, pat_backend="python_regex", signature_catalog=catalog,
    )
    assert labels == {0x10100: "runtime"}
    assert ranges == {0x10100: (0x10100, 0x10120)}
    assert formats == ("signature_catalog",)
    match.assert_called_once_with(catalog, binary, project, backend="python_regex", compiler_names=())
    assert not missing_root.exists()
