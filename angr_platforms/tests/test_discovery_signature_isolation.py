"""Isolated binary scans retain signature policy but not local debug evidence."""

from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import discovery_evidence_project as isolation


def test_isolation_retains_only_detached_signature_evidence(monkeypatch):
    metadata = LSTMetadata(
        data_labels={0x3000: "source_global"},
        code_labels={0x1000: "runtime", 0x1100: "source_function"},
        code_ranges={0x1000: (0x1000, 0x1020), 0x1100: (0x1100, 0x1140)},
        signature_code_addrs=frozenset({0x1000}),
        source_format="cod_listing+signature_catalog", cod_path="source.COD",
        debug_source_files=("source.c",),
    )
    source = SimpleNamespace(
        entry=0x1200, loader=SimpleNamespace(main_object=SimpleNamespace(binary="APP.EXE", linked_base=0x1000)),
        _inertia_lst_metadata=metadata, _inertia_include_library_functions=True,
    )
    target = SimpleNamespace()
    monkeypatch.setattr(isolation, "_build_project_cached", lambda *args, **kwargs: target)
    assert isolation.isolated_discovery_evidence_project_8616(source) is target
    copied = target._inertia_lst_metadata
    assert copied.code_labels == {0x1000: "runtime"}
    assert copied.code_ranges == {0x1000: (0x1000, 0x1020)}
    assert copied.signature_code_addrs == frozenset({0x1000})
    assert copied.cod_path is None
    assert copied.debug_source_files == ()
    assert copied.data_labels == {}
    assert target._inertia_include_library_functions is True
    copied.code_labels[0x1000] = "changed in isolated project"
    assert metadata.code_labels[0x1000] == "runtime"

    source._inertia_lst_metadata = None
    source._inertia_include_library_functions = False
    isolation.isolated_discovery_evidence_project_8616(source)
    assert target._inertia_lst_metadata is None
    assert target._inertia_include_library_functions is False
