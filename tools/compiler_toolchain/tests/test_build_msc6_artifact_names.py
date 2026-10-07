from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import tools.compiler_toolchain.build_msc6_examples as harness
from tools.compiler_toolchain.build_msc6_examples import (
    DEFAULT_BATCH_DECOMPILE_PROCS,
    REPO_ROOT,
    _dos_safe_names,
)


def test_batch_decompiler_entrypoint_uses_existing_canonical_owner() -> None:
    """Relocation must preserve the executable batch route instead of skipping it."""
    assert DEFAULT_BATCH_DECOMPILE_PROCS == REPO_ROOT / "tools/dev/batch_decompile_procs.py"
    assert DEFAULT_BATCH_DECOMPILE_PROCS.is_file()


def test_label_lookup_preserves_explicit_signature_catalog(tmp_path, monkeypatch) -> None:
    """Label harvesting must use the pinned catalog without selecting a global one."""
    binary = tmp_path / "CASE.EXE"
    catalog = tmp_path / "runtime.pat"
    project = object()
    monkeypatch.setattr(harness, "_build_project", Mock(return_value=project))
    metadata_loader = Mock(return_value=SimpleNamespace(code_labels={0x10010: "_cmp_i16"}))
    monkeypatch.setattr(harness, "_load_lst_metadata", metadata_loader)
    labels = harness._lookup_sidecar_code_labels(binary, signature_catalog=catalog)
    metadata_loader.assert_called_once_with(binary, project, pat_backend=None, signature_catalog=catalog)
    assert labels == {"_cmp_i16": 0x10010, "cmp_i16": 0x10010}


def test_coverage_expansion_sources_have_distinct_dos_names(tmp_path) -> None:
    """Each admitted fixture and fact probe must survive DOS filename staging."""
    stems = (
        "cond_side_effects", "bounded_recursion", "pointer_ops", "nested_struct",
        "enum_variants", "array_init", "char_signedness", "bitfield_layout", "aggregate_layout",
        "char_boundaries", "ulong_carry", "long_arith", "long_shift", "dense_switch",
        "variadic_args", "explicit_far_abi", "union_widths", "bitfield_signed", "library_call_boundary",
    )
    names = tuple(harness._dos_staged_source_name(tmp_path / f"{stem}.c") for stem in stems)
    assert len(set(names)) == len(stems)
    assert all(harness._DOS_83_STAGE_NAME.fullmatch(name) for name in names)
    assert len(set(harness._DOS_EXAMPLE_NAMES.values())) == len(harness._DOS_EXAMPLE_NAMES)
    with pytest.raises(ValueError, match=r"DOS 8\.3"):
        harness._dos_staged_source_name(tmp_path / "unregistered_long_name.c")


def test_rebuilt_names_cannot_overwrite_number_suffixed_original() -> None:
    rebuilt_names = _dos_safe_names("COMP32", counter=2)

    assert rebuilt_names == ("DCOMP02.C", "DCOMP02.OBJ", "DCOMP02.EXE", "DCOMP02.MAP")
    assert all(name.split(".", 1)[0] != "COMP32" for name in rebuilt_names)


def test_rebuilt_names_remain_distinct_when_default_marker_matches_source() -> None:
    rebuilt_names = _dos_safe_names("DDDDD00", counter=0)

    assert rebuilt_names == ("RDDDD00.C", "RDDDD00.OBJ", "RDDDD00.EXE", "RDDDD00.MAP")
    assert all(len(name.split(".", 1)[0]) <= 8 for name in rebuilt_names)
