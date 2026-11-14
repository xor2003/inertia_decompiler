"""Slim spec artifacts: lazy heavy records and match-result parity."""

from __future__ import annotations

import dataclasses

import pytest

from tools.signatures import omf_pat
from tools.signatures.omf_pat import (
    CachedPatRegexSpec,
    PatFixupKind,
    PatLinkerReference,
    PatModule,
    PatPublicName,
)


def _module(name: str = "runtime") -> PatModule:
    body = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3")
    return PatModule(
        source_path="<test>",
        compiler_name="test compiler",
        module_name=name,
        pattern_bytes=tuple(body),
        module_length=len(body),
        public_names=(PatPublicName(offset=0, name=name),),
        referenced_names=(PatPublicName(offset=4, name="extref"),),
        tail_bytes=(),
    )


def _reference() -> PatLinkerReference:
    return PatLinkerReference(
        offset=4,
        width_bytes=2,
        kind=PatFixupKind.SELF_RELATIVE_OFFSET16,
        target_public_identity="extref",
        explicit_target_displacement=None,
        source_library_sha256="ab" * 32,
        source_object_sha256="cd" * 32,
        source_segment_index=1,
        source_segment_offset=0,
        fixupp_record_offset=0,
        raw_fixupp_subrecord=b"\x9c\x04\x02",
    )


def _full_spec(module: PatModule) -> CachedPatRegexSpec:
    return omf_pat._compile_pat_module_to_cached_regex(module)


def _write_specs(tmp_path, specs):
    return omf_pat._write_slim_spec_artifacts(
        specs,
        tmp_path / "specs-slim.pickle",
        tmp_path / "specs.meta.bin",
        tmp_path / "specs.meta.idx.pickle",
    )


def test_slim_split_preserves_scan_fields(tmp_path):
    spec = dataclasses.replace(_full_spec(_module()), linker_references=(_reference(),))
    (slim,), store = _write_specs(tmp_path, (spec,))
    assert slim.linker_reference_count == 1
    assert slim.has_linker_references
    assert slim.linker_references == ()
    for field_name in (
        "source_path", "compiler_name", "module_name", "regex_source", "scan_source",
        "checked_match_length", "module_length", "public_names", "required_literal",
    ):
        assert getattr(slim, field_name) == getattr(spec, field_name)
    names, references = store.record(slim.meta_index)
    assert names == spec.referenced_names
    assert references == spec.linker_references


def test_slim_artifacts_round_trip(tmp_path):
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("90" * 32 + " 00 0000 0001 :0000 function\n---\n")
    omf_pat.load_cached_pat_regex_specs(catalog, tmp_path / "specs")
    omf_pat.load_slim_pat_match_specs.cache_clear()
    slim, store = omf_pat.load_slim_pat_match_specs(catalog, tmp_path / "specs")
    assert len(slim) == 1
    omf_pat.load_slim_pat_match_specs.cache_clear()
    slim2, store2 = omf_pat.load_slim_pat_match_specs(catalog, tmp_path / "specs")
    assert slim2 == slim
    assert store2 is not store


def test_match_pat_modules_slim_parity(tmp_path):
    spec = _full_spec(_module())
    (slim,), store = _write_specs(tmp_path, (spec,))
    image = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3") + b"\x90"
    full = omf_pat.match_pat_modules(image, 0x10000, (spec,), backend="python_regex")
    lazy = omf_pat.match_pat_modules(
        image, 0x10000, (slim,), backend="python_regex", spec_meta_store=store
    )
    assert lazy.code_labels == full.code_labels
    assert lazy.code_ranges == full.code_ranges
    assert lazy.matched_compiler_names == full.matched_compiler_names
    assert lazy.linker_evidence == full.linker_evidence


def test_match_deferred_provenance_identical(tmp_path):
    spec = _full_spec(_module())
    image = b"\x90" * 4 + bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3")
    first = omf_pat.match_pat_modules(image, 0x1000, (spec,), backend="python_regex")
    second = omf_pat.match_pat_modules(image, 0x1000, (spec,), backend="python_regex")
    assert first.code_labels == second.code_labels
    assert first.code_labels == {0x1004: "runtime"}


def test_linker_spec_without_store_refuses_loudly(tmp_path):
    spec = dataclasses.replace(_full_spec(_module()), linker_references=(_reference(),))
    (slim,), _store = _write_specs(tmp_path, (spec,))
    image = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3")
    with pytest.raises(ValueError, match="meta store"):
        omf_pat.match_pat_modules(image, 0x10000, (slim,), backend="python_regex")
