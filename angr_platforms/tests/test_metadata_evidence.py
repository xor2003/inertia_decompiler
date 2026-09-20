"""Binary signature evidence is not source/debug assistance."""

from dataclasses import replace
from pathlib import Path

import pytest
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.metadata_evidence import has_only_binary_signatures
from inertia_decompiler.work_items import recovery_evidence_line


def _signatures():
    return LSTMetadata(
        data_labels={}, code_labels={0x100: "runtime"},
        code_ranges={0x100: (0x100, 0x110)},
        signature_code_addrs=frozenset({0x100}), source_format="signature_catalog",
    )


def test_signature_only_evidence_is_reported_as_binary():
    metadata = _signatures()
    assert has_only_binary_signatures(metadata)
    message = recovery_evidence_line(Path("APP.EXE"), metadata)
    assert "pure binary recovery mode" in message
    assert "binary signatures" in message
    assert "sidecar-assisted" not in message


@pytest.mark.parametrize("fields", [
    {"data_labels": {4: "global"}},
    {"code_labels": {0x100: "runtime", 0x200: "application"}},
    {"code_ranges": {0x200: (0x200, 0x220)}},
    {"function_entry_addrs": frozenset({0x200})},
    {"cod_path": "APP.COD"},
    {"debug_source_files": ("APP.C",)},
    {"debug_line_map": {0x100: (0, 7)}},
    {"struct_names": ("state",)},
])
def test_source_evidence_is_never_reported_as_signature_only(fields):
    assert not has_only_binary_signatures(replace(_signatures(), **fields))


@pytest.mark.parametrize("metadata", [None, object(), LSTMetadata({}, {})])
def test_missing_or_unknown_record_does_not_prove_signature_only(metadata):
    assert not has_only_binary_signatures(metadata)
