from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.cod_extract import CODListingMetadata
import inertia.cli.sidecar_metadata as sidecar_metadata


def test_cod_listing_does_not_relocate_existing_public_label(monkeypatch, tmp_path):
    binary = tmp_path / "SAMPLE.EXE"
    binary.write_bytes(b"MZ")
    binary.with_suffix(".COD").write_text("", encoding="utf-8")

    monkeypatch.setattr(
        sidecar_metadata,
        "_parse_cod_sidecar_metadata",
        lambda *_args, **_kwargs: CODListingMetadata(
            code_labels={0x107B8: "Swaps"},
            code_ranges={0x107B8: (0x107B8, 0x107D0)},
            proc_kinds={0x107B8: "NEAR"},
        ),
    )
    monkeypatch.setattr(
        sidecar_metadata,
        "_reconcile_cod_listing_with_codeview",
        lambda cod_listing, _codeview_code, _codeview_ranges: cod_listing,
    )
    monkeypatch.setattr(
        sidecar_metadata,
        "_detect_flair_metadata",
        lambda *_args, **_kwargs: ({}, {}, ()),
    )

    code_labels = {0x10794: "Swaps"}
    code_ranges = {}
    cod_proc_kinds = {}

    sidecar_metadata._load_cod_mzre_flair_sidecars(
        binary,
        SimpleNamespace(),
        load_base_linear=0x10000,
        code_labels=code_labels,
        data_labels={},
        code_ranges=code_ranges,
        source_formats=[],
        codeview_code={},
        codeview_ranges={},
        pat_backend=None,
        signature_catalog=None,
        cod_proc_kinds=cod_proc_kinds,
    )

    assert code_labels[0x10794] == "Swaps"
    assert 0x107B8 not in code_labels
    assert code_ranges[0x10794] == (0x10794, 0x107D0)
    assert cod_proc_kinds[0x10794] == "NEAR"


def test_codeview_reconciliation_preserves_cod_proc_kind(monkeypatch, tmp_path):
    binary = tmp_path / "SAMPLE.EXE"
    binary.write_bytes(b"MZ")
    binary.with_suffix(".COD").write_text("", encoding="utf-8")

    monkeypatch.setattr(
        sidecar_metadata,
        "_parse_cod_sidecar_metadata",
        lambda *_args, **_kwargs: CODListingMetadata(
            code_labels={0x107B8: "Swaps"},
            code_ranges={0x107B8: (0x107B8, 0x107D0)},
            proc_kinds={0x107B8: "NEAR"},
        ),
    )
    monkeypatch.setattr(
        sidecar_metadata,
        "_detect_flair_metadata",
        lambda *_args, **_kwargs: ({}, {}, ()),
    )

    code_labels = {0x10794: "Swaps"}
    code_ranges = {0x10794: (0x10794, 0x107D0)}
    cod_proc_kinds = {}

    sidecar_metadata._load_cod_mzre_flair_sidecars(
        binary,
        SimpleNamespace(),
        load_base_linear=0x10000,
        code_labels=code_labels,
        data_labels={},
        code_ranges=code_ranges,
        source_formats=[],
        codeview_code={0x10794: "Swaps"},
        codeview_ranges={0x10794: (0x10794, 0x107D0)},
        pat_backend=None,
        signature_catalog=None,
        cod_proc_kinds=cod_proc_kinds,
    )

    assert code_labels == {0x10794: "Swaps"}
    assert code_ranges == {0x10794: (0x10794, 0x107D0)}
    assert cod_proc_kinds == {0x10794: "NEAR"}
