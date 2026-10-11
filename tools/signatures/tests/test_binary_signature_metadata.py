"""Binary signature evidence remains available when local hints are disabled."""

from types import SimpleNamespace
from unittest.mock import Mock

import angr
import pytest

import inertia.cli.binary_signature_metadata as signatures
import inertia.cli.cli_core as cli_core
from inertia.cli.lst_extract import LSTMetadata
from inertia.cli.sidecar_metadata import _visible_code_labels


@pytest.mark.parametrize("matched", [False, True])
def test_signature_loader_keeps_debug_fields_empty(tmp_path, monkeypatch, matched):
    binary = tmp_path / "APP.EXE"
    for suffix in (".COD", ".MAP", ".LST", ".C"):
        binary.with_suffix(suffix).write_text("must not be consumed")
    project = angr.load_shellcode(b"\xc3", arch="x86")
    project._inertia_lst_metadata = "stale"
    labels = {0x10100: "runtime"} if matched else {}
    ranges = {0x10100: (0x10100, 0x10120)} if matched else {}
    detect = Mock(return_value=(labels, ranges, ("signature_catalog",) if matched else ()))
    monkeypatch.setattr(signatures, "_detect_flair_metadata", detect)
    catalog = tmp_path / "catalog.pat"
    metadata = signatures.load_binary_signature_metadata(
        binary, project, pat_backend="python_regex", signature_catalog=catalog,
    )
    detect.assert_called_once_with(binary, project, pat_backend="python_regex", signature_catalog=catalog)
    assert project._inertia_lst_metadata is metadata
    assert all(project.kb.labels[addr] == name for addr, name in labels.items())
    if not matched:
        assert metadata is None
        return
    assert metadata.signature_code_addrs == frozenset(labels)
    assert metadata.code_ranges == ranges
    assert metadata.signature_code_ranges == ranges
    assert metadata.cod_path is None
    assert not metadata.data_labels
    assert not metadata.cod_proc_kinds
    assert not metadata.debug_symbols
    assert not metadata.debug_source_files
    assert _visible_code_labels(metadata) == {}


def test_cli_source_free_setup_loads_signatures_not_sidecars(tmp_path, monkeypatch, capsys):
    project = SimpleNamespace()
    args = SimpleNamespace(
        binary=tmp_path / "APP.EXE", proc=None, declared_call_effects=(),
        blob=False, base_addr=0x1000,
        entry_point=0x1000, c_target="portable-flat", trace_c_stages=False,
        dump_layers=False, dump_layer_dir=None, dump_layer_filter=None,
        ignore_local_sidecar_hints=True, pat_backend="python_regex",
    )
    sentinel = LSTMetadata(
        data_labels={}, code_labels={0x100: "runtime"},
        signature_code_addrs=frozenset({0x100}), source_format="signature_catalog",
    )
    load_signatures = Mock(return_value=sentinel)
    sidecars = Mock(side_effect=AssertionError("source-free setup read sidecars"))
    monkeypatch.setattr(cli_core, "_build_project", lambda *args, **kwargs: project)
    monkeypatch.setattr(cli_core, "load_binary_signature_metadata", load_signatures)
    monkeypatch.setattr(cli_core, "_load_lst_metadata", sidecars)
    monkeypatch.setattr(cli_core, "_set_tail_validation_runtime_enabled", lambda *args: None)
    monkeypatch.setattr(cli_core, "_tail_validation_enabled_for_run", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli_core, "_apply_binary_specific_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli_core, "_recovery_evidence_line", lambda *args: "binary signatures")
    catalog = tmp_path / "catalog.pat"
    setup = cli_core._prepare_main_project_8616(args, catalog)
    assert setup.lst_metadata is sentinel
    load_signatures.assert_called_once_with(args.binary, project, pat_backend="python_regex", signature_catalog=catalog)
    sidecars.assert_not_called()
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in capsys.readouterr().out


def test_signature_extents_survive_cache_without_debug_range_promotion():
    from inertia.cli.sidecar_cache import _deserialize_lst_metadata, _serialize_lst_metadata

    metadata = LSTMetadata(
        data_labels={}, code_labels={0x1000: "runtime"},
        code_ranges={0x1000: (0x1000, 0x2000)},
        signature_code_ranges={0x1000: (0x1000, 0x1020)},
        signature_code_addrs=frozenset({0x1000}),
    )
    restored = _deserialize_lst_metadata(_serialize_lst_metadata(metadata))
    assert restored.signature_code_ranges == {0x1000: (0x1000, 0x1020)}
    assert restored.code_ranges == {0x1000: (0x1000, 0x2000)}
    old_payload = _serialize_lst_metadata(metadata)
    del old_payload["signature_code_ranges"]
    assert _deserialize_lst_metadata(old_payload).signature_code_ranges == {}


def test_startup_prefix_does_not_invent_body_range():
    from inertia.cli.sidecar_parsers import _merge_startup_flair_evidence_8616
    from tools.signatures.omf_pat import LocalPatMatchResult

    labels, ranges = {}, {}
    project = SimpleNamespace(entry=0x1000)
    prefix = SimpleNamespace(public_names=((0, "runtime"),), compiler_tag="test", pat_path="test.pat")
    _merge_startup_flair_evidence_8616(
        project, (prefix,), LocalPatMatchResult({}, {}, ()), labels, ranges, [], [])
    assert labels == {0x1000: "runtime"}
    assert ranges == {}


def test_sidecar_merge_keeps_verified_extent_separate_from_listing(monkeypatch, tmp_path):
    import inertia.cli.sidecar_metadata as sidecars

    labels = {0x1000: "source_name"}
    bounds = {0x1000: (0x1000, 0x2000)}
    verified = {}
    monkeypatch.setattr(sidecars, "_detect_flair_metadata", lambda *args, **kwargs: (
        {0x1000: "binary_name"}, {0x1000: (0x1000, 0x1020)}, ("signature_catalog",),
    ))
    addresses = sidecars._load_flair_sidecar_8616(
        tmp_path / "app.exe", SimpleNamespace(), pat_backend=None, signature_catalog=None,
        code_labels=labels, code_ranges=bounds, source_formats=[], signature_code_ranges=verified,
    )
    assert addresses == {0x1000}
    assert bounds == {0x1000: (0x1000, 0x2000)}
    assert verified == {0x1000: (0x1000, 0x1020)}


def test_rebase_preserves_separate_signature_extent():
    from inertia.cli.sidecar_cache import _maybe_rebase_stale_absolute_metadata

    metadata = LSTMetadata(
        data_labels={}, code_labels={0: "entry"}, code_ranges={0: (0, 256)},
        signature_code_ranges={0: (0, 16)}, signature_code_addrs=frozenset({0}),
        absolute_addrs=True, source_format="cod_listing+signature_catalog",
    )
    project = SimpleNamespace(entry=0x1000, loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000)))
    rebased = _maybe_rebase_stale_absolute_metadata(metadata, project)
    assert rebased.code_ranges == {0x1000: (0x1000, 0x1100)}
    assert rebased.signature_code_ranges == {0x1000: (0x1000, 0x1010)}
