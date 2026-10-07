"""Skipping a library body must not extend its neighboring application body."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from inertia.cli.lst_extract import LSTMetadata
import inertia.cli.cli_function_discovery as discovery
import inertia.cli.discovery_candidate_ranges as ranges_module
from inertia.cli.discovery_candidate_ranges import pre_entry_candidate_ranges
from inertia.cli.sidecar_metadata import _signature_matched_code_addrs


@pytest.mark.parametrize("signatures", [(), (0x900, 0x1200, 0x1300), (0x1000, 0x1000)])
def test_external_and_duplicate_boundaries_do_not_change_windows(signatures):
    assert pre_entry_candidate_ranges([0x1100, 0x1000, 0x1100], signatures, end=0x1200) == {
        0x1000: (0x1000, 0x1100), 0x1100: (0x1100, 0x1200),
    }


def test_invalid_selected_boundary_fails_explicitly():
    with pytest.raises(ValueError, match="must precede"):
        pre_entry_candidate_ranges([0x1200], (), end=0x1200)
    assert pre_entry_candidate_ranges([], [0x1000], end=0x1200) == {}


def test_signature_hit_inside_explicit_procedure_does_not_split_caller_range():
    """A library signature inside a COD procedure cannot truncate its caller scan."""
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "main", 0x1180: "library_hit", 0x1200: "library_start"},
        code_ranges={0x1100: (0x1100, 0x1200)},
        function_entry_addrs=frozenset({0x1100}),
        signature_code_addrs=frozenset({0x1180, 0x1200}),
        cod_proc_kinds={0x1100: "NEAR"},
    )

    assert _signature_matched_code_addrs(metadata) == frozenset({0x1200})


def test_library_entries_bound_recovery_and_caller_ranges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Without a binary body proof, recovery and caller scans keep library limits."""
    project = SimpleNamespace(
        entry=0x1200,
        loader=SimpleNamespace(main_object=SimpleNamespace(
            binary=tmp_path / "APP.EXE", linked_base=0x1000, max_addr=0x1300,
        )),
        _inertia_lst_metadata=LSTMetadata(
            data_labels={}, code_labels={0x1020: "runtime_a", 0x1180: "runtime_b"},
            signature_code_addrs=frozenset({0x1020, 0x1180}),
            source_format="signature_catalog",
        ),
    )
    monkeypatch.setattr(discovery, "_binary_padding_entry_aliases_8616", lambda project, addr: (addr,))
    monkeypatch.setattr(
        ranges_module, "exact_function_range_boundary_8616",
        lambda _project, _start, _end: None,
    )
    monkeypatch.setattr(discovery, "_entry_linear_caller_range_8616", lambda *args, **kwargs: None)
    monkeypatch.setattr(discovery, "_collect_caller_return_use_for_entry_aliases_8616", lambda *args: None)
    attempts = {}

    def recover(project, *, candidate_addr, exact_region, **kwargs):
        attempts[candidate_addr] = exact_region
        return SimpleNamespace(), SimpleNamespace(addr=candidate_addr)

    monkeypatch.setattr(discovery, "_recover_candidate_with_timeout", recover)
    recovered, evidence = discovery._recover_pre_entry_source_catalog_8616(
        project, source_seeds=[0x1000, 0x1100], timeout=10,
    )
    expected = {0x1000: (0x1000, 0x1020), 0x1100: (0x1100, 0x1180)}
    assert attempts == expected
    assert [function.addr for cfg, function in recovered] == [0x1000, 0x1100]
    assert evidence.complete
    assert discovery._pre_entry_source_function_ranges_8616(project, [0x1000, 0x1100]) == tuple(expected.values())
