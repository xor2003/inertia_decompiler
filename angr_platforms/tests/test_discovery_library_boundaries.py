"""Skipping a library body must not extend its neighboring application body."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli_function_discovery as discovery
from inertia_decompiler.discovery_candidate_ranges import pre_entry_candidate_ranges


@pytest.mark.parametrize("signatures", [(), (0x900, 0x1200, 0x1300), (0x1000, 0x1000)])
def test_external_and_duplicate_boundaries_do_not_change_windows(signatures):
    assert pre_entry_candidate_ranges([0x1100, 0x1000, 0x1100], signatures, end=0x1200) == {
        0x1000: (0x1000, 0x1100), 0x1100: (0x1100, 0x1200),
    }


def test_invalid_selected_boundary_fails_explicitly():
    with pytest.raises(ValueError, match="must precede"):
        pre_entry_candidate_ranges([0x1200], (), end=0x1200)
    assert pre_entry_candidate_ranges([], [0x1000], end=0x1200) == {}


def test_library_entries_bound_recovery_and_caller_ranges(monkeypatch, tmp_path):
    project = SimpleNamespace(
        entry=0x1200,
        loader=SimpleNamespace(main_object=SimpleNamespace(
            binary=tmp_path / "APP.EXE", linked_base=0x1000, max_addr=0x300,
        )),
        _inertia_lst_metadata=LSTMetadata(
            data_labels={}, code_labels={0x1020: "runtime_a", 0x1180: "runtime_b"},
            signature_code_addrs=frozenset({0x1020, 0x1180}),
            source_format="signature_catalog",
        ),
    )
    monkeypatch.setattr(discovery, "_binary_padding_entry_aliases_8616", lambda project, addr: (addr,))
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
