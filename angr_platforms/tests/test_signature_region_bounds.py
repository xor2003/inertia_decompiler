"""Library labels cannot claim the unmatched space between signatures."""

import pytest
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.sidecar_metadata import _lst_code_region


@pytest.mark.parametrize("explicit_range", [False, True])
def test_gap_after_signature_is_not_its_function(explicit_range):
    metadata = LSTMetadata(
        data_labels={}, code_labels={0x1000: "runtime_a", 0x1100: "runtime_b"},
        code_ranges={0x1000: (0x1000, 0x1020)} if explicit_range else {},
        signature_code_addrs=frozenset({0x1000, 0x1100}),
        source_format="signature_catalog", absolute_addrs=True,
    )
    assert _lst_code_region(metadata, 0x1080) is None
    assert _lst_code_region(metadata, 0x1100) is None
    if explicit_range:
        assert _lst_code_region(metadata, 0x1010) == (0x1000, 0x1020)


def test_listing_label_can_still_use_neighbor_as_boundary():
    metadata = LSTMetadata(
        data_labels={}, code_labels={0x1000: "application", 0x1100: "runtime"},
        signature_code_addrs=frozenset({0x1100}), source_format="cod_listing+signature_catalog",
    )
    assert _lst_code_region(metadata, 0x1080) == (0x1000, 0x1100)
