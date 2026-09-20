"""OMF LOCAT stores its control bits in the first byte, unlike Intel words.

Specification: https://openwatcom.org/ftp/devel/docs/omf.pdf, FIXUP Subrecord.
"""

import pytest

from omf_pat import _OMFDataRecordContext, _parse_fixupp_refs


@pytest.mark.parametrize("data_offset", [0, 2, 0x80, 0x102, 0x3FE])
def test_fixupp_location_uses_control_byte_first(data_offset):
    # Segment-relative word, frame=target, target=external 1, no displacement.
    locat = 0xC400 | data_offset
    payload = locat.to_bytes(2, "big") + bytes.fromhex("56 01")
    refs = _parse_fixupp_refs(payload, _OMFDataRecordContext(1, 0x200, 0x400), ["", "symbol"], {}, {})
    assert len(refs) == 1
    assert (refs[0].seg_index, refs[0].offset, refs[0].width, refs[0].name) == (
        1, 0x200 + data_offset, 2, "symbol",
    )
