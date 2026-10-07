"""Declared functionality-state policy preserves complete bounded table effects."""

from dataclasses import FrozenInstanceError

import pytest

import tools.dosunit.runtime.real16_program_video_state as vs
from tools.dosunit.runtime.real16_replay_model import SegOffset

STATIC = SegOffset(0xC000, 0x2A66)
ENTRY = SegOffset(0xF000, 0xF065)
DECLARED = {
    "static_state": STATIC,
    "dcc": 0x0008,
    "colours": 0x0010,
    "pages": 8,
    "scanline": 2,
    "misc": 0x21,
    "memory": 3,
    "entry": ENTRY,
}
BDA = bytes((3, 0x50, 0, 0, 0x10, 0, 0, 0, 0x15, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 7, 6, 0, 0xD4, 3, 0x29, 0x30))
ROWS = bytes((0x18, 0x10, 0x00))


def policy(**overrides):
    fields = {**DECLARED}
    fields.update(overrides)
    return vs.VideoStatePolicy(**fields)


def table(**overrides):
    return vs.video_state_table(policy(**overrides), BDA, ROWS)


@pytest.mark.parametrize(("field", "values"), [
    ("dcc", (0, 0x0008, 0xFFFF)),
    ("colours", (0, 1, 2, 4, 16, 256, 0xFFFF)),
    ("pages", (1, 8, 0xFF)),
    ("scanline", (0, 1, 2, 3)),
    ("misc", (0x01, 0x21)),
    ("memory", (0, 1, 2, 3)),
])
def test_policy_accepts_declared_static_domain(field, values):
    for value in values:
        assert getattr(policy(**{field: value}), field) == value


@pytest.mark.parametrize("entry", [SegOffset(0, 0), SegOffset(0xFFFF, 0xFFFF)])
@pytest.mark.parametrize("field", ["static_state", "entry"])
def test_policy_accepts_any_explicit_word_domain_pointer(field, entry):
    assert getattr(policy(**{field: entry}), field) == entry


@pytest.mark.parametrize("bad", [True, False, -1, 0x10000, 1.5, "8", "0x08", None])
@pytest.mark.parametrize("field", ["dcc", "colours"])
def test_policy_rejects_nonword_static_fields(field, bad):
    with pytest.raises(ValueError):
        policy(**{field: bad})


@pytest.mark.parametrize("bad", [True, False, -1, 0, 256, 1.5, "8", None])
def test_policy_rejects_zero_and_nonbyte_pages(bad):
    with pytest.raises(ValueError):
        policy(pages=bad)


@pytest.mark.parametrize("bad", [True, False, -1, 4, 255, 1.5, "2", None])
def test_policy_rejects_undefined_scanline_codes(bad):
    with pytest.raises(ValueError):
        policy(scanline=bad)


@pytest.mark.parametrize("bad", [True, False, -1, 0, 0x02, 0x11, 0x20, 0x22, 0xFF, 1.5, "33", None])
def test_policy_rejects_misc_values_native_cannot_write(bad):
    with pytest.raises(ValueError):
        policy(misc=bad)


@pytest.mark.parametrize("bad", [True, False, -1, 4, 64, 255, 1.5, "3", None])
def test_policy_rejects_undefined_memory_indicators(bad):
    with pytest.raises(ValueError):
        policy(memory=bad)


@pytest.mark.parametrize("field", ["static_state", "entry"])
@pytest.mark.parametrize("bad", [
    None, 5, "entry", (0xF000, 0xF065), {"segment": 0xF000, "offset": 0xF065},
    SegOffset(True, 0), SegOffset(0, False), SegOffset(1.5, 0),  # type: ignore[arg-type]
])
def test_policy_rejects_nontyped_and_loose_coordinate_pointers(field, bad):
    with pytest.raises(ValueError):
        policy(**{field: bad})


def test_policy_has_no_defaults_and_is_immutable():
    with pytest.raises(TypeError):
        vs.VideoStatePolicy()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        vs.VideoStatePolicy(static_state=STATIC, entry=ENTRY)  # type: ignore[call-arg]
    with pytest.raises(FrozenInstanceError):
        policy().dcc = 9  # pyright: ignore[reportAttributeAccessIssue]


def test_table_layout_matches_documented_field_offsets():
    built = table()
    expected = (
        bytes((0x66, 0x2A, 0x00, 0xC0))
        + BDA
        + bytes((0x19, 0x10, 0x00))
        + bytes((0x08, 0x00, 0x10, 0x00, 0x08, 0x02, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x03))
        + bytes(0x40 - 0x32)
    )
    assert built == expected
    assert len(built) == vs.VIDEO_STATE_TABLE_BYTES == 0x40


def test_table_copies_bda_verbatim_and_wraps_row_count():
    built = table()
    assert built[0x04:0x22] == BDA
    assert built[0x22] == (ROWS[0] + 1) & 0xFF
    assert built[0x23:0x25] == ROWS[1:3]


@pytest.mark.parametrize(("raw", "stored"), [(0x00, 0x01), (0x18, 0x19), (0xFE, 0xFF), (0xFF, 0x00)])
def test_table_row_count_wraps_at_byte(raw, stored):
    built = vs.video_state_table(policy(), BDA, bytes((raw, 0xAA, 0x55)))
    assert built[0x22] == stored
    assert built[0x23:0x25] == bytes((0xAA, 0x55))


@pytest.mark.parametrize("index", [0, 15, 29])
def test_table_tracks_each_live_bda_byte(index):
    mutated = bytearray(BDA)
    mutated[index] ^= 0xFF
    built = vs.video_state_table(policy(), bytes(mutated), ROWS)
    assert built[0x04 + index] == mutated[index]
    assert built[0x04:0x22] == bytes(mutated)


@pytest.mark.parametrize("field_offset", [
    ("dcc", 0x25), ("colours", 0x27), ("pages", 0x29),
    ("scanline", 0x2A), ("misc", 0x2D), ("memory", 0x31),
])
def test_table_writes_each_declared_field_at_its_offset(field_offset):
    field, offset = field_offset
    size = 2 if field in ("dcc", "colours") else 1
    built = table()
    expected = DECLARED[field].to_bytes(size, "little")
    assert built[offset:offset + size] == expected


def test_table_zero_fills_reserved_bytes_even_with_maximal_fields():
    maximal = {"dcc": 0xFFFF, "colours": 0xFFFF, "pages": 0xFF, "scanline": 3, "misc": 0x21, "memory": 3}
    built = vs.video_state_table(policy(**maximal), bytes(30), bytes(3))
    for offset in (0x2B, 0x2C, 0x2E, 0x2F, 0x30, 0x32, *range(0x33, 0x40)):
        assert built[offset] == 0


@pytest.mark.parametrize("bda", [
    bytes(29), bytes(31), bytes(0), bytearray(30), list(range(30)), "x" * 30, None, 5,
])
def test_table_requires_exact_thirty_live_bda_bytes(bda):
    with pytest.raises(ValueError):
        vs.video_state_table(policy(), bda, ROWS)  # type: ignore[arg-type]


@pytest.mark.parametrize("rows", [
    bytes(2), bytes(4), bytes(0), bytearray(3), [0x18, 0x10, 0], "abc", None, 5,
])
def test_table_requires_exact_three_live_row_bytes(rows):
    with pytest.raises(ValueError):
        vs.video_state_table(policy(), BDA, rows)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_policy", [None, "bios", 5, DECLARED])
def test_table_and_event_require_typed_policy(bad_policy):
    with pytest.raises(ValueError):
        vs.video_state_table(bad_policy, BDA, ROWS)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        vs.video_state_event_data(bad_policy, BDA, ROWS)  # type: ignore[arg-type]


def test_event_data_retains_selector_and_complete_table():
    data = vs.video_state_event_data(policy(), BDA, ROWS)
    assert len(data) == vs.VIDEO_STATE_EVENT_BYTES == 0x44
    assert data[:2] == vs.VIDEO_STATE_PREFIX == bytes((0x10, 0x1B))
    assert data[2:4] == bytes(2)
    assert data[4:] == table()
    assert vs.video_state_receipt_complete(data)


def test_receipt_stays_complete_for_arbitrary_table_payload():
    built = vs.VIDEO_STATE_PREFIX + bytes(2) + bytes(range(0x40))
    assert vs.video_state_receipt_complete(built)


@pytest.mark.parametrize("bad", [
    bytes(0), bytes(4), bytes(0x43), bytes(0x45),
    bytearray(vs.VIDEO_STATE_PREFIX + bytes(0x42)),
    vs.VIDEO_STATE_PREFIX + b"\x01\x00" + bytes(0x40),
    vs.VIDEO_STATE_PREFIX + b"\x00\x01" + bytes(0x40),
    bytes((0x11, 0x1B)) + bytes(0x42),
    bytes((0x10, 0x0F)) + bytes(0x42),
    bytes((0x10, 0x1B, 0x00, 0x00)) + bytes(0x3F),
    "receipt", None, 68,
])
def test_receipt_rejects_malformed_or_unsupported_selector(bad):
    assert not vs.video_state_receipt_complete(bad)  # type: ignore[arg-type]


def test_event_propagates_input_validation():
    with pytest.raises(ValueError):
        vs.video_state_event_data(policy(), bytes(29), ROWS)
    with pytest.raises(ValueError):
        vs.video_state_event_data(policy(), BDA, bytes(4))


def test_document_projects_every_declared_field():
    document = vs.video_state_document(policy())
    assert document == {
        "static_state": {"segment": 0xC000, "offset": 0x2A66},
        "dcc": 0x0008,
        "colours": 0x0010,
        "pages": 8,
        "scanline": 2,
        "misc": 0x21,
        "memory": 3,
        "entry": {"segment": 0xF000, "offset": 0xF065},
    }
    assert vs.video_state_document(None) is None
    for bad in (DECLARED, "bios", 5):
        with pytest.raises(ValueError):
            vs.video_state_document(bad)  # type: ignore[arg-type]


def test_parse_round_trips_document_identity():
    assert vs.parse_video_state_policy(vs.video_state_document(policy())) == policy()
    assert vs.parse_video_state_policy(None) is None


@pytest.mark.parametrize("missing", sorted(DECLARED))
def test_parse_rejects_missing_fields(missing):
    document = vs.video_state_document(policy())
    del document[missing]
    with pytest.raises(ValueError):
        vs.parse_video_state_policy(document)


@pytest.mark.parametrize("bad", [
    {**vs.video_state_document(policy()), "extra": 0},
    {**vs.video_state_document(policy()), "mode": 3},
    "bios", 5, [], (0x10, 0x1B), True,
])
def test_parse_rejects_unknown_or_nondict_shapes(bad):
    with pytest.raises(ValueError):
        vs.parse_video_state_policy(bad)


@pytest.mark.parametrize("field", ["static_state", "entry"])
@pytest.mark.parametrize("bad", [
    None, 5, "0xF000:0xF065", (0xF000, 0xF065), {},
    {"segment": 0xF000}, {"offset": 0xF065},
    {"segment": 0xF000, "offset": 0xF065, "extra": 0},
    {"segment": True, "offset": 0xF065}, {"segment": 0xF000, "offset": -1},
    {"segment": 0x10000, "offset": 0}, {"segment": 1.5, "offset": 0},
])
def test_parse_rejects_malformed_segmented_pointers(field, bad):
    document = vs.video_state_document(policy())
    document[field] = bad
    with pytest.raises(ValueError):
        vs.parse_video_state_policy(document)


@pytest.mark.parametrize(("field", "bad"), [
    ("dcc", True), ("dcc", "x"), ("dcc", -1), ("dcc", 0x10000), ("dcc", 1.5),
    ("colours", False), ("colours", 0x10000), ("colours", -1),
    ("pages", 0), ("pages", 256), ("pages", True), ("pages", -1),
    ("scanline", 4), ("scanline", -1), ("scanline", True),
    ("misc", 0x22), ("misc", 0), ("misc", True), ("misc", 0xFF),
    ("memory", 4), ("memory", 255), ("memory", True), ("memory", -1),
])
def test_parse_rejects_out_of_domain_field_values(field, bad):
    document = vs.video_state_document(policy())
    document[field] = bad
    with pytest.raises(ValueError):
        vs.parse_video_state_policy(document)


def test_parse_accepts_hex_and_decimal_manifest_strings():
    document = vs.video_state_document(policy())
    document["static_state"] = {"segment": "0xC000", "offset": "0x2a66"}
    document["entry"] = {"segment": "61440", "offset": "0xF065"}
    document["dcc"] = "0x08"
    document["pages"] = "8"
    assert vs.parse_video_state_policy(document) == policy()

