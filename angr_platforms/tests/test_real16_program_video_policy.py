"""Video-state query contract: strict declared bytes, segmented entry, complete receipts."""

from dataclasses import FrozenInstanceError

import pytest

from tools.dosunit.real16_program_video import (
    VIDEO_QUERY_EVENT_BYTES,
    VIDEO_QUERY_PREFIX,
    VideoQueryPolicy,
    parse_video_policy,
    video_policy_document,
    video_query_event_data,
    video_query_receipt_complete,
)
from tools.dosunit.real16_replay_model import SegOffset

ENTRY = SegOffset(0xF000, 0xF065)
DECLARED = {"mode": 3, "columns": 80, "page": 0}


def policy(**overrides):
    fields = {**DECLARED, "entry": ENTRY}
    fields.update(overrides)
    return VideoQueryPolicy(**fields)


@pytest.mark.parametrize(("mode", "columns", "page"), [
    (0, 0, 0), (255, 255, 255), (3, 80, 0), (0x03, 0x50, 0x07),
])
def test_policy_accepts_any_explicit_byte_domain_state(mode, columns, page):
    accepted = policy(mode=mode, columns=columns, page=page)
    assert (accepted.mode, accepted.columns, accepted.page) == (mode, columns, page)
    assert accepted.entry == ENTRY


@pytest.mark.parametrize("entry", [SegOffset(0, 0), SegOffset(0xFFFF, 0xFFFF)])
def test_policy_accepts_any_explicit_word_domain_entry(entry):
    assert policy(entry=entry).entry == entry


@pytest.mark.parametrize("field", ["mode", "columns", "page"])
@pytest.mark.parametrize("bad", [True, False, -1, 256, 0x100, 1.5, "3", "0x50", None])
def test_policy_rejects_bool_and_nonbyte_state_fields(field, bad):
    with pytest.raises(ValueError):
        policy(**{field: bad})


@pytest.mark.parametrize("entry", [
    None, 5, "entry", (0xF000, 0xF065), {"segment": 0xF000, "offset": 0xF065},
    SegOffset(True, 0), SegOffset(0, False), SegOffset(1.5, 0),  # type: ignore[arg-type]
])
def test_policy_rejects_nontyped_and_loose_coordinate_entries(entry):
    with pytest.raises(ValueError):
        policy(entry=entry)


def test_policy_has_no_defaults_and_is_immutable():
    with pytest.raises(TypeError):
        VideoQueryPolicy()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        VideoQueryPolicy(mode=3, columns=80, page=0)  # type: ignore[call-arg]
    with pytest.raises(FrozenInstanceError):
        policy().mode = 4  # pyright: ignore[reportAttributeAccessIssue]


def test_event_data_retains_selector_and_all_three_answer_bytes():
    data = video_query_event_data(policy())
    assert len(data) == VIDEO_QUERY_EVENT_BYTES == 5
    assert data[:2] == VIDEO_QUERY_PREFIX == bytes((0x10, 0x0F))
    assert data == bytes((0x10, 0x0F, 3, 80, 0))
    assert video_query_receipt_complete(data)
    for bad_policy in (None, "bios", 5, DECLARED):
        with pytest.raises(ValueError):
            video_query_event_data(bad_policy)  # type: ignore[arg-type]


@pytest.mark.parametrize(("field", "index", "changed"), [
    ("mode", 2, 7), ("columns", 3, 40), ("page", 4, 2),
])
def test_each_answer_byte_mutation_is_retained_by_the_receipt(field, index, changed):
    base = video_query_event_data(policy())
    mutated = video_query_event_data(policy(**{field: changed}))
    assert mutated != base
    assert mutated[index] == changed
    # Only the mutated answer byte differs; the selector prefix is unchanged.
    assert mutated[:index] == base[:index] and mutated[index + 1:] == base[index + 1:]
    # The receipt retains every answer byte: a changed byte is still complete,
    # observable evidence, never masked or dropped by the predicate.
    assert video_query_receipt_complete(mutated)


@pytest.mark.parametrize("data", [
    None, b"", "video", bytearray(VIDEO_QUERY_PREFIX + bytes(3)),
    bytes(4), bytes(5), bytes(6), VIDEO_QUERY_PREFIX, VIDEO_QUERY_PREFIX + bytes(2),
    VIDEO_QUERY_PREFIX + bytes(4), bytes((0x11, 0x0F, 3, 80, 0)),
    bytes((0x10, 0x0E, 3, 80, 0)), bytes((0x21, 0x30, 3, 80, 0)),
])
def test_malformed_prefix_and_length_receipts_reject(data):
    assert not video_query_receipt_complete(data)


def test_document_is_explicit_and_round_trips_through_strict_parsing():
    document = video_policy_document(policy())
    assert document == {
        "mode": 3, "columns": 80, "page": 0,
        "entry": {"segment": 0xF000, "offset": 0xF065},
    }
    assert parse_video_policy(document) == policy()
    assert video_policy_document(None) is None
    assert parse_video_policy(None) is None
    for bad in ("bios", 5, DECLARED):
        with pytest.raises(ValueError):
            video_policy_document(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("declaration", [
    {},
    {"mode": 3, "columns": 80, "page": 0},
    {"mode": 3, "columns": 80, "page": 0, "entry": {"segment": 0xF000}},
    {"mode": 3, "columns": 80, "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065,
                                                   "alias": 0}},
    {"mode": 3, "columns": 80, "page": 0, "entry": (0xF000, 0xF065)},
    {"mode": 3, "columns": 80, "page": 0, "entry": "F000:F065"},
    {"mode": True, "columns": 80, "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065}},
    {"mode": 3.0, "columns": 80, "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065}},
    {"mode": -1, "columns": 80, "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065}},
    {"mode": 256, "columns": 80, "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065}},
    {"mode": 3, "columns": "eighty", "page": 0, "entry": {"segment": 0xF000, "offset": 0xF065}},
    {"mode": 3, "columns": 80, "page": 0, "entry": {"segment": 0x10000, "offset": 0xF065}},
    {"mode": 3, "columns": 80, "page": 0, "entry": {"segment": -1, "offset": 0xF065}},
    {"mode": 3, "columns": 80, "page": 0, "extra": 1,
     "entry": {"segment": 0xF000, "offset": 0xF065}},
    5, "video", ["mode"],
])
def test_malformed_declarations_reject_before_any_execution(declaration):
    with pytest.raises(ValueError):
        parse_video_policy(declaration)


def test_parsing_uses_manifest_integer_style_for_every_field():
    declared = {
        "mode": "0x03", "columns": "80", "page": "0x00",
        "entry": {"segment": "0xF000", "offset": "0xf065"},
    }
    assert parse_video_policy(declared) == policy()
    for bad in ("0x", "zz", "1.5"):
        broken = dict(declared)
        broken["mode"] = bad
        with pytest.raises(ValueError):
            parse_video_policy(broken)
