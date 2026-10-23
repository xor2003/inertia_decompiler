"""DOSBox resize receipts bind complete premises and ordered native effects."""
import hashlib
from dataclasses import replace

import pytest

from inertia.frontend.real16_dosbox_resize import (
    DosboxMcbEntry,
    DosboxResizePolicy,
    DosboxResizeResponse,
    dosbox_resize_response,
)
from tools.dosunit.runtime.real16_dosbox_resize_receipt import (
    dosbox_resize_event_data,
    dosbox_resize_receipt_complete,
)

pytestmark = pytest.mark.dosunit
PREFIX = b"DOSBOX-4A-v1\0"


def _policy():
    prefix = DosboxMcbEntry(0x100, b"M" + (7).to_bytes(2, "little") + (2).to_bytes(2, "little") + b"x" * 11)
    final = DosboxMcbEntry(0x103, b"Z" + (0x104).to_bytes(2, "little") + (0x20).to_bytes(2, "little") + b"y" * 11)
    return DosboxResizePolicy(0x104, (prefix, final))


def _inputs(paragraphs=8):
    policy = _policy()
    return {"policy": policy, "segment": policy.final_entry.data_segment, "paragraphs": paragraphs,
            "ax": 0x4A37, "current_chain": tuple(entry.image for entry in policy.chain),
            "new_header_before": b"\xA5" * 16}


def _event(paragraphs=8):
    inputs = _inputs(paragraphs)
    result = dosbox_resize_response(**inputs)
    assert isinstance(result, DosboxResizeResponse)
    return dosbox_resize_event_data(**inputs, result=result)


def _redigest(payload):
    return payload + hashlib.sha256(payload).digest()


@pytest.mark.parametrize("paragraphs,write_count", [(0, 6), (8, 6), (0x20, 0), (0x21, 2)])
def test_complete_model_events_are_stable_and_all_writes_retained(paragraphs, write_count):
    inputs = _inputs(paragraphs)
    result = dosbox_resize_response(**inputs)
    assert isinstance(result, DosboxResizeResponse)
    assert len(result.writes) == write_count
    data = dosbox_resize_event_data(**inputs, result=result)
    assert data.startswith(PREFIX)
    assert data == _event(paragraphs)
    assert dosbox_resize_receipt_complete(data)


@pytest.mark.parametrize("offset", [len(PREFIX), len(PREFIX) + 6, 75, 80, 96, 116, -1])
def test_any_direct_premise_or_response_byte_mutation_refuses(offset):
    data = bytearray(_event())
    data[offset] ^= 1
    assert not dosbox_resize_receipt_complete(bytes(data))


@pytest.mark.parametrize("shape", ["omit", "duplicate", "reverse", "change", "response"])
def test_forged_responses_cannot_serialize_success(shape):
    inputs = _inputs()
    result = dosbox_resize_response(**inputs)
    assert isinstance(result, DosboxResizeResponse)
    writes = result.writes
    if shape == "omit":
        corrupted = replace(result, writes=writes[:-1])
    elif shape == "duplicate":
        corrupted = replace(result, writes=(*writes[:-1], writes[0]))
    elif shape == "reverse":
        corrupted = replace(result, writes=tuple(reversed(writes)))
    elif shape == "response":
        corrupted = replace(result, ax=result.ax ^ 1)
    else:
        corrupted = replace(result, writes=(replace(writes[0], data=b"\xFF\xFF"), *writes[1:]))
    with pytest.raises(ValueError):
        dosbox_resize_event_data(**inputs, result=corrupted)


@pytest.mark.parametrize("mutation", ["current", "policy", "segment", "missing_split"])
def test_refused_canonical_inputs_cannot_publish_receipt(mutation):
    inputs = _inputs()
    result = dosbox_resize_response(**inputs)
    assert isinstance(result, DosboxResizeResponse)
    if mutation == "current":
        inputs["current_chain"] = (b"\0" * 16, inputs["current_chain"][1])
    elif mutation == "policy":
        policy = inputs["policy"]
        prefix = replace(policy.chain[0], image=policy.chain[0].image[:-1] + b"z")
        inputs["policy"] = replace(policy, chain=(prefix, policy.chain[1]))
    elif mutation == "segment":
        inputs["segment"] += 1
    else:
        inputs["new_header_before"] = None
    with pytest.raises(ValueError):
        dosbox_resize_event_data(**inputs, result=result)


@pytest.mark.parametrize("data", [b"", b"\x21\x4a" + b"\0" * 43, PREFIX, b"x" * 4097])
def test_malformed_or_legacy_envelopes_are_incomplete(data):
    assert not dosbox_resize_receipt_complete(data)


def test_recomputed_checksum_does_not_hide_noncanonical_trailing_bytes():
    data = _event()
    assert not dosbox_resize_receipt_complete(_redigest(data[:-32] + b"\0"))


def test_truncation_is_never_complete():
    data = _event()
    assert all(not dosbox_resize_receipt_complete(data[:end]) for end in range(len(data)))


@pytest.mark.parametrize("mutation", ["response", "order", "omit", "duplicate", "request", "current"])
def test_redigested_corruption_still_fails_canonical_model(mutation):
    data = _event()
    payload = bytearray(data[:-32])
    count = int.from_bytes(payload[len(PREFIX) + 2:len(PREFIX) + 4], "little")
    request = len(PREFIX) + 4 + count * 18
    current = request + 6
    split_tag = current + count * 16
    response = split_tag + 1 + (16 if payload[split_tag] else 0)
    writes_start = response + 6
    writes = []
    cursor = writes_start
    for _ in range(payload[response + 5]):
        end = cursor + 5 + payload[cursor + 4]
        writes.append(bytes(payload[cursor:end]))
        cursor = end
    if mutation == "response":
        payload[response] ^= 1
    elif mutation == "request":
        payload[request + 4] ^= 1  # Different BX must change the native split writes.
    elif mutation == "current":
        payload[current + 15] ^= 1
    else:
        if mutation == "order":
            writes.reverse()
        elif mutation == "omit":
            writes.pop()
            payload[response + 5] -= 1
        else:
            writes[-1] = writes[0]
        payload[writes_start:] = b"".join(writes)
    assert not dosbox_resize_receipt_complete(_redigest(bytes(payload)))


def test_serializer_declares_chain_bound_and_specific_boundary_error():
    from tools.dosunit.runtime.real16_dosbox_resize_receipt import (
        DOSBOX_RESIZE_RECEIPT_MAX_CHAIN,
        DosboxResizeReceiptError,
    )
    entries = tuple(DosboxMcbEntry(index, b"M\1\0\0\0" + b"x" * 11)
                    for index in range(DOSBOX_RESIZE_RECEIPT_MAX_CHAIN))
    final = DosboxMcbEntry(DOSBOX_RESIZE_RECEIPT_MAX_CHAIN, b"Z\4\1\0\0" + b"x" * 11)
    policy = DosboxResizePolicy(0x104, (*entries, final))
    current = tuple(entry.image for entry in policy.chain)
    result = dosbox_resize_response(policy, segment=final.data_segment, paragraphs=0,
                                   ax=0x4A00, current_chain=current)
    assert isinstance(result, DosboxResizeResponse)
    with pytest.raises(DosboxResizeReceiptError, match="chain limit"):
        dosbox_resize_event_data(policy, segment=final.data_segment, paragraphs=0,
                                ax=0x4A00, current_chain=current, result=result)
