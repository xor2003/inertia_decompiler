from __future__ import annotations

from inertia.frontend.x86_16.cod_analysis_image import build_cod_analysis_image_8616


def test_cod_analysis_image_relocates_named_call_away_from_fallthrough() -> None:
    entries: list[dict[str, object]] = [
        {"offset": 0x10, "bytes": b"\x50", "text": "push ax"},
        {"offset": 0x11, "bytes": b"\xe8\x00\x00", "text": "call _Message"},
        {"offset": 0x14, "bytes": b"\xc3", "text": "ret"},
    ]

    image = build_cod_analysis_image_8616(entries)

    assert image.code == b"\x50\xe8\x01\x00\xc3\xc3"
    assert image.call_target_offsets == {5: "Message"}


def test_cod_analysis_image_reuses_stub_for_repeated_named_calls() -> None:
    entries: list[dict[str, object]] = [
        {"offset": 0x20, "bytes": b"\xe8\x00\x00", "text": "call _DrawBar"},
        {"offset": 0x23, "bytes": b"\xe8\x00\x00", "text": "call _DrawBar"},
        {"offset": 0x26, "bytes": b"\xc3", "text": "ret"},
    ]

    image = build_cod_analysis_image_8616(entries)

    assert image.code == b"\xe8\x04\x00\xe8\x01\x00\xc3\xc3"
    assert image.call_target_offsets == {7: "DrawBar"}


def test_cod_analysis_image_relocates_named_far_call_to_far_return_stub() -> None:
    entries: list[dict[str, object]] = [
        {"offset": 0x30, "bytes": b"\x9a\x00\x00\x00\x00", "text": "call FAR PTR _RectCopy"},
        {"offset": 0x35, "bytes": b"\xc3", "text": "ret"},
    ]

    image = build_cod_analysis_image_8616(entries, image_base=0x1000)

    assert image.code == b"\x9a\x06\x00\x00\x01\xc3\xcb"
    assert image.call_target_offsets == {6: "RectCopy"}
