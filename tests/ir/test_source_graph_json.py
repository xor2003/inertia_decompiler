"""Keep accelerated proof serialization byte-identical to its stdlib format."""

from __future__ import annotations

import json
from enum import StrEnum
from unittest.mock import patch

import pytest

from inertia.ir import source_graph_json as owner
from inertia.ir.source_graph_binding import canonical_source_graph_8616


class TextSubclass(str):
    """An accepted IR name whose content must survive codec fallback."""


class TextEnum(StrEnum):
    """String-valued metadata retains its textual content."""

    NAME = "name"


@pytest.mark.parametrize("text", [chr(value) for value in range(128)] + [
    "é中", "\U0001f600", "\ud800", "\udfff", TextSubclass("subclass"), TextEnum.NAME,
])
def test_text_bytes_match_stdlib(text: str) -> None:
    """Keys and values retain control-character and Unicode escaping exactly."""
    payload = {text: [text, {"z": None, "a": True}], "other": False}
    assert owner.canonical_json_dumps_8616(payload) == json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    )


def test_integer_and_sequence_bytes_match_stdlib() -> None:
    """Arbitrary precision, boolean distinctions and list order stay intact."""
    payload = {"z": [0, False, 1, True, None, 2**100, -(2**100)], "a": []}
    assert owner.canonical_json_dumps_8616(payload) == json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    )


def test_missing_optional_codec_keeps_stdlib_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codec absence changes performance only."""
    monkeypatch.setattr(owner, "_encode_json", None)
    payload = {"text": "\x7fé", "value": 2**100}
    assert owner.canonical_json_dumps_8616(payload) == json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    )


def test_missing_package_selects_stdlib() -> None:
    """Only absence of the optional package selects the fallback."""
    with patch("builtins.__import__", side_effect=ModuleNotFoundError(name="msgspec")):
        encode = owner._load_encoder_8616()
    assert encode is None


def test_broken_codec_installation_stays_loud() -> None:
    """A missing codec internals module is not optional-package absence."""
    failure = ModuleNotFoundError("broken codec", name="msgspec._core")
    with pytest.raises(ModuleNotFoundError) as caught, patch(
        "builtins.__import__", side_effect=failure,
    ):
        owner._load_encoder_8616()
    assert caught.value is failure


def test_cyclic_payload_keeps_stdlib_refusal() -> None:
    """A malformed cycle remains an error when the codec reaches its limit."""
    payload: dict[str, object] = {}
    payload["cycle"] = payload
    with pytest.raises(ValueError, match="Circular reference"):
        owner.canonical_json_dumps_8616(payload)


def test_graph_emission_uses_the_exact_fast_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The graph producer consumes the codec instead of leaving it disconnected."""
    encode = owner._encode_json
    if encode is None:
        pytest.skip("optional msgspec accelerator is not installed")
    observed: list[object] = []

    def recording_encode(payload: object) -> bytes:
        observed.append(payload)
        return encode(payload)

    monkeypatch.setattr(owner, "_encode_json", recording_encode)
    encoded = canonical_source_graph_8616(0x1000, ())
    assert len(observed) == 1
    assert encoded == json.dumps(observed[0], sort_keys=True, separators=(",", ":"))
