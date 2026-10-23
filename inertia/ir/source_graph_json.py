"""Byte-exact JSON emission for already validated source-graph payloads.

Layer: IR.
Responsibility: preserve stdlib canonical JSON bytes while accelerating their
emission. The graph encoder owns input validation: payloads contain only its
scalar, list and dictionary records, not arbitrary JSON-serializable objects.
Schema, source digests and refusal policy remain owned by source_graph_binding.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import cast


def _load_encoder_8616() -> Callable[[object], bytes] | None:
    """Use angr's optional CPython codec without hiding a broken installation."""
    try:
        from msgspec.json import Encoder
    except ModuleNotFoundError as error:
        if error.name != "msgspec":
            raise
        return None
    # msgspec's C method lacks a precise callable return annotation.
    return cast(Callable[[object], bytes], Encoder(order="sorted").encode)


_encode_json = _load_encoder_8616()


def canonical_json_dumps_8616(payload: dict[str, object]) -> str:
    """Emit the validated graph exactly as compact, sorted stdlib JSON.

    UTF-8 text and DEL have different escaping in the accelerator. Accepted
    string subclasses and lone surrogates may also need stdlib handling.
    Retrying those boundaries preserves the old bytes and exception behavior;
    unrelated codec failures propagate. The graph's validators must run first,
    since the accelerator accepts other types outside this owner's domain.
    """
    if _encode_json is not None:
        try:
            raw = _encode_json(payload)
        except (TypeError, UnicodeEncodeError, RecursionError):
            # Subclasses, lone surrogates and recursion use stdlib's result,
            # including its own failure when the input cannot be serialized.
            pass
        else:
            if raw.isascii() and b"\x7f" not in raw:
                return raw.decode("ascii")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
