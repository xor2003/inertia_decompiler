"""Decode explicit function-entry documents without inventing machine state.

Layer: Frontend.
Responsibility: decode the serialized frontend entry specification. Admission
and all source, environment and native-byte authentication remain with the
canonical declared_function_entry owner.
"""

from __future__ import annotations

from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntrySpec8616,
)

_FIELDS: frozenset[str] = frozenset({
    "version", "source_sha256", "relocated_sha256", "load_segment",
    "entry_segment", "entry_offset", "range_start", "range_end",
    "native_sha256", "environment_sha256", "use_environment_memory",
    "registers", "memory", "return_boundary",
})


def _object(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    """Require a closed JSON object, retaining every supplied field."""
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} requires exactly {sorted(fields)}")
    return value


def _integer(value: object, label: str) -> int:
    """Decode an integer without accepting Boolean or string coercions."""
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer")
    return value


def _text(value: object, label: str) -> str:
    """Decode a string; semantic restrictions belong to admission."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _registers(value: object) -> tuple[tuple[str, int], ...]:
    """Preserve ordered register constraints, including duplicates for rejection."""
    if not isinstance(value, list):
        raise ValueError("registers must be a list")
    pairs: list[tuple[str, int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("registers must contain name/value pairs")
        pairs.append((_text(item[0], "register name"), _integer(item[1], "register value")))
    return tuple(pairs)


def _memory(value: object) -> tuple[DeclaredEntryMemory8616, ...]:
    """Decode explicit byte spans without deriving any initial memory values."""
    if not isinstance(value, list):
        raise ValueError("memory must be a list")
    spans: list[DeclaredEntryMemory8616] = []
    for item in value:
        row = _object(item, frozenset({"address", "data"}), "memory span")
        encoded = _text(row["data"], "memory data")
        try:
            data = bytes.fromhex(encoded)
        except ValueError as error:
            raise ValueError("memory data must be hexadecimal bytes") from error
        if data.hex() != encoded:
            raise ValueError("memory data must be canonical lowercase hexadecimal bytes")
        spans.append(DeclaredEntryMemory8616(_integer(row["address"], "memory address"), data))
    return tuple(spans)


def parse_declared_function_entry_spec_8616(document: object) -> DeclaredFunctionEntrySpec8616:
    """Decode one serialized specification; this grants no admitted authority."""
    root = _object(document, _FIELDS, "function entry")
    boundary = _object(root["return_boundary"], frozenset({"kind", "segment", "offset"}), "return boundary")
    use_memory = root["use_environment_memory"]
    if type(use_memory) is not bool:
        raise ValueError("use_environment_memory must be explicitly Boolean")
    return DeclaredFunctionEntrySpec8616(
        version=_integer(root["version"], "version"),
        source_sha256=_text(root["source_sha256"], "source_sha256"),
        relocated_sha256=_text(root["relocated_sha256"], "relocated_sha256"),
        load_segment=_integer(root["load_segment"], "load_segment"),
        entry_segment=_integer(root["entry_segment"], "entry_segment"),
        entry_offset=_integer(root["entry_offset"], "entry_offset"),
        range_start=_integer(root["range_start"], "range_start"),
        range_end=_integer(root["range_end"], "range_end"),
        native_sha256=_text(root["native_sha256"], "native_sha256"),
        environment_sha256=_text(root["environment_sha256"], "environment_sha256"),
        use_environment_memory=use_memory,
        registers=_registers(root["registers"]),
        memory=_memory(root["memory"]),
        return_boundary=DeclaredEntryReturn8616(
            kind=DeclaredEntryReturnKind8616(_text(boundary["kind"], "return kind")),
            segment=_integer(boundary["segment"], "return segment"),
            offset=_integer(boundary["offset"], "return offset"),
        ),
    )
