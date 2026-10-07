"""Classify generated runtime memory-read helpers.

Layer: Types/Lowering.
Responsibility: expose typed identities for generated memory-read intrinsics at the angr C-AST boundary.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

These helpers describe reads only.  Store helpers remain outside this contract,
so callers may use a successful classification as side-effect-free read
evidence after recursively checking helper arguments.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall


class _NamedFunctionBoundary8616(Protocol):
    """Third-party function metadata exposing a rendered target name."""

    name: object


class _FunctionCallBoundary8616(Protocol):
    """Third-party structured-C call metadata used for helper classification."""

    callee_target: object
    callee_func: object


class MemoryPointerHelper8616(Enum):
    """Generated memory-read helper identities and dereference widths."""

    MEM_U8 = "MEM_U8"
    MEM_U16 = "MEM_U16"
    MEM_U32 = "MEM_U32"

    @property
    def helper_name(self) -> str:
        """Return the generated helper function name."""
        return self.value

    @property
    def width(self) -> int:
        """Return the byte width dereferenced by the helper."""
        if self is MemoryPointerHelper8616.MEM_U8:
            return 1
        if self is MemoryPointerHelper8616.MEM_U32:
            return 4
        return 2


class SegmentedMemoryReadHelper8616(Enum):
    """Generated segmented memory-read helper identities and widths."""

    SEG_U8 = "SEG_U8"
    SEG_U16 = "SEG_U16"
    SEG_U32 = "SEG_U32"

    @property
    def helper_name(self) -> str:
        """Return the generated helper function name."""
        return self.value

    @property
    def width(self) -> int:
        """Return the byte width read from segmented memory."""
        if self is SegmentedMemoryReadHelper8616.SEG_U8:
            return 1
        if self is SegmentedMemoryReadHelper8616.SEG_U32:
            return 4
        return 2


def _runtime_memory_helper_name_8616(node: object) -> str | None:
    """Return one normalized generated-helper identity at the angr boundary."""
    call = cast(_FunctionCallBoundary8616, node)
    try:
        raw_name = call.callee_target
    except AttributeError:
        raw_name = None
    if not isinstance(raw_name, str):
        try:
            callee = cast(_NamedFunctionBoundary8616, call.callee_func)
            raw_name = callee.name
        except AttributeError:
            raw_name = None
    return raw_name.strip().upper() if isinstance(raw_name, str) else None


def memory_pointer_helper_8616(node: object) -> MemoryPointerHelper8616 | None:
    """Return a typed memory-read helper at the dynamic angr C-call boundary."""
    normalized = _runtime_memory_helper_name_8616(node)
    if normalized is None:
        return None
    for helper in MemoryPointerHelper8616:
        if normalized == helper.helper_name:
            return helper
    return None


def proven_memory_pointer_helper_8616(node: object) -> MemoryPointerHelper8616 | None:
    """Consume an owned generated-read tag, never a machine callee's name alone.

    This proves only the outer read. Consumers must still inspect its argument
    for calls or other effects before preserving dataflow facts.
    """
    if (
        not isinstance(node, CFunctionCall)
        or not isinstance(node.tags, dict)
        or node.callee_func is not None
        or node.args is None
        or len(node.args) != 1
    ):
        return None
    identity = node.tags.get("inertia_x86_16_runtime_pointer_helper")
    for helper in MemoryPointerHelper8616:
        if identity == helper.value and node.callee_target == helper.value:
            return helper
    return None


def segmented_memory_read_helper_8616(node: object) -> SegmentedMemoryReadHelper8616 | None:
    """Return a typed segmented read helper at the dynamic angr boundary."""
    normalized = _runtime_memory_helper_name_8616(node)
    if normalized is None:
        return None
    for helper in SegmentedMemoryReadHelper8616:
        if normalized == helper.helper_name:
            return helper
    return None
