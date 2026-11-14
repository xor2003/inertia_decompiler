# cython: language_level=3, infer_types=True
"""Layer: IR / declared interrupt-service effect staging.

Responsibility: read complete DOSBox allocator premises from declared bytes
and the actual per-path memory overlay, derive the shared canonical response,
and preflight every ordered write without committing memory or register state.
The caller authenticates environment/service identity and supplies complete
code and interrupt/save-frame spans. Applicability budgets below bound staging
work only; they never change the frontend allocator model's supported chains.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.real16_dosbox_resize import (
    DOSBOX_MCB_BYTES,
    DOSBOX_RESIZE_FUNCTION,
    DosboxMcbEntry,
    DosboxResizePolicy,
    DosboxResizeRefusal,
    DosboxResizeResponse,
    dosbox_resize_response,
)
from inertia.ir.real16_declared_interrupt8616 import declared_memory_span_8616
from inertia.ir.real16_path_memory8616 import PathMemory8616
import dataclasses
import operator

DOSBOX_RESIZE_EFFECTS_MAX_CHAIN_8616: cython.longlong = 64
DOSBOX_RESIZE_EFFECTS_MAX_SPANS_8616: cython.longlong = 8192


class DosboxResizeEffectsRefusal8616(StrEnum):
    """Missing allocator evidence or a prohibited staged effect, never success."""

    INPUT_UNPROVEN = "dosbox_resize_input_unproven"
    POLICY_UNPROVEN = "dosbox_resize_policy_unproven"
    BUDGET_EXCEEDED = "dosbox_resize_staging_budget_exceeded"
    SPAN_UNPROVEN = "dosbox_resize_protection_span_unproven"
    TAINTED_MEMORY = "dosbox_resize_memory_tainted"
    CHAIN_UNPROVEN = "dosbox_resize_chain_bytes_unproven"
    CHAIN_CHANGED = "dosbox_resize_chain_changed"
    OTHER_BLOCK = "dosbox_resize_other_block"
    SPLIT_HEADER_UNPROVEN = "dosbox_resize_split_header_unproven"
    WRITE_UNDECLARED = "dosbox_resize_write_undeclared"
    IVT_ALIAS = "dosbox_resize_ivt_alias"
    CODE_WRITE = "dosbox_resize_code_write"
    FRAME_ALIAS = "dosbox_resize_frame_alias"


@dataclasses.dataclass(frozen=True, )
class DosboxResizeEffects8616:
    """Complete read-only staging evidence and every canonical ordered write."""

    response: DosboxResizeResponse
    current_chain: object
    new_header_before: object


@cython.ccall
def _word(value: cython.longlong) -> cython.bint:
    """Require an exact unsigned machine word, excluding Boolean values."""
    return type(value) is int and 0 <= value <= 0xFFFF


def _canonical_policy(policy: DosboxResizePolicy) -> DosboxResizePolicy:
    """Rebuild the bounded declaration through the authoritative constructors."""
    return DosboxResizePolicy(policy.psp_segment, tuple(
        DosboxMcbEntry(entry.segment, entry.image) for entry in iter(policy.chain)
    ))


@cython.ccall
def _spans_valid(spans: object) -> cython.bint:
    """Require exact finite nonwrapping physical spans before overlap arithmetic."""
    span: object
    if type(spans) is not tuple or len(spans) > DOSBOX_RESIZE_EFFECTS_MAX_SPANS_8616:
        return False
    for span in spans:
        if type(span) is not tuple or len(span) != 2:
            return False
        base, size = span
        if type(base) is not int or type(size) is not int:
            return False
        if not 0 <= base < base + size <= 0x100000:
            return False
    return True


def _input_refusal(
    policy: DosboxResizePolicy, segment: cython.longlong, paragraphs: cython.longlong, ax: cython.longlong,
    code_spans: object, frame_spans: object,
) -> DosboxResizeEffectsRefusal8616 | None:
    """Bound declarations and validate owned fields before any staging allocation."""
    if not all(_word(value) for value in iter((segment, paragraphs, ax))) or operator.ne(ax >> 8, DOSBOX_RESIZE_FUNCTION):
        return DosboxResizeEffectsRefusal8616.INPUT_UNPROVEN
    if type(policy) is not DosboxResizePolicy or type(policy.chain) is not tuple:
        return DosboxResizeEffectsRefusal8616.POLICY_UNPROVEN
    if len(policy.chain) > DOSBOX_RESIZE_EFFECTS_MAX_CHAIN_8616:
        return DosboxResizeEffectsRefusal8616.BUDGET_EXCEEDED
    if any(type(entry) is not DosboxMcbEntry for entry in iter(policy.chain)):
        return DosboxResizeEffectsRefusal8616.POLICY_UNPROVEN
    if not _spans_valid(code_spans) or not _spans_valid(frame_spans):
        return DosboxResizeEffectsRefusal8616.SPAN_UNPROVEN
    try:
        _canonical_policy(policy)
    except ValueError:
        return DosboxResizeEffectsRefusal8616.POLICY_UNPROVEN
    return None


@cython.ccall
def _read_overlay_header(environment: object, memory: PathMemory8616, address: cython.longlong) -> object:
    """Require declared initial bytes, then honor every known/unknown path byte."""
    initial: object
    value: object
    initial = declared_memory_span_8616(environment, address, DOSBOX_MCB_BYTES)
    if initial is None or memory.tainted:
        return None
    current = bytearray(initial)
    for offset in range(DOSBOX_MCB_BYTES):
        byte_address = address + offset
        if byte_address in memory.unknown:
            return None
        value = memory.known.get(byte_address, initial[offset])
        if type(value) is not int or not 0 <= value <= 0xFF:
            return None
        current[offset] = value
    return bytes(current)


@cython.ccall
def _read_current_chain(
    policy: DosboxResizePolicy, environment: object, memory: PathMemory8616,
) -> object:
    """Read every declared header through the same path-associated overlay."""
    header: object
    entry: object
    current: list[bytes] = []
    for entry in policy.chain:
        header = _read_overlay_header(environment, memory, entry.address)
        if header is None:
            return None
        current.append(header)
    return tuple(current)


@cython.ccall
def _model_refusal(refusal: DosboxResizeRefusal) -> DosboxResizeEffectsRefusal8616:
    """Preserve each canonical refusal as a visible typed staging non-result."""
    return {
        DosboxResizeRefusal.CURRENT_CHAIN_ABSENT: DosboxResizeEffectsRefusal8616.CHAIN_UNPROVEN,
        DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE: DosboxResizeEffectsRefusal8616.CHAIN_UNPROVEN,
        DosboxResizeRefusal.CURRENT_CHAIN_CHANGED: DosboxResizeEffectsRefusal8616.CHAIN_CHANGED,
        DosboxResizeRefusal.OTHER_BLOCK: DosboxResizeEffectsRefusal8616.OTHER_BLOCK,
        DosboxResizeRefusal.NEW_HEADER_UNPROVEN: DosboxResizeEffectsRefusal8616.SPLIT_HEADER_UNPROVEN,
    }[refusal]


def _overlaps(base: cython.longlong, size: cython.longlong, spans: object) -> cython.bint:
    """Compare bounded physical spans without weakening their supplied extents."""
    return any(base < protected + extent and protected < base + size
               for protected, extent in iter(spans))


@cython.ccall
def _preflight_writes(
    response: DosboxResizeResponse, environment: object,
    code_spans: object, frame_spans: object,
) -> DosboxResizeEffectsRefusal8616 | None:
    """Check every ordered native store, including same-value error-path stores."""
    write: object
    for write in response.writes:
        size = len(write.data)
        if declared_memory_span_8616(environment, write.address, size) is None:
            return DosboxResizeEffectsRefusal8616.WRITE_UNDECLARED
        if write.address < 0x400:
            return DosboxResizeEffectsRefusal8616.IVT_ALIAS
        if _overlaps(write.address, size, code_spans):
            return DosboxResizeEffectsRefusal8616.CODE_WRITE
        if _overlaps(write.address, size, frame_spans):
            return DosboxResizeEffectsRefusal8616.FRAME_ALIAS
    return None


@cython.ccall
def stage_dosbox_resize_effects_8616(
    policy: DosboxResizePolicy, *, environment: object, memory: PathMemory8616,
    segment: cython.longlong, paragraphs: cython.longlong, ax: cython.longlong,
    code_spans: object, frame_spans: object,
) -> DosboxResizeEffects8616 | DosboxResizeEffectsRefusal8616:
    """Stage one declared initial-state resize from actual path byte evidence.

    Tainted, unknown, incomplete or changed header state refuses. Shrinking
    also requires all sixteen current prospective-header bytes, including its
    reserved fields. The canonical model derives every response and ordered
    write; no semantic branch or native allocator effect is reconstructed here.
    Staging never changes the supplied overlay or any environment bytes.
    """
    current: object
    refusal: object
    refusal = _input_refusal(policy, segment, paragraphs, ax, code_spans, frame_spans)
    if refusal is not None:
        return refusal
    if memory.tainted:
        return DosboxResizeEffectsRefusal8616.TAINTED_MEMORY
    current = _read_current_chain(policy, environment, memory)
    if current is None:
        return DosboxResizeEffectsRefusal8616.CHAIN_UNPROVEN
    # First ask the owner whether a split header is required. This preserves
    # canonical refusal precedence for changed chains and foreign ES values.
    response = dosbox_resize_response(policy, segment=segment, paragraphs=paragraphs,
                                      ax=ax, current_chain=current)
    split: object = None
    if response is DosboxResizeRefusal.NEW_HEADER_UNPROVEN:
        split = _read_overlay_header(environment, memory, (segment + paragraphs) << 4)
        response = dosbox_resize_response(policy, segment=segment, paragraphs=paragraphs,
                                          ax=ax, current_chain=current, new_header_before=split)
    if isinstance(response, DosboxResizeRefusal):
        return _model_refusal(response)
    refusal = _preflight_writes(response, environment, code_spans, frame_spans)
    if refusal is not None:
        return refusal
    return DosboxResizeEffects8616(response, current, split)
