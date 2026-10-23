"""Conditional native entry context for one authentic near CALL.

Layer: frontend x86_16.
Responsibility: bind the source-bound near-CALL frame premise, its proven
conditional CS selector interval, the exact callee boundary, and the live
mapped bytes into one immutable context, then re-authenticate every
retained identity and byte witness before a consumer may rely on it.

This context certifies only a conditional claim: if the exact authentic
near CALL executes, it enters this bound callee under this CS interval. It
never establishes reachability to the callsite, CS preservation inside the
callee, argument/stack/memory facts beyond the retained frame premise,
whole-CFG semantic validity, or unconditional admission. A consumer must
separately bind its exact raw artifact, prove CS preservation, and carry
this conditional scope; the context deliberately exposes no ``complete``
property a context-free consumer could mistake for success.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, Protocol, cast

from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616,
)

from .arch_86_16 import Arch86_16
from .frontend_boundary_transport import (
    FunctionBoundaryWitness8616,
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from .frontend_direct_callsite_index import DecodedDirectCallsiteIndex8616
from .frontend_function_boundary import ExactFunctionRangeBoundary8616
from .frontend_near_return_continuation import (
    EntryTopSlotKind8616,
    NearCallFramePremise8616,
    prove_near_call_frame_premise_8616,
)
from .near_call_selector_window import (
    NearCallSelectorWindow8616,
    NearCallSelectorWindowRefusal8616,
    project_near_call_selector_window_8616,
)

__all__ = [
    "NativeNearCallEntry8616",
    "NativeNearCallEntryFailure8616",
    "NativeNearCallEntryRefusal8616",
    "bind_native_near_call_entry_8616",
    "consume_native_near_call_entry_8616",
]

_NEAR_CALL_SIZE_8616 = 3


class NativeNearCallEntryFailure8616(StrEnum):
    """Typed reasons a near-CALL entry context cannot be bound."""

    UNSUPPORTED_ARCHITECTURE = "native_near_call_entry_unsupported_architecture"
    FOREIGN_BOUNDARY = "native_near_call_entry_foreign_boundary"
    PREMISE_ABSENT = "native_near_call_entry_premise_absent"
    FOREIGN_CALLSITE_INDEX = "native_near_call_entry_foreign_callsite_index"
    PREMISE_REPROOF_FAILED = "native_near_call_entry_premise_reproof_failed"
    PREMISE_COORDINATE_FORGERY = "native_near_call_entry_premise_coordinate_forgery"
    SELECTOR_WINDOW_UNPROVED = "native_near_call_entry_selector_window_unproved"
    RAW_TARGET_NOT_ENTRY = "native_near_call_entry_raw_target_not_entry"
    CALLSITE_BYTES_UNBOUND = "native_near_call_entry_callsite_bytes_unbound"
    BOUNDARY_WITNESS_UNAVAILABLE = "native_near_call_entry_boundary_witness_unavailable"
    BOUNDARY_CENSUS_MISMATCH = "native_near_call_entry_boundary_census_mismatch"
    BUDGET_EXHAUSTED = "native_near_call_entry_budget_exhausted"


@dataclass(frozen=True, slots=True)
class NativeNearCallEntry8616:
    """Authenticated conditional entry binding for one exact near CALL.

    Retained identities — ``project``, ``boundary``, ``premise``,
    ``callsite_index`` — are bound by object identity and re-proven by
    their canonical owners at consumption; ``callee_witness`` and
    ``call_encoding`` are immutable byte witnesses re-validated against
    live mapped bytes. ``selector_low``/``selector_high`` are the proven
    conditional CS interval; ``target_addr`` is the raw ``E8``
    destination (never a normalized lookup alias), proven equal to
    ``boundary.addr``. ``callee_addr`` is the premise's separately
    retained bound callee coordinate.
    """

    conditional_only: ClassVar[bool] = True
    cs_preservation_required: ClassVar[bool] = True
    reachability_unproved: ClassVar[bool] = True
    callee_preservation_unproved: ClassVar[bool] = True

    project: object = field(compare=False, repr=False)
    boundary: ExactFunctionRangeBoundary8616 = field(compare=False, repr=False)
    premise: NearCallFramePremise8616 = field(compare=False, repr=False)
    callsite_index: DecodedDirectCallsiteIndex8616 = field(compare=False, repr=False)
    callee_witness: FunctionBoundaryWitness8616 = field(compare=False, repr=False)
    call_encoding: bytes = b""
    callsite_addr: int = 0
    next_addr: int = 0
    target_addr: int = 0
    callee_addr: int = 0
    selector_low: int = 0
    selector_high: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize this context's proven coordinates for diagnostics."""
        return {
            "callsite_addr": self.callsite_addr,
            "next_addr": self.next_addr,
            "target_addr": self.target_addr,
            "callee_addr": self.callee_addr,
            "selector_low": self.selector_low,
            "selector_high": self.selector_high,
            "conditional_only": self.conditional_only,
            "cs_preservation_required": self.cs_preservation_required,
        }


@dataclass(frozen=True, slots=True)
class NativeNearCallEntryRefusal8616:
    """Honest non-result for a context that cannot be bound."""

    failure: NativeNearCallEntryFailure8616
    callsite_addr: int | None = None
    callee_addr: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize this refusal for diagnostics."""
        return {
            "failure": self.failure.value,
            "callsite_addr": self.callsite_addr,
            "callee_addr": self.callee_addr,
            "detail": self.detail,
        }


class _CallsiteInstruction8616(Protocol):
    """Exact encoding exposed by one retained decoded callsite instruction."""

    bytes: bytes


class _MemoryBoundary8616(Protocol):
    """Third-party loader memory used for live byte authentication."""

    def load(self, addr: int, size: int) -> bytes:
        """Read exactly the requested mapped bytes."""
        ...


class _LoaderBoundary8616(Protocol):
    """Third-party loader surface exposing mapped memory."""

    memory: _MemoryBoundary8616


class _ProjectBoundary8616(Protocol):
    """Third-party project surfaces this context authenticates."""

    arch: object
    loader: _LoaderBoundary8616


def _refusal_8616(
    failure: NativeNearCallEntryFailure8616,
    premise: NearCallFramePremise8616 | None = None,
    *,
    detail: str = "",
) -> NativeNearCallEntryRefusal8616:
    """Retain one typed refusal with best-effort diagnostic coordinates."""
    return NativeNearCallEntryRefusal8616(
        failure=failure,
        callsite_addr=None if premise is None else premise.callsite_addr,
        callee_addr=None if premise is None else premise.callee_addr,
        detail=detail,
    )


def _live_encoding_8616(project: object, callsite_addr: int, size: int) -> bytes | None:
    """Read the exact live mapped instruction bytes, or refuse honestly."""
    try:
        memory = cast(_ProjectBoundary8616, project).loader.memory
        return bytes(memory.load(callsite_addr, size))
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _boundary_census_matches_8616(
    restored: ExactFunctionRangeBoundary8616,
    bound: ExactFunctionRangeBoundary8616,
) -> bool:
    """Return whether one rebuilt boundary carries the bound census exactly."""
    return bool(
        restored.addr == bound.addr
        and restored.block_addrs_set == bound.block_addrs_set
        and restored.reachable_instruction_addrs == bound.reachable_instruction_addrs
        and frozenset(restored.successor_edges) == frozenset(bound.successor_edges)
    )


def _live_call_encoding_8616(
    project: object, frame: NearCallFramePremise8616
) -> bytes | None:
    """Return live mapped CALL bytes only when they equal the retained row."""
    live = _live_encoding_8616(project, frame.callsite_addr, _NEAR_CALL_SIZE_8616)
    if live is None:
        return None
    retained = bytes(
        cast(
            _CallsiteInstruction8616,
            frame.callsite.instructions[frame.callsite.instruction_index],
        ).bytes
    )
    return live if live == retained else None


def _callee_witness_8616(
    project: object, bound: ExactFunctionRangeBoundary8616
) -> FunctionBoundaryWitness8616 | NativeNearCallEntryFailure8616:
    """Capture and revalidate the callee boundary's byte witnesses.

    The boundary-transport owner re-reads every witnessed extent against
    current mapped bytes and rebuilds the closed reachability census; a
    rebuilt census that disagrees with the offered boundary is a distinct
    typed failure from an unavailable witness.
    """
    witness = capture_function_boundary_8616(project, bound)
    if type(witness) is not FunctionBoundaryWitness8616 or witness.entry != bound.addr:
        return NativeNearCallEntryFailure8616.BOUNDARY_WITNESS_UNAVAILABLE
    try:
        restored = restore_function_boundary_8616(project, witness)
    except ValueError:
        return NativeNearCallEntryFailure8616.BOUNDARY_CENSUS_MISMATCH
    if (
        type(restored) is not ExactFunctionRangeBoundary8616
        or restored.project is not project
        or not _boundary_census_matches_8616(restored, bound)
    ):
        return NativeNearCallEntryFailure8616.BOUNDARY_CENSUS_MISMATCH
    return witness


def _premise_identity_8616(
    premise: object, callsite_index: object
) -> NearCallFramePremise8616 | NativeNearCallEntryRefusal8616:
    """Re-prove the frame premise and index identity, or refuse honestly.

    The explicitly supplied ``callsite_index`` must be the identical
    retained index the premise was proven against; the canonical
    frame-premise owner then re-proves the retained row and the re-derived
    coordinates must equal the offered ones — a foreign index, a lost row,
    a changed width, or forged coordinates each keep a typed refusal.
    """
    if (
        type(premise) is not NearCallFramePremise8616
        or premise.kind
        is not EntryTopSlotKind8616.NEAR_CALL_CONTINUATION
    ):
        return _refusal_8616(NativeNearCallEntryFailure8616.PREMISE_ABSENT)
    frame = premise
    if type(callsite_index) is not DecodedDirectCallsiteIndex8616:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.FOREIGN_CALLSITE_INDEX, frame
        )
    index = callsite_index
    if not index.stats.closed or frame.callsite_index is not index:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.FOREIGN_CALLSITE_INDEX, frame
        )
    reproven = prove_near_call_frame_premise_8616(
        frame.callsite, index, frame.callee_addr
    )
    if reproven is None:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.PREMISE_REPROOF_FAILED, frame
        )
    if reproven.callsite is not frame.callsite or (
        reproven.callsite_addr,
        reproven.caller_start,
        reproven.callee_addr,
        reproven.return_addr,
    ) != (
        frame.callsite_addr,
        frame.caller_start,
        frame.callee_addr,
        frame.return_addr,
    ):
        return _refusal_8616(
            NativeNearCallEntryFailure8616.PREMISE_COORDINATE_FORGERY, frame
        )
    return frame


def _final_evidence_failure_8616(
    project: object, frame: NearCallFramePremise8616, encoding: bytes,
) -> NativeNearCallEntryFailure8616 | None:
    """Recheck the CALL and deadline after callee decoding callbacks finish."""
    if direct_evidence_deadline_expired_8616(project):
        return NativeNearCallEntryFailure8616.BUDGET_EXHAUSTED
    if _live_call_encoding_8616(project, frame) != encoding:
        return NativeNearCallEntryFailure8616.CALLSITE_BYTES_UNBOUND
    if direct_evidence_deadline_expired_8616(project):
        return NativeNearCallEntryFailure8616.BUDGET_EXHAUSTED
    return None


def _native_source_failure_8616(
    project: object, boundary: object,
) -> NativeNearCallEntryFailure8616 | None:
    """Reject an expired request or a boundary outside this native project."""
    if direct_evidence_deadline_expired_8616(project):
        return NativeNearCallEntryFailure8616.BUDGET_EXHAUSTED
    try:
        arch = cast(_ProjectBoundary8616, project).arch
    except AttributeError:
        arch = None
    if type(arch) is not Arch86_16:
        return NativeNearCallEntryFailure8616.UNSUPPORTED_ARCHITECTURE
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or boundary.project is not project
    ):
        return NativeNearCallEntryFailure8616.FOREIGN_BOUNDARY
    return None


def bind_native_near_call_entry_8616(
    project: object,
    boundary: object,
    premise: object,
    *,
    callsite_index: object,
) -> NativeNearCallEntry8616 | NativeNearCallEntryRefusal8616:
    """Bind one authentic near CALL to its conditional callee entry context.

    Scope: the exact ``Arch86_16`` project owns ``boundary``; ``premise``
    is re-proven by the canonical frame-premise owner against the
    explicitly supplied ``callsite_index``; the selector window is
    re-derived by its canonical projection; the raw ``E8`` destination —
    never a normalized lookup alias — must equal ``boundary.addr``; the
    live mapped three-byte CALL must equal the retained row encoding; and
    the callee boundary's byte witnesses are captured and immediately
    revalidated through the boundary-transport owner. No new address
    discovery happens here; every failed check keeps its typed refusal.
    """
    source_failure = _native_source_failure_8616(project, boundary)
    if source_failure is not None:
        return _refusal_8616(source_failure)
    bound = cast(ExactFunctionRangeBoundary8616, boundary)
    authenticated = _premise_identity_8616(premise, callsite_index)
    if type(authenticated) is NativeNearCallEntryRefusal8616:
        return authenticated
    frame = cast(NearCallFramePremise8616, authenticated)
    window = project_near_call_selector_window_8616(frame)
    if type(window) is not NearCallSelectorWindow8616:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.SELECTOR_WINDOW_UNPROVED,
            frame,
            detail=cast(NearCallSelectorWindowRefusal8616, window).failure.value,
        )
    coordinates = frame.callsite.encoded_near_coordinates()
    if coordinates is None:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.PREMISE_REPROOF_FAILED, frame
        )
    next_addr, target_addr = coordinates
    if target_addr != bound.addr:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.RAW_TARGET_NOT_ENTRY, frame
        )
    call_encoding = _live_call_encoding_8616(project, frame)
    if call_encoding is None:
        return _refusal_8616(
            NativeNearCallEntryFailure8616.CALLSITE_BYTES_UNBOUND, frame
        )
    witness = _callee_witness_8616(project, bound)
    if type(witness) is not FunctionBoundaryWitness8616:
        return _refusal_8616(cast(NativeNearCallEntryFailure8616, witness), frame)
    failure = _final_evidence_failure_8616(project, frame, call_encoding)
    if failure is not None:
        return _refusal_8616(failure, frame)
    return NativeNearCallEntry8616(
        project=project,
        boundary=bound,
        premise=frame,
        callsite_index=frame.callsite_index,
        callee_witness=witness,
        call_encoding=call_encoding,
        callsite_addr=window.callsite_addr,
        next_addr=next_addr,
        target_addr=target_addr,
        callee_addr=window.callee_addr,
        selector_low=window.selector_low,
        selector_high=window.selector_high,
    )


def consume_native_near_call_entry_8616(
    project: object,
    context: object,
    *,
    callsite_index: object,
) -> bool:
    """Re-authenticate a bound context against live evidence before use.

    The full binding proof runs again over the context's retained
    identities: the explicitly supplied current ``callsite_index`` must be
    the identical retained index, the frame premise is re-proven, the
    selector window is re-derived, the raw ``E8`` destination must still
    bind the retained callee head, the live mapped CALL bytes must equal
    the retained row encoding, and the callee boundary's byte witnesses
    are revalidated through the boundary-transport owner. Foreign project,
    index, or boundary coordinates, mutated native bytes, forged
    projection bounds or coordinates, a changed instruction width, or an
    expired existing direct-evidence deadline all return ``False`` —
    never a stale or borrowed context.
    """
    if type(context) is not NativeNearCallEntry8616 or context.project is not project:
        return False
    if type(callsite_index) is not DecodedDirectCallsiteIndex8616 or (
        callsite_index is not context.callsite_index
    ):
        return False
    if direct_evidence_deadline_expired_8616(project):
        return False
    bound = context.boundary
    if (
        type(bound) is not ExactFunctionRangeBoundary8616
        or bound.project is not project
        or bound.addr != context.target_addr
    ):
        return False
    authenticated = _premise_identity_8616(context.premise, callsite_index)
    if type(authenticated) is NativeNearCallEntryRefusal8616:
        return False
    rebound = bind_native_near_call_entry_8616(
        project, bound, authenticated, callsite_index=callsite_index
    )
    if type(rebound) is not NativeNearCallEntry8616:
        return False
    return bool(
        type(context.call_encoding) is bytes
        and rebound.call_encoding == context.call_encoding
        and rebound.callee_witness == context.callee_witness
        and (
            rebound.callsite_addr,
            rebound.next_addr,
            rebound.target_addr,
            rebound.callee_addr,
            rebound.selector_low,
            rebound.selector_high,
        )
        == (
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        )
    )
