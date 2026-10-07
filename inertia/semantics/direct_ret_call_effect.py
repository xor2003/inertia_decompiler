"""Layer: Semantics.

Responsibility: prove the register and memory preservation of a direct near
call whose mapped, real callee body consists of a single near RET instruction.
Unknown bodies remain unknown; this proof does not infer a compiler ABI.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from cle.backends.externs import ExternObject

from inertia.frontend.x86_16.synthetic_call_stub_evidence import synthetic_call_stub_registry_8616
from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616


class DirectRetCallEffectVerdict8616(StrEnum):
    """Typed preservation result for one real direct-call target."""

    PRESERVED = "preserved"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class DirectRetCallEffect8616:
    """A closed one-target instruction-body proof or explicit refusal."""

    callsite_addr: int | None
    target_addr: int | None
    verdict: DirectRetCallEffectVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether one exact target yielded one preservation fact."""
        return (
            self.verdict is DirectRetCallEffectVerdict8616.PRESERVED
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


class _MemorySurface8616(Protocol):
    """Third-party loader memory API used for exact mapped bytes."""

    def load(self, address: int, size: int) -> bytes:
        """Read a mapped byte range or raise for an unmapped address."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader boundary for real image membership."""

    memory: _MemorySurface8616

    def find_object_containing(self, address: int) -> object | None:
        """Return the loaded object containing this address, if any."""
        ...


class _ArchSurface8616(Protocol):
    """Third-party architecture identity used at the decoding boundary."""

    name: str


class _ProjectSurface8616(Protocol):
    """Minimal third-party project view for exact instruction bytes."""

    arch: _ArchSurface8616
    loader: _LoaderSurface8616


def _refuse_8616(
    callsite_addr: int | None, target_addr: int | None, *, normalized: bool = False,
) -> DirectRetCallEffect8616:
    """Retain one failed body obligation without claiming preservation."""
    return DirectRetCallEffect8616(
        callsite_addr, target_addr, DirectRetCallEffectVerdict8616.UNKNOWN_REFUSE,
        1, int(normalized), 0, 0, 1,
    )


def direct_near_call_target_is_bound_8616(
    project: object, callsite_addr: int | None, return_addr: int | None,
    target_addr: int | None, frame_kind: CallsiteMachineFrameKind8616 | None,
) -> bool:
    """Match a real mapped E8 transfer to one exact same-image target.

    This establishes the call coordinate only, not any callee effect or ABI.
    Synthetic targets and absent/malformed third-party loader surfaces refuse.
    """
    synthetic = synthetic_call_stub_registry_8616(project)
    if synthetic is not None and (not synthetic.closes_evidence or target_addr in synthetic.addresses):
        return False
    return direct_near_call_encoding_is_bound_8616(
        project, callsite_addr, return_addr, target_addr, frame_kind
    )


def direct_near_call_encoding_is_bound_8616(
    project: object, callsite_addr: int | None, return_addr: int | None,
    target_addr: int | None, frame_kind: CallsiteMachineFrameKind8616 | None,
) -> bool:
    """Bind current E8 bytes to an exact same-image target, without effects.

    This neutral encoding predicate does not authorize synthetic behavior or
    prove a real callee body. Its consumer must enforce its target policy.
    """
    if frame_kind is not CallsiteMachineFrameKind8616.NEAR:
        return False
    if type(callsite_addr) is not int or callsite_addr < 0 or return_addr != callsite_addr + 3:
        return False
    if type(target_addr) is not int or target_addr < 0:
        return False
    boundary = cast(_ProjectSurface8616, project)
    try:
        loaded = boundary.loader.find_object_containing(target_addr)
        if (boundary.arch.name != "86_16" or loaded is None or isinstance(loaded, ExternObject)
                or loaded is not boundary.loader.find_object_containing(callsite_addr)):
            return False
        call_bytes = bytes(boundary.loader.memory.load(callsite_addr, 3))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return bool(len(call_bytes) == 3 and call_bytes[0] == 0xE8
                and callsite_addr + 3 + int.from_bytes(call_bytes[1:], "little", signed=True) == target_addr)


def prove_direct_near_ret_only_effect_8616(
    project: object,
    callsite_addr: int | None,
    return_addr: int | None,
    target_addr: int | None,
    frame_kind: CallsiteMachineFrameKind8616 | None,
) -> DirectRetCallEffect8616:
    """Prove a real one-byte near RET leaves BP and caller memory unchanged.

    A synthetic analysis stub can contain RET bytes but is not callee-body
    evidence. All other bodies, frame kinds, and unmapped targets refuse.
    """
    if frame_kind is not CallsiteMachineFrameKind8616.NEAR:
        return _refuse_8616(callsite_addr, target_addr)
    if not isinstance(callsite_addr, int) or isinstance(callsite_addr, bool) or callsite_addr < 0:
        return _refuse_8616(callsite_addr, target_addr)
    if return_addr != callsite_addr + 3:
        return _refuse_8616(callsite_addr, target_addr)
    if not isinstance(target_addr, int) or isinstance(target_addr, bool) or target_addr < 0:
        return _refuse_8616(callsite_addr, target_addr)
    if not direct_near_call_target_is_bound_8616(project, callsite_addr, return_addr, target_addr, frame_kind):
        return _refuse_8616(callsite_addr, target_addr, normalized=True)
    boundary = cast(_ProjectSurface8616, project)
    try:
        opcode = bytes(boundary.loader.memory.load(target_addr, 1))
    except (AttributeError, KeyError, TypeError, ValueError):
        return _refuse_8616(callsite_addr, target_addr, normalized=True)
    if opcode != b"\xc3":
        return _refuse_8616(callsite_addr, target_addr, normalized=True)
    return DirectRetCallEffect8616(
        callsite_addr, target_addr, DirectRetCallEffectVerdict8616.PRESERVED,
        1, 1, 1, 1, 0,
    )


__all__ = [
    "DirectRetCallEffect8616",
    "DirectRetCallEffectVerdict8616",
    "direct_near_call_encoding_is_bound_8616",
    "direct_near_call_target_is_bound_8616",
    "prove_direct_near_ret_only_effect_8616",
]
