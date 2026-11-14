# cython: language_level=3, infer_types=True
"""Convert string-instruction artifacts into typed IR string effects.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.semantics.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .segment_state import SegmentStateArtifact
import dataclasses
import operator
import builtins

__all__ = [
    "IRStringEffectArtifact",
    "IRStringEffectRecord",
    "apply_x86_16_typed_string_effect_artifact",
    "build_x86_16_typed_string_effect_artifact",
]


class _StringEffectCodegenBoundary(Protocol):
    """Dynamic codegen attributes consumed and produced by this IR attachment."""

    _inertia_string_instruction_artifact: object
    _inertia_segment_state_artifact: object
    _inertia_string_effect_artifact: IRStringEffectArtifact


@dataclasses.dataclass(frozen=True, )
class IRStringEffectRecord:
    """Typed IR effect recovered from one 16-bit string instruction."""

    index: cython.longlong
    family: object
    repeat_kind: object
    width: cython.longlong
    direction_mode: object
    source: IRAddress | None
    destination: IRAddress | None
    zf_sensitive: cython.bint
    zero_seeded_accumulator: bool | None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "index": self.index,
            "family": self.family,
            "repeat_kind": self.repeat_kind,
            "width": self.width,
            "direction_mode": self.direction_mode,
            "source": None if self.source is None else self.source.to_dict(),
            "destination": None if self.destination is None else self.destination.to_dict(),
            "zf_sensitive": self.zf_sensitive,
            "zero_seeded_accumulator": self.zero_seeded_accumulator,
        }


@dataclasses.dataclass(frozen=True, )
class IRStringEffectArtifact:
    """Typed string-effect facts available to later IR consumers."""

    records: tuple[IRStringEffectRecord, ...] = ()
    refusal_kinds: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "records": [record.to_dict() for record in iter(self.records)],
            "refusal_kinds": list(self.refusal_kinds),
        }


@cython.ccall
def _space_for_segment(segment: object) -> MemSpace | None:
    if segment == "ds":
        return MemSpace.DS
    if segment == "es":
        return MemSpace.ES
    if segment == "ss":
        return MemSpace.SS
    return None


@cython.ccall
def _source_base_for_family(family: object) -> tuple[str, ...]:
    if family in {"movs", "lods", "cmps", "outs"}:
        return ("si",)
    return ()


@cython.ccall
def _destination_base_for_family(family: object) -> tuple[str, ...]:
    if family in {"movs", "stos", "scas", "cmps", "ins"}:
        return ("di",)
    return ()


@cython.ccall
def _segment_state_status(
    segment: object,
    segment_state_artifact: object,
    instruction_addr: object,
) -> AddressStatus:
    state: object
    if segment_state_artifact is None:
        return AddressStatus.PROVISIONAL
    if segment is None:
        return AddressStatus.UNKNOWN
    state = (
        segment_state_artifact.state_before_instruction(instruction_addr, segment)
        if instruction_addr is not None
        else segment_state_artifact.state_for_register(segment)
    )
    if state is None:
        return AddressStatus.PROVISIONAL
    if operator.eq(state.origin, SegmentOrigin.PROVEN):
        return AddressStatus.STABLE
    return AddressStatus.PROVISIONAL


@cython.ccall
def _typed_address(
    segment: object,
    base: object,
    width: cython.longlong,
    expr: object,
    *,
    segment_state_artifact: SegmentStateArtifact | None = None,
    instruction_addr: int | None = None,
) -> IRAddress | None:
    space: object
    space = _space_for_segment(segment)
    if space is None:
        return None
    return IRAddress(
        space=space,
        base=base,
        offset=0,
        size=width,
        status=_segment_state_status(segment, segment_state_artifact, instruction_addr),
        segment_origin=SegmentOrigin.PROVEN,
        expr=(expr,),
    )


@cython.ccall
def _typed_record(
    index: cython.longlong,
    record: StringInstructionRecord,
    *,
    segment_state_artifact: SegmentStateArtifact | None = None,
) -> IRStringEffectRecord:
    return IRStringEffectRecord(
        index=index,
        family=record.family,
        repeat_kind=record.repeat_kind,
        width=record.width,
        direction_mode=record.direction_mode,
        source=_typed_address(
            record.source_segment,
            _source_base_for_family(record.family),
            record.width,
            f"{record.family}_source",
            segment_state_artifact=segment_state_artifact,
            instruction_addr=record.instruction_addr,
        ),
        destination=_typed_address(
            record.destination_segment,
            _destination_base_for_family(record.family),
            record.width,
            f"{record.family}_destination",
            segment_state_artifact=segment_state_artifact,
            instruction_addr=record.instruction_addr,
        ),
        zf_sensitive=record.zf_sensitive,
        zero_seeded_accumulator=record.zero_seeded_accumulator,
    )


def build_x86_16_typed_string_effect_artifact(
    artifact: StringInstructionArtifact,
    *,
    segment_state_artifact: SegmentStateArtifact | None = None,
) -> IRStringEffectArtifact:
    """Convert raw string-instruction recovery into typed IR effects."""
    return IRStringEffectArtifact(
        records=tuple(
            _typed_record(index, record, segment_state_artifact=segment_state_artifact)
            for index, record in builtins.iter(enumerate(artifact.records))
        ),
        refusal_kinds=tuple(item.kind for item in iter(artifact.refusals)),
    )


@cython.ccall
def apply_x86_16_typed_string_effect_artifact(project: object, codegen: object) -> cython.bint:
    """Attach typed string effects to codegen for later IR consumers."""
    boundary = cast(_StringEffectCodegenBoundary, codegen)
    try:
        raw_artifact = boundary._inertia_string_instruction_artifact
    except AttributeError:
        return False
    if not isinstance(raw_artifact, StringInstructionArtifact):
        return False
    try:
        segment_state_candidate = boundary._inertia_segment_state_artifact
    except AttributeError:
        segment_state_candidate = None
    segment_state_artifact = (
        segment_state_candidate if isinstance(segment_state_candidate, SegmentStateArtifact) else None
    )
    artifact = build_x86_16_typed_string_effect_artifact(
        raw_artifact,
        segment_state_artifact=segment_state_artifact,
    )
    boundary._inertia_string_effect_artifact = artifact
    return False
