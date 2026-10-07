"""Convert string-instruction artifacts into typed IR string effects.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.semantics.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .segment_state import SegmentStateArtifact

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


@dataclass(frozen=True, slots=True)
class IRStringEffectRecord:
    """Typed IR effect recovered from one 16-bit string instruction."""

    index: int
    family: str
    repeat_kind: str
    width: int
    direction_mode: str
    source: IRAddress | None
    destination: IRAddress | None
    zf_sensitive: bool
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


@dataclass(frozen=True, slots=True)
class IRStringEffectArtifact:
    """Typed string-effect facts available to later IR consumers."""

    records: tuple[IRStringEffectRecord, ...] = ()
    refusal_kinds: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "records": [record.to_dict() for record in self.records],
            "refusal_kinds": list(self.refusal_kinds),
        }


def _space_for_segment(segment: str | None) -> MemSpace | None:
    if segment == "ds":
        return MemSpace.DS
    if segment == "es":
        return MemSpace.ES
    if segment == "ss":
        return MemSpace.SS
    return None


def _source_base_for_family(family: str) -> tuple[str, ...]:
    if family in {"movs", "lods", "cmps", "outs"}:
        return ("si",)
    return ()


def _destination_base_for_family(family: str) -> tuple[str, ...]:
    if family in {"movs", "stos", "scas", "cmps", "ins"}:
        return ("di",)
    return ()


def _segment_state_status(
    segment: str | None,
    segment_state_artifact: SegmentStateArtifact | None,
    instruction_addr: int | None,
) -> AddressStatus:
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
    if state.origin == SegmentOrigin.PROVEN:
        return AddressStatus.STABLE
    return AddressStatus.PROVISIONAL


def _typed_address(
    segment: str | None,
    base: tuple[str, ...],
    width: int,
    expr: str,
    *,
    segment_state_artifact: SegmentStateArtifact | None = None,
    instruction_addr: int | None = None,
) -> IRAddress | None:
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


def _typed_record(
    index: int,
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
            for index, record in enumerate(artifact.records)
        ),
        refusal_kinds=tuple(item.kind for item in artifact.refusals),
    )


def apply_x86_16_typed_string_effect_artifact(project: object, codegen: object) -> bool:
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
