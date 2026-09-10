"""Layer: Analysis.

Responsibility: summarize SS frame accesses from typed IR artifacts.
Entry-frame proof must follow the last BP write before use; overwritten setup
candidates are neither live evidence nor conflicting alternatives.
Captured register views retain their source temporary: trace that SSA value
instead of adding an old SP displacement to the current stack delta again.
Forbidden: inventing locals/args without segmented SS:BP/SP evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir.core import IRAddress, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from ..ir.scalar_affine_contracts import ScalarAffineEntryRegister8616
from ..ir.scalar_affine_trace import trace_scalar_affine_expression_8616
from ..ir.ssa import build_x86_16_block_local_ssa
from ..ir.ssa_function import SSAFunctionArtifact, build_x86_16_ir_predecessor_map

__all__ = [
    "BPFrameCoordinateEvidence8616",
    "FrameAccessArtifact",
    "FrameCoordinateStats8616",
    "FrameCoordinateStatus8616",
    "StackFrameSlot",
    "build_x86_16_ir_frame_access_artifact",
]


class FrameCoordinateStatus8616(StrEnum):
    """Typed state of the BP-to-entry-SP coordinate proof."""

    UNKNOWN = "unknown"
    PROVEN = "proven"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class FrameCoordinateStats8616:
    """Closed evidence accounting for one frame-coordinate proof."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every normalized relation has one outcome."""
        return (
            self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Return the mandatory five evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class BPFrameCoordinateEvidence8616:
    """Proven relation from machine BP to angr's entry-SP coordinate."""

    status: FrameCoordinateStatus8616 = FrameCoordinateStatus8616.UNKNOWN
    bp_entry_sp_delta: int | None = None
    detail: str = "no BP-relative stack access"
    stats: FrameCoordinateStats8616 = FrameCoordinateStats8616()

    @property
    def complete(self) -> bool:
        """Return whether counters close and the typed state is coherent."""
        if not self.stats.complete:
            return False
        return (self.status is FrameCoordinateStatus8616.PROVEN) == isinstance(self.bp_entry_sp_delta, int)

    def to_dict(self) -> dict[str, object]:
        """Serialize the coordinate proof for diagnostics and gates."""
        return {
            "status": self.status.value,
            "bp_entry_sp_delta": self.bp_entry_sp_delta,
            "detail": self.detail,
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class StackFrameSlot:
    """Evidence-backed SS:BP/SP stack-frame access."""

    base: str
    offset: int
    role: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Serialize this stack-frame slot for diagnostics and artifacts."""
        return {
            "base": self.base,
            "offset": self.offset,
            "role": self.role,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FrameAccessArtifact:
    """Summary of stack-frame accesses recovered from typed IR."""

    slots: tuple[StackFrameSlot, ...] = ()
    refusals: tuple[str, ...] = ()
    bp_coordinate: BPFrameCoordinateEvidence8616 = BPFrameCoordinateEvidence8616()

    def to_dict(self) -> dict[str, object]:
        """Serialize the frame-access artifact for diagnostics and artifacts."""
        return {
            "slots": [item.to_dict() for item in self.slots],
            "refusals": list(self.refusals),
            "bp_coordinate": self.bp_coordinate.to_dict(),
        }


def _slot_role(base: str, offset: int) -> str:
    """Classify one exact frame slot without naming it."""
    if base == "bp":
        if offset >= 4:
            return "arg"
        if offset < 0:
            return "local"
        return "frame_meta"
    return "sp_relative"


def _writes_register_8616(instruction: IRInstr, register: str) -> bool:
    """Return whether one typed instruction writes the exact register."""
    destination = instruction.dst
    return isinstance(destination, IRValue) and destination.space is MemSpace.REG and destination.name == register


def _bp_access_8616(instruction: IRInstr) -> bool:
    """Return whether one instruction accesses exact SS:BP storage."""
    return any(
        isinstance(argument, IRAddress) and argument.space is MemSpace.SS and argument.base == ("bp",)
        for argument in instruction.args
    )


def _sp_relative_value_8616(instruction: IRInstr) -> IRValue | None:
    """Return a direct SP read; captured temporaries require SSA provenance."""
    if instruction.op != "MOV" or len(instruction.args) != 1:
        return None
    source = instruction.args[0]
    if (
        isinstance(source, IRValue)
        and source.space is MemSpace.REG
        and source.name == "sp"
        and source.source_tmp is None
    ):
        return source
    return None


def _build_bp_coordinate_evidence_8616(artifact: IRFunctionArtifact) -> BPFrameCoordinateEvidence8616:
    """Prove BP's entry-SP delta from typed register effects before first use."""
    has_bp_access = any(_bp_access_8616(instruction) for block in artifact.blocks for instruction in block.instrs)
    if not has_bp_access:
        return BPFrameCoordinateEvidence8616()

    entry_block = next((block for block in artifact.blocks if block.addr == artifact.function_addr), None)
    if entry_block is None:
        stats = FrameCoordinateStats8616(1, 1, 1, 0, 1)
        return BPFrameCoordinateEvidence8616(
            detail="function entry block is unavailable",
            stats=stats,
        )

    predecessors = build_x86_16_ir_predecessor_map(artifact)
    if predecessors.get(entry_block.addr):
        return BPFrameCoordinateEvidence8616(
            detail="entry block has incoming CFG edges; entry-register origin is unproven",
            stats=FrameCoordinateStats8616(1, 1, 1, 0, 1),
        )

    sp_delta = 0
    sp_delta_known = True
    bp_delta: int | None = None
    bp_write_count = 0
    ssa_artifact: SSAFunctionArtifact | None = None

    def traced_delta(index: int) -> int | None:
        """Resolve indirect setup through exact SSA, keeping compact MOV facts local."""
        nonlocal ssa_artifact
        if ssa_artifact is None:
            ssa_artifact = SSAFunctionArtifact(
                artifact.function_addr, (build_x86_16_block_local_ssa(entry_block),),
            )
        root = ssa_artifact.blocks[0].instrs[index].dst
        if root is None:
            return None
        trace = trace_scalar_affine_expression_8616(
            ssa_artifact, root, block_addr=entry_block.addr,
            before_index=index + 1, allow_entry_registers=True,
        )
        expression = trace.expression
        if not trace.complete or expression is None or len(expression.terms) != 1:
            return None
        term = expression.terms[0]
        if not (
            isinstance(term.source, ScalarAffineEntryRegister8616)
            and term.source.register_name == "sp" and term.coefficient == 1
        ):
            return None
        return (expression.constant + 0x8000) % 0x10000 - 0x8000

    for index, instruction in enumerate(entry_block.instrs):
        if _bp_access_8616(instruction):
            break
        if _writes_register_8616(instruction, "sp"):
            source = _sp_relative_value_8616(instruction)
            if source is None or not sp_delta_known:
                recovered = traced_delta(index)
                sp_delta_known = recovered is not None
                if recovered is not None:
                    sp_delta = recovered
            else:
                sp_delta += source.offset
            continue
        if _writes_register_8616(instruction, "bp"):
            bp_write_count += 1
            source = _sp_relative_value_8616(instruction)
            bp_delta = sp_delta + source.offset if source is not None and sp_delta_known else traced_delta(index)

    raw_count = max(1, bp_write_count)
    if bp_delta is not None:
        stats = FrameCoordinateStats8616(raw_count, 1, 1, 1, 0)
        return BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=bp_delta,
            detail="the reaching typed BP write establishes a known entry-SP delta",
            stats=stats,
        )
    stats = FrameCoordinateStats8616(raw_count, 1, 1, 0, 1)
    return BPFrameCoordinateEvidence8616(
        status=FrameCoordinateStatus8616.UNKNOWN,
        detail="the reaching BP value has no proven entry-SP relation",
        stats=stats,
    )


def build_x86_16_ir_frame_access_artifact(artifact: IRFunctionArtifact) -> FrameAccessArtifact:
    """Build stack-frame access evidence from SS addresses in typed IR."""

    def _impl() -> FrameAccessArtifact:
        slots: dict[tuple[str, int, int], StackFrameSlot] = {}
        refusals: list[str] = []
        for block in artifact.blocks:
            for instr in block.instrs:
                values = tuple(arg for arg in instr.args if isinstance(arg, IRAddress) and arg.space == MemSpace.SS)
                for value in values:
                    base = value.base[0] if len(value.base) == 1 else None
                    if base not in {"bp", "sp"}:
                        refusals.append("non_frame_ss_access")
                        continue
                    size = int(value.size or instr.size or 0)
                    key = (base or "", value.offset, size)
                    slots.setdefault(
                        key,
                        StackFrameSlot(
                            base=base or "sp",
                            offset=value.offset,
                            role=_slot_role(base or "sp", value.offset),
                            size=size,
                        ),
                    )
        return FrameAccessArtifact(
            slots=tuple(sorted(slots.values(), key=lambda item: (item.base, item.offset, item.size))),
            refusals=tuple(sorted(set(refusals))),
            bp_coordinate=_build_bp_coordinate_evidence_8616(artifact),
        )

    return _impl()
